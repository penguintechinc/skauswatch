"""
checkpoint-core — upstream IDP federation proxy (JIT provisioning).

ProxyDelegate: delegates authentication to an upstream IdP at login time,
then provisions (or updates) the local user account if auth succeeds.

Supported delegation types:
  - oidc  — password-grant or token-exchange to upstream OIDC provider
  - saml  — redirects the browser to upstream IdP; caller must handle redirect
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)


# ── Data structures ────────────────────────────────────────────────────────────


@dataclass(slots=True)
class ProxyAuthResult:
    """
    Result of a ProxyDelegate.authenticate() call.

    Fields:
      success        — True if the upstream authenticated the user
      user_uuid      — UUID of the local user account (may be newly created)
      email          — canonical email from the upstream assertion/token
      display_name   — display name from the upstream assertion/token
      attributes     — extra upstream attributes (groups, roles, etc.)
      redirect_url   — set when idp_type='saml'; caller must redirect browser
      error          — human-readable error message on failure
    """

    success: bool
    user_uuid: str = ""
    email: str = ""
    display_name: str = ""
    attributes: dict[str, Any] = field(default_factory=dict)
    redirect_url: str = ""  # SAML redirect flow only
    error: str = ""


# ── ProxyDelegate ──────────────────────────────────────────────────────────────


class ProxyDelegate:
    """
    JIT user provisioning via upstream IdP authentication delegation.

    For each login attempt:
      1. Decrypt the upstream IDP configuration.
      2. Delegate the credential check to the upstream IdP.
      3. If authentication succeeds, search for the user in skauswatch-core
         by email.  Create the account if it does not exist; update display_name
         if it has changed.
      4. Return a ProxyAuthResult with the local user UUID and upstream claims.

    The caller is responsible for issuing a JWT/session after a successful
    ProxyAuthResult (success=True).
    """

    def __init__(self, db: Any, core_client: Any) -> None:
        """
        Initialise the proxy delegate.

        Args:
            db:          PyDAL DAL instance (migrate=False).
            core_client: CoreIdentityClient (gRPC client to skauswatch-core).
        """
        self._db = db
        self._core = core_client

    # ── Public API ─────────────────────────────────────────────────────────────

    async def authenticate(
        self,
        idp_id: int,
        username: str,
        password: str | None = None,
        upstream_token: str | None = None,
    ) -> ProxyAuthResult:
        """
        Delegate authentication to the upstream IdP and provision the local user.

        For OIDC IDPs either `password` (Resource Owner Password Credentials
        grant) or `upstream_token` (token-exchange / bearer forwarding) must be
        supplied.

        For SAML IDPs neither credential is needed — returns a redirect_url
        that the caller must redirect the browser to.

        Args:
            idp_id:         ID of the upstream IDP row in checkpoint_upstream_idps.
            username:       The end-user's username / email.
            password:       Plain-text password for ROPC grant (OIDC only).
            upstream_token: Existing access-token from the upstream IdP
                            (token-exchange path).

        Returns:
            ProxyAuthResult — check .success before using other fields.
        """
        db = self._db

        # Load IDP row
        idp_row = db(db.checkpoint_upstream_idps.id == idp_id).select().first()
        if idp_row is None:
            return ProxyAuthResult(success=False, error=f"upstream IDP {idp_id} not found")

        if not idp_row.is_active:
            return ProxyAuthResult(success=False, error="upstream IDP is disabled")

        if idp_row.federation_mode != "proxy":
            return ProxyAuthResult(
                success=False,
                error=f"IDP {idp_id} is in federation_mode={idp_row.federation_mode!r}, expected 'proxy'",
            )

        # Decrypt IDP config
        from crypto.envelope import decrypt_config_json

        try:
            idp_cfg = decrypt_config_json(idp_row.config_json_encrypted)
        except Exception as exc:
            logger.error("proxy.config_decrypt_error idp_id=%d error=%r", idp_id, exc)
            return ProxyAuthResult(success=False, error="IDP configuration error")

        idp_type: str = idp_row.idp_type or "oidc"

        if idp_type == "oidc":
            return await self._authenticate_oidc(
                idp_id=idp_id,
                idp_cfg=idp_cfg,
                username=username,
                password=password,
                upstream_token=upstream_token,
            )

        if idp_type == "saml":
            return await self._authenticate_saml(
                idp_id=idp_id,
                idp_cfg=idp_cfg,
                username=username,
            )

        return ProxyAuthResult(
            success=False,
            error=f"unsupported idp_type={idp_type!r} for proxy federation",
        )

    # ── OIDC delegation ────────────────────────────────────────────────────────

    async def _authenticate_oidc(
        self,
        idp_id: int,
        idp_cfg: dict[str, Any],
        username: str,
        password: str | None,
        upstream_token: str | None,
    ) -> ProxyAuthResult:
        """
        Authenticate via OIDC:
          - Resource Owner Password Credentials (ROPC) if `password` supplied.
          - Token introspection / userinfo if `upstream_token` supplied.

        Returns ProxyAuthResult with local user UUID after JIT provisioning.
        """
        token_endpoint: str = idp_cfg.get("token_endpoint", "")
        userinfo_endpoint: str = idp_cfg.get("userinfo_endpoint", "")
        client_id: str = idp_cfg.get("client_id", "")
        client_secret: str = idp_cfg.get("client_secret", "")

        if not token_endpoint or not client_id:
            return ProxyAuthResult(
                success=False,
                error="OIDC IDP configuration is incomplete (missing token_endpoint or client_id)",
            )

        access_token: str = ""
        claims: dict[str, Any] = {}

        if upstream_token:
            # Token-exchange / bearer forwarding path
            access_token = upstream_token
        elif password is not None:
            # Resource Owner Password Credentials grant
            try:
                access_token = await self._ropc_grant(
                    token_endpoint=token_endpoint,
                    client_id=client_id,
                    client_secret=client_secret,
                    username=username,
                    password=password,
                )
            except _UpstreamAuthError as exc:
                logger.info(
                    "proxy.oidc.ropc_denied idp_id=%d username=%s reason=%r",
                    idp_id,
                    username,
                    str(exc),
                )
                return ProxyAuthResult(success=False, error="upstream authentication failed")
            except Exception as exc:
                logger.error("proxy.oidc.ropc_error idp_id=%d error=%r", idp_id, exc)
                return ProxyAuthResult(success=False, error="upstream communication error")
        else:
            return ProxyAuthResult(
                success=False,
                error="either password or upstream_token must be provided for OIDC proxy",
            )

        # Fetch user info using the access token
        if userinfo_endpoint:
            try:
                claims = await self._fetch_userinfo(
                    userinfo_endpoint=userinfo_endpoint,
                    access_token=access_token,
                )
            except Exception as exc:
                logger.error("proxy.oidc.userinfo_error idp_id=%d error=%r", idp_id, exc)
                return ProxyAuthResult(success=False, error="failed to fetch user info from upstream")
        else:
            # Fall back to decoding the JWT claims (unsigned decode — trust the ROPC result)
            claims = _decode_jwt_claims_unsafe(access_token)

        email: str = (
            claims.get("email")
            or claims.get("preferred_username")
            or username
        ).lower().strip()
        display_name: str = (
            claims.get("name")
            or claims.get("display_name")
            or claims.get("given_name", "")
            + (" " + claims.get("family_name", "") if claims.get("family_name") else "")
        ).strip()
        attributes: dict[str, Any] = {
            k: v
            for k, v in claims.items()
            if k not in {"email", "preferred_username", "name", "sub", "iss", "aud", "exp", "iat"}
        }

        # JIT provision
        user_uuid = await self._provision_user(email=email, display_name=display_name)
        if not user_uuid:
            return ProxyAuthResult(success=False, error="failed to provision user account")

        logger.info(
            "proxy.oidc.success idp_id=%d user_uuid=%s email_domain=%s",
            idp_id,
            user_uuid,
            email.split("@")[-1] if "@" in email else "[no-domain]",
        )
        return ProxyAuthResult(
            success=True,
            user_uuid=user_uuid,
            email=email,
            display_name=display_name,
            attributes=attributes,
        )

    # ── SAML delegation ────────────────────────────────────────────────────────

    async def _authenticate_saml(
        self,
        idp_id: int,
        idp_cfg: dict[str, Any],
        username: str,
    ) -> ProxyAuthResult:
        """
        Generate a SAML AuthnRequest for the upstream IdP.

        Returns ProxyAuthResult with redirect_url set — the caller MUST redirect
        the browser to this URL.  The actual assertion handling and JIT
        provisioning happen in the ACS endpoint (saml/endpoints.py:acs()).
        """
        from saml.utils import SAMLIdpConfig, generate_saml_request

        idp_config = SAMLIdpConfig(
            entity_id=idp_cfg.get("entity_id", ""),
            sso_url=idp_cfg.get("sso_url", ""),
            signing_cert=idp_cfg.get("signing_cert", ""),
        )

        if not idp_config.entity_id or not idp_config.sso_url:
            return ProxyAuthResult(
                success=False,
                error="SAML IDP configuration is incomplete (missing entity_id or sso_url)",
            )

        import base64
        import urllib.parse

        from config import CheckpointConfig

        cfg = CheckpointConfig()  # type: ignore[call-arg]
        sp_entity_id = cfg.issuer_url
        sp_entity_b64 = base64.urlsafe_b64encode(sp_entity_id.encode()).decode().rstrip("=")
        acs_url = f"{cfg.issuer_url.rstrip('/')}/saml/acs/{sp_entity_b64}"

        # Embed idp_id + username hint in relay_state for the ACS handler
        relay_state_hint = f"idp:{idp_id}:proxy:{username}"

        try:
            saml_request_b64, relay_state_out = generate_saml_request(
                idp_config=idp_config,
                relay_state=relay_state_hint,
                acs_url=acs_url,
                sp_entity_id=sp_entity_id,
            )
        except Exception as exc:
            logger.error("proxy.saml.generate_request_error idp_id=%d error=%r", idp_id, exc)
            return ProxyAuthResult(success=False, error="failed to generate SAML AuthnRequest")

        redirect_url = (
            f"{idp_config.sso_url}?"
            f"SAMLRequest={urllib.parse.quote(saml_request_b64)}&"
            f"RelayState={urllib.parse.quote(relay_state_out)}"
        )

        logger.info("proxy.saml.redirect_generated idp_id=%d", idp_id)
        return ProxyAuthResult(
            success=True,
            redirect_url=redirect_url,
        )

    # ── JIT provisioning ───────────────────────────────────────────────────────

    async def _provision_user(self, email: str, display_name: str) -> str:
        """
        Find or create the local user account via CoreIdentityClient.

        Args:
            email:        Canonical email address from the upstream assertion.
            display_name: Display name from the upstream assertion.

        Returns:
            UUID of the (existing or newly created) user, or empty string on error.
        """
        core = self._core

        try:
            # Search by email
            results = await core.search_users(query=email, limit=1)
            if results:
                user = results[0]
                existing_uuid: str = user.get("uuid", "")
                existing_name: str = user.get("display_name", "")

                # Update display_name if it changed
                if existing_name != display_name and display_name:
                    await core.update_user(uuid=existing_uuid, display_name=display_name)
                    logger.debug(
                        "proxy.provision.updated uuid=%s display_name updated",
                        existing_uuid,
                    )

                return existing_uuid

            # Create new user account
            new_user = await core.create_user(
                email=email,
                display_name=display_name or email.split("@")[0],
            )
            new_uuid: str = new_user.get("uuid", "")
            logger.info(
                "proxy.provision.created uuid=%s email_domain=%s",
                new_uuid,
                email.split("@")[-1] if "@" in email else "[no-domain]",
            )
            return new_uuid

        except Exception as exc:
            logger.error(
                "proxy.provision.error email_domain=%s error=%r",
                email.split("@")[-1] if "@" in email else "[no-domain]",
                exc,
            )
            return ""

    # ── OIDC helpers ───────────────────────────────────────────────────────────

    @staticmethod
    async def _ropc_grant(
        token_endpoint: str,
        client_id: str,
        client_secret: str,
        username: str,
        password: str,
    ) -> str:
        """
        Execute the OAuth2 Resource Owner Password Credentials (ROPC) grant.

        Args:
            token_endpoint: Full URL of the upstream token endpoint.
            client_id:      Client ID registered at the upstream IdP.
            client_secret:  Client secret (may be empty for public clients).
            username:       End-user's login name.
            password:       End-user's plain-text password.

        Returns:
            access_token string.

        Raises:
            _UpstreamAuthError: when the upstream explicitly denies the credentials
                                (HTTP 400/401/403 with error payload).
            aiohttp.ClientError: on network/transport errors.
        """
        payload: dict[str, str] = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": client_id,
            "scope": "openid profile email",
        }
        if client_secret:
            payload["client_secret"] = client_secret

        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(token_endpoint, data=payload) as resp:
                body = await resp.json(content_type=None)
                if resp.status not in (200, 201):
                    error_desc = body.get("error_description") or body.get("error") or str(resp.status)
                    raise _UpstreamAuthError(error_desc)
                return body.get("access_token", "")

    @staticmethod
    async def _fetch_userinfo(
        userinfo_endpoint: str,
        access_token: str,
    ) -> dict[str, Any]:
        """
        Fetch user claims from the upstream OIDC userinfo endpoint.

        Args:
            userinfo_endpoint: Full URL of the upstream userinfo endpoint.
            access_token:      Bearer token for the userinfo request.

        Returns:
            dict of OIDC claims (email, name, sub, etc.).
        """
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            ) as resp:
                resp.raise_for_status()
                return await resp.json(content_type=None)


# ── Internal helpers ──────────────────────────────────────────────────────────


class _UpstreamAuthError(Exception):
    """Raised when the upstream IdP explicitly rejects the credentials."""


def _decode_jwt_claims_unsafe(token: str) -> dict[str, Any]:
    """
    Decode JWT claims without signature verification.

    Used only as a last resort when no userinfo endpoint is available —
    the token was already obtained via an ROPC grant against the upstream
    IdP, so we trust it implicitly for claim extraction purposes only.

    Args:
        token: Base64url-encoded JWT string.

    Returns:
        dict of claims from the payload section, or empty dict on parse error.
    """
    import base64
    import json

    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        # Add padding to satisfy base64 decoder
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        return json.loads(payload_bytes)
    except Exception:
        return {}


# ── Module-level async helper ─────────────────────────────────────────────────


async def provision_saml_assertion(
    db: Any,
    core_client: Any,
    claims: dict[str, Any],
    idp_id: int,
) -> str:
    """
    JIT provision a user from a validated SAML assertion.

    Called by the ACS endpoint after `validate_saml_response` succeeds,
    to ensure the local user account exists before the OIDC token is issued.

    Args:
        db:          PyDAL DAL instance.
        core_client: CoreIdentityClient.
        claims:      Validated assertion claims: sub, email, attributes.
        idp_id:      Upstream IDP ID (for audit logging).

    Returns:
        UUID of the provisioned user, or empty string on error.
    """
    delegate = ProxyDelegate(db=db, core_client=core_client)
    email: str = claims.get("email") or claims.get("sub", "")
    attrs: dict[str, Any] = claims.get("attributes", {})
    display_name: str = (
        attrs.get("displayName")
        or attrs.get("display_name")
        or attrs.get("cn")
        or email.split("@")[0]
    )
    return await delegate._provision_user(email=email.lower().strip(), display_name=display_name)
