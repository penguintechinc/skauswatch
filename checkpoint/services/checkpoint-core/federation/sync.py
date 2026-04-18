"""
checkpoint-core — UpstreamSyncLoop: batch user import from upstream IDPs.

Supported IDP types: oidc, ldap, google, okta, saml

For each active IDP with federation_mode='sync', queries the upstream
directory and provisions users into skauswatch-core via CoreIdentityClient.
Respects per-IDP sync_interval_secs. Updates last_sync_at and sync_error.

All config is stored encrypted in checkpoint_upstream_idps.config_json_encrypted.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Maximum users fetched per IDP per sync cycle (safety limit)
_MAX_USERS_PER_SYNC = 10_000


@dataclass(slots=True)
class SyncResult:
    """Summary of a single IDP sync run."""

    idp_id: int
    idp_name: str
    idp_type: str
    users_synced: int
    users_created: int
    users_updated: int
    errors: int
    duration_ms: int
    error_message: str | None = None


class UpstreamSyncLoop:
    """
    Periodic background task that syncs users from upstream IDPs.

    Usage (from main.py background task):

        loop = UpstreamSyncLoop(app)
        await loop.run_forever()
    """

    def __init__(self, app: Any, poll_interval_secs: int = 60) -> None:
        """
        Initialise the sync loop.

        Args:
            app:                Quart application instance.
            poll_interval_secs: How often to check for IDPs due for sync.
        """
        self._app = app
        self._poll_interval = poll_interval_secs

    async def run_forever(self) -> None:
        """Run the sync loop indefinitely (call as an asyncio task)."""
        logger.info("upstream_sync_loop.started poll_interval=%ds", self._poll_interval)
        while True:
            try:
                await asyncio.sleep(self._poll_interval)
                await self._tick()
            except asyncio.CancelledError:
                logger.info("upstream_sync_loop.cancelled")
                break
            except Exception as exc:  # noqa: BLE001
                logger.error("upstream_sync_loop.unhandled_error error=%r", exc)

    async def _tick(self) -> None:
        """Check all active sync-mode IDPs and run those that are due."""
        async with self._app.app_context():
            db: Any = self._app.extensions.get("checkpoint_db")
            core: Any = self._app.extensions.get("checkpoint_core_client")
            if db is None or core is None:
                return

            now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
            idps = db(
                (db.checkpoint_upstream_idps.is_active == True)  # noqa: E712
                & (db.checkpoint_upstream_idps.federation_mode == "sync")
            ).select()

            for idp in idps:
                interval = int(idp.sync_interval_secs or 3600)
                last = idp.last_sync_at
                if last is None or (now - last).total_seconds() >= interval:
                    result = await self._sync_idp(idp, db, core, now)
                    _log_sync_result(result)

    async def _sync_idp(
        self,
        idp: Any,
        db: Any,
        core: Any,
        now: datetime,
    ) -> SyncResult:
        """Run a full sync for a single IDP. Updates DB regardless of outcome."""
        from crypto.envelope import decrypt_config_json

        start_ms = _now_ms()
        idp_id = int(idp.id)
        idp_type: str = (idp.type or "").lower()
        idp_name: str = idp.name or f"idp#{idp_id}"

        logger.info(
            "upstream_sync.start idp_id=%d name=%s type=%s",
            idp_id,
            idp_name,
            idp_type,
        )

        error_message: str | None = None
        users_synced = users_created = users_updated = errors = 0

        try:
            config = decrypt_config_json(idp.config_json_encrypted)
        except Exception as exc:
            error_message = f"config_decrypt_failed: {exc}"
            _update_idp_status(db, idp_id, now, error_message)
            return SyncResult(
                idp_id=idp_id,
                idp_name=idp_name,
                idp_type=idp_type,
                users_synced=0,
                users_created=0,
                users_updated=0,
                errors=1,
                duration_ms=_elapsed_ms(start_ms),
                error_message=error_message,
            )

        try:
            if idp_type == "oidc":
                user_list = await _sync_oidc(config)
            elif idp_type == "ldap":
                user_list = await _sync_ldap(config)
            elif idp_type == "google":
                user_list = await _sync_google(config)
            elif idp_type == "okta":
                user_list = await _sync_okta(config)
            elif idp_type == "saml":
                # SAML is inherently request-driven; batch sync reads from SCIM if configured
                user_list = await _sync_saml_scim(config)
            else:
                logger.warning(
                    "upstream_sync.unknown_type idp_id=%d type=%s", idp_id, idp_type
                )
                user_list = []

            for user_attrs in user_list[:_MAX_USERS_PER_SYNC]:
                try:
                    result_code = await _provision_user(core, user_attrs)
                    if result_code == "created":
                        users_created += 1
                    elif result_code == "updated":
                        users_updated += 1
                    users_synced += 1
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "upstream_sync.provision_error idp_id=%d email=%s error=%r",
                        idp_id,
                        user_attrs.get("email", "?"),
                        exc,
                    )
                    errors += 1

        except Exception as exc:  # noqa: BLE001
            error_message = str(exc)
            logger.error(
                "upstream_sync.fetch_error idp_id=%d type=%s error=%r",
                idp_id,
                idp_type,
                exc,
            )

        _update_idp_status(db, idp_id, now, error_message)

        return SyncResult(
            idp_id=idp_id,
            idp_name=idp_name,
            idp_type=idp_type,
            users_synced=users_synced,
            users_created=users_created,
            users_updated=users_updated,
            errors=errors,
            duration_ms=_elapsed_ms(start_ms),
            error_message=error_message,
        )


# ── Per-type sync functions ────────────────────────────────────────────────────


async def _sync_oidc(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Fetch users from an upstream OIDC provider that supports SCIM or a
    custom user listing endpoint.

    Config keys:
      token_endpoint    (str)  — token URL
      client_id         (str)
      client_secret     (str)
      users_endpoint    (str)  — e.g. https://idp.example.com/scim/v2/Users
    """
    import aiohttp

    token_endpoint = config.get("token_endpoint", "")
    client_id = config.get("client_id", "")
    client_secret = config.get("client_secret", "")
    users_endpoint = config.get("users_endpoint", "")

    if not all([token_endpoint, client_id, client_secret, users_endpoint]):
        raise ValueError("oidc sync requires token_endpoint, client_id, client_secret, users_endpoint")

    async with aiohttp.ClientSession() as session:
        # Client-credentials grant to get access token
        async with session.post(
            token_endpoint,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "openid profile email",
            },
            timeout=aiohttp.ClientTimeout(total=30),
        ) as resp:
            if resp.status != 200:
                raise ValueError(f"OIDC token fetch failed: HTTP {resp.status}")
            token_data = await resp.json()
            access_token = token_data.get("access_token", "")

        # Fetch user list (SCIM-style pagination)
        users: list[dict[str, Any]] = []
        start_index = 1
        page_size = 100

        while True:
            async with session.get(
                users_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
                params={"startIndex": start_index, "count": page_size},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    raise ValueError(f"OIDC users fetch failed: HTTP {resp.status}")
                data = await resp.json()

            resources = data.get("Resources", [])
            for r in resources:
                email = _extract_email_from_scim(r)
                if email:
                    users.append({
                        "email": email,
                        "display_name": r.get("displayName", ""),
                        "username": r.get("userName", email),
                        "external_id": r.get("id", ""),
                        "is_active": not r.get("active") is False,
                    })

            total = int(data.get("totalResults", 0))
            if start_index + page_size > total or not resources:
                break
            start_index += page_size

        return users


async def _sync_ldap(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Fetch users from an LDAP directory (read-only bind + search).

    Config keys:
      host         (str)
      port         (int, default 389)
      bind_dn      (str)
      bind_password (str)
      user_base_dn (str)
      user_filter  (str, default "(objectClass=inetOrgPerson)")
      attributes   (list[str], default ["uid", "mail", "cn", "sn"])
    """
    import asyncio

    host = config.get("host", "localhost")
    port = int(config.get("port", 389))
    bind_dn = config.get("bind_dn", "")
    bind_password = config.get("bind_password", "")
    user_base_dn = config.get("user_base_dn", "")
    user_filter = config.get("user_filter", "(objectClass=inetOrgPerson)")
    attributes = config.get("attributes", ["uid", "mail", "cn", "sn"])

    if not user_base_dn:
        raise ValueError("ldap sync requires user_base_dn")

    # Run blocking python-ldap operations in executor
    def _ldap_search() -> list[dict[str, Any]]:
        import ldap  # type: ignore[import-untyped]

        conn = ldap.initialize(f"ldap://{host}:{port}")
        conn.set_option(ldap.OPT_REFERRALS, 0)
        conn.set_option(ldap.OPT_TIMEOUT, 30)
        conn.simple_bind_s(bind_dn, bind_password)

        results = conn.search_s(
            user_base_dn,
            ldap.SCOPE_SUBTREE,
            user_filter,
            attributes,
        )
        conn.unbind_s()

        users: list[dict[str, Any]] = []
        for _dn, attrs in results:
            if not isinstance(attrs, dict):
                continue
            mail = _first_bytes(attrs.get("mail", []))
            uid = _first_bytes(attrs.get("uid", []))
            cn = _first_bytes(attrs.get("cn", []))
            if not mail:
                continue
            users.append({
                "email": mail,
                "username": uid or mail,
                "display_name": cn,
                "is_active": True,
            })
        return users

    return await asyncio.to_thread(_ldap_search)


async def _sync_google(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Fetch users from Google Workspace Directory API.

    Config keys:
      service_account_json (str)  — JSON string of service account credentials
      domain               (str)  — Google Workspace domain
      subject              (str)  — Admin email for domain-wide delegation
    """
    import asyncio
    import json

    service_account_json = config.get("service_account_json", "")
    domain = config.get("domain", "")
    subject = config.get("subject", "")

    if not all([service_account_json, domain, subject]):
        raise ValueError("google sync requires service_account_json, domain, subject")

    def _google_list() -> list[dict[str, Any]]:
        from google.oauth2 import service_account  # type: ignore[import-untyped]
        from googleapiclient.discovery import build  # type: ignore[import-untyped]

        sa_info = json.loads(service_account_json)
        creds = service_account.Credentials.from_service_account_info(
            sa_info,
            scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly"],
            subject=subject,
        )
        service = build("admin", "directory_v1", credentials=creds)

        users: list[dict[str, Any]] = []
        page_token: str | None = None
        while True:
            result = service.users().list(
                domain=domain,
                maxResults=200,
                orderBy="email",
                pageToken=page_token,
            ).execute()
            for u in result.get("users", []):
                email = u.get("primaryEmail", "")
                if email:
                    users.append({
                        "email": email,
                        "display_name": u.get("name", {}).get("fullName", ""),
                        "username": email,
                        "is_active": not u.get("suspended", False),
                    })
            page_token = result.get("nextPageToken")
            if not page_token:
                break
        return users

    return await asyncio.to_thread(_google_list)


async def _sync_okta(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Fetch users from Okta via REST API.

    Config keys:
      domain    (str)  — e.g. company.okta.com
      api_token (str)
    """
    import aiohttp

    domain = config.get("domain", "")
    api_token = config.get("api_token", "")

    if not all([domain, api_token]):
        raise ValueError("okta sync requires domain and api_token")

    users: list[dict[str, Any]] = []
    url: str = f"https://{domain}/api/v1/users?limit=200&filter=status+eq+%22ACTIVE%22"

    async with aiohttp.ClientSession() as session:
        while url:
            async with session.get(
                url,
                headers={"Authorization": f"SSWS {api_token}", "Accept": "application/json"},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    raise ValueError(f"Okta users fetch failed: HTTP {resp.status}")
                data = await resp.json()
                for u in data:
                    profile = u.get("profile", {})
                    email = profile.get("email", "") or profile.get("login", "")
                    if email:
                        users.append({
                            "email": email,
                            "display_name": f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip(),
                            "username": profile.get("login", email),
                            "external_id": u.get("id", ""),
                            "is_active": u.get("status") == "ACTIVE",
                        })

                # Follow Okta's Link header for pagination
                link_header = resp.headers.get("Link", "")
                url = _parse_next_link(link_header)

    return users


async def _sync_saml_scim(config: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Fetch users from a SAML IDP that also exposes a SCIM endpoint.

    Config keys:
      scim_endpoint  (str)
      scim_token     (str)  — Bearer token for SCIM endpoint
    """
    import aiohttp

    scim_endpoint = config.get("scim_endpoint", "")
    scim_token = config.get("scim_token", "")

    if not scim_endpoint:
        # SAML IDPs without SCIM cannot do batch sync
        logger.debug("saml_scim_sync.no_scim_endpoint — skipping batch sync")
        return []

    users: list[dict[str, Any]] = []
    start_index = 1
    page_size = 100

    async with aiohttp.ClientSession() as session:
        while True:
            headers: dict[str, str] = {"Accept": "application/scim+json"}
            if scim_token:
                headers["Authorization"] = f"Bearer {scim_token}"

            async with session.get(
                f"{scim_endpoint}/Users",
                headers=headers,
                params={"startIndex": start_index, "count": page_size},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status != 200:
                    raise ValueError(f"SAML SCIM users fetch failed: HTTP {resp.status}")
                data = await resp.json()

            resources = data.get("Resources", [])
            for r in resources:
                email = _extract_email_from_scim(r)
                if email:
                    users.append({
                        "email": email,
                        "display_name": r.get("displayName", ""),
                        "username": r.get("userName", email),
                        "is_active": not r.get("active") is False,
                    })

            total = int(data.get("totalResults", 0))
            if start_index + page_size > total or not resources:
                break
            start_index += page_size

    return users


# ── User provisioning ──────────────────────────────────────────────────────────


async def _provision_user(core: Any, attrs: dict[str, Any]) -> str:
    """
    Provision or update a user in skauswatch-core via CoreIdentityClient.

    Returns 'created', 'updated', or 'skipped'.
    """
    email: str = attrs.get("email", "")
    if not email:
        raise ValueError("user attrs missing email")

    # Search for existing user by email
    results = await core.search_users(email)
    if results:
        existing = results[0]
        # Update only if display_name changed
        new_name = attrs.get("display_name", "")
        if new_name and new_name != getattr(existing, "display_name", ""):
            await core.update_user(
                existing.uuid,
                {"display_name": new_name},
            )
            return "updated"
        return "skipped"

    # Create new user
    await core.create_user({
        "email": email,
        "username": attrs.get("username", email),
        "display_name": attrs.get("display_name", ""),
        "is_active": bool(attrs.get("is_active", True)),
        "external_id": attrs.get("external_id", ""),
    })
    return "created"


# ── Private helpers ────────────────────────────────────────────────────────────


def _update_idp_status(
    db: Any,
    idp_id: int,
    synced_at: datetime,
    error: str | None,
) -> None:
    """Update last_sync_at and sync_error for an IDP row."""
    try:
        db(db.checkpoint_upstream_idps.id == idp_id).update(
            last_sync_at=synced_at,
            sync_error=error,
        )
        db.commit()
    except Exception as exc:  # noqa: BLE001
        logger.error("upstream_sync.db_update_error idp_id=%d error=%r", idp_id, exc)


def _log_sync_result(result: SyncResult) -> None:
    if result.error_message:
        logger.error(
            "upstream_sync.failed idp_id=%d name=%s type=%s error=%s duration_ms=%d",
            result.idp_id,
            result.idp_name,
            result.idp_type,
            result.error_message,
            result.duration_ms,
        )
    else:
        logger.info(
            "upstream_sync.complete idp_id=%d name=%s type=%s synced=%d created=%d updated=%d errors=%d duration_ms=%d",
            result.idp_id,
            result.idp_name,
            result.idp_type,
            result.users_synced,
            result.users_created,
            result.users_updated,
            result.errors,
            result.duration_ms,
        )


def _now_ms() -> int:
    """Return current monotonic time in milliseconds."""
    import time

    return int(time.monotonic() * 1000)


def _elapsed_ms(start_ms: int) -> int:
    return _now_ms() - start_ms


def _first_bytes(values: list[Any]) -> str:
    """Return first LDAP attribute value decoded as UTF-8, or empty string."""
    if values:
        v = values[0]
        return v.decode("utf-8") if isinstance(v, bytes) else str(v)
    return ""


def _extract_email_from_scim(resource: dict[str, Any]) -> str:
    """Extract primary email from a SCIM Resource dict."""
    # Try emails array
    for email_entry in resource.get("emails", []):
        if isinstance(email_entry, dict):
            if email_entry.get("primary") or email_entry.get("type") == "work":
                return email_entry.get("value", "")
    # Fallback to userName if it looks like an email
    username = resource.get("userName", "")
    if "@" in username:
        return username
    return ""


def _parse_next_link(link_header: str) -> str:
    """Parse the 'next' URL from an RFC 5988 Link header, or return empty string."""
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            url_part = part.split(";")[0].strip()
            return url_part.strip("<>")
    return ""
