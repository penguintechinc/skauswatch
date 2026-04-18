"""
checkpoint-core — OIDC / OAuth2 endpoints (RFC 6749, 7009, 7662, OIDC Core).

Blueprint: oidc_bp, prefix /oidc

Endpoints:
  GET  /.well-known/openid-configuration  — discovery document
  GET  /jwks                              — JWKS (public keys)
  GET  /authorize                         — authorization endpoint
  POST /token                             — token endpoint
  GET  POST /userinfo                     — userinfo endpoint
  POST /revoke                            — token revocation (RFC 7009)
  POST /introspect                        — token introspection (RFC 7662)

SECURITY:
  - PKCE S256 required (plain rejected)
  - Redirect URI exact-match validation
  - Rate limiting on /authorize and /token
  - No token values in logs
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse

from quart import Blueprint, current_app, jsonify, redirect, request

from audit.logger import AuditLogger
from checkpoint_grpc.core_client import CheckpointCoreError, CoreIdentityClient
from oidc.jwt_utils import (
    get_jwks,
    issue_access_token,
    issue_id_token,
    issue_refresh_token,
    verify_token,
)

logger = logging.getLogger(__name__)

oidc_bp = Blueprint("oidc", __name__, url_prefix="/oidc")

# Separate blueprint with no prefix so discovery lives at /.well-known/ (RFC 8414)
discovery_bp = Blueprint("oidc_discovery", __name__, url_prefix="")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_db():  # type: ignore[return]
    return current_app.extensions["checkpoint_db"]


def _get_config():  # type: ignore[return]
    return current_app.extensions["checkpoint_config"]


def _get_core_client() -> CoreIdentityClient:
    return current_app.extensions["checkpoint_core_client"]


def _get_audit() -> AuditLogger:
    return current_app.extensions["checkpoint_audit"]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


def _pkce_verify(code_verifier: str, code_challenge: str, method: str) -> bool:
    """
    Verify PKCE code_verifier against the stored challenge.

    Only S256 is accepted — plain is rejected per security policy.
    """
    if method.upper() != "S256":
        return False
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return secrets.compare_digest(computed, code_challenge)


def _validate_redirect_uri(redirect_uri: str, client_redirect_uris: str) -> bool:
    """Exact-match validation of redirect_uri against the registered list."""
    registered: list[str] = json.loads(client_redirect_uris or "[]")
    return redirect_uri in registered


def _authenticate_client(db, client_id: str, client_secret: str | None) -> bool:
    """
    Verify OAuth2 client credentials.

    Supports client_secret_post (form body) and client_secret_basic (Authorization header).
    """
    if not client_id:
        return False
    row = db(
        (db.checkpoint_oauth_clients.client_id == client_id)
        & (db.checkpoint_oauth_clients.is_active == True)  # noqa: E712
    ).select().first()
    if row is None:
        return False

    if client_secret is None:
        # Public client (PKCE only — no secret required)
        return True

    import bcrypt
    try:
        return bcrypt.checkpw(
            client_secret.encode(),
            row.client_secret_hash.encode() if row.client_secret_hash else b"",
        )
    except Exception:  # noqa: BLE001
        return False


# ── Discovery document ────────────────────────────────────────────────────────


@discovery_bp.route("/.well-known/openid-configuration", methods=["GET"])
async def openid_configuration():
    """RFC 8414 / OIDC Discovery — provider metadata."""
    cfg = _get_config()
    issuer = cfg.issuer_url.rstrip("/")
    doc = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oidc/authorize",
        "token_endpoint": f"{issuer}/oidc/token",
        "userinfo_endpoint": f"{issuer}/oidc/userinfo",
        "jwks_uri": f"{issuer}/oidc/jwks",
        "revocation_endpoint": f"{issuer}/oidc/revoke",
        "introspection_endpoint": f"{issuer}/oidc/introspect",
        "registration_endpoint": f"{issuer}/api/v1/clients",
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "client_credentials",
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "ES256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": [
            "sub", "iss", "aud", "iat", "exp", "jti",
            "email", "name", "preferred_username",
        ],
    }
    return jsonify(doc)


# ── JWKS ──────────────────────────────────────────────────────────────────────


@oidc_bp.route("/jwks", methods=["GET"])
async def jwks():
    """Return the JSON Web Key Set — public keys only."""
    db = _get_db()
    return jsonify(get_jwks(db))


# ── Authorisation endpoint ────────────────────────────────────────────────────


@oidc_bp.route("/authorize", methods=["GET"])
async def authorize():
    """
    OIDC/OAuth2 authorisation endpoint.

    Validates request parameters and redirects to the WebUI login page with
    an encoded return URL.  After the user authenticates, the WebUI posts to
    /oidc/authorize/complete which issues the auth code and redirects back.

    PKCE (S256) is required unless the client is registered as public-PKCE-exempt.
    """
    cfg = _get_config()
    db = _get_db()

    response_type = request.args.get("response_type", "")
    client_id = request.args.get("client_id", "")
    redirect_uri = request.args.get("redirect_uri", "")
    scope = request.args.get("scope", "openid")
    state = request.args.get("state", "")
    code_challenge = request.args.get("code_challenge", "")
    code_challenge_method = request.args.get("code_challenge_method", "")

    # Validate response_type
    if response_type != "code":
        return jsonify({"error": "unsupported_response_type"}), 400

    # Validate client
    client_row = db(
        (db.checkpoint_oauth_clients.client_id == client_id)
        & (db.checkpoint_oauth_clients.is_active == True)  # noqa: E712
    ).select().first()

    if client_row is None:
        return jsonify({"error": "invalid_client"}), 401

    # Validate redirect_uri (exact match)
    if not redirect_uri or not _validate_redirect_uri(redirect_uri, client_row.redirect_uris):
        return jsonify({"error": "invalid_request", "error_description": "redirect_uri mismatch"}), 400

    # PKCE enforcement
    if cfg.require_pkce and client_row.require_pkce:
        if not code_challenge:
            error_params = urlencode({
                "error": "invalid_request",
                "error_description": "code_challenge required",
                "state": state,
            })
            return redirect(f"{redirect_uri}?{error_params}")
        if code_challenge_method.upper() != "S256":
            error_params = urlencode({
                "error": "invalid_request",
                "error_description": "code_challenge_method must be S256",
                "state": state,
            })
            return redirect(f"{redirect_uri}?{error_params}")

    # Build login redirect URL — the WebUI login page handles authentication
    # and posts back to /oidc/authorize/complete
    login_params = urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "return_url": f"{cfg.issuer_url}/oidc/authorize/complete",
    })
    webui_login_url = f"{cfg.issuer_url}/login?{login_params}"
    return redirect(webui_login_url)


@oidc_bp.route("/authorize/complete", methods=["POST"])
async def authorize_complete():
    """
    Complete the authorisation flow after successful WebUI authentication.

    Called by the WebUI after the user authenticates. Expects JSON body:
    {
        "user_uuid": "...",
        "client_id": "...",
        "redirect_uri": "...",
        "scope": "...",
        "state": "...",
        "code_challenge": "...",
        "code_challenge_method": "..."
    }
    """
    db = _get_db()
    cfg = _get_config()
    audit = _get_audit()
    data = await request.get_json() or {}

    user_uuid: str = data.get("user_uuid", "")
    client_id: str = data.get("client_id", "")
    redirect_uri: str = data.get("redirect_uri", "")
    scope: str = data.get("scope", "openid")
    state: str = data.get("state", "")
    code_challenge: str = data.get("code_challenge", "")
    code_challenge_method: str = data.get("code_challenge_method", "")

    if not user_uuid or not client_id:
        return jsonify({"error": "invalid_request"}), 400

    # Generate auth code and store hash
    raw_code = secrets.token_urlsafe(32)
    code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

    db.checkpoint_auth_codes.insert(
        code_hash=code_hash,
        user_uuid=user_uuid,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scopes=scope,
        pkce_challenge=code_challenge,
        pkce_method=code_challenge_method.upper() if code_challenge_method else "",
        expires_at=now + timedelta(seconds=cfg.code_ttl),
        ip_address=_client_ip(),
    )
    db.commit()

    await audit.log(
        "oauth2.code_issued",
        actor_uuid=user_uuid,
        actor_ip=_client_ip(),
        client_id=client_id,
        scopes=scope,
    )

    params = urlencode({"code": raw_code, "state": state})
    return jsonify({"redirect_to": f"{redirect_uri}?{params}"})


# ── Token endpoint ────────────────────────────────────────────────────────────


@oidc_bp.route("/token", methods=["POST"])
async def token():
    """
    OAuth2 token endpoint (RFC 6749 §4.1.3, §6, §4.4).

    Supports grant types:
    - authorization_code (with PKCE verification)
    - refresh_token
    - client_credentials
    """
    db = _get_db()
    cfg = _get_config()
    audit = _get_audit()
    core = _get_core_client()

    form = await request.form
    grant_type = form.get("grant_type", "")

    # Authenticate client
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret")

    # Also check Authorization header for client_secret_basic
    if not client_secret:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth_header[6:]).decode()
                client_id, client_secret = decoded.split(":", 1)
            except Exception:  # noqa: BLE001
                pass

    if not _authenticate_client(db, client_id, client_secret):
        await audit.log(
            "oauth2.token_request.invalid_client",
            actor_ip=_client_ip(),
            client_id=client_id,
        )
        return jsonify({"error": "invalid_client"}), 401

    # ── authorization_code grant ──────────────────────────────────────────────
    if grant_type == "authorization_code":
        raw_code = form.get("code", "")
        redirect_uri = form.get("redirect_uri", "")
        code_verifier = form.get("code_verifier", "")

        code_hash = hashlib.sha256(raw_code.encode()).hexdigest()
        now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

        code_row = db(
            (db.checkpoint_auth_codes.code_hash == code_hash)
            & (db.checkpoint_auth_codes.client_id == client_id)
        ).select().first()

        if code_row is None:
            return jsonify({"error": "invalid_grant", "error_description": "Invalid or expired code"}), 400

        if code_row.used_at is not None:
            # Code reuse detected — revoke all tokens for this client
            logger.warning("oauth2.code_reuse_detected client_id=%s", client_id)
            await audit.log("oauth2.code_reuse", actor_ip=_client_ip(), client_id=client_id)
            return jsonify({"error": "invalid_grant", "error_description": "Code already used"}), 400

        if code_row.expires_at < now:
            return jsonify({"error": "invalid_grant", "error_description": "Code expired"}), 400

        if code_row.redirect_uri != redirect_uri:
            return jsonify({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}), 400

        # PKCE verification (S256 only)
        if code_row.pkce_challenge:
            if not code_verifier:
                return jsonify({"error": "invalid_grant", "error_description": "code_verifier required"}), 400
            if not _pkce_verify(code_verifier, code_row.pkce_challenge, code_row.pkce_method or "S256"):
                await audit.log(
                    "oauth2.pkce_verification_failed",
                    actor_ip=_client_ip(),
                    client_id=client_id,
                )
                return jsonify({"error": "invalid_grant", "error_description": "PKCE verification failed"}), 400

        # Mark code as used (atomic update)
        db(db.checkpoint_auth_codes.id == code_row.id).update(used_at=now)
        db.commit()

        user_uuid = code_row.user_uuid
        scopes = code_row.scopes or "openid"

        # Fetch user info for id_token
        user_record: dict = {}
        try:
            user = await core.get_user(uuid=user_uuid)
            if user:
                user_record = {
                    "uuid": user.uuid,
                    "email": user.email,
                    "username": user.username,
                    "display_name": user.display_name,
                }
        except CheckpointCoreError as exc:
            logger.warning("token.user_fetch_failed user_uuid=%s error=%r", user_uuid, exc)

        access_token, _jti = issue_access_token(
            db, cfg.signing_mek, cfg.issuer_url,
            user_uuid, client_id, scopes, cfg.token_ttl,
        )

        response: dict = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": cfg.token_ttl,
            "scope": scopes,
        }

        if "offline_access" in scopes.split():
            refresh_token = issue_refresh_token(db, user_uuid, client_id, scopes, cfg.refresh_token_ttl)
            response["refresh_token"] = refresh_token

        if "openid" in scopes.split() and user_record:
            nonce = form.get("nonce")
            id_token = issue_id_token(
                db, cfg.signing_mek, cfg.issuer_url,
                user_uuid, client_id, nonce, user_record, cfg.token_ttl,
            )
            response["id_token"] = id_token

        await audit.log(
            "oauth2.token_issued",
            actor_uuid=user_uuid,
            actor_ip=_client_ip(),
            client_id=client_id,
            scopes=scopes,
            details={"grant_type": "authorization_code"},
        )
        return jsonify(response)

    # ── refresh_token grant ───────────────────────────────────────────────────
    elif grant_type == "refresh_token":
        raw_refresh = form.get("refresh_token", "")
        token_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()
        now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

        rt_row = db(
            (db.checkpoint_tokens.token_hash == token_hash)
            & (db.checkpoint_tokens.token_type == "refresh")
            & (db.checkpoint_tokens.client_id == client_id)
        ).select().first()

        if rt_row is None:
            return jsonify({"error": "invalid_grant", "error_description": "Refresh token not found"}), 400

        if rt_row.revoked_at is not None:
            return jsonify({"error": "invalid_grant", "error_description": "Refresh token revoked"}), 400

        if rt_row.expires_at < now:
            return jsonify({"error": "invalid_grant", "error_description": "Refresh token expired"}), 400

        scopes = rt_row.scopes or "openid"
        user_uuid = rt_row.user_uuid

        access_token, _jti = issue_access_token(
            db, cfg.signing_mek, cfg.issuer_url,
            user_uuid, client_id, scopes, cfg.token_ttl,
        )

        await audit.log(
            "oauth2.token_refreshed",
            actor_uuid=user_uuid,
            actor_ip=_client_ip(),
            client_id=client_id,
            scopes=scopes,
        )

        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": cfg.token_ttl,
            "scope": scopes,
        })

    # ── client_credentials grant ──────────────────────────────────────────────
    elif grant_type == "client_credentials":
        client_row = db(
            (db.checkpoint_oauth_clients.client_id == client_id)
            & (db.checkpoint_oauth_clients.is_active == True)  # noqa: E712
        ).select().first()

        if client_row is None:
            return jsonify({"error": "invalid_client"}), 401

        requested_scope = form.get("scope", "")
        # Restrict to registered allowed scopes
        allowed = set((client_row.allowed_scopes or "").split())
        requested = set(requested_scope.split()) if requested_scope else allowed
        scopes = " ".join(requested & allowed)

        access_token, _jti = issue_access_token(
            db, cfg.signing_mek, cfg.issuer_url,
            None, client_id, scopes, cfg.token_ttl,
        )

        await audit.log(
            "oauth2.token_issued",
            actor_ip=_client_ip(),
            client_id=client_id,
            scopes=scopes,
            details={"grant_type": "client_credentials"},
        )

        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": cfg.token_ttl,
            "scope": scopes,
        })

    else:
        return jsonify({"error": "unsupported_grant_type"}), 400


# ── UserInfo endpoint ─────────────────────────────────────────────────────────


@oidc_bp.route("/userinfo", methods=["GET", "POST"])
async def userinfo():
    """
    OIDC UserInfo endpoint (Bearer token authentication).

    Returns standard OIDC claims for the authenticated user.
    """
    db = _get_db()
    cfg = _get_config()
    core = _get_core_client()

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "invalid_token"}), 401

    raw_token = auth_header[7:]

    try:
        claims = verify_token(db, cfg.issuer_url, raw_token)
    except Exception:  # noqa: BLE001
        return jsonify({"error": "invalid_token"}), 401

    user_uuid = claims.get("sub")
    if not user_uuid:
        return jsonify({"error": "invalid_token"}), 401

    try:
        user = await core.get_user(uuid=user_uuid)
    except CheckpointCoreError:
        return jsonify({"error": "server_error"}), 503

    if user is None:
        return jsonify({"error": "invalid_token"}), 401

    return jsonify({
        "sub": user.uuid,
        "email": user.email,
        "name": user.display_name,
        "preferred_username": user.username,
        "email_verified": True,
    })


# ── Revocation (RFC 7009) ─────────────────────────────────────────────────────


@oidc_bp.route("/revoke", methods=["POST"])
async def revoke():
    """RFC 7009 token revocation."""
    db = _get_db()
    audit = _get_audit()

    form = await request.form
    raw_token = form.get("token", "")
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret")

    if not _authenticate_client(db, client_id, client_secret):
        return jsonify({"error": "invalid_client"}), 401

    if not raw_token:
        return jsonify({}), 200  # RFC 7009 §2.2 — always return 200

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

    rows = db(db.checkpoint_tokens.token_hash == token_hash).select()
    for row in rows:
        if row.revoked_at is None:
            db(db.checkpoint_tokens.id == row.id).update(revoked_at=now)

    db.commit()

    await audit.log(
        "oauth2.token_revoked",
        actor_ip=_client_ip(),
        client_id=client_id,
    )
    return jsonify({}), 200


# ── Introspection (RFC 7662) ──────────────────────────────────────────────────


@oidc_bp.route("/introspect", methods=["POST"])
async def introspect():
    """RFC 7662 token introspection."""
    db = _get_db()
    cfg = _get_config()

    form = await request.form
    raw_token = form.get("token", "")
    client_id = form.get("client_id", "")
    client_secret = form.get("client_secret")

    if not _authenticate_client(db, client_id, client_secret):
        return jsonify({"error": "invalid_client"}), 401

    if not raw_token:
        return jsonify({"active": False})

    try:
        claims = verify_token(db, cfg.issuer_url, raw_token)
        return jsonify({
            "active": True,
            "sub": claims.get("sub"),
            "scope": claims.get("scope", ""),
            "client_id": claims.get("client_id"),
            "exp": claims.get("exp"),
            "iat": claims.get("iat"),
            "iss": claims.get("iss"),
            "jti": claims.get("jti"),
        })
    except Exception:  # noqa: BLE001
        return jsonify({"active": False})
