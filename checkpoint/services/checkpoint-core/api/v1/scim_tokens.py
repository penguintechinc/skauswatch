"""
checkpoint-core — SCIM token management API.

Blueprint: scim_tokens_bp, prefix /api/v1/scim

Allows admins to create and revoke SCIM provisioning tokens.
SCIM tokens are Bearer tokens stored as SHA-256 hashes in
checkpoint_scim_tokens.

Scopes required:
  checkpoint:admin  — create/revoke tokens
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from quart import Blueprint, current_app, jsonify, request

from audit.logger import AuditLogger
from oidc.jwt_utils import verify_token

logger = logging.getLogger(__name__)

scim_tokens_bp = Blueprint("scim_tokens", __name__, url_prefix="/api/v1/scim")

_TOKEN_BYTES = 32  # 256-bit raw token


# ── App extension helpers ──────────────────────────────────────────────────────


def _get_db() -> Any:
    return current_app.extensions["checkpoint_db"]


def _get_config() -> Any:
    return current_app.extensions["checkpoint_config"]


def _get_audit() -> AuditLogger:
    return current_app.extensions["checkpoint_audit"]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


# ── Auth helper ────────────────────────────────────────────────────────────────


async def _get_token_claims() -> dict[str, Any] | None:
    """Extract and verify Bearer JWT from Authorization header."""
    db = _get_db()
    cfg = _get_config()
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    raw_token = auth[7:]
    try:
        return verify_token(db, cfg.issuer_url, raw_token)
    except Exception:  # noqa: BLE001
        return None


def _require_admin_scope():  # type: ignore[return]
    """Decorator: require checkpoint:admin scope."""
    import functools

    def decorator(fn):  # type: ignore[return]
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            claims = await _get_token_claims()
            if claims is None:
                return jsonify({"error": "unauthorized"}), 401
            token_scopes = set((claims.get("scope") or "").split())
            if "checkpoint:admin" not in token_scopes:
                return jsonify({"error": "insufficient_scope — checkpoint:admin required"}), 403
            return await fn(*args, **kwargs)

        return wrapper

    return decorator


# ── Endpoints ─────────────────────────────────────────────────────────────────


@scim_tokens_bp.route("/tokens", methods=["POST"])
@_require_admin_scope()
async def create_scim_token() -> Any:
    """
    Create a new SCIM provisioning token.

    Body (JSON):
      name        — string (required) — human-readable label
      scopes      — string (optional) — space-separated scopes
                    default: "scim:users:read scim:users:write scim:groups:read scim:groups:write"
      expires_at  — ISO8601 string (optional) — token expiry

    Returns:
      token       — the raw bearer token value (shown only once)
      token_id    — DB row ID for reference
      name        — label
      scopes      — scopes string
      expires_at  — expiry or null
    """
    db = _get_db()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    data = await request.get_json() or {}
    name: str = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    scopes: str = (data.get("scopes") or "scim:users:read scim:users:write scim:groups:read scim:groups:write").strip()
    expires_at_raw: str | None = data.get("expires_at")

    expires_at: datetime | None = None
    if expires_at_raw:
        try:
            expires_at = datetime.fromisoformat(expires_at_raw.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, TypeError):
            return jsonify({"error": "expires_at must be a valid ISO8601 datetime"}), 400

    # Generate cryptographically random token
    raw_token = secrets.token_urlsafe(_TOKEN_BYTES)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

    try:
        token_id = db.checkpoint_scim_tokens.insert(
            token_hash=token_hash,
            name=name,
            scopes=scopes,
            created_by_uuid=actor_uuid,
            expires_at=expires_at,
            revoked_at=None,
            created_at=now,
        )
        db.commit()
    except Exception as exc:
        logger.error("scim_tokens.create.db_error error=%r", exc)
        return jsonify({"error": "failed to create token"}), 500

    await audit.log(
        "scim.token_created",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        details={"name": name, "scopes": scopes},
    )

    logger.info("scim_token.created name=%s actor=%s", name, actor_uuid)

    return jsonify({
        "token": raw_token,  # Shown once — cannot be retrieved again
        "token_id": int(token_id),
        "name": name,
        "scopes": scopes,
        "expires_at": expires_at.isoformat() + "Z" if expires_at else None,
        "created_at": now.isoformat() + "Z",
    }), 201


@scim_tokens_bp.route("/tokens", methods=["GET"])
@_require_admin_scope()
async def list_scim_tokens() -> Any:
    """
    List all SCIM tokens (metadata only — token values not retrievable).

    Returns id, name, scopes, expires_at, revoked_at, created_at for each token.
    """
    db = _get_db()

    rows = db(db.checkpoint_scim_tokens.id > 0).select(
        orderby=~db.checkpoint_scim_tokens.created_at
    )

    return jsonify({
        "tokens": [
            {
                "token_id": int(r.id),
                "name": r.name,
                "scopes": r.scopes,
                "expires_at": r.expires_at.isoformat() + "Z" if r.expires_at else None,
                "revoked_at": r.revoked_at.isoformat() + "Z" if r.revoked_at else None,
                "created_at": r.created_at.isoformat() + "Z" if r.created_at else None,
                "created_by_uuid": r.created_by_uuid,
            }
            for r in rows
        ]
    })


@scim_tokens_bp.route("/tokens/<int:token_id>", methods=["DELETE"])
@_require_admin_scope()
async def revoke_scim_token(token_id: int) -> Any:
    """Revoke a SCIM token by ID."""
    db = _get_db()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    row = db(db.checkpoint_scim_tokens.id == token_id).select().first()
    if row is None:
        return jsonify({"error": "token not found"}), 404

    if row.revoked_at is not None:
        return jsonify({"error": "token already revoked"}), 409

    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    db(db.checkpoint_scim_tokens.id == token_id).update(revoked_at=now)
    db.commit()

    await audit.log(
        "scim.token_revoked",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        details={"token_id": token_id, "name": row.name},
    )

    logger.info("scim_token.revoked token_id=%d actor=%s", token_id, actor_uuid)

    return jsonify({"status": "revoked", "token_id": token_id})
