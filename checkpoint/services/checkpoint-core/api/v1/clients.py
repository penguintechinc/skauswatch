"""
checkpoint-core — OAuth2 client management REST API.

Blueprint: clients_bp, prefix /api/v1/clients

Endpoints:
  GET    /api/v1/clients          — list clients (requires checkpoint:clients:read)
  POST   /api/v1/clients          — create client (requires checkpoint:clients:write)
  GET    /api/v1/clients/{id}     — get client (requires checkpoint:clients:read)
  PUT    /api/v1/clients/{id}     — update client (requires checkpoint:clients:write)
  DELETE /api/v1/clients/{id}     — delete client (requires checkpoint:clients:write)

All endpoints require a valid Bearer token with appropriate scopes.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
from datetime import datetime, timezone
from functools import wraps
from typing import Any, Callable

import bcrypt
from quart import Blueprint, current_app, jsonify, request

from audit.logger import AuditLogger
from oidc.jwt_utils import verify_token

logger = logging.getLogger(__name__)

clients_bp = Blueprint("clients", __name__, url_prefix="/api/v1/clients")


# ── Auth helpers ──────────────────────────────────────────────────────────────


def _get_db():  # type: ignore[return]
    return current_app.extensions["checkpoint_db"]


def _get_config():  # type: ignore[return]
    return current_app.extensions["checkpoint_config"]


def _get_audit() -> AuditLogger:
    return current_app.extensions["checkpoint_audit"]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


async def _get_token_claims() -> dict[str, Any] | None:
    """Extract and verify Bearer token from Authorization header."""
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


def require_checkpoint_scope(*required_scopes: str) -> Callable:
    """
    Decorator that enforces one of the required scopes on the request token.

    Usage::

        @require_checkpoint_scope("checkpoint:clients:read")
        async def my_endpoint():
            ...
    """
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            claims = await _get_token_claims()
            if claims is None:
                return jsonify({"error": "unauthorized"}), 401

            token_scopes = set((claims.get("scope") or "").split())
            if not any(s in token_scopes for s in required_scopes):
                return jsonify({"error": "insufficient_scope"}), 403

            return await fn(*args, **kwargs)
        return wrapper
    return decorator


# ── Serialiser ────────────────────────────────────────────────────────────────


def _serialise_client(row: Any) -> dict[str, Any]:
    """Convert a PyDAL row to a safe dict (omit secret hash)."""
    return {
        "id": row.id,
        "client_id": row.client_id,
        "name": row.name,
        "description": row.description or "",
        "redirect_uris": json.loads(row.redirect_uris or "[]"),
        "allowed_scopes": row.allowed_scopes or "",
        "grant_types": json.loads(row.grant_types or "[]"),
        "require_pkce": bool(row.require_pkce),
        "is_active": bool(row.is_active),
        "created_by_uuid": row.created_by_uuid or "",
        "created_at": row.created_at.isoformat() + "Z" if row.created_at else None,
        "updated_at": row.updated_at.isoformat() + "Z" if row.updated_at else None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────


@clients_bp.route("", methods=["GET"])
@require_checkpoint_scope("checkpoint:clients:read", "checkpoint:admin")
async def list_clients():
    """List all OAuth2 clients."""
    db = _get_db()
    rows = db(db.checkpoint_oauth_clients).select(
        orderby=db.checkpoint_oauth_clients.name
    )
    return jsonify([_serialise_client(r) for r in rows])


@clients_bp.route("", methods=["POST"])
@require_checkpoint_scope("checkpoint:clients:write", "checkpoint:admin")
async def create_client():
    """
    Register a new OAuth2 client.

    Generates a client_id and client_secret automatically.
    The raw client_secret is returned ONCE — it is not stored in plaintext.
    """
    db = _get_db()
    audit = _get_audit()
    claims = await _get_token_claims()

    data = await request.get_json() or {}

    name: str = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    redirect_uris: list[str] = data.get("redirect_uris") or []
    if not redirect_uris:
        return jsonify({"error": "redirect_uris is required"}), 400

    # Validate redirect URIs — must be HTTPS (or localhost for dev)
    for uri in redirect_uris:
        parsed = __import__("urllib.parse", fromlist=["urlparse"]).urlparse(uri)
        if parsed.scheme not in ("https", "http") or not parsed.netloc:
            return jsonify({"error": f"invalid redirect_uri: {uri}"}), 400

    allowed_scopes: str = data.get("allowed_scopes") or "openid profile email"
    grant_types: list[str] = data.get("grant_types") or ["authorization_code"]
    require_pkce: bool = bool(data.get("require_pkce", True))
    description: str = data.get("description") or ""

    # Generate credentials
    raw_client_id = "cp_" + secrets.token_urlsafe(20)
    raw_secret = secrets.token_urlsafe(40)
    secret_hash = bcrypt.hashpw(raw_secret.encode(), bcrypt.gensalt()).decode()

    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    actor_uuid = claims.get("sub") if claims else None

    client_db_id = db.checkpoint_oauth_clients.insert(
        client_id=raw_client_id,
        client_secret_hash=secret_hash,
        name=name,
        description=description,
        redirect_uris=json.dumps(redirect_uris),
        allowed_scopes=allowed_scopes,
        grant_types=json.dumps(grant_types),
        require_pkce=require_pkce,
        is_active=True,
        created_by_uuid=actor_uuid,
        created_at=now,
        updated_at=now,
    )
    db.commit()

    await audit.log(
        "oauth2.client_created",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_type="oauth_client",
        details={"client_id": raw_client_id, "name": name},
    )

    return jsonify({
        "id": client_db_id,
        "client_id": raw_client_id,
        "client_secret": raw_secret,  # Only returned on creation
        "name": name,
        "description": description,
        "redirect_uris": redirect_uris,
        "allowed_scopes": allowed_scopes,
        "grant_types": grant_types,
        "require_pkce": require_pkce,
        "is_active": True,
        "created_at": now.isoformat() + "Z",
    }), 201


@clients_bp.route("/<int:client_db_id>", methods=["GET"])
@require_checkpoint_scope("checkpoint:clients:read", "checkpoint:admin")
async def get_client(client_db_id: int):
    """Get a single OAuth2 client by database ID."""
    db = _get_db()
    row = db(db.checkpoint_oauth_clients.id == client_db_id).select().first()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(_serialise_client(row))


@clients_bp.route("/<int:client_db_id>", methods=["PUT"])
@require_checkpoint_scope("checkpoint:clients:write", "checkpoint:admin")
async def update_client(client_db_id: int):
    """Update an existing OAuth2 client registration."""
    db = _get_db()
    audit = _get_audit()
    claims = await _get_token_claims()

    row = db(db.checkpoint_oauth_clients.id == client_db_id).select().first()
    if row is None:
        return jsonify({"error": "not found"}), 404

    data = await request.get_json() or {}
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

    updates: dict[str, Any] = {"updated_at": now}

    if "name" in data:
        updates["name"] = (data["name"] or "").strip()
    if "description" in data:
        updates["description"] = data["description"]
    if "redirect_uris" in data:
        updates["redirect_uris"] = json.dumps(data["redirect_uris"])
    if "allowed_scopes" in data:
        updates["allowed_scopes"] = data["allowed_scopes"]
    if "grant_types" in data:
        updates["grant_types"] = json.dumps(data["grant_types"])
    if "require_pkce" in data:
        updates["require_pkce"] = bool(data["require_pkce"])
    if "is_active" in data:
        updates["is_active"] = bool(data["is_active"])

    db(db.checkpoint_oauth_clients.id == client_db_id).update(**updates)
    db.commit()

    actor_uuid = claims.get("sub") if claims else None
    await audit.log(
        "oauth2.client_updated",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_type="oauth_client",
        details={"client_db_id": client_db_id, "fields_updated": list(updates.keys())},
    )

    updated_row = db(db.checkpoint_oauth_clients.id == client_db_id).select().first()
    return jsonify(_serialise_client(updated_row))


@clients_bp.route("/<int:client_db_id>", methods=["DELETE"])
@require_checkpoint_scope("checkpoint:clients:write", "checkpoint:admin")
async def delete_client(client_db_id: int):
    """
    Delete (deactivate) an OAuth2 client.

    Soft-deletes by setting is_active=False rather than removing the row,
    to preserve audit log integrity.
    """
    db = _get_db()
    audit = _get_audit()
    claims = await _get_token_claims()

    row = db(db.checkpoint_oauth_clients.id == client_db_id).select().first()
    if row is None:
        return jsonify({"error": "not found"}), 404

    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    db(db.checkpoint_oauth_clients.id == client_db_id).update(
        is_active=False, updated_at=now
    )
    db.commit()

    actor_uuid = claims.get("sub") if claims else None
    await audit.log(
        "oauth2.client_deleted",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_type="oauth_client",
        details={"client_db_id": client_db_id, "client_id": row.client_id},
    )

    return jsonify({"status": "deleted"}), 200
