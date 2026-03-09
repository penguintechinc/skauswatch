"""
IceBox Secrets API — Phase 2

CRUD operations for secrets with envelope encryption, versioning, and owner management.
All values are stored encrypted; plaintext is only returned on /value endpoint.

Routes:
    GET    /secrets                    → list (secrets:read)
    POST   /secrets                    → create (secrets:write)
    GET    /secrets/{id}               → get metadata (secrets:read)
    PUT    /secrets/{id}               → update (secrets:write)
    DELETE /secrets/{id}               → delete (secrets:delete)
    GET    /secrets/{id}/value         → get plaintext (secrets:read OR valid JIT token)
    GET    /secrets/{id}/versions      → version history (secrets:read)
    POST   /secrets/{id}/rotate        → rotate value (secrets:write)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from datetime import datetime
from typing import Any, Dict
from uuid import uuid4

from quart import Blueprint, current_app, g, jsonify, request

from api.v1.auth import auth_required, require_scope
from models.db import get_db

logger = logging.getLogger(__name__)
bp = Blueprint("secrets", __name__)


def _secret_to_dict(secret: Any, include_value: bool = False) -> Dict:
    """Convert PyDAL row to response dict (never includes raw encrypted fields)."""
    return {
        "id": secret.id,
        "name": secret.name,
        "description": secret.description,
        "secret_type": secret.secret_type,
        "tags": secret.tags,
        "expires_at": secret.expires_at.isoformat() if secret.expires_at else None,
        "created_at": secret.created_at.isoformat() if secret.created_at else None,
        "updated_at": secret.updated_at.isoformat() if secret.updated_at else None,
        "created_by": secret.created_by,
    }


def _write_audit(db: Any, actor_id: str, action: str, resource_id: str, req) -> None:
    """Write an entry to icebox_audit_log."""
    db.icebox_audit_log.insert(
        id=str(uuid4()),
        actor_id=actor_id,
        action=action,
        resource_type="secret",
        resource_id=resource_id,
        ip_address=req.remote_addr,
        user_agent=req.headers.get("User-Agent", "")[:512],
        created_at=datetime.utcnow(),
    )
    db.commit()


@bp.route("", methods=["GET"])
@auth_required
@require_scope("secrets:read")
async def list_secrets():
    """List secrets (metadata only, no values)."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)
    offset = (page - 1) * per_page

    secret_type = request.args.get("type")
    query = db.icebox_secrets
    if secret_type:
        query = db.icebox_secrets.secret_type == secret_type

    rows = db(query).select(
        orderby=~db.icebox_secrets.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    return jsonify({
        "secrets": [_secret_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    })


@bp.route("", methods=["POST"])
@auth_required
@require_scope("secrets:write")
async def create_secret():
    """Create a new secret with envelope-encrypted value."""
    config = current_app.config["ICEBOX_CONFIG"]
    enc = current_app.config["ENVELOPE_ENC"]
    db = get_db(config.database.uri, config.database.pool_size)

    body = await request.get_json()
    if not body:
        return jsonify({"error": "Request body required"}), 400

    name = str(body.get("name", "")).strip()
    value = str(body.get("value", "")).strip()
    if not name or not value:
        return jsonify({"error": "name and value are required"}), 400

    secret_type = body.get("type", "api_key")
    valid_types = {
        "api_key", "db_password", "token", "cloud_credential",
        "service_account", "certificate", "ssh_key",
    }
    if secret_type not in valid_types:
        return jsonify({"error": f"Invalid type. Must be one of: {', '.join(sorted(valid_types))}"}), 400

    encrypted_value, encrypted_dek, dek_version = enc.encrypt(value)
    secret_id = str(uuid4())
    now = datetime.utcnow()

    db.icebox_secrets.insert(
        id=secret_id,
        name=name,
        description=body.get("description", ""),
        secret_type=secret_type,
        encrypted_value=encrypted_value,
        encrypted_dek=encrypted_dek,
        dek_version=dek_version,
        tags=body.get("tags"),
        secret_metadata=body.get("metadata"),
        expires_at=body.get("expires_at"),
        created_at=now,
        updated_at=now,
        created_by=g.user_id,
    )

    # Create initial version record
    db.icebox_secret_versions.insert(
        id=str(uuid4()),
        secret_id=secret_id,
        version_number=1,
        encrypted_value=encrypted_value,
        encrypted_dek=encrypted_dek,
        dek_version=dek_version,
        created_by=g.user_id,
        created_at=now,
    )

    # Auto-assign creator as owner
    db.icebox_secret_owners.insert(
        secret_id=secret_id,
        owner_type="user",
        owner_id=g.user_id,
    )

    db.commit()
    _write_audit(db, g.user_id, "secret.create", secret_id, request)

    secret = db(db.icebox_secrets.id == secret_id).select().first()
    return jsonify(_secret_to_dict(secret)), 201


@bp.route("/<secret_id>", methods=["GET"])
@auth_required
@require_scope("secrets:read")
async def get_secret(secret_id: str):
    """Get secret metadata (no value)."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    secret = db(db.icebox_secrets.id == secret_id).select().first()
    if not secret:
        return jsonify({"error": "Not found"}), 404

    return jsonify(_secret_to_dict(secret))


@bp.route("/<secret_id>", methods=["PUT"])
@auth_required
@require_scope("secrets:write")
async def update_secret(secret_id: str):
    """Update secret metadata (NOT the value — use /rotate for value changes)."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    secret = db(db.icebox_secrets.id == secret_id).select().first()
    if not secret:
        return jsonify({"error": "Not found"}), 404

    body = await request.get_json() or {}
    updates: Dict = {}

    if "name" in body:
        updates["name"] = str(body["name"]).strip()
    if "description" in body:
        updates["description"] = body["description"]
    if "tags" in body:
        updates["tags"] = body["tags"]
    if "expires_at" in body:
        updates["expires_at"] = body["expires_at"]
    if "metadata" in body:
        updates["secret_metadata"] = body["metadata"]

    updates["updated_at"] = datetime.utcnow()
    db(db.icebox_secrets.id == secret_id).update(**updates)
    db.commit()
    _write_audit(db, g.user_id, "secret.update", secret_id, request)

    secret = db(db.icebox_secrets.id == secret_id).select().first()
    return jsonify(_secret_to_dict(secret))


@bp.route("/<secret_id>", methods=["DELETE"])
@auth_required
@require_scope("secrets:delete")
async def delete_secret(secret_id: str):
    """Delete a secret and all associated records."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    secret = db(db.icebox_secrets.id == secret_id).select().first()
    if not secret:
        return jsonify({"error": "Not found"}), 404

    _write_audit(db, g.user_id, "secret.delete", secret_id, request)
    db(db.icebox_secrets.id == secret_id).delete()
    db.commit()

    return "", 204


@bp.route("/<secret_id>/value", methods=["GET"])
async def get_secret_value(secret_id: str):
    """
    Get decrypted secret value.

    Accepts either a standard JWT (secrets:read scope) or a JIT token
    (scoped to this specific secret for the current user).
    """
    config = current_app.config["ICEBOX_CONFIG"]
    enc = current_app.config["ENVELOPE_ENC"]
    db = get_db(config.database.uri, config.database.pool_size)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization required"}), 401

    token = auth_header.removeprefix("Bearer ").strip()

    # Try JIT token first (HMAC-signed, not a full JWT)
    jit_valid = await _validate_jit_token(token, secret_id, db, config)

    if not jit_valid:
        # Fall back to standard JWT + scope check
        import jwt as pyjwt
        try:
            claims = pyjwt.decode(
                token,
                config.auth.jwt_secret,
                algorithms=[config.auth.jwt_algorithm],
                options={"require": ["sub", "exp", "scope"]},
            )
        except pyjwt.InvalidTokenError:
            return jsonify({"error": "Invalid or expired token"}), 401

        scopes = set(claims.get("scope", "").split())
        if "secrets:read" not in scopes:
            return jsonify({"error": "Insufficient scope"}), 403

        actor_id = claims.get("sub", "unknown")
    else:
        actor_id = jit_valid

    secret = db(db.icebox_secrets.id == secret_id).select().first()
    if not secret:
        return jsonify({"error": "Not found"}), 404

    try:
        plaintext = enc.decrypt(
            secret.encrypted_value,
            secret.encrypted_dek,
            secret.dek_version,
        )
    except Exception as exc:
        logger.error("Decryption failed for secret %s: %s", secret_id, exc)
        return jsonify({"error": "Decryption failed"}), 500

    _write_audit(db, actor_id, "secret.value.read", secret_id, request)

    return jsonify({
        "id": secret_id,
        "name": secret.name,
        "value": plaintext,
        "retrieved_at": datetime.utcnow().isoformat(),
    })


async def _validate_jit_token(token: str, secret_id: str, db, config) -> str | None:
    """
    Validate a JIT access token. Returns grantee_id on success, None on failure.

    JIT tokens are HMAC-SHA256 signed strings encoding:
    grant_id:secret_id:grantee_id:expires_epoch
    """
    import hashlib as hl
    import time

    try:
        parts = token.split(":")
        if len(parts) != 4 or parts[0] != "jit":
            return None

        _, grant_id, grantee_id, expires_str = parts
        expires_epoch = int(expires_str)

        if time.time() > expires_epoch:
            return None

        # Check the grant exists and is not revoked, and matches secret_id
        grant = db(
            (db.icebox_jit_grants.id == grant_id)
            & (db.icebox_jit_grants.secret_id == secret_id)
            & (db.icebox_jit_grants.grantee_id == grantee_id)
            & (db.icebox_jit_grants.revoked_at == None)
        ).select().first()

        if not grant:
            return None

        if grant.expires_at and grant.expires_at < datetime.utcnow():
            return None

        # Verify HMAC signature stored in grant
        token_hash = hl.sha256(token.encode()).hexdigest()
        if token_hash != grant.access_token_hash:
            return None

        return grantee_id
    except (ValueError, AttributeError):
        return None


@bp.route("/<secret_id>/versions", methods=["GET"])
@auth_required
@require_scope("secrets:read")
async def list_secret_versions(secret_id: str):
    """List version history for a secret (metadata only, no values)."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    secret = db(db.icebox_secrets.id == secret_id).select().first()
    if not secret:
        return jsonify({"error": "Not found"}), 404

    versions = db(
        db.icebox_secret_versions.secret_id == secret_id
    ).select(orderby=~db.icebox_secret_versions.version_number)

    return jsonify({
        "secret_id": secret_id,
        "versions": [
            {
                "id": v.id,
                "version_number": v.version_number,
                "created_by": v.created_by,
                "created_at": v.created_at.isoformat() if v.created_at else None,
                "deprecated_at": v.deprecated_at.isoformat() if v.deprecated_at else None,
            }
            for v in versions
        ],
    })


@bp.route("/<secret_id>/rotate", methods=["POST"])
@auth_required
@require_scope("secrets:write")
async def rotate_secret(secret_id: str):
    """Rotate secret value — creates a new version, deprecates old."""
    config = current_app.config["ICEBOX_CONFIG"]
    enc = current_app.config["ENVELOPE_ENC"]
    db = get_db(config.database.uri, config.database.pool_size)

    secret = db(db.icebox_secrets.id == secret_id).select().first()
    if not secret:
        return jsonify({"error": "Not found"}), 404

    body = await request.get_json() or {}
    new_value = body.get("value", "").strip()
    if not new_value:
        return jsonify({"error": "value is required for rotation"}), 400

    # Deprecate old version
    db(
        (db.icebox_secret_versions.secret_id == secret_id)
        & (db.icebox_secret_versions.deprecated_at == None)
    ).update(deprecated_at=datetime.utcnow())

    # Encrypt new value
    encrypted_value, encrypted_dek, dek_version = enc.encrypt(new_value)
    now = datetime.utcnow()

    # Get next version number
    latest = db(
        db.icebox_secret_versions.secret_id == secret_id
    ).select(
        db.icebox_secret_versions.version_number.max()
    ).first()
    next_version = (latest[db.icebox_secret_versions.version_number.max()] or 0) + 1

    # Insert new version
    db.icebox_secret_versions.insert(
        id=str(uuid4()),
        secret_id=secret_id,
        version_number=next_version,
        encrypted_value=encrypted_value,
        encrypted_dek=encrypted_dek,
        dek_version=dek_version,
        created_by=g.user_id,
        created_at=now,
    )

    # Update current secret
    db(db.icebox_secrets.id == secret_id).update(
        encrypted_value=encrypted_value,
        encrypted_dek=encrypted_dek,
        dek_version=dek_version,
        updated_at=now,
    )
    db.commit()
    _write_audit(db, g.user_id, "secret.rotate", secret_id, request)

    return jsonify({"id": secret_id, "version": next_version, "rotated_at": now.isoformat()})
