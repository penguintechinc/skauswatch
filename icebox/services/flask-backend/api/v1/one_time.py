"""
IceBox One-Time Secrets API — Phase 4

Create secrets that self-destruct on first view.

Routes:
    POST /one-time-secrets            → create (secrets:write)
    GET  /one-time-secrets/{token}    → retrieve (no auth — token IS the credential)

Security:
  - Token is URL-safe random bytes, SHA-256 hash stored in DB
  - viewed_at set atomically before returning value (race-condition safe via DB)
  - 410 Gone on second access or after TTL expiry
"""

from __future__ import annotations

import hashlib
import logging
import os
import secrets as secrets_module
from datetime import datetime, timedelta
from uuid import uuid4

from quart import Blueprint, current_app, g, jsonify, request

from api.v1.auth import auth_required, require_scope
from models.db import get_db

logger = logging.getLogger(__name__)
bp = Blueprint("one_time", __name__)


def _generate_token() -> tuple[str, str]:
    """Generate URL-safe token and its SHA-256 hash."""
    token = secrets_module.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token, token_hash


@bp.route("", methods=["POST"])
@auth_required
@require_scope("secrets:write")
async def create_one_time_secret():
    """Create a one-time viewable secret."""
    config = current_app.config["ICEBOX_CONFIG"]
    enc = current_app.config["ENVELOPE_ENC"]
    db = get_db(config.database.uri, config.database.pool_size)

    body = await request.get_json() or {}
    value = body.get("value", "").strip()
    if not value:
        return jsonify({"error": "value is required"}), 400

    ttl_seconds = int(body.get("ttl_seconds", 86400))  # Default: 24 hours
    if ttl_seconds < 60 or ttl_seconds > 604800:  # 1 min to 7 days
        return jsonify({"error": "ttl_seconds must be between 60 and 604800"}), 400

    encrypted_value, encrypted_dek, dek_version = enc.encrypt(value)
    token, token_hash = _generate_token()
    secret_id = str(uuid4())
    expires_at = datetime.utcnow() + timedelta(seconds=ttl_seconds)

    db.icebox_one_time_secrets.insert(
        id=secret_id,
        token_hash=token_hash,
        encrypted_value=encrypted_value,
        encrypted_dek=encrypted_dek,
        dek_version=dek_version,
        expires_at=expires_at,
        created_by=g.user_id,
        created_at=datetime.utcnow(),
    )
    db.commit()

    # Build view URL using request host
    view_url = f"{request.scheme}://{request.host}/api/v1/one-time-secrets/{token}"

    return jsonify({
        "id": secret_id,
        "view_url": view_url,
        "expires_at": expires_at.isoformat(),
        "ttl_seconds": ttl_seconds,
    }), 201


@bp.route("/<token>", methods=["GET"])
async def retrieve_one_time_secret(token: str):
    """
    Retrieve and consume a one-time secret.

    No authentication required — the token itself is the credential.
    Returns 410 Gone if already viewed or expired.
    """
    config = current_app.config["ICEBOX_CONFIG"]
    enc = current_app.config["ENVELOPE_ENC"]
    db = get_db(config.database.uri, config.database.pool_size)

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    row = db(db.icebox_one_time_secrets.token_hash == token_hash).select().first()
    if not row:
        return jsonify({"error": "Not found"}), 404

    # Check expiry
    if row.expires_at and row.expires_at < datetime.utcnow():
        return jsonify({"error": "This secret has expired"}), 410

    # Check already viewed
    if row.viewed_at is not None:
        return jsonify({"error": "This secret has already been viewed"}), 410

    # Mark viewed atomically before decrypting and returning
    updated = db(
        (db.icebox_one_time_secrets.token_hash == token_hash)
        & (db.icebox_one_time_secrets.viewed_at == None)
    ).update(viewed_at=datetime.utcnow())
    db.commit()

    if not updated:
        # Race condition: another request already consumed it
        return jsonify({"error": "This secret has already been viewed"}), 410

    try:
        plaintext = enc.decrypt(row.encrypted_value, row.encrypted_dek, row.dek_version)
    except Exception as exc:
        logger.error("Decryption failed for one-time secret: %s", exc)
        return jsonify({"error": "Decryption failed"}), 500

    return jsonify({
        "value": plaintext,
        "retrieved_at": datetime.utcnow().isoformat(),
    })
