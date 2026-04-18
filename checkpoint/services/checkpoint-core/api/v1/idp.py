"""
checkpoint-core — Upstream Identity Provider (IDP) management REST API.

Blueprint: idp_bp, prefix /api/v1/idps

All endpoints require scope: checkpoint:idps:admin

IDP config_json is AES-256-GCM encrypted at rest. The encrypted blob is
stored in config_json_encrypted as JSON:
  {"dek_encrypted": "<b64>", "nonce": "<b64>", "ciphertext": "<b64>"}

The DEK is AES-256 wrapped with the MEK (CHECKPOINT_SIGNING_MEK env var,
same key used for signing-key protection). Decrypted config is never
returned to callers.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from datetime import datetime, timezone
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from quart import Blueprint, current_app, jsonify, request

from audit.logger import AuditLogger
from oidc.jwt_utils import verify_token

logger = logging.getLogger(__name__)

idp_bp = Blueprint("idps", __name__, url_prefix="/api/v1/idps")

# Supported IDP types
_VALID_IDP_TYPES: frozenset[str] = frozenset({"oidc", "saml", "ldap", "google", "okta"})
_VALID_FEDERATION_MODES: frozenset[str] = frozenset({"sync", "proxy"})


# ── App extension helpers ──────────────────────────────────────────────────────


def _get_db() -> Any:
    return current_app.extensions["checkpoint_db"]


def _get_config() -> Any:
    return current_app.extensions["checkpoint_config"]


def _get_audit() -> AuditLogger:
    return current_app.extensions["checkpoint_audit"]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


async def _get_token_claims() -> dict[str, Any] | None:
    db = _get_db()
    cfg = _get_config()
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return verify_token(db, cfg.issuer_url, auth[7:])
    except Exception:  # noqa: BLE001
        return None


def require_idp_admin(fn):  # type: ignore[return]
    """Decorator enforcing checkpoint:idps:admin scope."""
    import functools

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        claims = await _get_token_claims()
        if claims is None:
            return jsonify({"error": "unauthorized"}), 401
        scopes = set((claims.get("scope") or "").split())
        if "checkpoint:idps:admin" not in scopes and "checkpoint:admin" not in scopes:
            return jsonify({"error": "insufficient_scope"}), 403
        return await fn(*args, **kwargs)

    return wrapper


# ── Encryption helpers ─────────────────────────────────────────────────────────


def _load_mek() -> bytes:
    """
    Load the Master Encryption Key from CHECKPOINT_SIGNING_MEK env var.

    The MEK is base64-encoded 32-byte key (256-bit AES).
    Raises RuntimeError if missing or wrong size.
    """
    raw = os.environ.get("CHECKPOINT_SIGNING_MEK", "")
    if not raw:
        raise RuntimeError("CHECKPOINT_SIGNING_MEK environment variable is not set")
    mek = base64.b64decode(raw)
    if len(mek) != 32:
        raise RuntimeError(
            f"CHECKPOINT_SIGNING_MEK must decode to 32 bytes, got {len(mek)}"
        )
    return mek


def _encrypt_config(config_json: str) -> str:
    """
    Encrypt config_json string with AES-256-GCM envelope encryption.

    1. Generate a random 32-byte DEK.
    2. Encrypt config_json with DEK using AES-256-GCM.
    3. Encrypt (wrap) DEK with MEK using AES-256-GCM.
    4. Return JSON blob: {dek_encrypted, dek_nonce, nonce, ciphertext}.

    Returns a JSON string suitable for storage.
    """
    mek = _load_mek()
    dek = secrets.token_bytes(32)

    # Encrypt DEK with MEK
    dek_nonce = secrets.token_bytes(12)
    mek_aes = AESGCM(mek)
    dek_encrypted = mek_aes.encrypt(dek_nonce, dek, None)

    # Encrypt plaintext with DEK
    data_nonce = secrets.token_bytes(12)
    dek_aes = AESGCM(dek)
    ciphertext = dek_aes.encrypt(data_nonce, config_json.encode(), None)

    envelope = {
        "dek_encrypted": base64.b64encode(dek_encrypted).decode(),
        "dek_nonce": base64.b64encode(dek_nonce).decode(),
        "nonce": base64.b64encode(data_nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }
    return json.dumps(envelope)


def _decrypt_config(encrypted_blob: str) -> str:
    """
    Decrypt config JSON from the envelope blob.

    Reverses _encrypt_config. Returns the plaintext config JSON string.
    """
    mek = _load_mek()
    envelope = json.loads(encrypted_blob)

    dek_encrypted = base64.b64decode(envelope["dek_encrypted"])
    dek_nonce = base64.b64decode(envelope["dek_nonce"])
    data_nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])

    # Decrypt DEK
    mek_aes = AESGCM(mek)
    dek = mek_aes.decrypt(dek_nonce, dek_encrypted, None)

    # Decrypt data
    dek_aes = AESGCM(dek)
    plaintext = dek_aes.decrypt(data_nonce, ciphertext, None)
    return plaintext.decode()


# ── Validation helpers ─────────────────────────────────────────────────────────


def _validate_idp_config(idp_type: str, config: dict[str, Any]) -> list[str]:
    """
    Validate IDP configuration by type.

    Returns a list of validation error messages (empty = valid).
    """
    errors: list[str] = []
    if idp_type == "oidc":
        for field in ("issuer_url", "client_id", "client_secret"):
            if not config.get(field):
                errors.append(f"oidc config requires '{field}'")
    elif idp_type == "ldap":
        for field in ("host", "port", "bind_dn", "bind_password", "base_dn"):
            if not config.get(field):
                errors.append(f"ldap config requires '{field}'")
    elif idp_type == "saml":
        for field in ("entity_id", "sso_url", "x509_cert"):
            if not config.get(field):
                errors.append(f"saml config requires '{field}'")
    elif idp_type == "google":
        for field in ("service_account_json", "admin_email", "domain"):
            if not config.get(field):
                errors.append(f"google config requires '{field}'")
    elif idp_type == "okta":
        for field in ("domain", "api_token"):
            if not config.get(field):
                errors.append(f"okta config requires '{field}'")
    return errors


# ── Serialiser ────────────────────────────────────────────────────────────────


def _serialise_idp(row: Any) -> dict[str, Any]:
    """Safe IDP dict — never includes decrypted config_json."""
    return {
        "id": row.id,
        "name": row.name,
        "type": row.type,
        "federation_mode": row.federation_mode,
        "sync_interval_secs": row.sync_interval_secs,
        "is_active": bool(row.is_active),
        "last_sync_at": row.last_sync_at.isoformat() + "Z" if row.last_sync_at else None,
        "sync_error": row.sync_error or None,
        "created_at": row.created_at.isoformat() + "Z" if row.created_at else None,
        "updated_at": row.updated_at.isoformat() + "Z" if row.updated_at else None,
    }


# ── Endpoints ─────────────────────────────────────────────────────────────────


@idp_bp.route("", methods=["GET"])
@require_idp_admin
async def list_idps() -> Any:
    """List all upstream IDPs."""
    db = _get_db()
    rows = db(db.checkpoint_upstream_idps).select(
        orderby=db.checkpoint_upstream_idps.name
    )
    return jsonify([_serialise_idp(r) for r in rows])


@idp_bp.route("", methods=["POST"])
@require_idp_admin
async def create_idp() -> Any:
    """
    Register a new upstream IDP.

    Required body:
      name            — display name
      type            — oidc | saml | ldap | google | okta
      config          — dict with type-specific fields (will be encrypted)

    Optional:
      federation_mode — sync | proxy (default: sync)
      sync_interval_secs — seconds between syncs (default: 3600)
    """
    db = _get_db()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    data = await request.get_json() or {}
    name: str = (data.get("name") or "").strip()
    idp_type: str = (data.get("type") or "").lower().strip()
    config: dict[str, Any] = data.get("config") or {}
    federation_mode: str = (data.get("federation_mode") or "sync").lower().strip()
    sync_interval: int = int(data.get("sync_interval_secs") or 3600)

    if not name:
        return jsonify({"error": "name is required"}), 400
    if idp_type not in _VALID_IDP_TYPES:
        return jsonify({"error": f"type must be one of: {sorted(_VALID_IDP_TYPES)}"}), 400
    if federation_mode not in _VALID_FEDERATION_MODES:
        return jsonify({"error": f"federation_mode must be one of: {sorted(_VALID_FEDERATION_MODES)}"}), 400
    if not config:
        return jsonify({"error": "config is required"}), 400

    validation_errors = _validate_idp_config(idp_type, config)
    if validation_errors:
        return jsonify({"error": "invalid config", "details": validation_errors}), 400

    # Encrypt config JSON
    try:
        encrypted_blob = _encrypt_config(json.dumps(config))
    except RuntimeError as exc:
        logger.error("create_idp.encryption_failed error=%r", exc)
        return jsonify({"error": "server configuration error — MEK not available"}), 500

    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    row_id = db.checkpoint_upstream_idps.insert(
        name=name,
        type=idp_type,
        federation_mode=federation_mode,
        sync_interval_secs=sync_interval,
        config_json_encrypted=encrypted_blob,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    db.commit()

    await audit.log(
        "idp.created",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_type="upstream_idp",
        details={"name": name, "type": idp_type, "federation_mode": federation_mode},
    )

    row = db(db.checkpoint_upstream_idps.id == row_id).select().first()
    return jsonify(_serialise_idp(row)), 201


@idp_bp.route("/<int:idp_id>", methods=["GET"])
@require_idp_admin
async def get_idp(idp_id: int) -> Any:
    """Get an IDP by ID. Does NOT return decrypted config_json."""
    db = _get_db()
    row = db(db.checkpoint_upstream_idps.id == idp_id).select().first()
    if row is None:
        return jsonify({"error": "not found"}), 404
    return jsonify(_serialise_idp(row))


@idp_bp.route("/<int:idp_id>", methods=["PUT"])
@require_idp_admin
async def update_idp(idp_id: int) -> Any:
    """
    Update an IDP. If 'config' key is present, re-encrypts the config.
    """
    db = _get_db()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    row = db(db.checkpoint_upstream_idps.id == idp_id).select().first()
    if row is None:
        return jsonify({"error": "not found"}), 404

    data = await request.get_json() or {}
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    updates: dict[str, Any] = {"updated_at": now}

    if "name" in data:
        updates["name"] = (data["name"] or "").strip()
    if "federation_mode" in data:
        fm = (data["federation_mode"] or "").lower()
        if fm not in _VALID_FEDERATION_MODES:
            return jsonify({"error": f"federation_mode must be one of: {sorted(_VALID_FEDERATION_MODES)}"}), 400
        updates["federation_mode"] = fm
    if "sync_interval_secs" in data:
        updates["sync_interval_secs"] = int(data["sync_interval_secs"])
    if "is_active" in data:
        updates["is_active"] = bool(data["is_active"])
    if "config" in data:
        config = data["config"] or {}
        validation_errors = _validate_idp_config(row.type, config)
        if validation_errors:
            return jsonify({"error": "invalid config", "details": validation_errors}), 400
        try:
            updates["config_json_encrypted"] = _encrypt_config(json.dumps(config))
        except RuntimeError as exc:
            logger.error("update_idp.encryption_failed error=%r", exc)
            return jsonify({"error": "server configuration error — MEK not available"}), 500

    db(db.checkpoint_upstream_idps.id == idp_id).update(**updates)
    db.commit()

    await audit.log(
        "idp.updated",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_type="upstream_idp",
        details={"idp_id": idp_id, "fields_updated": list(updates.keys())},
    )

    updated_row = db(db.checkpoint_upstream_idps.id == idp_id).select().first()
    return jsonify(_serialise_idp(updated_row))


@idp_bp.route("/<int:idp_id>", methods=["DELETE"])
@require_idp_admin
async def delete_idp(idp_id: int) -> Any:
    """Soft-delete an IDP by setting is_active=False."""
    db = _get_db()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    row = db(db.checkpoint_upstream_idps.id == idp_id).select().first()
    if row is None:
        return jsonify({"error": "not found"}), 404

    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
    db(db.checkpoint_upstream_idps.id == idp_id).update(is_active=False, updated_at=now)
    db.commit()

    await audit.log(
        "idp.deleted",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_type="upstream_idp",
        details={"idp_id": idp_id, "name": row.name},
    )

    return jsonify({"status": "deleted"}), 200


@idp_bp.route("/<int:idp_id>/sync", methods=["POST"])
@require_idp_admin
async def trigger_sync(idp_id: int) -> Any:
    """
    Trigger an immediate manual sync for the given IDP.

    Forces last_sync_at to None so the background sync loop picks it up
    on the next tick (within 60 seconds).
    """
    db = _get_db()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    row = db(db.checkpoint_upstream_idps.id == idp_id).select().first()
    if row is None:
        return jsonify({"error": "not found"}), 404
    if not row.is_active:
        return jsonify({"error": "IDP is inactive"}), 400
    if row.type == "saml" and row.federation_mode == "sync":
        return jsonify({"error": "SAML IDPs do not support sync mode"}), 400

    # Reset last_sync_at so the background loop picks it up immediately
    db(db.checkpoint_upstream_idps.id == idp_id).update(last_sync_at=None, sync_error=None)
    db.commit()

    await audit.log(
        "idp.sync_triggered",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_type="upstream_idp",
        details={"idp_id": idp_id, "name": row.name},
    )

    return jsonify({"status": "sync_queued", "idp_id": idp_id}), 202
