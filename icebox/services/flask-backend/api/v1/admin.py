"""
IceBox Admin API — Phase 5 (licensing) + MEK rotation

Routes:
    POST /admin/license               → set license key (vault_admin)
    GET  /admin/license               → get license status (vault_admin)
    POST /admin/mek/rotate            → rotate master encryption key (vault_admin)
"""

from __future__ import annotations

import logging
from datetime import datetime
from uuid import uuid4

from quart import Blueprint, current_app, g, jsonify, request

from api.v1.auth import auth_required, require_scope
from licensing.validator import LicenseValidator
from models.db import get_db

logger = logging.getLogger(__name__)
bp = Blueprint("admin", __name__)


@bp.route("/license", methods=["GET"])
@auth_required
@require_scope("secrets:admin")
async def get_license_status():
    """Return current license status and entitlements."""
    config = current_app.config["ICEBOX_CONFIG"]
    validator: LicenseValidator = current_app.config["LICENSE_VALIDATOR"]

    status = await validator.get_status()
    return jsonify(status)


@bp.route("/license", methods=["POST"])
@auth_required
@require_scope("secrets:admin")
async def set_license_key():
    """
    Set or update the IceBox license key.

    The key is validated immediately against the license server.
    Stored encrypted in icebox_license table.
    """
    config = current_app.config["ICEBOX_CONFIG"]
    enc = current_app.config["ENVELOPE_ENC"]
    db = get_db(config.database.uri, config.database.pool_size)
    validator: LicenseValidator = current_app.config["LICENSE_VALIDATOR"]

    body = await request.get_json() or {}
    license_key = body.get("license_key", "").strip()
    if not license_key:
        return jsonify({"error": "license_key is required"}), 400

    # Validate against license server immediately
    result = await validator.validate_key(license_key)
    if not result.get("valid"):
        return jsonify({
            "error": "License key validation failed",
            "detail": result.get("message", "Unknown error"),
        }), 402

    # Encrypt and store
    key_ciphertext, key_dek, key_version = enc.encrypt(license_key)
    encrypted_key_json = f"{key_ciphertext}:{key_dek}:{key_version}"

    existing = db(db.icebox_license).select().first()
    if existing:
        db(db.icebox_license.id == existing.id).update(
            license_key_encrypted=encrypted_key_json,
            validated_at=datetime.utcnow(),
            entitlements=result.get("entitlements"),
            license_server_url=config.licensing.license_server_url,
        )
    else:
        db.icebox_license.insert(
            license_key_encrypted=encrypted_key_json,
            validated_at=datetime.utcnow(),
            entitlements=result.get("entitlements"),
            license_server_url=config.licensing.license_server_url,
            auto_bypass_domains=config.licensing.auto_bypass_domains,
        )
    db.commit()

    return jsonify({
        "status": "licensed",
        "validated_at": datetime.utcnow().isoformat(),
        "entitlements": result.get("entitlements", []),
    })


@bp.route("/mek/rotate", methods=["POST"])
@auth_required
@require_scope("secrets:admin")
async def rotate_mek():
    """
    Rotate the Master Encryption Key.

    Re-wraps all DEK rows under the new MEK version.
    The new MEK must already be configured via ICEBOX_MEK_V{N} env var.
    """
    config = current_app.config["ICEBOX_CONFIG"]
    enc = current_app.config["ENVELOPE_ENC"]
    db = get_db(config.database.uri, config.database.pool_size)

    body = await request.get_json() or {}
    new_version = body.get("new_mek_version")
    if new_version is None:
        return jsonify({"error": "new_mek_version is required"}), 400

    new_version = int(new_version)
    if new_version not in enc.mek_versions:
        return jsonify({
            "error": f"MEK version {new_version} not loaded. Set ICEBOX_MEK_V{new_version} env var."
        }), 400

    # Collect all rows needing re-wrapping
    def _collect_rows(table_name: str, table) -> list:
        rows = []
        for r in db(table).select(table.id, table.encrypted_dek, table.dek_version):
            if r.dek_version != new_version:
                rows.append({
                    "id": r.id,
                    "encrypted_dek": r.encrypted_dek,
                    "dek_version": r.dek_version,
                    "_table": table_name,
                })
        return rows

    secret_rows = _collect_rows("icebox_secrets", db.icebox_secrets)
    version_rows = _collect_rows("icebox_secret_versions", db.icebox_secret_versions)
    ots_rows = _collect_rows("icebox_one_time_secrets", db.icebox_one_time_secrets)

    all_rows = secret_rows + version_rows + ots_rows
    updated = enc.rotate_mek(new_version, all_rows)

    # Persist re-wrapped DEKs
    for row in all_rows:
        table_name = row.pop("_table")
        table = getattr(db, table_name)
        db(table.id == row["id"]).update(
            encrypted_dek=row["encrypted_dek"],
            dek_version=row["dek_version"],
        )
    db.commit()

    logger.warning(
        "MEK rotation complete: %d rows re-wrapped to version %d by %s",
        updated,
        new_version,
        g.user_id,
    )

    return jsonify({
        "rows_updated": updated,
        "new_version": new_version,
        "rotated_at": datetime.utcnow().isoformat(),
    })
