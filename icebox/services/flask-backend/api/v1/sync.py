"""
IceBox Cloud Sync API — Phase 7

Manages cloud vault integrations (AWS/Azure/GCP/Oracle/K8s).
Publishes sync events to Redis Streams for the sync-worker service.

Routes:
    GET    /sync/integrations           → list (sync:read)
    POST   /sync/integrations           → create (sync:admin)
    PUT    /sync/integrations/{id}      → update (sync:admin)
    DELETE /sync/integrations/{id}      → delete (sync:admin)
    POST   /sync/integrations/{id}/trigger → manual sync (sync:admin)
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from uuid import uuid4

from quart import Blueprint, current_app, g, jsonify, request

from api.v1.auth import auth_required, require_scope
from models.db import get_db

logger = logging.getLogger(__name__)
bp = Blueprint("sync", __name__)

VALID_PROVIDERS = {"aws", "azure", "gcp", "oracle", "kubernetes"}
VALID_DIRECTIONS = {"icebox_to_cloud", "cloud_to_icebox", "bidirectional"}


def _integration_to_dict(row) -> dict:
    return {
        "id": row.id,
        "provider": row.provider,
        "name": row.name,
        "description": row.description,
        "sync_direction": row.sync_direction,
        "sync_scopes": row.sync_scopes,
        "enabled": row.enabled,
        "config": row.config,
        "last_sync_at": row.last_sync_at.isoformat() if row.last_sync_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


async def _publish_sync_event(integration_id: str, provider: str, event_type: str) -> None:
    """Publish a sync event to the Redis Stream for the given provider."""
    try:
        redis = current_app.config.get("REDIS_CLIENT")
        if not redis:
            logger.warning("No Redis client configured — skipping sync event publish")
            return

        stream_key = f"icebox:sync:{provider}"
        message = {
            "integration_id": integration_id,
            "event_type": event_type,
            "timestamp": datetime.utcnow().isoformat(),
        }
        await redis.xadd(stream_key, message)
        logger.info("Published sync event %s to %s", event_type, stream_key)
    except Exception as exc:
        logger.error("Failed to publish sync event: %s", exc)


@bp.route("/integrations", methods=["GET"])
@auth_required
@require_scope("sync:read")
async def list_integrations():
    """List all cloud sync integrations."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    rows = db(db.icebox_cloud_integrations).select(
        orderby=db.icebox_cloud_integrations.name
    )
    return jsonify({"integrations": [_integration_to_dict(r) for r in rows]})


@bp.route("/integrations", methods=["POST"])
@auth_required
@require_scope("sync:admin")
async def create_integration():
    """Create a new cloud sync integration."""
    config = current_app.config["ICEBOX_CONFIG"]
    enc = current_app.config["ENVELOPE_ENC"]
    db = get_db(config.database.uri, config.database.pool_size)

    body = await request.get_json() or {}
    provider = body.get("provider", "").strip().lower()
    name = body.get("name", "").strip()

    if provider not in VALID_PROVIDERS:
        return jsonify({"error": f"provider must be one of: {', '.join(sorted(VALID_PROVIDERS))}"}), 400
    if not name:
        return jsonify({"error": "name is required"}), 400

    sync_direction = body.get("sync_direction", "icebox_to_cloud")
    if sync_direction not in VALID_DIRECTIONS:
        return jsonify({"error": f"sync_direction must be one of: {', '.join(VALID_DIRECTIONS)}"}), 400

    # Encrypt provider credentials if provided
    encrypted_creds = None
    if body.get("credentials"):
        creds_json = json.dumps(body["credentials"])
        ciphertext, encrypted_dek, dek_version = enc.encrypt(creds_json)
        encrypted_creds = json.dumps({
            "ciphertext": ciphertext,
            "dek": encrypted_dek,
            "version": dek_version,
        })

    integration_id = str(uuid4())
    db.icebox_cloud_integrations.insert(
        id=integration_id,
        provider=provider,
        name=name,
        description=body.get("description", ""),
        sync_direction=sync_direction,
        sync_scopes=body.get("sync_scopes"),
        encrypted_credentials=encrypted_creds,
        enabled=body.get("enabled", True),
        config=body.get("config"),
        created_at=datetime.utcnow(),
    )
    db.commit()

    row = db(db.icebox_cloud_integrations.id == integration_id).select().first()
    return jsonify(_integration_to_dict(row)), 201


@bp.route("/integrations/<integration_id>", methods=["PUT"])
@auth_required
@require_scope("sync:admin")
async def update_integration(integration_id: str):
    """Update a cloud sync integration."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    row = db(db.icebox_cloud_integrations.id == integration_id).select().first()
    if not row:
        return jsonify({"error": "Not found"}), 404

    body = await request.get_json() or {}
    updates = {}

    for field in ("name", "description", "sync_direction", "sync_scopes", "config", "enabled"):
        if field in body:
            if field == "sync_direction" and body[field] not in VALID_DIRECTIONS:
                return jsonify({"error": f"Invalid sync_direction"}), 400
            updates[field] = body[field]

    if updates:
        db(db.icebox_cloud_integrations.id == integration_id).update(**updates)
        db.commit()

    row = db(db.icebox_cloud_integrations.id == integration_id).select().first()
    return jsonify(_integration_to_dict(row))


@bp.route("/integrations/<integration_id>", methods=["DELETE"])
@auth_required
@require_scope("sync:admin")
async def delete_integration(integration_id: str):
    """Delete a cloud sync integration."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    if not db(db.icebox_cloud_integrations.id == integration_id).count():
        return jsonify({"error": "Not found"}), 404

    db(db.icebox_cloud_integrations.id == integration_id).delete()
    db.commit()
    return "", 204


@bp.route("/integrations/<integration_id>/trigger", methods=["POST"])
@auth_required
@require_scope("sync:admin")
async def trigger_sync(integration_id: str):
    """Manually trigger a sync for the given integration."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    row = db(db.icebox_cloud_integrations.id == integration_id).select().first()
    if not row:
        return jsonify({"error": "Not found"}), 404

    if not row.enabled:
        return jsonify({"error": "Integration is disabled"}), 409

    await _publish_sync_event(integration_id, row.provider, "manual_trigger")

    return jsonify({
        "integration_id": integration_id,
        "provider": row.provider,
        "status": "sync_queued",
        "queued_at": datetime.utcnow().isoformat(),
    })
