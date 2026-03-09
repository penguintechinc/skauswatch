"""
IceBox Audit Log API — read-only access to the audit trail.

Routes:
    GET /audit/log    → paginated audit entries (audit:read)
"""

from __future__ import annotations

import logging

from quart import Blueprint, current_app, g, jsonify, request

from api.v1.auth import auth_required, require_scope
from models.db import get_db

logger = logging.getLogger(__name__)
bp = Blueprint("audit", __name__)


@bp.route("/log", methods=["GET"])
@auth_required
@require_scope("audit:read")
async def get_audit_log():
    """List audit log entries with pagination and filtering."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 50, type=int), 200)
    offset = (page - 1) * per_page

    actor_id = request.args.get("actor_id")
    resource_type = request.args.get("resource_type")
    resource_id = request.args.get("resource_id")
    action = request.args.get("action")

    query = db.icebox_audit_log

    if actor_id:
        query = db.icebox_audit_log.actor_id == actor_id
    if resource_type:
        cond = db.icebox_audit_log.resource_type == resource_type
        query = (query & cond) if not isinstance(query, type(db.icebox_audit_log)) else cond
    if resource_id:
        cond = db.icebox_audit_log.resource_id == resource_id
        query = (query & cond) if not isinstance(query, type(db.icebox_audit_log)) else cond
    if action:
        cond = db.icebox_audit_log.action == action
        query = (query & cond) if not isinstance(query, type(db.icebox_audit_log)) else cond

    rows = db(query).select(
        orderby=~db.icebox_audit_log.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    return jsonify({
        "entries": [
            {
                "id": r.id,
                "actor_id": r.actor_id,
                "action": r.action,
                "resource_type": r.resource_type,
                "resource_id": r.resource_id,
                "ip_address": r.ip_address,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
        "total": total,
        "page": page,
        "per_page": per_page,
    })
