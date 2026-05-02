"""
Alert management API endpoints.

Provides:
- Create alerts
- List/search alerts
- Update alert status
- Request AI review
"""

from datetime import datetime
from typing import List, Optional
import logging

from api.v1.auth import auth_required, role_required
from models.db import get_db
from pydantic import ValidationError
from quart import Blueprint, current_app, g, jsonify, request
from validators.pydantic_models import (
    AlertCreateRequest,
    AlertResponse,
    AlertSearchRequest,
    AlertSeverity,
    AlertStatus,
    AlertUpdateRequest,
)

logger = logging.getLogger(__name__)

bp = Blueprint("alerts", __name__)


@bp.route("", methods=["GET"])
@auth_required
async def list_alerts():
    """List alerts with pagination and filtering."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Get pagination params
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    per_page = min(per_page, 100)

    # Get filter params
    severity = request.args.getlist("severity")
    status = request.args.getlist("status")
    source = request.args.get("source")

    offset = (page - 1) * per_page

    # Build query
    query = db.alerts

    if severity:
        query = query & (db.alerts.severity.belongs(severity))
    if status:
        query = query & (db.alerts.status.belongs(status))
    if source:
        query = query & (db.alerts.source == source)

    # Execute query
    alerts = db(query).select(
        orderby=~db.alerts.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    # Convert to response format
    alert_list = []
    for alert in alerts:
        alert_list.append(
            {
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "status": alert.status,
                "source": alert.source,
                "indicators": alert.indicators or [],
                "ai_review": alert.ai_review,
                "assigned_to": alert.assigned_to,
                "resolved_at": (
                    alert.resolved_at.isoformat() if alert.resolved_at else None
                ),
                "resolution_notes": alert.resolution_notes,
                "created_at": (
                    alert.created_at.isoformat() if alert.created_at else None
                ),
                "updated_at": (
                    alert.updated_at.isoformat() if alert.updated_at else None
                ),
            }
        )

    return (
        jsonify(
            {
                "items": alert_list,
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page,
            }
        ),
        200,
    )


@bp.route("/<int:alert_id>", methods=["GET"])
@auth_required
async def get_alert(alert_id: int):
    """Get alert by ID."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    alert = db(db.alerts.id == alert_id).select().first()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    return (
        jsonify(
            {
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "status": alert.status,
                "source": alert.source,
                "indicators": alert.indicators or [],
                "ai_review": alert.ai_review,
                "assigned_to": alert.assigned_to,
                "resolved_at": (
                    alert.resolved_at.isoformat() if alert.resolved_at else None
                ),
                "resolution_notes": alert.resolution_notes,
                "created_at": (
                    alert.created_at.isoformat() if alert.created_at else None
                ),
                "updated_at": (
                    alert.updated_at.isoformat() if alert.updated_at else None
                ),
            }
        ),
        200,
    )


@bp.route("", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def create_alert():
    """Create a new alert."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        create_data = AlertCreateRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    # Create alert
    alert_id = db.alerts.insert(
        title=create_data.title,
        description=create_data.description,
        severity=create_data.severity.value,
        status="pending",
        source=create_data.source,
        indicators=create_data.indicators,
    )
    db.commit()

    alert = db(db.alerts.id == alert_id).select().first()

    # Publish to alerts stream for background processing
    stream_manager = current_app.config.get("STREAM_MANAGER")
    if stream_manager:
        try:
            await stream_manager.publish_event(
                "alerts:pending",
                {
                    "alert_id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "source": alert.source or "",
                    "created_at": alert.created_at.isoformat() if alert.created_at else "",
                },
            )
        except Exception as stream_err:
            logger.warning("Failed to publish alert to stream", error=str(stream_err))

    return (
        jsonify(
            {
                "message": "Alert created successfully",
                "alert": {
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "status": alert.status,
                    "created_at": (
                        alert.created_at.isoformat() if alert.created_at else None
                    ),
                },
            }
        ),
        201,
    )


@bp.route("/<int:alert_id>", methods=["PUT"])
@auth_required
@role_required("admin", "maintainer")
async def update_alert(alert_id: int):
    """Update an alert."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        update_data = AlertUpdateRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    alert = db(db.alerts.id == alert_id).select().first()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    # Build update dict
    updates = {}

    if update_data.title is not None:
        updates["title"] = update_data.title
    if update_data.description is not None:
        updates["description"] = update_data.description
    if update_data.severity is not None:
        updates["severity"] = update_data.severity.value
    if update_data.status is not None:
        updates["status"] = update_data.status.value
        # Set resolved_at if status is resolved
        if update_data.status == AlertStatus.RESOLVED:
            updates["resolved_at"] = datetime.utcnow()
    if update_data.assigned_to is not None:
        updates["assigned_to"] = update_data.assigned_to
    if update_data.resolution_notes is not None:
        updates["resolution_notes"] = update_data.resolution_notes

    if updates:
        db(db.alerts.id == alert_id).update(**updates)
        db.commit()

    # Fetch updated alert
    alert = db(db.alerts.id == alert_id).select().first()

    return (
        jsonify(
            {
                "message": "Alert updated successfully",
                "alert": {
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity,
                    "status": alert.status,
                    "updated_at": (
                        alert.updated_at.isoformat() if alert.updated_at else None
                    ),
                },
            }
        ),
        200,
    )


@bp.route("/<int:alert_id>/status", methods=["PUT"])
@auth_required
async def update_alert_status(alert_id: int):
    """Update alert status only."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    alert = db(db.alerts.id == alert_id).select().first()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    data = await request.get_json()
    new_status = data.get("status")

    if new_status not in [s.value for s in AlertStatus]:
        return jsonify({"error": "Invalid status"}), 400

    updates = {"status": new_status}
    if new_status == "resolved":
        updates["resolved_at"] = datetime.utcnow()

    db(db.alerts.id == alert_id).update(**updates)
    db.commit()

    return (
        jsonify(
            {
                "message": "Status updated",
                "alert_id": alert_id,
                "new_status": new_status,
            }
        ),
        200,
    )


@bp.route("/<int:alert_id>/ai-review", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def request_ai_review(alert_id: int):
    """Request AI review for an alert."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    if not config.ai.enabled:
        return jsonify({"error": "AI integration is disabled"}), 503

    alert = db(db.alerts.id == alert_id).select().first()
    if not alert:
        return jsonify({"error": "Alert not found"}), 404

    data = await request.get_json() or {}
    provider = data.get("provider", config.ai.default_provider)
    priority = data.get("priority", 1)

    import uuid as _uuid
    job_id = str(_uuid.uuid4())
    # Publish to AI task queue for processing
    stream_manager = current_app.config.get("STREAM_MANAGER")
    if stream_manager:
        try:
            await stream_manager.publish_event(
                "ai:tasks",
                {
                    "job_id": job_id,
                    "alert_id": alert_id,
                    "provider": provider,
                    "priority": priority,
                    "task_type": "alert_review",
                    "submitted_at": datetime.utcnow().isoformat(),
                },
            )
        except Exception as stream_err:
            logger.warning("Failed to publish AI review task to stream", error=str(stream_err))

    return (
        jsonify(
            {
                "message": "AI review requested",
                "job_id": job_id,
                "alert_id": alert_id,
                "provider": provider,
                "priority": priority,
                "submitted_at": datetime.utcnow().isoformat(),
            }
        ),
        202,
    )


@bp.route("/search", methods=["POST"])
@auth_required
async def search_alerts():
    """Search alerts with advanced filtering."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        search_data = AlertSearchRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    offset = (search_data.page - 1) * search_data.per_page

    # Build query
    query = db.alerts

    if search_data.query:
        query = query & (
            db.alerts.title.contains(search_data.query)
            | db.alerts.description.contains(search_data.query)
        )
    if search_data.severity:
        query = query & (
            db.alerts.severity.belongs([s.value for s in search_data.severity])
        )
    if search_data.status:
        query = query & (
            db.alerts.status.belongs([s.value for s in search_data.status])
        )
    if search_data.source:
        query = query & (db.alerts.source == search_data.source)
    if search_data.assigned_to:
        query = query & (db.alerts.assigned_to == search_data.assigned_to)
    if search_data.created_after:
        query = query & (db.alerts.created_at >= search_data.created_after)
    if search_data.created_before:
        query = query & (db.alerts.created_at <= search_data.created_before)

    # Execute query
    alerts = db(query).select(
        orderby=~db.alerts.created_at,
        limitby=(offset, offset + search_data.per_page),
    )
    total = db(query).count()

    # Convert to response format
    alert_list = []
    for alert in alerts:
        alert_list.append(
            {
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "status": alert.status,
                "source": alert.source,
                "created_at": (
                    alert.created_at.isoformat() if alert.created_at else None
                ),
            }
        )

    return (
        jsonify(
            {
                "items": alert_list,
                "total": total,
                "page": search_data.page,
                "per_page": search_data.per_page,
                "pages": (total + search_data.per_page - 1) // search_data.per_page,
            }
        ),
        200,
    )


@bp.route("/statistics", methods=["GET"])
@auth_required
async def get_alert_statistics():
    """Get alert statistics."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Count by severity
    severity_counts = {}
    for severity in AlertSeverity:
        count = db(db.alerts.severity == severity.value).count()
        severity_counts[severity.value] = count

    # Count by status
    status_counts = {}
    for status in AlertStatus:
        count = db(db.alerts.status == status.value).count()
        status_counts[status.value] = count

    # Recent alerts (last 24 hours)
    from datetime import timedelta

    yesterday = datetime.utcnow() - timedelta(days=1)
    recent_count = db(db.alerts.created_at >= yesterday).count()

    return (
        jsonify(
            {
                "total": db(db.alerts).count(),
                "by_severity": severity_counts,
                "by_status": status_counts,
                "last_24_hours": recent_count,
            }
        ),
        200,
    )
