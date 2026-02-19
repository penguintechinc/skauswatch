"""Flask blueprint for scan schedule CRUD operations.

This module provides REST API endpoints for managing security scan schedules.
All endpoints require JWT authentication and use PyDAL for database operations.
Supports pagination, filtering, full CRUD operations, and manual trigger execution.

Endpoints:
    GET /schedules - List schedules with optional filtering and pagination
    POST /schedules - Create new scan schedule
    GET /schedules/<id> - Get single schedule details
    PUT /schedules/<id> - Update schedule configuration
    DELETE /schedules/<id> - Delete schedule
    POST /schedules/<id>/run - Manually trigger scheduled scan immediately
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional, Tuple

from api.middleware.auth import get_current_user_id, jwt_required
from config.settings import settings
from croniter import croniter
from database.models import get_configured_db
from flask import Blueprint, g, jsonify, request

# Configure logging
logger = logging.getLogger(__name__)

# Create Flask blueprint
schedules_bp = Blueprint("schedules", __name__)


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """Convert PyDAL Row object to dictionary with datetime serialization.

    Uses row.as_dict() to extract only actual database fields (excludes
    PyDAL back-reference objects like RecordDeleter). Handles datetime
    objects by converting them to ISO 8601 format strings.

    Args:
        row: PyDAL Row object from database query

    Returns:
        Dictionary representation of the row with properly serialized values

    Example:
        >>> row = db.scan_schedules[1]
        >>> schedule_dict = _row_to_dict(row)
        >>> print(schedule_dict['created_at'])  # '2025-01-29T12:00:00'
    """
    result = row.as_dict()
    for key, value in list(result.items()):
        if isinstance(value, datetime):
            result[key] = value.isoformat()
    return result


@schedules_bp.route("", methods=["GET"])
@jwt_required
def list_schedules() -> Tuple[Dict[str, Any], int]:
    """List all scan schedules with optional pagination and filtering.

    Query Parameters:
        enabled (bool, optional): Filter by enabled status (true/false/null)
        page (int, optional): Page number for pagination (default: 1)
        per_page (int, optional): Items per page (default: 20, max: 100)

    Returns:
        JSON response with schedule list, total count, and pagination info

    Response Format:
        {
            "schedules": [
                {
                    "id": 1,
                    "name": "Daily scan",
                    "target_id": 1,
                    "scanner_type": "nuclei",
                    "scan_type": "baseline",
                    "cron_expression": "0 0 * * *",
                    "config": {},
                    "enabled": true,
                    "last_run": "2025-01-29T00:00:00",
                    "next_run": "2025-01-30T00:00:00",
                    "created_at": "2025-01-01T12:00:00",
                    "created_by": "user123"
                }
            ],
            "total": 50,
            "page": 1,
            "per_page": 20
        }

    Example:
        GET /schedules?page=1&per_page=10&enabled=true
    """
    try:
        # Get pagination parameters
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)

        # Validate pagination parameters
        if page < 1:
            page = 1
        if per_page < 1 or per_page > 100:
            per_page = 20

        # Get database connection
        db = get_configured_db()

        # Build query
        query = db.scan_schedules.id > 0  # Base query (always true)

        # Apply enabled filter if provided
        enabled_param = request.args.get("enabled", None)
        if enabled_param is not None:
            enabled_value = enabled_param.lower() in ("true", "1", "yes")
            query &= db.scan_schedules.enabled == enabled_value

        # Get total count
        total_count = db(query).count()

        # Calculate offset and limit
        offset = (page - 1) * per_page
        limit = per_page

        # Execute query with pagination
        rows = db(query).select(
            orderby=~db.scan_schedules.created_at, limitby=(offset, offset + limit)
        )

        # Convert rows to dictionaries
        schedules = [_row_to_dict(row) for row in rows]

        logger.info(
            "Listed %d schedules (page %d, total %d)", len(schedules), page, total_count
        )

        return (
            jsonify(
                {
                    "schedules": schedules,
                    "total": total_count,
                    "page": page,
                    "per_page": per_page,
                }
            ),
            200,
        )

    except Exception as e:
        logger.error("Failed to list schedules: %s", str(e))
        return (
            jsonify({"error": f"Failed to list schedules: {str(e)}", "code": 500}),
            500,
        )


@schedules_bp.route("", methods=["POST"])
@jwt_required
def create_schedule() -> Tuple[Dict[str, Any], int]:
    """Create a new scan schedule.

    Request Body:
        name (str, required): Schedule name (1-255 chars)
        target_id (int, required): ID of scan target
        scanner_type (str, required): Scanner type (nuclei, zap, openvas)
        scan_type (str, required): Scan type (baseline, full, quick, etc.)
        cron_expression (str, required): Cron expression for scheduling
        config (dict, optional): Custom scan configuration (default: {})
        enabled (bool, optional): Enable schedule (default: true)

    Returns:
        201 Created: JSON with created schedule including ID and timestamps
        400 Bad Request: Invalid cron expression, disabled scanner, or validation error
        404 Not Found: Target does not exist

    Example:
        POST /schedules
        {
            "name": "Daily vulnerability scan",
            "target_id": 1,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "cron_expression": "0 0 * * *",
            "config": {"severity": "high"},
            "enabled": true
        }
    """
    try:
        # Get request JSON
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required", "code": 400}), 400

        # Validate required fields
        required_fields = [
            "name",
            "target_id",
            "scanner_type",
            "scan_type",
            "cron_expression",
        ]
        missing_fields = [f for f in required_fields if f not in data]
        if missing_fields:
            return (
                jsonify(
                    {
                        "error": "Missing required fields",
                        "missing": missing_fields,
                        "code": 400,
                    }
                ),
                400,
            )

        # Validate cron expression
        cron_expression = data.get("cron_expression", "").strip()
        if not cron_expression:
            return (
                jsonify({"error": "Cron expression cannot be empty", "code": 400}),
                400,
            )

        if not croniter.is_valid(cron_expression):
            return jsonify({"error": "Invalid cron expression", "code": 400}), 400

        # Get database connection
        db = get_configured_db()

        # Verify target exists
        target_id = data.get("target_id")
        target = db.scan_targets[target_id]
        if not target:
            logger.warning("Target not found for schedule creation: %d", target_id)
            return jsonify({"error": "Target not found", "code": 404}), 404

        # Verify scanner is enabled
        scanner_type = data.get("scanner_type", "").lower()
        scanner_enabled = False

        if scanner_type == "nuclei":
            scanner_enabled = settings.scanner_toggles.nuclei_enabled
        elif scanner_type == "zap":
            scanner_enabled = settings.scanner_toggles.zap_enabled
        elif scanner_type == "openvas":
            scanner_enabled = settings.scanner_toggles.openvas_enabled

        if not scanner_enabled:
            logger.warning("Scanner not available for schedule: %s", scanner_type)
            return (
                jsonify(
                    {"error": f"Scanner {scanner_type} is not available", "code": 400}
                ),
                400,
            )

        # Calculate next_run from cron expression
        try:
            cron_iter = croniter(cron_expression, datetime.utcnow())
            next_run = cron_iter.get_next(datetime)
        except Exception as e:
            logger.error("Failed to calculate next_run: %s", str(e))
            return (
                jsonify({"error": "Failed to calculate next run time", "code": 400}),
                400,
            )

        # Get current user ID
        user_id = get_current_user_id()

        # Prepare insert data
        insert_data = {
            "name": data.get("name", "").strip(),
            "target_id": target_id,
            "scanner_type": scanner_type,
            "scan_type": data.get("scan_type", "").strip(),
            "cron_expression": cron_expression,
            "config": data.get("config", {}),
            "enabled": data.get("enabled", True),
            "next_run": next_run,
            "created_at": datetime.utcnow(),
            "created_by": user_id,
        }

        # Insert into database
        schedule_id = db.scan_schedules.insert(**insert_data)
        db.commit()

        # Fetch the created schedule
        row = db.scan_schedules[schedule_id]
        schedule_dict = _row_to_dict(row)

        logger.info(
            "Created schedule %d: %s for target %d by user %s",
            schedule_id,
            insert_data["name"],
            target_id,
            user_id,
        )

        return jsonify(schedule_dict), 201

    except Exception as e:
        logger.error("Failed to create schedule: %s", str(e))
        return (
            jsonify({"error": f"Failed to create schedule: {str(e)}", "code": 500}),
            500,
        )


@schedules_bp.route("/<int:schedule_id>", methods=["GET"])
@jwt_required
def get_schedule(schedule_id: int) -> Tuple[Dict[str, Any], int]:
    """Retrieve a specific scan schedule by ID.

    Args:
        schedule_id (int): The ID of the schedule to retrieve

    Returns:
        200 OK: JSON with schedule details
        404 Not Found: Schedule does not exist

    Example:
        GET /schedules/123
    """
    try:
        # Get database connection
        db = get_configured_db()

        # Fetch schedule
        row = db.scan_schedules[schedule_id]
        if not row:
            logger.warning("Schedule not found: %d", schedule_id)
            return jsonify({"error": "Schedule not found", "code": 404}), 404

        # Convert to dictionary
        schedule_dict = _row_to_dict(row)

        logger.debug("Retrieved schedule %d", schedule_id)

        return jsonify(schedule_dict), 200

    except Exception as e:
        logger.error("Failed to retrieve schedule %d: %s", schedule_id, str(e))
        return (
            jsonify({"error": f"Failed to retrieve schedule: {str(e)}", "code": 500}),
            500,
        )


@schedules_bp.route("/<int:schedule_id>", methods=["PUT"])
@jwt_required
def update_schedule(schedule_id: int) -> Tuple[Dict[str, Any], int]:
    """Update a scan schedule.

    Supports partial updates of schedule configuration. If cron_expression is
    changed, next_run is automatically recalculated. If enabled is changed to True,
    next_run is also recalculated.

    Args:
        schedule_id (int): The ID of the schedule to update

    Request Body (all optional):
        name (str): Schedule name
        scanner_type (str): Scanner type
        scan_type (str): Scan type
        cron_expression (str): Cron expression (validated)
        config (dict): Custom scan configuration
        enabled (bool): Enable/disable schedule

    Returns:
        200 OK: JSON with updated schedule
        400 Bad Request: Validation error or invalid cron expression
        404 Not Found: Schedule does not exist

    Example:
        PUT /schedules/123
        {
            "cron_expression": "0 2 * * *",
            "enabled": false
        }
    """
    try:
        # Get request JSON
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required", "code": 400}), 400

        # Get database connection
        db = get_configured_db()

        # Check schedule exists
        row = db.scan_schedules[schedule_id]
        if not row:
            logger.warning("Schedule not found for update: %d", schedule_id)
            return jsonify({"error": "Schedule not found", "code": 404}), 404

        # Prepare update data
        update_data = {}

        # Update simple fields
        if "name" in data:
            update_data["name"] = data.get("name", "").strip()
        if "scanner_type" in data:
            scanner_type = data.get("scanner_type", "").lower()
            # Verify scanner is enabled if changing scanner_type
            scanner_enabled = False
            if scanner_type == "nuclei":
                scanner_enabled = settings.scanner_toggles.nuclei_enabled
            elif scanner_type == "zap":
                scanner_enabled = settings.scanner_toggles.zap_enabled
            elif scanner_type == "openvas":
                scanner_enabled = settings.scanner_toggles.openvas_enabled

            if not scanner_enabled:
                logger.warning(
                    "Scanner not available for schedule update: %s", scanner_type
                )
                return (
                    jsonify(
                        {
                            "error": f"Scanner {scanner_type} is not available",
                            "code": 400,
                        }
                    ),
                    400,
                )

            update_data["scanner_type"] = scanner_type

        if "scan_type" in data:
            update_data["scan_type"] = data.get("scan_type", "").strip()

        if "config" in data:
            update_data["config"] = data.get("config", {})

        # Handle cron_expression update with next_run recalculation
        if "cron_expression" in data:
            cron_expression = data.get("cron_expression", "").strip()
            if not cron_expression:
                return (
                    jsonify({"error": "Cron expression cannot be empty", "code": 400}),
                    400,
                )

            if not croniter.is_valid(cron_expression):
                return jsonify({"error": "Invalid cron expression", "code": 400}), 400

            # Calculate new next_run
            try:
                cron_iter = croniter(cron_expression, datetime.utcnow())
                next_run = cron_iter.get_next(datetime)
                update_data["next_run"] = next_run
            except Exception as e:
                logger.error("Failed to calculate next_run: %s", str(e))
                return (
                    jsonify(
                        {"error": "Failed to calculate next run time", "code": 400}
                    ),
                    400,
                )

            update_data["cron_expression"] = cron_expression

        # Handle enabled flag change with next_run recalculation
        if "enabled" in data:
            enabled_value = data.get("enabled", True)
            update_data["enabled"] = enabled_value

            # If enabling schedule, recalculate next_run
            if enabled_value and "cron_expression" not in data:
                current_cron = row.cron_expression
                try:
                    cron_iter = croniter(current_cron, datetime.utcnow())
                    next_run = cron_iter.get_next(datetime)
                    update_data["next_run"] = next_run
                except Exception as e:
                    logger.error("Failed to recalculate next_run: %s", str(e))

        # Update in database
        if update_data:
            db(db.scan_schedules.id == schedule_id).update(**update_data)
            db.commit()

        # Fetch updated schedule
        row = db.scan_schedules[schedule_id]
        schedule_dict = _row_to_dict(row)

        logger.info("Updated schedule %d", schedule_id)

        return jsonify(schedule_dict), 200

    except Exception as e:
        logger.error("Failed to update schedule %d: %s", schedule_id, str(e))
        return (
            jsonify({"error": f"Failed to update schedule: {str(e)}", "code": 500}),
            500,
        )


@schedules_bp.route("/<int:schedule_id>", methods=["DELETE"])
@jwt_required
def delete_schedule(schedule_id: int) -> Tuple[str, int]:
    """Delete a scan schedule.

    Args:
        schedule_id (int): The ID of the schedule to delete

    Returns:
        204 No Content: Schedule deleted successfully
        404 Not Found: Schedule does not exist

    Example:
        DELETE /schedules/123
    """
    try:
        # Get database connection
        db = get_configured_db()

        # Check schedule exists
        row = db.scan_schedules[schedule_id]
        if not row:
            logger.warning("Schedule not found for deletion: %d", schedule_id)
            return jsonify({"error": "Schedule not found", "code": 404}), 404

        # Delete schedule
        db(db.scan_schedules.id == schedule_id).delete()
        db.commit()

        logger.info("Deleted schedule %d", schedule_id)

        return "", 204

    except Exception as e:
        logger.error("Failed to delete schedule %d: %s", schedule_id, str(e))
        return (
            jsonify({"error": f"Failed to delete schedule: {str(e)}", "code": 500}),
            500,
        )


@schedules_bp.route("/<int:schedule_id>/run", methods=["POST"])
@jwt_required
def run_schedule(schedule_id: int) -> Tuple[Dict[str, Any], int]:
    """Manually trigger a scheduled scan immediately.

    Creates a new scan job using the schedule's configuration and dispatches
    a Celery worker task to execute the scan.

    Args:
        schedule_id (int): The ID of the schedule to run

    Returns:
        202 Accepted: Scan job created and queued for execution
        404 Not Found: Schedule does not exist

    Response Format:
        {
            "job_id": 1,
            "target_id": 1,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "status": "pending",
            "created_at": "2025-01-29T12:00:00",
            "created_by": "user123"
        }

    Example:
        POST /schedules/123/run
    """
    try:
        # Get database connection
        db = get_configured_db()

        # Fetch schedule
        schedule = db.scan_schedules[schedule_id]
        if not schedule:
            logger.warning("Schedule not found for manual execution: %d", schedule_id)
            return jsonify({"error": "Schedule not found", "code": 404}), 404

        # Get current user ID
        user_id = get_current_user_id()

        # Create new scan job using schedule's configuration
        job_id = db.scan_jobs.insert(
            target_id=schedule.target_id,
            scanner_type=schedule.scanner_type,
            scan_type=schedule.scan_type,
            status="pending",
            priority=5,  # Default priority for manual execution
            config=schedule.config,
            created_at=datetime.utcnow(),
            created_by=user_id,
        )

        # Commit transaction
        db.commit()

        # Fetch created job
        job = db.scan_jobs[job_id]
        job_dict = _row_to_dict(job)

        logger.info(
            "Created manual scan job %d from schedule %d by user %s",
            job_id,
            schedule_id,
            user_id,
        )

        # Dispatch async Celery task
        try:
            # Import here to avoid circular dependencies
            from workers.scan_worker import execute_scan

            task = execute_scan.delay(job_id)
            logger.info("Dispatched Celery task %s for manual job %d", task.id, job_id)
        except Exception as e:
            logger.error(
                "Failed to dispatch Celery task for manual job %d: %s", job_id, str(e)
            )
            # Don't fail the request - job is created, worker can pick it up later
            # Update job with error status for visibility
            db(db.scan_jobs.id == job_id).update(
                status="failed", error_message=f"Failed to dispatch task: {str(e)}"
            )
            db.commit()

        # Return 202 Accepted (async processing)
        return jsonify(job_dict), 202

    except Exception as e:
        logger.error("Failed to execute schedule %d: %s", schedule_id, str(e))
        return (
            jsonify({"error": f"Failed to execute schedule: {str(e)}", "code": 500}),
            500,
        )
