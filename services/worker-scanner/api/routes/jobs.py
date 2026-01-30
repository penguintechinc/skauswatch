"""Scan job management API routes.

This module provides RESTful API endpoints for managing security scan jobs.
All routes require JWT authentication and use PyDAL for database operations.

Endpoints:
    GET /jobs - List jobs with filtering
    POST /jobs - Create new scan job
    GET /jobs/<id> - Get single job details
    DELETE /jobs/<id> - Cancel/delete job
    GET /jobs/<id>/output - Get job output/error
    GET /jobs/<id>/findings - Get job findings
    POST /jobs/<id>/retry - Retry failed job
"""

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from flask import Blueprint, jsonify, request
from marshmallow import ValidationError

from api.middleware.auth import get_current_user_id, jwt_required
from api.schemas.job import CreateJobSchema, JobFilterSchema, JobResponseSchema
from config.settings import settings
from database.models import get_configured_db

# Configure logging
logger = logging.getLogger(__name__)

# Create Flask blueprint
jobs_bp = Blueprint("jobs", __name__)

# Initialize marshmallow schemas
create_job_schema = CreateJobSchema()
job_response_schema = JobResponseSchema()
job_filter_schema = JobFilterSchema()


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """Convert PyDAL Row object to dictionary with datetime serialization.

    Uses row.as_dict() to extract only actual database fields (excludes
    PyDAL back-reference objects like RecordDeleter).

    Args:
        row: PyDAL Row object from database query

    Returns:
        Dictionary representation of the row with properly serialized values
    """
    result = row.as_dict()
    for key, value in list(result.items()):
        if isinstance(value, datetime):
            result[key] = value.isoformat()
    return result


@jobs_bp.route("", methods=["GET"])
@jwt_required
def list_jobs() -> tuple[Any, int]:
    """List scan jobs with optional filtering and pagination.

    Query parameters:
        status: Filter by job status (pending, running, completed, failed, cancelled)
        scanner_type: Filter by scanner type (nuclei, zap, openvas)
        target_id: Filter by target ID
        page: Page number (default: 1)
        per_page: Items per page (default: 20, max: 100)

    Returns:
        JSON response with jobs list, total count, and pagination info

    Response format:
        {
            "jobs": [job objects],
            "total": 100,
            "page": 1,
            "per_page": 20
        }
    """
    try:
        # Validate query parameters
        params = job_filter_schema.load(request.args)
    except ValidationError as e:
        logger.warning("Invalid job filter parameters: %s", e.messages)
        return jsonify({"error": "Invalid parameters", "details": e.messages}), 400

    # Get database connection
    db = get_configured_db()

    # Build PyDAL query dynamically based on filters
    query = db.scan_jobs.id > 0  # Base query (always true)

    if params.get("status"):
        query &= db.scan_jobs.status == params["status"]

    if params.get("scanner_type"):
        query &= db.scan_jobs.scanner_type == params["scanner_type"]

    if params.get("target_id"):
        query &= db.scan_jobs.target_id == params["target_id"]

    # Get pagination parameters
    page = params.get("page", 1)
    per_page = params.get("per_page", 20)

    # Calculate offset for pagination
    offset = (page - 1) * per_page

    # Get total count
    total = db(query).count()

    # Fetch paginated results ordered by created_at desc
    rows = db(query).select(
        orderby=~db.scan_jobs.created_at, limitby=(offset, offset + per_page)
    )

    # Convert rows to dictionaries
    jobs = [_row_to_dict(row) for row in rows]

    logger.info(
        "Listed %d jobs (page %d, total %d) with filters: %s",
        len(jobs),
        page,
        total,
        params,
    )

    return (
        jsonify({"jobs": jobs, "total": total, "page": page, "per_page": per_page}),
        200,
    )


@jobs_bp.route("", methods=["POST"])
@jwt_required
def create_job() -> tuple[Any, int]:
    """Create a new scan job and dispatch to Celery worker.

    Request body:
        {
            "target_id": 1,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "priority": 5,
            "config": {}
        }

    Returns:
        202 Accepted with created job data (async processing)

    Raises:
        400: Invalid request data, disabled target, or scanner not available
        404: Target not found
    """
    try:
        # Validate request body
        data = create_job_schema.load(request.get_json())
    except ValidationError as e:
        logger.warning("Invalid job creation request: %s", e.messages)
        return jsonify({"error": "Invalid request data", "details": e.messages}), 400

    # Get database connection
    db = get_configured_db()

    # Verify target exists
    target = db.scan_targets[data["target_id"]]
    if not target:
        logger.warning("Target not found: %d", data["target_id"])
        return jsonify({"error": "Target not found"}), 404

    # Verify target is enabled
    if not target.enabled:
        logger.warning("Target is disabled: %d", data["target_id"])
        return jsonify({"error": "Target is disabled"}), 400

    # Verify scanner is enabled
    scanner_type = data["scanner_type"]
    scanner_enabled = False

    if scanner_type == "nuclei":
        scanner_enabled = settings.scanner_toggles.nuclei_enabled
    elif scanner_type == "zap":
        scanner_enabled = settings.scanner_toggles.zap_enabled
    elif scanner_type == "openvas":
        scanner_enabled = settings.scanner_toggles.openvas_enabled

    if not scanner_enabled:
        logger.warning("Scanner not available: %s", scanner_type)
        return jsonify({"error": f"Scanner {scanner_type} is not available"}), 400

    # Get current user ID
    user_id = get_current_user_id()

    # Insert new job
    job_id = db.scan_jobs.insert(
        target_id=data["target_id"],
        scanner_type=data["scanner_type"],
        scan_type=data["scan_type"],
        status="pending",
        priority=data.get("priority", 5),
        config=data.get("config", {}),
        created_at=datetime.utcnow(),
        created_by=user_id,
    )

    # Commit transaction
    db.commit()

    # Fetch created job
    job = db.scan_jobs[job_id]
    job_dict = _row_to_dict(job)

    logger.info(
        "Created job %d: %s scan on target %d by user %s",
        job_id,
        scanner_type,
        data["target_id"],
        user_id,
    )

    # Dispatch async Celery task
    try:
        # Import here to avoid circular dependencies
        from workers.scan_worker import execute_scan

        task = execute_scan.delay(job_id)
        logger.info("Dispatched Celery task %s for job %d", task.id, job_id)
    except Exception as e:
        logger.error("Failed to dispatch Celery task for job %d: %s", job_id, str(e))
        # Don't fail the request - job is created, worker can pick it up later
        # Update job with error status
        db(db.scan_jobs.id == job_id).update(
            status="failed", error_message=f"Failed to dispatch task: {str(e)}"
        )
        db.commit()

    # Return 202 Accepted (async processing)
    return jsonify(job_dict), 202


@jobs_bp.route("/<int:job_id>", methods=["GET"])
@jwt_required
def get_job(job_id: int) -> tuple[Any, int]:
    """Get details of a specific scan job.

    Args:
        job_id: Job ID from URL path

    Returns:
        JSON response with job details

    Raises:
        404: Job not found
    """
    # Get database connection
    db = get_configured_db()

    # Fetch job
    job = db.scan_jobs[job_id]
    if not job:
        logger.warning("Job not found: %d", job_id)
        return jsonify({"error": "Job not found"}), 404

    job_dict = _row_to_dict(job)
    logger.debug("Retrieved job %d", job_id)

    return jsonify(job_dict), 200


@jobs_bp.route("/<int:job_id>", methods=["DELETE"])
@jwt_required
def delete_job(job_id: int) -> tuple[Any, int]:
    """Cancel or delete a scan job.

    Behavior depends on job status:
    - running: Update status to cancelled, attempt to revoke Celery task
    - pending: Update status to cancelled
    - completed/failed/cancelled: Delete job and its findings

    Args:
        job_id: Job ID from URL path

    Returns:
        204 No Content on success

    Raises:
        404: Job not found
    """
    # Get database connection
    db = get_configured_db()

    # Fetch job
    job = db.scan_jobs[job_id]
    if not job:
        logger.warning("Job not found for deletion: %d", job_id)
        return jsonify({"error": "Job not found"}), 404

    status = job.status

    # Handle running jobs - cancel them
    if status == "running":
        logger.info("Cancelling running job %d", job_id)

        # Update status to cancelled
        db(db.scan_jobs.id == job_id).update(status="cancelled")
        db.commit()

        # Attempt to revoke Celery task (best effort)
        try:
            from workers.celery_app import celery_app

            # We don't have task_id stored, so this is limited
            # In production, you'd want to store celery task_id in the job record
            celery_app.control.revoke(str(job_id), terminate=True)
            logger.info("Revoked Celery task for job %d", job_id)
        except Exception as e:
            logger.warning("Failed to revoke Celery task for job %d: %s", job_id, str(e))
            # Continue anyway - job is marked as cancelled

    # Handle pending jobs - just cancel them
    elif status == "pending":
        logger.info("Cancelling pending job %d", job_id)
        db(db.scan_jobs.id == job_id).update(status="cancelled")
        db.commit()

    # Handle completed/failed/cancelled jobs - delete them
    elif status in ("completed", "failed", "cancelled"):
        logger.info("Deleting job %d and its findings", job_id)

        # Delete findings first (foreign key constraint)
        db(db.scan_findings.job_id == job_id).delete()

        # Delete job
        db(db.scan_jobs.id == job_id).delete()
        db.commit()

    return "", 204


@jobs_bp.route("/<int:job_id>/output", methods=["GET"])
@jwt_required
def get_job_output(job_id: int) -> tuple[Any, int]:
    """Get raw output and error message from a completed or failed job.

    Args:
        job_id: Job ID from URL path

    Returns:
        JSON response with job output data:
        {
            "job_id": 1,
            "status": "completed",
            "error_message": null,
            "result_summary": {...}
        }

    Raises:
        404: Job not found
    """
    # Get database connection
    db = get_configured_db()

    # Fetch job
    job = db.scan_jobs[job_id]
    if not job:
        logger.warning("Job not found: %d", job_id)
        return jsonify({"error": "Job not found"}), 404

    # Return output fields
    output_data = {
        "job_id": job.id,
        "status": job.status,
        "error_message": job.error_message,
        "result_summary": job.result_summary,
    }

    logger.debug("Retrieved output for job %d", job_id)

    return jsonify(output_data), 200


@jobs_bp.route("/<int:job_id>/findings", methods=["GET"])
@jwt_required
def get_job_findings(job_id: int) -> tuple[Any, int]:
    """Get all security findings for a specific job.

    Query parameters:
        severity: Filter by severity (critical, high, medium, low, info)
        status: Filter by finding status (open, acknowledged, resolved, false_positive)
        page: Page number (default: 1)
        per_page: Items per page (default: 20, max: 100)

    Args:
        job_id: Job ID from URL path

    Returns:
        JSON response with findings list:
        {
            "job_id": 1,
            "findings": [finding objects],
            "total": 50
        }

    Raises:
        404: Job not found
    """
    # Get database connection
    db = get_configured_db()

    # Verify job exists
    job = db.scan_jobs[job_id]
    if not job:
        logger.warning("Job not found: %d", job_id)
        return jsonify({"error": "Job not found"}), 404

    # Build query for findings
    query = db.scan_findings.job_id == job_id

    # Apply filters from query parameters
    severity = request.args.get("severity")
    if severity:
        query &= db.scan_findings.severity == severity

    status = request.args.get("status")
    if status:
        query &= db.scan_findings.status == status

    # Get pagination parameters
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)

    # Calculate offset
    offset = (page - 1) * per_page

    # Get total count
    total = db(query).count()

    # Fetch paginated findings
    rows = db(query).select(
        orderby=~db.scan_findings.discovered_at, limitby=(offset, offset + per_page)
    )

    # Convert to dictionaries
    findings = [_row_to_dict(row) for row in rows]

    logger.info(
        "Retrieved %d findings for job %d (page %d, total %d)",
        len(findings),
        job_id,
        page,
        total,
    )

    return jsonify({"job_id": job_id, "findings": findings, "total": total}), 200


@jobs_bp.route("/<int:job_id>/retry", methods=["POST"])
@jwt_required
def retry_job(job_id: int) -> tuple[Any, int]:
    """Retry a failed or cancelled job by creating a new job with same parameters.

    Args:
        job_id: Job ID from URL path

    Returns:
        202 Accepted with new job data

    Raises:
        400: Job is not in failed or cancelled status
        404: Job not found
    """
    # Get database connection
    db = get_configured_db()

    # Fetch original job
    original_job = db.scan_jobs[job_id]
    if not original_job:
        logger.warning("Job not found for retry: %d", job_id)
        return jsonify({"error": "Job not found"}), 404

    # Verify job is in retryable status
    if original_job.status not in ("failed", "cancelled"):
        logger.warning(
            "Cannot retry job %d with status %s", job_id, original_job.status
        )
        return (
            jsonify(
                {
                    "error": f"Cannot retry job with status '{original_job.status}'. "
                    "Only failed or cancelled jobs can be retried."
                }
            ),
            400,
        )

    # Get current user ID
    user_id = get_current_user_id()

    # Create new job with same parameters
    new_job_id = db.scan_jobs.insert(
        target_id=original_job.target_id,
        scanner_type=original_job.scanner_type,
        scan_type=original_job.scan_type,
        status="pending",
        priority=original_job.priority,
        config=original_job.config,
        created_at=datetime.utcnow(),
        created_by=user_id,
    )

    # Commit transaction
    db.commit()

    # Fetch new job
    new_job = db.scan_jobs[new_job_id]
    new_job_dict = _row_to_dict(new_job)

    logger.info(
        "Retrying job %d: created new job %d by user %s",
        job_id,
        new_job_id,
        user_id,
    )

    # Dispatch async Celery task
    try:
        from workers.scan_worker import execute_scan

        task = execute_scan.delay(new_job_id)
        logger.info("Dispatched Celery task %s for retry job %d", task.id, new_job_id)
    except Exception as e:
        logger.error(
            "Failed to dispatch Celery task for retry job %d: %s", new_job_id, str(e)
        )
        # Update job with error status
        db(db.scan_jobs.id == new_job_id).update(
            status="failed", error_message=f"Failed to dispatch task: {str(e)}"
        )
        db.commit()

    # Return 202 Accepted
    return jsonify(new_job_dict), 202
