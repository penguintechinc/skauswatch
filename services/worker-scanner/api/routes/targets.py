"""Flask blueprint for scan target CRUD operations.

This module provides REST API endpoints for managing security scan targets.
All endpoints require JWT authentication and use PyDAL for database operations.
Supports pagination, filtering, and full CRUD operations on scan targets.
"""

from datetime import datetime
from typing import Any, Dict, List, Tuple

from flask import Blueprint, g, jsonify, request
from marshmallow import ValidationError

from api.middleware.auth import get_current_user_id, jwt_required
from api.schemas.target import (
    CreateTargetSchema,
    TargetResponseSchema,
    UpdateTargetSchema,
)
from database.models import define_tables, get_configured_db

targets_bp = Blueprint("targets", __name__)


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """Convert PyDAL Row to dictionary with proper serialization.

    Uses row.as_dict() to extract only actual database fields (excludes
    PyDAL back-reference objects). Handles datetime serialization to
    ISO format strings and renames scan_metadata to metadata.

    Args:
        row: PyDAL Row object from database query result

    Returns:
        Dictionary with all fields properly serialized

    Example:
        >>> row = db.scan_targets[1]
        >>> target_dict = _row_to_dict(row)
        >>> print(target_dict['created_at'])  # '2025-01-29T12:00:00'
    """
    result = row.as_dict()
    for key, value in list(result.items()):
        if isinstance(value, datetime):
            result[key] = value.isoformat()
    # Rename scan_metadata to metadata for API response
    if "scan_metadata" in result:
        result["metadata"] = result.pop("scan_metadata")
    return result


@targets_bp.route("", methods=["GET"])
@jwt_required
def list_targets() -> Tuple[Dict[str, Any], int]:
    """List all scan targets with optional pagination and filtering.

    Query Parameters:
        page (int, optional): Page number for pagination (default: 1)
        per_page (int, optional): Items per page (default: 20)
        enabled (bool, optional): Filter by enabled status (true/false/null)

    Returns:
        JSON response with target list, total count, and pagination info

    Example:
        GET /targets?page=1&per_page=10&enabled=true
        {
            "targets": [...],
            "total": 100,
            "page": 1,
            "per_page": 10
        }
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

        # Build query condition
        query = db.scan_targets.id > 0

        # Apply enabled filter if provided
        enabled_param = request.args.get("enabled", None)
        if enabled_param is not None:
            enabled_value = enabled_param.lower() in ("true", "1", "yes")
            query &= db.scan_targets.enabled == enabled_value

        # Get total count
        total_count = db(query).count()

        # Calculate offset
        offset = (page - 1) * per_page

        # Execute query with pagination
        rows = db(query).select(
            orderby=~db.scan_targets.created_at, limitby=(offset, offset + per_page)
        )

        # Convert rows to dictionaries
        targets = [_row_to_dict(row) for row in rows]

        return (
            jsonify(
                {
                    "targets": targets,
                    "total": total_count,
                    "page": page,
                    "per_page": per_page,
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": f"Failed to list targets: {str(e)}", "code": 500}), 500


@targets_bp.route("", methods=["POST"])
@jwt_required
def create_target() -> Tuple[Dict[str, Any], int]:
    """Create a new scan target.

    Request Body:
        name (str, required): Target name (1-255 chars)
        target_type (str, required): Type of target (domain, ip, url, cidr)
        target_value (str, required): Target value (1-2048 chars)
        description (str, optional): Target description (max 5000 chars)
        enabled (bool, optional): Enable scanning (default: true)
        tags (list, optional): List of tags (default: [])
        metadata (dict, optional): Custom metadata (default: {})

    Returns:
        201 Created: JSON with created target including ID and timestamps
        400 Bad Request: Validation error or duplicate name
        409 Conflict: Target name already exists

    Example:
        POST /targets
        {
            "name": "example.com",
            "target_type": "domain",
            "target_value": "example.com",
            "description": "Main website"
        }
    """
    try:
        # Get request JSON
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required", "code": 400}), 400

        # Validate request with schema
        schema = CreateTargetSchema()
        try:
            validated_data = schema.load(data)
        except ValidationError as e:
            return (
                jsonify(
                    {"error": "Validation failed", "details": e.messages, "code": 400}
                ),
                400,
            )

        # Get database connection
        db = get_configured_db()

        # Check for duplicate name
        duplicate_count = db(db.scan_targets.name == validated_data["name"]).count()
        if duplicate_count > 0:
            return (
                jsonify(
                    {"error": "A target with this name already exists", "code": 409}
                ),
                409,
            )

        # Get current user ID
        user_id = get_current_user_id()

        # Prepare insert data
        insert_data = {
            "name": validated_data["name"],
            "target_type": validated_data["target_type"],
            "target_value": validated_data["target_value"],
            "description": validated_data.get("description", ""),
            "enabled": validated_data.get("enabled", True),
            "tags": validated_data.get("tags", []),
            "scan_metadata": validated_data.get("metadata", {}),
            "created_by": user_id,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }

        # Insert into database
        target_id = db.scan_targets.insert(**insert_data)
        db.commit()

        # Fetch the created target
        row = db.scan_targets[target_id]
        target_dict = _row_to_dict(row)

        return jsonify(target_dict), 201

    except ValidationError as e:
        return (
            jsonify({"error": "Validation failed", "details": e.messages, "code": 400}),
            400,
        )
    except Exception as e:
        return (
            jsonify({"error": f"Failed to create target: {str(e)}", "code": 500}),
            500,
        )


@targets_bp.route("/<int:target_id>", methods=["GET"])
@jwt_required
def get_target(target_id: int) -> Tuple[Dict[str, Any], int]:
    """Retrieve a specific scan target by ID.

    Args:
        target_id (int): The ID of the target to retrieve

    Returns:
        200 OK: JSON with target details
        404 Not Found: Target does not exist

    Example:
        GET /targets/123
        {
            "id": 123,
            "name": "example.com",
            "target_type": "domain",
            "target_value": "example.com",
            ...
        }
    """
    try:
        # Get database connection
        db = get_configured_db()

        # Fetch target
        row = db.scan_targets[target_id]
        if not row:
            return jsonify({"error": "Target not found", "code": 404}), 404

        # Convert to dictionary
        target_dict = _row_to_dict(row)

        return jsonify(target_dict), 200

    except Exception as e:
        return (
            jsonify({"error": f"Failed to retrieve target: {str(e)}", "code": 500}),
            500,
        )


@targets_bp.route("/<int:target_id>", methods=["PUT"])
@jwt_required
def update_target(target_id: int) -> Tuple[Dict[str, Any], int]:
    """Update a scan target.

    Args:
        target_id (int): The ID of the target to update

    Request Body:
        name (str, optional): Target name
        target_type (str, optional): Type of target
        target_value (str, optional): Target value
        description (str, optional): Target description
        enabled (bool, optional): Enable/disable scanning
        tags (list, optional): List of tags
        metadata (dict, optional): Custom metadata

    Returns:
        200 OK: JSON with updated target
        400 Bad Request: Validation error
        404 Not Found: Target does not exist

    Example:
        PUT /targets/123
        {
            "description": "Updated description",
            "enabled": false
        }
    """
    try:
        # Get request JSON
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body is required", "code": 400}), 400

        # Validate request with schema
        schema = UpdateTargetSchema()
        try:
            validated_data = schema.load(data)
        except ValidationError as e:
            return (
                jsonify(
                    {"error": "Validation failed", "details": e.messages, "code": 400}
                ),
                400,
            )

        # Get database connection
        db = get_configured_db()

        # Check target exists
        row = db.scan_targets[target_id]
        if not row:
            return jsonify({"error": "Target not found", "code": 404}), 404

        # Prepare update data
        update_data = {}
        if "name" in validated_data:
            update_data["name"] = validated_data["name"]
        if "target_type" in validated_data:
            update_data["target_type"] = validated_data["target_type"]
        if "target_value" in validated_data:
            update_data["target_value"] = validated_data["target_value"]
        if "description" in validated_data:
            update_data["description"] = validated_data["description"]
        if "enabled" in validated_data:
            update_data["enabled"] = validated_data["enabled"]
        if "tags" in validated_data:
            update_data["tags"] = validated_data["tags"]
        if "metadata" in validated_data:
            update_data["scan_metadata"] = validated_data["metadata"]

        # Always update timestamp
        update_data["updated_at"] = datetime.utcnow()

        # Update in database
        db(db.scan_targets.id == target_id).update(**update_data)
        db.commit()

        # Fetch updated target
        row = db.scan_targets[target_id]
        target_dict = _row_to_dict(row)

        return jsonify(target_dict), 200

    except ValidationError as e:
        return (
            jsonify({"error": "Validation failed", "details": e.messages, "code": 400}),
            400,
        )
    except Exception as e:
        return (
            jsonify({"error": f"Failed to update target: {str(e)}", "code": 500}),
            500,
        )


@targets_bp.route("/<int:target_id>", methods=["DELETE"])
@jwt_required
def delete_target(target_id: int) -> Tuple[Dict[str, Any], int]:
    """Delete a scan target and all related data.

    Checks for active jobs before deletion. Related findings, jobs, and
    schedules are cascade-deleted via database constraints.

    Args:
        target_id (int): The ID of the target to delete

    Returns:
        204 No Content: Target deleted successfully
        404 Not Found: Target does not exist
        409 Conflict: Active jobs exist for this target

    Example:
        DELETE /targets/123
        (returns 204 No Content)
    """
    try:
        # Get database connection
        db = get_configured_db()

        # Check target exists
        row = db.scan_targets[target_id]
        if not row:
            return jsonify({"error": "Target not found", "code": 404}), 404

        # Check for active jobs
        active_jobs_count = db(
            (db.scan_jobs.target_id == target_id)
            & (db.scan_jobs.status.belongs(["pending", "running"]))
        ).count()

        if active_jobs_count > 0:
            return (
                jsonify(
                    {
                        "error": f"Cannot delete target with {active_jobs_count} active job(s)",
                        "code": 409,
                    }
                ),
                409,
            )

        # Delete related schedules (will cascade to jobs and findings)
        db(db.scan_schedules.target_id == target_id).delete()

        # Delete related jobs (will cascade to findings)
        db(db.scan_jobs.target_id == target_id).delete()

        # Delete related findings
        db(db.scan_findings.target_id == target_id).delete()

        # Delete target
        db(db.scan_targets.id == target_id).delete()

        # Commit all deletions
        db.commit()

        return "", 204

    except Exception as e:
        return (
            jsonify({"error": f"Failed to delete target: {str(e)}", "code": 500}),
            500,
        )


@targets_bp.route("/<int:target_id>/history", methods=["GET"])
@jwt_required
def get_target_history(target_id: int) -> Tuple[Dict[str, Any], int]:
    """Get scan job history for a specific target.

    Returns all scan jobs associated with a target, ordered by most recent first.
    Includes job status, results, and execution details.

    Args:
        target_id (int): The ID of the target

    Returns:
        200 OK: JSON with target ID and list of jobs
        404 Not Found: Target does not exist

    Example:
        GET /targets/123/history
        {
            "target_id": 123,
            "jobs": [
                {
                    "id": 1,
                    "scanner_type": "nmap",
                    "status": "completed",
                    "created_at": "2025-01-29T12:00:00",
                    ...
                }
            ]
        }
    """
    try:
        # Get database connection
        db = get_configured_db()

        # Check target exists
        row = db.scan_targets[target_id]
        if not row:
            return jsonify({"error": "Target not found", "code": 404}), 404

        # Fetch all jobs for this target, ordered by created_at descending
        job_rows = db(db.scan_jobs.target_id == target_id).select(
            orderby=~db.scan_jobs.created_at
        )

        # Convert jobs to dictionaries
        jobs = [_row_to_dict(job) for job in job_rows]

        return jsonify({"target_id": target_id, "jobs": jobs}), 200

    except Exception as e:
        return (
            jsonify(
                {"error": f"Failed to retrieve target history: {str(e)}", "code": 500}
            ),
            500,
        )
