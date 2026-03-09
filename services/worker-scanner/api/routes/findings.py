"""Security findings retrieval, update, and export API routes.

This module provides RESTful API endpoints for managing security findings from scans.
All routes require JWT authentication and use PyDAL for database operations.

Endpoints:
    GET /findings - List findings with filtering and pagination
    GET /findings/<id> - Get single finding details
    PATCH /findings/<id> - Update finding status
    GET /findings/stats - Get finding statistics and aggregations
    POST /findings/export - Export findings in JSON or CSV format
"""

import csv
import io
import logging
from datetime import datetime
from typing import Any, Dict, Optional

from api.middleware.auth import jwt_required
from api.schemas.finding import (
    FindingExportSchema,
    FindingFilterSchema,
    FindingResponseSchema,
    FindingStatsSchema,
    UpdateFindingSchema,
)
from database.models import get_configured_db
from flask import Blueprint, Response, jsonify, request
from marshmallow import ValidationError

# Configure logging
logger = logging.getLogger(__name__)

# Create Flask blueprint
findings_bp = Blueprint("findings", __name__)

# Initialize marshmallow schemas
finding_response_schema = FindingResponseSchema()
update_finding_schema = UpdateFindingSchema()
finding_filter_schema = FindingFilterSchema()
finding_stats_schema = FindingStatsSchema()
finding_export_schema = FindingExportSchema()


def _row_to_dict(row: Any) -> Dict[str, Any]:
    """Convert PyDAL Row object to dictionary with datetime serialization.

    Uses row.as_dict() to extract only actual database fields (excludes
    PyDAL back-reference objects like RecordDeleter). Preserves all field
    types including JSON data.

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


@findings_bp.route("", methods=["GET"])
@jwt_required
def list_findings() -> tuple[Any, int]:
    """List security findings with optional filtering and pagination.

    Dynamically builds query based on filter parameters. For scanner_type filter,
    joins with scan_jobs table to match scanner type. Results are ordered by
    discovered_at in descending order (newest first).

    Query parameters:
        severity: Filter by severity (critical, high, medium, low, info)
        status: Filter by finding status (open, acknowledged, false_positive, fixed)
        scanner_type: Filter by scanner type (nuclei, zap, openvas)
        target_id: Filter by target ID
        job_id: Filter by job ID
        page: Page number (default: 1)
        per_page: Items per page (default: 20, max: 100)

    Returns:
        JSON response with findings list, total count, and pagination info:
        {
            "findings": [finding objects],
            "total": count,
            "page": page,
            "per_page": per_page
        }
    """
    try:
        # Validate query parameters
        params = finding_filter_schema.load(request.args)
    except ValidationError as e:
        logger.warning("Invalid finding filter parameters: %s", e.messages)
        return jsonify({"error": "Invalid parameters", "details": e.messages}), 400

    # Get database connection
    db = get_configured_db()

    # Build PyDAL query dynamically based on filters
    query = db.scan_findings.id > 0  # Base query (always true)

    if params.get("severity"):
        query &= db.scan_findings.severity == params["severity"]

    if params.get("status"):
        query &= db.scan_findings.status == params["status"]

    if params.get("target_id"):
        query &= db.scan_findings.target_id == params["target_id"]

    if params.get("job_id"):
        query &= db.scan_findings.job_id == params["job_id"]

    # For scanner_type filter, join with scan_jobs table
    if params.get("scanner_type"):
        # Need to join with scan_jobs to filter by scanner_type
        query &= db.scan_findings.job_id == db.scan_jobs.id
        query &= db.scan_jobs.scanner_type == params["scanner_type"]

    # Get pagination parameters
    page = params.get("page", 1)
    per_page = params.get("per_page", 20)

    # Calculate offset for pagination
    offset = (page - 1) * per_page

    # Get total count
    total = db(query).count()

    # Fetch paginated results ordered by discovered_at desc (newest first)
    if params.get("scanner_type"):
        # With join, need to select specific fields to avoid ambiguity
        rows = db(query).select(
            db.scan_findings.ALL,
            orderby=~db.scan_findings.discovered_at,
            limitby=(offset, offset + per_page),
        )
    else:
        rows = db(query).select(
            orderby=~db.scan_findings.discovered_at,
            limitby=(offset, offset + per_page),
        )

    # Convert rows to dictionaries
    findings = [_row_to_dict(row) for row in rows]

    logger.info(
        "Listed %d findings (page %d, total %d) with filters: %s",
        len(findings),
        page,
        total,
        params,
    )

    return (
        jsonify(
            {
                "findings": findings,
                "total": total,
                "page": page,
                "per_page": per_page,
            }
        ),
        200,
    )


@findings_bp.route("/<int:finding_id>", methods=["GET"])
@jwt_required
def get_finding(finding_id: int) -> tuple[Any, int]:
    """Get details of a specific security finding.

    Retrieves a single finding by ID with all associated data including
    vulnerability details, evidence, and status.

    Args:
        finding_id: Finding ID from URL path

    Returns:
        JSON response with finding details

    Raises:
        404: Finding not found
    """
    # Get database connection
    db = get_configured_db()

    # Fetch finding
    finding = db.scan_findings[finding_id]
    if not finding:
        logger.warning("Finding not found: %d", finding_id)
        return jsonify({"error": "Finding not found"}), 404

    finding_dict = _row_to_dict(finding)
    logger.debug("Retrieved finding %d", finding_id)

    return jsonify(finding_dict), 200


@findings_bp.route("/<int:finding_id>", methods=["PATCH"])
@jwt_required
def update_finding(finding_id: int) -> tuple[Any, int]:
    """Update finding status (acknowledge, mark as false positive, mark as fixed).

    Validates the update request with UpdateFindingSchema, updates the finding's
    status field, and updates the updated_at timestamp.

    Request body:
        {
            "status": "acknowledged" | "false_positive" | "fixed" | "open"
        }

    Args:
        finding_id: Finding ID from URL path

    Returns:
        JSON response with updated finding details

    Raises:
        400: Invalid request data
        404: Finding not found
    """
    try:
        # Validate request body
        data = update_finding_schema.load(request.get_json())
    except ValidationError as e:
        logger.warning("Invalid finding update request: %s", e.messages)
        return jsonify({"error": "Invalid request data", "details": e.messages}), 400

    # Get database connection
    db = get_configured_db()

    # Verify finding exists
    finding = db.scan_findings[finding_id]
    if not finding:
        logger.warning("Finding not found for update: %d", finding_id)
        return jsonify({"error": "Finding not found"}), 404

    # Update finding status and updated_at timestamp
    db(db.scan_findings.id == finding_id).update(
        status=data["status"], updated_at=datetime.utcnow()
    )

    # Commit transaction
    db.commit()

    # Fetch updated finding
    updated_finding = db.scan_findings[finding_id]
    finding_dict = _row_to_dict(updated_finding)

    logger.info(
        "Updated finding %d status to '%s'",
        finding_id,
        data["status"],
    )

    return jsonify(finding_dict), 200


@findings_bp.route("/stats", methods=["GET"])
@jwt_required
def get_findings_stats() -> tuple[Any, int]:
    """Get aggregate statistics about security findings.

    Provides comprehensive statistics including total count, breakdown by
    severity level, breakdown by status, and breakdown by scanner type.
    Scanner type data comes from joining with scan_jobs table.

    Returns:
        JSON response with statistics:
        {
            "total": total_count,
            "by_severity": {
                "critical": count,
                "high": count,
                "medium": count,
                "low": count,
                "info": count
            },
            "by_status": {
                "open": count,
                "acknowledged": count,
                "false_positive": count,
                "fixed": count
            },
            "by_scanner": {
                "nuclei": count,
                "zap": count,
                "openvas": count
            }
        }
    """
    # Get database connection
    db = get_configured_db()

    # Get total count
    total = db(db.scan_findings.id > 0).count()

    # Count by severity - group by severity level
    severity_stats = {}
    for severity in ["critical", "high", "medium", "low", "info"]:
        count = db(db.scan_findings.severity == severity).count()
        severity_stats[severity] = count

    # Count by status - group by status
    status_stats = {}
    for status in ["open", "acknowledged", "false_positive", "fixed"]:
        count = db(db.scan_findings.status == status).count()
        status_stats[status] = count

    # Count by scanner type - join with scan_jobs and group by scanner_type
    scanner_stats = {}
    for scanner_type in ["nuclei", "zap", "openvas"]:
        # Query findings joined with their jobs, filtered by scanner type
        query = (db.scan_findings.job_id == db.scan_jobs.id) & (
            db.scan_jobs.scanner_type == scanner_type
        )
        count = db(query).count()
        scanner_stats[scanner_type] = count

    stats = {
        "total": total,
        "by_severity": severity_stats,
        "by_status": status_stats,
        "by_scanner": scanner_stats,
    }

    logger.debug("Retrieved finding statistics: %s", stats)

    return jsonify(stats), 200


@findings_bp.route("/export", methods=["POST"])
@jwt_required
def export_findings() -> tuple[Any, int]:
    """Export security findings in JSON or CSV format with optional filters.

    Validates the export request with FindingExportSchema, builds a query with
    specified filters, and returns findings in the requested format. Supports
    JSON array export and CSV file export with standard columns.

    CSV export includes columns: id, severity, title, affected_url, cvss_score,
    cve_ids, status, discovered_at.

    Request body:
        {
            "format": "json" | "csv",
            "severity": ["critical", "high"],  # optional, default: all
            "status": ["open", "acknowledged"],  # optional, default: all
            "target_id": 1,  # optional
            "job_id": 1  # optional
        }

    Returns:
        JSON response for format "json": Array of finding objects
        CSV response for format "csv": CSV file attachment with findings

    Raises:
        400: Invalid request data
    """
    try:
        # Validate request body
        data = finding_export_schema.load(request.get_json())
    except ValidationError as e:
        logger.warning("Invalid finding export request: %s", e.messages)
        return jsonify({"error": "Invalid request data", "details": e.messages}), 400

    # Get database connection
    db = get_configured_db()

    # Build PyDAL query with filters
    query = db.scan_findings.id > 0  # Base query (always true)

    # Apply severity filters if provided
    if data.get("severity") and len(data["severity"]) > 0:
        severity_list = data["severity"]
        severity_query = db.scan_findings.severity.belongs(severity_list)
        query &= severity_query

    # Apply status filters if provided
    if data.get("status") and len(data["status"]) > 0:
        status_list = data["status"]
        status_query = db.scan_findings.status.belongs(status_list)
        query &= status_query

    # Apply target_id filter if provided
    if data.get("target_id"):
        query &= db.scan_findings.target_id == data["target_id"]

    # Apply job_id filter if provided
    if data.get("job_id"):
        query &= db.scan_findings.job_id == data["job_id"]

    # Fetch all matching findings (ordered by discovered_at desc)
    findings_rows = db(query).select(orderby=~db.scan_findings.discovered_at)

    # Convert to dictionaries
    findings = [_row_to_dict(row) for row in findings_rows]

    logger.info(
        "Exporting %d findings in %s format with filters: %s",
        len(findings),
        data["format"],
        data,
    )

    # Return JSON export
    if data["format"] == "json":
        return jsonify(findings), 200

    # Return CSV export
    elif data["format"] == "csv":
        # Build CSV in memory using StringIO
        output = io.StringIO()
        writer = csv.writer(output)

        # Write CSV header
        csv_headers = [
            "id",
            "severity",
            "title",
            "affected_url",
            "cvss_score",
            "cve_ids",
            "status",
            "discovered_at",
        ]
        writer.writerow(csv_headers)

        # Write CSV rows
        for finding in findings:
            # Convert cve_ids list to comma-separated string
            cve_ids_str = (
                ",".join(finding.get("cve_ids", [])) if finding.get("cve_ids") else ""
            )

            # Format discovered_at as ISO string if it's a datetime
            discovered_at = finding.get("discovered_at", "")
            if isinstance(discovered_at, datetime):
                discovered_at = discovered_at.isoformat()

            row = [
                finding.get("id", ""),
                finding.get("severity", ""),
                finding.get("title", ""),
                finding.get("affected_url", ""),
                finding.get("cvss_score", ""),
                cve_ids_str,
                finding.get("status", ""),
                discovered_at,
            ]
            writer.writerow(row)

        # Get CSV content from StringIO
        csv_content = output.getvalue()
        output.close()

        # Return as CSV attachment response
        response = Response(csv_content, mimetype="text/csv")
        response.headers["Content-Disposition"] = (
            "attachment; filename=findings_export.csv"
        )

        return response, 200

    # Should not reach here due to schema validation
    return jsonify({"error": "Invalid export format"}), 400
