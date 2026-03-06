"""Dashboard Analytics API - Aggregated statistics and findings with drill-down."""

from flask import Blueprint, jsonify, request
from typing import Any
from datetime import datetime, timedelta

from ...middleware import auth_required
from ...models import get_db

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/stats", methods=["GET"])
@auth_required
def get_dashboard_stats() -> tuple[dict[str, Any], int]:
    """
    Get aggregated dashboard statistics.

    Returns:
        JSON response with overview stats, findings by severity, and platform breakdown
    """
    db = get_db()

    # Calculate date threshold for findings (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)

    # Overview stats
    total_repositories = db(db.repo_configs).count()
    total_reviews = db(db.reviews).count()
    pending_reviews = db(db.reviews.status == "queued").count()

    # Findings by severity (last 30 days)
    findings_query = db.review_comments.created_at >= thirty_days_ago

    critical_count = db(findings_query & (db.review_comments.severity == "critical")).count()
    major_count = db(findings_query & (db.review_comments.severity == "major")).count()
    minor_count = db(findings_query & (db.review_comments.severity == "minor")).count()
    suggestion_count = db(findings_query & (db.review_comments.severity == "suggestion")).count()

    # Repositories by platform
    platform_counts = {}
    for platform in ["github", "gitlab", "git"]:
        count = db(db.repo_configs.platform == platform).count()
        if count > 0:
            platform_counts[platform] = count

    return jsonify({
        "overview": {
            "total_repositories": total_repositories,
            "total_reviews": total_reviews,
            "pending_reviews": pending_reviews,
        },
        "findings": {
            "critical": critical_count,
            "major": major_count,
            "minor": minor_count,
            "suggestion": suggestion_count,
        },
        "platforms": platform_counts,
    }), 200


@dashboard_bp.route("/findings", methods=["GET"])
@auth_required
def get_dashboard_findings() -> tuple[dict[str, Any], int]:
    """
    Get findings with drill-down filtering.

    Query Parameters:
        platform: Filter by platform (github, gitlab, git)
        organization: Filter by organization
        repository_id: Filter by repository ID
        severity: Filter by severity (critical, major, minor, suggestion)
        page: Page number (default: 1)
        per_page: Results per page (default: 20, max: 100)

    Returns:
        JSON response with filtered findings and pagination info
    """
    # Get query parameters
    platform = request.args.get("platform")
    organization = request.args.get("organization")
    repository_id_str = request.args.get("repository_id")
    severity = request.args.get("severity")
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)

    db = get_db()
    offset = (page - 1) * per_page

    # Build query with joins
    # Join review_comments → reviews → repo_configs
    query = (
        (db.review_comments.review_id == db.reviews.id) &
        (db.reviews.repository == db.repo_configs.repository) &
        (db.reviews.platform == db.repo_configs.platform)
    )

    # Apply filters
    if platform:
        query &= db.repo_configs.platform == platform
    if organization:
        query &= db.repo_configs.platform_organization == organization
    if repository_id_str:
        try:
            repository_id = int(repository_id_str)
            query &= db.repo_configs.id == repository_id
        except ValueError:
            return jsonify({"error": "Invalid repository_id"}), 400
    if severity:
        if severity not in ["critical", "major", "minor", "suggestion"]:
            return jsonify({"error": "Invalid severity"}), 400
        query &= db.review_comments.severity == severity

    # Get findings with repository info
    findings_raw = db(query).select(
        db.review_comments.ALL,
        db.repo_configs.id,
        db.repo_configs.repository,
        db.repo_configs.platform,
        db.repo_configs.display_name,
        orderby=~db.review_comments.created_at,
        limitby=(offset, offset + per_page),
    )

    # Get total count
    total = db(query).count()

    # Format findings
    findings = []
    for row in findings_raw:
        finding = {
            "id": row.review_comments.id,
            "review_id": row.review_comments.review_id,
            "file_path": row.review_comments.file_path,
            "line_start": row.review_comments.line_start,
            "line_end": row.review_comments.line_end,
            "severity": row.review_comments.severity,
            "category": row.review_comments.category,
            "title": row.review_comments.title,
            "body": row.review_comments.body,
            "suggestion": row.review_comments.suggestion,
            "created_at": row.review_comments.created_at.isoformat() if row.review_comments.created_at else None,
            "repository": {
                "id": row.repo_configs.id,
                "name": row.repo_configs.repository,
                "platform": row.repo_configs.platform,
                "display_name": row.repo_configs.display_name,
            }
        }
        findings.append(finding)

    # Calculate pagination metadata
    pages = (total + per_page - 1) // per_page  # Ceiling division

    return jsonify({
        "findings": findings,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": pages,
        }
    }), 200
