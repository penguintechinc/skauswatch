"""Issue Listing and Status Update API Endpoints."""

from flask import Blueprint, jsonify, request

from ...middleware import auth_required, role_required
from ...models import (
    get_db,
    get_comments_by_review,
    update_comment_status,
    get_review_by_id,
)

issues_bp = Blueprint("issues", __name__, url_prefix="/api/v1/issues")


@issues_bp.route("", methods=["GET"])
@auth_required
def list_issues():
    """List all issues/comments across reviews."""
    db = get_db()

    # Pagination
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    # Filters
    severity = request.args.get("severity")
    category = request.args.get("category")
    status = request.args.get("status")
    review_id = request.args.get("review_id", type=int)

    # Validate pagination
    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20

    # Build query
    query = db.review_comments.id > 0

    if review_id:
        query &= db.review_comments.review_id == review_id
    if severity:
        query &= db.review_comments.severity == severity
    if category:
        query &= db.review_comments.category == category
    if status:
        query &= db.review_comments.status == status

    # Get total count
    total = db(query).count()

    # Calculate offset
    offset = (page - 1) * per_page

    # Execute query
    comments = db(query).select(
        orderby=~db.review_comments.created_at,
        limitby=(offset, offset + per_page),
    )

    # Convert to dicts and enrich with review info
    issues = []
    for comment in comments:
        issue = comment.as_dict()
        # Add review info
        review = get_review_by_id(comment.review_id)
        if review:
            issue["review_external_id"] = review.get("external_id")
            issue["repository"] = review.get("repository")
            issue["platform"] = review.get("platform")
        issues.append(issue)

    return jsonify({
        "data": issues,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
        "filters": {
            "severity": severity,
            "category": category,
            "status": status,
            "review_id": review_id,
        },
    }), 200


@issues_bp.route("/<int:comment_id>", methods=["GET"])
@auth_required
def get_issue(comment_id: int):
    """Get a specific issue/comment."""
    db = get_db()

    comment = db(db.review_comments.id == comment_id).select().first()
    if not comment:
        return jsonify({"error": "Issue not found"}), 404

    issue = comment.as_dict()

    # Add review info
    review = get_review_by_id(comment.review_id)
    if review:
        issue["review_external_id"] = review.get("external_id")
        issue["repository"] = review.get("repository")
        issue["platform"] = review.get("platform")

    return jsonify(issue), 200


@issues_bp.route("/<int:comment_id>/status", methods=["PATCH"])
@auth_required
@role_required("admin", "maintainer")
def update_issue_status(comment_id: int):
    """Update issue/comment status."""
    db = get_db()

    comment = db(db.review_comments.id == comment_id).select().first()
    if not comment:
        return jsonify({"error": "Issue not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    new_status = data.get("status")
    if not new_status:
        return jsonify({"error": "Status is required"}), 400

    # Validate status
    valid_statuses = ["open", "acknowledged", "fixed", "wont_fix", "false_positive"]
    if new_status not in valid_statuses:
        return jsonify({
            "error": f"Invalid status: {new_status}",
            "valid_statuses": valid_statuses,
        }), 400

    # Update status
    updated_comment = update_comment_status(comment_id, new_status)

    return jsonify({
        "message": f"Issue status updated to {new_status}",
        "issue": updated_comment,
    }), 200


@issues_bp.route("/by-severity", methods=["GET"])
@auth_required
def list_issues_by_severity():
    """Get issue count breakdown by severity."""
    db = get_db()

    review_id = request.args.get("review_id", type=int)
    category = request.args.get("category")

    # Build query
    query = db.review_comments.id > 0
    if review_id:
        query &= db.review_comments.review_id == review_id
    if category:
        query &= db.review_comments.category == category

    # Count by severity
    severities = ["critical", "major", "minor", "suggestion"]
    breakdown = {}

    for sev in severities:
        count = db(query & (db.review_comments.severity == sev)).count()
        breakdown[sev] = count

    return jsonify({
        "breakdown": breakdown,
        "total": sum(breakdown.values()),
        "filters": {
            "review_id": review_id,
            "category": category,
        },
    }), 200


@issues_bp.route("/by-category", methods=["GET"])
@auth_required
def list_issues_by_category():
    """Get issue count breakdown by category."""
    db = get_db()

    review_id = request.args.get("review_id", type=int)
    severity = request.args.get("severity")

    # Build query
    query = db.review_comments.id > 0
    if review_id:
        query &= db.review_comments.review_id == review_id
    if severity:
        query &= db.review_comments.severity == severity

    # Count by category
    categories = ["security", "best_practices", "framework", "iac"]
    breakdown = {}

    for cat in categories:
        count = db(query & (db.review_comments.category == cat)).count()
        breakdown[cat] = count

    return jsonify({
        "breakdown": breakdown,
        "total": sum(breakdown.values()),
        "filters": {
            "review_id": review_id,
            "severity": severity,
        },
    }), 200


@issues_bp.route("/by-status", methods=["GET"])
@auth_required
def list_issues_by_status():
    """Get issue count breakdown by status."""
    db = get_db()

    review_id = request.args.get("review_id", type=int)

    # Build query
    query = db.review_comments.id > 0
    if review_id:
        query &= db.review_comments.review_id == review_id

    # Count by status
    statuses = ["open", "acknowledged", "fixed", "wont_fix", "false_positive"]
    breakdown = {}

    for stat in statuses:
        count = db(query & (db.review_comments.status == stat)).count()
        breakdown[stat] = count

    return jsonify({
        "breakdown": breakdown,
        "total": sum(breakdown.values()),
        "filters": {
            "review_id": review_id,
        },
    }), 200


@issues_bp.route("/critical", methods=["GET"])
@auth_required
def list_critical_issues():
    """Get all critical issues."""
    db = get_db()

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    review_id = request.args.get("review_id", type=int)

    # Validate pagination
    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20

    # Build query
    query = db.review_comments.severity == "critical"
    if review_id:
        query &= db.review_comments.review_id == review_id

    total = db(query).count()
    offset = (page - 1) * per_page

    comments = db(query).select(
        orderby=~db.review_comments.created_at,
        limitby=(offset, offset + per_page),
    )

    issues = []
    for comment in comments:
        issue = comment.as_dict()
        review = get_review_by_id(comment.review_id)
        if review:
            issue["review_external_id"] = review.get("external_id")
            issue["repository"] = review.get("repository")
        issues.append(issue)

    return jsonify({
        "data": issues,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }), 200


@issues_bp.route("/unresolved", methods=["GET"])
@auth_required
def list_unresolved_issues():
    """Get all unresolved issues (open and acknowledged)."""
    db = get_db()

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    review_id = request.args.get("review_id", type=int)

    # Validate pagination
    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20

    # Build query
    query = (db.review_comments.status == "open") | (db.review_comments.status == "acknowledged")
    if review_id:
        query &= db.review_comments.review_id == review_id

    total = db(query).count()
    offset = (page - 1) * per_page

    comments = db(query).select(
        orderby=~db.review_comments.created_at,
        limitby=(offset, offset + per_page),
    )

    issues = []
    for comment in comments:
        issue = comment.as_dict()
        review = get_review_by_id(comment.review_id)
        if review:
            issue["review_external_id"] = review.get("external_id")
            issue["repository"] = review.get("repository")
        issues.append(issue)

    return jsonify({
        "data": issues,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }), 200
