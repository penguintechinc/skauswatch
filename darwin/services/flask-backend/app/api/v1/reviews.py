"""Review API Endpoints - POST/GET/retry reviews."""

from flask import Blueprint, g, jsonify, request
from datetime import datetime

from ...middleware import auth_required, role_required
from ...models import (
    create_review,
    get_review_by_id,
    get_review_by_external_id,
    list_reviews,
    update_review_status,
    get_comments_by_review,
    get_detections_by_review,
    get_usage_by_review,
    get_db,
)

reviews_bp = Blueprint("reviews", __name__, url_prefix="/api/v1/reviews")


@reviews_bp.route("", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
def create_review_request():
    """Create a new review request."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    # Validate required fields
    required_fields = ["external_id", "platform", "repository", "review_type", "ai_provider"]
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Validate enums
    if data.get("platform") not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    if data.get("review_type") not in ["differential", "whole"]:
        return jsonify({"error": "Review type must be 'differential' or 'whole'"}), 400

    # Check for existing external_id
    existing = get_review_by_external_id(data.get("external_id"))
    if existing:
        return jsonify({"error": "Review with this external_id already exists"}), 409

    # Create review
    categories = data.get("categories", [])
    if not isinstance(categories, list):
        return jsonify({"error": "Categories must be a list"}), 400

    # Extract user and tenant context from authenticated session
    user = g.current_user
    user_tenant_id = getattr(g, "user_tenant_id", None)

    review = create_review(
        external_id=data.get("external_id"),
        platform=data.get("platform"),
        repository=data.get("repository"),
        review_type=data.get("review_type"),
        categories=categories,
        ai_provider=data.get("ai_provider"),
        pull_request_id=data.get("pull_request_id"),
        pull_request_url=data.get("pull_request_url"),
        base_sha=data.get("base_sha"),
        head_sha=data.get("head_sha"),
        triggered_by=user.get("id") if user else None,
        tenant_id=user_tenant_id,
    )

    return jsonify(review), 201


@reviews_bp.route("/<int:review_id>", methods=["GET"])
@auth_required
def get_review(review_id: int):
    """Get a specific review by ID."""
    review = get_review_by_id(review_id)

    if not review:
        return jsonify({"error": "Review not found"}), 404

    # Enrich response with related data
    comments = get_comments_by_review(review_id)
    detections = get_detections_by_review(review_id)
    usage = get_usage_by_review(review_id)

    return jsonify({
        **review,
        "comments": comments,
        "detections": detections,
        "usage": usage,
    }), 200


@reviews_bp.route("", methods=["GET"])
@auth_required
def list_all_reviews():
    """List reviews with optional filtering."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    platform = request.args.get("platform")
    repository = request.args.get("repository")
    status = request.args.get("status")

    # Validate pagination
    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20

    # Scope to user's tenant when available
    user_tenant_id = getattr(g, "user_tenant_id", None)

    reviews, total = list_reviews(
        platform=platform,
        repository=repository,
        status=status,
        tenant_id=user_tenant_id,
        page=page,
        per_page=per_page,
    )

    return jsonify({
        "data": reviews,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }), 200


@reviews_bp.route("/<int:review_id>/retry", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
def retry_review(review_id: int):
    """Retry a failed review."""
    review = get_review_by_id(review_id)

    if not review:
        return jsonify({"error": "Review not found"}), 404

    # Only allow retrying failed reviews
    if review.get("status") not in ["failed", "cancelled"]:
        return jsonify({
            "error": f"Cannot retry review with status '{review.get('status')}'",
            "allowed_statuses": ["failed", "cancelled"],
        }), 400

    # Reset review to queued status
    updated_review = update_review_status(review_id, "queued")

    return jsonify({
        "message": "Review queued for retry",
        "review": updated_review,
    }), 200


@reviews_bp.route("/<int:review_id>/cancel", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
def cancel_review(review_id: int):
    """Cancel an in-progress or queued review."""
    review = get_review_by_id(review_id)

    if not review:
        return jsonify({"error": "Review not found"}), 404

    # Only allow cancelling queued or in-progress reviews
    if review.get("status") not in ["queued", "in_progress"]:
        return jsonify({
            "error": f"Cannot cancel review with status '{review.get('status')}'",
            "allowed_statuses": ["queued", "in_progress"],
        }), 400

    # Update review to cancelled
    updated_review = update_review_status(review_id, "cancelled")

    return jsonify({
        "message": "Review cancelled",
        "review": updated_review,
    }), 200


@reviews_bp.route("/external/<external_id>", methods=["GET"])
@auth_required
def get_review_by_external(external_id: str):
    """Get review by external ID (from GitHub/GitLab)."""
    review = get_review_by_external_id(external_id)

    if not review:
        return jsonify({"error": "Review not found"}), 404

    # Enrich response with related data
    comments = get_comments_by_review(review.get("id"))
    detections = get_detections_by_review(review.get("id"))
    usage = get_usage_by_review(review.get("id"))

    return jsonify({
        **review,
        "comments": comments,
        "detections": detections,
        "usage": usage,
    }), 200


@reviews_bp.route("/<int:review_id>/status", methods=["PATCH"])
@auth_required
@role_required("admin", "maintainer")
def update_review(review_id: int):
    """Update review status and metrics."""
    review = get_review_by_id(review_id)

    if not review:
        return jsonify({"error": "Review not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    # Validate status if provided
    new_status = data.get("status")
    if new_status:
        valid_statuses = ["queued", "in_progress", "completed", "failed", "cancelled"]
        if new_status not in valid_statuses:
            return jsonify({
                "error": f"Invalid status: {new_status}",
                "valid_statuses": valid_statuses,
            }), 400

    # Update review
    updated_review = update_review_status(
        review_id,
        new_status or review.get("status"),
        error_message=data.get("error_message"),
        files_reviewed=data.get("files_reviewed"),
        comments_posted=data.get("comments_posted"),
    )

    return jsonify(updated_review), 200


@reviews_bp.route("/<int:review_id>/comments", methods=["GET"])
@auth_required
def get_review_comments(review_id: int):
    """Get all comments for a review."""
    review = get_review_by_id(review_id)

    if not review:
        return jsonify({"error": "Review not found"}), 404

    category = request.args.get("category")
    severity = request.args.get("severity")

    comments = get_comments_by_review(
        review_id,
        category=category,
        severity=severity,
    )

    return jsonify({
        "review_id": review_id,
        "total": len(comments),
        "comments": comments,
    }), 200
