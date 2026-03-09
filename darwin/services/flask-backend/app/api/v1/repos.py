"""Repository API Endpoints - Standalone repo review endpoints."""

from flask import Blueprint, jsonify, request

from ...middleware import auth_required, role_required
from ...models import (
    create_review,
    list_reviews,
    get_review_by_id,
    get_db,
)

repos_bp = Blueprint("repos", __name__, url_prefix="/api/v1/repos")


@repos_bp.route("/<platform>/<path:repository>/review", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
def trigger_standalone_review(platform: str, repository: str):
    """Trigger a standalone review for a repository."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    data = request.get_json() or {}

    # Validate required fields
    review_type = data.get("review_type", "whole")
    if review_type not in ["differential", "whole"]:
        return jsonify({"error": "Review type must be 'differential' or 'whole'"}), 400

    # Create external ID
    import uuid
    external_id = f"{platform}-{repository}-{uuid.uuid4()}"

    # Create review
    review = create_review(
        external_id=external_id,
        platform=platform,
        repository=repository,
        review_type=review_type,
        categories=data.get("categories", ["security", "best_practices"]),
        ai_provider=data.get("ai_provider", "claude"),
        pull_request_id=data.get("pull_request_id"),
        pull_request_url=data.get("pull_request_url"),
        base_sha=data.get("base_sha"),
        head_sha=data.get("head_sha"),
    )

    return jsonify({
        "message": "Review queued",
        "review": review,
    }), 202


@repos_bp.route("/<platform>/<path:repository>/reviews", methods=["GET"])
@auth_required
def get_repository_reviews(platform: str, repository: str):
    """Get all reviews for a specific repository."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    status = request.args.get("status")

    # Validate pagination
    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20

    reviews, total = list_reviews(
        platform=platform,
        repository=repository,
        status=status,
        page=page,
        per_page=per_page,
    )

    return jsonify({
        "platform": platform,
        "repository": repository,
        "data": reviews,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }), 200


@repos_bp.route("/<platform>/<path:repository>/stats", methods=["GET"])
@auth_required
def get_repository_stats(platform: str, repository: str):
    """Get review statistics for a repository."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    # Get database connection
    db = get_db()

    # Query review statistics
    reviews, _ = list_reviews(
        platform=platform,
        repository=repository,
        page=1,
        per_page=10000,  # Get all reviews for stats
    )

    # Calculate statistics
    total_reviews = len(reviews)
    by_status = {}
    total_files = 0
    total_comments = 0

    for review in reviews:
        status = review.get("status", "unknown")
        by_status[status] = by_status.get(status, 0) + 1
        total_files += review.get("files_reviewed", 0)
        total_comments += review.get("comments_posted", 0)

    # Calculate success rate
    completed = by_status.get("completed", 0)
    success_rate = (completed / total_reviews * 100) if total_reviews > 0 else 0

    return jsonify({
        "platform": platform,
        "repository": repository,
        "total_reviews": total_reviews,
        "by_status": by_status,
        "total_files_reviewed": total_files,
        "total_comments": total_comments,
        "success_rate": round(success_rate, 2),
        "average_files_per_review": round(total_files / total_reviews, 2) if total_reviews > 0 else 0,
        "average_comments_per_review": round(total_comments / total_reviews, 2) if total_reviews > 0 else 0,
    }), 200


@repos_bp.route("/<platform>/<path:repository>/latest", methods=["GET"])
@auth_required
def get_latest_repository_review(platform: str, repository: str):
    """Get the latest review for a repository."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    reviews, _ = list_reviews(
        platform=platform,
        repository=repository,
        page=1,
        per_page=1,
    )

    if not reviews:
        return jsonify({"error": "No reviews found for this repository"}), 404

    latest_review = reviews[0]
    return jsonify(latest_review), 200


@repos_bp.route("/<platform>/<path:repository>/<int:pull_request_id>/review", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
def trigger_pr_review(platform: str, repository: str, pull_request_id: int):
    """Trigger a review for a specific pull request."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    data = request.get_json() or {}

    # Validate required fields
    review_type = data.get("review_type", "differential")
    if review_type not in ["differential", "whole"]:
        return jsonify({"error": "Review type must be 'differential' or 'whole'"}), 400

    # Create external ID
    external_id = f"{platform}-{repository}-pr{pull_request_id}"

    # Create review
    review = create_review(
        external_id=external_id,
        platform=platform,
        repository=repository,
        pull_request_id=pull_request_id,
        pull_request_url=data.get("pull_request_url"),
        base_sha=data.get("base_sha"),
        head_sha=data.get("head_sha"),
        review_type=review_type,
        categories=data.get("categories", ["security", "best_practices"]),
        ai_provider=data.get("ai_provider", "claude"),
    )

    return jsonify({
        "message": "Review queued for pull request",
        "review": review,
    }), 202


@repos_bp.route("/<platform>/<path:repository>/<int:pull_request_id>/reviews", methods=["GET"])
@auth_required
def get_pr_reviews(platform: str, repository: str, pull_request_id: int):
    """Get all reviews for a specific pull request."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    # Get database connection
    db = get_db()

    # Query reviews for this pull request
    reviews, _ = list_reviews(
        platform=platform,
        repository=repository,
        page=1,
        per_page=10000,
    )

    # Filter by pull request ID
    pr_reviews = [r for r in reviews if r.get("pull_request_id") == pull_request_id]

    return jsonify({
        "platform": platform,
        "repository": repository,
        "pull_request_id": pull_request_id,
        "total": len(pr_reviews),
        "reviews": pr_reviews,
    }), 200
