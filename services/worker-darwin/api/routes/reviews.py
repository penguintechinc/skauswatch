"""Code review endpoints for worker-darwin.

License cap enforcement (Point C):
  - POST /reviews checks daily review count vs max_reviews_per_day unless
    darwin feature is fully licensed.
"""

import logging
from datetime import date, datetime, timezone
from typing import Tuple

from config.settings import settings
from database.models import get_db
from flask import Blueprint, Response, jsonify, request
from workers.review_worker import process_review

logger = logging.getLogger(__name__)

reviews_bp = Blueprint("reviews", __name__)


def _check_review_day_cap() -> Tuple[bool, int, str]:
    """Check if daily review cap has been reached for free tier.

    Returns:
        Tuple of (allowed: bool, http_status: int, message: str)
    """
    try:
        from penguin_licensing import get_license_client

        lc = get_license_client()
        if lc.has_feature("darwin"):
            return True, 200, ""
    except Exception:
        pass  # dev mode or unreachable

    db = get_db()
    today_start = datetime.combine(date.today(), datetime.min.time())
    count = db((db.darwin_reviews.created_at >= today_start)).count()

    cap = settings.license.max_reviews_per_day
    if count >= cap:
        return (
            False,
            403,
            f"Darwin community daily review limit reached ({cap}/day). "
            "Purchase Darwin license for unlimited reviews.",
        )
    return True, 200, ""


@reviews_bp.route("", methods=["GET"])
def list_reviews() -> Tuple[Response, int]:
    """List code reviews with optional repo_id filter."""
    db = get_db()
    repo_id = request.args.get("repo_id", type=int)

    if repo_id:
        rows = db(db.darwin_reviews.repo_config_id == repo_id).select(
            orderby=~db.darwin_reviews.created_at
        )
    else:
        rows = db(db.darwin_reviews).select(orderby=~db.darwin_reviews.created_at)

    return jsonify([_review_to_dict(r) for r in rows]), 200


@reviews_bp.route("", methods=["POST"])
def create_review() -> Tuple[Response, int]:
    """Queue a new code review.

    Enforces daily review cap on free tier (license gate Point C).
    """
    allowed, status, message = _check_review_day_cap()
    if not allowed:
        return jsonify({"error": message}), status

    body = request.get_json(force=True, silent=True) or {}

    if not body.get("repo_config_id"):
        return jsonify({"error": "Missing required field: repo_config_id"}), 400

    db = get_db()
    repo = db(db.darwin_repo_configs.id == body["repo_config_id"]).select().first()
    if not repo:
        return jsonify({"error": "Repository configuration not found"}), 404

    row_id = db.darwin_reviews.insert(
        repo_config_id=body["repo_config_id"],
        pr_number=body.get("pr_number", 0),
        pr_url=body.get("pr_url", ""),
        status="pending",
        ai_provider=body.get("ai_provider", settings.ai.provider),
        model=body.get("model", settings.ai.model),
        created_at=datetime.now(timezone.utc),
    )
    db.commit()

    # Queue review task
    process_review.apply_async(args=[row_id], queue="darwin_reviews")

    row = db(db.darwin_reviews.id == row_id).select().first()
    return jsonify(_review_to_dict(row)), 202


@reviews_bp.route("/<int:review_id>", methods=["GET"])
def get_review(review_id: int) -> Tuple[Response, int]:
    """Get a code review by ID, including its comments."""
    db = get_db()
    row = db(db.darwin_reviews.id == review_id).select().first()
    if not row:
        return jsonify({"error": "Review not found"}), 404

    data = _review_to_dict(row)

    # Include comments
    comments = db(db.darwin_review_comments.review_id == review_id).select(
        orderby=db.darwin_review_comments.id
    )
    data["comments"] = [_comment_to_dict(c) for c in comments]

    return jsonify(data), 200


def _review_to_dict(row: object) -> dict:
    """Serialize a darwin_reviews record to dict."""
    return {
        "id": row.id,
        "repo_config_id": row.repo_config_id,
        "pr_number": row.pr_number,
        "pr_url": row.pr_url,
        "status": row.status,
        "ai_provider": row.ai_provider,
        "model": row.model,
        "summary": row.summary,
        "completed_at": row.completed_at.isoformat() if row.completed_at else None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def _comment_to_dict(row: object) -> dict:
    """Serialize a darwin_review_comments record to dict."""
    return {
        "id": row.id,
        "review_id": row.review_id,
        "file_path": row.file_path,
        "line_number": row.line_number,
        "comment": row.comment,
        "severity": row.severity,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
