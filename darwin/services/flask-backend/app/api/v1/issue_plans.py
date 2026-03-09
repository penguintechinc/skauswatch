"""Issue Plans REST API Endpoints."""

from flask import Blueprint, jsonify, request

from ...auth_middleware import auth_required, maintainer_or_admin_required, get_current_user
from ...models import (
    list_issue_plans,
    get_issue_plan_by_id,
    update_issue_plan_status,
)
from ...tasks.plan_worker import process_issue_plan

issue_plans_bp = Blueprint("issue_plans", __name__, url_prefix="/api/v1/issue-plans")


@issue_plans_bp.route("", methods=["GET"])
@auth_required
def list_plans():
    """List issue plans with pagination and filtering.

    Query parameters:
    - platform: Filter by platform (github, gitlab)
    - repository: Filter by repository name
    - status: Filter by status (queued, in_progress, completed, failed)
    - page: Page number (default: 1)
    - per_page: Items per page (default: 20, max: 100)

    Returns:
        {
            "plans": [...],
            "total": N,
            "page": N,
            "per_page": N,
            "filters": {
                "platform": "...",
                "repository": "...",
                "status": "..."
            }
        }
    """
    # Get query parameters
    platform = request.args.get("platform")
    repository = request.args.get("repository")
    status = request.args.get("status")

    # Get pagination parameters
    try:
        page = int(request.args.get("page", 1))
        per_page = int(request.args.get("per_page", 20))
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid pagination parameters"}), 400

    # Validate pagination
    if page < 1:
        return jsonify({"error": "Page must be >= 1"}), 400

    if per_page < 1 or per_page > 100:
        return jsonify({"error": "per_page must be between 1 and 100"}), 400

    # Validate status filter if provided
    valid_statuses = ["queued", "in_progress", "completed", "failed"]
    if status and status not in valid_statuses:
        return jsonify({
            "error": f"Invalid status: {status}",
            "valid_statuses": valid_statuses,
        }), 400

    # Get plans from database
    plans, total = list_issue_plans(
        platform=platform,
        repository=repository,
        status=status,
        page=page,
        per_page=per_page,
    )

    return jsonify({
        "plans": plans,
        "total": total,
        "page": page,
        "per_page": per_page,
        "filters": {
            "platform": platform,
            "repository": repository,
            "status": status,
        },
    }), 200


@issue_plans_bp.route("/<int:plan_id>", methods=["GET"])
@auth_required
def get_plan(plan_id: int):
    """Get specific issue plan details.

    Path parameters:
    - plan_id: Issue plan ID

    Returns:
        Full plan object or 404 if not found
    """
    plan = get_issue_plan_by_id(plan_id)

    if not plan:
        return jsonify({"error": "Issue plan not found"}), 404

    return jsonify(plan), 200


@issue_plans_bp.route("/<int:plan_id>/regenerate", methods=["POST"])
@auth_required
@maintainer_or_admin_required
def regenerate_plan(plan_id: int):
    """Manually trigger plan regeneration.

    Path parameters:
    - plan_id: Issue plan ID

    Returns:
        202 Accepted with task queued message
    """
    # Validate plan exists
    plan = get_issue_plan_by_id(plan_id)

    if not plan:
        return jsonify({"error": "Issue plan not found"}), 404

    # Reset status to "queued" for reprocessing
    updated_plan = update_issue_plan_status(plan_id, "queued")

    if not updated_plan:
        return jsonify({"error": "Failed to update plan status"}), 500

    # Queue worker task for plan regeneration
    try:
        task = process_issue_plan.delay(plan_id)
        return jsonify({
            "message": "Plan regeneration queued",
            "plan_id": plan_id,
            "task_id": str(task.id),
            "status": "queued",
        }), 202
    except Exception as e:
        # If task queueing fails, revert status back to previous state
        update_issue_plan_status(plan_id, plan.get("status"))
        return jsonify({
            "error": "Failed to queue plan regeneration",
            "details": str(e),
        }), 500
