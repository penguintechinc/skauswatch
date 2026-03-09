"""Issue plan endpoints for worker-darwin."""

import logging
from datetime import datetime, timezone
from typing import Tuple

from config.settings import settings
from database.models import get_db
from flask import Blueprint, Response, jsonify, request
from workers.plan_worker import generate_plan

logger = logging.getLogger(__name__)

plans_bp = Blueprint("plans", __name__)


@plans_bp.route("", methods=["GET"])
def list_plans() -> Tuple[Response, int]:
    """List issue plans with optional repo_id filter."""
    db = get_db()
    repo_id = request.args.get("repo_id", type=int)

    if repo_id:
        rows = db(db.darwin_issue_plans.repo_config_id == repo_id).select(
            orderby=~db.darwin_issue_plans.created_at
        )
    else:
        rows = db(db.darwin_issue_plans).select(
            orderby=~db.darwin_issue_plans.created_at
        )

    return jsonify([_plan_to_dict(r) for r in rows]), 200


@plans_bp.route("", methods=["POST"])
def create_plan() -> Tuple[Response, int]:
    """Queue a new issue plan generation."""
    body = request.get_json(force=True, silent=True) or {}

    required = ["repo_config_id", "issue_number"]
    for field in required:
        if not body.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    db = get_db()
    repo = db(db.darwin_repo_configs.id == body["repo_config_id"]).select().first()
    if not repo:
        return jsonify({"error": "Repository configuration not found"}), 404

    row_id = db.darwin_issue_plans.insert(
        repo_config_id=body["repo_config_id"],
        issue_number=body["issue_number"],
        issue_url=body.get("issue_url", ""),
        ai_provider=body.get("ai_provider", settings.ai.provider),
        status="pending",
        created_at=datetime.now(timezone.utc),
    )
    db.commit()

    generate_plan.apply_async(args=[row_id], queue="darwin_plans")

    row = db(db.darwin_issue_plans.id == row_id).select().first()
    return jsonify(_plan_to_dict(row)), 202


@plans_bp.route("/<int:plan_id>", methods=["GET"])
def get_plan(plan_id: int) -> Tuple[Response, int]:
    """Get an issue plan by ID."""
    db = get_db()
    row = db(db.darwin_issue_plans.id == plan_id).select().first()
    if not row:
        return jsonify({"error": "Plan not found"}), 404
    return jsonify(_plan_to_dict(row)), 200


def _plan_to_dict(row: object) -> dict:
    """Serialize a darwin_issue_plans record to dict."""
    return {
        "id": row.id,
        "repo_config_id": row.repo_config_id,
        "issue_number": row.issue_number,
        "issue_url": row.issue_url,
        "plan_content": row.plan_content,
        "ai_provider": row.ai_provider,
        "status": row.status,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
