"""Repository configuration endpoints for worker-darwin.

License cap enforcement (Point B):
  - POST /repos checks active repo count vs max_repos_free unless
    the darwin_unlimited_repos feature is licensed.
"""

import logging
from datetime import datetime, timezone
from typing import Tuple

from flask import Blueprint, Response, jsonify, request

from config.settings import settings
from database.models import get_db

logger = logging.getLogger(__name__)

repos_bp = Blueprint("repos", __name__)


def _check_repo_cap() -> Tuple[bool, int, str]:
    """Check if repo cap has been reached for free tier.

    Returns:
        Tuple of (allowed: bool, http_status: int, message: str)
    """
    db = get_db()
    count = db(db.darwin_repo_configs.is_active == True).count()  # noqa: E712
    cap = settings.license.max_repos_free

    # If license server is reachable and darwin_unlimited_repos is licensed, allow
    try:
        from penguin_licensing import get_license_client
        lc = get_license_client()
        if lc.has_feature("darwin_unlimited_repos"):
            return True, 200, ""
    except Exception:
        pass  # dev mode or license server unreachable — apply cap

    if count >= cap:
        return (
            False,
            403,
            f"Darwin community limit reached ({cap} repos). "
            "Purchase Darwin license for unlimited repositories.",
        )
    return True, 200, ""


@repos_bp.route("", methods=["GET"])
def list_repos() -> Tuple[Response, int]:
    """List all repository configurations."""
    db = get_db()
    rows = db(db.darwin_repo_configs).select(orderby=db.darwin_repo_configs.id)
    return jsonify([_repo_to_dict(r) for r in rows]), 200


@repos_bp.route("", methods=["POST"])
def create_repo() -> Tuple[Response, int]:
    """Create a new repository configuration.

    Enforces repo cap on free tier (license gate Point B).
    """
    allowed, status, message = _check_repo_cap()
    if not allowed:
        return jsonify({"error": message}), status

    body = request.get_json(force=True, silent=True) or {}

    required = ["provider", "repo_url", "repo_name"]
    for field in required:
        if not body.get(field):
            return jsonify({"error": f"Missing required field: {field}"}), 400

    provider = body["provider"]
    if provider not in ("github", "gitlab"):
        return jsonify({"error": "provider must be 'github' or 'gitlab'"}), 400

    db = get_db()
    row_id = db.darwin_repo_configs.insert(
        tenant_id=body.get("tenant_id", 1),
        provider=provider,
        repo_url=body["repo_url"],
        repo_name=body["repo_name"],
        webhook_secret=body.get("webhook_secret", ""),
        auto_review=body.get("auto_review", True),
        is_active=True,
        created_at=datetime.now(timezone.utc),
    )
    db.commit()

    row = db(db.darwin_repo_configs.id == row_id).select().first()
    return jsonify(_repo_to_dict(row)), 201


@repos_bp.route("/<int:repo_id>", methods=["GET"])
def get_repo(repo_id: int) -> Tuple[Response, int]:
    """Get a repository configuration by ID."""
    db = get_db()
    row = db(db.darwin_repo_configs.id == repo_id).select().first()
    if not row:
        return jsonify({"error": "Repository not found"}), 404
    return jsonify(_repo_to_dict(row)), 200


@repos_bp.route("/<int:repo_id>", methods=["PUT"])
def update_repo(repo_id: int) -> Tuple[Response, int]:
    """Update a repository configuration."""
    db = get_db()
    row = db(db.darwin_repo_configs.id == repo_id).select().first()
    if not row:
        return jsonify({"error": "Repository not found"}), 404

    body = request.get_json(force=True, silent=True) or {}
    update_fields = {}
    for field in ("repo_url", "repo_name", "webhook_secret", "auto_review", "is_active"):
        if field in body:
            update_fields[field] = body[field]

    if update_fields:
        db(db.darwin_repo_configs.id == repo_id).update(**update_fields)
        db.commit()

    row = db(db.darwin_repo_configs.id == repo_id).select().first()
    return jsonify(_repo_to_dict(row)), 200


@repos_bp.route("/<int:repo_id>", methods=["DELETE"])
def delete_repo(repo_id: int) -> Tuple[Response, int]:
    """Soft-delete a repository configuration."""
    db = get_db()
    row = db(db.darwin_repo_configs.id == repo_id).select().first()
    if not row:
        return jsonify({"error": "Repository not found"}), 404

    db(db.darwin_repo_configs.id == repo_id).update(is_active=False)
    db.commit()
    return jsonify({"status": "deleted"}), 200


def _repo_to_dict(row: object) -> dict:
    """Serialize a darwin_repo_configs record to dict."""
    return {
        "id": row.id,
        "tenant_id": row.tenant_id,
        "provider": row.provider,
        "repo_url": row.repo_url,
        "repo_name": row.repo_name,
        "auto_review": row.auto_review,
        "is_active": row.is_active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
