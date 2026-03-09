"""Repository Configuration API Endpoints."""

from flask import Blueprint, jsonify, request

from ...middleware import auth_required, role_required
from ...models import (
    get_repo_config,
    create_or_update_repo_config,
    list_repo_configs,
    get_db,
)

configs_bp = Blueprint("configs", __name__, url_prefix="/api/v1/configs")


@configs_bp.route("/<platform>/<path:repository>", methods=["GET"])
@auth_required
def get_repo_configuration(platform: str, repository: str):
    """Get configuration for a specific repository."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    config = get_repo_config(platform, repository)

    if not config:
        return jsonify({"error": "Configuration not found"}), 404

    return jsonify(config), 200


@configs_bp.route("/<platform>/<path:repository>", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
def create_repo_configuration(platform: str, repository: str):
    """Create or update configuration for a repository."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    data = request.get_json() or {}

    # Prepare configuration data
    config_data = {}

    # Set defaults
    config_data["enabled"] = data.get("enabled", True)
    config_data["auto_review"] = data.get("auto_review", True)
    config_data["review_on_open"] = data.get("review_on_open", True)
    config_data["review_on_sync"] = data.get("review_on_sync", False)

    # Categories
    categories = data.get("default_categories")
    if categories:
        if not isinstance(categories, list):
            return jsonify({"error": "Categories must be a list"}), 400
        config_data["default_categories"] = categories
    else:
        config_data["default_categories"] = ["security", "best_practices"]

    # AI Provider
    ai_provider = data.get("default_ai_provider", "claude")
    config_data["default_ai_provider"] = ai_provider

    # Ignored paths
    ignored_paths = data.get("ignored_paths")
    if ignored_paths:
        if not isinstance(ignored_paths, list):
            return jsonify({"error": "Ignored paths must be a list"}), 400
        config_data["ignored_paths"] = ignored_paths

    # Custom rules
    custom_rules = data.get("custom_rules")
    if custom_rules:
        if not isinstance(custom_rules, dict):
            return jsonify({"error": "Custom rules must be an object"}), 400
        config_data["custom_rules"] = custom_rules

    # Webhook secret
    if data.get("webhook_secret"):
        config_data["webhook_secret"] = data.get("webhook_secret")

    # Create or update configuration
    config = create_or_update_repo_config(platform, repository, **config_data)

    return jsonify({
        "message": "Configuration created/updated successfully",
        "config": config,
    }), 201


@configs_bp.route("/<platform>/<path:repository>", methods=["PATCH"])
@auth_required
@role_required("admin", "maintainer")
def update_repo_configuration(platform: str, repository: str):
    """Partially update repository configuration."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    existing_config = get_repo_config(platform, repository)
    if not existing_config:
        return jsonify({"error": "Configuration not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    # Prepare update data
    update_data = {}

    if "enabled" in data:
        update_data["enabled"] = data.get("enabled")

    if "auto_review" in data:
        update_data["auto_review"] = data.get("auto_review")

    if "review_on_open" in data:
        update_data["review_on_open"] = data.get("review_on_open")

    if "review_on_sync" in data:
        update_data["review_on_sync"] = data.get("review_on_sync")

    if "default_categories" in data:
        categories = data.get("default_categories")
        if not isinstance(categories, list):
            return jsonify({"error": "Categories must be a list"}), 400
        update_data["default_categories"] = categories

    if "default_ai_provider" in data:
        update_data["default_ai_provider"] = data.get("default_ai_provider")

    if "ignored_paths" in data:
        ignored_paths = data.get("ignored_paths")
        if not isinstance(ignored_paths, list):
            return jsonify({"error": "Ignored paths must be a list"}), 400
        update_data["ignored_paths"] = ignored_paths

    if "custom_rules" in data:
        custom_rules = data.get("custom_rules")
        if not isinstance(custom_rules, dict):
            return jsonify({"error": "Custom rules must be an object"}), 400
        update_data["custom_rules"] = custom_rules

    if "webhook_secret" in data:
        update_data["webhook_secret"] = data.get("webhook_secret")

    # Update configuration
    config = create_or_update_repo_config(platform, repository, **update_data)

    return jsonify({
        "message": "Configuration updated successfully",
        "config": config,
    }), 200


@configs_bp.route("", methods=["GET"])
@auth_required
def list_all_configurations():
    """List all repository configurations."""
    platform = request.args.get("platform")
    enabled_only = request.args.get("enabled_only", "false").lower() == "true"

    if platform and platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    configs = list_repo_configs(
        platform=platform,
        enabled_only=enabled_only,
    )

    return jsonify({
        "data": configs,
        "total": len(configs),
        "filters": {
            "platform": platform,
            "enabled_only": enabled_only,
        },
    }), 200


@configs_bp.route("/<platform>/<path:repository>", methods=["DELETE"])
@auth_required
@role_required("admin")
def delete_repo_configuration(platform: str, repository: str):
    """Delete repository configuration."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    db = get_db()

    existing = db(
        (db.repo_configs.platform == platform) &
        (db.repo_configs.repository == repository)
    ).select().first()

    if not existing:
        return jsonify({"error": "Configuration not found"}), 404

    # Delete configuration
    deleted = db(
        (db.repo_configs.platform == platform) &
        (db.repo_configs.repository == repository)
    ).delete()

    db.commit()

    return jsonify({
        "message": "Configuration deleted successfully",
        "deleted": deleted > 0,
    }), 200


@configs_bp.route("/<platform>/<path:repository>/reset", methods=["POST"])
@auth_required
@role_required("admin")
def reset_repo_configuration(platform: str, repository: str):
    """Reset repository configuration to defaults."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    existing_config = get_repo_config(platform, repository)
    if not existing_config:
        return jsonify({"error": "Configuration not found"}), 404

    # Reset to defaults
    default_config = {
        "enabled": True,
        "auto_review": True,
        "review_on_open": True,
        "review_on_sync": False,
        "default_categories": ["security", "best_practices"],
        "default_ai_provider": "claude",
        "ignored_paths": [],
        "custom_rules": None,
    }

    config = create_or_update_repo_config(platform, repository, **default_config)

    return jsonify({
        "message": "Configuration reset to defaults",
        "config": config,
    }), 200


@configs_bp.route("/<platform>/<path:repository>/enabled", methods=["PATCH"])
@auth_required
@role_required("admin", "maintainer")
def toggle_repo_enabled(platform: str, repository: str):
    """Toggle repository enabled status."""
    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    existing_config = get_repo_config(platform, repository)
    if not existing_config:
        return jsonify({"error": "Configuration not found"}), 404

    data = request.get_json()
    if not data or "enabled" not in data:
        return jsonify({"error": "Enabled status is required"}), 400

    enabled = data.get("enabled")
    config = create_or_update_repo_config(platform, repository, enabled=enabled)

    return jsonify({
        "message": f"Repository {'enabled' if enabled else 'disabled'}",
        "config": config,
    }), 200


@configs_bp.route("/stats", methods=["GET"])
@auth_required
def get_configuration_stats():
    """Get statistics on repository configurations."""
    all_configs = list_repo_configs()

    total = len(all_configs)
    enabled = sum(1 for c in all_configs if c.get("enabled"))
    disabled = total - enabled
    auto_review = sum(1 for c in all_configs if c.get("auto_review"))

    # Count by platform
    by_platform = {}
    for config in all_configs:
        platform = config.get("platform")
        if platform:
            by_platform[platform] = by_platform.get(platform, 0) + 1

    return jsonify({
        "total_configurations": total,
        "enabled": enabled,
        "disabled": disabled,
        "with_auto_review": auto_review,
        "by_platform": by_platform,
    }), 200
