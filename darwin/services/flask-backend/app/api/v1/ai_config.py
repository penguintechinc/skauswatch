"""AI Configuration API endpoints."""

from flask import Blueprint, jsonify, request
from flask_jwt_extended import jwt_required

from ...middleware import role_required
from ...models import (
    delete_ai_config,
    get_ai_config_source,
    get_ai_enabled,
    set_ai_enabled,
)

ai_config_bp = Blueprint("ai_config", __name__)


@ai_config_bp.route("/config/ai", methods=["GET"])
@jwt_required(optional=True)
def get_ai_configuration():
    """
    Get current AI configuration status.

    Returns:
        JSON response with AI enabled status and configuration source.

    Response:
        {
            "enabled": true|false,
            "source": "database|environment|default"
        }
    """
    enabled = get_ai_enabled()
    source = get_ai_config_source()

    return jsonify({
        "enabled": enabled,
        "source": source,
    }), 200


@ai_config_bp.route("/config/ai", methods=["PATCH"])
@jwt_required()
@role_required("admin")
def update_ai_configuration():
    """
    Update AI configuration status (admin only).

    Stores the configuration in the database, overriding environment variable.

    Request Body:
        {
            "enabled": true|false
        }

    Returns:
        JSON response with updated AI status and confirmation message.

    Response:
        {
            "enabled": true|false,
            "source": "database",
            "message": "AI configuration updated successfully"
        }
    """
    data = request.get_json()

    if "enabled" not in data:
        return jsonify({
            "error": "Missing required field: enabled",
            "details": "Request body must include 'enabled' boolean field"
        }), 400

    enabled = data.get("enabled")

    # Validate boolean type
    if not isinstance(enabled, bool):
        return jsonify({
            "error": "Invalid value for 'enabled'",
            "details": "Field 'enabled' must be a boolean (true or false)"
        }), 400

    # Update database configuration
    set_ai_enabled(enabled)

    return jsonify({
        "enabled": enabled,
        "source": "database",
        "message": "AI configuration updated successfully"
    }), 200


@ai_config_bp.route("/config/ai", methods=["DELETE"])
@jwt_required()
@role_required("admin")
def reset_ai_configuration():
    """
    Reset AI configuration to environment variable default (admin only).

    Removes the database override, reverting to environment variable or default.

    Returns:
        JSON response with current AI status after reset.

    Response:
        {
            "enabled": true|false,
            "source": "environment|default",
            "message": "AI configuration reset to default"
        }
    """
    # Delete database configuration
    delete_ai_config()

    # Get current status after deletion (will fall back to env var)
    enabled = get_ai_enabled()
    source = get_ai_config_source()

    return jsonify({
        "enabled": enabled,
        "source": source,
        "message": "AI configuration reset to default"
    }), 200
