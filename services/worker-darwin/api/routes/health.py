"""Health check endpoint for worker-darwin service."""

from flask import Blueprint, jsonify

from config.settings import settings

health_bp = Blueprint("health", __name__)


@health_bp.route("/healthz", methods=["GET"])
def health_check():
    """Health check endpoint.

    Returns:
        JSON response with service health status
    """
    return jsonify({
        "status": "healthy",
        "service": "worker-darwin",
        "version": "1.0.0",
        "environment": settings.flask.env,
        "ai_provider": settings.ai.provider,
        "ai_model": settings.ai.model,
    }), 200
