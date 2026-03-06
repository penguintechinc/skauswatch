"""Worker-Darwin Flask Application Entry Point.

This module provides the Flask application factory for the worker-darwin service.
Darwin is the AI-powered code review and issue planning sub-module of SkausWatch.

The name Darwin is intentional: a tongue-in-cheek nod to the hubris of thinking
AI has solved code review. (Darwin thought he had solved the world's code, but
was sorely mistaken.)

Architecture:
    - Flask REST API with versioned endpoints (/api/v1/darwin)
    - PyDAL for all database operations (migrate=False, Alembic owns schema)
    - Celery for background review/plan task processing (Redis DB 2)
    - Three enforcement points for license caps (manager proxy, repo cap, user cap)

Environment Variables:
    FLASK_ENV: Environment (development/production)
    DARWIN_PORT: Port to bind (default: 5005)
    DB_TYPE: Database type (postgres/mysql/sqlite)
    DARWIN_DB_USER: Dedicated DB account for darwin
    DARWIN_DB_PASS: Dedicated DB password
    ANTHROPIC_API_KEY: Claude API key
    OPENAI_API_KEY: OpenAI fallback key
    OLLAMA_URL: Local model endpoint
    DARWIN_AI_PROVIDER: Default AI provider (anthropic)
    DARWIN_AI_MODEL: Default model (claude-opus-4-5)
    LICENSE_KEY: PenguinTech license key
    DARWIN_FREE_TIER_USER_CAP: Community user limit (default: 3)
    DARWIN_MAX_REPOS_FREE: Community repo limit (default: 3)
    DARWIN_MAX_REVIEWS_PER_DAY: Community daily review limit (default: 10)
"""

import logging
import sys
from typing import Tuple

from flask import Flask, Response, jsonify
from flask_cors import CORS

from config.settings import settings
from database.models import teardown_db

logging.basicConfig(
    level=getattr(logging, settings.flask.env == "production" and "INFO" or "DEBUG"),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """Flask application factory.

    Returns:
        Flask: Configured Flask application instance
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = settings.flask.secret_key
    app.config["DEBUG"] = settings.flask.debug

    # Initialize CORS
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": "*",
                "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "supports_credentials": True,
            }
        },
    )

    # Register teardown to close PyDAL connection after each request
    app.teardown_appcontext(teardown_db)

    # Register blueprints
    try:
        from api.routes.health import health_bp
        from api.routes.repos import repos_bp
        from api.routes.reviews import reviews_bp
        from api.routes.plans import plans_bp

        app.register_blueprint(health_bp)
        app.register_blueprint(repos_bp, url_prefix="/api/v1/darwin/repos")
        app.register_blueprint(reviews_bp, url_prefix="/api/v1/darwin/reviews")
        app.register_blueprint(plans_bp, url_prefix="/api/v1/darwin/plans")

        logger.info("Darwin API blueprints registered: repos, reviews, plans")
    except ImportError as exc:
        logger.error("Failed to import blueprints: %s", exc)
        raise

    # Status endpoint
    @app.route("/api/v1/darwin/status", methods=["GET"])
    def darwin_status() -> Tuple[Response, int]:
        """Darwin service status endpoint."""
        return jsonify({
            "service": "worker-darwin",
            "status": "running",
            "ai_provider": settings.ai.provider,
            "ai_model": settings.ai.model,
            "license": {
                "free_tier_user_cap": settings.license.free_tier_user_cap,
                "max_repos_free": settings.license.max_repos_free,
                "max_reviews_per_day": settings.license.max_reviews_per_day,
            },
        }), 200

    # Error handlers
    @app.errorhandler(400)
    def bad_request(error: Exception) -> Tuple[Response, int]:
        logger.warning("Bad request: %s", str(error))
        return jsonify({"error": "Bad Request", "message": str(error)}), 400

    @app.errorhandler(404)
    def not_found(error: Exception) -> Tuple[Response, int]:
        return jsonify({"error": "Not Found", "message": "Resource not found"}), 404

    @app.errorhandler(500)
    def internal_server_error(error: Exception) -> Tuple[Response, int]:
        logger.error("Internal server error: %s", str(error), exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500

    logger.info("=" * 60)
    logger.info("Darwin Worker Service Starting")
    logger.info("=" * 60)
    logger.info("Port: %d", settings.flask.port)
    logger.info("AI Provider: %s (%s)", settings.ai.provider, settings.ai.model)
    logger.info("Free tier caps: %d users / %d repos / %d reviews/day",
                settings.license.free_tier_user_cap,
                settings.license.max_repos_free,
                settings.license.max_reviews_per_day)
    logger.info("=" * 60)

    return app


if __name__ == "__main__":
    app = create_app()
    logger.info("Starting Darwin development server on 0.0.0.0:%d", settings.flask.port)
    app.run(
        host="0.0.0.0",
        port=settings.flask.port,
        debug=settings.flask.debug,
        threaded=True,
    )
