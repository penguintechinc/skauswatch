"""Worker-Scanner Flask Application Entry Point.

This module provides the Flask application factory for the worker-scanner service.
The worker-scanner service handles vulnerability scanning using multiple scanning engines
(Nuclei, ZAP, OpenVAS) and manages scan jobs, targets, findings, and schedules.

Architecture:
    - Flask REST API with versioned endpoints (/api/v1/scanner)
    - PyDAL for all database operations
    - Celery for background scan task processing
    - Multi-scanner support with toggle configuration

Environment Variables:
    FLASK_ENV: Environment (development/production)
    FLASK_DEBUG: Debug mode (true/false)
    SECRET_KEY: Flask secret key
    WORKER_SCANNER_PORT: Port to bind (default: 5001)
    DB_TYPE: Database type (postgres/mysql/sqlite)
    LOG_LEVEL: Logging level (DEBUG/INFO/WARNING/ERROR)

Usage:
    # Development server
    python app.py

    # Production server (use gunicorn)
    gunicorn -w 4 -b 0.0.0.0:5001 "app:create_app()"
"""

import logging
import sys
from typing import Any, Dict, Tuple

from config.settings import settings
from database.connection import init_app as init_db
from flask import Flask, Response, jsonify
from flask_cors import CORS

# Configure logging based on settings
logging.basicConfig(
    level=getattr(logging, settings.logging.level.upper(), logging.INFO),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger(__name__)


def create_app() -> Flask:
    """Flask application factory.

    Creates and configures the Flask application instance with all necessary
    components including database, CORS, blueprints, and error handlers.

    Returns:
        Flask: Configured Flask application instance

    Raises:
        ImportError: If required blueprint modules are not found
        Exception: If application initialization fails
    """
    # Create Flask application
    app = Flask(__name__)

    # Load configuration from settings
    app.config["SECRET_KEY"] = settings.flask.secret_key
    app.config["DEBUG"] = settings.flask.debug
    app.config["ENV"] = settings.flask.env
    app.config["JSONIFY_PRETTYPRINT_REGULAR"] = settings.flask.debug

    # JWT Configuration
    app.config["JWT_SECRET_KEY"] = settings.jwt.secret_key
    app.config["JWT_ALGORITHM"] = settings.jwt.algorithm

    # Database Configuration
    app.config["DB_TYPE"] = settings.database.type
    app.config["DB_HOST"] = settings.database.host
    app.config["DB_PORT"] = settings.database.port
    app.config["DB_NAME"] = settings.database.name

    logger.info(
        "Flask application created: environment=%s, debug=%s",
        settings.flask.env,
        settings.flask.debug,
    )

    # Initialize CORS with permissive development defaults
    # NOTE: In production, configure specific origins via environment variables
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": "*",
                "methods": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
                "allow_headers": ["Content-Type", "Authorization"],
                "expose_headers": ["Content-Type", "Authorization"],
                "supports_credentials": True,
                "max_age": 3600,
            }
        },
    )
    logger.info("CORS initialized with permissive development defaults")

    # Initialize database connection manager
    try:
        init_db(app)
        logger.info(
            "Database connection manager initialized: type=%s, host=%s, name=%s",
            settings.database.type,
            settings.database.host,
            settings.database.name,
        )
    except Exception as e:
        logger.error("Failed to initialize database: %s", str(e))
        raise

    # Register API blueprints
    # Import blueprints here to avoid circular imports
    try:
        from api.routes.findings import findings_bp
        from api.routes.jobs import jobs_bp
        from api.routes.scanners import scanners_bp
        from api.routes.schedules import schedules_bp
        from api.routes.targets import targets_bp

        # Register all blueprints under /api/v1/scanner prefix with resource sub-paths
        app.register_blueprint(targets_bp, url_prefix="/api/v1/scanner/targets")
        app.register_blueprint(jobs_bp, url_prefix="/api/v1/scanner/jobs")
        app.register_blueprint(findings_bp, url_prefix="/api/v1/scanner/findings")
        app.register_blueprint(schedules_bp, url_prefix="/api/v1/scanner/schedules")
        app.register_blueprint(scanners_bp, url_prefix="/api/v1/scanner")

        from api.routes.asm import asm_bp

        app.register_blueprint(asm_bp, url_prefix="/api/v1/asm")

        logger.info(
            "API blueprints registered: targets, jobs, findings, schedules, scanners, asm"
        )
    except ImportError as e:
        logger.error("Failed to import blueprints: %s", str(e))
        logger.warning(
            "Blueprint registration failed - continuing with limited functionality"
        )

    # Register health check endpoint
    @app.route("/api/v1/scanner/healthz", methods=["GET"])
    def health_check() -> Tuple[Response, int]:
        """Health check endpoint.

        Returns service status, version, and configuration information.

        Returns:
            Tuple[Response, int]: JSON response with health status and HTTP 200
        """
        health_data = {
            "status": "healthy",
            "service": "worker-scanner",
            "version": "1.0.0",
            "environment": settings.flask.env,
            "database": {
                "type": settings.database.type,
                "host": settings.database.host,
                "connected": True,  # Connection is lazy, will be checked on first use
            },
            "scanners": {
                "nuclei": settings.scanner_toggles.nuclei_enabled,
                "zap": settings.scanner_toggles.zap_enabled,
                "openvas": settings.scanner_toggles.openvas_enabled,
            },
        }
        return jsonify(health_data), 200

    # Register error handlers

    @app.errorhandler(400)
    def bad_request(error: Exception) -> Tuple[Response, int]:
        """Handle 400 Bad Request errors.

        Args:
            error: Exception instance

        Returns:
            Tuple[Response, int]: JSON error response and HTTP 400
        """
        logger.warning("Bad request: %s", str(error))
        return (
            jsonify(
                {"error": "Bad Request", "message": str(error), "status_code": 400}
            ),
            400,
        )

    @app.errorhandler(404)
    def not_found(error: Exception) -> Tuple[Response, int]:
        """Handle 404 Not Found errors.

        Args:
            error: Exception instance

        Returns:
            Tuple[Response, int]: JSON error response and HTTP 404
        """
        logger.warning("Resource not found: %s", str(error))
        return (
            jsonify(
                {
                    "error": "Not Found",
                    "message": "The requested resource was not found",
                    "status_code": 404,
                }
            ),
            404,
        )

    @app.errorhandler(422)
    def unprocessable_entity(error: Exception) -> Tuple[Response, int]:
        """Handle 422 Unprocessable Entity errors.

        Args:
            error: Exception instance

        Returns:
            Tuple[Response, int]: JSON error response and HTTP 422
        """
        logger.warning("Unprocessable entity: %s", str(error))
        return (
            jsonify(
                {
                    "error": "Unprocessable Entity",
                    "message": str(error),
                    "status_code": 422,
                }
            ),
            422,
        )

    @app.errorhandler(500)
    def internal_server_error(error: Exception) -> Tuple[Response, int]:
        """Handle 500 Internal Server Error.

        Args:
            error: Exception instance

        Returns:
            Tuple[Response, int]: JSON error response and HTTP 500
        """
        logger.error("Internal server error: %s", str(error), exc_info=True)
        return (
            jsonify(
                {
                    "error": "Internal Server Error",
                    "message": "An unexpected error occurred",
                    "status_code": 500,
                }
            ),
            500,
        )

    # Log startup information
    logger.info("=" * 80)
    logger.info("Worker-Scanner Service Starting")
    logger.info("=" * 80)
    logger.info("Environment: %s", settings.flask.env)
    logger.info("Debug Mode: %s", settings.flask.debug)
    logger.info("Port: %d", settings.flask.port)
    logger.info(
        "Database: %s @ %s:%d/%s",
        settings.database.type,
        settings.database.host,
        settings.database.port,
        settings.database.name,
    )
    logger.info("Enabled Scanners:")
    logger.info(
        "  - Nuclei:  %s",
        "ENABLED" if settings.scanner_toggles.nuclei_enabled else "DISABLED",
    )
    logger.info(
        "  - ZAP:     %s",
        "ENABLED" if settings.scanner_toggles.zap_enabled else "DISABLED",
    )
    logger.info(
        "  - OpenVAS: %s",
        "ENABLED" if settings.scanner_toggles.openvas_enabled else "DISABLED",
    )
    logger.info("=" * 80)

    return app


if __name__ == "__main__":
    """Run Flask development server.

    This should only be used for local development. In production, use a proper
    WSGI server like gunicorn or uwsgi.

    Example:
        python app.py
    """
    app = create_app()

    # Run development server
    logger.info("Starting Flask development server on 0.0.0.0:%d", settings.flask.port)
    logger.warning(
        "WARNING: This is a development server. "
        "Do not use it in production. Use gunicorn or uwsgi instead."
    )

    app.run(
        host="0.0.0.0",
        port=settings.flask.port,
        debug=settings.flask.debug,
        threaded=True,
    )
