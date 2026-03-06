"""
SkausWatch Manager Service - Main Application

Quart-based unified Manager service providing:
- REST API for external clients
- gRPC server for inter-service communication
- Alert management with AI review
- Threat intelligence aggregation
- EDR agent management
- Approval workflows
"""

import asyncio
import logging
import os
from datetime import datetime
from typing import List, Optional

import structlog
from models.db import close_db, get_db, init_database_schema
from quart import Quart, jsonify
from quart_cors import cors

from config import ManagerConfig, load_config
from services.streams.redis_streams import (
    AuditLogPublisher,
    RedisStreamManager,
    create_stream_consumer,
)

# Configure structured logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

# Global instances
config: Optional[ManagerConfig] = None
stream_manager: Optional[RedisStreamManager] = None
audit_publisher: Optional[AuditLogPublisher] = None
background_tasks: List[asyncio.Task] = []


def get_version() -> str:
    """Get application version."""
    version_file = os.path.join(os.path.dirname(__file__), "..", "..", ".version")
    try:
        with open(version_file) as f:
            return f.read().strip()
    except FileNotFoundError:
        return "0.0.0-dev"


def create_app(config_instance: ManagerConfig = None) -> Quart:
    """
    Create and configure the Quart application.

    Args:
        config_instance: Optional configuration instance

    Returns:
        Configured Quart application
    """
    global config

    # Load configuration
    config = config_instance or load_config()

    # Configure logging
    log_level = getattr(logging, config.log_level.upper(), logging.INFO)
    logging.basicConfig(level=log_level)

    # Create Quart app
    app = Quart(__name__)
    app.config["SECRET_KEY"] = config.auth.secret_key
    app.config["JSON_SORT_KEYS"] = False

    # Enable CORS if configured
    if config.api.cors_enabled:
        app = cors(
            app,
            allow_origin=config.api.cors_origins,
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Agent-ID"],
        )

    # Store config in app
    app.config["MANAGER_CONFIG"] = config

    # Register lifecycle hooks
    @app.before_serving
    async def startup():
        """Application startup."""
        global stream_manager, audit_publisher

        logger.info(
            "Starting SkausWatch Manager Service",
            version=get_version(),
            environment=config.environment,
        )

        try:
            # Initialize database schema (SQLAlchemy - one time only)
            init_database_schema(config.database.uri)

            # Initialize Redis Stream Manager
            stream_manager = RedisStreamManager(
                redis_url=config.redis.full_url,
                prefix=config.redis.key_prefix,
                max_connections=config.redis.max_connections,
            )
            await stream_manager.connect()

            # Initialize publishers
            audit_publisher = AuditLogPublisher(stream_manager)

            # Create consumer groups
            await stream_manager.create_consumer_group(
                RedisStreamManager.STREAM_EDR_EVENTS,
                f"{config.redis.consumer_group_prefix}-edr",
            )
            await stream_manager.create_consumer_group(
                RedisStreamManager.STREAM_ALERTS_PENDING,
                f"{config.redis.consumer_group_prefix}-alerts",
            )
            await stream_manager.create_consumer_group(
                RedisStreamManager.STREAM_AI_TASKS,
                f"{config.redis.consumer_group_prefix}-ai",
            )

            # Create S3 scan consumer groups
            await stream_manager.create_consumer_group(
                RedisStreamManager.STREAM_S3_SCAN_TASKS,
                f"{config.redis.consumer_group_prefix}-s3scan",
            )
            await stream_manager.create_consumer_group(
                RedisStreamManager.STREAM_S3_SCAN_RESULTS,
                f"{config.redis.consumer_group_prefix}-s3scan-results",
            )

            # Start background tasks
            await _start_background_tasks()

            logger.info("SkausWatch Manager Service started successfully")

        except Exception as e:
            logger.error("Failed to start Manager Service", error=str(e))
            raise

    @app.after_serving
    async def shutdown():
        """Application shutdown."""
        logger.info("Shutting down SkausWatch Manager Service...")

        # Cancel background tasks
        for task in background_tasks:
            task.cancel()

        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)

        # Close Redis connection
        if stream_manager:
            await stream_manager.close()

        # Close database connections
        close_db()

        logger.info("SkausWatch Manager Service shutdown complete")

    # Register error handlers
    @app.errorhandler(400)
    async def bad_request(error):
        return jsonify({"error": "Bad Request", "detail": str(error)}), 400

    @app.errorhandler(401)
    async def unauthorized(error):
        return jsonify({"error": "Unauthorized", "detail": str(error)}), 401

    @app.errorhandler(403)
    async def forbidden(error):
        return jsonify({"error": "Forbidden", "detail": str(error)}), 403

    @app.errorhandler(404)
    async def not_found(error):
        return jsonify({"error": "Not Found", "detail": str(error)}), 404

    @app.errorhandler(500)
    async def internal_error(error):
        logger.error("Internal server error", error=str(error))
        return jsonify({"error": "Internal Server Error"}), 500

    # Register blueprints
    _register_blueprints(app)

    # Health check endpoints
    @app.route("/healthz")
    async def health_check():
        """Health check endpoint."""
        try:
            # Check database
            db = get_db(config.database.uri)
            db.executesql("SELECT 1")
            db_status = "connected"
        except Exception as e:
            db_status = f"error: {str(e)}"

        # Check Redis
        try:
            if stream_manager and stream_manager._client:
                await stream_manager._client.ping()
                redis_status = "connected"
            else:
                redis_status = "not initialized"
        except Exception as e:
            redis_status = f"error: {str(e)}"

        status = (
            "healthy"
            if db_status == "connected" and redis_status == "connected"
            else "unhealthy"
        )
        status_code = 200 if status == "healthy" else 503

        return (
            jsonify(
                {
                    "status": status,
                    "version": get_version(),
                    "database": db_status,
                    "redis": redis_status,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            ),
            status_code,
        )

    @app.route("/readyz")
    async def readiness_check():
        """Readiness check endpoint."""
        return jsonify({"status": "ready"}), 200

    @app.route("/version")
    async def version_info():
        """Version information endpoint."""
        return jsonify(
            {
                "name": "SkausWatch Manager Service",
                "version": get_version(),
                "environment": config.environment,
            }
        )

    return app


def _register_blueprints(app: Quart) -> None:
    """Register API blueprints."""
    from api.v1 import (
        alerts,
        approvals,
        asm,
        auth,
        darwin,
        edr,
        research,
        s3_scan,
        siem,
        threat_intel,
        users,
    )

    app.register_blueprint(auth.bp, url_prefix="/api/v1/auth")
    app.register_blueprint(users.bp, url_prefix="/api/v1/users")
    app.register_blueprint(alerts.bp, url_prefix="/api/v1/alerts")
    app.register_blueprint(threat_intel.bp, url_prefix="/api/v1/threat-intel")
    app.register_blueprint(research.research_bp, url_prefix="/api/v1/research")
    app.register_blueprint(approvals.bp, url_prefix="/api/v1/approvals")
    app.register_blueprint(edr.bp, url_prefix="/api/v1/edr")
    app.register_blueprint(s3_scan.bp, url_prefix="/api/v1/s3-scan")
    app.register_blueprint(siem.bp, url_prefix="/api/v1/siem")
    app.register_blueprint(asm.bp, url_prefix="/api/v1/asm")
    app.register_blueprint(darwin.bp, url_prefix="/api/v1/darwin")


async def _start_background_tasks() -> None:
    """Start background processing tasks."""

    # EDR event processor
    async def process_edr_event(message):
        logger.debug("Processing EDR event", message_id=message.id)
        # TODO: Implement EDR event processing

    task = await create_stream_consumer(
        stream_manager,
        RedisStreamManager.STREAM_EDR_EVENTS,
        f"{config.redis.consumer_group_prefix}-edr",
        "processor-1",
        process_edr_event,
    )
    background_tasks.append(task)

    # Alert processor
    async def process_alert(message):
        logger.debug("Processing alert", message_id=message.id)
        # TODO: Implement alert processing with AI review

    task = await create_stream_consumer(
        stream_manager,
        RedisStreamManager.STREAM_ALERTS_PENDING,
        f"{config.redis.consumer_group_prefix}-alerts",
        "processor-1",
        process_alert,
    )
    background_tasks.append(task)

    logger.info("Background tasks started", count=len(background_tasks))


# ============================================
# gRPC Server (separate process)
# ============================================


async def run_grpc_server(config: ManagerConfig) -> None:
    """Run the gRPC server."""
    if not config.grpc.enabled:
        logger.info("gRPC server disabled")
        return

    # Import here to avoid circular imports
    from grpc.server import serve

    logger.info(
        "Starting gRPC server",
        host=config.grpc.host,
        port=config.grpc.port,
    )

    await serve(config)


# ============================================
# Application Entry Points
# ============================================


def main():
    """Main entry point for the Manager service."""
    import argparse

    import hypercorn.asyncio
    from hypercorn.config import Config as HypercornConfig

    parser = argparse.ArgumentParser(description="SkausWatch Manager Service")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", "-p", type=int, default=5000, help="Port to bind to")
    parser.add_argument("--grpc-port", type=int, default=50051, help="gRPC port")
    parser.add_argument("--workers", type=int, default=1, help="Number of workers")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    args = parser.parse_args()

    # Load configuration
    config = load_config()
    config.api.port = args.port
    config.api.debug = args.debug
    config.grpc.port = args.grpc_port

    # Create Quart app
    app = create_app(config)

    # Configure Hypercorn
    hypercorn_config = HypercornConfig()
    hypercorn_config.bind = [f"{args.host}:{args.port}"]
    hypercorn_config.workers = args.workers

    if args.debug:
        hypercorn_config.use_reloader = True

    async def run_all():
        """Run both REST and gRPC servers."""
        # Start gRPC server as separate task
        grpc_task = asyncio.create_task(run_grpc_server(config))

        # Run Quart with Hypercorn
        try:
            await hypercorn.asyncio.serve(app, hypercorn_config)
        finally:
            grpc_task.cancel()
            try:
                await grpc_task
            except asyncio.CancelledError:
                pass

    try:
        asyncio.run(run_all())
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")


if __name__ == "__main__":
    main()
