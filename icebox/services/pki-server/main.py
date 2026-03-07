"""SkausWatch PKI Server - Unified X.509 and SSH Certificate Authority.

This service provides both REST API and gRPC endpoints for managing
X.509 and SSH certificates.
"""

import asyncio
import signal
from datetime import datetime
from typing import List, Set

import structlog
from hypercorn.asyncio import serve
from hypercorn.config import Config as HypercornConfig
from quart import Quart
from quart_cors import cors

from .api.v1 import api_v1
from .ca import SSHCertificateAuthority, X509CertificateAuthority
from .config import Settings, get_settings
from .grpc.server import serve_grpc
from .models.db import close_db, get_db, init_database_schema
from .services.certificate_manager import CertificateManager

logger = structlog.get_logger()

# Global instances
config: Settings = None
x509_ca: X509CertificateAuthority = None
ssh_ca: SSHCertificateAuthority = None
cert_manager: CertificateManager = None
grpc_server = None
background_tasks: Set[asyncio.Task] = set()


def create_app() -> Quart:
    """Create and configure the Quart application."""
    global config

    config = get_settings()

    app = Quart(__name__)
    app = cors(app, allow_origin="*")

    # Store config in app
    app.config["settings"] = config

    # Register blueprints
    app.register_blueprint(api_v1)

    # Register lifecycle hooks
    app.before_serving(startup)
    app.after_serving(shutdown)

    # Register health endpoints
    @app.route("/healthz")
    async def healthz():
        """Liveness probe."""
        return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

    @app.route("/readyz")
    async def readyz():
        """Readiness probe."""
        checks = {
            "database": False,
            "x509_ca": False,
            "ssh_ca": False,
        }

        try:
            # Check database
            db = get_db()
            checks["database"] = db is not None

            # Check CAs
            checks["x509_ca"] = x509_ca is not None
            checks["ssh_ca"] = ssh_ca is not None

            all_healthy = all(checks.values())
            status_code = 200 if all_healthy else 503

            return {
                "status": "ready" if all_healthy else "not_ready",
                "checks": checks,
                "timestamp": datetime.utcnow().isoformat(),
            }, status_code

        except Exception as e:
            logger.error("Readiness check failed", error=str(e))
            return {
                "status": "not_ready",
                "checks": checks,
                "error": str(e),
            }, 503

    @app.route("/version")
    async def version():
        """Version information."""
        return {
            "app_name": config.app_name,
            "version": config.version,
            "environment": config.environment,
        }

    @app.route("/health")
    async def health():
        """Detailed health check."""
        return {
            "status": "healthy",
            "version": config.version,
            "timestamp": datetime.utcnow().isoformat(),
            "components": {
                "rest_api": True,
                "grpc_server": grpc_server is not None,
                "x509_ca": x509_ca is not None,
                "ssh_ca": ssh_ca is not None,
            },
        }

    return app


async def startup() -> None:
    """Application startup tasks."""
    global x509_ca, ssh_ca, cert_manager, grpc_server

    logger.info("Starting PKI Server", version=config.version)

    # Initialize database schema
    logger.info("Initializing database schema")
    init_database_schema(config.database.url)

    # Initialize X.509 CA
    logger.info("Initializing X.509 Certificate Authority")
    x509_ca = X509CertificateAuthority(config.x509_ca)
    await x509_ca.initialize()

    # Initialize SSH CA
    logger.info("Initializing SSH Certificate Authority")
    ssh_ca = SSHCertificateAuthority(config.ssh_ca)
    await ssh_ca.initialize()

    # Create certificate manager
    cert_manager = CertificateManager(x509_ca, ssh_ca)

    # Store cert_manager in app config for API access
    from quart import current_app

    current_app.config["cert_manager"] = cert_manager

    # Start gRPC server
    logger.info("Starting gRPC server", port=config.grpc.port)
    grpc_server = await serve_grpc(cert_manager, config, port=config.grpc.port)

    # Start background tasks
    task = asyncio.create_task(cleanup_expired_certificates())
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)

    logger.info(
        "PKI Server started successfully",
        rest_port=config.api.port,
        grpc_port=config.grpc.port,
    )


async def shutdown() -> None:
    """Application shutdown tasks."""
    logger.info("Shutting down PKI Server")

    # Cancel background tasks
    for task in background_tasks:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    # Stop gRPC server
    if grpc_server:
        await grpc_server.stop(grace=5)
        logger.info("gRPC server stopped")

    # Close database connections
    close_db()

    logger.info("PKI Server shutdown complete")


async def cleanup_expired_certificates() -> None:
    """Background task to mark expired certificates."""
    while True:
        try:
            await asyncio.sleep(3600)  # Run every hour

            from .models.db import db_session

            now = datetime.utcnow()
            updated_count = 0

            with db_session() as db:
                # Update expired X.509 certificates
                x509_updated = db(
                    (db.x509_certificates.status == "active")
                    & (db.x509_certificates.not_after < now)
                ).update(status="expired", updated_at=now)
                updated_count += x509_updated

                # Update expired SSH certificates
                ssh_updated = db(
                    (db.ssh_certificates.status == "active")
                    & (db.ssh_certificates.valid_before < now)
                ).update(status="expired", updated_at=now)
                updated_count += ssh_updated

            if updated_count > 0:
                logger.info(
                    "Cleaned up expired certificates", updated_count=updated_count
                )

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Cleanup task error", error=str(e))
            await asyncio.sleep(60)  # Wait before retry


def run() -> None:
    """Run the PKI Server."""
    app = create_app()

    hypercorn_config = HypercornConfig()
    hypercorn_config.bind = [f"{config.api.host}:{config.api.port}"]
    hypercorn_config.use_reloader = config.api.debug

    # Handle signals
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    shutdown_event = asyncio.Event()

    def signal_handler():
        shutdown_event.set()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    async def run_server():
        await serve(app, hypercorn_config, shutdown_trigger=shutdown_event.wait)

    try:
        loop.run_until_complete(run_server())
    finally:
        loop.close()


if __name__ == "__main__":
    run()
