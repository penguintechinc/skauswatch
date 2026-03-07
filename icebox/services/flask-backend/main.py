"""
IceBox Flask Backend — Main Application

Quart-based REST API service providing:
  - Secrets CRUD with envelope encryption
  - JIT (Just-in-Time) access with approval workflows
  - One-time secret sharing
  - Cloud vault sync management (AWS/Azure/GCP/Oracle/K8s)
  - Audit log
  - License management
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

import aioredis
import structlog
from quart import Quart, jsonify, request
from quart_cors import cors

from api.v1 import api_v1
from config import IceBoxConfig, get_config
from crypto.envelope import EnvelopeEncryption
from licensing.validator import LicenseValidator, license_middleware
from models.db import close_db, wait_for_database

# Structured logging
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

background_tasks: Set[asyncio.Task] = set()


def _get_version() -> str:
    """Read version from .version file at repo root."""
    version_file = os.path.join(os.path.dirname(__file__), "..", "..", "..", ".version")
    try:
        with open(version_file) as f:
            return f.read().strip()
    except FileNotFoundError:
        return "0.0.0-dev"


def create_app(config: Optional[IceBoxConfig] = None) -> Quart:
    """Create and configure the Quart application."""
    if config is None:
        config = get_config()

    app = Quart(__name__)
    app = cors(app, allow_origin="*")

    app.config["ICEBOX_CONFIG"] = config

    # Initialise envelope encryption
    try:
        enc = EnvelopeEncryption.from_env()
        app.config["ENVELOPE_ENC"] = enc
        logger.info("Envelope encryption initialized", mek_version=enc.current_version)
    except ValueError as exc:
        logger.error("Encryption init failed — ICEBOX_MEK not set", error=str(exc))
        # In development, fall back to a generated key (NOT for production)
        if config.debug:
            import base64
            dummy_mek = base64.b64encode(b"\x00" * 32).decode()
            os.environ["ICEBOX_MEK"] = dummy_mek
            enc = EnvelopeEncryption.from_env()
            app.config["ENVELOPE_ENC"] = enc
            logger.warning("Using dummy MEK for development — DO NOT USE IN PRODUCTION")
        else:
            sys.exit(1)

    # License validator
    validator = LicenseValidator(config.licensing)
    app.config["LICENSE_VALIDATOR"] = validator

    # Register blueprints
    app.register_blueprint(api_v1)

    # Register lifecycle hooks
    app.before_serving(_make_startup(app, config, validator))
    app.after_serving(_make_shutdown(app, config, validator))

    # Health endpoints (bypass license check)
    @app.route("/healthz")
    async def healthz():
        """Liveness probe."""
        return jsonify({"status": "healthy", "timestamp": datetime.utcnow().isoformat()})

    @app.route("/readyz")
    async def readyz():
        """Readiness probe — also checks license."""
        licensed = validator.is_licensed_or_bypassed()
        return jsonify({
            "status": "ready" if licensed else "degraded",
            "licensed": licensed,
            "timestamp": datetime.utcnow().isoformat(),
        }), 200 if licensed else 503

    @app.route("/api/v1/status")
    async def status():
        """API version status endpoint (for WebUI ConsoleVersion component)."""
        return jsonify({
            "version": _get_version(),
            "service": "icebox",
            "timestamp": datetime.utcnow().isoformat(),
        })

    # Apply license middleware (402 on unlicensed)
    asyncio.ensure_future(_apply_license_middleware_after_build(app, config, validator))

    return app


async def _apply_license_middleware_after_build(app, config, validator):
    """Workaround: apply middleware after app object is fully built."""
    await license_middleware(app, config, validator)


def _make_startup(app: Quart, config: IceBoxConfig, validator: LicenseValidator):
    """Return async startup handler."""

    async def startup():
        logger.info("IceBox starting up", version=_get_version())

        # Wait for database
        if not wait_for_database(config.database.uri, max_retries=10, retry_delay=3):
            logger.error("Database unavailable after retries — exiting")
            sys.exit(1)

        # Redis client
        try:
            redis = await aioredis.from_url(
                config.redis.full_url,
                max_connections=config.redis.max_connections,
                decode_responses=True,
            )
            app.config["REDIS_CLIENT"] = redis
            logger.info("Redis connected", url=config.redis.url)
        except Exception as exc:
            logger.warning("Redis unavailable — sync features disabled", error=str(exc))
            app.config["REDIS_CLIENT"] = None

        # Start JIT revocation background task
        task = asyncio.create_task(_jit_revocation_loop(config))
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)

        # Start license validator
        host = os.getenv("APP_HOST", "")
        await validator.start(app_host=host)

        logger.info("IceBox startup complete")

    return startup


def _make_shutdown(app: Quart, config: IceBoxConfig, validator: LicenseValidator):
    """Return async shutdown handler."""

    async def shutdown():
        logger.info("IceBox shutting down")

        for task in list(background_tasks):
            task.cancel()

        await validator.stop()

        redis = app.config.get("REDIS_CLIENT")
        if redis:
            await redis.close()

        close_db()
        logger.info("IceBox shutdown complete")

    return shutdown


async def _jit_revocation_loop(config: IceBoxConfig) -> None:
    """Background task: revoke expired JIT grants every 60 seconds."""
    from models.db import get_db

    interval = config.auth.jit_revocation_check_interval_seconds
    while True:
        try:
            await asyncio.sleep(interval)
            db = get_db(config.database.uri, config.database.pool_size)
            now = datetime.utcnow()

            # Revoke expired grants
            expired = db(
                (db.icebox_jit_grants.expires_at <= now)
                & (db.icebox_jit_grants.revoked_at == None)
            ).select()

            for grant in expired:
                db(db.icebox_jit_grants.id == grant.id).update(revoked_at=now)
                db(db.icebox_jit_requests.id == grant.request_id).update(status="expired")

            if expired:
                db.commit()
                logger.info("JIT revocation: %d grants expired", len(expired))

        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.error("JIT revocation loop error: %s", exc)


def main() -> None:
    """Entry point for running the IceBox flask-backend."""
    import hypercorn.asyncio
    from hypercorn.config import Config as HypercornConfig

    config = get_config()
    app = create_app(config)

    hconfig = HypercornConfig()
    hconfig.bind = [f"{config.host}:{config.port}"]
    hconfig.loglevel = config.log_level.lower()

    logger.info("Starting IceBox on %s:%d", config.host, config.port)
    asyncio.run(hypercorn.asyncio.serve(app, hconfig))


if __name__ == "__main__":
    main()
