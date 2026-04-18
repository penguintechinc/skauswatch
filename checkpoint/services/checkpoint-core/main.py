"""
checkpoint-core — AAA protocol layer for SkausWatch.

Exposes:
  - OIDC / OAuth2 endpoints  (/oidc/*)
  - REST management API      (/api/v1/*)
  - gRPC server              (port CHECKPOINT_GRPC_PORT, called by ldap-agent)
  - LDAP server              (port CHECKPOINT_LDAP_PORT, if CHECKPOINT_LDAP_ENABLED)

Identity data (users, groups) is owned by skauswatch-core (manager-new) and
accessed via gRPC — checkpoint never queries identity tables directly.
"""
from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any

import structlog
from quart import Quart
from quart_cors import cors

from api.v1.audit import audit_bp
from api.v1.clients import clients_bp
from api.v1.health import health_bp
from api.v1.idp import idp_bp
from api.v1.scim_tokens import scim_tokens_bp
from api.v1.users_groups import users_groups_bp
from audit.logger import AuditLogger
from config import CheckpointConfig
from federation.sync import UpstreamSyncLoop
from checkpoint_grpc.core_client import CoreIdentityClient
from checkpoint_grpc.server import start_grpc_server
from ldap.server import LDAPServer
from models.db import init_checkpoint_tables
from oidc.endpoints import discovery_bp, oidc_bp
from saml.endpoints import saml_bp
from scim.endpoints import scim_bp

# ── Logging ───────────────────────────────────────────────────────────────────

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)


# ── Application factory ───────────────────────────────────────────────────────


def create_app(cfg: CheckpointConfig | None = None) -> Quart:
    """
    Create and configure the checkpoint-core Quart application.

    Extensions stored on app.extensions:
      checkpoint_config      — CheckpointConfig instance
      checkpoint_db          — PyDAL DAL instance
      checkpoint_core_client — CoreIdentityClient
      checkpoint_audit       — AuditLogger
    """
    if cfg is None:
        cfg = CheckpointConfig()  # type: ignore[call-arg]

    app = Quart(__name__)

    # CORS — restrict in production via cfg.issuer_url
    app = cors(app, allow_origin="*")

    # Store config
    app.extensions["checkpoint_config"] = cfg

    # Register blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(discovery_bp)
    app.register_blueprint(oidc_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(scim_bp)
    app.register_blueprint(saml_bp)
    app.register_blueprint(scim_tokens_bp)
    app.register_blueprint(audit_bp)
    app.register_blueprint(idp_bp)
    app.register_blueprint(users_groups_bp)

    # ── DB init (deferred to startup) ─────────────────────────────────────────

    @app.before_serving
    async def startup() -> None:
        """Initialise DB connection, gRPC client, and background tasks."""
        logger.info("checkpoint_core.startup issuer=%s", cfg.issuer_url)

        # penguin-dal connection — auto-reflects schema from database
        db = init_checkpoint_tables(cfg.db_uri, pool_size=cfg.db_pool_size)
        app.extensions["checkpoint_db"] = db
        logger.info("checkpoint_core.db_connected")

        # gRPC client → skauswatch-core
        core_client = CoreIdentityClient(
            host=cfg.core_grpc_host,
            port=cfg.core_grpc_port,
        )
        await core_client.connect()
        app.extensions["checkpoint_core_client"] = core_client
        logger.info(
            "checkpoint_core.grpc_client_connected target=%s:%d",
            cfg.core_grpc_host,
            cfg.core_grpc_port,
        )

        # Audit logger
        audit = AuditLogger(
            db,
            watcher_enabled=cfg.watcher_enabled,
            watcher_url=cfg.watcher_url,
        )
        app.extensions["checkpoint_audit"] = audit

        # Inbound gRPC server (for ldap-agent)
        grpc_server = await start_grpc_server(
            core_client=core_client,
            db=db,
            audit=audit,
            port=cfg.grpc_port,
            ldap_base_dn=cfg.ldap_base_dn,
        )
        app.extensions["checkpoint_grpc_server"] = grpc_server

        # Background tasks
        asyncio.create_task(_signing_key_rotation_check(app, cfg))
        asyncio.create_task(_upstream_idp_sync_loop(app, cfg))

        if cfg.ldap_enabled:
            asyncio.create_task(_start_ldap_server(app, cfg))

        logger.info("checkpoint_core.ready port=%d", cfg.port)

    @app.after_serving
    async def shutdown() -> None:
        """Graceful shutdown — close DB connection and gRPC channels."""
        logger.info("checkpoint_core.shutdown")

        core_client: CoreIdentityClient | None = app.extensions.get("checkpoint_core_client")
        if core_client:
            await core_client.close()

        grpc_server = app.extensions.get("checkpoint_grpc_server")
        if grpc_server:
            await grpc_server.stop(grace=5)

        db = app.extensions.get("checkpoint_db")
        if db:
            try:
                db.close()
            except Exception:  # noqa: BLE001
                pass

        logger.info("checkpoint_core.shutdown_complete")

    return app


# ── Background tasks ──────────────────────────────────────────────────────────


async def _signing_key_rotation_check(app: Quart, cfg: CheckpointConfig) -> None:
    """
    Periodic task: check whether the active signing key needs rotation.

    Logs a warning if no active key exists (operator must generate one via API).
    Runs every 6 hours.
    """
    from oidc.jwt_utils import get_active_signing_key

    while True:
        try:
            await asyncio.sleep(6 * 3600)
            async with app.app_context():
                db = app.extensions.get("checkpoint_db")
                if db is None:
                    continue
                key = get_active_signing_key(db)
                if key is None:
                    logger.warning("signing_key_rotation.no_active_key — operator action required")
                else:
                    logger.debug("signing_key_rotation.ok kid=%s", key["kid"])
        except asyncio.CancelledError:
            break
        except Exception as exc:  # noqa: BLE001
            logger.error("signing_key_rotation.error error=%r", exc)


async def _upstream_idp_sync_loop(app: Quart, cfg: CheckpointConfig) -> None:
    """
    Background task: sync users from active upstream IDPs (federation mode=sync).

    Delegates entirely to UpstreamSyncLoop which manages per-IDP sync
    intervals, retry logic, and per-type sync handlers (OIDC, SAML, LDAP, etc.).
    """
    await UpstreamSyncLoop(app).run_forever()


async def _start_ldap_server(app: Quart, cfg: CheckpointConfig) -> None:
    """
    Background task: run the LDAP server daemon.

    The LDAP server proxies all requests through CoreIdentityClient — it does
    NOT query identity data directly.  Uses ldaptor for RFC 4511-compliant
    async TCP handling.
    """
    core_client: CoreIdentityClient | None = app.extensions.get(
        "checkpoint_core_client"
    )
    if core_client is None:
        logger.error("ldap_server.start_failed — core_client not available")
        return

    server = LDAPServer(
        core_client=core_client,
        base_dn=cfg.ldap_base_dn,
        port=cfg.ldap_port,
        ldaps_port=cfg.ldaps_port,
        allow_anon=cfg.ldap_allow_anonymous,
    )
    await server.start()


# ── Entry point ───────────────────────────────────────────────────────────────

app = create_app()

if __name__ == "__main__":
    import hypercorn.asyncio
    import hypercorn.config as hypercorn_cfg

    cfg = CheckpointConfig()  # type: ignore[call-arg]
    h_cfg = hypercorn_cfg.Config()
    h_cfg.bind = [f"0.0.0.0:{cfg.port}"]

    asyncio.run(hypercorn.asyncio.serve(app, h_cfg))
