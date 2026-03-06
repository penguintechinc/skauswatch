"""PyDAL table definitions for worker-darwin service.

All tables use darwin_ prefix. PyDAL is used ONLY for runtime operations.
Schema creation/migration is handled exclusively by Alembic.

IMPORTANT: migrate=False on all DAL instances — Alembic manages schema.
"""

import logging
from typing import Optional

from flask import g
from pydal import DAL, Field

from config.settings import settings

logger = logging.getLogger(__name__)


def get_db() -> DAL:
    """Get PyDAL connection for the current Flask request context.

    Uses Flask g for request-scoped connection per flask-backend pattern.

    Returns:
        DAL: PyDAL connection instance
    """
    if "db" not in g:
        g.db = _create_connection()
    return g.db


def get_configured_db() -> DAL:
    """Get a standalone PyDAL connection for use outside Flask context (e.g., Celery).

    Callers are responsible for calling db.close() when done.

    Returns:
        DAL: PyDAL connection instance
    """
    return _create_connection()


def _create_connection() -> DAL:
    """Create and configure a PyDAL connection with all darwin tables defined."""
    uri = settings.database.get_pydal_uri()
    db = DAL(
        uri,
        pool_size=5,
        migrate=False,
        fake_migrate=False,
        lazy_tables=True,
    )
    define_darwin_tables(db)
    return db


def define_darwin_tables(db: DAL) -> None:
    """Define all darwin_* tables on the given DAL instance.

    Called at app startup and for Celery worker connections.
    migrate=False — Alembic owns the schema.

    Args:
        db: PyDAL instance to define tables on
    """
    db.define_table(
        "darwin_tenants",
        Field("name", "string", length=255, requires=None),
        Field("plan", "string", length=50, default="free"),  # free | paid
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_users",
        Field("tenant_id", "integer"),
        Field("email", "string", length=255, requires=None),
        Field("password_hash", "string", length=255),
        Field("role", "string", length=50, default="viewer"),
        Field("is_active", "boolean", default=True),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_repo_configs",
        Field("tenant_id", "integer"),
        Field("provider", "string", length=50),  # github | gitlab
        Field("repo_url", "string", length=512),
        Field("repo_name", "string", length=255),
        Field("webhook_secret", "string", length=255),
        Field("auto_review", "boolean", default=True),
        Field("is_active", "boolean", default=True),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_git_credentials",
        Field("tenant_id", "integer"),
        Field("provider", "string", length=50),
        Field("token_encrypted", "string", length=2048),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_reviews",
        Field("repo_config_id", "integer"),
        Field("pr_number", "integer"),
        Field("pr_url", "string", length=512),
        Field("status", "string", length=50, default="pending"),
        Field("ai_provider", "string", length=50),
        Field("model", "string", length=100),
        Field("summary", "text"),
        Field("completed_at", "datetime"),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_review_comments",
        Field("review_id", "integer"),
        Field("file_path", "string", length=512),
        Field("line_number", "integer"),
        Field("comment", "text"),
        Field("severity", "string", length=50),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_review_detections",
        Field("review_id", "integer"),
        Field("detection_type", "string", length=100),
        Field("detail", "text"),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_issue_plans",
        Field("repo_config_id", "integer"),
        Field("issue_number", "integer"),
        Field("issue_url", "string", length=512),
        Field("plan_content", "text"),
        Field("ai_provider", "string", length=50),
        Field("status", "string", length=50, default="pending"),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_provider_usage",
        Field("tenant_id", "integer"),
        Field("provider", "string", length=50),
        Field("model", "string", length=100),
        Field("tokens_in", "integer", default=0),
        Field("tokens_out", "integer", default=0),
        Field("cost_usd", "double", default=0.0),
        Field("recorded_at", "datetime"),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_license_policies",
        Field("repo_config_id", "integer"),
        Field("allowed_spdx", "text"),
        Field("denied_spdx", "text"),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_license_detections",
        Field("review_id", "integer"),
        Field("file_path", "string", length=512),
        Field("spdx_id", "string", length=100),
        Field("created_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "darwin_license_violations",
        Field("review_id", "integer"),
        Field("file_path", "string", length=512),
        Field("spdx_id", "string", length=100),
        Field("reason", "text"),
        Field("created_at", "datetime"),
        migrate=False,
    )


def teardown_db(error: Optional[Exception] = None) -> None:
    """Close database connection after Flask request.

    Args:
        error: Exception if request ended with an error
    """
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception as exc:
            logger.warning("Error closing database connection: %s", exc)
