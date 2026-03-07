"""
IceBox PyDAL Table Definitions

PyDAL handles ALL runtime database operations. Tables are defined here
matching the Alembic migration schema. migrate=False is MANDATORY —
Alembic is the sole source of truth for schema changes.

Usage:
    from models.db import get_db, close_db, define_tables
    db = get_db(config.database.uri)
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime
from typing import Optional

from pydal import DAL

logger = logging.getLogger(__name__)

_thread_local = threading.local()


def get_db(db_uri: str, pool_size: int = 10) -> DAL:
    """
    Return a thread-local PyDAL instance.

    Creates one DAL instance per thread on first call; reuses on subsequent
    calls within the same thread. migrate=False is always enforced.
    """
    if not hasattr(_thread_local, "db") or _thread_local.db is None:
        db = DAL(
            db_uri,
            pool_size=pool_size,
            migrate=False,
            fake_migrate=False,
            lazy_tables=True,
        )
        define_tables(db)
        _thread_local.db = db
        logger.debug("Created new PyDAL instance for thread %s", threading.get_ident())
    return _thread_local.db


def close_db() -> None:
    """Close and discard the thread-local PyDAL instance."""
    if hasattr(_thread_local, "db") and _thread_local.db is not None:
        try:
            _thread_local.db.close()
        except Exception:
            pass
        _thread_local.db = None


def wait_for_database(db_uri: str, max_retries: int = 10, retry_delay: int = 5) -> bool:
    """Wait for the database to become available with exponential backoff."""
    for attempt in range(max_retries):
        try:
            db = DAL(db_uri, pool_size=1, migrate=False, fake_migrate=False)
            db.close()
            logger.info("Database connection established")
            return True
        except Exception as exc:
            wait = min(retry_delay * (2 ** attempt), 60)
            logger.warning(
                "Database unavailable (attempt %d/%d): %s. Retrying in %ds",
                attempt + 1,
                max_retries,
                exc,
                wait,
            )
            time.sleep(wait)
    return False


def define_tables(db: DAL) -> None:
    """
    Define all IceBox tables on the provided PyDAL DAL instance.

    Table schemas must match the Alembic migration in
    alembic/versions/001_icebox_initial.py.
    """
    # icebox_secrets
    db.define_table(
        "icebox_secrets",
        db.Field("id", "string", length=36, notnull=True),
        db.Field("name", "string", length=255, notnull=True),
        db.Field("description", "text"),
        db.Field("secret_type", "string", length=50, notnull=True, default="api_key"),
        db.Field("encrypted_value", "text", notnull=True),
        db.Field("encrypted_dek", "text", notnull=True),
        db.Field("dek_version", "integer", notnull=True, default=1),
        db.Field("cloud_kms_ref", "string", length=1024),
        db.Field("tags", "json"),
        db.Field("secret_metadata", "json"),
        db.Field("expires_at", "datetime"),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        db.Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow, notnull=True),
        db.Field("created_by", "string", length=255),
        primarykey=["id"],
        migrate=False,
    )

    # icebox_secret_owners
    db.define_table(
        "icebox_secret_owners",
        db.Field("secret_id", "string", length=36, notnull=True),
        db.Field("owner_type", "string", length=20, notnull=True),
        db.Field("owner_id", "string", length=255, notnull=True),
        migrate=False,
    )

    # icebox_secret_versions
    db.define_table(
        "icebox_secret_versions",
        db.Field("id", "string", length=36, notnull=True),
        db.Field("secret_id", "string", length=36, notnull=True),
        db.Field("version_number", "integer", notnull=True, default=1),
        db.Field("encrypted_value", "text", notnull=True),
        db.Field("encrypted_dek", "text", notnull=True),
        db.Field("dek_version", "integer", notnull=True, default=1),
        db.Field("created_by", "string", length=255),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        db.Field("deprecated_at", "datetime"),
        primarykey=["id"],
        migrate=False,
    )

    # icebox_secret_policies
    db.define_table(
        "icebox_secret_policies",
        db.Field("secret_id", "string", length=36, notnull=True),
        db.Field("operation", "string", length=50, notnull=True),
        db.Field("required_scope", "string", length=100, notnull=True),
        db.Field("required_role", "string", length=100),
        migrate=False,
    )

    # icebox_jit_requests
    db.define_table(
        "icebox_jit_requests",
        db.Field("id", "string", length=36, notnull=True),
        db.Field("secret_id", "string", length=36, notnull=True),
        db.Field("requestor_id", "string", length=255, notnull=True),
        db.Field("reason", "text", notnull=True),
        db.Field("requested_duration_seconds", "integer", notnull=True),
        db.Field("approved_duration_seconds", "integer"),
        db.Field("status", "string", length=20, notnull=True, default="pending"),
        db.Field("approved_by", "string", length=255),
        db.Field("approved_at", "datetime"),
        db.Field("access_expires_at", "datetime"),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        primarykey=["id"],
        migrate=False,
    )

    # icebox_jit_grants
    db.define_table(
        "icebox_jit_grants",
        db.Field("id", "string", length=36, notnull=True),
        db.Field("request_id", "string", length=36, notnull=True),
        db.Field("secret_id", "string", length=36, notnull=True),
        db.Field("grantee_id", "string", length=255, notnull=True),
        db.Field("access_token_hash", "string", length=64, notnull=True),
        db.Field("expires_at", "datetime", notnull=True),
        db.Field("revoked_at", "datetime"),
        primarykey=["id"],
        migrate=False,
    )

    # icebox_one_time_secrets
    db.define_table(
        "icebox_one_time_secrets",
        db.Field("id", "string", length=36, notnull=True),
        db.Field("token_hash", "string", length=64, notnull=True, unique=True),
        db.Field("encrypted_value", "text", notnull=True),
        db.Field("encrypted_dek", "text", notnull=True),
        db.Field("dek_version", "integer", notnull=True, default=1),
        db.Field("viewed_at", "datetime"),
        db.Field("expires_at", "datetime", notnull=True),
        db.Field("created_by", "string", length=255),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        primarykey=["id"],
        migrate=False,
    )

    # icebox_cloud_integrations
    db.define_table(
        "icebox_cloud_integrations",
        db.Field("id", "string", length=36, notnull=True),
        db.Field("provider", "string", length=20, notnull=True),
        db.Field("name", "string", length=255, notnull=True),
        db.Field("description", "text"),
        db.Field("sync_direction", "string", length=30, notnull=True, default="icebox_to_cloud"),
        db.Field("sync_scopes", "json"),
        db.Field("encrypted_credentials", "text"),
        db.Field("enabled", "boolean", notnull=True, default=True),
        db.Field("config", "json"),
        db.Field("last_sync_at", "datetime"),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        primarykey=["id"],
        migrate=False,
    )

    # icebox_cloud_sync_state
    db.define_table(
        "icebox_cloud_sync_state",
        db.Field("secret_id", "string", length=36, notnull=True),
        db.Field("integration_id", "string", length=36, notnull=True),
        db.Field("external_ref", "string", length=1024),
        db.Field("last_synced_at", "datetime"),
        db.Field("sync_status", "string", length=50),
        db.Field("conflict_resolution", "string", length=20, notnull=True, default="icebox_wins"),
        migrate=False,
    )

    # icebox_audit_log
    db.define_table(
        "icebox_audit_log",
        db.Field("id", "string", length=36, notnull=True),
        db.Field("actor_id", "string", length=255, notnull=True),
        db.Field("action", "string", length=100, notnull=True),
        db.Field("resource_type", "string", length=50, notnull=True),
        db.Field("resource_id", "string", length=255),
        db.Field("ip_address", "string", length=45),
        db.Field("user_agent", "string", length=512),
        db.Field("log_metadata", "json"),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        primarykey=["id"],
        migrate=False,
    )

    # icebox_license
    db.define_table(
        "icebox_license",
        db.Field("license_key_encrypted", "text", notnull=True),
        db.Field("validated_at", "datetime"),
        db.Field("entitlements", "json"),
        db.Field("license_server_url", "string", length=512, notnull=True,
                 default="https://license.penguintech.io"),
        db.Field("auto_bypass_domains", "json"),
        migrate=False,
    )
