"""
Database initialization and runtime operations.

SQLAlchemy is used ONLY for database schema initialization.
PyDAL is used for ALL runtime database operations.
"""

import logging
import os
from contextlib import contextmanager
from datetime import datetime
from threading import local
from typing import Any, Dict, List, Optional

from pydal import DAL, Field
from pydal.validators import (
    CLEANUP,
    CRYPT,
    IS_EMAIL,
    IS_FLOAT_IN_RANGE,
    IS_IN_DB,
    IS_IN_SET,
    IS_JSON,
    IS_LENGTH,
    IS_MATCH,
    IS_NOT_EMPTY,
    IS_NOT_IN_DB,
    IS_SLUG,
)
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.engine import Engine

logger = logging.getLogger(__name__)

# Thread-local storage for PyDAL connections
_thread_local = local()


# ============================================
# SQLAlchemy: DB INITIALIZATION ONLY
# ============================================


def init_database_schema(database_url: str) -> None:
    """
    One-time schema creation with SQLAlchemy.
    Called ONCE at application startup if tables don't exist.
    DO NOT use SQLAlchemy for any runtime operations.
    """
    logger.info("Initializing database schema with SQLAlchemy...")

    # Convert PyDAL URI to SQLAlchemy format
    sqlalchemy_url = _convert_pydal_to_sqlalchemy_uri(database_url)
    engine = create_engine(sqlalchemy_url)
    metadata = MetaData()

    # Users table
    Table(
        "users",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("email", String(255), unique=True, nullable=False),
        Column("password_hash", String(255), nullable=False),
        Column("full_name", String(255)),
        Column("role", String(20), nullable=False, default="viewer"),
        Column("is_active", Boolean, default=True),
        Column("mfa_enabled", Boolean, default=False),
        Column("mfa_secret", String(32)),
        Column("failed_login_attempts", Integer, default=0),
        Column("account_locked_until", DateTime),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, onupdate=datetime.utcnow),
    )

    # Refresh tokens table
    Table(
        "refresh_tokens",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("user_id", Integer, nullable=False),
        Column("token_hash", String(255), unique=True),
        Column("expires_at", DateTime),
        Column("revoked", Boolean, default=False),
        Column("created_at", DateTime, server_default="now()"),
    )

    # Threat indicators table
    Table(
        "threat_indicators",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("indicator_type", String(50), nullable=False),
        Column("value", Text, nullable=False),
        Column("threat_level", String(20)),
        Column("confidence", Float),
        Column("source", String(100)),
        Column("tags", JSONB),
        Column("metadata", JSONB),
        Column("expires_at", DateTime),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, onupdate=datetime.utcnow),
    )

    # Alerts table
    Table(
        "alerts",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("title", String(255), nullable=False),
        Column("description", Text),
        Column("severity", String(20), nullable=False),
        Column("status", String(20), default="pending"),
        Column("source", String(100)),
        Column("indicators", JSONB),
        Column("ai_review", JSONB),
        Column("assigned_to", Integer),
        Column("resolved_at", DateTime),
        Column("resolution_notes", Text),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, onupdate=datetime.utcnow),
    )

    # Approval requests table
    Table(
        "approval_requests",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("request_type", String(50), nullable=False),
        Column("resource_id", String(128)),
        Column("resource_type", String(50)),
        Column("requester_id", Integer, nullable=False),
        Column("status", String(20), default="pending"),
        Column("required_approvals", Integer, default=1),
        Column("current_approvals", Integer, default=0),
        Column("approvers", JSONB),
        Column("approval_history", JSONB),
        Column("expires_at", DateTime),
        Column("completed_at", DateTime),
        Column("metadata", JSONB),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, onupdate=datetime.utcnow),
    )

    # Audit logs table
    Table(
        "audit_logs",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("event_type", String(64), nullable=False),
        Column("action", String(128), nullable=False),
        Column("resource_type", String(64)),
        Column("resource_id", String(128)),
        Column("user_id", Integer),
        Column("ip_address", String(45)),
        Column("user_agent", Text),
        Column("success", Boolean, nullable=False),
        Column("details", JSONB),
        Column("severity", String(16), default="info"),
        Column("created_at", DateTime, server_default="now()"),
    )

    # EDR agents table
    Table(
        "edr_agents",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("agent_id", String(128), unique=True, nullable=False),
        Column("hostname", String(255)),
        Column("ip_address", String(45)),
        Column("os_type", String(50)),
        Column("os_version", String(100)),
        Column("agent_version", String(32)),
        Column("status", String(20), default="active"),
        Column("last_heartbeat", DateTime),
        Column("metadata", JSONB),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, onupdate=datetime.utcnow),
    )

    # EDR events table
    Table(
        "edr_events",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("agent_id", String(128), nullable=False),
        Column("event_type", String(64), nullable=False),
        Column("severity", String(20)),
        Column("process_name", String(255)),
        Column("process_path", Text),
        Column("process_hash", String(128)),
        Column("parent_process", String(255)),
        Column("command_line", Text),
        Column("network_connections", JSONB),
        Column("file_operations", JSONB),
        Column("registry_operations", JSONB),
        Column("details", JSONB),
        Column("created_at", DateTime, server_default="now()"),
    )

    # S3 bucket configurations table
    Table(
        "s3_bucket_configs",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("name", String(255), unique=True, nullable=False),
        Column("endpoint_url", String(255), nullable=False),
        Column("bucket_name", String(255), nullable=False),
        Column("access_key_id", String(255), nullable=False),
        Column("secret_access_key", String(255), nullable=False),
        Column("region", String(50)),
        Column("use_ssl", Boolean, default=True),
        Column("path_style", Boolean, default=False),
        Column("prefix_filter", String(255)),
        Column("file_types_filter", JSONB),
        Column("max_file_size_mb", Integer, default=100),
        Column("scan_enabled", Boolean, default=True),
        Column("yara_enabled", Boolean, default=False),
        Column("created_by", Integer, nullable=False),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, onupdate=datetime.utcnow),
    )

    # S3 scan jobs table
    Table(
        "s3_scan_jobs",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("job_id", String(36), unique=True, nullable=False),
        Column("bucket_config_id", Integer, nullable=False),
        Column("job_type", String(50), nullable=False),
        Column("status", String(20), default="pending"),
        Column("total_objects", Integer, default=0),
        Column("scanned_objects", Integer, default=0),
        Column("infected_objects", Integer, default=0),
        Column("pup_objects", Integer, default=0),
        Column("skipped_objects", Integer, default=0),
        Column("error_count", Integer, default=0),
        Column("started_at", DateTime),
        Column("completed_at", DateTime),
        Column("triggered_by", Integer, nullable=False),
        Column("error_message", Text),
        Column("metadata", JSONB),
        Column("created_at", DateTime, server_default="now()"),
    )

    # S3 scan results table
    Table(
        "s3_scan_results",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("job_id", Integer, nullable=False),
        Column("bucket_config_id", Integer, nullable=False),
        Column("object_key", Text, nullable=False),
        Column("object_size", Integer),
        Column("object_etag", String(128)),
        Column("content_type", String(128)),
        Column("detected_file_type", String(64)),
        Column("scan_status", String(20)),
        Column("is_malware", Boolean, default=False),
        Column("is_pup", Boolean, default=False),
        Column("is_threat", Boolean, default=False),
        Column("threat_names", JSONB),
        Column("clamav_result", JSONB),
        Column("yara_matches", JSONB),
        Column("file_md5", String(32)),
        Column("file_sha1", String(40)),
        Column("file_sha256", String(64)),
        Column("ti_enrichment", JSONB),
        Column("ti_indicator_created", Boolean, default=False),
        Column("ti_indicator_id", Integer),
        Column("sandbox_submitted", Boolean, default=False),
        Column("sandbox_task_id", String(128)),
        Column("sandbox_status", String(20)),
        Column("sandbox_result", JSONB),
        Column("sandbox_completed_at", DateTime),
        Column("scan_duration_ms", Integer),
        Column("tags_applied", JSONB),
        Column("scanned_at", DateTime),
    )

    # Ad-hoc scan results table
    Table(
        "adhoc_scan_results",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("scan_id", String(36), unique=True, nullable=False),
        Column("uploaded_by", Integer, nullable=False),
        Column("original_filename", String(255), nullable=False),
        Column("file_size", Integer),
        Column("content_type", String(128)),
        Column("detected_file_type", String(64)),
        Column("scan_status", String(20)),
        Column("is_malware", Boolean, default=False),
        Column("is_pup", Boolean, default=False),
        Column("is_threat", Boolean, default=False),
        Column("threat_names", JSONB),
        Column("file_md5", String(32)),
        Column("file_sha1", String(40)),
        Column("file_sha256", String(64)),
        Column("clamav_result", JSONB),
        Column("yara_matches", JSONB),
        Column("ti_enrichment", JSONB),
        Column("sandbox_submitted", Boolean, default=False),
        Column("sandbox_result", JSONB),
        Column("scan_duration_ms", Integer),
        Column("uploaded_at", DateTime, server_default="now()"),
        Column("scanned_at", DateTime),
        Column("expires_at", DateTime),
    )

    # S3 scan schedules table
    Table(
        "s3_scan_schedules",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("bucket_config_id", Integer, unique=True, nullable=False),
        Column("cron_expression", String(100), nullable=False),
        Column("timezone", String(50), default="UTC"),
        Column("enabled", Boolean, default=True),
        Column("last_run_at", DateTime),
        Column("next_run_at", DateTime),
        Column("created_at", DateTime, server_default="now()"),
        Column("updated_at", DateTime, onupdate=datetime.utcnow),
    )

    # Create all tables
    try:
        metadata.create_all(engine)
        logger.info("Database schema initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize database schema: {e}")
        raise
    finally:
        engine.dispose()


def _convert_pydal_to_sqlalchemy_uri(pydal_uri: str) -> str:
    """Convert PyDAL URI format to SQLAlchemy format."""
    if pydal_uri.startswith("postgres://"):
        return pydal_uri.replace("postgres://", "postgresql://", 1)
    return pydal_uri


# ============================================
# PyDAL: ALL RUNTIME OPERATIONS
# ============================================


def get_db(database_uri: str = None) -> DAL:
    """
    Get thread-local PyDAL connection for ALL runtime operations.

    This function returns a PyDAL instance for the current thread.
    Tables are defined with migrate=False since schema is managed by SQLAlchemy.
    """
    if not hasattr(_thread_local, "db") or _thread_local.db is None:
        if database_uri is None:
            database_uri = os.getenv("DATABASE_URL", "sqlite://storage.db")

        _thread_local.db = DAL(
            database_uri,
            migrate=False,  # Schema managed by SQLAlchemy init
            pool_size=10,
            check_reserved=["all"],
        )

        # Define tables for runtime use
        define_pydal_tables(_thread_local.db)

    return _thread_local.db


def close_db() -> None:
    """Close the thread-local database connection."""
    if hasattr(_thread_local, "db") and _thread_local.db is not None:
        _thread_local.db.close()
        _thread_local.db = None


@contextmanager
def db_session(database_uri: str = None):
    """Context manager for database sessions with automatic cleanup."""
    db = get_db(database_uri)
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def define_pydal_tables(db: DAL) -> None:
    """Define PyDAL table definitions for runtime use."""

    # Valid roles
    VALID_ROLES = ["admin", "maintainer", "viewer"]

    # Valid threat levels
    THREAT_LEVELS = ["critical", "high", "medium", "low", "info"]

    # Valid alert statuses
    ALERT_STATUSES = [
        "pending",
        "in_progress",
        "resolved",
        "false_positive",
        "escalated",
    ]

    # Valid indicator types
    INDICATOR_TYPES = ["ip", "domain", "hash", "url", "email", "file", "registry"]

    db.define_table(
        "users",
        Field(
            "email",
            "string",
            length=255,
            required=True,
            requires=[IS_NOT_EMPTY(), IS_EMAIL()],
        ),
        Field("password_hash", "string", length=255, required=True),
        Field("full_name", "string", length=255),
        Field(
            "role",
            "string",
            length=20,
            default="viewer",
            requires=IS_IN_SET(
                VALID_ROLES,
                error_message=f"Role must be one of: {', '.join(VALID_ROLES)}",
            ),
        ),
        Field("is_active", "boolean", default=True),
        Field("mfa_enabled", "boolean", default=False),
        Field("mfa_secret", "string", length=32),
        Field("failed_login_attempts", "integer", default=0),
        Field("account_locked_until", "datetime"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", update=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "refresh_tokens",
        Field("user_id", "reference users", required=True),
        Field("token_hash", "string", length=255, unique=True),
        Field("expires_at", "datetime"),
        Field("revoked", "boolean", default=False),
        Field("created_at", "datetime", default=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "threat_indicators",
        Field(
            "indicator_type",
            "string",
            length=50,
            required=True,
            requires=IS_IN_SET(INDICATOR_TYPES),
        ),
        Field("value", "text", required=True),
        Field("threat_level", "string", length=20, requires=IS_IN_SET(THREAT_LEVELS)),
        Field(
            "confidence", "double", default=0.5, requires=IS_FLOAT_IN_RANGE(0.0, 1.0)
        ),
        Field("source", "string", length=100, required=True),
        Field("tags", "json", default=[]),
        Field("metadata", "json", default={}),
        Field("expires_at", "datetime"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", update=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "alerts",
        Field("title", "string", length=255, required=True, requires=IS_NOT_EMPTY()),
        Field("description", "text"),
        Field(
            "severity",
            "string",
            length=20,
            required=True,
            requires=IS_IN_SET(THREAT_LEVELS),
        ),
        Field(
            "status",
            "string",
            length=20,
            default="pending",
            requires=IS_IN_SET(ALERT_STATUSES),
        ),
        Field("source", "string", length=100),
        Field("indicators", "json", default=[]),
        Field("ai_review", "json"),
        Field("assigned_to", "reference users"),
        Field("resolved_at", "datetime"),
        Field("resolution_notes", "text"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", update=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "approval_requests",
        Field(
            "request_type",
            "string",
            length=50,
            required=True,
            requires=IS_IN_SET(["certificate", "user", "service", "configuration"]),
        ),
        Field("resource_id", "string", length=128),
        Field("resource_type", "string", length=50),
        Field("requester_id", "reference users", required=True),
        Field(
            "status",
            "string",
            length=20,
            default="pending",
            requires=IS_IN_SET(["pending", "approved", "rejected", "expired"]),
        ),
        Field("required_approvals", "integer", default=1),
        Field("current_approvals", "integer", default=0),
        Field("approvers", "json", default=[]),
        Field("approval_history", "json", default=[]),
        Field("expires_at", "datetime"),
        Field("completed_at", "datetime"),
        Field("metadata", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", update=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "audit_logs",
        Field(
            "event_type",
            "string",
            length=64,
            required=True,
            requires=IS_IN_SET(
                [
                    "authentication",
                    "authorization",
                    "user_management",
                    "alert_management",
                    "threat_intel",
                    "certificate",
                    "configuration",
                    "edr",
                ]
            ),
        ),
        Field("action", "string", length=128, required=True),
        Field("resource_type", "string", length=64),
        Field("resource_id", "string", length=128),
        Field("user_id", "reference users"),
        Field("ip_address", "string", length=45),
        Field("user_agent", "text"),
        Field("success", "boolean", required=True),
        Field("details", "json", default={}),
        Field(
            "severity",
            "string",
            length=16,
            default="info",
            requires=IS_IN_SET(["debug", "info", "warning", "error", "critical"]),
        ),
        Field("created_at", "datetime", default=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "edr_agents",
        Field("agent_id", "string", length=128, unique=True, required=True),
        Field("hostname", "string", length=255),
        Field("ip_address", "string", length=45),
        Field("os_type", "string", length=50),
        Field("os_version", "string", length=100),
        Field("agent_version", "string", length=32),
        Field(
            "status",
            "string",
            length=20,
            default="active",
            requires=IS_IN_SET(["active", "inactive", "disconnected"]),
        ),
        Field("last_heartbeat", "datetime"),
        Field("metadata", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", update=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "edr_events",
        Field("agent_id", "string", length=128, required=True),
        Field("event_type", "string", length=64, required=True),
        Field("severity", "string", length=20),
        Field("process_name", "string", length=255),
        Field("process_path", "text"),
        Field("process_hash", "string", length=128),
        Field("parent_process", "string", length=255),
        Field("command_line", "text"),
        Field("network_connections", "json"),
        Field("file_operations", "json"),
        Field("registry_operations", "json"),
        Field("details", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "s3_bucket_configs",
        Field(
            "name",
            "string",
            length=255,
            unique=True,
            required=True,
            requires=IS_NOT_EMPTY(),
        ),
        Field("endpoint_url", "string", length=255, required=True),
        Field("bucket_name", "string", length=255, required=True),
        Field("access_key_id", "string", length=255, required=True),
        Field("secret_access_key", "string", length=255, required=True),
        Field("region", "string", length=50),
        Field("use_ssl", "boolean", default=True),
        Field("path_style", "boolean", default=False),
        Field("prefix_filter", "string", length=255),
        Field("file_types_filter", "json", default=[]),
        Field("max_file_size_mb", "integer", default=100),
        Field("scan_enabled", "boolean", default=True),
        Field("yara_enabled", "boolean", default=False),
        Field("created_by", "reference users", required=True),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", update=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "s3_scan_jobs",
        Field("job_id", "string", length=36, unique=True, required=True),
        Field("bucket_config_id", "reference s3_bucket_configs", required=True),
        Field(
            "job_type",
            "string",
            length=50,
            required=True,
            requires=IS_IN_SET(["full_scan", "incremental_scan", "prefix_scan"]),
        ),
        Field(
            "status",
            "string",
            length=20,
            default="pending",
            requires=IS_IN_SET(
                ["pending", "running", "completed", "failed", "cancelled"]
            ),
        ),
        Field("total_objects", "integer", default=0),
        Field("scanned_objects", "integer", default=0),
        Field("infected_objects", "integer", default=0),
        Field("pup_objects", "integer", default=0),
        Field("skipped_objects", "integer", default=0),
        Field("error_count", "integer", default=0),
        Field("started_at", "datetime"),
        Field("completed_at", "datetime"),
        Field("triggered_by", "reference users", required=True),
        Field("error_message", "text"),
        Field("metadata", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        migrate=False,
    )

    db.define_table(
        "s3_scan_results",
        Field("job_id", "reference s3_scan_jobs", required=True),
        Field("bucket_config_id", "reference s3_bucket_configs", required=True),
        Field("object_key", "text", required=True),
        Field("object_size", "integer"),
        Field("object_etag", "string", length=128),
        Field("content_type", "string", length=128),
        Field("detected_file_type", "string", length=64),
        Field(
            "scan_status",
            "string",
            length=20,
            requires=IS_IN_SET(
                ["pending", "scanning", "completed", "failed", "skipped"]
            ),
        ),
        Field("is_malware", "boolean", default=False),
        Field("is_pup", "boolean", default=False),
        Field("is_threat", "boolean", default=False),
        Field("threat_names", "json", default=[]),
        Field("clamav_result", "json"),
        Field("yara_matches", "json"),
        Field("file_md5", "string", length=32),
        Field("file_sha1", "string", length=40),
        Field("file_sha256", "string", length=64),
        Field("ti_enrichment", "json"),
        Field("ti_indicator_created", "boolean", default=False),
        Field("ti_indicator_id", "reference threat_indicators"),
        Field("sandbox_submitted", "boolean", default=False),
        Field("sandbox_task_id", "string", length=128),
        Field("sandbox_status", "string", length=20),
        Field("sandbox_result", "json"),
        Field("sandbox_completed_at", "datetime"),
        Field("scan_duration_ms", "integer"),
        Field("tags_applied", "json"),
        Field("scanned_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "adhoc_scan_results",
        Field("scan_id", "string", length=36, unique=True, required=True),
        Field("uploaded_by", "reference users", required=True),
        Field("original_filename", "string", length=255, required=True),
        Field("file_size", "integer"),
        Field("content_type", "string", length=128),
        Field("detected_file_type", "string", length=64),
        Field(
            "scan_status",
            "string",
            length=20,
            requires=IS_IN_SET(["pending", "scanning", "completed", "failed"]),
        ),
        Field("is_malware", "boolean", default=False),
        Field("is_pup", "boolean", default=False),
        Field("is_threat", "boolean", default=False),
        Field("threat_names", "json", default=[]),
        Field("file_md5", "string", length=32),
        Field("file_sha1", "string", length=40),
        Field("file_sha256", "string", length=64),
        Field("clamav_result", "json"),
        Field("yara_matches", "json"),
        Field("ti_enrichment", "json"),
        Field("sandbox_submitted", "boolean", default=False),
        Field("sandbox_result", "json"),
        Field("scan_duration_ms", "integer"),
        Field("uploaded_at", "datetime", default=datetime.utcnow),
        Field("scanned_at", "datetime"),
        Field("expires_at", "datetime"),
        migrate=False,
    )

    db.define_table(
        "s3_scan_schedules",
        Field(
            "bucket_config_id",
            "reference s3_bucket_configs",
            unique=True,
            required=True,
        ),
        Field("cron_expression", "string", length=100, required=True),
        Field("timezone", "string", length=50, default="UTC"),
        Field("enabled", "boolean", default=True),
        Field("last_run_at", "datetime"),
        Field("next_run_at", "datetime"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", update=datetime.utcnow),
        migrate=False,
    )
