"""
PyDAL Table Definitions for Worker-Scanner Service.

This module defines all database tables using PyDAL for runtime operations.
Table schemas match the Alembic migrations. Per project standards, PyDAL handles
ALL runtime database operations while Alembic manages schema migrations.

Tables:
    - scan_targets: Security scan target definitions
    - scan_jobs: Scan job execution records
    - scan_findings: Security findings from scans
    - scan_schedules: Scheduled scan configurations
"""

import logging
from datetime import datetime
from typing import Any

from pydal import DAL

from .connection import get_db

# Configure logging
logger = logging.getLogger(__name__)


def define_tables(db: DAL) -> None:
    """
    Define all database tables on the provided PyDAL DAL instance.

    This function defines table schemas matching the Alembic migrations.
    Tables are defined with proper field types, constraints, and defaults.

    Args:
        db: PyDAL DAL instance to define tables on

    Note:
        - All tables use default PyDAL 'id' primary key (integer auto-increment)
        - Foreign keys use PyDAL 'reference' type
        - JSON fields store structured data
        - Timestamps use datetime fields
        - migrate=False as Alembic handles schema changes
    """
    # scan_targets table: Security scan target definitions
    db.define_table(
        "scan_targets",
        db.Field("name", "string", length=255, notnull=True),
        db.Field("target_type", "string", length=50, notnull=True),
        db.Field("target_value", "string", length=2048, notnull=True),
        db.Field("description", "text"),
        db.Field("enabled", "boolean", default=True, notnull=True),
        db.Field("tags", "json"),
        db.Field(
            "scan_metadata", "json"
        ),  # Renamed from 'metadata_' for PyDAL compatibility
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        db.Field(
            "updated_at",
            "datetime",
            default=datetime.utcnow,
            update=datetime.utcnow,
            notnull=True,
        ),
        db.Field("created_by", "string", length=255),
        migrate=False,
    )

    # scan_jobs table: Scan job execution records
    db.define_table(
        "scan_jobs",
        db.Field(
            "target_id", "reference scan_targets", notnull=True, ondelete="CASCADE"
        ),
        db.Field("scanner_type", "string", length=50, notnull=True),
        db.Field("scan_type", "string", length=50, notnull=True),
        db.Field("status", "string", length=50, default="pending", notnull=True),
        db.Field("priority", "integer", default=5, notnull=True),
        db.Field("config", "json"),
        db.Field("started_at", "datetime"),
        db.Field("completed_at", "datetime"),
        db.Field("duration_seconds", "integer"),
        db.Field("error_message", "text"),
        db.Field("result_summary", "json"),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        db.Field("created_by", "string", length=255),
        migrate=False,
    )

    # scan_findings table: Security findings from scans
    db.define_table(
        "scan_findings",
        db.Field("job_id", "reference scan_jobs", notnull=True, ondelete="CASCADE"),
        db.Field(
            "target_id", "reference scan_targets", notnull=True, ondelete="CASCADE"
        ),
        db.Field("finding_id", "string", length=512, notnull=True),
        db.Field("severity", "string", length=50, notnull=True),
        db.Field("title", "string", length=1024, notnull=True),
        db.Field("description", "text"),
        db.Field("remediation", "text"),
        db.Field("affected_url", "string", length=2048),
        db.Field("cvss_score", "double"),
        db.Field("cve_ids", "json"),
        db.Field("cwe_ids", "json"),
        db.Field("evidence", "text"),
        db.Field("raw_finding", "json"),
        db.Field("status", "string", length=50, default="open", notnull=True),
        db.Field("discovered_at", "datetime", default=datetime.utcnow, notnull=True),
        db.Field(
            "updated_at",
            "datetime",
            default=datetime.utcnow,
            update=datetime.utcnow,
            notnull=True,
        ),
        migrate=False,
    )

    # scan_schedules table: Scheduled scan configurations
    db.define_table(
        "scan_schedules",
        db.Field("name", "string", length=255, notnull=True),
        db.Field(
            "target_id", "reference scan_targets", notnull=True, ondelete="CASCADE"
        ),
        db.Field("scanner_type", "string", length=50, notnull=True),
        db.Field("scan_type", "string", length=50, notnull=True),
        db.Field("cron_expression", "string", length=255, notnull=True),
        db.Field("config", "json"),
        db.Field("enabled", "boolean", default=True, notnull=True),
        db.Field("last_run", "datetime"),
        db.Field("next_run", "datetime"),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        db.Field("created_by", "string", length=255),
        migrate=False,
    )

    logger.info(
        "PyDAL tables defined: scan_targets, scan_jobs, scan_findings, scan_schedules"
    )


def define_asm_tables(db: DAL) -> None:
    """
    Define ASM (Attack Surface Management) database tables.

    All tables use migrate=False as Alembic manages schema changes.

    Args:
        db: PyDAL DAL instance to define tables on
    """
    # asm_scans table
    db.define_table(
        "asm_scans",
        db.Field(
            "target_id", "reference scan_targets", notnull=True, ondelete="CASCADE"
        ),
        db.Field("mode", "string", length=20, default="external", notnull=True),
        db.Field("status", "string", length=50, default="pending", notnull=True),
        db.Field("ports_config", "json"),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        db.Field("started_at", "datetime"),
        db.Field("completed_at", "datetime"),
        db.Field("created_by", "string", length=255),
        migrate=False,
    )

    # asm_hosts table
    db.define_table(
        "asm_hosts",
        db.Field("scan_id", "reference asm_scans", notnull=True, ondelete="CASCADE"),
        db.Field("ip_address", "string", length=45, notnull=True),
        db.Field("hostname", "string", length=255),
        db.Field("is_alive", "boolean", default=True, notnull=True),
        db.Field("latency_ms", "double"),
        db.Field("os_guess", "string", length=255),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        migrate=False,
    )

    # asm_services table
    db.define_table(
        "asm_services",
        db.Field("host_id", "reference asm_hosts", notnull=True, ondelete="CASCADE"),
        db.Field("port", "integer", notnull=True),
        db.Field("protocol", "string", length=10, default="tcp", notnull=True),
        db.Field("state", "string", length=20, default="open", notnull=True),
        db.Field("service_name", "string", length=100),
        db.Field("banner", "text"),
        db.Field("version", "string", length=255),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        migrate=False,
    )

    # asm_screenshots table
    db.define_table(
        "asm_screenshots",
        db.Field(
            "service_id", "reference asm_services", notnull=True, ondelete="CASCADE"
        ),
        db.Field("s3_key", "string", length=1024, notnull=True),
        db.Field("url", "string", length=2048),
        db.Field("tool", "string", length=50, notnull=True),
        db.Field("width", "integer"),
        db.Field("height", "integer"),
        db.Field("file_size_bytes", "integer"),
        db.Field("captured_at", "datetime"),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        migrate=False,
    )

    # asm_certs table
    db.define_table(
        "asm_certs",
        db.Field(
            "service_id", "reference asm_services", notnull=True, ondelete="CASCADE"
        ),
        db.Field("subject", "string", length=512),
        db.Field("issuer", "string", length=512),
        db.Field("not_before", "datetime"),
        db.Field("not_after", "datetime"),
        db.Field("is_expired", "boolean", default=False, notnull=True),
        db.Field("days_until_expiry", "integer"),
        db.Field("sans", "json"),
        db.Field("fingerprint_sha256", "string", length=64),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        migrate=False,
    )

    # asm_diffs table
    db.define_table(
        "asm_diffs",
        db.Field("scan_id", "reference asm_scans", notnull=True, ondelete="CASCADE"),
        db.Field("prev_scan_id", "reference asm_scans"),
        db.Field("new_services", "json"),
        db.Field("removed_services", "json"),
        db.Field("new_certs", "json"),
        db.Field("expired_certs", "json"),
        db.Field("created_at", "datetime", default=datetime.utcnow, notnull=True),
        migrate=False,
    )

    # asm_settings table
    db.define_table(
        "asm_settings",
        db.Field("key", "string", length=255, notnull=True, unique=True),
        db.Field("value", "json"),
        db.Field(
            "updated_at",
            "datetime",
            default=datetime.utcnow,
            update=datetime.utcnow,
            notnull=True,
        ),
        db.Field("updated_by", "string", length=255),
        migrate=False,
    )

    logger.info(
        "PyDAL ASM tables defined: asm_scans, asm_hosts, asm_services, "
        "asm_screenshots, asm_certs, asm_diffs, asm_settings"
    )


def get_configured_db() -> DAL:
    """
    Get PyDAL database connection with all tables defined.

    This is a convenience function that combines get_db() and define_tables()
    to return a fully configured DAL instance ready for runtime operations.

    Returns:
        DAL: PyDAL database connection with all tables defined

    Example:
        >>> db = get_configured_db()
        >>> targets = db(db.scan_targets.enabled == True).select()
        >>> new_target = db.scan_targets.insert(
        ...     name='example.com',
        ...     target_type='domain',
        ...     target_value='example.com'
        ... )
        >>> db.commit()
    """
    db = get_db()
    define_tables(db)
    define_asm_tables(db)
    return db
