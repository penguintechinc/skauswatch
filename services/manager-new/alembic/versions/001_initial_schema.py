"""Initial manager schema

Revision ID: 001
Revises:
Create Date: 2026-01-29

This migration creates the core manager database schema (users, tokens, threat
intelligence, alerts, approvals, audit logs, EDR, and S3 scan tables).
Per project standards:
- SQLAlchemy is used ONLY for schema definition and migrations
- PyDAL handles all runtime database operations
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all core manager tables and indexes."""

    # users table — legacy authentication; PII lives here
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=255), nullable=True),
        sa.Column(
            "role", sa.String(length=20), nullable=False, server_default="viewer"
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("mfa_secret", sa.String(length=32), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("account_locked_until", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=True,
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )

    # refresh_tokens table
    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("token_hash", sa.String(length=255), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )

    # threat_indicators table
    op.create_table(
        "threat_indicators",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("indicator_type", sa.String(length=50), nullable=False),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("threat_level", sa.String(length=20), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("source", sa.String(length=100), nullable=True),
        sa.Column(
            "tags",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "metadata",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=True,
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # alerts table
    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="pending"
        ),
        sa.Column("source", sa.String(length=100), nullable=True),
        sa.Column(
            "indicators",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "ai_review",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("assigned_to", sa.Integer(), nullable=True),
        sa.Column("resolved_at", sa.DateTime(), nullable=True),
        sa.Column("resolution_notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=True,
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["assigned_to"], ["users.id"]),
    )

    # approval_requests table
    op.create_table(
        "approval_requests",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("request_type", sa.String(length=50), nullable=False),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("resource_type", sa.String(length=50), nullable=True),
        sa.Column("requester_id", sa.Integer(), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="pending"
        ),
        sa.Column("required_approvals", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("current_approvals", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "approvers",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "approval_history",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column(
            "metadata",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=True,
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["requester_id"], ["users.id"]),
    )

    # audit_logs table
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=True),
        sa.Column("resource_id", sa.String(length=128), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column(
            "details",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "severity", sa.String(length=16), nullable=False, server_default="info"
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
    )

    # edr_agents table
    op.create_table(
        "edr_agents",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("os_type", sa.String(length=50), nullable=True),
        sa.Column("os_version", sa.String(length=100), nullable=True),
        sa.Column("agent_version", sa.String(length=32), nullable=True),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="active"
        ),
        sa.Column("last_heartbeat", sa.DateTime(), nullable=True),
        sa.Column(
            "metadata",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=True,
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("agent_id"),
    )

    # edr_events table
    op.create_table(
        "edr_events",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("agent_id", sa.String(length=128), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=True),
        sa.Column("process_name", sa.String(length=255), nullable=True),
        sa.Column("process_path", sa.Text(), nullable=True),
        sa.Column("process_hash", sa.String(length=128), nullable=True),
        sa.Column("parent_process", sa.String(length=255), nullable=True),
        sa.Column("command_line", sa.Text(), nullable=True),
        sa.Column(
            "network_connections",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "file_operations",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "registry_operations",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "details",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
    )

    # s3_bucket_configs table
    op.create_table(
        "s3_bucket_configs",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("endpoint_url", sa.String(length=255), nullable=False),
        sa.Column("bucket_name", sa.String(length=255), nullable=False),
        sa.Column("access_key_id", sa.String(length=255), nullable=False),
        sa.Column("secret_access_key", sa.String(length=255), nullable=False),
        sa.Column("region", sa.String(length=50), nullable=True),
        sa.Column("use_ssl", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("path_style", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("prefix_filter", sa.String(length=255), nullable=True),
        sa.Column(
            "file_types_filter",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("max_file_size_mb", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("scan_enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("yara_enabled", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("created_by", sa.Integer(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=True,
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"]),
    )

    # s3_scan_jobs table
    op.create_table(
        "s3_scan_jobs",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("job_id", sa.String(length=36), nullable=False),
        sa.Column("bucket_config_id", sa.Integer(), nullable=False),
        sa.Column("job_type", sa.String(length=50), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="pending"
        ),
        sa.Column("total_objects", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("scanned_objects", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("infected_objects", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("pup_objects", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("skipped_objects", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("triggered_by", sa.Integer(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("job_id"),
        sa.ForeignKeyConstraint(["bucket_config_id"], ["s3_bucket_configs.id"]),
        sa.ForeignKeyConstraint(["triggered_by"], ["users.id"]),
    )

    # s3_scan_results table
    op.create_table(
        "s3_scan_results",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("bucket_config_id", sa.Integer(), nullable=False),
        sa.Column("object_key", sa.Text(), nullable=False),
        sa.Column("object_size", sa.Integer(), nullable=True),
        sa.Column("object_etag", sa.String(length=128), nullable=True),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("detected_file_type", sa.String(length=64), nullable=True),
        sa.Column("scan_status", sa.String(length=20), nullable=True),
        sa.Column("is_malware", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("is_pup", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("is_threat", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column(
            "threat_names",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "clamav_result",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "yara_matches",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("file_md5", sa.String(length=32), nullable=True),
        sa.Column("file_sha1", sa.String(length=40), nullable=True),
        sa.Column("file_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "ti_enrichment",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("ti_indicator_created", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("ti_indicator_id", sa.Integer(), nullable=True),
        sa.Column("sandbox_submitted", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("sandbox_task_id", sa.String(length=128), nullable=True),
        sa.Column("sandbox_status", sa.String(length=20), nullable=True),
        sa.Column(
            "sandbox_result",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("sandbox_completed_at", sa.DateTime(), nullable=True),
        sa.Column("scan_duration_ms", sa.Integer(), nullable=True),
        sa.Column(
            "tags_applied",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("scanned_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["job_id"], ["s3_scan_jobs.id"]),
        sa.ForeignKeyConstraint(["bucket_config_id"], ["s3_bucket_configs.id"]),
        sa.ForeignKeyConstraint(["ti_indicator_id"], ["threat_indicators.id"]),
    )

    # adhoc_scan_results table
    op.create_table(
        "adhoc_scan_results",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("scan_id", sa.String(length=36), nullable=False),
        sa.Column("uploaded_by", sa.Integer(), nullable=False),
        sa.Column("original_filename", sa.String(length=255), nullable=False),
        sa.Column("file_size", sa.Integer(), nullable=True),
        sa.Column("content_type", sa.String(length=128), nullable=True),
        sa.Column("detected_file_type", sa.String(length=64), nullable=True),
        sa.Column("scan_status", sa.String(length=20), nullable=True),
        sa.Column("is_malware", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("is_pup", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("is_threat", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column(
            "threat_names",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("file_md5", sa.String(length=32), nullable=True),
        sa.Column("file_sha1", sa.String(length=40), nullable=True),
        sa.Column("file_sha256", sa.String(length=64), nullable=True),
        sa.Column(
            "clamav_result",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "yara_matches",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "ti_enrichment",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("sandbox_submitted", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column(
            "sandbox_result",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("scan_duration_ms", sa.Integer(), nullable=True),
        sa.Column(
            "uploaded_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("scanned_at", sa.DateTime(), nullable=True),
        sa.Column("expires_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id"),
        sa.ForeignKeyConstraint(["uploaded_by"], ["users.id"]),
    )

    # s3_scan_schedules table
    op.create_table(
        "s3_scan_schedules",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("bucket_config_id", sa.Integer(), nullable=False),
        sa.Column("cron_expression", sa.String(length=100), nullable=False),
        sa.Column(
            "timezone", sa.String(length=50), nullable=False, server_default="UTC"
        ),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("last_run_at", sa.DateTime(), nullable=True),
        sa.Column("next_run_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=True,
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("bucket_config_id"),
        sa.ForeignKeyConstraint(["bucket_config_id"], ["s3_bucket_configs.id"]),
    )

    # Indexes
    op.create_index("ix_threat_indicators_indicator_type", "threat_indicators", ["indicator_type"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])
    op.create_index("ix_edr_events_agent_id", "edr_events", ["agent_id"])
    op.create_index("ix_edr_events_event_type", "edr_events", ["event_type"])


def downgrade() -> None:
    """Drop all core manager tables in reverse order."""
    op.drop_index("ix_edr_events_event_type", table_name="edr_events")
    op.drop_index("ix_edr_events_agent_id", table_name="edr_events")
    op.drop_index("ix_audit_logs_created_at", table_name="audit_logs")
    op.drop_index("ix_audit_logs_event_type", table_name="audit_logs")
    op.drop_index("ix_alerts_severity", table_name="alerts")
    op.drop_index("ix_alerts_status", table_name="alerts")
    op.drop_index("ix_threat_indicators_indicator_type", table_name="threat_indicators")

    op.drop_table("s3_scan_schedules")
    op.drop_table("adhoc_scan_results")
    op.drop_table("s3_scan_results")
    op.drop_table("s3_scan_jobs")
    op.drop_table("s3_bucket_configs")
    op.drop_table("edr_events")
    op.drop_table("edr_agents")
    op.drop_table("audit_logs")
    op.drop_table("approval_requests")
    op.drop_table("alerts")
    op.drop_table("threat_indicators")
    op.drop_table("refresh_tokens")
    op.drop_table("users")
