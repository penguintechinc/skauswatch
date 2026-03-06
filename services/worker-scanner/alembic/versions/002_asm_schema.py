"""ASM (Attack Surface Management) schema

Revision ID: 002
Revises: 001
Create Date: 2026-03-03

This migration creates the ASM database schema for attack surface management.
Per project standards:
- SQLAlchemy is used ONLY for schema definition and migrations
- PyDAL handles all runtime database operations
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all ASM tables and indexes."""

    # Create asm_scans table
    op.create_table(
        "asm_scans",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("target_id", sa.Integer(), nullable=False),
        sa.Column("mode", sa.String(length=20), nullable=False, server_default="external"),
        sa.Column("status", sa.String(length=50), nullable=False, server_default="pending"),
        sa.Column("ports_config", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column("started_at", sa.DateTime(), nullable=True),
        sa.Column("completed_at", sa.DateTime(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(["target_id"], ["scan_targets.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_asm_scans_target_id", "asm_scans", ["target_id"])
    op.create_index("idx_asm_scans_status", "asm_scans", ["status"])

    # Create asm_hosts table
    op.create_table(
        "asm_hosts",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("is_alive", sa.Boolean(), nullable=False, server_default="1"),
        sa.Column("latency_ms", sa.Float(), nullable=True),
        sa.Column("os_guess", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["scan_id"], ["asm_scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_asm_hosts_scan_id", "asm_hosts", ["scan_id"])
    op.create_index("idx_asm_hosts_ip", "asm_hosts", ["ip_address"])

    # Create asm_services table
    op.create_table(
        "asm_services",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("protocol", sa.String(length=10), nullable=False, server_default="tcp"),
        sa.Column("state", sa.String(length=20), nullable=False, server_default="open"),
        sa.Column("service_name", sa.String(length=100), nullable=True),
        sa.Column("banner", sa.Text(), nullable=True),
        sa.Column("version", sa.String(length=255), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["host_id"], ["asm_hosts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_asm_services_host_id", "asm_services", ["host_id"])
    op.create_index("idx_asm_services_port", "asm_services", ["port"])

    # Create asm_screenshots table
    op.create_table(
        "asm_screenshots",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("service_id", sa.Integer(), nullable=False),
        sa.Column("s3_key", sa.String(length=1024), nullable=False),
        sa.Column("url", sa.String(length=2048), nullable=True),
        sa.Column("tool", sa.String(length=50), nullable=False),
        sa.Column("width", sa.Integer(), nullable=True),
        sa.Column("height", sa.Integer(), nullable=True),
        sa.Column("file_size_bytes", sa.Integer(), nullable=True),
        sa.Column("captured_at", sa.DateTime(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["service_id"], ["asm_services.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_asm_screenshots_service_id", "asm_screenshots", ["service_id"])

    # Create asm_certs table
    op.create_table(
        "asm_certs",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("service_id", sa.Integer(), nullable=False),
        sa.Column("subject", sa.String(length=512), nullable=True),
        sa.Column("issuer", sa.String(length=512), nullable=True),
        sa.Column("not_before", sa.DateTime(), nullable=True),
        sa.Column("not_after", sa.DateTime(), nullable=True),
        sa.Column("is_expired", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("days_until_expiry", sa.Integer(), nullable=True),
        sa.Column("sans", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column("fingerprint_sha256", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["service_id"], ["asm_services.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_asm_certs_service_id", "asm_certs", ["service_id"])
    op.create_index("idx_asm_certs_expiry", "asm_certs", ["is_expired", "days_until_expiry"])

    # Create asm_diffs table
    op.create_table(
        "asm_diffs",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("prev_scan_id", sa.Integer(), nullable=True),
        sa.Column("new_services", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column("removed_services", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column("new_certs", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column("expired_certs", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["scan_id"], ["asm_scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["prev_scan_id"], ["asm_scans.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("idx_asm_diffs_scan_id", "asm_diffs", ["scan_id"])

    # Create asm_settings table for port config persistence
    op.create_table(
        "asm_settings",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("key", sa.String(length=255), nullable=False, unique=True),
        sa.Column("value", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=False, server_default=sa.func.now(),
                  onupdate=sa.func.now()),
        sa.Column("updated_by", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    """Drop all ASM tables in reverse dependency order."""
    op.drop_table("asm_settings")
    op.drop_index("idx_asm_diffs_scan_id", table_name="asm_diffs")
    op.drop_table("asm_diffs")
    op.drop_index("idx_asm_certs_expiry", table_name="asm_certs")
    op.drop_index("idx_asm_certs_service_id", table_name="asm_certs")
    op.drop_table("asm_certs")
    op.drop_index("idx_asm_screenshots_service_id", table_name="asm_screenshots")
    op.drop_table("asm_screenshots")
    op.drop_index("idx_asm_services_port", table_name="asm_services")
    op.drop_index("idx_asm_services_host_id", table_name="asm_services")
    op.drop_table("asm_services")
    op.drop_index("idx_asm_hosts_ip", table_name="asm_hosts")
    op.drop_index("idx_asm_hosts_scan_id", table_name="asm_hosts")
    op.drop_table("asm_hosts")
    op.drop_index("idx_asm_scans_status", table_name="asm_scans")
    op.drop_index("idx_asm_scans_target_id", table_name="asm_scans")
    op.drop_table("asm_scans")
