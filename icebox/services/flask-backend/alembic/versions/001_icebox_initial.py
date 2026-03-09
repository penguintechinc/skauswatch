"""IceBox initial schema

Revision ID: 001
Revises: None
Create Date: 2026-03-06

Creates all IceBox tables:
    - secrets, secret_owners, secret_versions, secret_policies
    - jit_access_requests, jit_access_grants
    - one_time_secrets
    - cloud_integrations, cloud_sync_state
    - audit_log
    - icebox_license

Per project standards:
- SQLAlchemy is used ONLY for schema definition and migrations
- PyDAL handles all runtime database operations (migrate=False)
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all IceBox tables."""

    # secrets — core secrets table with envelope encryption columns
    op.create_table(
        "icebox_secrets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column(
            "secret_type",
            sa.String(50),
            nullable=False,
            server_default="api_key",
            comment=(
                "api_key | db_password | token | cloud_credential | "
                "service_account | certificate | ssh_key | one_time"
            ),
        ),
        sa.Column("encrypted_value", sa.Text, nullable=False),
        sa.Column("encrypted_dek", sa.Text, nullable=False),
        sa.Column("dek_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("cloud_kms_ref", sa.String(1024), nullable=True),
        sa.Column("tags", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True),
        sa.Column(
            "secret_metadata",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("expires_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Column("created_by", sa.String(255), nullable=True),
    )
    op.create_index("idx_icebox_secrets_name", "icebox_secrets", ["name"])
    op.create_index("idx_icebox_secrets_type", "icebox_secrets", ["secret_type"])

    # secret_owners — multi-owner: user OR team per secret
    op.create_table(
        "icebox_secret_owners",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "secret_id",
            sa.String(36),
            sa.ForeignKey("icebox_secrets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "owner_type",
            sa.String(20),
            nullable=False,
            comment="user | team",
        ),
        sa.Column("owner_id", sa.String(255), nullable=False),
    )
    op.create_index(
        "idx_icebox_owners_secret", "icebox_secret_owners", ["secret_id"]
    )
    op.create_index(
        "idx_icebox_owners_owner", "icebox_secret_owners", ["owner_type", "owner_id"]
    )

    # secret_versions — full value history (never deleted)
    op.create_table(
        "icebox_secret_versions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "secret_id",
            sa.String(36),
            sa.ForeignKey("icebox_secrets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer, nullable=False, server_default="1"),
        sa.Column("encrypted_value", sa.Text, nullable=False),
        sa.Column("encrypted_dek", sa.Text, nullable=False),
        sa.Column("dek_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deprecated_at", sa.DateTime, nullable=True),
    )
    op.create_index(
        "idx_icebox_versions_secret", "icebox_secret_versions", ["secret_id"]
    )
    op.create_unique_constraint(
        "uq_secret_version",
        "icebox_secret_versions",
        ["secret_id", "version_number"],
    )

    # secret_policies — OIDC-scoped per-resource access control
    op.create_table(
        "icebox_secret_policies",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "secret_id",
            sa.String(36),
            sa.ForeignKey("icebox_secrets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "operation",
            sa.String(50),
            nullable=False,
            comment="read | write | delete | jit_request | jit_approve",
        ),
        sa.Column("required_scope", sa.String(100), nullable=False),
        sa.Column("required_role", sa.String(100), nullable=True),
    )
    op.create_index(
        "idx_icebox_policies_secret", "icebox_secret_policies", ["secret_id"]
    )

    # jit_access_requests
    op.create_table(
        "icebox_jit_requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "secret_id",
            sa.String(36),
            sa.ForeignKey("icebox_secrets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("requestor_id", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("requested_duration_seconds", sa.Integer, nullable=False),
        sa.Column("approved_duration_seconds", sa.Integer, nullable=True),
        sa.Column(
            "status",
            sa.String(20),
            nullable=False,
            server_default="pending",
            comment="pending | approved | rejected | expired | revoked",
        ),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime, nullable=True),
        sa.Column("access_expires_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "idx_icebox_jit_requests_secret", "icebox_jit_requests", ["secret_id"]
    )
    op.create_index(
        "idx_icebox_jit_requests_status", "icebox_jit_requests", ["status"]
    )
    op.create_index(
        "idx_icebox_jit_requests_requestor",
        "icebox_jit_requests",
        ["requestor_id"],
    )

    # jit_access_grants
    op.create_table(
        "icebox_jit_grants",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "request_id",
            sa.String(36),
            sa.ForeignKey("icebox_jit_requests.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "secret_id",
            sa.String(36),
            sa.ForeignKey("icebox_secrets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("grantee_id", sa.String(255), nullable=False),
        sa.Column("access_token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("revoked_at", sa.DateTime, nullable=True),
    )
    op.create_index(
        "idx_icebox_jit_grants_token", "icebox_jit_grants", ["access_token_hash"]
    )
    op.create_index(
        "idx_icebox_jit_grants_expires", "icebox_jit_grants", ["expires_at"]
    )

    # one_time_secrets
    op.create_table(
        "icebox_one_time_secrets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "token_hash",
            sa.String(64),
            nullable=False,
            unique=True,
            comment="SHA-256 of URL token",
        ),
        sa.Column("encrypted_value", sa.Text, nullable=False),
        sa.Column("encrypted_dek", sa.Text, nullable=False),
        sa.Column("dek_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("viewed_at", sa.DateTime, nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("created_by", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "idx_icebox_ots_token", "icebox_one_time_secrets", ["token_hash"]
    )

    # cloud_integrations
    op.create_table(
        "icebox_cloud_integrations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "provider",
            sa.String(20),
            nullable=False,
            comment="aws | azure | gcp | oracle | kubernetes",
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column(
            "sync_direction",
            sa.String(30),
            nullable=False,
            server_default="icebox_to_cloud",
            comment="icebox_to_cloud | cloud_to_icebox | bidirectional",
        ),
        sa.Column(
            "sync_scopes",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column("encrypted_credentials", sa.Text, nullable=True),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default="1"),
        sa.Column(
            "config", sa.JSON().with_variant(sa.Text(), "sqlite"), nullable=True
        ),
        sa.Column("last_sync_at", sa.DateTime, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "idx_icebox_integrations_provider",
        "icebox_cloud_integrations",
        ["provider"],
    )

    # cloud_sync_state
    op.create_table(
        "icebox_cloud_sync_state",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "secret_id",
            sa.String(36),
            sa.ForeignKey("icebox_secrets.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "integration_id",
            sa.String(36),
            sa.ForeignKey("icebox_cloud_integrations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "external_ref",
            sa.String(1024),
            nullable=True,
            comment="ARN / resource ID / K8s secret name",
        ),
        sa.Column("last_synced_at", sa.DateTime, nullable=True),
        sa.Column("sync_status", sa.String(50), nullable=True),
        sa.Column(
            "conflict_resolution",
            sa.String(20),
            nullable=False,
            server_default="icebox_wins",
            comment="icebox_wins | cloud_wins | manual",
        ),
    )
    op.create_unique_constraint(
        "uq_sync_state",
        "icebox_cloud_sync_state",
        ["secret_id", "integration_id"],
    )

    # audit_log
    op.create_table(
        "icebox_audit_log",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_id", sa.String(255), nullable=False),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("resource_type", sa.String(50), nullable=False),
        sa.Column("resource_id", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("user_agent", sa.String(512), nullable=True),
        sa.Column(
            "log_metadata",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime,
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "idx_icebox_audit_actor", "icebox_audit_log", ["actor_id"]
    )
    op.create_index(
        "idx_icebox_audit_resource",
        "icebox_audit_log",
        ["resource_type", "resource_id"],
    )
    op.create_index(
        "idx_icebox_audit_created", "icebox_audit_log", ["created_at"]
    )

    # icebox_license
    op.create_table(
        "icebox_license",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("license_key_encrypted", sa.Text, nullable=False),
        sa.Column("validated_at", sa.DateTime, nullable=True),
        sa.Column(
            "entitlements",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
        sa.Column(
            "license_server_url",
            sa.String(512),
            nullable=False,
            server_default="https://license.penguintech.io",
        ),
        sa.Column(
            "auto_bypass_domains",
            sa.JSON().with_variant(sa.Text(), "sqlite"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Drop all IceBox tables in reverse dependency order."""
    op.drop_table("icebox_license")
    op.drop_table("icebox_audit_log")
    op.drop_table("icebox_cloud_sync_state")
    op.drop_table("icebox_cloud_integrations")
    op.drop_table("icebox_one_time_secrets")
    op.drop_table("icebox_jit_grants")
    op.drop_table("icebox_jit_requests")
    op.drop_table("icebox_secret_policies")
    op.drop_table("icebox_secret_versions")
    op.drop_table("icebox_secret_owners")
    op.drop_table("icebox_secrets")
