"""checkpoint initial schema — all 8 protocol tables.

Revision ID: 001
Revises: (none)
Create Date: 2025-01-01 00:00:00
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    # ── checkpoint_oauth_clients ──────────────────────────────────────────────
    op.create_table(
        "checkpoint_oauth_clients",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("client_id", sa.String(128), nullable=False, unique=True),
        sa.Column("client_secret_hash", sa.String(256)),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text()),
        sa.Column("redirect_uris", sa.Text(), nullable=False),
        sa.Column("allowed_scopes", sa.Text(), nullable=False),
        sa.Column("grant_types", sa.Text(), nullable=False),
        sa.Column("require_pkce", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_by_uuid", sa.String(36)),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
    )
    op.create_index(
        "ix_checkpoint_oauth_clients_client_id",
        "checkpoint_oauth_clients",
        ["client_id"],
    )

    # ── checkpoint_saml_providers ─────────────────────────────────────────────
    op.create_table(
        "checkpoint_saml_providers",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("entity_id", sa.String(512), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("acs_url", sa.String(512), nullable=False),
        sa.Column("metadata_url", sa.String(512)),
        sa.Column("signing_cert", sa.Text()),
        sa.Column("signing_key", sa.Text()),
        sa.Column("encryption_cert", sa.Text()),
        sa.Column(
            "name_id_format",
            sa.String(256),
            server_default="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        ),
        sa.Column("attribute_mapping", sa.Text()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime()),
    )
    op.create_index(
        "ix_checkpoint_saml_providers_entity_id",
        "checkpoint_saml_providers",
        ["entity_id"],
    )

    # ── checkpoint_upstream_idps ──────────────────────────────────────────────
    op.create_table(
        "checkpoint_upstream_idps",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("federation_mode", sa.String(16), nullable=False, server_default="sync"),
        sa.Column("sync_interval_secs", sa.Integer(), server_default="3600"),
        sa.Column("config_json_encrypted", sa.Text()),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("last_sync_at", sa.DateTime()),
        sa.Column("sync_error", sa.Text()),
        sa.Column("created_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
    )

    # ── checkpoint_tokens ─────────────────────────────────────────────────────
    op.create_table(
        "checkpoint_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("jti", sa.String(128), nullable=False, unique=True),
        sa.Column("token_hash", sa.String(64)),
        sa.Column("user_uuid", sa.String(36)),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("scopes", sa.Text()),
        sa.Column("token_type", sa.String(16), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime()),
        sa.Column("issued_at", sa.DateTime(), nullable=False),
        sa.Column("ip_address", sa.String(45)),
    )
    op.create_index("ix_checkpoint_tokens_jti", "checkpoint_tokens", ["jti"])
    op.create_index(
        "ix_checkpoint_tokens_user_uuid",
        "checkpoint_tokens",
        ["user_uuid"],
    )
    op.create_index(
        "ix_checkpoint_tokens_expires_at",
        "checkpoint_tokens",
        ["expires_at"],
    )

    # ── checkpoint_auth_codes ─────────────────────────────────────────────────
    op.create_table(
        "checkpoint_auth_codes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("code_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("user_uuid", sa.String(36), nullable=False),
        sa.Column("client_id", sa.String(128), nullable=False),
        sa.Column("redirect_uri", sa.String(512), nullable=False),
        sa.Column("scopes", sa.Text()),
        sa.Column("pkce_challenge", sa.String(128)),
        sa.Column("pkce_method", sa.String(8)),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime()),
        sa.Column("ip_address", sa.String(45)),
    )
    op.create_index(
        "ix_checkpoint_auth_codes_code_hash",
        "checkpoint_auth_codes",
        ["code_hash"],
    )

    # ── checkpoint_signing_keys ───────────────────────────────────────────────
    op.create_table(
        "checkpoint_signing_keys",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("kid", sa.String(128), nullable=False, unique=True),
        sa.Column("algorithm", sa.String(16), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("private_key_encrypted", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("grace_period_until", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime()),
    )
    op.create_index(
        "ix_checkpoint_signing_keys_kid",
        "checkpoint_signing_keys",
        ["kid"],
    )

    # ── checkpoint_audit_log ──────────────────────────────────────────────────
    op.create_table(
        "checkpoint_audit_log",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("actor_uuid", sa.String(36)),
        sa.Column("actor_ip", sa.String(45)),
        sa.Column("target_uuid", sa.String(36)),
        sa.Column("target_type", sa.String(64)),
        sa.Column("client_id", sa.String(128)),
        sa.Column("scopes", sa.Text()),
        sa.Column("details_json", sa.Text()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index(
        "ix_checkpoint_audit_log_created_at",
        "checkpoint_audit_log",
        ["created_at"],
    )
    op.create_index(
        "ix_checkpoint_audit_log_actor_uuid",
        "checkpoint_audit_log",
        ["actor_uuid"],
    )
    op.create_index(
        "ix_checkpoint_audit_log_event_type",
        "checkpoint_audit_log",
        ["event_type"],
    )

    # ── checkpoint_scim_tokens ────────────────────────────────────────────────
    op.create_table(
        "checkpoint_scim_tokens",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("scopes", sa.Text()),
        sa.Column("created_by_uuid", sa.String(36)),
        sa.Column("expires_at", sa.DateTime()),
        sa.Column("revoked_at", sa.DateTime()),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("checkpoint_scim_tokens")
    op.drop_table("checkpoint_audit_log")
    op.drop_table("checkpoint_signing_keys")
    op.drop_table("checkpoint_auth_codes")
    op.drop_table("checkpoint_tokens")
    op.drop_table("checkpoint_upstream_idps")
    op.drop_table("checkpoint_saml_providers")
    op.drop_table("checkpoint_oauth_clients")
