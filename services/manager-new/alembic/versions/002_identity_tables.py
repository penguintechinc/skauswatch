"""Identity tables for Checkpoint sub-module.

Revision ID: 002
Revises: 001
Create Date: 2026-03-11

Adds 6 identity tables for the Checkpoint identity provider:
- identity_users: PII-centralized user records
- identity_groups: Groups/roles for RBAC
- identity_memberships: User-group membership
- identity_attributes: Extensible key/value attributes for users and groups
- identity_sessions: Active JWT session tracking
- identity_mfa_challenges: Pending MFA challenges
"""

from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, None] = None
depends_on: Union[str, None] = None


def upgrade() -> None:
    """Create all 6 identity tables."""

    # identity_users — PII lives here ONLY; all other tables reference by uuid
    op.create_table(
        "identity_users",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("given_name", sa.String(length=255), nullable=True),
        sa.Column("family_name", sa.String(length=255), nullable=True),
        sa.Column("phone", sa.String(length=50), nullable=True),
        sa.Column(
            "status",
            sa.String(length=20),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("password_hash", sa.Text(), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("mfa_secret_encrypted", sa.Text(), nullable=True),
        sa.Column("locale", sa.String(length=10), nullable=True),
        sa.Column("timezone", sa.String(length=64), nullable=True),
        sa.Column("avatar_url", sa.Text(), nullable=True),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("external_provider", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.Column("last_login_at", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("uuid"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_identity_users_email", "identity_users", ["email"])
    op.create_index("ix_identity_users_uuid", "identity_users", ["uuid"])
    op.create_index(
        "ix_identity_users_external",
        "identity_users",
        ["external_provider", "external_id"],
    )

    # identity_groups — groups and roles
    op.create_table(
        "identity_groups",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "type",
            sa.String(length=20),
            nullable=False,
            server_default="local",
        ),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("external_provider", sa.String(length=64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("uuid"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_identity_groups_uuid", "identity_groups", ["uuid"])
    op.create_index("ix_identity_groups_name", "identity_groups", ["name"])

    # identity_memberships — user-group membership (no PII)
    op.create_table(
        "identity_memberships",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("user_uuid", sa.String(length=36), nullable=False),
        sa.Column("group_uuid", sa.String(length=36), nullable=False),
        sa.Column(
            "role",
            sa.String(length=20),
            nullable=False,
            server_default="member",
        ),
        sa.Column("added_by_uuid", sa.String(length=36), nullable=True),
        sa.Column(
            "source",
            sa.String(length=20),
            nullable=False,
            server_default="local",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("uuid"),
        sa.UniqueConstraint("user_uuid", "group_uuid", name="uq_membership_user_group"),
    )
    op.create_index(
        "ix_identity_memberships_user_uuid",
        "identity_memberships",
        ["user_uuid"],
    )
    op.create_index(
        "ix_identity_memberships_group_uuid",
        "identity_memberships",
        ["group_uuid"],
    )

    # identity_attributes — extensible key/value attributes for users and groups (no PII)
    op.create_table(
        "identity_attributes",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("subject_uuid", sa.String(length=36), nullable=False),
        sa.Column(
            "subject_type",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column("key", sa.String(length=255), nullable=False),
        sa.Column("value", sa.Text(), nullable=True),
        sa.Column(
            "source",
            sa.String(length=20),
            nullable=False,
            server_default="local",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
            onupdate=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("uuid"),
        sa.UniqueConstraint(
            "subject_uuid",
            "subject_type",
            "key",
            name="uq_attribute_subject_key",
        ),
    )
    op.create_index(
        "ix_identity_attributes_subject",
        "identity_attributes",
        ["subject_uuid", "subject_type"],
    )

    # identity_sessions — active JWT session tracking (no PII; user_uuid ref only)
    op.create_table(
        "identity_sessions",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("user_uuid", sa.String(length=36), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=True),
        sa.Column(
            "issued_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("uuid"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index(
        "ix_identity_sessions_token_hash",
        "identity_sessions",
        ["token_hash"],
    )
    op.create_index(
        "ix_identity_sessions_user_uuid",
        "identity_sessions",
        ["user_uuid"],
    )
    op.create_index(
        "ix_identity_sessions_expires_at",
        "identity_sessions",
        ["expires_at"],
    )

    # identity_mfa_challenges — pending MFA challenges (no PII; user_uuid ref only)
    op.create_table(
        "identity_mfa_challenges",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("uuid", sa.String(length=36), nullable=False),
        sa.Column("user_uuid", sa.String(length=36), nullable=False),
        sa.Column(
            "type",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column("code_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(), nullable=False),
        sa.Column("used_at", sa.DateTime(), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("uuid"),
    )
    op.create_index(
        "ix_identity_mfa_challenges_user_uuid",
        "identity_mfa_challenges",
        ["user_uuid"],
    )
    op.create_index(
        "ix_identity_mfa_challenges_expires_at",
        "identity_mfa_challenges",
        ["expires_at"],
    )


def downgrade() -> None:
    """Drop all 6 identity tables in reverse order."""
    op.drop_table("identity_mfa_challenges")
    op.drop_table("identity_sessions")
    op.drop_table("identity_attributes")
    op.drop_table("identity_memberships")
    op.drop_table("identity_groups")
    op.drop_table("identity_users")
