"""Darwin initial schema.

Revision ID: 001_darwin_initial_schema
Revises: (none)
Create Date: 2026-03-06

Creates all darwin_* tables. Run with: alembic upgrade head
NEVER run automatically at app startup — always operator/Job action.
"""

from alembic import op
import sqlalchemy as sa

revision = "001_darwin_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create all darwin_* tables."""

    op.create_table(
        "darwin_tenants",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("plan", sa.String(50), server_default="free", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "darwin_users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("darwin_tenants.id"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(50), server_default="viewer", nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("TRUE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_darwin_users_email", "darwin_users", ["email"], unique=True)

    op.create_table(
        "darwin_repo_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("darwin_tenants.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),  # github | gitlab
        sa.Column("repo_url", sa.String(512), nullable=False),
        sa.Column("repo_name", sa.String(255), nullable=False),
        sa.Column("webhook_secret", sa.String(255), nullable=True),
        sa.Column("auto_review", sa.Boolean(), server_default=sa.text("TRUE"), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("TRUE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "darwin_git_credentials",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("darwin_tenants.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("token_encrypted", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "darwin_reviews",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("repo_config_id", sa.Integer(), sa.ForeignKey("darwin_repo_configs.id"), nullable=False),
        sa.Column("pr_number", sa.Integer(), nullable=True),
        sa.Column("pr_url", sa.String(512), nullable=True),
        sa.Column("status", sa.String(50), server_default="pending", nullable=False),
        sa.Column("ai_provider", sa.String(50), nullable=True),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_darwin_reviews_repo_config_id", "darwin_reviews", ["repo_config_id"])
    op.create_index("ix_darwin_reviews_status", "darwin_reviews", ["status"])

    op.create_table(
        "darwin_review_comments",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("review_id", sa.Integer(), sa.ForeignKey("darwin_reviews.id"), nullable=False),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=True),
        sa.Column("comment", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "darwin_review_detections",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("review_id", sa.Integer(), sa.ForeignKey("darwin_reviews.id"), nullable=False),
        sa.Column("detection_type", sa.String(100), nullable=False),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "darwin_issue_plans",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("repo_config_id", sa.Integer(), sa.ForeignKey("darwin_repo_configs.id"), nullable=False),
        sa.Column("issue_number", sa.Integer(), nullable=False),
        sa.Column("issue_url", sa.String(512), nullable=True),
        sa.Column("plan_content", sa.Text(), nullable=True),
        sa.Column("ai_provider", sa.String(50), nullable=True),
        sa.Column("status", sa.String(50), server_default="pending", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("ix_darwin_issue_plans_repo_config_id", "darwin_issue_plans", ["repo_config_id"])

    op.create_table(
        "darwin_provider_usage",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("tenant_id", sa.Integer(), sa.ForeignKey("darwin_tenants.id"), nullable=False),
        sa.Column("provider", sa.String(50), nullable=False),
        sa.Column("model", sa.String(100), nullable=True),
        sa.Column("tokens_in", sa.Integer(), server_default="0", nullable=False),
        sa.Column("tokens_out", sa.Integer(), server_default="0", nullable=False),
        sa.Column("cost_usd", sa.Numeric(10, 6), server_default="0", nullable=False),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "darwin_license_policies",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("repo_config_id", sa.Integer(), sa.ForeignKey("darwin_repo_configs.id"), nullable=False),
        sa.Column("allowed_spdx", sa.Text(), nullable=True),
        sa.Column("denied_spdx", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "darwin_license_detections",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("review_id", sa.Integer(), sa.ForeignKey("darwin_reviews.id"), nullable=False),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("spdx_id", sa.String(100), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    op.create_table(
        "darwin_license_violations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("review_id", sa.Integer(), sa.ForeignKey("darwin_reviews.id"), nullable=False),
        sa.Column("file_path", sa.String(512), nullable=False),
        sa.Column("spdx_id", sa.String(100), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )


def downgrade() -> None:
    """Drop all darwin_* tables in reverse dependency order."""
    op.drop_table("darwin_license_violations")
    op.drop_table("darwin_license_detections")
    op.drop_table("darwin_license_policies")
    op.drop_table("darwin_provider_usage")
    op.drop_table("darwin_issue_plans")
    op.drop_table("darwin_review_detections")
    op.drop_table("darwin_review_comments")
    op.drop_table("darwin_reviews")
    op.drop_table("darwin_git_credentials")
    op.drop_table("darwin_repo_configs")
    op.drop_table("darwin_users")
    op.drop_table("darwin_tenants")
