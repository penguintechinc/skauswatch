"""Add issue_plans table and extend repo_configs

Revision ID: 001
Revises:
Create Date: 2025-02-07

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create issue_plans table
    op.create_table('issue_plans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('external_id', sa.String(length=128), nullable=False),
        sa.Column('platform', sa.String(length=64), nullable=False),
        sa.Column('repository', sa.String(length=255), nullable=False),
        sa.Column('issue_number', sa.Integer(), nullable=False),
        sa.Column('issue_url', sa.String(length=512), nullable=True),
        sa.Column('issue_title', sa.String(length=512), nullable=True),
        sa.Column('issue_body', sa.Text(), nullable=True),
        sa.Column('plan_content', sa.Text(), nullable=True),
        sa.Column('plan_steps', sa.JSON(), nullable=True),
        sa.Column('ai_provider', sa.String(length=64), nullable=True),
        sa.Column('ai_model', sa.String(length=128), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('comment_posted', sa.Boolean(), nullable=True),
        sa.Column('platform_comment_id', sa.String(length=128), nullable=True),
        sa.Column('token_usage', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('external_id')
    )

    # Add new columns to repo_configs
    op.add_column('repo_configs', sa.Column('auto_plan_on_issue', sa.Boolean(), nullable=True))
    op.add_column('repo_configs', sa.Column('issue_plan_provider', sa.String(length=64), nullable=True))
    op.add_column('repo_configs', sa.Column('issue_plan_model', sa.String(length=128), nullable=True))
    op.add_column('repo_configs', sa.Column('issue_plan_daily_limit', sa.Integer(), nullable=True))
    op.add_column('repo_configs', sa.Column('issue_plan_cost_limit_usd', sa.Integer(), nullable=True))


def downgrade() -> None:
    # Remove columns from repo_configs
    op.drop_column('repo_configs', 'issue_plan_cost_limit_usd')
    op.drop_column('repo_configs', 'issue_plan_daily_limit')
    op.drop_column('repo_configs', 'issue_plan_model')
    op.drop_column('repo_configs', 'issue_plan_provider')
    op.drop_column('repo_configs', 'auto_plan_on_issue')

    # Drop issue_plans table
    op.drop_table('issue_plans')
