"""Initial scanner schema

Revision ID: 001
Revises:
Create Date: 2026-01-29

This migration creates the core scanner database schema.
Per project standards:
- SQLAlchemy is used ONLY for schema definition and migrations
- PyDAL handles all runtime database operations
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql, mysql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create all scanner tables and indexes."""

    # Create scan_targets table
    op.create_table(
        'scan_targets',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_value', sa.String(length=2048), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('tags', sa.JSON().with_variant(sa.Text(), 'sqlite'), nullable=True),
        sa.Column('scan_metadata', sa.JSON().with_variant(sa.Text(), 'sqlite'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.Column('created_by', sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )

    # Create scan_jobs table
    op.create_table(
        'scan_jobs',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('scanner_type', sa.String(length=50), nullable=False),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='pending'),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('config', sa.JSON().with_variant(sa.Text(), 'sqlite'), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('duration_seconds', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('result_summary', sa.JSON().with_variant(sa.Text(), 'sqlite'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['target_id'], ['scan_targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for scan_jobs
    op.create_index('idx_scan_jobs_target_status', 'scan_jobs', ['target_id', 'status'])
    op.create_index('idx_scan_jobs_scanner_type', 'scan_jobs', ['scanner_type'])
    op.create_index('idx_scan_jobs_status', 'scan_jobs', ['status'])

    # Create scan_findings table
    op.create_table(
        'scan_findings',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('job_id', sa.Integer(), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('finding_id', sa.String(length=512), nullable=True),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=1024), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('remediation', sa.Text(), nullable=True),
        sa.Column('affected_url', sa.String(length=2048), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cve_ids', sa.JSON().with_variant(sa.Text(), 'sqlite'), nullable=True),
        sa.Column('cwe_ids', sa.JSON().with_variant(sa.Text(), 'sqlite'), nullable=True),
        sa.Column('evidence', sa.Text(), nullable=True),
        sa.Column('raw_finding', sa.JSON().with_variant(sa.Text(), 'sqlite'), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='open'),
        sa.Column('discovered_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now(), onupdate=sa.func.now()),
        sa.ForeignKeyConstraint(['job_id'], ['scan_jobs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['scan_targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for scan_findings
    op.create_index('idx_scan_findings_job_id', 'scan_findings', ['job_id'])
    op.create_index('idx_scan_findings_target_id', 'scan_findings', ['target_id'])
    op.create_index('idx_scan_findings_severity', 'scan_findings', ['severity'])
    op.create_index('idx_scan_findings_status', 'scan_findings', ['status'])

    # Create scan_schedules table
    op.create_table(
        'scan_schedules',
        sa.Column('id', sa.Integer(), nullable=False, autoincrement=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('scanner_type', sa.String(length=50), nullable=False),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('cron_expression', sa.String(length=255), nullable=False),
        sa.Column('config', sa.JSON().with_variant(sa.Text(), 'sqlite'), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('last_run', sa.DateTime(), nullable=True),
        sa.Column('next_run', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('created_by', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['target_id'], ['scan_targets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # Create indexes for scan_schedules
    op.create_index('idx_scan_schedules_enabled_next_run', 'scan_schedules', ['enabled', 'next_run'])


def downgrade() -> None:
    """Drop all scanner tables in reverse dependency order."""

    # Drop scan_schedules table
    op.drop_index('idx_scan_schedules_enabled_next_run', table_name='scan_schedules')
    op.drop_table('scan_schedules')

    # Drop scan_findings table
    op.drop_index('idx_scan_findings_status', table_name='scan_findings')
    op.drop_index('idx_scan_findings_severity', table_name='scan_findings')
    op.drop_index('idx_scan_findings_target_id', table_name='scan_findings')
    op.drop_index('idx_scan_findings_job_id', table_name='scan_findings')
    op.drop_table('scan_findings')

    # Drop scan_jobs table
    op.drop_index('idx_scan_jobs_status', table_name='scan_jobs')
    op.drop_index('idx_scan_jobs_scanner_type', table_name='scan_jobs')
    op.drop_index('idx_scan_jobs_target_status', table_name='scan_jobs')
    op.drop_table('scan_jobs')

    # Drop scan_targets table
    op.drop_table('scan_targets')
