"""SQLAlchemy-based database schema initialization.

This module handles database schema creation and migration using SQLAlchemy.
PyDAL is used only for runtime operations, not schema management.
"""

import logging
from sqlalchemy import create_engine, text, MetaData, Table, Column, UniqueConstraint
from sqlalchemy import Integer, String, Text, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func
from .config import Config

logger = logging.getLogger(__name__)


def get_sqlalchemy_engine():
    """Create SQLAlchemy engine from config.

    Supports PostgreSQL, MySQL, and MariaDB Galera.
    Converts PyDAL URI format to SQLAlchemy 2.0 format with explicit drivers.
    """
    db_uri = Config.get_db_uri()

    # Convert PyDAL URI format to SQLAlchemy 2.0 format with explicit drivers
    if db_uri.startswith("postgres://"):
        # PostgreSQL: postgres:// -> postgresql+psycopg2://
        db_uri = db_uri.replace("postgres://", "postgresql+psycopg2://", 1)
    elif db_uri.startswith("mysql://"):
        # MySQL/MariaDB: mysql:// -> mysql+pymysql://
        # Note: pymysql works for both MySQL and MariaDB Galera
        db_uri = db_uri.replace("mysql://", "mysql+pymysql://", 1)
    # SQLite already uses correct format: sqlite://

    return create_engine(db_uri, pool_pre_ping=True, echo=False)


def check_table_exists(engine, table_name):
    """Check if a table exists in the database."""
    with engine.connect() as conn:
        result = conn.execute(text(
            f"SELECT EXISTS (SELECT FROM information_schema.tables "
            f"WHERE table_name = '{table_name}')"
        ))
        return result.scalar()


def check_admin_user_exists(engine):
    """Check if admin@localhost.local user exists."""
    try:
        with engine.connect() as conn:
            # First check if users table exists
            if not check_table_exists(engine, 'users'):
                return False

            result = conn.execute(text(
                "SELECT COUNT(*) FROM users WHERE email = 'admin@localhost.local'"
            ))
            count = result.scalar()
            return count > 0
    except Exception as e:
        logger.warning(f"Error checking admin user: {e}")
        return False


def init_database_schema(app=None):
    """Initialize database schema using Alembic migrations.

    This function runs pending Alembic migrations on startup to ensure
    the database schema is up-to-date. If Alembic is not available (e.g.,
    in development), it falls back to create_all() using the table definitions.

    Args:
        app: Flask app instance (optional, for logging context)
    """
    logger.info("Starting database schema initialization with Alembic migrations")

    try:
        # Try to use Alembic migrations
        from alembic.config import Config as AlembicConfig
        from alembic import command
        import os

        # Get the directory of this file (app/)
        current_dir = os.path.dirname(os.path.abspath(__file__))
        # Go up to flask-backend directory
        backend_dir = os.path.dirname(current_dir)
        alembic_ini = os.path.join(backend_dir, 'alembic.ini')

        if os.path.exists(alembic_ini):
            logger.info(f"Found alembic.ini at {alembic_ini}")
            alembic_cfg = AlembicConfig(alembic_ini)
            # Run migrations to head
            command.upgrade(alembic_cfg, "head")
            logger.info("Database migrations completed successfully")
            return get_sqlalchemy_engine()
        else:
            logger.warning(
                f"alembic.ini not found at {alembic_ini}, "
                "falling back to create_all()"
            )
            return _create_all_fallback()

    except ImportError as e:
        logger.warning(
            f"Alembic not available ({e}), falling back to create_all()"
        )
        return _create_all_fallback()
    except Exception as e:
        logger.error(f"Database migration failed: {e}")
        if app and app.config.get("RELEASE_MODE", False):
            # In production, fail if migrations don't work
            raise
        else:
            # In development, fall back to create_all
            logger.warning("Continuing with create_all() fallback due to migration error")
            return _create_all_fallback()


def _create_all_fallback():
    """Fallback function using create_all() when Alembic is unavailable.

    This maintains backward compatibility for development environments.
    """
    logger.info("Using SQLAlchemy create_all() for schema initialization")

    engine = get_sqlalchemy_engine()
    metadata = MetaData()

    # Define all tables
    tenants = Table(
        'tenants', metadata,
        Column('id', Integer, primary_key=True),
        Column('name', String(255), unique=True, nullable=False),
        Column('slug', String(128), unique=True, nullable=False),
        Column('description', Text),
        Column('is_active', Boolean, default=True),
        Column('max_users', Integer, default=0),
        Column('max_repositories', Integer, default=0),
        Column('max_teams', Integer, default=0),
        Column('settings', JSON, default={}),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    users = Table(
        'users', metadata,
        Column('id', Integer, primary_key=True),
        Column('email', String(255), unique=True, nullable=False),
        Column('password_hash', String(255), nullable=False),
        Column('full_name', String(255)),
        Column('role', String(50), default='viewer'),
        Column('global_role', String(50), default='viewer'),
        Column('default_tenant_id', Integer, ForeignKey('tenants.id', ondelete='SET NULL')),
        Column('is_active', Boolean, default=True),
        Column('email_confirmed', Boolean, default=False),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    refresh_tokens = Table(
        'refresh_tokens', metadata,
        Column('id', Integer, primary_key=True),
        Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        Column('token', String(500), unique=True, nullable=False),
        Column('expires_at', DateTime(timezone=True), nullable=False),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
    )

    teams = Table(
        'teams', metadata,
        Column('id', Integer, primary_key=True),
        Column('tenant_id', Integer, ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        Column('name', String(255), nullable=False),
        Column('slug', String(128), nullable=False),
        Column('description', Text),
        Column('is_active', Boolean, default=True),
        Column('is_default', Boolean, default=False),
        Column('settings', JSON, default={}),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    custom_roles = Table(
        'custom_roles', metadata,
        Column('id', Integer, primary_key=True),
        Column('tenant_id', Integer, ForeignKey('tenants.id', ondelete='CASCADE')),
        Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE')),
        Column('name', String(128), nullable=False),
        Column('slug', String(128), nullable=False),
        Column('description', Text),
        Column('role_level', String(64)),
        Column('scopes', JSON, nullable=False),
        Column('is_active', Boolean, default=True),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    tenant_members = Table(
        'tenant_members', metadata,
        Column('id', Integer, primary_key=True),
        Column('tenant_id', Integer, ForeignKey('tenants.id', ondelete='CASCADE'), nullable=False),
        Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        Column('role', String(50), default='viewer'),
        Column('custom_role_id', Integer, ForeignKey('custom_roles.id', ondelete='SET NULL')),
        Column('scopes', JSON, default=[]),
        Column('is_active', Boolean, default=True),
        Column('joined_at', DateTime(timezone=True), server_default=func.now()),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    team_members = Table(
        'team_members', metadata,
        Column('id', Integer, primary_key=True),
        Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE'), nullable=False),
        Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        Column('role', String(50), default='viewer'),
        Column('custom_role_id', Integer, ForeignKey('custom_roles.id', ondelete='SET NULL')),
        Column('scopes', JSON, default=[]),
        Column('is_active', Boolean, default=True),
        Column('joined_at', DateTime(timezone=True), server_default=func.now()),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    scopes = Table(
        'scopes', metadata,
        Column('id', Integer, primary_key=True),
        Column('permission_scope', String(128), unique=True, nullable=False),
        Column('description', Text),
        Column('category', String(64)),
        Column('scope_level', String(64)),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
    )

    repo_configs = Table(
        'repo_configs', metadata,
        Column('id', Integer, primary_key=True),
        # Multi-tenancy fields
        Column('tenant_id', Integer, ForeignKey('tenants.id', ondelete='CASCADE')),
        Column('team_id', Integer, ForeignKey('teams.id', ondelete='CASCADE')),
        Column('owner_id', Integer, ForeignKey('users.id', ondelete='SET NULL')),
        # Repository identification
        Column('platform', String(64)),
        Column('repository', String(255), nullable=False),
        Column('enabled', Boolean, default=True),
        Column('auto_review', Boolean, default=True),
        Column('review_on_open', Boolean, default=True),
        Column('review_on_sync', Boolean, default=False),
        Column('default_categories', JSON),
        Column('default_ai_provider', String(64)),
        Column('ignored_paths', JSON),
        Column('custom_rules', JSON),
        Column('webhook_secret', String(255)),
        # Polling configuration
        Column('polling_enabled', Boolean, default=False),
        Column('polling_interval_minutes', Integer, default=5),
        Column('last_poll_at', DateTime(timezone=True)),
        # Organization grouping (for dashboard drill-down)
        Column('platform_organization', String(255)),
        # Display settings
        Column('display_name', String(255)),
        Column('description', Text),
        Column('is_active', Boolean, default=True),
        # Credential selection
        Column('credential_id', Integer, ForeignKey('git_credentials.id', ondelete='SET NULL')),
        # Advanced settings
        Column('max_review_age_hours', Integer, default=168),  # 7 days
        Column('skip_patterns', JSON),
        # Issue plan automation
        Column('auto_plan_on_issue', Boolean, default=False),
        Column('issue_plan_provider', String(64)),
        Column('issue_plan_model', String(128)),
        Column('issue_plan_daily_limit', Integer),
        Column('issue_plan_cost_limit_usd', Integer),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    reviews = Table(
        'reviews', metadata,
        Column('id', Integer, primary_key=True),
        Column('tenant_id', Integer, ForeignKey('tenants.id')),
        Column('team_id', Integer, ForeignKey('teams.id')),
        Column('triggered_by', Integer, ForeignKey('users.id')),
        Column('repo_id', Integer, ForeignKey('repo_configs.id', ondelete='CASCADE')),
        Column('pr_number', Integer),
        Column('pr_title', String(512)),
        Column('pr_url', String(512)),
        Column('commit_sha', String(64)),
        Column('status', String(50), default='pending'),
        Column('started_at', DateTime(timezone=True)),
        Column('completed_at', DateTime(timezone=True)),
        Column('summary', Text),
        Column('score', Integer),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    review_comments = Table(
        'review_comments', metadata,
        Column('id', Integer, primary_key=True),
        Column('review_id', Integer, ForeignKey('reviews.id', ondelete='CASCADE'), nullable=False),
        Column('file_path', String(512)),
        Column('line_number', Integer),
        Column('category', String(50)),
        Column('severity', String(20)),
        Column('message', Text),
        Column('suggestion', Text),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
    )

    git_credentials = Table(
        'git_credentials', metadata,
        Column('id', Integer, primary_key=True),
        Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE')),
        Column('platform', String(50), nullable=False),
        Column('credential_type', String(50), default='token'),
        Column('encrypted_token', Text),
        Column('token_expires_at', DateTime(timezone=True)),
        Column('is_active', Boolean, default=True),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    repository_members = Table(
        'repository_members', metadata,
        Column('id', Integer, primary_key=True),
        Column('repository_id', Integer, ForeignKey('repo_configs.id', ondelete='CASCADE')),
        Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE')),
        Column('role', String(50), default='viewer'),
        Column('custom_role_id', Integer, ForeignKey('custom_roles.id', ondelete='SET NULL')),
        Column('scopes', JSON, default=[]),
        Column('personal_token_id', Integer, ForeignKey('git_credentials.id', ondelete='SET NULL')),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    platform_identities = Table(
        'platform_identities', metadata,
        Column('id', Integer, primary_key=True),
        Column('user_id', Integer, ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        Column('platform', String(64), nullable=False),
        Column('platform_username', String(255), nullable=False),
        Column('platform_user_id', String(128)),
        Column('platform_avatar_url', String(512)),
        Column('is_verified', Boolean, default=False),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
        UniqueConstraint('platform', 'platform_username', name='uq_platform_identity'),
    )

    provider_usage = Table(
        'provider_usage', metadata,
        Column('id', Integer, primary_key=True),
        Column('review_id', Integer, ForeignKey('reviews.id')),
        Column('provider', String(64)),
        Column('model', String(128)),
        Column('prompt_tokens', Integer),
        Column('completion_tokens', Integer),
        Column('total_tokens', Integer),
        Column('latency_ms', Integer),
        Column('cost_estimate', Integer),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
    )

    issue_plans = Table(
        'issue_plans', metadata,
        Column('id', Integer, primary_key=True),
        Column('external_id', String(128), unique=True, nullable=False),
        Column('platform', String(64), nullable=False),
        Column('repository', String(255), nullable=False),
        Column('issue_number', Integer, nullable=False),
        Column('issue_url', String(512)),
        Column('issue_title', String(512)),
        Column('issue_body', Text),
        Column('plan_content', Text),
        Column('plan_steps', JSON),
        Column('ai_provider', String(64)),
        Column('ai_model', String(128)),
        Column('status', String(50), default='queued'),
        Column('error_message', Text),
        Column('comment_posted', Boolean, default=False),
        Column('platform_comment_id', String(128)),
        Column('token_usage', JSON),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    ai_model_config = Table(
        'ai_model_config', metadata,
        Column('id', Integer, primary_key=True),
        Column('category', String(64), unique=True, nullable=False),
        Column('provider', String(64), nullable=False),
        Column('model_name', String(128), nullable=False),
        Column('is_active', Boolean, default=True),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    installation_config = Table(
        'installation_config', metadata,
        Column('id', Integer, primary_key=True),
        Column('config_key', String(128), unique=True, nullable=False),
        Column('config_value', Text),
        Column('created_at', DateTime(timezone=True), server_default=func.now()),
        Column('updated_at', DateTime(timezone=True), server_default=func.now(), onupdate=func.now()),
    )

    # Create all tables
    logger.info("Creating database tables with SQLAlchemy create_all()...")
    metadata.create_all(engine)
    logger.info("Database schema initialization complete")

    return engine
