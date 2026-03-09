"""Alembic migration environment configuration.

This module sets up the Alembic environment for database migrations.
It handles both offline (SQL mode) and online (connection) modes.
"""

from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool, MetaData
from alembic import context
import sys
import os
import logging

# Add parent directory to path to import app modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Configure logging
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger(__name__)


def get_alembic_engine():
    """Get SQLAlchemy engine for migrations.

    Imports config from app and converts PyDAL URI format to SQLAlchemy format.
    """
    try:
        from app.config import Config
        from app.db_schema import get_sqlalchemy_engine

        # Get engine from db_schema (handles URI conversion)
        return get_sqlalchemy_engine()
    except Exception as e:
        logger.error(f"Error getting SQLAlchemy engine: {e}")
        raise


def set_sqlalchemy_url():
    """Set the SQLAlchemy URL in alembic config."""
    try:
        from app.config import Config
        db_uri = Config.get_db_uri()

        # Convert PyDAL URI format to SQLAlchemy 2.0 format with explicit drivers
        if db_uri.startswith("postgres://"):
            db_uri = db_uri.replace("postgres://", "postgresql+psycopg2://", 1)
        elif db_uri.startswith("mysql://"):
            db_uri = db_uri.replace("mysql://", "mysql+pymysql://", 1)

        config.set_main_option("sqlalchemy.url", db_uri)
        logger.info(f"SQLAlchemy URL set from app config: {db_uri[:50]}...")
    except Exception as e:
        logger.error(f"Error setting SQLAlchemy URL: {e}")
        raise


# Set the SQLAlchemy URL
set_sqlalchemy_url()

# Target metadata for migrations
target_metadata = MetaData()


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = get_alembic_engine()

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
