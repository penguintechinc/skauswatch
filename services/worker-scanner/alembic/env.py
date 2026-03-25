"""Alembic migration environment configuration.

This module configures the Alembic environment for database migrations.
Per project standards:
- SQLAlchemy is used ONLY for schema definition and migrations
- PyDAL handles all runtime database operations
"""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = None

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def get_url() -> str:
    """Get database URL from environment variables.

    Returns:
        Database connection URL
    """
    # Check for DATABASE_URL environment variable first
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return database_url

    # Construct from individual environment variables
    db_type = os.getenv("DB_TYPE", "sqlite")
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME", "scanner")
    db_user = os.getenv("DB_USER", "scanner")
    db_password = os.getenv("DB_PASSWORD", "scanner")

    # Handle SQLite special case
    if db_type == "sqlite":
        db_path = os.getenv("DB_PATH", "data/scanner.db")
        return f"sqlite:///{db_path}"

    # Map DB_TYPE to SQLAlchemy dialects
    dialect_map = {
        "postgres": "postgresql",
        "postgresql": "postgresql",
        "mysql": "mysql+pymysql",
        "mariadb": "mysql+pymysql",
    }

    dialect = dialect_map.get(db_type, db_type)

    # Construct connection URL
    if db_password:
        return f"{dialect}://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
    else:
        return f"{dialect}://{db_user}@{db_host}:{db_port}/{db_name}"


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        version_table="alembic_version_scanner",
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    url = get_url()

    connectable = create_engine(
        url,
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
            version_table="alembic_version_scanner",
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
