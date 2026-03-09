"""Alembic environment configuration for worker-darwin.

Alembic is the ONLY mechanism for schema changes. PyDAL is configured with
migrate=False and must never issue DDL.

Run manually: alembic upgrade head
              alembic current
              alembic history
              alembic downgrade -1
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Add the service root to the path so we can import settings
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import settings  # noqa: E402

# Alembic Config object
config = context.config

# Configure logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Set the SQLAlchemy URL from settings
target_metadata = None

# Build SQLAlchemy URL (note: different format from PyDAL URI)
db_type = settings.database.type.lower()
if db_type in ("postgres", "postgresql"):
    driver = "postgresql+psycopg2"
elif db_type in ("mysql", "mariadb"):
    driver = "mysql+mysqlconnector"
elif db_type == "sqlite":
    driver = "sqlite"
else:
    driver = "postgresql+psycopg2"

if db_type == "sqlite":
    url = f"sqlite:///{settings.database.name}.db"
else:
    url = (
        f"{driver}://{settings.database.user}:{settings.database.password}"
        f"@{settings.database.host}:{settings.database.port}/{settings.database.name}"
    )

config.set_main_option("sqlalchemy.url", url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (no DB connection needed)."""
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (requires DB connection)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
