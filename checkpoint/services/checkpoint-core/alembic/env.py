"""
Alembic environment for checkpoint-core.

DB URL is read from CHECKPOINT_DB_* env vars at runtime, overriding alembic.ini.
"""
from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# ── Alembic Config object ─────────────────────────────────────────────────────
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Override sqlalchemy.url from environment ──────────────────────────────────
def _build_db_url() -> str:
    db_type = os.environ.get("CHECKPOINT_DB_TYPE", "postgresql")
    db_user = os.environ.get("CHECKPOINT_DB_USER", "checkpoint-rw")
    db_pass = os.environ.get("CHECKPOINT_DB_PASS", "")
    db_host = os.environ.get("CHECKPOINT_DB_HOST", "localhost")
    db_port = os.environ.get("CHECKPOINT_DB_PORT", "5432")
    db_name = os.environ.get("CHECKPOINT_DB_NAME", "skauswatch")
    return f"{db_type}://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"


config.set_main_option("sqlalchemy.url", _build_db_url())

# target_metadata = None — we use raw op.create_table() in migrations
target_metadata = None


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (without a live DB connection)."""
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
    """Run migrations in 'online' mode (with a live DB connection)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
