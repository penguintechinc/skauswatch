"""Alembic environment configuration."""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.schema import Base

# this is the Alembic Config object, which provides
# the values of the alembic.ini file in here
# as well as other options that can be passed
# to EnvironmentContext.configure()
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata

# Build DATABASE_URI from environment variables
db_type = os.getenv("DB_TYPE", "postgresql")
db_host = os.getenv("DB_HOST", "localhost")
db_port = os.getenv("DB_PORT", "5432")
db_name = os.getenv("DB_NAME", "app_db")
db_user = os.getenv("DB_USER", "app_user")
db_pass = os.getenv("DB_PASS", "app_pass")

# Map common aliases to SQLAlchemy driver format
type_map = {
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "mysql": "mysql+pymysql",
    "sqlite": "sqlite",
    "mssql": "mssql+pyodbc",
}
driver_type = type_map.get(db_type, db_type)

if driver_type == "sqlite":
    database_uri = f"sqlite:///{db_name}.db"
else:
    database_uri = (
        f"{driver_type}://{db_user}:{db_pass}@"
        f"{db_host}:{db_port}/{db_name}"
    )

config.set_main_option("sqlalchemy.url", database_uri)


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
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = database_uri
    connectable = engine_from_config(
        configuration,
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
