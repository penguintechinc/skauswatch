"""
checkpoint-core — penguin-dal database connection and initialization.

penguin-dal auto-reflects table definitions from the database schema.
Alembic owns all schema changes — no migrations in this code.
"""
from __future__ import annotations

from penguin_dal import DB


def init_checkpoint_tables(db_uri: str, pool_size: int = 10) -> DB:
    """
    Initialize and return a penguin-dal DB instance.

    penguin-dal automatically reflects all tables from the database schema.
    Tables are defined and migrated via Alembic — this function only creates
    the connection pool and returns the DB instance.

    Args:
        db_uri: Database connection URI (e.g., 'postgresql://user:pass@host/db')
        pool_size: Connection pool size (default 10)

    Returns:
        DB: penguin-dal database instance with all tables auto-reflected
    """
    return DB(db_uri, pool_size=pool_size)
