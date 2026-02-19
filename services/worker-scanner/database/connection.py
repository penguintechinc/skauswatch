"""
PyDAL Database Connection Manager for Worker-Scanner Service.

This module provides thread-safe database connection management using PyDAL.
Per project standards, PyDAL handles ALL runtime database operations.

Environment Variables:
    DB_TYPE: Database type (postgres, mysql, sqlite)
    DB_HOST: Database host (not required for sqlite)
    DB_PORT: Database port (not required for sqlite)
    DB_NAME: Database name
    DB_USER: Database user (not required for sqlite)
    DB_PASSWORD: Database password (not required for sqlite)
"""

import logging
import os
import threading
from typing import Optional

from pydal import DAL

# Configure logging
logger = logging.getLogger(__name__)

# Thread-local storage for database connections
_thread_local = threading.local()


def _build_connection_uri() -> str:
    """
    Build PyDAL connection URI from environment variables.

    Returns:
        str: PyDAL connection URI

    Raises:
        ValueError: If required environment variables are missing or DB_TYPE is invalid
    """
    db_type = os.environ.get("DB_TYPE", "postgres").lower()

    if db_type == "sqlite":
        db_name = os.environ.get("DB_NAME", "storage.db")
        return f"sqlite://{db_name}"

    elif db_type in ("postgres", "postgresql"):
        # Required parameters for PostgreSQL
        db_host = os.environ.get("DB_HOST")
        db_port = os.environ.get("DB_PORT", "5432")
        db_name = os.environ.get("DB_NAME")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")

        if not all([db_host, db_name, db_user, db_password]):
            raise ValueError(
                "PostgreSQL requires DB_HOST, DB_NAME, DB_USER, and DB_PASSWORD environment variables"
            )

        return f"postgres://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

    elif db_type == "mysql":
        # Required parameters for MySQL
        db_host = os.environ.get("DB_HOST")
        db_port = os.environ.get("DB_PORT", "3306")
        db_name = os.environ.get("DB_NAME")
        db_user = os.environ.get("DB_USER")
        db_password = os.environ.get("DB_PASSWORD")

        if not all([db_host, db_name, db_user, db_password]):
            raise ValueError(
                "MySQL requires DB_HOST, DB_NAME, DB_USER, and DB_PASSWORD environment variables"
            )

        return f"mysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"

    else:
        raise ValueError(
            f"Invalid DB_TYPE: {db_type}. Supported types: postgres, mysql, sqlite"
        )


def get_db() -> DAL:
    """
    Get thread-local PyDAL database connection.

    This function returns a thread-safe PyDAL DAL instance. Each thread gets
    its own connection instance to prevent threading issues.

    Returns:
        DAL: PyDAL database connection instance

    Raises:
        ValueError: If database configuration is invalid
        Exception: If database connection fails
    """
    # Check if this thread already has a connection
    if not hasattr(_thread_local, "db") or _thread_local.db is None:
        try:
            # Build connection URI
            uri = _build_connection_uri()

            # Create new DAL instance for this thread
            # migrate=False because Alembic handles all schema migrations
            # pool_size=10 for connection pooling
            _thread_local.db = DAL(
                uri,
                pool_size=10,
                migrate=False,
                fake_migrate=False,
                folder="databases",  # PyDAL metadata folder
                lazy_tables=False,
            )

            logger.info(
                "Database connection established for thread %s",
                threading.current_thread().name,
            )

        except ValueError as e:
            logger.error("Database configuration error: %s", str(e))
            raise
        except Exception as e:
            logger.error("Failed to connect to database: %s", str(e))
            raise

    return _thread_local.db


def close_db() -> None:
    """
    Close thread-local database connection.

    This function should be called when a thread is done with the database
    connection to properly release resources.
    """
    if hasattr(_thread_local, "db") and _thread_local.db is not None:
        try:
            _thread_local.db.close()
            logger.info(
                "Database connection closed for thread %s",
                threading.current_thread().name,
            )
        except Exception as e:
            logger.warning("Error closing database connection: %s", str(e))
        finally:
            _thread_local.db = None


def init_app(app) -> None:
    """
    Initialize database connection management for Flask application.

    This function registers a teardown handler to ensure database connections
    are properly closed when the Flask request context ends.

    Args:
        app: Flask application instance
    """

    @app.teardown_appcontext
    def teardown_db(exception: Optional[Exception] = None) -> None:
        """Close database connection at end of request context."""
        if exception:
            logger.warning("Request ended with exception: %s", str(exception))
        close_db()

    logger.info("Database connection manager initialized for Flask app")
