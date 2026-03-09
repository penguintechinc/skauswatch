"""
Shared pytest fixtures for unit tests.

Provides mock configurations, Redis clients, and database sessions.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def mock_config():
    """Minimal mock configuration for services."""
    config = MagicMock()
    config.service_name = "test-service"
    config.environment = "test"
    config.log_level = "DEBUG"

    # Database config
    config.database = MagicMock()
    config.database.type = "sqlite"
    config.database.name = ":memory:"
    config.database.uri = "sqlite://:memory:"

    # Redis config
    config.redis = MagicMock()
    config.redis.url = "redis://localhost:6379/0"
    config.redis.password = None
    config.redis.key_prefix = "test"
    config.redis.streams_enabled = True

    # Auth config
    config.auth = MagicMock()
    config.auth.secret_key = "test-secret-key"
    config.auth.jwt_secret = "test-jwt-secret"
    config.auth.jwt_algorithm = "HS256"

    return config


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    redis_client = AsyncMock()
    redis_client.get = AsyncMock(return_value=None)
    redis_client.set = AsyncMock(return_value=True)
    redis_client.delete = AsyncMock(return_value=0)
    redis_client.xread = AsyncMock(return_value=[])
    redis_client.xadd = AsyncMock(return_value=b"1234567890-0")
    redis_client.close = AsyncMock()
    return redis_client


@pytest.fixture
def mock_db():
    """Mock database connection."""
    db = MagicMock()
    db.define_tables = MagicMock()
    db.commit = MagicMock()
    db.rollback = MagicMock()
    db.close = MagicMock()
    return db


@pytest.fixture
def mock_logger():
    """Mock logger."""
    logger = MagicMock()
    logger.debug = MagicMock()
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    logger.critical = MagicMock()
    return logger
