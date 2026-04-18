"""
Pytest configuration and fixtures for aaa-monitor unit tests.
"""

import os
import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

# Ensure the service root is on the path so `from health import HealthChecker` works
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def health_config():
    """Minimal health-check configuration dictionary."""
    return {
        "max_history": 10,
        "check_interval": 30,
        "checks": ["collector1"],
    }


@pytest.fixture
def mock_redis():
    """Async mock Redis client."""
    redis_mock = AsyncMock()
    redis_mock.ping = AsyncMock(return_value=True)
    redis_mock.info = AsyncMock(
        return_value={
            "used_memory": 1024 * 1024,
            "used_memory_peak": 2 * 1024 * 1024,
            "connected_clients": 5,
            "total_commands_processed": 10000,
            "maxmemory": 0,
        }
    )
    return redis_mock


@pytest.fixture
def mock_component():
    """Generic component mock that has running/initialized attributes."""
    comp = MagicMock()
    comp.running = True
    comp.initialized = True
    return comp


@pytest.fixture
def health_checker(health_config, mock_redis, mock_component):
    """HealthChecker instance wired with mock dependencies."""
    from health import HealthChecker

    components = {"collector1": mock_component}
    return HealthChecker(health_config, mock_redis, components)
