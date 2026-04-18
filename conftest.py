"""Root conftest.py for SkausWatch test suite.

Registers all test markers and provides session-scoped infrastructure
fixtures with graceful skip when services are unavailable.
"""

import socket

import pytest


def pytest_configure(config):
    """Register all custom test markers."""
    markers = [
        "unit: Unit tests (mocked dependencies, fast)",
        "integration: Integration tests (require test infra via docker-compose.test.yml)",
        "e2e: End-to-end tests (require full stack running)",
        "smoke: Smoke tests (pre-commit, <2 min total)",
        "api: API endpoint tests (test clients or live services)",
        "functional: Functional tests (Playwright browser tests)",
        "performance: Performance/load tests (slow)",
        "security: Security tests (auth bypass, injection, etc.)",
        "lint: Lint validation tests",
        "build: Docker build tests (slow)",
        "stream: Redis Stream / pipeline tests",
        "slow: Slow tests (deselect with '-m \"not slow\"')",
    ]
    for marker in markers:
        config.addinivalue_line("markers", marker)


def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a TCP port is accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@pytest.fixture(scope="session")
def test_postgres_url():
    """PostgreSQL URL for test database (docker-compose.test.yml).

    Returns URL or skips if not reachable.
    """
    host, port = "localhost", 5499
    if not _is_port_open(host, port):
        pytest.skip("Test PostgreSQL not available (start with docker-compose.test.yml)")
    return f"postgresql://test_user:test_password@{host}:{port}/skauswatch_test"


@pytest.fixture(scope="session")
def test_redis_url():
    """Redis URL for test instance (docker-compose.test.yml).

    Returns URL or skips if not reachable.
    """
    host, port = "localhost", 6399
    if not _is_port_open(host, port):
        pytest.skip("Test Redis not available (start with docker-compose.test.yml)")
    return f"redis://:test_password@{host}:{port}/0"


@pytest.fixture(scope="session")
def test_minio_url():
    """MinIO URL for test instance (docker-compose.test.yml).

    Returns URL or skips if not reachable.
    """
    host, port = "localhost", 9099
    if not _is_port_open(host, port):
        pytest.skip("Test MinIO not available (start with docker-compose.test.yml)")
    return f"http://{host}:{port}"


@pytest.fixture(scope="session")
def test_minio_credentials():
    """MinIO credentials for test instance."""
    return {
        "access_key": "test_access_key",
        "secret_key": "test_secret_key",
    }
