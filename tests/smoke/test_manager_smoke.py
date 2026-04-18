"""Smoke tests: quick Quart test client checks for manager-new.

These tests verify basic HTTP responses without requiring any external
services (database is SQLite :memory:, Redis is mocked).
"""

import os
import sys
from unittest.mock import AsyncMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MANAGER_DIR = os.path.join(REPO_ROOT, "services", "manager-new")


def _manager_available():
    """Check whether manager-new source directory exists."""
    return os.path.isdir(MANAGER_DIR) and os.path.isfile(
        os.path.join(MANAGER_DIR, "main.py")
    )


# Skip the entire module when manager-new is not present
pytestmark = [
    pytest.mark.smoke,
    pytest.mark.skipif(
        not _manager_available(),
        reason="services/manager-new not found in worktree",
    ),
]


@pytest.fixture(autouse=True)
def _manager_path():
    """Ensure manager-new is on sys.path for the duration of the test."""
    if MANAGER_DIR not in sys.path:
        sys.path.insert(0, MANAGER_DIR)
    yield
    if MANAGER_DIR in sys.path:
        sys.path.remove(MANAGER_DIR)


@pytest.fixture(autouse=True)
def _set_test_env(monkeypatch):
    """Set environment variables before any manager imports."""
    monkeypatch.setenv("DB_TYPE", "sqlite")
    monkeypatch.setenv("DB_NAME", ":memory:")
    monkeypatch.setenv("JWT_SECRET_KEY", "test-jwt-secret")
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    monkeypatch.setenv("GRPC_ENABLED", "false")
    monkeypatch.setenv("AI_ENABLED", "false")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/15")
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    monkeypatch.setenv("QUART_ENV", "testing")


@pytest.fixture
def app():
    """Create the Quart test application with mocked Redis."""
    mock_stream_manager = AsyncMock()
    mock_stream_manager.connect = AsyncMock()
    mock_stream_manager.close = AsyncMock()
    mock_stream_manager.create_consumer_group = AsyncMock()
    mock_stream_manager._client = AsyncMock()
    mock_stream_manager._client.ping = AsyncMock(return_value=True)

    with (
        patch(
            "main.RedisStreamManager",
            return_value=mock_stream_manager,
        ),
        patch("main.create_stream_consumer", new_callable=AsyncMock),
        patch(
            "main.AuditLogPublisher",
            return_value=AsyncMock(),
        ),
    ):
        from config import AuthConfig, DatabaseConfig, ManagerConfig, RedisConfig
        from main import create_app

        config = ManagerConfig(
            service_name="skauswatch-manager-smoke",
            environment="testing",
            log_level="WARNING",
            database=DatabaseConfig(
                type="sqlite",
                name=":memory:",
            ),
            redis=RedisConfig(
                url="redis://localhost:6379/15",
                streams_enabled=False,
            ),
            auth=AuthConfig(
                secret_key="test-secret-key",
                jwt_secret="test-jwt-secret",
                jwt_algorithm="HS256",
                access_token_expires_minutes=30,
                refresh_token_expires_days=7,
                max_login_attempts=5,
                lockout_duration_minutes=15,
            ),
        )
        test_app = create_app(config)
        test_app.config["TESTING"] = True
        yield test_app


@pytest.fixture
def client(app):
    """Quart test client."""
    return app.test_client()


async def test_healthz_endpoint(client):
    """GET /healthz should return JSON with a 'status' key."""
    response = await client.get("/healthz")
    data = await response.get_json()
    assert data is not None, "Expected JSON response from /healthz"
    assert "status" in data, f"Missing 'status' key in /healthz response: {data}"


async def test_readyz_endpoint(client):
    """GET /readyz should return 200."""
    response = await client.get("/readyz")
    assert response.status_code == 200
    data = await response.get_json()
    assert data is not None


async def test_version_endpoint(client):
    """GET /version should return JSON with 'name' and 'version' keys."""
    response = await client.get("/version")
    data = await response.get_json()
    assert data is not None, "Expected JSON response from /version"
    assert "name" in data, f"Missing 'name' key in /version response: {data}"
    assert "version" in data, f"Missing 'version' key in /version response: {data}"


async def test_login_returns_json(client):
    """POST /api/v1/auth/login with empty body should return JSON error."""
    response = await client.post(
        "/api/v1/auth/login",
        json={},
    )
    data = await response.get_json()
    assert data is not None, "Expected JSON response from login endpoint"
    # Should be an error response (400/401/422), not a 500 crash
    assert response.status_code < 500, (
        f"Login endpoint crashed with status {response.status_code}: {data}"
    )
