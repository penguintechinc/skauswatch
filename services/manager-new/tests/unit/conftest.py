"""Unit test fixtures for manager-new service.

Creates a Quart test app with SQLite :memory: database and mocked
Redis/gRPC connections. No external services required.
"""

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add manager-new source to path so imports work
MANAGER_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
sys.path.insert(0, MANAGER_DIR)


@pytest.fixture(autouse=True)
def _set_test_env(monkeypatch):
    """Set environment variables for testing before any imports."""
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
def manager_config():
    """Create a ManagerConfig for testing."""
    from config import AuthConfig, DatabaseConfig, ManagerConfig, RedisConfig

    return ManagerConfig(
        service_name="skauswatch-manager-test",
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


@pytest.fixture
def app(manager_config):
    """Create the Quart test application.

    Patches Redis stream manager to avoid real connections.
    Uses SQLite :memory: for database.
    """
    # Mock the Redis stream manager before importing create_app
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
        from main import create_app

        test_app = create_app(manager_config)
        test_app.config["TESTING"] = True
        yield test_app


@pytest.fixture
def client(app):
    """Quart test client."""
    return app.test_client()


@pytest.fixture
def _seed_admin_user(app):
    """Seed an admin user into the test database.

    Returns the user dict with plaintext password for login testing.
    """
    import bcrypt

    from config import ManagerConfig
    from models.db import get_db

    config: ManagerConfig = app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    password = "AdminPass123!"
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    user_id = db.users.insert(
        email="admin@test.com",
        password_hash=password_hash,
        full_name="Test Admin",
        role="admin",
        is_active=True,
        failed_login_attempts=0,
    )
    db.commit()

    return {
        "id": user_id,
        "email": "admin@test.com",
        "password": password,
        "full_name": "Test Admin",
        "role": "admin",
    }


@pytest.fixture
def seed_admin_user(_seed_admin_user):
    """Public alias for seeded admin user."""
    return _seed_admin_user


@pytest.fixture
def _seed_viewer_user(app):
    """Seed a viewer user into the test database."""
    import bcrypt

    from config import ManagerConfig
    from models.db import get_db

    config: ManagerConfig = app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    password = "ViewerPass123!"
    password_hash = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt()
    ).decode("utf-8")

    user_id = db.users.insert(
        email="viewer@test.com",
        password_hash=password_hash,
        full_name="Test Viewer",
        role="viewer",
        is_active=True,
        failed_login_attempts=0,
    )
    db.commit()

    return {
        "id": user_id,
        "email": "viewer@test.com",
        "password": password,
        "full_name": "Test Viewer",
        "role": "viewer",
    }


@pytest.fixture
def seed_viewer_user(_seed_viewer_user):
    """Public alias for seeded viewer user."""
    return _seed_viewer_user


@pytest.fixture
async def admin_token(client, seed_admin_user):
    """Get a valid admin access token by logging in."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": seed_admin_user["email"],
            "password": seed_admin_user["password"],
        },
    )
    data = await response.get_json()
    return data["access_token"]


@pytest.fixture
async def viewer_token(client, seed_viewer_user):
    """Get a valid viewer access token by logging in."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": seed_viewer_user["email"],
            "password": seed_viewer_user["password"],
        },
    )
    data = await response.get_json()
    return data["access_token"]


@pytest.fixture
def admin_headers(admin_token):
    """Authorization headers for admin user."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    """Authorization headers for viewer user."""
    return {"Authorization": f"Bearer {viewer_token}"}
