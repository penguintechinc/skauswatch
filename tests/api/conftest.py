"""Shared fixtures for API tests.

Provides a manager Quart test client with pre-seeded users
and auth tokens for all three roles: admin, maintainer, viewer.
"""

import os
import sys
from unittest.mock import AsyncMock, patch

import bcrypt
import pytest

MANAGER_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "services", "manager-new"
)
sys.path.insert(0, MANAGER_DIR)


@pytest.fixture(scope="module")
def _env_setup():
    """Set environment for testing."""
    os.environ.update(
        {
            "DB_TYPE": "sqlite",
            "DB_NAME": ":memory:",
            "JWT_SECRET_KEY": "test-jwt-secret",
            "SECRET_KEY": "test-secret-key",
            "GRPC_ENABLED": "false",
            "AI_ENABLED": "false",
            "REDIS_URL": "redis://localhost:6379/15",
            "LOG_LEVEL": "WARNING",
        }
    )


@pytest.fixture
def app(_env_setup):
    """Create manager test app."""
    mock_stream = AsyncMock(
        connect=AsyncMock(),
        close=AsyncMock(),
        create_consumer_group=AsyncMock(),
        _client=AsyncMock(ping=AsyncMock(return_value=True)),
    )

    with (
        patch("main.RedisStreamManager", return_value=mock_stream),
        patch("main.create_stream_consumer", new_callable=AsyncMock),
        patch("main.AuditLogPublisher", return_value=AsyncMock()),
    ):
        from config import AuthConfig, DatabaseConfig, ManagerConfig, RedisConfig
        from main import create_app

        config = ManagerConfig(
            environment="testing",
            database=DatabaseConfig(type="sqlite", name=":memory:"),
            redis=RedisConfig(url="redis://localhost:6379/15", streams_enabled=False),
            auth=AuthConfig(jwt_secret="test-jwt-secret", secret_key="test-secret-key"),
        )
        test_app = create_app(config)
        test_app.config["TESTING"] = True
        yield test_app


@pytest.fixture
def client(app):
    """Quart test client."""
    return app.test_client()


def _create_user(app, email, password, role, full_name):
    """Insert a user directly into the test database."""
    from models.db import get_db

    config = app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    user_id = db.users.insert(
        email=email,
        password_hash=pw_hash,
        full_name=full_name,
        role=role,
        is_active=True,
        failed_login_attempts=0,
    )
    db.commit()
    return {"id": user_id, "email": email, "password": password, "role": role}


@pytest.fixture
def admin_user(app):
    return _create_user(app, "admin@api.test", "AdminPass123!", "admin", "API Admin")


@pytest.fixture
def maintainer_user(app):
    return _create_user(
        app, "maint@api.test", "MaintPass123!", "maintainer", "API Maintainer"
    )


@pytest.fixture
def viewer_user(app):
    return _create_user(app, "viewer@api.test", "ViewerPass123!", "viewer", "API Viewer")


async def _login(client, email, password):
    """Login and return the access token."""
    resp = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    data = await resp.get_json()
    return data["access_token"]


@pytest.fixture
async def admin_token(client, admin_user):
    return await _login(client, admin_user["email"], admin_user["password"])


@pytest.fixture
async def maintainer_token(client, maintainer_user):
    return await _login(client, maintainer_user["email"], maintainer_user["password"])


@pytest.fixture
async def viewer_token(client, viewer_user):
    return await _login(client, viewer_user["email"], viewer_user["password"])


@pytest.fixture
def admin_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def maintainer_headers(maintainer_token):
    return {"Authorization": f"Bearer {maintainer_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}
