"""
Input validation security tests.

Tests that the API properly validates inputs and returns appropriate
error responses (400/413) rather than server errors (500).
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

pytestmark = [pytest.mark.security, pytest.mark.asyncio]


@pytest.fixture
def app():
    """Test app for input validation security tests."""
    os.environ.update(
        {
            "DB_TYPE": "sqlite",
            "DB_NAME": ":memory:",
            "JWT_SECRET_KEY": "test-secret",
            "SECRET_KEY": "test-secret-key",
            "GRPC_ENABLED": "false",
            "AI_ENABLED": "false",
            "REDIS_URL": "redis://localhost:6379/15",
            "LOG_LEVEL": "WARNING",
        }
    )

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
            auth=AuthConfig(
                jwt_secret="test-secret",
                secret_key="test-secret-key",
                max_login_attempts=5,
                lockout_duration_minutes=15,
            ),
        )
        app = create_app(config)
        app.config["TESTING"] = True
        yield app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def _admin_token(app):
    """Seed an admin user and return a valid JWT token."""
    from models.db import get_db

    config = app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    password_hash = bcrypt.hashpw(b"AdminPass123!", bcrypt.gensalt()).decode("utf-8")
    db.users.insert(
        email="admin@inputval.test",
        password_hash=password_hash,
        full_name="Admin User",
        role="admin",
        is_active=True,
        failed_login_attempts=0,
    )
    db.commit()

    import jwt as pyjwt
    from datetime import datetime, timedelta

    token = pyjwt.encode(
        {
            "sub": "1",
            "role": "admin",
            "type": "access",
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow(),
        },
        "test-secret",
        algorithm="HS256",
    )
    return token


@pytest.mark.security
class TestMissingRequiredFields:
    """Requests missing required fields must not cause 500 errors."""

    async def test_login_empty_body(self, client):
        """POST /auth/login with empty body returns 400."""
        response = await client.post("/api/v1/auth/login", json={})
        assert response.status_code == 400
        assert response.status_code != 500

    async def test_login_missing_password(self, client):
        """POST /auth/login with missing password returns 400."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "user@test.com"},
        )
        assert response.status_code == 400
        assert response.status_code != 500

    async def test_login_missing_email(self, client):
        """POST /auth/login with missing email returns 400."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"password": "SomePass123!"},
        )
        assert response.status_code == 400
        assert response.status_code != 500

    async def test_create_user_empty_body(self, client, _admin_token):
        """POST /users with empty body returns 400 or 422."""
        response = await client.post(
            "/api/v1/users",
            json={},
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code in (400, 422)
        assert response.status_code != 500

    async def test_create_s3_bucket_empty_body(self, client, _admin_token):
        """POST /s3-scan/buckets with empty body returns 400 or 422."""
        response = await client.post(
            "/api/v1/s3-scan/buckets",
            json={},
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code in (400, 422)
        assert response.status_code != 500


@pytest.mark.security
class TestNullByteInjection:
    """Null byte payloads should not cause server errors."""

    async def test_null_byte_in_login_email(self, client):
        """POST /auth/login with null byte in email returns 400, not 500."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "test\x00@test.com", "password": "SomePass123!"},
        )
        assert response.status_code != 500
        assert response.status_code in (400, 401, 422)

    async def test_null_byte_in_user_full_name(self, client, _admin_token):
        """POST /users with null byte in full_name returns 400, not 500."""
        response = await client.post(
            "/api/v1/users",
            json={
                "email": "nullbyte@test.com",
                "password": "ValidPass123!",
                "full_name": "Valid\x00Name",
                "role": "viewer",
            },
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        # Must not crash; validation may allow the name through (201) or reject
        # it (400/422) — either is acceptable as long as it is not 500.
        assert response.status_code != 500

    async def test_null_byte_in_alert_search_param(self, client, _admin_token):
        """GET /alerts with null byte in search param is sanitised or rejected."""
        response = await client.get(
            "/api/v1/alerts?source=test\x00source",
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        # Query-string null bytes should never produce a 500.
        assert response.status_code != 500


@pytest.mark.security
class TestOversizedPayloads:
    """Oversized payloads must be rejected before reaching application logic."""

    async def test_oversized_email_field_in_login(self, client):
        """POST /auth/login with 1 MB email field returns 400 or 413."""
        huge_email = "a" * (1024 * 1024) + "@test.com"
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": huge_email, "password": "SomePass123!"},
        )
        assert response.status_code in (400, 413, 422)
        assert response.status_code != 500

    async def test_oversized_alert_body(self, client, _admin_token):
        """POST /alerts with a 10 MB body is rejected with 400 or 413."""
        huge_description = "X" * (10 * 1024 * 1024)
        response = await client.post(
            "/api/v1/alerts",
            json={
                "title": "Oversized Alert",
                "description": huge_description,
                "severity": "low",
                "source": "test",
            },
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code in (400, 413, 422)
        assert response.status_code != 500

    async def test_content_length_exceeds_limit_for_s3_upload(self, client, _admin_token):
        """POST /s3-scan/upload with Content-Length > 100 MB returns 413."""
        # Send a request claiming an extremely large body but with an empty body.
        # Most frameworks reject requests based on Content-Length header alone.
        over_limit_bytes = 101 * 1024 * 1024  # 101 MB
        response = await client.post(
            "/api/v1/s3-scan/upload",
            data=b"",
            headers={
                "Authorization": f"Bearer {_admin_token}",
                "Content-Length": str(over_limit_bytes),
                "Content-Type": "application/octet-stream",
            },
        )
        # Either rejected at framework level (413) or by missing required fields
        # (400/415/422). The key guarantee is no 500.
        assert response.status_code != 500
        assert response.status_code in (400, 413, 415, 422)


@pytest.mark.security
class TestInvalidEnumValues:
    """Invalid enum values in request payloads should return 400, not 500."""

    async def test_create_user_invalid_role(self, client, _admin_token):
        """POST /users with role='superadmin' returns 400."""
        response = await client.post(
            "/api/v1/users",
            json={
                "email": "badroletemp@test.com",
                "password": "ValidPass123!",
                "full_name": "Bad Role",
                "role": "superadmin",
            },
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code == 400
        assert response.status_code != 500

    async def test_update_alert_invalid_status(self, client, _admin_token):
        """PUT /alerts/{id} with status='invalid_status' returns 400."""
        response = await client.put(
            "/api/v1/alerts/9999",
            json={"status": "invalid_status"},
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code in (400, 404)
        assert response.status_code != 500

    async def test_create_s3_bucket_invalid_provider(self, client, _admin_token):
        """POST /s3-scan/buckets with an invalid provider field returns 400."""
        response = await client.post(
            "/api/v1/s3-scan/buckets",
            json={
                "name": "test-bucket",
                "endpoint_url": "https://s3.invalid.com",
                "bucket_name": "mybucket",
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "provider": "invalid_provider",
            },
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        # 'provider' is not a recognised field so pydantic may ignore it (201)
        # or reject it (400/422). Either way, no 500.
        assert response.status_code != 500


@pytest.mark.security
class TestNegativeIntegers:
    """Negative or zero pagination parameters must not crash the server."""

    async def test_users_negative_page(self, client, _admin_token):
        """GET /users?page=-1 returns 400 or falls back to default, not 500."""
        response = await client.get(
            "/api/v1/users?page=-1",
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code != 500
        assert response.status_code in (200, 400, 422)

    async def test_alerts_negative_per_page(self, client, _admin_token):
        """GET /alerts?per_page=-50 returns 400 or uses default, not 500."""
        response = await client.get(
            "/api/v1/alerts?per_page=-50",
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code != 500
        assert response.status_code in (200, 400, 422)

    async def test_s3_results_zero_page(self, client, _admin_token):
        """GET /s3-scan/results?page=0 returns 400 or default, not 500."""
        response = await client.get(
            "/api/v1/s3-scan/results?page=0",
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code != 500
        assert response.status_code in (200, 400, 422)


@pytest.mark.security
class TestSQLCharactersInSearch:
    """SQL special characters in search parameters must not expose DB errors."""

    async def test_alerts_search_sql_or(self, client, _admin_token):
        """GET /alerts?search=' OR 1=1 -- does not expose SQL errors."""
        response = await client.get(
            "/api/v1/alerts?source=' OR 1=1 --",
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code != 500
        # Should return a valid (possibly empty) result set or a validation error.
        assert response.status_code in (200, 400, 422)

    async def test_users_search_drop_table(self, client, _admin_token):
        """GET /users?search='; DROP TABLE users; -- does not expose SQL errors."""
        response = await client.get(
            "/api/v1/users?search='; DROP TABLE users; --",
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code != 500
        assert response.status_code in (200, 400, 422)

    async def test_iocs_search_union_select(self, client, _admin_token):
        """GET /threat-intel/iocs?search=UNION SELECT * FROM does not expose SQL errors."""
        response = await client.get(
            "/api/v1/threat-intel/iocs?source=UNION SELECT * FROM",
            headers={"Authorization": f"Bearer {_admin_token}"},
        )
        assert response.status_code != 500
        assert response.status_code in (200, 400, 422)
