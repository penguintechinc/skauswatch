"""Security tests for authentication and authorization.

Tests common attack vectors: SQL injection, XSS, JWT manipulation,
brute force, token replay, mass assignment.

Uses the same Quart test client pattern as unit tests.
"""

import os
import sys
from unittest.mock import AsyncMock, patch

import pytest

MANAGER_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "services", "manager-new"
)
sys.path.insert(0, MANAGER_DIR)


@pytest.fixture
def app():
    """Test app for security tests."""
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
                jwt_secret="test-jwt-secret",
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
def _seed_user(app):
    """Seed a test user."""
    import bcrypt

    from models.db import get_db

    config = app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    password_hash = bcrypt.hashpw(
        b"SecurePass123!", bcrypt.gensalt()
    ).decode("utf-8")

    user_id = db.users.insert(
        email="security@test.com",
        password_hash=password_hash,
        full_name="Security Tester",
        role="viewer",
        is_active=True,
        failed_login_attempts=0,
    )
    db.commit()
    return {"id": user_id, "email": "security@test.com", "password": "SecurePass123!"}


@pytest.mark.security
class TestSQLInjection:
    """SQL injection attack vectors in login/search."""

    async def test_sql_injection_login_email(self, client):
        """SQL injection in login email field."""
        payloads = [
            "' OR '1'='1",
            "admin@test.com'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin@test.com' OR 1=1 --",
        ]
        for payload in payloads:
            response = await client.post(
                "/api/v1/auth/login",
                json={"email": payload, "password": "anything"},
            )
            # Should be 400 (validation) or 401 (auth failed), never 200
            assert response.status_code in (400, 401, 422), (
                f"Unexpected 200/5xx for SQL injection payload: {payload}"
            )

    async def test_sql_injection_login_password(self, client, _seed_user):
        """SQL injection in password field."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": _seed_user["email"],
                "password": "' OR '1'='1",
            },
        )
        assert response.status_code == 401


@pytest.mark.security
class TestXSS:
    """XSS attack vectors in user-facing fields."""

    async def test_xss_in_registration_name(self, client):
        """XSS payload in user full_name is stored safely."""
        xss_payload = '<script>alert("xss")</script>'
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "xss@test.com",
                "password": "SafePass123!",
                "full_name": xss_payload,
            },
        )
        # Registration may succeed but stored value should not cause issues
        if response.status_code == 201:
            data = await response.get_json()
            # Name should be stored as-is (API returns JSON, not HTML)
            # The important thing is no server crash
            assert data["user"]["full_name"] is not None


@pytest.mark.security
class TestJWTManipulation:
    """JWT token manipulation attacks."""

    async def test_jwt_alg_none_attack(self, client):
        """JWT with algorithm 'none' is rejected."""
        import base64
        import json

        # Create a token with alg: none
        header = base64.urlsafe_b64encode(
            json.dumps({"alg": "none", "typ": "JWT"}).encode()
        ).rstrip(b"=")
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "1", "role": "admin", "type": "access"}).encode()
        ).rstrip(b"=")
        forged_token = f"{header.decode()}.{payload.decode()}."

        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {forged_token}"},
        )
        assert response.status_code == 401

    async def test_jwt_wrong_secret(self, client):
        """Token signed with wrong secret is rejected."""
        import jwt as pyjwt
        from datetime import datetime, timedelta

        token = pyjwt.encode(
            {
                "sub": "1",
                "role": "admin",
                "type": "access",
                "exp": datetime.utcnow() + timedelta(hours=1),
            },
            "wrong-secret",
            algorithm="HS256",
        )

        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 401

    async def test_jwt_missing_bearer_prefix(self, client):
        """Token without 'Bearer ' prefix is rejected."""
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "some-token-value"},
        )
        assert response.status_code == 401

    async def test_jwt_empty_authorization(self, client):
        """Empty Authorization header is rejected."""
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": ""},
        )
        assert response.status_code == 401


@pytest.mark.security
class TestBruteForce:
    """Brute force protection."""

    async def test_account_lockout_after_failures(self, client, _seed_user):
        """Account locks after 5 failed login attempts."""
        for i in range(5):
            resp = await client.post(
                "/api/v1/auth/login",
                json={
                    "email": _seed_user["email"],
                    "password": f"WrongPass{i}!",
                },
            )
            assert resp.status_code == 401

        # 6th attempt with correct password should still fail (locked)
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": _seed_user["email"],
                "password": _seed_user["password"],
            },
        )
        assert response.status_code == 401
        data = await response.get_json()
        assert "locked" in data["error"].lower()


@pytest.mark.security
class TestTokenReplay:
    """Token replay after logout."""

    async def test_access_token_after_logout(self, client, _seed_user):
        """Access token may still work briefly after logout (stateless JWT).

        This test documents the behavior - stateless JWTs can't be
        immediately revoked. The refresh token IS revoked.
        """
        # Login
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": _seed_user["email"],
                "password": _seed_user["password"],
            },
        )
        data = await login_resp.get_json()
        access_token = data["access_token"]
        refresh_token = data["refresh_token"]

        # Logout
        await client.post(
            "/api/v1/auth/logout",
            headers={"Authorization": f"Bearer {access_token}"},
        )

        # Refresh token should be revoked
        refresh_resp = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert refresh_resp.status_code == 401


@pytest.mark.security
class TestMassAssignment:
    """Mass assignment / privilege escalation."""

    async def test_viewer_cannot_set_admin_role_on_register(self, client):
        """Registration always creates viewer role regardless of input."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "escalation@test.com",
                "password": "EscalateMe123!",
                "full_name": "Escalator",
                "role": "admin",  # Should be ignored
            },
        )
        if response.status_code == 201:
            data = await response.get_json()
            assert data["user"]["role"] == "viewer"


@pytest.mark.security
class TestInputValidation:
    """Input validation edge cases."""

    async def test_oversized_password_rejected(self, client):
        """Extremely long password (>128 chars) is rejected or handled safely."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "test@test.com",
                "password": "A" * 200,
            },
        )
        # Should not crash (bcrypt has 72-byte limit, but app should handle gracefully)
        assert response.status_code in (400, 401)

    async def test_null_bytes_in_email(self, client):
        """Null bytes in email are rejected."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "test\x00@test.com",
                "password": "SomePass123!",
            },
        )
        assert response.status_code in (400, 401)

    async def test_empty_json_body(self, client):
        """Empty JSON body returns 400, not 500."""
        response = await client.post(
            "/api/v1/auth/login",
            json={},
        )
        assert response.status_code == 400

    async def test_non_json_content_type(self, client):
        """Non-JSON content type is handled gracefully."""
        response = await client.post(
            "/api/v1/auth/login",
            data="not json",
            headers={"Content-Type": "text/plain"},
        )
        assert response.status_code in (400, 415)
