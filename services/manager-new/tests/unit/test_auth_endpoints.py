"""Unit tests for manager-new authentication endpoints.

Tests: POST /api/v1/auth/login, /refresh, /logout, /register, GET /me
Uses Quart test client with SQLite :memory: database.
"""

import pytest


@pytest.mark.unit
class TestLogin:
    """POST /api/v1/auth/login"""

    async def test_login_success(self, client, seed_admin_user):
        """Successful login returns access and refresh tokens."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": seed_admin_user["email"],
                "password": seed_admin_user["password"],
            },
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] > 0
        assert data["user"]["email"] == seed_admin_user["email"]
        assert data["user"]["role"] == "admin"

    async def test_login_wrong_password(self, client, seed_admin_user):
        """Wrong password returns 401."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": seed_admin_user["email"],
                "password": "WrongPassword123!",
            },
        )
        assert response.status_code == 401
        data = await response.get_json()
        assert "error" in data

    async def test_login_nonexistent_email(self, client):
        """Non-existent email returns 401."""
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "nobody@test.com",
                "password": "SomePassword123!",
            },
        )
        assert response.status_code == 401

    async def test_login_inactive_user(self, client, app):
        """Inactive user cannot login."""
        import bcrypt

        from config import ManagerConfig
        from models.db import get_db

        config: ManagerConfig = app.config["MANAGER_CONFIG"]
        db = get_db(config.database.uri)

        password = "InactivePass123!"
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        db.users.insert(
            email="inactive@test.com",
            password_hash=password_hash,
            full_name="Inactive User",
            role="viewer",
            is_active=False,
            failed_login_attempts=0,
        )
        db.commit()

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "inactive@test.com", "password": password},
        )
        assert response.status_code == 401

    async def test_login_account_lockout(self, client, seed_admin_user):
        """Account locks after 5 failed attempts."""
        for _ in range(5):
            await client.post(
                "/api/v1/auth/login",
                json={
                    "email": seed_admin_user["email"],
                    "password": "WrongPassword!",
                },
            )

        # 6th attempt should fail even with correct password
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": seed_admin_user["email"],
                "password": seed_admin_user["password"],
            },
        )
        assert response.status_code == 401
        data = await response.get_json()
        assert "locked" in data["error"].lower()

    async def test_login_missing_fields(self, client):
        """Missing required fields return 400."""
        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "test@test.com"},
        )
        assert response.status_code == 400

    async def test_login_empty_body(self, client):
        """Empty request body returns 400."""
        response = await client.post(
            "/api/v1/auth/login",
            json={},
        )
        assert response.status_code == 400


@pytest.mark.unit
class TestRefresh:
    """POST /api/v1/auth/refresh"""

    async def test_refresh_valid_token(self, client, seed_admin_user):
        """Valid refresh token returns new token pair."""
        # Login first to get tokens
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": seed_admin_user["email"],
                "password": seed_admin_user["password"],
            },
        )
        login_data = await login_resp.get_json()
        refresh_token = login_data["refresh_token"]

        # Use refresh token
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert "access_token" in data
        assert "refresh_token" in data
        # New tokens should be different from originals
        assert data["access_token"] != login_data["access_token"]
        assert data["refresh_token"] != login_data["refresh_token"]

    async def test_refresh_revoked_token(self, client, seed_admin_user):
        """Revoked refresh token returns 401."""
        # Login to get tokens
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": seed_admin_user["email"],
                "password": seed_admin_user["password"],
            },
        )
        login_data = await login_resp.get_json()
        refresh_token = login_data["refresh_token"]

        # Use refresh token once (revokes the old one)
        await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )

        # Try to reuse the original refresh token
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token},
        )
        assert response.status_code == 401

    async def test_refresh_invalid_token(self, client):
        """Invalid refresh token returns 401."""
        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid.token.here"},
        )
        assert response.status_code == 401

    async def test_refresh_access_token_rejected(self, client, seed_admin_user):
        """Access token used as refresh token is rejected."""
        login_resp = await client.post(
            "/api/v1/auth/login",
            json={
                "email": seed_admin_user["email"],
                "password": seed_admin_user["password"],
            },
        )
        login_data = await login_resp.get_json()
        access_token = login_data["access_token"]

        response = await client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": access_token},
        )
        assert response.status_code == 401


@pytest.mark.unit
class TestLogout:
    """POST /api/v1/auth/logout"""

    async def test_logout_success(self, client, admin_headers):
        """Authenticated user can logout."""
        response = await client.post(
            "/api/v1/auth/logout",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert "message" in data
        assert "tokens_revoked" in data

    async def test_logout_without_auth(self, client):
        """Unauthenticated logout returns 401."""
        response = await client.post("/api/v1/auth/logout")
        assert response.status_code == 401


@pytest.mark.unit
class TestGetMe:
    """GET /api/v1/auth/me"""

    async def test_get_me_success(self, client, admin_headers, seed_admin_user):
        """Returns current user profile."""
        response = await client.get(
            "/api/v1/auth/me",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["email"] == seed_admin_user["email"]
        assert data["role"] == "admin"
        assert data["is_active"] is True
        assert "id" in data
        assert "password_hash" not in data
        assert "password" not in data

    async def test_get_me_without_auth(self, client):
        """Unauthenticated request returns 401."""
        response = await client.get("/api/v1/auth/me")
        assert response.status_code == 401

    async def test_get_me_expired_token(self, client):
        """Expired token returns 401."""
        response = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer expired.token.value"},
        )
        assert response.status_code == 401


@pytest.mark.unit
class TestRegister:
    """POST /api/v1/auth/register"""

    async def test_register_success(self, client):
        """New user registration creates viewer account."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": "newuser@test.com",
                "password": "StrongPass123!",
                "full_name": "New User",
            },
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert data["user"]["email"] == "newuser@test.com"
        assert data["user"]["role"] == "viewer"

    async def test_register_duplicate_email(self, client, seed_admin_user):
        """Duplicate email returns 409."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "email": seed_admin_user["email"],
                "password": "AnotherPass123!",
                "full_name": "Duplicate User",
            },
        )
        assert response.status_code == 409

    async def test_register_missing_email(self, client):
        """Missing email returns 400."""
        response = await client.post(
            "/api/v1/auth/register",
            json={
                "password": "StrongPass123!",
                "full_name": "No Email User",
            },
        )
        assert response.status_code == 400

    async def test_register_then_login(self, client):
        """Registered user can immediately login."""
        # Register
        await client.post(
            "/api/v1/auth/register",
            json={
                "email": "logintest@test.com",
                "password": "LoginPass123!",
                "full_name": "Login Test",
            },
        )

        # Login
        response = await client.post(
            "/api/v1/auth/login",
            json={
                "email": "logintest@test.com",
                "password": "LoginPass123!",
            },
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert "access_token" in data
