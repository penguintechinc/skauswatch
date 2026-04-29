"""Tests for authentication endpoints."""

from typing import Any

import pytest
from quart import Quart

from app.auth import hash_password, verify_password
from app.models import create_user, get_user_by_email


@pytest.mark.asyncio
async def test_register_creates_user(client: Any, app: Quart) -> None:
    """POST /api/v1/auth/register creates user and returns 201."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "newuser@example.com",
            "password": "Password123",
            "full_name": "New User",
        },
    )

    assert response.status_code == 201
    data = await response.get_json()
    assert data["message"] == "Registration successful"
    assert data["user"]["email"] == "newuser@example.com"
    assert data["user"]["role"] == "viewer"
    assert "access_token" in data
    assert "refresh_token" in data

    # Verify user was created in database
    async with app.app_context():
        user = await get_user_by_email("newuser@example.com")
        assert user is not None
        assert user["email"] == "newuser@example.com"
        assert user["full_name"] == "New User"


@pytest.mark.asyncio
async def test_register_duplicate_email_returns_409(client: Any, admin_user_data: dict) -> None:
    """POST /api/v1/auth/register with duplicate email returns 409."""
    # Register first user
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "duplicate@example.com",
            "password": "Password123",
            "full_name": "First User",
        },
    )

    # Try to register with same email
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "duplicate@example.com",
            "password": "DifferentPass123",
            "full_name": "Second User",
        },
    )

    assert response.status_code == 409
    data = await response.get_json()
    assert "already registered" in data["error"].lower()


@pytest.mark.asyncio
async def test_register_missing_email_returns_400(client: Any) -> None:
    """POST /api/v1/auth/register without email returns 400."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "password": "Password123",
            "full_name": "No Email User",
        },
    )

    assert response.status_code == 400
    data = await response.get_json()
    assert "email" in data["error"].lower()


@pytest.mark.asyncio
async def test_register_short_password_returns_400(client: Any) -> None:
    """POST /api/v1/auth/register with password < 8 chars returns 400."""
    response = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "user@example.com",
            "password": "short",
            "full_name": "User",
        },
    )

    assert response.status_code == 400
    data = await response.get_json()
    assert "at least 8" in data["error"].lower()


@pytest.mark.asyncio
async def test_login_valid_credentials_returns_tokens(
    client: Any, admin_user: dict, admin_user_data: dict
) -> None:
    """POST /api/v1/auth/login with valid credentials returns tokens."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user_data["email"],
            "password": admin_user_data["password"],
        },
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"
    assert data["user"]["email"] == admin_user_data["email"]
    assert data["user"]["role"] == "admin"


@pytest.mark.asyncio
async def test_login_wrong_password_returns_401(
    client: Any, admin_user: dict, admin_user_data: dict
) -> None:
    """POST /api/v1/auth/login with wrong password returns 401."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user_data["email"],
            "password": "WrongPassword123",
        },
    )

    assert response.status_code == 401
    data = await response.get_json()
    assert "invalid" in data["error"].lower()


@pytest.mark.asyncio
async def test_login_unknown_email_returns_401(client: Any) -> None:
    """POST /api/v1/auth/login with unknown email returns 401."""
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "nonexistent@example.com",
            "password": "Password123",
        },
    )

    assert response.status_code == 401
    data = await response.get_json()
    assert "invalid" in data["error"].lower()


@pytest.mark.asyncio
async def test_login_missing_credentials_returns_400(client: Any) -> None:
    """POST /api/v1/auth/login without email/password returns 400."""
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": "user@example.com"},
    )

    assert response.status_code == 400
    data = await response.get_json()
    assert "required" in data["error"].lower()


@pytest.mark.asyncio
async def test_login_no_body_returns_400(client: Any) -> None:
    """POST /api/v1/auth/login with no body returns 400."""
    response = await client.post("/api/v1/auth/login")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_refresh_valid_token_returns_new_tokens(
    client: Any, admin_user: dict, app: Quart
) -> None:
    """POST /api/v1/auth/refresh with valid refresh_token returns new tokens."""
    # Get initial tokens
    async with app.app_context():
        provider = app.extensions.get("oidc_provider")
        from app.auth import _build_claims

        claims = _build_claims(admin_user)
        token_set = provider.issue_token_set(claims)

    refresh_token = token_set.refresh_token

    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token},
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "Bearer"


@pytest.mark.asyncio
async def test_refresh_invalid_token_returns_401(client: Any) -> None:
    """POST /api/v1/auth/refresh with invalid token returns 401."""
    response = await client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": "invalid-token"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_missing_token_returns_400(client: Any) -> None:
    """POST /api/v1/auth/refresh without refresh_token returns 400."""
    response = await client.post(
        "/api/v1/auth/refresh",
        json={},
    )

    assert response.status_code == 400
    data = await response.get_json()
    assert "error" in data


@pytest.mark.asyncio
async def test_logout_with_valid_token_returns_200(
    client: Any, admin_headers: dict
) -> None:
    """POST /api/v1/auth/logout with valid token returns 200."""
    response = await client.post(
        "/api/v1/auth/logout",
        headers=admin_headers,
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert "logged out" in data["message"].lower()


@pytest.mark.asyncio
async def test_logout_without_token_returns_401(client: Any) -> None:
    """POST /api/v1/auth/logout without Authorization header returns 401."""
    response = await client.post("/api/v1/auth/logout")

    assert response.status_code == 401
    data = await response.get_json()
    assert "authorization" in data["error"].lower()


@pytest.mark.asyncio
async def test_me_with_valid_token_returns_user(
    client: Any, admin_user: dict, admin_headers: dict
) -> None:
    """GET /api/v1/auth/me with valid token returns current user info."""
    response = await client.get(
        "/api/v1/auth/me",
        headers=admin_headers,
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert data["email"] == admin_user["email"]
    assert data["role"] == "admin"
    assert data["is_active"] is True
    assert "created_at" in data


@pytest.mark.asyncio
async def test_me_without_token_returns_401(client: Any) -> None:
    """GET /api/v1/auth/me without token returns 401."""
    response = await client.get("/api/v1/auth/me")

    assert response.status_code == 401
    data = await response.get_json()
    assert "authorization" in data["error"].lower()


@pytest.mark.asyncio
async def test_me_with_invalid_token_returns_401(client: Any) -> None:
    """GET /api/v1/auth/me with invalid token returns 401."""
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_deactivated_user_returns_401(
    client: Any, app: Quart, admin_user: dict, admin_user_data: dict
) -> None:
    """POST /api/v1/auth/login for deactivated user returns 401."""
    async with app.app_context():
        from app.models import update_user

        await update_user(admin_user["id"], is_active=False)

    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user_data["email"],
            "password": admin_user_data["password"],
        },
    )

    assert response.status_code == 401
    data = await response.get_json()
    assert "deactivated" in data["error"].lower()


@pytest.mark.asyncio
async def test_password_hashing_and_verification() -> None:
    """Verify password hashing and verification works correctly."""
    password = "TestPassword123"
    hash_value = hash_password(password)

    assert hash_value != password
    assert verify_password(password, hash_value)
    assert not verify_password("WrongPassword123", hash_value)
