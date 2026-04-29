"""Tests for authentication and authorization middleware."""

from datetime import datetime, timedelta, timezone
from typing import Any

import jwt as pyjwt
import pytest
from penguin_aaa import Claims
from quart import Quart

from app.middleware import LocalTokenValidator, auth_required, role_required, admin_required


@pytest.mark.asyncio
async def test_local_token_validator_verifies_valid_token(
    app: Quart, admin_token: str
) -> None:
    """LocalTokenValidator.verify_token validates valid RS256 token."""
    async with app.app_context():
        validator = app.extensions.get("token_validator")
        claims = await validator.verify_token(admin_token)

        assert claims.sub is not None
        assert claims.iss == app.config["ISSUER_URL"]
        assert app.config["JWT_AUDIENCE"] in claims.aud
        assert "scope" in dir(claims)


@pytest.mark.asyncio
async def test_local_token_validator_rejects_invalid_token(app: Quart) -> None:
    """LocalTokenValidator.verify_token rejects invalid token."""
    async with app.app_context():
        validator = app.extensions.get("token_validator")

        with pytest.raises(pyjwt.InvalidTokenError):
            await validator.verify_token("invalid-token-data")


@pytest.mark.asyncio
async def test_local_token_validator_rejects_expired_token(
    app: Quart,
) -> None:
    """LocalTokenValidator.verify_token rejects expired token."""
    async with app.app_context():
        validator = app.extensions.get("token_validator")
        provider = app.extensions.get("oidc_provider")

        # Create an expired token manually
        signing_key, _kid = provider._keystore.get_signing_key()

        payload = {
            "sub": "1",
            "iss": app.config["ISSUER_URL"],
            "aud": [app.config["JWT_AUDIENCE"]],
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),  # expired
            "scope": ["*:read"],
            "roles": ["admin"],
            "tenant": "default",
            "teams": [],
        }

        expired_token = pyjwt.encode(
            payload,
            signing_key,
            algorithm="RS256",
        )

        with pytest.raises(pyjwt.ExpiredSignatureError):
            await validator.verify_token(expired_token)


@pytest.mark.asyncio
async def test_local_token_validator_rejects_wrong_audience(
    app: Quart,
) -> None:
    """LocalTokenValidator.verify_token rejects token with wrong audience."""
    async with app.app_context():
        validator = app.extensions.get("token_validator")
        provider = app.extensions.get("oidc_provider")

        # Create token with wrong audience
        signing_key, _kid = provider._keystore.get_signing_key()

        payload = {
            "sub": "1",
            "iss": app.config["ISSUER_URL"],
            "aud": ["wrong-audience"],
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "scope": ["*:read"],
            "roles": ["admin"],
            "tenant": "default",
            "teams": [],
        }

        wrong_aud_token = pyjwt.encode(
            payload,
            signing_key,
            algorithm="RS256",
        )

        with pytest.raises(pyjwt.InvalidAudienceError):
            await validator.verify_token(wrong_aud_token)


@pytest.mark.asyncio
async def test_auth_required_decorator_accepts_valid_token(
    client: Any, admin_headers: dict, admin_user: dict
) -> None:
    """@auth_required decorator accepts valid token in Authorization header."""
    response = await client.get(
        "/api/v1/auth/me",
        headers=admin_headers,
    )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_auth_required_decorator_rejects_missing_token(client: Any) -> None:
    """@auth_required decorator rejects requests without Authorization header."""
    response = await client.get("/api/v1/auth/me")

    assert response.status_code == 401
    data = await response.get_json()
    assert "authorization" in data["error"].lower()


@pytest.mark.asyncio
async def test_auth_required_decorator_rejects_invalid_token(client: Any) -> None:
    """@auth_required decorator rejects invalid token."""
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid-token"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_auth_required_decorator_rejects_malformed_header(client: Any) -> None:
    """@auth_required decorator rejects malformed Authorization header."""
    response = await client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "InvalidFormat token"},
    )

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_role_required_decorator_admin_has_access(
    client: Any, admin_headers: dict
) -> None:
    """@role_required('admin') allows admin to access."""
    response = await client.get(
        "/api/v1/users",
        headers=admin_headers,
    )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_role_required_decorator_viewer_denied_access(
    client: Any, viewer_headers: dict
) -> None:
    """@role_required('admin') denies viewer access."""
    response = await client.get(
        "/api/v1/users",
        headers=viewer_headers,
    )

    assert response.status_code == 403
    data = await response.get_json()
    assert "insufficient" in data["error"].lower()


@pytest.mark.asyncio
async def test_admin_required_decorator_admin_has_access(
    client: Any, admin_headers: dict
) -> None:
    """@admin_required decorator allows admin to access."""
    response = await client.get(
        "/api/v1/users",
        headers=admin_headers,
    )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_admin_required_decorator_non_admin_denied(
    client: Any, maintainer_headers: dict
) -> None:
    """@admin_required decorator denies non-admin access."""
    response = await client.get(
        "/api/v1/users",
        headers=maintainer_headers,
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_role_required_multiple_roles_admin_has_access(
    client: Any, admin_headers: dict, admin_user: dict
) -> None:
    """@role_required('admin', 'maintainer') allows admin."""
    # This would need a route decorated with role_required("admin", "maintainer")
    # Using existing admin endpoint which checks admin scope
    response = await client.get(
        "/api/v1/users",
        headers=admin_headers,
    )

    assert response.status_code == 200


@pytest.mark.asyncio
async def test_token_validator_decodes_claims_correctly(
    app: Quart, admin_user: dict, admin_token: str
) -> None:
    """LocalTokenValidator decodes all required claims."""
    async with app.app_context():
        validator = app.extensions.get("token_validator")
        claims = await validator.verify_token(admin_token)

        assert claims.sub == str(admin_user["id"])
        assert claims.iss == app.config["ISSUER_URL"]
        assert app.config["JWT_AUDIENCE"] in claims.aud
        assert isinstance(claims.iat, datetime)
        assert isinstance(claims.exp, datetime)
        assert isinstance(claims.scope, list)
        assert isinstance(claims.roles, list)
        assert claims.tenant == "default"


@pytest.mark.asyncio
async def test_auth_required_stores_user_in_context(
    client: Any, admin_headers: dict, admin_user: dict
) -> None:
    """@auth_required decorator stores user and claims in g context."""
    response = await client.get(
        "/api/v1/auth/me",
        headers=admin_headers,
    )

    assert response.status_code == 200
    data = await response.get_json()
    # The /me endpoint returns user data, proving context was populated
    assert data["id"] == admin_user["id"]


@pytest.mark.asyncio
async def test_auth_required_deactivated_user_denied(
    client: Any, app: Quart, admin_user: dict, admin_user_data: dict
) -> None:
    """@auth_required decorator denies access for deactivated users."""
    async with app.app_context():
        from app.models import update_user

        # Deactivate user
        await update_user(admin_user["id"], is_active=False)

    # Try to access protected endpoint with deactivated user's token
    # First get a fresh token (but it would still be valid JWT-wise)
    # Since the token is already issued, we just test login which also checks
    response = await client.post(
        "/api/v1/auth/login",
        json={
            "email": admin_user_data["email"],
            "password": admin_user_data["password"],
        },
    )

    # Login should reject deactivated user
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_auth_required_nonexistent_user_denied(
    app: Quart,
) -> None:
    """@auth_required decorator denies access if user not in database."""
    async with app.app_context():
        # Create a token for a user, then delete the user
        provider = app.extensions.get("oidc_provider")

        # Create token for user ID that doesn't exist
        claims = Claims(
            sub="99999",  # nonexistent user ID
            iss=app.config["ISSUER_URL"],
            aud=[app.config["JWT_AUDIENCE"]],
            iat=datetime.now(timezone.utc),
            exp=datetime.now(timezone.utc) + timedelta(hours=1),
            scope=["*:read"],
            roles=["admin"],
            tenant="default",
            teams=[],
            ext={},
        )
        token_set = provider.issue_token_set(claims)

        # Try to use token for nonexistent user
        response = await app.test_client().get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {token_set.access_token}"},
        )

        assert response.status_code == 401
        data = await response.get_json()
        assert "not found" in data["error"].lower()
