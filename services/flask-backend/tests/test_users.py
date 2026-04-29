"""Tests for user management endpoints (admin only)."""

from typing import Any

import pytest
from quart import Quart


@pytest.mark.asyncio
async def test_get_users_admin_can_list(
    client: Any, admin_user: dict, admin_headers: dict, maintainer_user: dict
) -> None:
    """GET /api/v1/users — admin can list users."""
    response = await client.get(
        "/api/v1/users",
        headers=admin_headers,
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert "users" in data
    assert "pagination" in data
    assert len(data["users"]) >= 1
    assert data["pagination"]["page"] == 1
    assert data["pagination"]["total"] >= 2  # admin + maintainer


@pytest.mark.asyncio
async def test_get_users_viewer_gets_403(
    client: Any, viewer_user: dict, viewer_headers: dict, admin_user: dict
) -> None:
    """GET /api/v1/users — viewer gets 403."""
    response = await client.get(
        "/api/v1/users",
        headers=viewer_headers,
    )

    assert response.status_code == 403
    data = await response.get_json()
    assert "insufficient" in data["error"].lower()


@pytest.mark.asyncio
async def test_get_users_without_auth_returns_401(client: Any) -> None:
    """GET /api/v1/users without auth returns 401."""
    response = await client.get("/api/v1/users")

    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_users_pagination(
    client: Any, admin_headers: dict, admin_user: dict, app: Quart
) -> None:
    """GET /api/v1/users pagination works correctly."""
    async with app.app_context():
        from app.models import create_user

        # Create additional users
        for i in range(5):
            await create_user(
                email=f"user{i}@example.com",
                password_hash="hash",
                full_name=f"User {i}",
                role="viewer",
            )

    # Get first page
    response = await client.get(
        "/api/v1/users?page=1&per_page=2",
        headers=admin_headers,
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert data["pagination"]["page"] == 1
    assert data["pagination"]["per_page"] == 2
    assert len(data["users"]) <= 2


@pytest.mark.asyncio
async def test_get_user_by_id_admin_can_fetch(
    client: Any, admin_headers: dict, admin_user: dict
) -> None:
    """GET /api/v1/users/<id> — admin can get user by id."""
    response = await client.get(
        f"/api/v1/users/{admin_user['id']}",
        headers=admin_headers,
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert data["id"] == admin_user["id"]
    assert data["email"] == admin_user["email"]
    assert "password_hash" not in data


@pytest.mark.asyncio
async def test_get_user_by_id_returns_404_for_nonexistent(
    client: Any, admin_headers: dict
) -> None:
    """GET /api/v1/users/<id> — 404 for nonexistent user."""
    response = await client.get(
        "/api/v1/users/99999",
        headers=admin_headers,
    )

    assert response.status_code == 404
    data = await response.get_json()
    assert "not found" in data["error"].lower()


@pytest.mark.asyncio
async def test_create_user_admin_creates_user(
    client: Any, admin_headers: dict, app: Quart
) -> None:
    """POST /api/v1/users — admin creates user."""
    response = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "newadmin@example.com",
            "password": "Password123",
            "full_name": "New Admin",
            "role": "admin",
        },
    )

    assert response.status_code == 201
    data = await response.get_json()
    assert data["message"] == "User created successfully"
    assert data["user"]["email"] == "newadmin@example.com"
    assert data["user"]["role"] == "admin"
    assert "password_hash" not in data["user"]

    # Verify in database
    async with app.app_context():
        from app.models import get_user_by_email

        user = await get_user_by_email("newadmin@example.com")
        assert user is not None
        assert user["role"] == "admin"


@pytest.mark.asyncio
async def test_create_user_viewer_gets_403(
    client: Any, viewer_headers: dict
) -> None:
    """POST /api/v1/users — viewer gets 403."""
    response = await client.post(
        "/api/v1/users",
        headers=viewer_headers,
        json={
            "email": "newuser@example.com",
            "password": "Password123",
            "full_name": "New User",
            "role": "viewer",
        },
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_create_user_duplicate_email_returns_409(
    client: Any, admin_headers: dict, admin_user: dict
) -> None:
    """POST /api/v1/users with duplicate email returns 409."""
    response = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": admin_user["email"],
            "password": "Password123",
            "full_name": "Different Name",
            "role": "viewer",
        },
    )

    assert response.status_code == 409
    data = await response.get_json()
    assert "already" in data["error"].lower()


@pytest.mark.asyncio
async def test_create_user_short_password_returns_400(
    client: Any, admin_headers: dict
) -> None:
    """POST /api/v1/users with short password returns 400."""
    response = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "user@example.com",
            "password": "short",
            "full_name": "User",
            "role": "viewer",
        },
    )

    assert response.status_code == 400
    data = await response.get_json()
    assert "at least 8" in data["error"].lower()


@pytest.mark.asyncio
async def test_create_user_invalid_role_returns_400(
    client: Any, admin_headers: dict
) -> None:
    """POST /api/v1/users with invalid role returns 400."""
    response = await client.post(
        "/api/v1/users",
        headers=admin_headers,
        json={
            "email": "user@example.com",
            "password": "Password123",
            "full_name": "User",
            "role": "superadmin",
        },
    )

    assert response.status_code == 400
    data = await response.get_json()
    assert "invalid role" in data["error"].lower()


@pytest.mark.asyncio
async def test_update_user_admin_updates_user(
    client: Any, admin_headers: dict, admin_user: dict, app: Quart
) -> None:
    """PUT /api/v1/users/<id> — admin updates user."""
    user_id = admin_user["id"]
    response = await client.put(
        f"/api/v1/users/{user_id}",
        headers=admin_headers,
        json={
            "full_name": "Updated Admin",
            "role": "viewer",
        },
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert data["message"] == "User updated successfully"
    assert data["user"]["full_name"] == "Updated Admin"
    assert data["user"]["role"] == "viewer"

    # Verify in database
    async with app.app_context():
        from app.models import get_user_by_id

        updated = await get_user_by_id(user_id)
        assert updated["full_name"] == "Updated Admin"


@pytest.mark.asyncio
async def test_update_user_nonexistent_returns_404(
    client: Any, admin_headers: dict
) -> None:
    """PUT /api/v1/users/<id> — 404 for nonexistent user."""
    response = await client.put(
        "/api/v1/users/99999",
        headers=admin_headers,
        json={"full_name": "Updated"},
    )

    assert response.status_code == 404
    data = await response.get_json()
    assert "not found" in data["error"].lower()


@pytest.mark.asyncio
async def test_update_user_email_conflict_returns_409(
    client: Any, admin_headers: dict, admin_user: dict, maintainer_user: dict
) -> None:
    """PUT /api/v1/users/<id> with conflicting email returns 409."""
    response = await client.put(
        f"/api/v1/users/{admin_user['id']}",
        headers=admin_headers,
        json={"email": maintainer_user["email"]},
    )

    assert response.status_code == 409
    data = await response.get_json()
    assert "already" in data["error"].lower()


@pytest.mark.asyncio
async def test_update_user_invalid_role_returns_400(
    client: Any, admin_headers: dict, admin_user: dict
) -> None:
    """PUT /api/v1/users/<id> with invalid role returns 400."""
    response = await client.put(
        f"/api/v1/users/{admin_user['id']}",
        headers=admin_headers,
        json={"role": "invalid-role"},
    )

    assert response.status_code == 400
    data = await response.get_json()
    assert "invalid role" in data["error"].lower()


@pytest.mark.asyncio
async def test_update_user_short_password_returns_400(
    client: Any, admin_headers: dict, admin_user: dict
) -> None:
    """PUT /api/v1/users/<id> with short password returns 400."""
    response = await client.put(
        f"/api/v1/users/{admin_user['id']}",
        headers=admin_headers,
        json={"password": "short"},
    )

    assert response.status_code == 400
    data = await response.get_json()
    assert "at least 8" in data["error"].lower()


@pytest.mark.asyncio
async def test_delete_user_admin_deletes_user(
    client: Any, admin_headers: dict, maintainer_user: dict, app: Quart
) -> None:
    """DELETE /api/v1/users/<id> — admin deletes user."""
    user_id = maintainer_user["id"]

    response = await client.delete(
        f"/api/v1/users/{user_id}",
        headers=admin_headers,
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert "deleted" in data["message"].lower()

    # Verify user was deleted
    async with app.app_context():
        from app.models import get_user_by_id

        deleted = await get_user_by_id(user_id)
        assert deleted is None


@pytest.mark.asyncio
async def test_delete_user_nonexistent_returns_404(
    client: Any, admin_headers: dict
) -> None:
    """DELETE /api/v1/users/<id> — 404 for nonexistent user."""
    response = await client.delete(
        "/api/v1/users/99999",
        headers=admin_headers,
    )

    assert response.status_code == 404
    data = await response.get_json()
    assert "not found" in data["error"].lower()


@pytest.mark.asyncio
async def test_delete_user_cannot_delete_self(
    client: Any, admin_user: dict, admin_headers: dict
) -> None:
    """DELETE /api/v1/users/<id> — cannot delete own account."""
    user_id = admin_user["id"]

    response = await client.delete(
        f"/api/v1/users/{user_id}",
        headers=admin_headers,
    )

    assert response.status_code == 400
    data = await response.get_json()
    assert "cannot delete" in data["error"].lower()


@pytest.mark.asyncio
async def test_delete_user_viewer_gets_403(
    client: Any, viewer_headers: dict, maintainer_user: dict
) -> None:
    """DELETE /api/v1/users/<id> — viewer gets 403."""
    response = await client.delete(
        f"/api/v1/users/{maintainer_user['id']}",
        headers=viewer_headers,
    )

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_roles_admin_returns_list(client: Any, admin_headers: dict) -> None:
    """GET /api/v1/users/roles — admin returns list of valid roles."""
    response = await client.get(
        "/api/v1/users/roles",
        headers=admin_headers,
    )

    assert response.status_code == 200
    data = await response.get_json()
    assert "roles" in data
    assert "admin" in data["roles"]
    assert "maintainer" in data["roles"]
    assert "viewer" in data["roles"]
    assert "descriptions" in data


@pytest.mark.asyncio
async def test_get_roles_viewer_gets_403(client: Any, viewer_headers: dict) -> None:
    """GET /api/v1/users/roles — viewer gets 403."""
    response = await client.get(
        "/api/v1/users/roles",
        headers=viewer_headers,
    )

    assert response.status_code == 403
