"""Unit tests for manager-new user management endpoints.

Tests: GET/POST/PUT/DELETE /api/v1/users
"""

import pytest


@pytest.mark.unit
class TestListUsers:
    """GET /api/v1/users"""

    async def test_list_users_as_admin(self, client, admin_headers, seed_admin_user):
        """Admin can list all users."""
        response = await client.get(
            "/api/v1/users",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert "items" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert isinstance(data["items"], list)
        assert data["total"] >= 1

    async def test_list_users_as_viewer_forbidden(
        self, client, viewer_headers
    ):
        """Viewer cannot list users (403)."""
        response = await client.get(
            "/api/v1/users",
            headers=viewer_headers,
        )
        assert response.status_code == 403

    async def test_list_users_unauthenticated(self, client):
        """Unauthenticated request returns 401."""
        response = await client.get("/api/v1/users")
        assert response.status_code == 401

    async def test_list_users_pagination(self, client, admin_headers, seed_admin_user):
        """Pagination parameters are respected."""
        response = await client.get(
            "/api/v1/users?page=1&per_page=5",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["page"] == 1
        assert data["per_page"] == 5


@pytest.mark.unit
class TestGetUser:
    """GET /api/v1/users/<user_id>"""

    async def test_get_own_profile(self, client, admin_headers, seed_admin_user):
        """User can view their own profile."""
        user_id = seed_admin_user["id"]
        response = await client.get(
            f"/api/v1/users/{user_id}",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["email"] == seed_admin_user["email"]

    async def test_viewer_cannot_view_other_user(
        self, client, viewer_headers, seed_admin_user
    ):
        """Viewer cannot view another user's profile (403)."""
        admin_id = seed_admin_user["id"]
        response = await client.get(
            f"/api/v1/users/{admin_id}",
            headers=viewer_headers,
        )
        assert response.status_code == 403

    async def test_get_nonexistent_user(self, client, admin_headers, seed_admin_user):
        """Non-existent user returns 404."""
        response = await client.get(
            "/api/v1/users/99999",
            headers=admin_headers,
        )
        assert response.status_code == 404


@pytest.mark.unit
class TestCreateUser:
    """POST /api/v1/users"""

    async def test_admin_creates_user(self, client, admin_headers, seed_admin_user):
        """Admin can create a new user."""
        response = await client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": "newuser@test.com",
                "password": "NewUserPass123!",
                "full_name": "New User",
                "role": "maintainer",
            },
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert data["user"]["email"] == "newuser@test.com"
        assert data["user"]["role"] == "maintainer"

    async def test_viewer_cannot_create_user(self, client, viewer_headers):
        """Viewer cannot create users (403)."""
        response = await client.post(
            "/api/v1/users",
            headers=viewer_headers,
            json={
                "email": "forbidden@test.com",
                "password": "ForbiddenPass123!",
                "full_name": "Forbidden User",
                "role": "viewer",
            },
        )
        assert response.status_code == 403

    async def test_create_duplicate_email(
        self, client, admin_headers, seed_admin_user
    ):
        """Duplicate email returns 409."""
        response = await client.post(
            "/api/v1/users",
            headers=admin_headers,
            json={
                "email": seed_admin_user["email"],
                "password": "DuplicatePass123!",
                "full_name": "Duplicate User",
                "role": "viewer",
            },
        )
        assert response.status_code == 409


@pytest.mark.unit
class TestUpdateUser:
    """PUT /api/v1/users/<user_id>"""

    async def test_admin_updates_user_role(
        self, client, admin_headers, seed_viewer_user, seed_admin_user
    ):
        """Admin can update another user's role."""
        viewer_id = seed_viewer_user["id"]
        response = await client.put(
            f"/api/v1/users/{viewer_id}",
            headers=admin_headers,
            json={"role": "maintainer"},
        )
        assert response.status_code == 200

    async def test_user_updates_own_name(
        self, client, viewer_headers, seed_viewer_user
    ):
        """User can update their own full_name."""
        viewer_id = seed_viewer_user["id"]
        response = await client.put(
            f"/api/v1/users/{viewer_id}",
            headers=viewer_headers,
            json={"full_name": "Updated Name"},
        )
        assert response.status_code == 200

    async def test_viewer_cannot_change_own_role(
        self, client, viewer_headers, seed_viewer_user
    ):
        """Viewer cannot escalate their own role."""
        viewer_id = seed_viewer_user["id"]
        response = await client.put(
            f"/api/v1/users/{viewer_id}",
            headers=viewer_headers,
            json={"role": "admin"},
        )
        # Should either 403 or ignore the role change
        if response.status_code == 200:
            data = await response.get_json()
            # Role should NOT have changed
            get_resp = await client.get(
                f"/api/v1/users/{viewer_id}",
                headers=viewer_headers,
            )
            get_data = await get_resp.get_json()
            assert get_data["role"] == "viewer"
        else:
            assert response.status_code == 403


@pytest.mark.unit
class TestDeleteUser:
    """DELETE /api/v1/users/<user_id>"""

    async def test_admin_deletes_user(
        self, client, admin_headers, seed_viewer_user, seed_admin_user
    ):
        """Admin can delete another user."""
        viewer_id = seed_viewer_user["id"]
        response = await client.delete(
            f"/api/v1/users/{viewer_id}",
            headers=admin_headers,
        )
        assert response.status_code == 200

        # Verify user is gone
        get_resp = await client.get(
            f"/api/v1/users/{viewer_id}",
            headers=admin_headers,
        )
        assert get_resp.status_code == 404

    async def test_admin_cannot_delete_self(
        self, client, admin_headers, seed_admin_user
    ):
        """Admin cannot delete their own account."""
        admin_id = seed_admin_user["id"]
        response = await client.delete(
            f"/api/v1/users/{admin_id}",
            headers=admin_headers,
        )
        assert response.status_code == 400

    async def test_viewer_cannot_delete_user(
        self, client, viewer_headers, seed_admin_user
    ):
        """Viewer cannot delete users (403)."""
        response = await client.delete(
            f"/api/v1/users/{seed_admin_user['id']}",
            headers=viewer_headers,
        )
        assert response.status_code == 403
