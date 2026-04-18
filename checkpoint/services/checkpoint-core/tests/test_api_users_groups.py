"""Comprehensive pytest tests for users_groups.py REST API."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from checkpoint_grpc.core_client import CheckpointCoreError


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def mock_core_client() -> AsyncMock:
    """Mock gRPC core client."""
    return AsyncMock()


@pytest.fixture
def valid_token() -> str:
    """Valid bearer token (mocked)."""
    return "valid_token_123"


@pytest.fixture
def admin_token_claims() -> dict:
    """Token claims with checkpoint:admin scope."""
    return {
        "sub": "user-admin",
        "scope": "checkpoint:admin",
        "iat": 1234567890,
        "exp": 9999999999,
    }


@pytest.fixture
def user_read_token_claims() -> dict:
    """Token claims with checkpoint:users:read scope."""
    return {
        "sub": "user-reader",
        "scope": "checkpoint:users:read",
        "iat": 1234567890,
        "exp": 9999999999,
    }


@pytest.fixture
def user_write_token_claims() -> dict:
    """Token claims with checkpoint:users:write scope."""
    return {
        "sub": "user-writer",
        "scope": "checkpoint:users:write",
        "iat": 1234567890,
        "exp": 9999999999,
    }


@pytest.fixture
def user_delete_token_claims() -> dict:
    """Token claims with checkpoint:users:delete scope."""
    return {
        "sub": "user-deleter",
        "scope": "checkpoint:users:delete",
        "iat": 1234567890,
        "exp": 9999999999,
    }


@pytest.fixture
def group_read_token_claims() -> dict:
    """Token claims with checkpoint:groups:read scope."""
    return {
        "sub": "user-reader",
        "scope": "checkpoint:groups:read",
        "iat": 1234567890,
        "exp": 9999999999,
    }


@pytest.fixture
def group_write_token_claims() -> dict:
    """Token claims with checkpoint:groups:write scope."""
    return {
        "sub": "user-writer",
        "scope": "checkpoint:groups:write",
        "iat": 1234567890,
        "exp": 9999999999,
    }


@pytest.fixture
def insufficient_token_claims() -> dict:
    """Token claims with insufficient scopes."""
    return {
        "sub": "user-viewer",
        "scope": "some:other:scope",
        "iat": 1234567890,
        "exp": 9999999999,
    }


@pytest.fixture
def mock_user() -> SimpleNamespace:
    """Mock user record."""
    return SimpleNamespace(
        uuid="user-001",
        username="alice",
        email="alice@example.com",
        display_name="Alice Wonder",
        is_active=True,
        groups=["group-1", "group-2"],
        attributes={"department": "engineering", "location": "sf"},
    )


@pytest.fixture
def mock_user_inactive() -> SimpleNamespace:
    """Mock inactive user record."""
    return SimpleNamespace(
        uuid="user-002",
        username="bob",
        email="bob@example.com",
        display_name="Bob Smith",
        is_active=False,
        groups=[],
        attributes={},
    )


@pytest.fixture
def mock_group() -> SimpleNamespace:
    """Mock group record."""
    return SimpleNamespace(
        uuid="group-001",
        name="Engineering",
        description="Engineering team",
        member_count=5,
    )


@pytest.fixture
def mock_group_no_description() -> SimpleNamespace:
    """Mock group record without description."""
    return SimpleNamespace(
        uuid="group-002",
        name="Finance",
        member_count=3,
    )


# ── User List Tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_users_unauthorized(client):
    """Test GET /users returns 401 when no token provided."""
    response = await client.get("/api/v1/users")
    assert response.status_code == 401
    data = await response.get_json()
    assert data["error"] == "unauthorized"


@pytest.mark.asyncio
async def test_list_users_insufficient_scope(client, insufficient_token_claims):
    """Test GET /users returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.get("/api/v1/users")
        assert response.status_code == 403
        data = await response.get_json()
        assert data["error"] == "insufficient_scope"


@pytest.mark.asyncio
async def test_list_users_success(
    client, user_read_token_claims, mock_user, mock_user_inactive, mock_core_client
):
    """Test GET /users returns paginated user list with checkpoint:users:read."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_users.return_value = [mock_user, mock_user_inactive]
        response = await client.get("/api/v1/users?page=0&per_page=50")
        assert response.status_code == 200
        data = await response.get_json()
        assert len(data["users"]) == 2
        assert data["users"][0]["uuid"] == "user-001"
        assert data["users"][0]["username"] == "alice"
        assert data["users"][0]["email"] == "alice@example.com"
        assert data["users"][0]["display_name"] == "Alice Wonder"
        assert data["users"][0]["is_active"] is True
        assert data["users"][0]["groups"] == ["group-1", "group-2"]
        assert data["users"][1]["uuid"] == "user-002"
        assert data["users"][1]["is_active"] is False
        assert data["page"] == 0
        assert data["per_page"] == 50


@pytest.mark.asyncio
async def test_list_users_with_admin_scope(
    client, admin_token_claims, mock_user, mock_core_client
):
    """Test GET /users works with checkpoint:admin scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=admin_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_users.return_value = [mock_user]
        response = await client.get("/api/v1/users")
        assert response.status_code == 200
        data = await response.get_json()
        assert len(data["users"]) == 1


@pytest.mark.asyncio
async def test_list_users_filter_active(
    client, user_read_token_claims, mock_user, mock_core_client
):
    """Test GET /users?status=active filters to active users."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_users.return_value = [mock_user]
        response = await client.get("/api/v1/users?status=active")
        assert response.status_code == 200
        mock_core_client.list_users.assert_called_once_with(
            page=0, page_size=100, filter_active=True
        )


@pytest.mark.asyncio
async def test_list_users_filter_inactive(
    client, user_read_token_claims, mock_user_inactive, mock_core_client
):
    """Test GET /users?status=inactive filters to inactive users."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_users.return_value = [mock_user_inactive]
        response = await client.get("/api/v1/users?status=inactive")
        assert response.status_code == 200
        mock_core_client.list_users.assert_called_once_with(
            page=0, page_size=100, filter_active=False
        )


@pytest.mark.asyncio
async def test_list_users_filter_all(
    client, user_read_token_claims, mock_user, mock_core_client
):
    """Test GET /users?status=all (default) returns all users."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_users.return_value = [mock_user]
        response = await client.get("/api/v1/users?status=all")
        assert response.status_code == 200
        mock_core_client.list_users.assert_called_once_with(
            page=0, page_size=100, filter_active=None
        )


@pytest.mark.asyncio
async def test_list_users_pagination(
    client, user_read_token_claims, mock_user, mock_core_client
):
    """Test pagination params (page, per_page) are respected."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_users.return_value = [mock_user]
        response = await client.get("/api/v1/users?page=2&per_page=25")
        assert response.status_code == 200
        data = await response.get_json()
        assert data["page"] == 2
        assert data["per_page"] == 25
        mock_core_client.list_users.assert_called_once_with(
            page=2, page_size=25, filter_active=None
        )


@pytest.mark.asyncio
async def test_list_users_pagination_max_limit(
    client, user_read_token_claims, mock_user, mock_core_client
):
    """Test per_page is capped at 500."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_users.return_value = [mock_user]
        response = await client.get("/api/v1/users?per_page=1000")
        assert response.status_code == 200
        mock_core_client.list_users.assert_called_once_with(
            page=0, page_size=500, filter_active=None
        )


@pytest.mark.asyncio
async def test_list_users_rpc_error(
    client, user_read_token_claims, mock_core_client
):
    """Test GET /users returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_users.side_effect = CheckpointCoreError("gRPC error")
        response = await client.get("/api/v1/users")
        assert response.status_code == 502
        data = await response.get_json()
        assert data["error"] == "upstream identity service error"


# ── Get User Tests ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_user_unauthorized(client):
    """Test GET /users/<uuid> returns 401 without token."""
    response = await client.get("/api/v1/users/user-001")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_user_insufficient_scope(client, insufficient_token_claims):
    """Test GET /users/<uuid> returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.get("/api/v1/users/user-001")
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_user_success(
    client, user_read_token_claims, mock_user, mock_core_client
):
    """Test GET /users/<uuid> returns user data."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.get_user.return_value = mock_user
        response = await client.get("/api/v1/users/user-001")
        assert response.status_code == 200
        data = await response.get_json()
        assert data["uuid"] == "user-001"
        assert data["username"] == "alice"
        assert data["email"] == "alice@example.com"
        mock_core_client.get_user.assert_called_once_with(uuid="user-001")


@pytest.mark.asyncio
async def test_get_user_not_found(
    client, user_read_token_claims, mock_core_client
):
    """Test GET /users/<uuid> returns 404 when user not found."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.get_user.return_value = None
        response = await client.get("/api/v1/users/nonexistent")
        assert response.status_code == 404
        data = await response.get_json()
        assert data["error"] == "not found"


@pytest.mark.asyncio
async def test_get_user_rpc_error(
    client, user_read_token_claims, mock_core_client
):
    """Test GET /users/<uuid> returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.get_user.side_effect = CheckpointCoreError("gRPC error")
        response = await client.get("/api/v1/users/user-001")
        assert response.status_code == 502


# ── Create User Tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_user_unauthorized(client):
    """Test POST /users returns 401 without token."""
    response = await client.post("/api/v1/users", json={})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_create_user_insufficient_scope(client, insufficient_token_claims):
    """Test POST /users returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.post("/api/v1/users", json={})
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_create_user_missing_username(
    client, user_write_token_claims
):
    """Test POST /users returns 400 when username is missing."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ):
        response = await client.post(
            "/api/v1/users",
            json={"email": "test@example.com", "display_name": "Test"},
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert data["error"] == "username is required"


@pytest.mark.asyncio
async def test_create_user_missing_email(
    client, user_write_token_claims
):
    """Test POST /users returns 400 when email is missing."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ):
        response = await client.post(
            "/api/v1/users",
            json={"username": "alice", "display_name": "Alice"},
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert data["error"] == "email is required"


@pytest.mark.asyncio
async def test_create_user_missing_display_name(
    client, user_write_token_claims
):
    """Test POST /users returns 400 when display_name is missing."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ):
        response = await client.post(
            "/api/v1/users",
            json={"username": "alice", "email": "alice@example.com"},
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert data["error"] == "display_name is required"


@pytest.mark.asyncio
async def test_create_user_invalid_email(
    client, user_write_token_claims
):
    """Test POST /users returns 400 for invalid email format."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ):
        response = await client.post(
            "/api/v1/users",
            json={
                "username": "alice",
                "email": "notanemail",
                "display_name": "Alice",
            },
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert data["error"] == "invalid email format"


@pytest.mark.asyncio
async def test_create_user_success(
    client, user_write_token_claims, mock_user, mock_core_client
):
    """Test POST /users creates user and returns 201."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ), patch(
        "api.v1.users_groups._get_audit",
    ) as mock_audit:
        mock_audit.return_value.log = AsyncMock()
        mock_core_client.create_user.return_value = mock_user
        response = await client.post(
            "/api/v1/users",
            json={
                "username": "alice",
                "email": "alice@example.com",
                "display_name": "Alice Wonder",
                "attributes": {"department": "engineering"},
                "group_uuids": ["group-1"],
            },
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert data["uuid"] == "user-001"
        mock_core_client.create_user.assert_called_once()
        call_kwargs = mock_core_client.create_user.call_args[1]
        assert call_kwargs["username"] == "alice"
        assert call_kwargs["email"] == "alice@example.com"
        assert call_kwargs["display_name"] == "Alice Wonder"
        mock_audit.return_value.log.assert_called_once()


@pytest.mark.asyncio
async def test_create_user_rpc_error(
    client, user_write_token_claims, mock_core_client
):
    """Test POST /users returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.create_user.side_effect = CheckpointCoreError("gRPC error")
        response = await client.post(
            "/api/v1/users",
            json={
                "username": "alice",
                "email": "alice@example.com",
                "display_name": "Alice",
            },
        )
        assert response.status_code == 502


# ── Update User Tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_user_unauthorized(client):
    """Test PUT /users/<uuid> returns 401 without token."""
    response = await client.put("/api/v1/users/user-001", json={})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_update_user_insufficient_scope(client, insufficient_token_claims):
    """Test PUT /users/<uuid> returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.put("/api/v1/users/user-001", json={})
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_update_user_no_fields(client, user_write_token_claims):
    """Test PUT /users/<uuid> returns 400 when no fields provided."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ):
        response = await client.put("/api/v1/users/user-001", json={})
        assert response.status_code == 400
        data = await response.get_json()
        assert data["error"] == "no fields to update"


@pytest.mark.asyncio
async def test_update_user_success(
    client, user_write_token_claims, mock_user, mock_core_client
):
    """Test PUT /users/<uuid> updates user fields."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ), patch(
        "api.v1.users_groups._get_audit",
    ) as mock_audit:
        mock_audit.return_value.log = AsyncMock()
        mock_core_client.update_user.return_value = mock_user
        response = await client.put(
            "/api/v1/users/user-001",
            json={"display_name": "Alice Updated"},
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["uuid"] == "user-001"
        mock_core_client.update_user.assert_called_once()
        mock_audit.return_value.log.assert_called_once()


@pytest.mark.asyncio
async def test_update_user_not_found(
    client, user_write_token_claims, mock_core_client
):
    """Test PUT /users/<uuid> returns 404 when user not found."""
    import grpc

    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        exc = CheckpointCoreError("not found")
        exc.grpc_code = grpc.StatusCode.NOT_FOUND
        mock_core_client.update_user.side_effect = exc
        response = await client.put(
            "/api/v1/users/nonexistent",
            json={"display_name": "Test"},
        )
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_user_rpc_error(
    client, user_write_token_claims, mock_core_client
):
    """Test PUT /users/<uuid> returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.update_user.side_effect = CheckpointCoreError("gRPC error")
        response = await client.put(
            "/api/v1/users/user-001",
            json={"display_name": "Test"},
        )
        assert response.status_code == 502


# ── Delete User Tests ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_user_unauthorized(client):
    """Test DELETE /users/<uuid> returns 401 without token."""
    response = await client.delete("/api/v1/users/user-001")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_delete_user_insufficient_scope(client, insufficient_token_claims):
    """Test DELETE /users/<uuid> returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.delete("/api/v1/users/user-001")
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_delete_user_success(
    client, user_delete_token_claims, mock_core_client
):
    """Test DELETE /users/<uuid> deletes user."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_delete_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ), patch(
        "api.v1.users_groups._get_audit",
    ) as mock_audit:
        mock_audit.return_value.log = AsyncMock()
        mock_core_client.delete_user.return_value = None
        response = await client.delete("/api/v1/users/user-001")
        assert response.status_code == 200
        data = await response.get_json()
        assert data["status"] == "deleted"
        mock_core_client.delete_user.assert_called_once_with(uuid="user-001")
        mock_audit.return_value.log.assert_called_once()


@pytest.mark.asyncio
async def test_delete_user_not_found(
    client, user_delete_token_claims, mock_core_client
):
    """Test DELETE /users/<uuid> returns 404 when user not found."""
    import grpc

    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_delete_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        exc = CheckpointCoreError("not found")
        exc.grpc_code = grpc.StatusCode.NOT_FOUND
        mock_core_client.delete_user.side_effect = exc
        response = await client.delete("/api/v1/users/nonexistent")
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_user_rpc_error(
    client, user_delete_token_claims, mock_core_client
):
    """Test DELETE /users/<uuid> returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=user_delete_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.delete_user.side_effect = CheckpointCoreError("gRPC error")
        response = await client.delete("/api/v1/users/user-001")
        assert response.status_code == 502


# ── Group List Tests ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_groups_unauthorized(client):
    """Test GET /groups returns 401 without token."""
    response = await client.get("/api/v1/groups")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_groups_insufficient_scope(client, insufficient_token_claims):
    """Test GET /groups returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.get("/api/v1/groups")
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_list_groups_success(
    client, group_read_token_claims, mock_group, mock_core_client
):
    """Test GET /groups returns paginated group list."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_groups.return_value = [mock_group]
        response = await client.get("/api/v1/groups?page=0&per_page=50")
        assert response.status_code == 200
        data = await response.get_json()
        assert len(data["groups"]) == 1
        assert data["groups"][0]["uuid"] == "group-001"
        assert data["groups"][0]["name"] == "Engineering"
        assert data["groups"][0]["member_count"] == 5
        assert data["page"] == 0
        assert data["per_page"] == 50


@pytest.mark.asyncio
async def test_list_groups_pagination(
    client, group_read_token_claims, mock_group, mock_core_client
):
    """Test pagination params for group list."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_groups.return_value = [mock_group]
        response = await client.get("/api/v1/groups?page=1&per_page=25")
        assert response.status_code == 200
        mock_core_client.list_groups.assert_called_once_with(page=1, page_size=25)


@pytest.mark.asyncio
async def test_list_groups_rpc_error(
    client, group_read_token_claims, mock_core_client
):
    """Test GET /groups returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_groups.side_effect = CheckpointCoreError("gRPC error")
        response = await client.get("/api/v1/groups")
        assert response.status_code == 502


# ── Get Group Tests ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_group_unauthorized(client):
    """Test GET /groups/<uuid> returns 401 without token."""
    response = await client.get("/api/v1/groups/group-001")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_get_group_insufficient_scope(client, insufficient_token_claims):
    """Test GET /groups/<uuid> returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.get("/api/v1/groups/group-001")
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_group_success(
    client, group_read_token_claims, mock_group, mock_core_client
):
    """Test GET /groups/<uuid> returns group data."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.get_group.return_value = mock_group
        response = await client.get("/api/v1/groups/group-001")
        assert response.status_code == 200
        data = await response.get_json()
        assert data["uuid"] == "group-001"
        assert data["name"] == "Engineering"
        mock_core_client.get_group.assert_called_once_with(uuid="group-001")


@pytest.mark.asyncio
async def test_get_group_not_found(
    client, group_read_token_claims, mock_core_client
):
    """Test GET /groups/<uuid> returns 404 when group not found."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.get_group.return_value = None
        response = await client.get("/api/v1/groups/nonexistent")
        assert response.status_code == 404
        data = await response.get_json()
        assert data["error"] == "not found"


@pytest.mark.asyncio
async def test_get_group_rpc_error(
    client, group_read_token_claims, mock_core_client
):
    """Test GET /groups/<uuid> returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.get_group.side_effect = CheckpointCoreError("gRPC error")
        response = await client.get("/api/v1/groups/group-001")
        assert response.status_code == 502


# ── Create Group Tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_group_unauthorized(client):
    """Test POST /groups returns 401 without token."""
    response = await client.post("/api/v1/groups", json={})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_create_group_insufficient_scope(client, insufficient_token_claims):
    """Test POST /groups returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.post("/api/v1/groups", json={})
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_create_group_missing_name(client, group_write_token_claims):
    """Test POST /groups returns 400 when name is missing."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ):
        response = await client.post(
            "/api/v1/groups",
            json={"description": "Test group"},
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert data["error"] == "name is required"


@pytest.mark.asyncio
async def test_create_group_success(
    client, group_write_token_claims, mock_group, mock_core_client
):
    """Test POST /groups creates group and returns 201."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ), patch(
        "api.v1.users_groups._get_audit",
    ) as mock_audit:
        mock_audit.return_value.log = AsyncMock()
        mock_core_client.create_group.return_value = mock_group
        response = await client.post(
            "/api/v1/groups",
            json={
                "name": "Engineering",
                "description": "Engineering team",
            },
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert data["uuid"] == "group-001"
        assert data["name"] == "Engineering"
        mock_core_client.create_group.assert_called_once()
        mock_audit.return_value.log.assert_called_once()


@pytest.mark.asyncio
async def test_create_group_rpc_error(
    client, group_write_token_claims, mock_core_client
):
    """Test POST /groups returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.create_group.side_effect = CheckpointCoreError("gRPC error")
        response = await client.post(
            "/api/v1/groups",
            json={"name": "Engineering"},
        )
        assert response.status_code == 502


# ── Update Group Tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_update_group_unauthorized(client):
    """Test PUT /groups/<uuid> returns 401 without token."""
    response = await client.put("/api/v1/groups/group-001", json={})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_update_group_insufficient_scope(client, insufficient_token_claims):
    """Test PUT /groups/<uuid> returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.put("/api/v1/groups/group-001", json={})
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_update_group_no_fields(client, group_write_token_claims):
    """Test PUT /groups/<uuid> returns 400 when no fields provided."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ):
        response = await client.put("/api/v1/groups/group-001", json={})
        assert response.status_code == 400
        data = await response.get_json()
        assert data["error"] == "no fields to update"


@pytest.mark.asyncio
async def test_update_group_success(
    client, group_write_token_claims, mock_group, mock_core_client
):
    """Test PUT /groups/<uuid> updates group."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ), patch(
        "api.v1.users_groups._get_audit",
    ) as mock_audit:
        mock_audit.return_value.log = AsyncMock()
        mock_core_client.update_group.return_value = mock_group
        response = await client.put(
            "/api/v1/groups/group-001",
            json={"description": "Updated description"},
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["uuid"] == "group-001"
        mock_core_client.update_group.assert_called_once()
        mock_audit.return_value.log.assert_called_once()


@pytest.mark.asyncio
async def test_update_group_not_found(
    client, group_write_token_claims, mock_core_client
):
    """Test PUT /groups/<uuid> returns 404 when group not found."""
    import grpc

    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        exc = CheckpointCoreError("not found")
        exc.grpc_code = grpc.StatusCode.NOT_FOUND
        mock_core_client.update_group.side_effect = exc
        response = await client.put(
            "/api/v1/groups/nonexistent",
            json={"name": "Test"},
        )
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_update_group_rpc_error(
    client, group_write_token_claims, mock_core_client
):
    """Test PUT /groups/<uuid> returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.update_group.side_effect = CheckpointCoreError("gRPC error")
        response = await client.put(
            "/api/v1/groups/group-001",
            json={"name": "Test"},
        )
        assert response.status_code == 502


# ── Delete Group Tests ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_delete_group_unauthorized(client):
    """Test DELETE /groups/<uuid> returns 401 without token."""
    response = await client.delete("/api/v1/groups/group-001")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_delete_group_insufficient_scope(client, insufficient_token_claims):
    """Test DELETE /groups/<uuid> returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.delete("/api/v1/groups/group-001")
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_delete_group_success(
    client, group_write_token_claims, mock_core_client
):
    """Test DELETE /groups/<uuid> deletes group."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ), patch(
        "api.v1.users_groups._get_audit",
    ) as mock_audit:
        mock_audit.return_value.log = AsyncMock()
        mock_core_client.delete_group.return_value = None
        response = await client.delete("/api/v1/groups/group-001")
        assert response.status_code == 200
        data = await response.get_json()
        assert data["status"] == "deleted"
        mock_core_client.delete_group.assert_called_once_with(uuid="group-001")
        mock_audit.return_value.log.assert_called_once()


@pytest.mark.asyncio
async def test_delete_group_not_found(
    client, group_write_token_claims, mock_core_client
):
    """Test DELETE /groups/<uuid> returns 404 when group not found."""
    import grpc

    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        exc = CheckpointCoreError("not found")
        exc.grpc_code = grpc.StatusCode.NOT_FOUND
        mock_core_client.delete_group.side_effect = exc
        response = await client.delete("/api/v1/groups/nonexistent")
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_delete_group_rpc_error(
    client, group_write_token_claims, mock_core_client
):
    """Test DELETE /groups/<uuid> returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.delete_group.side_effect = CheckpointCoreError("gRPC error")
        response = await client.delete("/api/v1/groups/group-001")
        assert response.status_code == 502


# ── List Group Members Tests ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_group_members_unauthorized(client):
    """Test GET /groups/<uuid>/members returns 401 without token."""
    response = await client.get("/api/v1/groups/group-001/members")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_list_group_members_insufficient_scope(client, insufficient_token_claims):
    """Test GET /groups/<uuid>/members returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.get("/api/v1/groups/group-001/members")
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_list_group_members_success(
    client, group_read_token_claims, mock_user, mock_core_client
):
    """Test GET /groups/<uuid>/members returns member list."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_group_members.return_value = [mock_user]
        response = await client.get("/api/v1/groups/group-001/members")
        assert response.status_code == 200
        data = await response.get_json()
        assert data["group_uuid"] == "group-001"
        assert len(data["members"]) == 1
        assert data["members"][0]["uuid"] == "user-001"
        mock_core_client.list_group_members.assert_called_once_with(
            group_uuid="group-001"
        )


@pytest.mark.asyncio
async def test_list_group_members_not_found(
    client, group_read_token_claims, mock_core_client
):
    """Test GET /groups/<uuid>/members returns 404 when group not found."""
    import grpc

    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        exc = CheckpointCoreError("not found")
        exc.grpc_code = grpc.StatusCode.NOT_FOUND
        mock_core_client.list_group_members.side_effect = exc
        response = await client.get("/api/v1/groups/nonexistent/members")
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_group_members_rpc_error(
    client, group_read_token_claims, mock_core_client
):
    """Test GET /groups/<uuid>/members returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_read_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.list_group_members.side_effect = CheckpointCoreError(
            "gRPC error"
        )
        response = await client.get("/api/v1/groups/group-001/members")
        assert response.status_code == 502


# ── Add Group Member Tests ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_add_group_member_unauthorized(client):
    """Test POST /groups/<uuid>/members returns 401 without token."""
    response = await client.post("/api/v1/groups/group-001/members", json={})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_add_group_member_insufficient_scope(client, insufficient_token_claims):
    """Test POST /groups/<uuid>/members returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.post("/api/v1/groups/group-001/members", json={})
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_add_group_member_missing_user_uuid(
    client, group_write_token_claims
):
    """Test POST /groups/<uuid>/members returns 400 when user_uuid missing."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ):
        response = await client.post(
            "/api/v1/groups/group-001/members",
            json={},
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert data["error"] == "user_uuid is required"


@pytest.mark.asyncio
async def test_add_group_member_success(
    client, group_write_token_claims, mock_core_client
):
    """Test POST /groups/<uuid>/members adds member."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ), patch(
        "api.v1.users_groups._get_audit",
    ) as mock_audit:
        mock_audit.return_value.log = AsyncMock()
        mock_core_client.add_membership.return_value = None
        response = await client.post(
            "/api/v1/groups/group-001/members",
            json={"user_uuid": "user-001"},
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert data["status"] == "added"
        assert data["group_uuid"] == "group-001"
        assert data["user_uuid"] == "user-001"
        mock_core_client.add_membership.assert_called_once_with(
            group_uuid="group-001", user_uuid="user-001"
        )
        mock_audit.return_value.log.assert_called_once()


@pytest.mark.asyncio
async def test_add_group_member_not_found(
    client, group_write_token_claims, mock_core_client
):
    """Test POST /groups/<uuid>/members returns 404 when group/user not found."""
    import grpc

    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        exc = CheckpointCoreError("not found")
        exc.grpc_code = grpc.StatusCode.NOT_FOUND
        mock_core_client.add_membership.side_effect = exc
        response = await client.post(
            "/api/v1/groups/group-001/members",
            json={"user_uuid": "user-001"},
        )
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_add_group_member_rpc_error(
    client, group_write_token_claims, mock_core_client
):
    """Test POST /groups/<uuid>/members returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.add_membership.side_effect = CheckpointCoreError(
            "gRPC error"
        )
        response = await client.post(
            "/api/v1/groups/group-001/members",
            json={"user_uuid": "user-001"},
        )
        assert response.status_code == 502


# ── Remove Group Member Tests ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_remove_group_member_unauthorized(client):
    """Test DELETE /groups/<uuid>/members/<uuid> returns 401 without token."""
    response = await client.delete("/api/v1/groups/group-001/members/user-001")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_remove_group_member_insufficient_scope(
    client, insufficient_token_claims
):
    """Test DELETE /groups/<uuid>/members/<uuid> returns 403 with insufficient scope."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=insufficient_token_claims,
    ):
        response = await client.delete(
            "/api/v1/groups/group-001/members/user-001"
        )
        assert response.status_code == 403


@pytest.mark.asyncio
async def test_remove_group_member_success(
    client, group_write_token_claims, mock_core_client
):
    """Test DELETE /groups/<uuid>/members/<uuid> removes member."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ), patch(
        "api.v1.users_groups._get_audit",
    ) as mock_audit:
        mock_audit.return_value.log = AsyncMock()
        mock_core_client.remove_membership.return_value = None
        response = await client.delete(
            "/api/v1/groups/group-001/members/user-001"
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["status"] == "removed"
        mock_core_client.remove_membership.assert_called_once_with(
            group_uuid="group-001", user_uuid="user-001"
        )
        mock_audit.return_value.log.assert_called_once()


@pytest.mark.asyncio
async def test_remove_group_member_not_found(
    client, group_write_token_claims, mock_core_client
):
    """Test DELETE /groups/<uuid>/members/<uuid> returns 404 when not found."""
    import grpc

    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        exc = CheckpointCoreError("not found")
        exc.grpc_code = grpc.StatusCode.NOT_FOUND
        mock_core_client.remove_membership.side_effect = exc
        response = await client.delete(
            "/api/v1/groups/group-001/members/user-001"
        )
        assert response.status_code == 404


@pytest.mark.asyncio
async def test_remove_group_member_rpc_error(
    client, group_write_token_claims, mock_core_client
):
    """Test DELETE /groups/<uuid>/members/<uuid> returns 502 on gRPC error."""
    with patch(
        "api.v1.users_groups._get_token_claims",
        return_value=group_write_token_claims,
    ), patch(
        "api.v1.users_groups._get_core",
        return_value=mock_core_client,
    ):
        mock_core_client.remove_membership.side_effect = CheckpointCoreError(
            "gRPC error"
        )
        response = await client.delete(
            "/api/v1/groups/group-001/members/user-001"
        )
        assert response.status_code == 502
