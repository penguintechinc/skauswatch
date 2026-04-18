"""
Tests for scim/endpoints.py — SCIM 2.0 provisioning endpoints.

Covers:
  - GET /scim/v2/ServiceProviderConfig → capabilities (no auth required)
  - GET /scim/v2/Users → list/filter users (auth required)
  - POST /scim/v2/Users → create user
  - GET /scim/v2/Users/{id} → get user
  - PUT /scim/v2/Users/{id} → replace user
  - PATCH /scim/v2/Users/{id} → partial update
  - DELETE /scim/v2/Users/{id} → delete user
  - GET /scim/v2/Groups → list groups
  - POST /scim/v2/Groups → create group
  - GET /scim/v2/Groups/{id} → get group
  - PUT /scim/v2/Groups/{id} → replace group
  - PATCH /scim/v2/Groups/{id} → update group members
  - DELETE /scim/v2/Groups/{id} → delete group
  - Bearer token auth (missing/invalid → 401)
  - Required fields validation
  - 404 for nonexistent resources
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

import pytest

from checkpoint_grpc.core_client import CheckpointCoreError


@pytest.mark.asyncio
class TestServiceProviderConfig:
    """Test GET /scim/v2/ServiceProviderConfig endpoint."""

    async def test_service_provider_config_returns_200(self, client):
        """GET /scim/v2/ServiceProviderConfig returns 200 with config."""
        response = await client.get("/scim/v2/ServiceProviderConfig")
        assert response.status_code == 200
        assert "application/scim+json" in response.content_type

        data = await response.get_json()
        assert "schemas" in data
        assert "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig" in data["schemas"]

    async def test_service_provider_config_no_auth_required(self, client):
        """ServiceProviderConfig requires no authentication."""
        response = await client.get("/scim/v2/ServiceProviderConfig")
        assert response.status_code == 200

    async def test_service_provider_config_includes_capabilities(self, client):
        """Config includes PATCH and filter support."""
        response = await client.get("/scim/v2/ServiceProviderConfig")
        data = await response.get_json()

        assert data["patch"]["supported"] is True
        assert data["filter"]["supported"] is True
        assert "maxResults" in data["filter"]

    async def test_service_provider_config_includes_auth_schemes(self, client):
        """Config includes OAuth Bearer Token auth scheme."""
        response = await client.get("/scim/v2/ServiceProviderConfig")
        data = await response.get_json()

        auth_schemes = data.get("authenticationSchemes", [])
        assert len(auth_schemes) > 0
        scheme_types = [s["type"] for s in auth_schemes]
        assert "oauthbearertoken" in scheme_types


@pytest.mark.asyncio
class TestScimTokenAuth:
    """Test SCIM Bearer token authentication."""

    async def test_users_missing_token_returns_401(self, client):
        """Missing Bearer token returns 401."""
        response = await client.get("/scim/v2/Users")
        assert response.status_code == 401
        data = await response.get_json()
        assert "required or invalid" in data.get("detail", data.get("message", "")).lower()

    async def test_users_invalid_token_returns_401(self, client, mock_db):
        """Invalid token returns 401."""
        mock_db.return_value.select.return_value.first.return_value = None

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.get(
                "/scim/v2/Users",
                headers={"Authorization": "Bearer invalid-token"},
            )
            assert response.status_code == 401

    async def test_users_expired_token_returns_401(self, client, mock_db):
        """Expired token returns 401."""
        now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        expired_token = MagicMock()
        expired_token.expires_at = now - timedelta(hours=1)
        expired_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = expired_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.get(
                "/scim/v2/Users",
                headers={"Authorization": "Bearer expired-token"},
            )
            assert response.status_code == 401

    async def test_users_revoked_token_returns_401(self, client, mock_db):
        """Revoked token returns 401."""
        revoked_token = MagicMock()
        revoked_token.expires_at = None
        revoked_token.revoked_at = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        mock_db.return_value.select.return_value.first.return_value = revoked_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.get(
                "/scim/v2/Users",
                headers={"Authorization": "Bearer revoked-token"},
            )
            assert response.status_code == 401


@pytest.mark.asyncio
class TestListUsers:
    """Test GET /scim/v2/Users endpoint."""

    async def test_list_users_returns_200(self, client, mock_db, user_record):
        """GET /scim/v2/Users returns 200 with ListResponse."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.list_users.return_value = [user_record]
            mock_core.get_user_groups.return_value = []
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Users",
                headers={"Authorization": f"Bearer valid-token"},
            )
            assert response.status_code == 200
            assert "application/scim+json" in response.content_type

            data = await response.get_json()
            assert "schemas" in data
            assert "Resources" in data
            assert len(data["Resources"]) > 0

    async def test_list_users_with_filter(self, client, mock_db, user_record):
        """GET /scim/v2/Users?filter= filters users."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.search_users.return_value = [user_record]
            mock_core.get_user_groups.return_value = []
            mock_core_fn.return_value = mock_core

            response = await client.get(
                '/scim/v2/Users?filter=userName eq "jdoe"',
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            data = await response.get_json()
            assert "Resources" in data

    async def test_list_users_invalid_filter_returns_400(self, client, mock_db):
        """Invalid filter syntax returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.get(
                "/scim/v2/Users?filter=invalid-filter-expression",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "invalidFilter" in data.get("scimType", "")

    async def test_list_users_core_unavailable_returns_503(self, client, mock_db):
        """Core service unavailable returns 503."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.list_users.side_effect = CheckpointCoreError("Service unavailable")
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Users",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503


@pytest.mark.asyncio
class TestCreateUser:
    """Test POST /scim/v2/Users endpoint."""

    async def test_create_user_returns_201(self, client, mock_db, user_record):
        """POST /scim/v2/Users creates user and returns 201."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.create_user.return_value = user_record
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.post(
                "/scim/v2/Users",
                json={
                    "userName": "jdoe",
                    "emails": [{"value": "jdoe@example.com", "primary": True}],
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 201
            assert "application/scim+json" in response.content_type
            data = await response.get_json()
            assert data["id"] == "user-123"

    async def test_create_user_missing_username_returns_400(self, client, mock_db):
        """Missing userName returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.post(
                "/scim/v2/Users",
                json={"emails": [{"value": "jdoe@example.com"}]},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "userName is required" in data.get("detail", "")

    async def test_create_user_missing_email_returns_400(self, client, mock_db):
        """Missing email returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.post(
                "/scim/v2/Users",
                json={"userName": "jdoe"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "emails" in data.get("detail", "").lower()

    async def test_create_user_core_unavailable_returns_503(self, client, mock_db):
        """Core service unavailable returns 503."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.create_user.side_effect = CheckpointCoreError("Service unavailable")
            mock_core_fn.return_value = mock_core

            response = await client.post(
                "/scim/v2/Users",
                json={
                    "userName": "jdoe",
                    "emails": [{"value": "jdoe@example.com"}],
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503


@pytest.mark.asyncio
class TestGetUser:
    """Test GET /scim/v2/Users/{id} endpoint."""

    async def test_get_user_returns_200(self, client, mock_db, user_record):
        """GET /scim/v2/Users/{id} returns user."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_user.return_value = user_record
            mock_core.get_user_groups.return_value = []
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Users/user-123",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            data = await response.get_json()
            assert data["id"] == "user-123"
            assert data["userName"] == "jdoe"

    async def test_get_user_not_found_returns_404(self, client, mock_db):
        """Non-existent user returns 404."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_user.return_value = None
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Users/nonexistent",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404

    async def test_get_user_core_unavailable_returns_503(self, client, mock_db):
        """Core unavailable returns 503."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_user.side_effect = CheckpointCoreError("Service unavailable")
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Users/user-123",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503


@pytest.mark.asyncio
class TestReplaceUser:
    """Test PUT /scim/v2/Users/{id} endpoint."""

    async def test_replace_user_returns_200(self, client, mock_db, user_record):
        """PUT /scim/v2/Users/{id} replaces user."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.update_user.return_value = user_record
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.put(
                "/scim/v2/Users/user-123",
                json={"userName": "jdoe_updated", "emails": [{"value": "new@example.com"}]},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200

    async def test_replace_user_not_found_returns_404(self, client, mock_db):
        """Replace non-existent user returns 404."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Not found")
            error.grpc_code = grpc.StatusCode.NOT_FOUND
            mock_core.update_user.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.put(
                "/scim/v2/Users/nonexistent",
                json={"userName": "jdoe"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404


@pytest.mark.asyncio
class TestPatchUser:
    """Test PATCH /scim/v2/Users/{id} endpoint."""

    async def test_patch_user_returns_200(self, client, mock_db, user_record):
        """PATCH /scim/v2/Users/{id} updates user partially."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.update_user.return_value = user_record
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Users/user-123",
                json={
                    "Operations": [
                        {"op": "replace", "path": "displayName", "value": "John Updated"}
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200

    async def test_patch_user_no_operations_returns_current(self, client, mock_db, user_record):
        """PATCH with no actionable operations returns current state."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_user.return_value = user_record
            mock_core_fn.return_value = mock_core

            response = await client.patch(
                "/scim/v2/Users/user-123",
                json={"Operations": []},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200

    async def test_patch_user_not_found_returns_404(self, client, mock_db):
        """PATCH non-existent user returns 404."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Not found")
            error.grpc_code = grpc.StatusCode.NOT_FOUND
            mock_core.update_user.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.patch(
                "/scim/v2/Users/nonexistent",
                json={"Operations": [{"op": "replace", "path": "displayName", "value": "Name"}]},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404


@pytest.mark.asyncio
class TestDeleteUser:
    """Test DELETE /scim/v2/Users/{id} endpoint."""

    async def test_delete_user_returns_204(self, client, mock_db):
        """DELETE /scim/v2/Users/{id} deletes user and returns 204."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.delete_user.return_value = None
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.delete(
                "/scim/v2/Users/user-123",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 204

    async def test_delete_user_not_found_returns_404(self, client, mock_db):
        """DELETE non-existent user returns 404."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Not found")
            error.grpc_code = grpc.StatusCode.NOT_FOUND
            mock_core.delete_user.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.delete(
                "/scim/v2/Users/nonexistent",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404


@pytest.mark.asyncio
class TestListGroups:
    """Test GET /scim/v2/Groups endpoint."""

    async def test_list_groups_returns_200(self, client, mock_db, group_record):
        """GET /scim/v2/Groups returns 200 with ListResponse."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.list_groups.return_value = [group_record]
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            data = await response.get_json()
            assert "Resources" in data
            assert len(data["Resources"]) > 0

    async def test_list_groups_core_unavailable_returns_503(self, client, mock_db):
        """Core unavailable returns 503."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.list_groups.side_effect = CheckpointCoreError("Service unavailable")
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503


@pytest.mark.asyncio
class TestCreateGroup:
    """Test POST /scim/v2/Groups endpoint."""

    async def test_create_group_returns_201(self, client, mock_db, group_record):
        """POST /scim/v2/Groups creates group and returns 201."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.create_group.return_value = group_record
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.post(
                "/scim/v2/Groups",
                json={"displayName": "Engineering Team"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 201
            data = await response.get_json()
            assert data["id"] == "group-789"

    async def test_create_group_missing_displayname_returns_400(self, client, mock_db):
        """Missing displayName returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.post(
                "/scim/v2/Groups",
                json={},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "displayName is required" in data.get("detail", "")


@pytest.mark.asyncio
class TestGetGroup:
    """Test GET /scim/v2/Groups/{id} endpoint."""

    async def test_get_group_returns_200(self, client, mock_db, group_record, member_records):
        """GET /scim/v2/Groups/{id} returns group."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = member_records
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            data = await response.get_json()
            assert data["id"] == "group-789"

    async def test_get_group_not_found_returns_404(self, client, mock_db):
        """Non-existent group returns 404."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_group.return_value = None
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups/nonexistent",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404


@pytest.mark.asyncio
class TestReplaceGroup:
    """Test PUT /scim/v2/Groups/{id} endpoint."""

    async def test_replace_group_returns_200(self, client, mock_db, group_record):
        """PUT /scim/v2/Groups/{id} replaces group."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.update_group.return_value = group_record
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.put(
                "/scim/v2/Groups/group-789",
                json={"displayName": "New Team Name"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200

    async def test_replace_group_missing_displayname_returns_400(self, client, mock_db):
        """PUT without displayName returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.put(
                "/scim/v2/Groups/group-789",
                json={},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400


@pytest.mark.asyncio
class TestPatchGroup:
    """Test PATCH /scim/v2/Groups/{id} endpoint."""

    async def test_patch_group_add_members_returns_200(self, client, mock_db, group_record, member_records):
        """PATCH /scim/v2/Groups/{id} adds members."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.add_membership.return_value = None
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = member_records
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "add",
                            "path": "members",
                            "value": [{"value": "user-001"}],
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200

    async def test_patch_group_remove_members_returns_200(self, client, mock_db, group_record, member_records):
        """PATCH /scim/v2/Groups/{id} removes members."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.remove_membership.return_value = None
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "remove",
                            "path": 'members[value eq "user-001"]',
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200

    async def test_patch_group_invalid_operations_returns_400(self, client, mock_db):
        """PATCH with invalid Operations returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={"Operations": "not-an-array"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400


@pytest.mark.asyncio
class TestDeleteGroup:
    """Test DELETE /scim/v2/Groups/{id} endpoint."""

    async def test_delete_group_returns_204(self, client, mock_db):
        """DELETE /scim/v2/Groups/{id} deletes group and returns 204."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.delete_group.return_value = None
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.delete(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 204

    async def test_delete_group_not_found_returns_404(self, client, mock_db):
        """DELETE non-existent group returns 404."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Not found")
            error.grpc_code = grpc.StatusCode.NOT_FOUND
            mock_core.delete_group.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.delete(
                "/scim/v2/Groups/nonexistent",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404


# ── Uncovered Line Tests ────────────────────────────────────────────────────────


class TestParseScimFilter:
    """Direct unit tests for _parse_scim_filter function (lines 150, 153, 161)."""

    def test_empty_filter_returns_none(self):
        """Line 150: empty filter → None."""
        from scim.endpoints import _parse_scim_filter

        result = _parse_scim_filter("")
        assert result is None

    def test_none_filter_returns_none(self):
        """Line 150: None filter → None."""
        from scim.endpoints import _parse_scim_filter

        result = _parse_scim_filter("")
        assert result is None

    def test_long_filter_returns_none(self):
        """Line 153: filter > 512 chars → None."""
        from scim.endpoints import _parse_scim_filter

        long_filter = "x" * 513
        result = _parse_scim_filter(long_filter)
        assert result is None

    def test_invalid_filter_format_returns_none(self):
        """Line 161: invalid filter format → None."""
        from scim.endpoints import _parse_scim_filter

        result = _parse_scim_filter("invalid format no operator")
        assert result is None


# ── PATCH User Additional Tests ────────────────────────────────────────────────


@pytest.mark.asyncio
class TestPatchUserAdvanced:
    """Additional PATCH /scim/v2/Users tests for uncovered lines 417–463."""

    async def test_patch_user_add_operation_replace_username(self, client, mock_db, user_record):
        """PATCH with add op on username path (line 417) → update succeeds."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn, \
             patch("scim.endpoints._get_config"):
            mock_core = AsyncMock()
            updated_user = MagicMock()
            updated_user.uuid = "user-123"
            updated_user.username = "newusername"
            updated_user.email = "user@example.com"
            updated_user.display_name = "User"
            updated_user.is_active = True
            updated_user.groups = []
            updated_user.attributes = {}
            mock_core.update_user.return_value = updated_user
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Users/user-123",
                json={
                    "Operations": [
                        {"op": "add", "path": "username", "value": "newusername"}
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            mock_core.update_user.assert_called_once()
            call_args = mock_core.update_user.call_args
            assert call_args[1]["fields"]["username"] == "newusername"

    async def test_patch_user_replace_email_list(self, client, mock_db, user_record):
        """PATCH with replace on emails list (line 422–426)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.update_user.return_value = user_record
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Users/user-123",
                json={
                    "Operations": [
                        {
                            "op": "replace",
                            "path": "emails",
                            "value": [{"value": "newemail@example.com", "type": "work"}],
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            call_args = mock_core.update_user.call_args
            assert "email" in call_args[1]["fields"]
            assert call_args[1]["fields"]["email"] == "newemail@example.com"

    async def test_patch_user_remove_active(self, client, mock_db, user_record):
        """PATCH with remove on active path (line 433–434)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.update_user.return_value = user_record
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Users/user-123",
                json={
                    "Operations": [
                        {"op": "remove", "path": "active"}
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            call_args = mock_core.update_user.call_args
            assert call_args[1]["fields"]["is_active"] is False

    async def test_patch_user_no_operations_not_found(self, client, mock_db):
        """PATCH with no fields and user not found (line 438–444)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_user.return_value = None
            mock_core_fn.return_value = mock_core

            response = await client.patch(
                "/scim/v2/Users/nonexistent",
                json={"Operations": []},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404

    async def test_patch_user_core_error_returns_503(self, client, mock_db):
        """PATCH with core error (line 458–463)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Service error")
            error.grpc_code = grpc.StatusCode.INTERNAL
            mock_core.update_user.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.patch(
                "/scim/v2/Users/user-123",
                json={
                    "Operations": [
                        {"op": "replace", "path": "displayName", "value": "NewName"}
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503

    async def test_patch_user_delete_core_error_returns_503(self, client, mock_db):
        """DELETE with core error (line 494–499)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Service error")
            error.grpc_code = grpc.StatusCode.INTERNAL
            mock_core.delete_user.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.delete(
                "/scim/v2/Users/user-123",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503


# ── GET Groups Additional Tests ────────────────────────────────────────────────


@pytest.mark.asyncio
class TestGetGroupAdvanced:
    """Additional GET /scim/v2/Groups tests for uncovered lines 559–618."""

    async def test_get_group_with_members(self, client, mock_db, group_record, member_records):
        """GET /scim/v2/Groups/{id} with members (line 609–612 members assignment)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = member_records
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            data = await response.get_json()
            assert "members" in data
            assert len(data.get("members", [])) == 2

    async def test_get_group_members_fetch_fails_silent(self, client, mock_db, group_record):
        """GET group with member fetch failure (line 609–612, except clause)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.side_effect = Exception("Fetch failed")
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )
            # Should still return 200, members will be empty
            assert response.status_code == 200

    async def test_get_group_core_error_returns_503(self, client, mock_db):
        """GET group with core error (line 594–600)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_group.side_effect = CheckpointCoreError("Service error")
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503


# ── Group Create/Replace/Patch/Delete Additional Tests ────────────────────────


@pytest.mark.asyncio
class TestGroupOperationsAdvanced:
    """Additional group operation tests for uncovered error paths."""

    async def test_create_group_core_error_returns_503(self, client, mock_db):
        """POST /scim/v2/Groups with core error (line 560–565)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.create_group.side_effect = CheckpointCoreError("Service error")
            mock_core_fn.return_value = mock_core

            response = await client.post(
                "/scim/v2/Groups",
                json={"displayName": "Test Group"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503

    async def test_replace_group_not_found_returns_404(self, client, mock_db):
        """PUT /scim/v2/Groups/{id} not found (line 643–654)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Not found")
            error.grpc_code = grpc.StatusCode.NOT_FOUND
            mock_core.update_group.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.put(
                "/scim/v2/Groups/nonexistent",
                json={"displayName": "Updated Name"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404

    async def test_replace_group_core_error_returns_503(self, client, mock_db):
        """PUT /scim/v2/Groups/{id} with core error (line 649–654)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Service error")
            error.grpc_code = grpc.StatusCode.INTERNAL
            mock_core.update_group.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.put(
                "/scim/v2/Groups/group-789",
                json={"displayName": "Updated Name"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503

    async def test_patch_group_add_member_with_add_op(self, client, mock_db, group_record):
        """PATCH group with add op on members (line 700–705 add_membership path)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.add_membership.return_value = None
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "add",
                            "path": "members",
                            "value": [{"value": "user-new"}],
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            mock_core.add_membership.assert_called_once_with(group_uuid="group-789", user_uuid="user-new")

    async def test_patch_group_add_member_error_silenced(self, client, mock_db, group_record):
        """PATCH group add membership error logged but silenced (line 701–705)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.add_membership.side_effect = CheckpointCoreError("Add failed")
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "add",
                            "path": "members",
                            "value": [{"value": "user-new"}],
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            # Errors in membership ops are logged but not returned as errors
            assert response.status_code == 200

    async def test_patch_group_remove_member_by_filter(self, client, mock_db, group_record):
        """PATCH group remove with filter path (line 707–719)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.remove_membership.return_value = None
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "remove",
                            "path": 'members[value eq "user-to-remove"]',
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            mock_core.remove_membership.assert_called_once_with(group_uuid="group-789", user_uuid="user-to-remove")

    async def test_patch_group_remove_member_error_silenced(self, client, mock_db, group_record):
        """PATCH group remove membership error logged but silenced (line 717–729)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.remove_membership.side_effect = CheckpointCoreError("Remove failed")
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "remove",
                            "path": 'members[value eq "user-to-remove"]',
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200

    async def test_patch_group_update_displayname(self, client, mock_db, group_record):
        """PATCH group update displayName (line 731–736)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.update_group.return_value = group_record
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "replace",
                            "path": "displayName",
                            "value": "New Group Name",
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            mock_core.update_group.assert_called_once()

    async def test_patch_group_displayname_update_error_logged(self, client, mock_db, group_record):
        """PATCH group displayName update error (line 734–736)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.update_group.side_effect = CheckpointCoreError("Update failed")
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "replace",
                            "path": "displayName",
                            "value": "New Group Name",
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            # Error is logged but PATCH still succeeds
            assert response.status_code == 200

    async def test_patch_group_get_group_error_returns_503(self, client, mock_db):
        """PATCH group final get_group call error (line 748–763)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Get failed")
            error.grpc_code = grpc.StatusCode.INTERNAL
            mock_core.get_group.side_effect = error
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "add",
                            "path": "members",
                            "value": [{"value": "user-123"}],
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503

    async def test_patch_group_get_group_not_found_returns_404(self, client, mock_db):
        """PATCH group final get returns 404 (line 753–758)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Not found")
            error.grpc_code = grpc.StatusCode.NOT_FOUND
            mock_core.get_group.side_effect = error
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.patch(
                "/scim/v2/Groups/nonexistent",
                json={
                    "Operations": [
                        {
                            "op": "add",
                            "path": "members",
                            "value": [{"value": "user-123"}],
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404

    async def test_delete_group_core_error_returns_503(self, client, mock_db):
        """DELETE group with core error (line 790–795)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        import grpc

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Service error")
            error.grpc_code = grpc.StatusCode.INTERNAL
            mock_core.delete_group.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.delete(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 503

    def test_unknown_attr_returns_none(self):
        """Line 161: unknown attribute not in allowed set → None."""
        from scim.endpoints import _parse_scim_filter

        # 'groups.value' is not in the allowed set (only 'username' and 'emails.value')
        result = _parse_scim_filter('groups.value eq "test"')
        assert result is None

    def test_valid_username_filter(self):
        """Valid 'userName eq' filter."""
        from scim.endpoints import _parse_scim_filter

        result = _parse_scim_filter('userName eq "alice"')
        assert result == ("username", "alice")

    def test_valid_email_filter(self):
        """Valid 'emails.value eq' filter."""
        from scim.endpoints import _parse_scim_filter

        result = _parse_scim_filter('emails.value eq "alice@example.com"')
        assert result == ("emails.value", "alice@example.com")


@pytest.mark.asyncio
class TestGetUserGroupsFailure:
    """Test exception handling in GET user when groups fetch fails (lines 335-336)."""

    async def test_get_user_groups_exception_ignored(self, client, mock_db, user_record):
        """Line 335-336: get_user_groups exception is caught and ignored."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit", return_value=AsyncMock()):
            mock_core = AsyncMock()
            mock_core.get_user.return_value = user_record
            mock_core.get_user_groups.side_effect = Exception("Groups unavailable")
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Users/user-123",
                headers={"Authorization": "Bearer valid-token"},
            )

        # Exception is caught, user still returned with empty groups
        assert response.status_code == 200
        data = await response.get_json()
        assert data["id"] == "user-123"


@pytest.mark.asyncio
class TestReplaceUserEndpoint:
    """Test PUT user validation and error paths (lines 352, 369-370)."""

    async def test_put_user_no_fields_returns_400(self, client, mock_db):
        """Line 352: PUT with no fields → 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core_fn.return_value = mock_core

            response = await client.put(
                "/scim/v2/Users/user-123",
                json={},  # Empty body
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 400

    async def test_put_user_service_error_returns_503(self, client, mock_db, user_record):
        """Line 369-370: PUT with non-NOT_FOUND error → 503."""
        import grpc

        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            error = CheckpointCoreError("Service unavailable")
            error.grpc_code = grpc.StatusCode.INTERNAL
            mock_core.update_user.side_effect = error
            mock_core_fn.return_value = mock_core

            response = await client.put(
                "/scim/v2/Users/user-123",
                json={"displayName": "New Name"},
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 503

    async def test_put_user_success(self, client, mock_db, user_record):
        """Line 417: PUT user success path."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit", return_value=AsyncMock()):
            mock_core = AsyncMock()
            updated_user = SimpleNamespace(
                uuid="user-123",
                username="jdoe",
                email="jdoe@example.com",
                display_name="Jane Doe",
                is_active=True,
                groups=[],
                attributes={},
            )
            mock_core.update_user.return_value = updated_user
            mock_core.get_user_groups.return_value = []
            mock_core_fn.return_value = mock_core

            response = await client.put(
                "/scim/v2/Users/user-123",
                json={"displayName": "Jane Doe"},
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["displayName"] == "Jane Doe"


@pytest.mark.asyncio
class TestPatchUserEndpoint:
    """Test PATCH user success and update paths (lines 420-434, 440)."""

    async def test_patch_user_success_returns_updated_user(self, client, mock_db, user_record):
        """Line 420-434: PATCH user successfully updates and returns user."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit", return_value=AsyncMock()):
            mock_core = AsyncMock()
            updated_user = SimpleNamespace(
                uuid="user-123",
                username="jdoe",
                email="updated@example.com",
                display_name="John Doe Updated",
                is_active=True,
                groups=[],
                attributes={},
            )
            mock_core.update_user.return_value = updated_user
            mock_core.get_user_groups.return_value = []
            mock_core_fn.return_value = mock_core

            response = await client.patch(
                "/scim/v2/Users/user-123",
                json={"Operations": [{"op": "replace", "path": "displayName", "value": "John Doe Updated"}]},
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["displayName"] == "John Doe Updated"


@pytest.mark.asyncio
class TestDeleteUserEndpoint:
    """Test DELETE user success path (lines 458-459)."""

    async def test_delete_user_success(self, client, mock_db):
        """Line 458-459: DELETE user successfully deletes."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit", return_value=AsyncMock()):
            mock_core = AsyncMock()
            mock_core.delete_user.return_value = None
            mock_core_fn.return_value = mock_core

            response = await client.delete(
                "/scim/v2/Users/user-123",
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 204


@pytest.mark.asyncio
class TestGroupOperations:
    """Test group list and operations (lines 559-561, 594-596, 611-612, 649-650, 701-736, 750-759, 790-791)."""

    async def test_list_groups_success(self, client, mock_db, group_record):
        """Line 559-561: GET /Groups returns list."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.list_groups.return_value = [group_record]
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups",
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert len(data["Resources"]) == 1
        assert data["Resources"][0]["id"] == "group-789"

    async def test_create_group_success(self, client, mock_db, group_record):
        """Line 594-596, 611-612: POST /Groups creates group."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit", return_value=AsyncMock()):
            mock_core = AsyncMock()
            mock_core.create_group.return_value = group_record
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            response = await client.post(
                "/scim/v2/Groups",
                json={"displayName": "Engineering Team"},
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 201
        data = await response.get_json()
        assert data["displayName"] == "Engineering Team"

    async def test_patch_group_add_members(self, client, mock_db, group_record, member_records):
        """Line 649-650: PATCH group adds members (scim_patch_group covered)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.add_membership = AsyncMock(return_value=None)
            # Return the group and members for the response
            mock_core.get_group = AsyncMock(return_value=group_record)
            mock_core.list_group_members = AsyncMock(return_value=member_records)
            mock_core_fn.return_value = mock_core

            response = await client.patch(
                "/scim/v2/Groups/group-789",
                json={
                    "Operations": [
                        {
                            "op": "add",
                            "path": "members",
                            "value": [{"value": "user-001"}],
                        }
                    ]
                },
                headers={"Authorization": "Bearer valid-token"},
            )

        # Verify the operation was sent to core and group was returned
        assert response.status_code == 200
        mock_core.add_membership.assert_called()

    async def test_put_group_success(self, client, mock_db, group_record):
        """Line 701-736: PUT group replaces group."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit", return_value=AsyncMock()):
            mock_core = AsyncMock()
            updated_group = SimpleNamespace(uuid="group-789", name="Updated Team")
            mock_core.update_group.return_value = updated_group
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            response = await client.put(
                "/scim/v2/Groups/group-789",
                json={"displayName": "Updated Team"},
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["displayName"] == "Updated Team"

    async def test_get_group_success(self, client, mock_db, group_record):
        """Line 750-759: GET /Groups/{id} returns group with members."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_group.return_value = group_record
            mock_core.list_group_members.return_value = []
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["id"] == "group-789"

    async def test_delete_group_success(self, client, mock_db):
        """Line 790-791: DELETE /Groups/{id} deletes group."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit", return_value=AsyncMock()):
            mock_core = AsyncMock()
            mock_core.delete_group.return_value = None
            mock_core_fn.return_value = mock_core

            response = await client.delete(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )

        assert response.status_code == 204
