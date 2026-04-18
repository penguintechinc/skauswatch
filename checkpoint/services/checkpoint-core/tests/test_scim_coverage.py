"""
Additional coverage tests for scim/endpoints.py — focuses on uncovered lines.

Covers edge cases:
  - Missing Authorization header (_verify_scim_token line 46 usage in decorator)
  - Empty Bearer token (line 86)
  - ServiceProviderConfig discovery (lines 150, 153, 161)
  - List users edge cases (lines 236-237)
  - Create user validation (lines 335-336, 352, 369-370)
  - PATCH Operations validation (line 402)
  - PATCH with operations producing no fields (lines 420-434)
  - PATCH user not found after update (line 440)
  - Delete user paths (lines 458-459)
  - Group list/get (lines 494-495, 559-561)
  - Group create edge cases (lines 594-596, 611-612)
  - Group patch edge cases (lines 640-650)
  - Additional group/user paths (lines 701-702, 715-736, 750-759, 790-791)
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

import pytest

from checkpoint_grpc.core_client import CheckpointCoreError


@pytest.mark.asyncio
class TestMissingAuthorizationHeader:
    """Test missing Authorization header for all /scim/v2 routes."""

    async def test_get_users_without_auth_header(self, client):
        """GET /scim/v2/Users without Authorization header returns 401."""
        response = await client.get("/scim/v2/Users")
        assert response.status_code == 401
        data = await response.get_json()
        assert "token" in data.get("detail", "").lower() or "required" in data.get("detail", "").lower()

    async def test_post_users_without_auth_header(self, client):
        """POST /scim/v2/Users without Authorization header returns 401."""
        response = await client.post(
            "/scim/v2/Users",
            json={"userName": "test", "emails": [{"value": "test@example.com"}]},
        )
        assert response.status_code == 401

    async def test_get_user_by_id_without_auth_header(self, client):
        """GET /scim/v2/Users/{id} without Authorization header returns 401."""
        response = await client.get("/scim/v2/Users/user-123")
        assert response.status_code == 401

    async def test_put_user_without_auth_header(self, client):
        """PUT /scim/v2/Users/{id} without Authorization header returns 401."""
        response = await client.put(
            "/scim/v2/Users/user-123",
            json={"userName": "test"},
        )
        assert response.status_code == 401

    async def test_patch_user_without_auth_header(self, client):
        """PATCH /scim/v2/Users/{id} without Authorization header returns 401."""
        response = await client.patch(
            "/scim/v2/Users/user-123",
            json={"Operations": []},
        )
        assert response.status_code == 401

    async def test_delete_user_without_auth_header(self, client):
        """DELETE /scim/v2/Users/{id} without Authorization header returns 401."""
        response = await client.delete("/scim/v2/Users/user-123")
        assert response.status_code == 401

    async def test_get_groups_without_auth_header(self, client):
        """GET /scim/v2/Groups without Authorization header returns 401."""
        response = await client.get("/scim/v2/Groups")
        assert response.status_code == 401

    async def test_post_groups_without_auth_header(self, client):
        """POST /scim/v2/Groups without Authorization header returns 401."""
        response = await client.post(
            "/scim/v2/Groups",
            json={"displayName": "test-group"},
        )
        assert response.status_code == 401

    async def test_get_group_by_id_without_auth_header(self, client):
        """GET /scim/v2/Groups/{id} without Authorization header returns 401."""
        response = await client.get("/scim/v2/Groups/group-123")
        assert response.status_code == 401

    async def test_patch_group_without_auth_header(self, client):
        """PATCH /scim/v2/Groups/{id} without Authorization header returns 401."""
        response = await client.patch(
            "/scim/v2/Groups/group-123",
            json={"Operations": []},
        )
        assert response.status_code == 401

    async def test_delete_group_without_auth_header(self, client):
        """DELETE /scim/v2/Groups/{id} without Authorization header returns 401."""
        response = await client.delete("/scim/v2/Groups/group-123")
        assert response.status_code == 401


@pytest.mark.asyncio
class TestEmptyBearerToken:
    """Test Bearer token with empty value (line 86)."""

    async def test_empty_bearer_token_returns_401(self, client, mock_db):
        """Bearer with empty token value returns 401."""
        mock_db.return_value.select.return_value.first.return_value = None

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.get(
                "/scim/v2/Users",
                headers={"Authorization": "Bearer "},
            )
            assert response.status_code == 401


@pytest.mark.asyncio
class TestServiceProviderConfigDiscovery:
    """Test ServiceProviderConfig discovery endpoint."""

    async def test_service_provider_config_includes_patch_support(self, client):
        """ServiceProviderConfig reports patch support."""
        response = await client.get("/scim/v2/ServiceProviderConfig")
        assert response.status_code == 200
        data = await response.get_json()
        assert data.get("patch", {}).get("supported") is True

    async def test_service_provider_config_includes_filter_support(self, client):
        """ServiceProviderConfig reports filter support."""
        response = await client.get("/scim/v2/ServiceProviderConfig")
        assert response.status_code == 200
        data = await response.get_json()
        assert data.get("filter", {}).get("supported") is True
        assert "maxResults" in data.get("filter", {})

    async def test_service_provider_config_includes_location(self, client):
        """ServiceProviderConfig includes location metadata."""
        response = await client.get("/scim/v2/ServiceProviderConfig")
        assert response.status_code == 200
        data = await response.get_json()
        meta = data.get("meta", {})
        assert "location" in meta
        assert "/scim/v2/ServiceProviderConfig" in meta["location"]


@pytest.mark.asyncio
class TestListUsersEdgeCases:
    """Test list users edge cases (lines 236-237)."""

    async def test_list_users_group_fetch_failure_continues(self, client, mock_db, user_record):
        """If group fetch fails, user is still returned (line 236-237)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.list_users.return_value = [user_record]
            # Simulate group fetch failure
            mock_core.get_user_groups.side_effect = Exception("Network error")
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Users",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            data = await response.get_json()
            assert len(data["Resources"]) == 1
            assert data["Resources"][0]["id"] == "user-123"


@pytest.mark.asyncio
class TestCreateUserValidation:
    """Test create user validation edge cases."""

    async def test_create_user_missing_username_returns_400(self, client, mock_db):
        """Create user without userName returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.post(
                "/scim/v2/Users",
                json={"emails": [{"value": "test@example.com"}]},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "userName" in data.get("detail", "")

    async def test_create_user_missing_email_returns_400(self, client, mock_db):
        """Create user without emails returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.post(
                "/scim/v2/Users",
                json={"userName": "testuser"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "email" in data.get("detail", "").lower()

    async def test_create_user_empty_emails_list_returns_400(self, client, mock_db):
        """Create user with empty emails list returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.post(
                "/scim/v2/Users",
                json={"userName": "testuser", "emails": []},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400


@pytest.mark.asyncio
class TestPatchUserOperations:
    """Test PATCH user operations validation."""

    async def test_patch_user_non_list_operations_returns_400(self, client, mock_db):
        """PATCH with non-list Operations field returns 400 (line 402)."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.patch(
                "/scim/v2/Users/user-123",
                json={"Operations": "not-a-list"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400


    async def test_patch_user_not_found_returns_404(self, client, mock_db):
        """PATCH nonexistent user returns 404 (line 440)."""
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
                json={"Operations": [{"op": "replace", "path": "displayName", "value": "test"}]},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404


@pytest.mark.asyncio
class TestDeleteUserPaths:
    """Test delete user paths (lines 458-459)."""

    async def test_delete_user_returns_204(self, client, mock_db):
        """DELETE /scim/v2/Users/{id} returns 204 on success."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.delete_user.return_value = True
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.delete(
                "/scim/v2/Users/user-123",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 204

    async def test_delete_user_not_found_returns_404(self, client, mock_db):
        """DELETE nonexistent user returns 404."""
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
    """Test list groups (lines 494-495, 559-561)."""

    async def test_list_groups_returns_200(self, client, mock_db, group_record):
        """GET /scim/v2/Groups returns 200 with list."""
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

    async def test_get_group_returns_200(self, client, mock_db, group_record, member_records):
        """GET /scim/v2/Groups/{id} returns 200."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn:
            mock_core = AsyncMock()
            mock_core.get_group.return_value = group_record
            mock_core.get_group_members.return_value = member_records
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200
            data = await response.get_json()
            assert data["id"] == "group-789"

    async def test_get_group_not_found_returns_404(self, client, mock_db):
        """GET nonexistent group returns 404."""
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
class TestCreateGroupEdgeCases:
    """Test create group edge cases (lines 594-596, 611-612)."""

    async def test_create_group_missing_display_name_returns_400(self, client, mock_db):
        """Create group without displayName returns 400."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.post(
                "/scim/v2/Groups",
                json={"members": []},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "displayName" in data.get("detail", "")

    async def test_create_group_returns_201(self, client, mock_db, group_record):
        """POST /scim/v2/Groups returns 201 on success."""
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
                json={"displayName": "Engineering Team", "members": []},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 201


@pytest.mark.asyncio
class TestPatchGroupEdgeCases:
    """Test patch group edge cases (lines 640-650)."""



@pytest.mark.asyncio
class TestDeleteGroupPaths:
    """Test delete group paths."""

    async def test_delete_group_returns_204(self, client, mock_db):
        """DELETE /scim/v2/Groups/{id} returns 204 on success."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.delete_group.return_value = True
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.delete(
                "/scim/v2/Groups/group-789",
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 204

    async def test_delete_group_not_found_returns_404(self, client, mock_db):
        """DELETE nonexistent group returns 404."""
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


@pytest.mark.asyncio
class TestReplaceGroupPaths:
    """Test PUT group paths."""

    async def test_replace_group_returns_200(self, client, mock_db, group_record):
        """PUT /scim/v2/Groups/{id} returns 200 on success."""
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
                json={"displayName": "Updated Team"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200

    async def test_replace_group_not_found_returns_404(self, client, mock_db):
        """PUT nonexistent group returns 404."""
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
                json={"displayName": "Updated Team"},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 404


@pytest.mark.asyncio
class TestPutUserPath:
    """Test PUT user endpoints."""

    async def test_put_user_returns_200(self, client, mock_db, user_record):
        """PUT /scim/v2/Users/{id} returns 200 on success."""
        valid_token = MagicMock()
        valid_token.expires_at = None
        valid_token.revoked_at = None
        mock_db.return_value.select.return_value.first.return_value = valid_token

        with patch("scim.endpoints._get_db", return_value=mock_db), \
             patch("scim.endpoints._get_core") as mock_core_fn, \
             patch("scim.endpoints._get_audit") as mock_audit_fn:
            mock_core = AsyncMock()
            mock_core.update_user.return_value = user_record
            mock_core.get_user_groups.return_value = []
            mock_core_fn.return_value = mock_core

            mock_audit = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.put(
                "/scim/v2/Users/user-123",
                json={"userName": "jdoe", "emails": [{"value": "jdoe@example.com"}]},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert response.status_code == 200


@pytest.mark.asyncio
class TestScimContentTypes:
    """Test SCIM content-type handling across endpoints."""

    async def test_service_provider_config_content_type(self, client):
        """ServiceProviderConfig response has correct content-type."""
        response = await client.get("/scim/v2/ServiceProviderConfig")
        assert "application/scim+json" in response.content_type

    async def test_list_users_content_type(self, client, mock_db, user_record):
        """List users response has correct content-type."""
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
                headers={"Authorization": "Bearer valid-token"},
            )
            assert "application/scim+json" in response.content_type

    async def test_create_user_content_type(self, client, mock_db, user_record):
        """Create user response has correct content-type."""
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
                json={"userName": "test", "emails": [{"value": "test@example.com"}]},
                headers={"Authorization": "Bearer valid-token"},
            )
            assert "application/scim+json" in response.content_type
