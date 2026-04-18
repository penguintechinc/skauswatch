"""
Tests for checkpoint-core SCIM token management API.

Tests /api/v1/scim/tokens endpoints:
- POST /tokens — create token
- GET /tokens — list tokens
- DELETE /tokens/{id} — revoke token

Auth: Bearer JWT with checkpoint:admin scope required
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


class TestCreateSCIMToken:
    """Test POST /api/v1/scim/tokens endpoint."""

    @pytest.mark.asyncio
    async def test_missing_bearer_token(self, client):
        """Missing Authorization header → 401."""
        with (
            patch("api.v1.scim_tokens._get_db", return_value=MagicMock()),
            patch("api.v1.scim_tokens._get_config", return_value=MagicMock()),
            patch("api.v1.scim_tokens._get_audit", return_value=AsyncMock()),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                json={"name": "test token"},
            )

        assert response.status_code == 401
        data = await response.get_json()
        assert data.get("error") == "unauthorized"

    @pytest.mark.asyncio
    async def test_insufficient_scope(self, client):
        """Bearer token without checkpoint:admin scope → 403."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        # Mock token verification to return claims without checkpoint:admin
        mock_claims = {
            "sub": "user-123",
            "scope": "read write",  # Missing checkpoint:admin
        }

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
                json={"name": "test token"},
            )

        assert response.status_code == 403
        data = await response.get_json()
        assert "insufficient_scope" in data.get("error", "")

    @pytest.mark.asyncio
    async def test_missing_name(self, client):
        """Missing name in request → 400."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
                json={"name": ""},  # Empty name
            )

        assert response.status_code == 400
        data = await response.get_json()
        assert data.get("error") == "name is required"

    @pytest.mark.asyncio
    async def test_empty_name_stripped(self, client):
        """Name with only whitespace → 400."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
                json={"name": "   "},  # Whitespace only
            )

        assert response.status_code == 400
        data = await response.get_json()
        assert data.get("error") == "name is required"

    @pytest.mark.asyncio
    async def test_invalid_expires_at_format(self, client):
        """Invalid ISO8601 expires_at → 400."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
                json={
                    "name": "test token",
                    "expires_at": "not-a-date",
                },
            )

        assert response.status_code == 400
        data = await response.get_json()
        assert "expires_at must be a valid ISO8601" in data.get("error", "")

    @pytest.mark.asyncio
    async def test_successful_create_with_defaults(self, client):
        """Valid token creation with defaults → 201 with token value."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        # Mock DB insert to return a token ID
        mock_db.checkpoint_scim_tokens.insert.return_value = 1
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
            patch("api.v1.scim_tokens.secrets.token_urlsafe", return_value="test_raw_token_123"),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
                json={"name": "My SCIM Token"},
            )

        assert response.status_code == 201
        data = await response.get_json()

        assert data["token"] == "test_raw_token_123"
        assert data["token_id"] == 1
        assert data["name"] == "My SCIM Token"
        assert "scim:users:read" in data["scopes"]
        assert "scim:users:write" in data["scopes"]
        assert "expires_at" in data
        assert "created_at" in data

        # Verify DB insert was called
        mock_db.checkpoint_scim_tokens.insert.assert_called_once()
        call_kwargs = mock_db.checkpoint_scim_tokens.insert.call_args[1]
        assert call_kwargs["name"] == "My SCIM Token"
        assert call_kwargs["created_by_uuid"] == "user-123"

    @pytest.mark.asyncio
    async def test_successful_create_with_custom_scopes(self, client):
        """Token creation with custom scopes → 201."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-456",
            "scope": "checkpoint:admin",
        }

        mock_db.checkpoint_scim_tokens.insert.return_value = 2
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
            patch("api.v1.scim_tokens.secrets.token_urlsafe", return_value="custom_token"),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
                json={
                    "name": "Read-only Token",
                    "scopes": "scim:users:read scim:groups:read",
                },
            )

        assert response.status_code == 201
        data = await response.get_json()
        assert data["scopes"] == "scim:users:read scim:groups:read"

    @pytest.mark.asyncio
    async def test_successful_create_with_expiry(self, client):
        """Token creation with expires_at → 201."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-789",
            "scope": "checkpoint:admin",
        }

        mock_db.checkpoint_scim_tokens.insert.return_value = 3
        mock_db.commit = MagicMock()

        expires_iso = "2026-12-31T23:59:59Z"

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
            patch("api.v1.scim_tokens.secrets.token_urlsafe", return_value="expiring_token"),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
                json={
                    "name": "Temporary Token",
                    "expires_at": expires_iso,
                },
            )

        assert response.status_code == 201
        data = await response.get_json()
        assert "expires_at" in data
        assert data["expires_at"].startswith("2026-12-31")

        # Verify expires_at was set in DB insert
        call_kwargs = mock_db.checkpoint_scim_tokens.insert.call_args[1]
        assert call_kwargs["expires_at"] is not None

    @pytest.mark.asyncio
    async def test_db_insert_error(self, client):
        """DB insert fails → 500."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        # Simulate DB error
        mock_db.checkpoint_scim_tokens.insert.side_effect = Exception("DB connection failed")

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
            patch("api.v1.scim_tokens.secrets.token_urlsafe", return_value="token"),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
                json={"name": "test token"},
            )

        assert response.status_code == 500
        data = await response.get_json()
        assert "error" in data

    @pytest.mark.asyncio
    async def test_audit_log_on_create(self, client):
        """Token creation triggers audit log."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        mock_db.checkpoint_scim_tokens.insert.return_value = 1
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
            patch("api.v1.scim_tokens.secrets.token_urlsafe", return_value="token"),
        ):
            response = await client.post(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
                json={"name": "Audited Token"},
            )

        assert response.status_code == 201

        # Verify audit.log was called
        mock_audit.log.assert_called_once()
        call_args = mock_audit.log.call_args
        assert call_args[0][0] == "scim.token_created"
        assert call_args[1]["actor_uuid"] == "user-123"


class TestListSCIMTokens:
    """Test GET /api/v1/scim/tokens endpoint."""

    @pytest.mark.asyncio
    async def test_missing_bearer_token(self, client):
        """Missing Authorization header → 401."""
        with (
            patch("api.v1.scim_tokens._get_db", return_value=MagicMock()),
        ):
            response = await client.get("/api/v1/scim/tokens")

        assert response.status_code == 401
        data = await response.get_json()
        assert data.get("error") == "unauthorized"

    @pytest.mark.asyncio
    async def test_insufficient_scope(self, client, mock_db):
        """Bearer token without checkpoint:admin scope → 403."""
        mock_config = MagicMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "read",
        }

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.get(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
            )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_empty_list(self, client, mock_db):
        """No tokens in DB → 200 with empty list."""
        mock_config = MagicMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        # Mock DB query returns empty
        mock_db.return_value.select.return_value = []

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.get(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["tokens"] == []

    @pytest.mark.asyncio
    async def test_list_with_tokens(self, client, mock_db):
        """Tokens in DB → 200 with token list."""
        mock_config = MagicMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        expires = now + timedelta(days=30)

        mock_token_1 = MagicMock()
        mock_token_1.id = 1
        mock_token_1.name = "Token 1"
        mock_token_1.scopes = "scim:users:read"
        mock_token_1.expires_at = expires
        mock_token_1.revoked_at = None
        mock_token_1.created_at = now
        mock_token_1.created_by_uuid = "user-123"

        mock_token_2 = MagicMock()
        mock_token_2.id = 2
        mock_token_2.name = "Token 2"
        mock_token_2.scopes = "scim:groups:read"
        mock_token_2.expires_at = None
        mock_token_2.revoked_at = None
        mock_token_2.created_at = now
        mock_token_2.created_by_uuid = "user-456"

        mock_query = MagicMock()
        mock_query.select.return_value = [mock_token_1, mock_token_2]
        mock_db.return_value = mock_query

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.get(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()

        assert len(data["tokens"]) == 2
        assert data["tokens"][0]["token_id"] == 1
        assert data["tokens"][0]["name"] == "Token 1"
        assert data["tokens"][1]["token_id"] == 2
        assert data["tokens"][1]["expires_at"] is None

    @pytest.mark.asyncio
    async def test_list_includes_revoked_at(self, client, mock_db):
        """List includes revoked_at timestamp."""
        mock_config = MagicMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        now = datetime.now(tz=timezone.utc).replace(tzinfo=None)
        revoked = now - timedelta(hours=1)

        mock_token = MagicMock()
        mock_token.id = 5
        mock_token.name = "Revoked Token"
        mock_token.scopes = "scim:users:read"
        mock_token.expires_at = None
        mock_token.revoked_at = revoked
        mock_token.created_at = now
        mock_token.created_by_uuid = "user-789"

        mock_query = MagicMock()
        mock_query.select.return_value = [mock_token]
        mock_db.return_value = mock_query

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.get(
                "/api/v1/scim/tokens",
                headers={"Authorization": "Bearer mock_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["tokens"][0]["revoked_at"] is not None


class TestRevokeSCIMToken:
    """Test DELETE /api/v1/scim/tokens/{id} endpoint."""

    @pytest.mark.asyncio
    async def test_missing_bearer_token(self, client):
        """Missing Authorization header → 401."""
        with patch("api.v1.scim_tokens._get_db", return_value=MagicMock()):
            response = await client.delete("/api/v1/scim/tokens/1")

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_insufficient_scope(self, client):
        """Bearer token without checkpoint:admin → 403."""
        mock_db = MagicMock()
        mock_config = MagicMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "read",
        }

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.delete(
                "/api/v1/scim/tokens/1",
                headers={"Authorization": "Bearer mock_token"},
            )

        assert response.status_code == 403

    @pytest.mark.asyncio
    async def test_token_not_found(self, client):
        """Token ID not in DB → 404."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        # Mock query returns None
        mock_query = MagicMock()
        mock_query.select.return_value.first.return_value = None
        mock_db.return_value = mock_query

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.delete(
                "/api/v1/scim/tokens/999",
                headers={"Authorization": "Bearer mock_token"},
            )

        assert response.status_code == 404
        data = await response.get_json()
        assert data.get("error") == "token not found"

    @pytest.mark.asyncio
    async def test_already_revoked(self, client):
        """Revoking already-revoked token → 409."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

        mock_token = MagicMock()
        mock_token.id = 1
        mock_token.name = "Already Revoked"
        mock_token.revoked_at = now - timedelta(hours=1)  # Already revoked

        mock_query = MagicMock()
        mock_query.select.return_value.first.return_value = mock_token
        mock_db.return_value = mock_query

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.delete(
                "/api/v1/scim/tokens/1",
                headers={"Authorization": "Bearer mock_token"},
            )

        assert response.status_code == 409
        data = await response.get_json()
        assert data.get("error") == "token already revoked"

    @pytest.mark.asyncio
    async def test_successful_revoke(self, client):
        """Valid token revoke → 200."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-123",
            "scope": "checkpoint:admin",
        }

        mock_token = MagicMock()
        mock_token.id = 1
        mock_token.name = "Active Token"
        mock_token.revoked_at = None

        mock_query = MagicMock()
        mock_query.select.return_value.first.return_value = mock_token
        mock_db.return_value = mock_query
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.delete(
                "/api/v1/scim/tokens/1",
                headers={"Authorization": "Bearer mock_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data.get("status") == "revoked"
        assert data.get("token_id") == 1

        # Verify DB update was called
        mock_db.return_value.update.assert_called_once()

    @pytest.mark.asyncio
    async def test_audit_log_on_revoke(self, client):
        """Token revocation triggers audit log."""
        mock_db = MagicMock()
        mock_config = MagicMock()
        mock_audit = AsyncMock()

        mock_claims = {
            "sub": "user-456",
            "scope": "checkpoint:admin",
        }

        mock_token = MagicMock()
        mock_token.id = 1
        mock_token.name = "Audited Revoke"
        mock_token.revoked_at = None

        mock_query = MagicMock()
        mock_query.select.return_value.first.return_value = mock_token
        mock_db.return_value = mock_query
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.scim_tokens._get_db", return_value=mock_db),
            patch("api.v1.scim_tokens._get_config", return_value=mock_config),
            patch("api.v1.scim_tokens._get_audit", return_value=mock_audit),
            patch("api.v1.scim_tokens.verify_token", return_value=mock_claims),
        ):
            response = await client.delete(
                "/api/v1/scim/tokens/1",
                headers={"Authorization": "Bearer mock_token"},
            )

        assert response.status_code == 200

        # Verify audit.log was called
        mock_audit.log.assert_called_once()
        call_args = mock_audit.log.call_args
        assert call_args[0][0] == "scim.token_revoked"
        assert call_args[1]["actor_uuid"] == "user-456"
