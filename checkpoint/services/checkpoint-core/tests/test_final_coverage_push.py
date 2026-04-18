"""
Additional coverage tests focusing on error paths and edge cases.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

import pytest


@pytest.mark.asyncio
class TestSCIMTokenExpiry:
    """Test SCIM token expiry and revocation checks."""

    async def test_scim_token_expired(self, client, mock_db):
        """Token with expired expires_at is rejected."""
        expired_token = MagicMock()
        expired_token.revoked_at = None
        expired_token.expires_at = datetime(2020, 1, 1, tzinfo=timezone.utc)
        mock_db.select.return_value.first.return_value = expired_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.get(
                "/scim/v2/Users",
                headers={"Authorization": "Bearer expired-token"}
            )
            assert response.status_code == 401

    async def test_scim_token_revoked(self, client, mock_db):
        """Token with revoked_at is rejected."""
        revoked_token = MagicMock()
        revoked_token.revoked_at = datetime.now(tz=timezone.utc)
        revoked_token.expires_at = None
        mock_db.select.return_value.first.return_value = revoked_token

        with patch("scim.endpoints._get_db", return_value=mock_db):
            response = await client.get(
                "/scim/v2/Users",
                headers={"Authorization": "Bearer revoked-token"}
            )
            assert response.status_code == 401

    async def test_scim_empty_bearer_token(self, client):
        """Empty bearer token is rejected."""
        response = await client.get(
            "/scim/v2/Users",
            headers={"Authorization": "Bearer "}
        )
        assert response.status_code == 401


@pytest.mark.asyncio
class TestIDPScopeValidation:
    """Test IDP endpoint scope validation."""

    async def test_idp_insufficient_scope(self, client):
        """Insufficient scope returns 403."""
        with patch("api.v1.idp._get_token_claims", return_value={"scope": "read"}):
            response = await client.get(
                "/api/v1/idps",
                headers={"Authorization": "Bearer test-token"}
            )
            assert response.status_code == 403

    async def test_idp_no_claims(self, client):
        """Missing token claims returns 401."""
        with patch("api.v1.idp._get_token_claims", return_value=None):
            response = await client.get(
                "/api/v1/idps",
                headers={"Authorization": "Bearer invalid-token"}
            )
            assert response.status_code == 401
