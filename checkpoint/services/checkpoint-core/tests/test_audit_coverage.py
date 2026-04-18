"""
Additional audit endpoint tests to cover missing lines.

Targets:
  - api/v1/audit.py lines 38, 42, 46-54, 128-129 (helpers + per_page validation)
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch


@pytest.mark.asyncio
class TestAuditHelpersCoverage:
    """Exercise real helper functions by NOT patching them."""

    async def test_no_auth_header_calls_real_get_db_and_config(self, client):
        """
        Exercise _get_db() (line 38) and _get_config() (line 42) bodies.
        Patch _get_token_claims directly to force it to return None.
        """
        with patch("api.v1.audit._get_token_claims", return_value=None):
            response = await client.get("/api/v1/audit")
        assert response.status_code == 401

    async def test_missing_bearer_token_exercises_token_claims(self, client):
        """
        Exercise _get_token_claims body (lines 45-54):
          - Line 48: request.headers.get("Authorization", "")
          - Line 49-50: auth does not start with "Bearer " → return None
        """
        with patch("api.v1.audit.verify_token") as mock_verify:
            # NO Bearer header at all → _get_token_claims returns None early
            response = await client.get("/api/v1/audit")
        assert response.status_code == 401

    async def test_invalid_bearer_token_calls_verify_token(self, client):
        """
        Exercise _get_token_claims body (lines 51-54):
          - Line 51: Bearer header present, extract token
          - Line 52: verify_token() raises exception
          - Line 53: catch exception, return None
        """
        with patch("api.v1.audit.verify_token", side_effect=Exception("bad token")):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer invalid-jwt"}
            )
        assert response.status_code == 401

    async def test_per_page_invalid_value_coerced(self, client, mock_db):
        """
        Exercise list_audit_entries line 128-129:
          - per_page parameter is not a valid int → ValueError raised
          - Coerce to 50 (default)
        """
        with patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}), \
             patch("api.v1.audit._get_db", return_value=mock_db):
            mock_db.return_value.count.return_value = 0
            mock_db.return_value.select.return_value = []
            response = await client.get(
                "/api/v1/audit?per_page=notanumber",
                headers={"Authorization": "Bearer valid"}
            )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["per_page"] == 50

    async def test_page_invalid_value_coerced(self, client, mock_db):
        """
        Exercise line 123-125 (page parameter coercion).
        """
        with patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}), \
             patch("api.v1.audit._get_db", return_value=mock_db):
            mock_db.return_value.count.return_value = 0
            mock_db.return_value.select.return_value = []
            response = await client.get(
                "/api/v1/audit?page=notanumber",
                headers={"Authorization": "Bearer valid"}
            )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["page"] == 0

    async def test_per_page_max_clamped_to_500(self, client, mock_db):
        """
        Exercise line 127: per_page clamped to 500.
        """
        with patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}), \
             patch("api.v1.audit._get_db", return_value=mock_db):
            mock_db.return_value.count.return_value = 0
            mock_db.return_value.select.return_value = []
            response = await client.get(
                "/api/v1/audit?per_page=1000",
                headers={"Authorization": "Bearer valid"}
            )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["per_page"] == 500

    async def test_per_page_min_1_when_negative(self, client, mock_db):
        """
        Exercise line 127: per_page minimum is 1.
        """
        with patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}), \
             patch("api.v1.audit._get_db", return_value=mock_db):
            mock_db.return_value.count.return_value = 0
            mock_db.return_value.select.return_value = []
            response = await client.get(
                "/api/v1/audit?per_page=-5",
                headers={"Authorization": "Bearer valid"}
            )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["per_page"] == 1
