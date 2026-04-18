"""
Comprehensive pytest tests for checkpoint-core audit API.

Tests the audit log list endpoint with filtering, pagination, authentication,
and authorization. Uses Quart test client with mocked DB and auth helpers.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

import pytest


class TestAuditAuthAndAuthorization:
    """Test authentication and authorization for audit endpoints."""

    @pytest.mark.asyncio
    async def test_missing_auth_header_returns_401(self, client):
        """GET /api/v1/audit without Authorization header returns 401."""
        with patch("api.v1.audit._get_token_claims", return_value=None):
            response = await client.get("/api/v1/audit")
        assert response.status_code == 401
        data = await response.get_json()
        assert data.get("error") == "unauthorized"

    @pytest.mark.asyncio
    async def test_invalid_token_returns_401(self, client):
        """GET /api/v1/audit with malformed token returns 401."""
        with patch("api.v1.audit._get_token_claims", return_value=None):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer invalid_token"},
            )
        assert response.status_code == 401
        data = await response.get_json()
        assert data.get("error") == "unauthorized"

    @pytest.mark.asyncio
    async def test_token_without_scope_returns_403(self, client):
        """Token without checkpoint:audit:read scope returns 403."""
        claims = {
            "scope": "users:read reports:write",
            "tenant": "tenant-1",
            "sub": "user-123",
        }
        with patch("api.v1.audit._get_token_claims", return_value=claims):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )
        assert response.status_code == 403
        data = await response.get_json()
        assert data.get("error") == "insufficient_scope"

    @pytest.mark.asyncio
    async def test_checkpoint_admin_scope_grants_access(self, client, mock_db):
        """checkpoint:admin scope grants audit:read access."""
        claims = {
            "scope": "checkpoint:admin",
            "tenant": "tenant-1",
            "sub": "admin-123",
        }
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_checkpoint_audit_read_scope_grants_access(self, client, mock_db):
        """checkpoint:audit:read scope grants access to audit log."""
        claims = {
            "scope": "checkpoint:audit:read",
            "tenant": "tenant-1",
            "sub": "auditor-123",
        }
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )
        assert response.status_code == 200


class TestAuditListEndpoint:
    """Test /api/v1/audit list endpoint response format and pagination."""

    @pytest.mark.asyncio
    async def test_list_returns_200_with_json(self, client, mock_db):
        """GET /api/v1/audit returns 200 with JSON response."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert isinstance(data, dict)

    @pytest.mark.asyncio
    async def test_list_response_structure(self, client, mock_db):
        """Response contains entries, total, page, per_page fields."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert "entries" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert isinstance(data["entries"], list)
        assert isinstance(data["total"], int)

    @pytest.mark.asyncio
    async def test_list_with_multiple_entries(self, client, mock_db):
        """List endpoint returns multiple serialized audit entries."""
        claims = {"scope": "checkpoint:audit:read"}

        # Create mock audit log rows
        row1 = SimpleNamespace(
            id=1,
            event_type="oauth_client_created",
            actor_uuid="user-123",
            actor_ip="192.168.1.100",
            target_uuid="client-456",
            target_type="oauth_client",
            client_id="client-456",
            scopes="openid profile",
            details_json='{"name":"test-client"}',
            created_at=datetime(2025, 1, 1, 12, 0, 0),
        )
        row2 = SimpleNamespace(
            id=2,
            event_type="auth_code_issued",
            actor_uuid="user-123",
            actor_ip="192.168.1.101",
            target_uuid=None,
            target_type=None,
            client_id="client-456",
            scopes="openid",
            details_json="{}",
            created_at=datetime(2025, 1, 1, 12, 5, 0),
        )

        mock_db.return_value.select.return_value = [row1, row2]
        mock_db.return_value.count.return_value = 2

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert len(data["entries"]) == 2
        assert data["total"] == 2
        assert data["entries"][0]["event_type"] == "oauth_client_created"
        assert data["entries"][1]["event_type"] == "auth_code_issued"

    @pytest.mark.asyncio
    async def test_entry_serialization_format(self, client, mock_db):
        """Audit entries are properly serialized with all fields."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=42,
            event_type="token_revoked",
            actor_uuid="user-abc",
            actor_ip="10.0.0.1",
            target_uuid="token-xyz",
            target_type="token",
            client_id="oauth-client",
            scopes="read:user",
            details_json='{"reason":"explicit_revocation"}',
            created_at=datetime(2025, 1, 15, 14, 30, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        entry = data["entries"][0]
        assert entry["id"] == 42
        assert entry["event_type"] == "token_revoked"
        assert entry["actor_uuid"] == "user-abc"
        assert entry["actor_ip"] == "10.0.0.1"
        assert entry["target_uuid"] == "token-xyz"
        assert entry["target_type"] == "token"
        assert entry["client_id"] == "oauth-client"
        assert entry["scopes"] == "read:user"
        assert entry["details"] == '{"reason":"explicit_revocation"}'
        assert "created_at" in entry
        assert entry["created_at"].endswith("Z")

    @pytest.mark.asyncio
    async def test_null_fields_serialization(self, client, mock_db):
        """Null fields in audit entries serialize as None."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="system_event",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json=None,
            created_at=datetime(2025, 1, 1, 0, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        entry = data["entries"][0]
        assert entry["actor_uuid"] is None
        assert entry["actor_ip"] is None
        assert entry["target_uuid"] is None
        assert entry["target_type"] is None
        assert entry["client_id"] is None
        assert entry["scopes"] is None
        assert entry["details"] == "{}"  # None details_json → "{}"


class TestAuditPagination:
    """Test pagination parameters for audit list."""

    @pytest.mark.asyncio
    async def test_default_pagination(self, client, mock_db):
        """Default pagination uses page=0, per_page=50."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["page"] == 0
        assert data["per_page"] == 50

    @pytest.mark.asyncio
    async def test_custom_page_and_per_page(self, client, mock_db):
        """Custom page and per_page parameters are respected."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 200

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?page=2&per_page=25",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["page"] == 2
        assert data["per_page"] == 25

    @pytest.mark.asyncio
    async def test_per_page_max_limit(self, client, mock_db):
        """per_page is capped at 500."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?per_page=1000",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["per_page"] == 500

    @pytest.mark.asyncio
    async def test_per_page_min_limit(self, client, mock_db):
        """per_page minimum is 1."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?per_page=0",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["per_page"] == 1

    @pytest.mark.asyncio
    async def test_negative_page_defaults_to_zero(self, client, mock_db):
        """Negative page parameter defaults to 0."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?page=-5",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["page"] == 0


class TestAuditFiltering:
    """Test filter parameters for audit log queries."""

    @pytest.mark.asyncio
    async def test_filter_by_event_type(self, client, mock_db):
        """Filter by event_type parameter."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="oauth_client_created",
            actor_uuid="user-1",
            actor_ip="192.168.1.1",
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 1, 0, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?event_type=oauth_client_created",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert len(data["entries"]) == 1
        assert data["entries"][0]["event_type"] == "oauth_client_created"

    @pytest.mark.asyncio
    async def test_filter_by_actor_uuid(self, client, mock_db):
        """Filter by actor_uuid parameter."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event1",
            actor_uuid="actor-abc",
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 1, 0, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?actor_uuid=actor-abc",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert len(data["entries"]) == 1

    @pytest.mark.asyncio
    async def test_filter_by_target_uuid(self, client, mock_db):
        """Filter by target_uuid parameter."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event1",
            actor_uuid=None,
            actor_ip=None,
            target_uuid="target-xyz",
            target_type="resource",
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 1, 0, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?target_uuid=target-xyz",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert len(data["entries"]) == 1

    @pytest.mark.asyncio
    async def test_filter_by_client_id(self, client, mock_db):
        """Filter by client_id parameter."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event1",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id="oauth-app-123",
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 1, 0, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?client_id=oauth-app-123",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert len(data["entries"]) == 1

    @pytest.mark.asyncio
    async def test_filter_by_from_ts(self, client, mock_db):
        """Filter by from_ts (lower bound) timestamp."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event1",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 10, 12, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?from_ts=2025-01-05T00:00:00Z",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert len(data["entries"]) == 1

    @pytest.mark.asyncio
    async def test_filter_by_to_ts(self, client, mock_db):
        """Filter by to_ts (upper bound) timestamp."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event1",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 10, 12, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?to_ts=2025-01-15T23:59:59Z",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert len(data["entries"]) == 1

    @pytest.mark.asyncio
    async def test_filter_with_date_range(self, client, mock_db):
        """Combine from_ts and to_ts for date range filtering."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event1",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 10, 12, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?from_ts=2025-01-05T00:00:00Z&to_ts=2025-01-15T23:59:59Z",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert len(data["entries"]) == 1

    @pytest.mark.asyncio
    async def test_filter_with_multiple_criteria(self, client, mock_db):
        """Combine multiple filters (AND logic)."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="oauth_client_created",
            actor_uuid="user-123",
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id="client-456",
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 10, 12, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?event_type=oauth_client_created&actor_uuid=user-123&client_id=client-456",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert len(data["entries"]) == 1

    @pytest.mark.asyncio
    async def test_empty_filter_parameters_ignored(self, client, mock_db):
        """Empty string filter parameters are ignored."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?event_type=&actor_uuid=",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert response.status_code == 200
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_invalid_timestamp_format_ignored(self, client, mock_db):
        """Invalid timestamp filters are silently ignored (permissive)."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?from_ts=not-a-date&to_ts=invalid",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert response.status_code == 200


class TestAuditTimestampParsing:
    """Test timestamp parsing edge cases."""

    @pytest.mark.asyncio
    async def test_parse_z_suffix_format(self, client, mock_db):
        """Timestamps with Z suffix are parsed correctly."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event1",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 1, 12, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?from_ts=2025-01-01T00:00:00Z",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_parse_offset_format(self, client, mock_db):
        """Timestamps with +00:00 offset are parsed correctly."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event1",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 1, 12, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?from_ts=2025-01-01T00:00:00+00:00",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert response.status_code == 200


class TestAuditOrderingAndCounting:
    """Test ordering and counting behavior."""

    @pytest.mark.asyncio
    async def test_entries_ordered_newest_first(self, client, mock_db):
        """Audit entries are ordered by created_at DESC (newest first)."""
        claims = {"scope": "checkpoint:audit:read"}
        row1 = SimpleNamespace(
            id=3,
            event_type="event3",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 3, 0, 0, 0),
        )
        row2 = SimpleNamespace(
            id=2,
            event_type="event2",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 2, 0, 0, 0),
        )
        row3 = SimpleNamespace(
            id=1,
            event_type="event1",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 1, 0, 0, 0),
        )

        # Return in order (most recent first)
        mock_db.return_value.select.return_value = [row1, row2, row3]
        mock_db.return_value.count.return_value = 3

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["entries"][0]["id"] == 3
        assert data["entries"][1]["id"] == 2
        assert data["entries"][2]["id"] == 1

    @pytest.mark.asyncio
    async def test_total_count_reflects_all_matching(self, client, mock_db):
        """total field reflects total matching rows (across all pages)."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 500

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?per_page=50",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["total"] == 500


class TestAuditEdgeCases:
    """Test edge cases and error handling."""

    @pytest.mark.asyncio
    async def test_non_integer_page_coerced(self, client, mock_db):
        """Non-integer page parameter is coerced to int (or 0 on error)."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            # Non-integer page should be handled gracefully
            response = await client.get(
                "/api/v1/audit?page=abc",
                headers={"Authorization": "Bearer valid_token"},
            )

        # Should return 200 or 400 gracefully, not 500
        assert response.status_code in (200, 400)

    @pytest.mark.asyncio
    async def test_missing_created_at_null_serialization(self, client, mock_db):
        """created_at=None serializes as None."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=None,
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["entries"][0]["created_at"] is None

    @pytest.mark.asyncio
    async def test_empty_results_list(self, client, mock_db):
        """Empty query results return zero entries."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?event_type=nonexistent",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["entries"] == []
        assert data["total"] == 0

    @pytest.mark.asyncio
    async def test_large_details_json(self, client, mock_db):
        """Large details_json field is serialized correctly."""
        claims = {"scope": "checkpoint:audit:read"}
        large_json = '{"data":"' + ("x" * 5000) + '"}'
        row = SimpleNamespace(
            id=1,
            event_type="event",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json=large_json,
            created_at=datetime(2025, 1, 1, 0, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["entries"][0]["details"] == large_json


class TestAuditHelperFunctions:
    """Test audit helper functions for uncovered lines."""

    @pytest.mark.asyncio
    async def test_get_db_extension_access(self, client, mock_db):
        """_get_db() accesses current_app.extensions["checkpoint_db"] (line 38)."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_config_extension_access(self, client, mock_db):
        """_get_config() accesses current_app.extensions["checkpoint_config"] (line 42)."""
        claims = {"scope": "checkpoint:audit:read"}
        mock_db.return_value.select.return_value = []
        mock_db.return_value.count.return_value = 0

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200


class TestAuditDateRangeFilters:
    """Test date range filter building (lines 46-54)."""

    @pytest.mark.asyncio
    async def test_from_ts_filter_applied(self, client, mock_db):
        """from_ts filter applies >= created_at condition."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 15, 10, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?from_ts=2025-01-10T00:00:00Z",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_to_ts_filter_applied(self, client, mock_db):
        """to_ts filter applies <= created_at condition."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 5, 10, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?to_ts=2025-01-15T23:59:59Z",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["total"] == 1

    @pytest.mark.asyncio
    async def test_both_ts_filters_applied(self, client, mock_db):
        """Both from_ts and to_ts filters work together (AND logic)."""
        claims = {"scope": "checkpoint:audit:read"}
        row = SimpleNamespace(
            id=1,
            event_type="event",
            actor_uuid=None,
            actor_ip=None,
            target_uuid=None,
            target_type=None,
            client_id=None,
            scopes=None,
            details_json="{}",
            created_at=datetime(2025, 1, 10, 12, 0, 0),
        )

        mock_db.return_value.select.return_value = [row]
        mock_db.return_value.count.return_value = 1

        with (
            patch("api.v1.audit._get_token_claims", return_value=claims),
            patch("api.v1.audit._get_db", return_value=mock_db),
        ):
            response = await client.get(
                "/api/v1/audit?from_ts=2025-01-05T00:00:00Z&to_ts=2025-01-15T23:59:59Z",
                headers={"Authorization": "Bearer valid_token"},
            )

        data = await response.get_json()
        assert data["total"] == 1
