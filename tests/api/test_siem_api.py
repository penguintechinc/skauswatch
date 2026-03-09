"""Tests for the SIEM API blueprint (/api/v1/siem/*)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

pytestmark = pytest.mark.api


class TestSIEMHealth:
    async def test_health_ok(self, siem_client):
        mock_response = MagicMock()
        mock_response.status_code = 200
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_response):
            resp = await siem_client.get("/api/v1/siem/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["log_receiver"] == "ok"
        assert data["status"] == "ok"

    async def test_health_receiver_down(self, siem_client):
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock, side_effect=Exception("Connection refused")):
            resp = await siem_client.get("/api/v1/siem/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["log_receiver"] == "unavailable"
        assert data["status"] == "degraded"


class TestSIEMConfig:
    async def test_get_config(self, siem_client):
        resp = await siem_client.get("/api/v1/siem/config")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "retention_days" in data
        assert "enabled" in data
        assert "free_tier_user_cap" in data

    async def test_update_retention_valid(self, siem_client):
        resp = await siem_client.put(
            "/api/v1/siem/config",
            json={"retention_days": 120},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["retention_days"] == 120

    async def test_update_retention_exceeds_max(self, siem_client):
        resp = await siem_client.put(
            "/api/v1/siem/config",
            json={"retention_days": 401},
        )
        assert resp.status_code == 400

    async def test_update_retention_below_min(self, siem_client):
        resp = await siem_client.put(
            "/api/v1/siem/config",
            json={"retention_days": 0},
        )
        assert resp.status_code == 400

    async def test_update_retention_wrong_type(self, siem_client):
        resp = await siem_client.put(
            "/api/v1/siem/config",
            json={"retention_days": "ninety"},
        )
        assert resp.status_code == 400


@pytest.fixture
def siem_client(manager_test_client, admin_token):
    """Authenticated test client for SIEM endpoints (admin role)."""
    manager_test_client.headers["Authorization"] = f"Bearer {admin_token}"
    return manager_test_client
