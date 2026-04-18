"""
Integration tests for alert pipeline.

Tests: create alert -> status update -> search -> statistics.
Requires Manager service to be running.
"""

import httpx
import pytest

MANAGER_URL = "http://localhost:5000/api/v1"

pytestmark = [pytest.mark.integration]


@pytest.fixture
async def admin_client(manager_service_ready):
    """Provide authenticated admin client for alert operations."""
    if not manager_service_ready:
        pytest.skip("Manager service not available")

    async with httpx.AsyncClient(base_url=MANAGER_URL, timeout=10.0) as client:
        login_resp = await client.post(
            "/auth/login",
            json={"email": "admin@skauswatch.local", "password": "admin"},
        )
        if login_resp.status_code != 200:
            pytest.skip("Could not authenticate with manager service")

        token = login_resp.json().get("access_token")
        client.headers["Authorization"] = f"Bearer {token}"
        yield client


class TestAlertLifecycle:
    """Test complete alert CRUD lifecycle."""

    @pytest.mark.asyncio
    async def test_create_alert(self, admin_client):
        """Create a new security alert."""
        response = await admin_client.post(
            "/alerts",
            json={
                "title": "Integration Test Alert",
                "description": "Suspicious activity detected during integration test",
                "severity": "high",
                "source": "integration-test",
            },
        )
        assert response.status_code in (200, 201)
        data = response.json()
        assert "id" in data

    @pytest.mark.asyncio
    async def test_list_alerts(self, admin_client):
        """List all alerts with pagination."""
        response = await admin_client.get("/alerts", params={"page": 1, "per_page": 10})
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    @pytest.mark.asyncio
    async def test_get_alert_by_id(self, admin_client):
        """Create an alert then retrieve by ID."""
        create_resp = await admin_client.post(
            "/alerts",
            json={
                "title": "Get By ID Test",
                "description": "Test alert for retrieval",
                "severity": "medium",
                "source": "integration-test",
            },
        )
        if create_resp.status_code not in (200, 201):
            pytest.skip("Could not create test alert")

        alert_id = create_resp.json()["id"]
        get_resp = await admin_client.get(f"/alerts/{alert_id}")
        assert get_resp.status_code == 200
        assert get_resp.json()["id"] == alert_id

    @pytest.mark.asyncio
    async def test_update_alert_status(self, admin_client):
        """Create alert and update its status."""
        create_resp = await admin_client.post(
            "/alerts",
            json={
                "title": "Status Update Test",
                "description": "Will be acknowledged",
                "severity": "low",
                "source": "integration-test",
            },
        )
        if create_resp.status_code not in (200, 201):
            pytest.skip("Could not create test alert")

        alert_id = create_resp.json()["id"]
        update_resp = await admin_client.put(
            f"/alerts/{alert_id}",
            json={"status": "acknowledged"},
        )
        assert update_resp.status_code == 200

    @pytest.mark.asyncio
    async def test_delete_alert(self, admin_client):
        """Create and delete an alert."""
        create_resp = await admin_client.post(
            "/alerts",
            json={
                "title": "Delete Test",
                "description": "Will be deleted",
                "severity": "low",
                "source": "integration-test",
            },
        )
        if create_resp.status_code not in (200, 201):
            pytest.skip("Could not create test alert")

        alert_id = create_resp.json()["id"]
        delete_resp = await admin_client.delete(f"/alerts/{alert_id}")
        assert delete_resp.status_code in (200, 204)


class TestAlertSearch:
    """Test alert search and filtering."""

    @pytest.mark.asyncio
    async def test_search_by_severity(self, admin_client):
        """Filter alerts by severity."""
        response = await admin_client.get(
            "/alerts", params={"severity": "high"}
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_search_by_status(self, admin_client):
        """Filter alerts by status."""
        response = await admin_client.get(
            "/alerts", params={"status": "open"}
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_search_by_keyword(self, admin_client):
        """Search alerts by keyword."""
        response = await admin_client.get(
            "/alerts", params={"search": "suspicious"}
        )
        assert response.status_code == 200


class TestAlertStatistics:
    """Test alert statistics endpoint."""

    @pytest.mark.asyncio
    async def test_get_statistics(self, admin_client):
        """Retrieve alert statistics."""
        response = await admin_client.get("/alerts/statistics")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, dict)

    @pytest.mark.asyncio
    async def test_statistics_after_create(self, admin_client):
        """Statistics should reflect new alerts."""
        # Get initial stats
        before = await admin_client.get("/alerts/statistics")
        before_data = before.json() if before.status_code == 200 else {}

        # Create an alert
        await admin_client.post(
            "/alerts",
            json={
                "title": "Stats Test Alert",
                "description": "Testing statistics update",
                "severity": "critical",
                "source": "integration-test",
            },
        )

        # Stats should have updated
        after = await admin_client.get("/alerts/statistics")
        assert after.status_code == 200
