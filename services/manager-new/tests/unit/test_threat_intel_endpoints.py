"""Unit tests for manager-new threat intelligence endpoints.

Tests: GET/POST/DELETE /api/v1/threat-intel/iocs, /search, /statistics
Uses Quart test client with SQLite :memory: database.
"""

import pytest

IOC_CREATE_DATA = {
    "indicator_type": "ip",
    "value": "192.168.1.100",
    "threat_level": "malware",
    "confidence": 0.85,
    "source": "manual",
    "description": "Suspicious IP",
}


@pytest.mark.unit
class TestListIOCs:
    """GET /api/v1/threat-intel/iocs"""

    async def test_list_iocs_empty(self, client, admin_headers, seed_admin_user):
        """Empty IOC list returns valid pagination."""
        response = await client.get(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    async def test_list_iocs_after_create(
        self, client, admin_headers, seed_admin_user
    ):
        """Created IOCs appear in list."""
        await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json=IOC_CREATE_DATA,
        )

        response = await client.get(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1
        assert data["items"][0]["value"] == "192.168.1.100"

    async def test_list_iocs_unauthenticated(self, client):
        """Unauthenticated request returns 401."""
        response = await client.get("/api/v1/threat-intel/iocs")
        assert response.status_code == 401


@pytest.mark.unit
class TestCreateIOC:
    """POST /api/v1/threat-intel/iocs"""

    async def test_create_ioc_success(
        self, client, admin_headers, seed_admin_user
    ):
        """Admin creates IOC with valid data."""
        response = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json=IOC_CREATE_DATA,
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert "ioc" in data
        assert data["ioc"]["indicator_type"] == "ip"
        assert data["ioc"]["value"] == "192.168.1.100"
        assert data["ioc"]["id"] is not None

    async def test_create_ioc_viewer_forbidden(self, client, viewer_headers):
        """Viewer cannot create IOCs (403)."""
        response = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=viewer_headers,
            json=IOC_CREATE_DATA,
        )
        assert response.status_code == 403

    async def test_create_ioc_invalid_type(
        self, client, admin_headers, seed_admin_user
    ):
        """Invalid indicator type returns 400."""
        response = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json={
                **IOC_CREATE_DATA,
                "indicator_type": "invalid_type",
            },
        )
        assert response.status_code == 400

    async def test_create_ioc_duplicate(
        self, client, admin_headers, seed_admin_user
    ):
        """Duplicate IOC (same type + value) returns 409."""
        # Create first
        await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json=IOC_CREATE_DATA,
        )

        # Attempt duplicate
        response = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json=IOC_CREATE_DATA,
        )
        assert response.status_code == 409
        data = await response.get_json()
        assert "error" in data

    async def test_create_ioc_missing_fields(
        self, client, admin_headers, seed_admin_user
    ):
        """Missing required fields return 400."""
        response = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json={"indicator_type": "ip"},
        )
        assert response.status_code == 400


@pytest.mark.unit
class TestGetIOC:
    """GET /api/v1/threat-intel/iocs/<ioc_id>"""

    async def test_get_ioc_by_id(self, client, admin_headers, seed_admin_user):
        """Get a specific IOC by ID."""
        # Create first
        create_resp = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json=IOC_CREATE_DATA,
        )
        create_data = await create_resp.get_json()
        ioc_id = create_data["ioc"]["id"]

        # Get by ID
        response = await client.get(
            f"/api/v1/threat-intel/iocs/{ioc_id}",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["indicator_type"] == "ip"
        assert data["value"] == "192.168.1.100"
        assert data["confidence"] == 0.85

    async def test_get_nonexistent_ioc(
        self, client, admin_headers, seed_admin_user
    ):
        """Non-existent IOC returns 404."""
        response = await client.get(
            "/api/v1/threat-intel/iocs/99999",
            headers=admin_headers,
        )
        assert response.status_code == 404


@pytest.mark.unit
class TestDeleteIOC:
    """DELETE /api/v1/threat-intel/iocs/<ioc_id>"""

    async def test_delete_ioc_success(
        self, client, admin_headers, seed_admin_user
    ):
        """Admin can delete an IOC."""
        # Create first
        create_resp = await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json=IOC_CREATE_DATA,
        )
        create_data = await create_resp.get_json()
        ioc_id = create_data["ioc"]["id"]

        # Delete
        response = await client.delete(
            f"/api/v1/threat-intel/iocs/{ioc_id}",
            headers=admin_headers,
        )
        assert response.status_code == 200

        # Verify it is gone
        get_resp = await client.get(
            f"/api/v1/threat-intel/iocs/{ioc_id}",
            headers=admin_headers,
        )
        assert get_resp.status_code == 404

    async def test_delete_nonexistent_ioc(
        self, client, admin_headers, seed_admin_user
    ):
        """Deleting non-existent IOC returns 404."""
        response = await client.delete(
            "/api/v1/threat-intel/iocs/99999",
            headers=admin_headers,
        )
        assert response.status_code == 404


@pytest.mark.unit
class TestSearchIOCs:
    """POST /api/v1/threat-intel/iocs/search"""

    async def test_search_by_type(self, client, admin_headers, seed_admin_user):
        """Search filters by indicator type."""
        # Create IP IOC
        await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json=IOC_CREATE_DATA,
        )
        # Create domain IOC
        await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json={
                **IOC_CREATE_DATA,
                "indicator_type": "domain",
                "value": "evil.example.com",
            },
        )

        response = await client.post(
            "/api/v1/threat-intel/iocs/search",
            headers=admin_headers,
            json={"indicator_type": ["ip"]},
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert all(
            item["indicator_type"] == "ip" for item in data["items"]
        )

    async def test_search_by_value(self, client, admin_headers, seed_admin_user):
        """Search filters by value substring."""
        # Create IOC
        await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json=IOC_CREATE_DATA,
        )

        response = await client.post(
            "/api/v1/threat-intel/iocs/search",
            headers=admin_headers,
            json={"query": "192.168"},
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["total"] >= 1
        assert any(
            "192.168" in item["value"] for item in data["items"]
        )


@pytest.mark.unit
class TestTIStatistics:
    """GET /api/v1/threat-intel/statistics"""

    async def test_statistics_empty(self, client, admin_headers, seed_admin_user):
        """Statistics with no IOCs returns zero counts."""
        response = await client.get(
            "/api/v1/threat-intel/statistics",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["total"] == 0
        assert "by_type" in data
        assert "by_threat_level" in data

    async def test_statistics_after_create(
        self, client, admin_headers, seed_admin_user
    ):
        """Statistics reflect created IOCs."""
        await client.post(
            "/api/v1/threat-intel/iocs",
            headers=admin_headers,
            json=IOC_CREATE_DATA,
        )

        response = await client.get(
            "/api/v1/threat-intel/statistics",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["total"] >= 1
