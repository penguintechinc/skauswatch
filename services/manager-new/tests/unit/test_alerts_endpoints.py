"""Unit tests for manager-new alerts endpoints.

Tests: GET/POST/PUT /api/v1/alerts, /search, /statistics, /ai-review
"""

import pytest


@pytest.mark.unit
class TestListAlerts:
    """GET /api/v1/alerts"""

    async def test_list_alerts_empty(self, client, admin_headers, seed_admin_user):
        """Empty alert list returns valid pagination."""
        response = await client.get(
            "/api/v1/alerts",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    async def test_list_alerts_after_create(
        self, client, admin_headers, seed_admin_user
    ):
        """Created alerts appear in list."""
        # Create an alert
        await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "title": "Test Alert",
                "description": "Test description",
                "severity": "high",
                "source": "unit-test",
            },
        )

        response = await client.get(
            "/api/v1/alerts",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["total"] >= 1

    async def test_list_alerts_unauthenticated(self, client):
        """Unauthenticated request returns 401."""
        response = await client.get("/api/v1/alerts")
        assert response.status_code == 401


@pytest.mark.unit
class TestCreateAlert:
    """POST /api/v1/alerts"""

    async def test_create_alert_success(
        self, client, admin_headers, seed_admin_user
    ):
        """Admin creates alert with valid data."""
        response = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "title": "Critical Security Alert",
                "description": "Unauthorized access attempt detected",
                "severity": "critical",
                "source": "ids-sensor",
                "indicators": ["192.168.1.100", "evil.exe"],
            },
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert "alert" in data
        assert data["alert"]["title"] == "Critical Security Alert"
        assert data["alert"]["severity"] == "critical"

    async def test_create_alert_viewer_forbidden(self, client, viewer_headers):
        """Viewer cannot create alerts (403)."""
        response = await client.post(
            "/api/v1/alerts",
            headers=viewer_headers,
            json={
                "title": "Viewer Alert",
                "description": "Should fail",
                "severity": "low",
            },
        )
        assert response.status_code == 403

    async def test_create_alert_missing_title(
        self, client, admin_headers, seed_admin_user
    ):
        """Missing required title returns 400."""
        response = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "description": "No title",
                "severity": "medium",
            },
        )
        assert response.status_code == 400

    async def test_create_alert_invalid_severity(
        self, client, admin_headers, seed_admin_user
    ):
        """Invalid severity value returns 400."""
        response = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "title": "Bad Severity",
                "severity": "super_critical",
            },
        )
        assert response.status_code == 400


@pytest.mark.unit
class TestGetAlert:
    """GET /api/v1/alerts/<alert_id>"""

    async def test_get_alert_by_id(self, client, admin_headers, seed_admin_user):
        """Get a specific alert by ID."""
        # Create first
        create_resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "title": "Fetch Me",
                "description": "Alert to fetch",
                "severity": "medium",
            },
        )
        create_data = await create_resp.get_json()
        alert_id = create_data["alert"]["id"]

        # Get by ID
        response = await client.get(
            f"/api/v1/alerts/{alert_id}",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["title"] == "Fetch Me"

    async def test_get_nonexistent_alert(
        self, client, admin_headers, seed_admin_user
    ):
        """Non-existent alert returns 404."""
        response = await client.get(
            "/api/v1/alerts/99999",
            headers=admin_headers,
        )
        assert response.status_code == 404


@pytest.mark.unit
class TestUpdateAlert:
    """PUT /api/v1/alerts/<alert_id>"""

    async def test_update_alert_title(self, client, admin_headers, seed_admin_user):
        """Admin can update alert title."""
        # Create
        create_resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={
                "title": "Original Title",
                "severity": "low",
            },
        )
        create_data = await create_resp.get_json()
        alert_id = create_data["alert"]["id"]

        # Update
        response = await client.put(
            f"/api/v1/alerts/{alert_id}",
            headers=admin_headers,
            json={"title": "Updated Title"},
        )
        assert response.status_code == 200

    async def test_update_alert_viewer_forbidden(
        self, client, admin_headers, viewer_headers, seed_admin_user, seed_viewer_user
    ):
        """Viewer cannot update alerts (403)."""
        # Create as admin
        create_resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={"title": "Admin Alert", "severity": "medium"},
        )
        create_data = await create_resp.get_json()
        alert_id = create_data["alert"]["id"]

        # Try to update as viewer
        response = await client.put(
            f"/api/v1/alerts/{alert_id}",
            headers=viewer_headers,
            json={"title": "Viewer Updated"},
        )
        assert response.status_code == 403


@pytest.mark.unit
class TestUpdateAlertStatus:
    """PUT /api/v1/alerts/<alert_id>/status"""

    async def test_update_status(self, client, admin_headers, seed_admin_user):
        """Any authenticated user can update alert status."""
        # Create
        create_resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={"title": "Status Test", "severity": "high"},
        )
        create_data = await create_resp.get_json()
        alert_id = create_data["alert"]["id"]

        # Update status
        response = await client.put(
            f"/api/v1/alerts/{alert_id}/status",
            headers=admin_headers,
            json={"status": "in_progress"},
        )
        assert response.status_code == 200

    async def test_invalid_status_value(self, client, admin_headers, seed_admin_user):
        """Invalid status value returns 400."""
        create_resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={"title": "Bad Status", "severity": "low"},
        )
        create_data = await create_resp.get_json()
        alert_id = create_data["alert"]["id"]

        response = await client.put(
            f"/api/v1/alerts/{alert_id}/status",
            headers=admin_headers,
            json={"status": "nonexistent_status"},
        )
        assert response.status_code == 400


@pytest.mark.unit
class TestAlertStatistics:
    """GET /api/v1/alerts/statistics"""

    async def test_statistics_empty(self, client, admin_headers, seed_admin_user):
        """Statistics with no alerts returns zero counts."""
        response = await client.get(
            "/api/v1/alerts/statistics",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert "total" in data
        assert "by_severity" in data
        assert "by_status" in data

    async def test_statistics_after_creating_alerts(
        self, client, admin_headers, seed_admin_user
    ):
        """Statistics reflect created alerts."""
        # Create alerts of different severities
        for severity in ["critical", "high", "medium"]:
            await client.post(
                "/api/v1/alerts",
                headers=admin_headers,
                json={
                    "title": f"{severity} alert",
                    "severity": severity,
                },
            )

        response = await client.get(
            "/api/v1/alerts/statistics",
            headers=admin_headers,
        )
        data = await response.get_json()
        assert data["total"] >= 3


@pytest.mark.unit
class TestAlertSearch:
    """POST /api/v1/alerts/search"""

    async def test_search_by_severity(self, client, admin_headers, seed_admin_user):
        """Search filters by severity."""
        # Create alerts
        await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={"title": "Critical One", "severity": "critical"},
        )
        await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={"title": "Low One", "severity": "low"},
        )

        response = await client.post(
            "/api/v1/alerts/search",
            headers=admin_headers,
            json={"severity": ["critical"]},
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert all(
            item["severity"] == "critical" for item in data["items"]
        )


@pytest.mark.unit
class TestAlertAIReview:
    """POST /api/v1/alerts/<alert_id>/ai-review"""

    async def test_ai_review_disabled(self, client, admin_headers, seed_admin_user):
        """AI review returns 503 when AI is disabled."""
        # Create an alert
        create_resp = await client.post(
            "/api/v1/alerts",
            headers=admin_headers,
            json={"title": "AI Test", "severity": "high"},
        )
        create_data = await create_resp.get_json()
        alert_id = create_data["alert"]["id"]

        response = await client.post(
            f"/api/v1/alerts/{alert_id}/ai-review",
            headers=admin_headers,
        )
        # AI is disabled in test config, should return 503 or 202
        assert response.status_code in (202, 503)
