"""Unit tests for manager-new EDR endpoints.

Tests: POST /api/v1/edr/register, /heartbeat, /events, GET /agents, /statistics
Uses Quart test client with SQLite :memory: database.
"""

import pytest

EDR_API_KEY = "test-edr-api-key-long-enough"
EDR_AGENT_ID = "agent-001"

AGENT_REGISTER_DATA = {
    "agent_id": EDR_AGENT_ID,
    "hostname": "workstation-01",
    "ip_address": "10.0.0.50",
    "os_type": "linux",
    "os_version": "Ubuntu 22.04",
    "agent_version": "1.0.0",
}

EDR_HEADERS = {
    "X-API-Key": EDR_API_KEY,
    "X-Agent-ID": EDR_AGENT_ID,
}


@pytest.mark.unit
class TestEDRRegister:
    """POST /api/v1/edr/register"""

    async def test_register_success(self, client):
        """Agent registers successfully with valid API key."""
        response = await client.post(
            "/api/v1/edr/register",
            headers=EDR_HEADERS,
            json=AGENT_REGISTER_DATA,
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert data["agent_id"] == EDR_AGENT_ID
        assert data["status"] == "active"

    async def test_register_missing_api_key(self, client):
        """Missing API key returns 401."""
        response = await client.post(
            "/api/v1/edr/register",
            json=AGENT_REGISTER_DATA,
        )
        assert response.status_code == 401
        data = await response.get_json()
        assert "error" in data

    async def test_register_invalid_api_key(self, client):
        """Short/invalid API key returns 401."""
        response = await client.post(
            "/api/v1/edr/register",
            headers={"X-API-Key": "short"},
            json=AGENT_REGISTER_DATA,
        )
        assert response.status_code == 401

    async def test_register_reregister(self, client):
        """Re-registering existing agent updates it (200)."""
        # Register first time
        await client.post(
            "/api/v1/edr/register",
            headers=EDR_HEADERS,
            json=AGENT_REGISTER_DATA,
        )

        # Re-register
        response = await client.post(
            "/api/v1/edr/register",
            headers=EDR_HEADERS,
            json={**AGENT_REGISTER_DATA, "agent_version": "1.1.0"},
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["agent_id"] == EDR_AGENT_ID
        assert "re-registered" in data["message"].lower()


@pytest.mark.unit
class TestEDRHeartbeat:
    """POST /api/v1/edr/heartbeat"""

    async def test_heartbeat_success(self, client):
        """Registered agent heartbeat succeeds."""
        # Register first
        await client.post(
            "/api/v1/edr/register",
            headers=EDR_HEADERS,
            json=AGENT_REGISTER_DATA,
        )

        # Send heartbeat
        response = await client.post(
            "/api/v1/edr/heartbeat",
            headers=EDR_HEADERS,
            json={
                "agent_id": EDR_AGENT_ID,
                "status": "active",
            },
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["status"] == "ok"
        assert data["agent_id"] == EDR_AGENT_ID

    async def test_heartbeat_unregistered_agent(self, client):
        """Heartbeat from unregistered agent returns 404."""
        response = await client.post(
            "/api/v1/edr/heartbeat",
            headers=EDR_HEADERS,
            json={
                "agent_id": "nonexistent-agent",
                "status": "active",
            },
        )
        assert response.status_code == 404
        data = await response.get_json()
        assert "not registered" in data["error"].lower()


@pytest.mark.unit
class TestEDREvents:
    """POST /api/v1/edr/events"""

    async def test_events_success(self, client):
        """Registered agent can submit events."""
        # Register first
        await client.post(
            "/api/v1/edr/register",
            headers=EDR_HEADERS,
            json=AGENT_REGISTER_DATA,
        )

        # Submit events
        response = await client.post(
            "/api/v1/edr/events",
            headers=EDR_HEADERS,
            json=[
                {
                    "agent_id": EDR_AGENT_ID,
                    "event_type": "process_start",
                    "severity": "low",
                    "process_name": "bash",
                    "process_path": "/usr/bin/bash",
                },
            ],
        )
        assert response.status_code == 202
        data = await response.get_json()
        assert data["status"] == "accepted"
        assert data["events_received"] == 1
        assert data["events_stored"] == 1

    async def test_events_empty_batch(self, client):
        """Empty event batch is accepted."""
        response = await client.post(
            "/api/v1/edr/events",
            headers=EDR_HEADERS,
            json=[],
        )
        assert response.status_code == 202
        data = await response.get_json()
        assert data["events_received"] == 0
        assert data["events_stored"] == 0

    async def test_events_exceeds_batch_limit(self, client):
        """More than 100 events per request returns 400."""
        events = [
            {
                "agent_id": EDR_AGENT_ID,
                "event_type": "process_start",
                "process_name": f"proc-{i}",
            }
            for i in range(101)
        ]
        response = await client.post(
            "/api/v1/edr/events",
            headers=EDR_HEADERS,
            json=events,
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert "100" in data["error"]


@pytest.mark.unit
class TestEDRListAgents:
    """GET /api/v1/edr/agents"""

    async def test_list_agents_admin(self, client, admin_headers, seed_admin_user):
        """Admin can list agents."""
        response = await client.get(
            "/api/v1/edr/agents",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert "items" in data
        assert "total" in data
        assert "page" in data

    async def test_list_agents_viewer_forbidden(self, client, viewer_headers):
        """Viewer cannot list agents (403)."""
        response = await client.get(
            "/api/v1/edr/agents",
            headers=viewer_headers,
        )
        assert response.status_code == 403

    async def test_list_agents_unauthenticated(self, client):
        """Unauthenticated request returns 401."""
        response = await client.get("/api/v1/edr/agents")
        assert response.status_code == 401


@pytest.mark.unit
class TestEDRStatistics:
    """GET /api/v1/edr/statistics"""

    async def test_statistics_empty(self, client, admin_headers, seed_admin_user):
        """Statistics with no agents returns zero counts."""
        response = await client.get(
            "/api/v1/edr/statistics",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["total_agents"] == 0
        assert data["total_events"] == 0
        assert "agents_by_status" in data
        assert "agents_by_os" in data
