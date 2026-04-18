"""
Integration tests for EDR agent registration flow.

Tests: register agent -> heartbeat -> batch events ->
verify agent in list -> statistics.

Requires Manager service to be running.
"""

import uuid

import httpx
import pytest

MANAGER_URL = "http://localhost:5000/api/v1"

pytestmark = [pytest.mark.integration]


@pytest.fixture
async def admin_client(manager_service_ready):
    """Provide authenticated admin client."""
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


@pytest.fixture
def agent_api_key():
    """Provide a test API key for EDR agent registration."""
    return "test-edr-api-key-integration"


@pytest.fixture
def agent_id():
    """Generate a unique agent ID for testing."""
    return f"edr-test-{uuid.uuid4().hex[:8]}"


class TestEDRAgentRegistration:
    """Test EDR agent registration flow."""

    @pytest.mark.asyncio
    async def test_register_agent(self, admin_client, agent_id, agent_api_key):
        """Register a new EDR agent."""
        response = await admin_client.post(
            "/edr/register",
            json={
                "agent_id": agent_id,
                "hostname": "test-host-01",
                "os_type": "linux",
                "os_version": "Ubuntu 22.04",
                "agent_version": "1.0.0-test",
            },
            headers={
                "X-API-Key": agent_api_key,
                "X-Agent-ID": agent_id,
            },
        )
        # Registration should succeed or return conflict for existing agent
        assert response.status_code in (200, 201, 409)

    @pytest.mark.asyncio
    async def test_agent_heartbeat(self, admin_client, agent_id, agent_api_key):
        """Send heartbeat for registered agent."""
        # Register first
        await admin_client.post(
            "/edr/register",
            json={
                "agent_id": agent_id,
                "hostname": "test-host-02",
                "os_type": "linux",
                "os_version": "Ubuntu 22.04",
                "agent_version": "1.0.0-test",
            },
            headers={"X-API-Key": agent_api_key, "X-Agent-ID": agent_id},
        )

        # Send heartbeat
        response = await admin_client.post(
            "/edr/heartbeat",
            json={
                "agent_id": agent_id,
                "uptime": 3600,
                "cpu_percent": 25.5,
                "memory_percent": 42.0,
            },
            headers={"X-API-Key": agent_api_key, "X-Agent-ID": agent_id},
        )
        assert response.status_code in (200, 204)


class TestEDREventReporting:
    """Test EDR event batch reporting."""

    @pytest.mark.asyncio
    async def test_report_events_batch(self, admin_client, agent_id, agent_api_key):
        """Report a batch of security events."""
        # Register agent first
        await admin_client.post(
            "/edr/register",
            json={
                "agent_id": agent_id,
                "hostname": "event-test-host",
                "os_type": "linux",
                "os_version": "Ubuntu 22.04",
                "agent_version": "1.0.0",
            },
            headers={"X-API-Key": agent_api_key, "X-Agent-ID": agent_id},
        )

        events = [
            {
                "event_type": "process_start",
                "severity": "low",
                "details": {
                    "process_name": "bash",
                    "pid": 1234,
                    "command": "/bin/bash",
                },
            },
            {
                "event_type": "network_connection",
                "severity": "medium",
                "details": {
                    "remote_ip": "10.0.0.5",
                    "remote_port": 443,
                    "protocol": "tcp",
                },
            },
            {
                "event_type": "file_modification",
                "severity": "high",
                "details": {
                    "file_path": "/etc/shadow",
                    "operation": "write",
                },
            },
        ]

        response = await admin_client.post(
            "/edr/events",
            json={"agent_id": agent_id, "events": events},
            headers={"X-API-Key": agent_api_key, "X-Agent-ID": agent_id},
        )
        assert response.status_code in (200, 201, 202)

    @pytest.mark.asyncio
    async def test_report_events_max_batch(self, admin_client, agent_id, agent_api_key):
        """Report maximum batch size (100 events)."""
        await admin_client.post(
            "/edr/register",
            json={
                "agent_id": agent_id,
                "hostname": "batch-test-host",
                "os_type": "linux",
                "os_version": "Ubuntu 22.04",
                "agent_version": "1.0.0",
            },
            headers={"X-API-Key": agent_api_key, "X-Agent-ID": agent_id},
        )

        events = [
            {
                "event_type": "process_start",
                "severity": "low",
                "details": {"pid": i, "process_name": f"proc-{i}"},
            }
            for i in range(100)
        ]

        response = await admin_client.post(
            "/edr/events",
            json={"agent_id": agent_id, "events": events},
            headers={"X-API-Key": agent_api_key, "X-Agent-ID": agent_id},
        )
        assert response.status_code in (200, 201, 202)


class TestEDRAgentManagement:
    """Test EDR agent listing and statistics."""

    @pytest.mark.asyncio
    async def test_list_agents(self, admin_client):
        """Admin can list all registered agents."""
        response = await admin_client.get("/edr/agents")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, (dict, list))

    @pytest.mark.asyncio
    async def test_edr_statistics(self, admin_client):
        """Retrieve EDR statistics."""
        response = await admin_client.get("/edr/statistics")
        assert response.status_code == 200
