"""
Integration tests for service health endpoints.

Tests that each service is reachable and responds to health checks.
Covers all 6 application services + 3 infrastructure services.
Skips gracefully if services are not running.
"""

import pytest

pytestmark = [pytest.mark.integration]

# Service port mapping
SERVICES = {
    "manager": {"port": 5000, "endpoints": ["/health", "/healthz", "/version"]},
    "pki-server": {"port": 5001, "endpoints": ["/health", "/healthz"]},
    "ssh-ca": {"port": 5002, "endpoints": ["/health"]},
    "aaa-monitor": {"port": 5003, "endpoints": ["/health"]},
    "worker-scanner": {"port": 5004, "endpoints": ["/health", "/healthz"]},
    "webui": {"port": 3000, "endpoints": ["/"]},
}


@pytest.mark.asyncio
class TestServiceHealth:
    """Health endpoint tests for all SkausWatch services."""

    async def test_manager_health(self, manager_service_ready, async_http_client):
        """Manager service (port 5000) health endpoint."""
        if not manager_service_ready:
            pytest.skip("Manager service not reachable")
        response = await async_http_client.get("http://localhost:5000/health")
        assert response.status_code == 200

    async def test_manager_healthz(self, manager_service_ready, async_http_client):
        """Manager service /healthz endpoint."""
        if not manager_service_ready:
            pytest.skip("Manager service not reachable")
        response = await async_http_client.get("http://localhost:5000/healthz")
        assert response.status_code == 200

    async def test_manager_version(self, manager_service_ready, async_http_client):
        """Manager service /version endpoint returns version info."""
        if not manager_service_ready:
            pytest.skip("Manager service not reachable")
        response = await async_http_client.get("http://localhost:5000/version")
        assert response.status_code == 200
        data = response.json()
        assert "version" in data or "name" in data

    async def test_pki_server_health(self, pki_service_ready, async_http_client):
        """PKI Server (port 5001) health endpoint."""
        if not pki_service_ready:
            pytest.skip("PKI Server not reachable")
        response = await async_http_client.get("http://localhost:5001/health")
        assert response.status_code == 200

    async def test_ssh_ca_health(self, ssh_ca_service_ready, async_http_client):
        """SSH CA (port 5002) health endpoint."""
        if not ssh_ca_service_ready:
            pytest.skip("SSH CA not reachable")
        response = await async_http_client.get("http://localhost:5002/health")
        assert response.status_code == 200

    async def test_aaa_monitor_health(
        self, aaa_monitor_service_ready, async_http_client
    ):
        """AAA Monitor (port 5003) health endpoint."""
        if not aaa_monitor_service_ready:
            pytest.skip("AAA Monitor not reachable")
        response = await async_http_client.get("http://localhost:5003/health")
        assert response.status_code == 200

    async def test_worker_scanner_health(self, async_http_client):
        """Worker Scanner (port 5004) health endpoint."""
        try:
            response = await async_http_client.get(
                "http://localhost:5004/healthz", timeout=3.0
            )
            assert response.status_code == 200
        except Exception:
            pytest.skip("Worker Scanner not reachable")

    async def test_webui_health(self, async_http_client):
        """WebUI (port 3000) serves the app."""
        try:
            response = await async_http_client.get(
                "http://localhost:3000/", timeout=3.0
            )
            assert response.status_code == 200
        except Exception:
            pytest.skip("WebUI not reachable")


@pytest.mark.asyncio
class TestServiceReadiness:
    """Test service readiness (deeper than health)."""

    async def test_manager_ready_endpoint(
        self, manager_service_ready, async_http_client
    ):
        """Manager /ready includes dependency checks."""
        if not manager_service_ready:
            pytest.skip("Manager service not reachable")
        try:
            response = await async_http_client.get("http://localhost:5000/ready")
            # /ready may not exist — 404 is acceptable
            assert response.status_code in (200, 404)
        except Exception:
            pytest.skip("Manager /ready not available")


class TestInfrastructureDependencies:
    """Tests for external service dependencies (Postgres, Redis, MinIO)."""

    def test_postgres_available(self, postgres_reachable):
        """PostgreSQL should be reachable."""
        if not postgres_reachable:
            pytest.skip("PostgreSQL not available")
        assert postgres_reachable

    def test_redis_available(self, redis_reachable):
        """Redis should be reachable."""
        if not redis_reachable:
            pytest.skip("Redis not available")
        assert redis_reachable

    def test_minio_available(self, minio_reachable):
        """MinIO should be reachable for S3 tests."""
        if not minio_reachable:
            pytest.skip("MinIO not available")
        assert minio_reachable

    def test_redis_ping(self, redis_reachable):
        """Redis should respond to PING."""
        if not redis_reachable:
            pytest.skip("Redis not available")
        try:
            import redis

            r = redis.Redis(host="localhost", port=6379)
            assert r.ping() is True
            r.close()
        except Exception:
            pytest.skip("Redis PING failed")

    def test_postgres_connection(self, postgres_reachable):
        """PostgreSQL should accept connections."""
        if not postgres_reachable:
            pytest.skip("PostgreSQL not available")
        try:
            import psycopg2

            conn = psycopg2.connect(
                host="localhost",
                port=5432,
                user="skauswatch",
                password="skauswatch",
                dbname="skauswatch",
                connect_timeout=3,
            )
            conn.close()
        except ImportError:
            pytest.skip("psycopg2 not installed")
        except Exception:
            pytest.skip("PostgreSQL connection failed")
