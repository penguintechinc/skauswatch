"""Integration tests for service health endpoints.

Tests that each service is reachable and responds to health checks.
Skips gracefully if services are not running.
"""

import pytest


@pytest.mark.integration
@pytest.mark.asyncio
class TestServiceHealth:
    """Health endpoint tests for all SkausWatch services."""

    async def test_manager_health(self, service_urls, manager_service_ready, async_http_client):
        """Test Manager service health endpoint."""
        if not manager_service_ready:
            pytest.skip("Manager service not reachable")

        url = service_urls.get("manager")
        health_endpoint = service_urls.get("manager_health", "/health")
        response = await async_http_client.get(f"{url}{health_endpoint}")
        assert response.status_code == 200

    async def test_pki_health(self, service_urls, pki_service_ready, async_http_client):
        """Test PKI Server health endpoint."""
        if not pki_service_ready:
            pytest.skip("PKI Server not reachable")

        url = service_urls.get("pki")
        health_endpoint = service_urls.get("pki_health", "/health")
        response = await async_http_client.get(f"{url}{health_endpoint}")
        assert response.status_code == 200

    async def test_sshca_health(self, service_urls, sshca_service_ready, async_http_client):
        """Test SSH CA health endpoint."""
        if not sshca_service_ready:
            pytest.skip("SSH CA not reachable")

        url = service_urls.get("sshca")
        health_endpoint = service_urls.get("sshca_health", "/health")
        response = await async_http_client.get(f"{url}{health_endpoint}")
        assert response.status_code == 200

    async def test_monitor_health(self, service_urls, monitor_service_ready, async_http_client):
        """Test Monitor health endpoint."""
        if not monitor_service_ready:
            pytest.skip("Monitor not reachable")

        url = service_urls.get("monitor")
        health_endpoint = service_urls.get("monitor_health", "/health")
        response = await async_http_client.get(f"{url}{health_endpoint}")
        assert response.status_code == 200


@pytest.mark.integration
class TestDependencies:
    """Tests for external service dependencies."""

    def test_postgres_available(self, postgres_reachable):
        """PostgreSQL should be available for tests."""
        if not postgres_reachable:
            pytest.skip("PostgreSQL not available")
        assert postgres_reachable

    def test_redis_available(self, redis_reachable):
        """Redis should be available for tests."""
        if not redis_reachable:
            pytest.skip("Redis not available")
        assert redis_reachable

    def test_minio_available(self, minio_reachable):
        """MinIO should be available for S3 tests."""
        if not minio_reachable:
            pytest.skip("MinIO not available")
        assert minio_reachable
