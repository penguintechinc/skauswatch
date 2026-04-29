"""Integration tests for service health endpoints.

Tests that each service is reachable and responds to health checks.
Skips gracefully if services are not running.
"""

import pytest


@pytest.mark.integration
@pytest.mark.asyncio
class TestServiceHealth:
    """Health endpoint tests for all SkausWatch services."""

    async def test_manager_health(
        self, service_urls, manager_service_ready, async_http_client
    ):
        """Test Manager service health endpoint."""
        if not manager_service_ready:
            pytest.skip("Manager service not reachable")

        url = service_urls.get("manager")
        health_endpoint = service_urls.get("manager_health", "/health")
        response = await async_http_client.get(f"{url}{health_endpoint}")
        assert response.status_code == 200

    async def test_pki_server_health(
        self, service_urls, pki_service_ready, async_http_client
    ):
        """Test PKI Server health endpoint."""
        if not pki_service_ready:
            pytest.skip("PKI Server not reachable")

        url = service_urls.get("pki_server")
        health_endpoint = service_urls.get("pki_server_health", "/health")
        response = await async_http_client.get(f"{url}{health_endpoint}")
        assert response.status_code == 200

    async def test_ssh_ca_health(
        self, service_urls, ssh_ca_service_ready, async_http_client
    ):
        """Test SSH CA health endpoint."""
        if not ssh_ca_service_ready:
            pytest.skip("SSH CA not reachable")

        url = service_urls.get("ssh_ca")
        health_endpoint = service_urls.get("ssh_ca_health", "/health")
        response = await async_http_client.get(f"{url}{health_endpoint}")
        assert response.status_code == 200

    async def test_aaa_monitor_health(
        self, service_urls, aaa_monitor_service_ready, async_http_client
    ):
        """Test AAA Monitor health endpoint."""
        if not aaa_monitor_service_ready:
            pytest.skip("AAA Monitor not reachable")

        url = service_urls.get("aaa_monitor")
        health_endpoint = service_urls.get("aaa_monitor_health", "/health")
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
