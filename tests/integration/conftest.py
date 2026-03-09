"""Integration test fixtures and configuration.

Uses pytest markers to identify tests requiring real infrastructure.
Services are skipped gracefully if not reachable.
"""

import asyncio
import socket
from typing import Generator

import httpx
import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring real services"
    )


def _is_service_reachable(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a service is reachable."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    finally:
        sock.close()


async def _is_http_service_ready(
    host: str, port: int, endpoint: str = "/health", timeout: float = 2.0
) -> bool:
    """Check if an HTTP service is ready by testing health endpoint."""
    url = f"http://{host}:{port}{endpoint}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            return response.status_code < 500
    except Exception:
        return False


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def postgres_reachable() -> bool:
    """Check if PostgreSQL is reachable."""
    return _is_service_reachable("localhost", 5432, timeout=3.0)


@pytest.fixture(scope="session")
def redis_reachable() -> bool:
    """Check if Redis is reachable."""
    return _is_service_reachable("localhost", 6379, timeout=3.0)


@pytest.fixture(scope="session")
def minio_reachable() -> bool:
    """Check if MinIO is reachable."""
    return _is_service_reachable("localhost", 9000, timeout=3.0)


@pytest.fixture(scope="session")
async def manager_service_ready() -> bool:
    """Check if Manager service (port 5000) is ready."""
    return await _is_http_service_ready("localhost", 5000, "/health")


@pytest.fixture(scope="session")
async def pki_service_ready() -> bool:
    """Check if PKI Server (port 5001) is ready."""
    return await _is_http_service_ready("localhost", 5001, "/health")


@pytest.fixture(scope="session")
async def ssh_ca_service_ready() -> bool:
    """Check if SSH CA (port 5002) is ready."""
    return await _is_http_service_ready("localhost", 5002, "/health")


@pytest.fixture(scope="session")
async def aaa_monitor_service_ready() -> bool:
    """Check if AAA Monitor (port 5003) is ready."""
    return await _is_http_service_ready("localhost", 5003, "/health")


@pytest.fixture
def http_client() -> Generator[httpx.Client, None, None]:
    """Provide synchronous HTTP client."""
    with httpx.Client() as client:
        yield client


@pytest.fixture
async def async_http_client() -> Generator[httpx.AsyncClient, None, None]:
    """Provide asynchronous HTTP client."""
    async with httpx.AsyncClient() as client:
        yield client
