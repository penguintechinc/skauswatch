"""E2E test fixtures and configuration for SkausWatch."""

import os
from typing import Optional
from urllib.parse import urljoin

import pytest
import requests


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers",
        "e2e: mark test as an end-to-end test (skipped if services unavailable)",
    )


def is_service_healthy(url: str, timeout: int = 2) -> bool:
    """Check if a service is healthy by hitting its health endpoint."""
    try:
        response = requests.get(urljoin(url, "/healthz"), timeout=timeout)
        return response.status_code == 200
    except (requests.RequestException, ConnectionError):
        return False


@pytest.fixture(scope="session")
def manager_url() -> str:
    """Manager service base URL."""
    return os.getenv("MANAGER_URL", "http://localhost:5004")


@pytest.fixture(scope="session")
def pki_server_url() -> str:
    """PKI Server service base URL."""
    return os.getenv("PKI_SERVER_URL", "http://localhost:5001")


@pytest.fixture(scope="session")
def ssh_ca_url() -> str:
    """SSH CA service base URL."""
    return os.getenv("SSH_CA_URL", "http://localhost:5002")


@pytest.fixture(scope="session")
def aaa_monitor_url() -> str:
    """AAA Monitor service base URL."""
    return os.getenv("AAA_MONITOR_URL", "http://localhost:5003")


@pytest.fixture(scope="session")
def minio_url() -> str:
    """MinIO service base URL (S3-compatible storage)."""
    return os.getenv("MINIO_URL", "http://localhost:9020")


@pytest.fixture(scope="session")
def minio_credentials() -> dict:
    """MinIO access credentials."""
    return {
        "access_key": os.getenv("MINIO_ACCESS_KEY", "minioadmin"),
        "secret_key": os.getenv("MINIO_SECRET_KEY", "minioadmin"),
    }


@pytest.fixture(scope="session")
def jwt_token() -> Optional[str]:
    """JWT authentication token for API requests."""
    token = os.getenv("JWT_TOKEN")
    return token


def get_auth_headers(token: Optional[str]) -> dict:
    """Build authorization headers."""
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def auth_headers(jwt_token: Optional[str]) -> dict:
    """Authorization headers for API requests."""
    return get_auth_headers(jwt_token)


@pytest.fixture(scope="session", autouse=True)
def check_services_available(
    manager_url: str,
    pki_server_url: str,
    ssh_ca_url: str,
    aaa_monitor_url: str,
) -> dict:
    """Check service availability and skip tests if services are not running."""
    services = {
        "manager": manager_url,
        "pki_server": pki_server_url,
        "ssh_ca": ssh_ca_url,
        "aaa_monitor": aaa_monitor_url,
    }

    available = {}
    for name, url in services.items():
        available[name] = is_service_healthy(url)

    if not any(available.values()):
        pytest.skip(
            "No services available. Start services with 'make dev' or 'docker-compose up'",
            allow_module_level=True,
        )

    return available
