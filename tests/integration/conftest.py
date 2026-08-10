"""Integration test fixtures and configuration.

Uses pytest markers to identify tests requiring real infrastructure.
Services are skipped gracefully if not reachable.
Supports both K8s (local-alpha) and Docker Compose deployments.
"""

import asyncio
import atexit
import socket
import subprocess
import time
from collections.abc import Generator

import httpx
import pytest


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: mark test as integration test requiring real services"
    )


def _is_k8s_cluster_accessible() -> bool:
    """Check if kubectl can access local-alpha K8s cluster."""
    try:
        # kubectl resolved via PATH intentionally (dev/CI tooling, not user
        # input); argv list (no shell=True) — nothing here is attacker input.
        result = subprocess.run(  # noqa: S603
            ["kubectl", "--context", "local-alpha", "get", "pods", "-n", "skauswatch"],  # noqa: S607
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _find_free_port() -> int:
    """Find a free local port for port-forwarding."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _setup_port_forward(
    service_name: str, service_port: int, namespace: str = "skauswatch"
) -> tuple[int, subprocess.Popen | None]:
    """Set up kubectl port-forward and return (local_port, process).

    Returns (local_port, process) or (None, None) if setup fails.
    Process is stored globally for cleanup.
    """
    local_port = _find_free_port()
    try:
        # kubectl resolved via PATH intentionally (dev/CI tooling, not user
        # input); argv list (no shell=True) — nothing here is attacker input.
        process = subprocess.Popen(  # noqa: S603
            [  # noqa: S607
                "kubectl",
                "--context",
                "local-alpha",
                "port-forward",
                f"svc/{service_name}",
                f"{local_port}:{service_port}",
                "-n",
                namespace,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Give port-forward a moment to establish
        time.sleep(0.5)
        return local_port, process
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None, None


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
    host: str,
    port: int,
    endpoint: str = "/health",
    timeout: float = 2.0,  # noqa: ASYNC109 - forwarded to httpx.AsyncClient's own timeout, not custom cancellation
) -> bool:
    """Check if an HTTP service is ready by testing health endpoint."""
    url = f"http://{host}:{port}{endpoint}"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url)
            return response.status_code < 500
    except Exception:
        return False


# Global tracking of port-forward processes for cleanup
_port_forward_processes: dict[str, subprocess.Popen] = {}


def _cleanup_port_forwards():
    """Terminate all port-forward processes."""
    for process in _port_forward_processes.values():
        try:
            process.terminate()
            process.wait(timeout=2)
        except Exception:
            process.kill()


atexit.register(_cleanup_port_forwards)


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def k8s_available() -> bool:
    """Check if K8s cluster is accessible."""
    return _is_k8s_cluster_accessible()


@pytest.fixture(scope="session")
def service_urls(k8s_available) -> dict[str, str]:
    """Provide service URLs, using K8s port-forward or localhost fallback."""
    urls = {}

    if k8s_available:
        # Set up port-forwards for K8s services
        services = {
            "manager": ("alpha-manager", 5000, "/healthz"),
            "pki": ("alpha-pki", 5001, "/health"),
            "sshca": ("alpha-sshca", 5002, "/health"),
            "monitor": ("alpha-monitor", 5003, "/health"),
        }

        for service_key, (k8s_service, svc_port, health_endpoint) in services.items():
            local_port, process = _setup_port_forward(k8s_service, svc_port)
            if local_port and process:
                _port_forward_processes[service_key] = process
                urls[service_key] = f"http://localhost:{local_port}"
                # Verify health endpoint is accessible
                endpoint_path = health_endpoint or "/health"
                urls[f"{service_key}_health"] = endpoint_path
            else:
                urls[service_key] = None
    else:
        # Fallback to localhost (Docker Compose or local services)
        urls = {
            "manager": "http://localhost:5000",
            "manager_health": "/healthz",
            "pki": "http://localhost:5001",
            "pki_health": "/health",
            "sshca": "http://localhost:5002",
            "sshca_health": "/health",
            "monitor": "http://localhost:5003",
            "monitor_health": "/health",
        }

    return urls


@pytest.fixture(scope="session")
def postgres_reachable(k8s_available) -> bool:
    """Check if PostgreSQL is reachable."""
    if k8s_available:
        local_port, process = _setup_port_forward("alpha-postgres", 5432)
        if local_port and process:
            _port_forward_processes["postgres"] = process
            reachable = _is_service_reachable("localhost", local_port, timeout=3.0)
            return reachable
    return _is_service_reachable("localhost", 5432, timeout=3.0)


@pytest.fixture(scope="session")
def redis_reachable(k8s_available) -> bool:
    """Check if Redis is reachable."""
    if k8s_available:
        local_port, process = _setup_port_forward("alpha-redis", 6379)
        if local_port and process:
            _port_forward_processes["redis"] = process
            reachable = _is_service_reachable("localhost", local_port, timeout=3.0)
            return reachable
    return _is_service_reachable("localhost", 6379, timeout=3.0)


@pytest.fixture(scope="session")
def minio_reachable(k8s_available) -> bool:
    """Check if MinIO is reachable."""
    if k8s_available:
        local_port, process = _setup_port_forward("alpha-minio", 9000)
        if local_port and process:
            _port_forward_processes["minio"] = process
            reachable = _is_service_reachable("localhost", local_port, timeout=3.0)
            return reachable
    return _is_service_reachable("localhost", 9000, timeout=3.0)


@pytest.fixture(scope="session")
async def manager_service_ready(service_urls) -> bool:
    """Check if Manager service is ready."""
    url = service_urls.get("manager")
    if not url:
        return False
    health_endpoint = service_urls.get("manager_health", "/healthz")
    return await _is_http_service_ready(
        url.replace("http://", "").split(":")[0],
        int(url.split(":")[-1]),
        health_endpoint,
    )


@pytest.fixture(scope="session")
async def pki_service_ready(service_urls) -> bool:
    """Check if PKI Server is ready."""
    url = service_urls.get("pki")
    if not url:
        return False
    health_endpoint = service_urls.get("pki_health", "/health")
    return await _is_http_service_ready(
        url.replace("http://", "").split(":")[0],
        int(url.split(":")[-1]),
        health_endpoint,
    )


@pytest.fixture(scope="session")
async def sshca_service_ready(service_urls) -> bool:
    """Check if SSH CA is ready."""
    url = service_urls.get("sshca")
    if not url:
        return False
    health_endpoint = service_urls.get("sshca_health", "/health")
    return await _is_http_service_ready(
        url.replace("http://", "").split(":")[0],
        int(url.split(":")[-1]),
        health_endpoint,
    )


@pytest.fixture(scope="session")
async def monitor_service_ready(service_urls) -> bool:
    """Check if Monitor is ready."""
    url = service_urls.get("monitor")
    if not url:
        return False
    health_endpoint = service_urls.get("monitor_health", "/health")
    return await _is_http_service_ready(
        url.replace("http://", "").split(":")[0],
        int(url.split(":")[-1]),
        health_endpoint,
    )


@pytest.fixture
def http_client() -> Generator[httpx.Client]:
    """Provide synchronous HTTP client."""
    with httpx.Client() as client:
        yield client


@pytest.fixture
async def async_http_client() -> Generator[httpx.AsyncClient]:
    """Provide asynchronous HTTP client."""
    async with httpx.AsyncClient() as client:
        yield client
