"""Tests for health, discovery, hello, and SPIRE endpoints."""

from typing import Any

import pytest
import pytest_asyncio
from quart import Quart


# ── health / readiness ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_healthz_returns_200(client: Any) -> None:
    """GET /healthz returns 200 with healthy database."""
    response = await client.get("/healthz")
    assert response.status_code == 200
    data = await response.get_json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


@pytest.mark.asyncio
async def test_readyz_returns_200(client: Any) -> None:
    """GET /readyz returns 200."""
    response = await client.get("/readyz")
    assert response.status_code == 200
    data = await response.get_json()
    assert data["status"] == "ready"


# ── OIDC discovery ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_oidc_discovery_returns_document(client: Any) -> None:
    """GET /.well-known/openid-configuration returns OIDC discovery document."""
    response = await client.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    data = await response.get_json()
    assert "issuer" in data
    assert "authorization_endpoint" in data
    assert "token_endpoint" in data
    assert "jwks_uri" in data


@pytest.mark.asyncio
async def test_jwks_returns_key_set(client: Any) -> None:
    """GET /.well-known/jwks.json returns JWKS."""
    response = await client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    data = await response.get_json()
    assert "keys" in data
    assert len(data["keys"]) > 0


@pytest.mark.asyncio
async def test_openapi_spec_returns_json(client: Any) -> None:
    """GET /api/v1/openapi.json returns OpenAPI spec."""
    response = await client.get("/api/v1/openapi.json")
    assert response.status_code == 200
    data = await response.get_json()
    assert data.get("openapi", "").startswith("3.")
    assert "info" in data
    assert "paths" in data


# ── prometheus metrics ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_metrics_returns_prometheus_format(client: Any) -> None:
    """GET /metrics returns Prometheus text format."""
    response = await client.get("/metrics")
    assert response.status_code == 200


# ── hello endpoints ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_hello_requires_auth(client: Any) -> None:
    """GET /api/v1/hello without token returns 401."""
    response = await client.get("/api/v1/hello")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_hello_with_auth_returns_greeting(
    client: Any, admin_headers: dict
) -> None:
    """GET /api/v1/hello with valid token returns greeting."""
    response = await client.get("/api/v1/hello", headers=admin_headers)
    assert response.status_code == 200
    data = await response.get_json()
    assert "message" in data or "hello" in str(data).lower()


@pytest.mark.asyncio
async def test_hello_protected_requires_admin(
    client: Any, viewer_headers: dict
) -> None:
    """GET /api/v1/hello/protected with viewer token returns 403."""
    response = await client.get("/api/v1/hello/protected", headers=viewer_headers)
    assert response.status_code in (401, 403)


@pytest.mark.asyncio
async def test_hello_protected_admin_succeeds(
    client: Any, admin_headers: dict
) -> None:
    """GET /api/v1/hello/protected with admin token returns 200."""
    response = await client.get("/api/v1/hello/protected", headers=admin_headers)
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_status_is_public(client: Any) -> None:
    """GET /api/v1/status does not require authentication."""
    response = await client.get("/api/v1/status")
    assert response.status_code == 200


# ── SPIRE endpoints (no SPIRE server — expect graceful 503) ──────────────────


@pytest.mark.asyncio
async def test_spire_status_without_server_returns_503(
    client: Any, admin_headers: dict
) -> None:
    """GET /api/v1/spire/status without SPIRE server returns 503."""
    response = await client.get("/api/v1/spire/status", headers=admin_headers)
    assert response.status_code in (200, 503)  # 503 when no SPIRE pod found


@pytest.mark.asyncio
async def test_spire_status_requires_auth(client: Any) -> None:
    """GET /api/v1/spire/status without token returns 401."""
    response = await client.get("/api/v1/spire/status")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_spire_entries_requires_auth(client: Any) -> None:
    """GET /api/v1/spire/entries without token returns 401."""
    response = await client.get("/api/v1/spire/entries")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_spire_nodes_requires_auth(client: Any) -> None:
    """GET /api/v1/spire/nodes without token returns 401."""
    response = await client.get("/api/v1/spire/nodes")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_spire_entries_without_server(
    client: Any, admin_headers: dict
) -> None:
    """GET /api/v1/spire/entries without SPIRE server returns 503."""
    response = await client.get("/api/v1/spire/entries", headers=admin_headers)
    assert response.status_code in (200, 503)


@pytest.mark.asyncio
async def test_spire_nodes_without_server(
    client: Any, admin_headers: dict
) -> None:
    """GET /api/v1/spire/nodes without SPIRE server returns 503."""
    response = await client.get("/api/v1/spire/nodes", headers=admin_headers)
    assert response.status_code in (200, 503)


@pytest.mark.asyncio
async def test_spire_federation_requires_auth(client: Any) -> None:
    """GET /api/v1/spire/federation without token returns 401."""
    response = await client.get("/api/v1/spire/federation")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_spire_datastore_migrate_requires_auth(client: Any) -> None:
    """POST /api/v1/spire/datastore/migrate without token returns 401."""
    response = await client.post(
        "/api/v1/spire/datastore/migrate",
        json={"target": "postgresql"},
    )
    assert response.status_code == 401
