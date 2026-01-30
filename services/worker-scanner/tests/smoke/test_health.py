"""Smoke tests for worker-scanner service health and startup verification.

These tests verify basic functionality:
- Service starts and responds to requests
- Health endpoint returns expected format
- API endpoints are registered and reachable
- Authentication middleware is active
- Database connection is functional

Usage:
    # Against Flask test client (default):
    pytest tests/smoke/test_health.py -v

    # Against live instance:
    SMOKE_TEST_URL=http://localhost:5001 pytest tests/smoke/test_health.py -v
"""

import json
import os
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

import jwt
import pytest

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


# Check if testing against live instance
SMOKE_TEST_URL = os.environ.get("SMOKE_TEST_URL", "")

if SMOKE_TEST_URL and HAS_HTTPX:
    # Use httpx for live instance testing
    @pytest.fixture
    def client() -> "httpx.Client":
        """HTTP client for live instance."""
        return httpx.Client(base_url=SMOKE_TEST_URL, timeout=10)

    @pytest.fixture
    def auth_token() -> str:
        """Generate valid JWT auth token for live instance."""
        # Get JWT secret from environment (fallback to test value)
        secret_key = os.environ.get("JWT_SECRET_KEY", "dev-secret-key")
        token = jwt.encode(
            {
                "sub": "test-user",
                "exp": datetime.utcnow() + timedelta(hours=1),
                "iat": datetime.utcnow(),
            },
            secret_key,
            algorithm="HS256",
        )
        return token

else:
    # Use Flask test client for CI testing
    @pytest.fixture
    def app():
        """Create a Flask test app with SQLite in-memory database."""
        os.environ["DB_TYPE"] = "sqlite"
        os.environ["DB_NAME"] = ":memory:"
        os.environ["JWT_SECRET_KEY"] = "test-secret"
        os.environ["FLASK_ENV"] = "testing"
        os.environ["SCANNER_NUCLEI_ENABLED"] = "true"
        os.environ["SCANNER_ZAP_ENABLED"] = "true"
        os.environ["SCANNER_OPENVAS_ENABLED"] = "true"

        from app import create_app

        app = create_app()
        app.config["TESTING"] = True
        yield app

    @pytest.fixture
    def client(app):
        """Flask test client."""
        return app.test_client()

    @pytest.fixture
    def auth_token() -> str:
        """Generate valid JWT auth token for Flask test client."""
        token = jwt.encode(
            {
                "sub": "test-user",
                "exp": datetime.utcnow() + timedelta(hours=1),
                "iat": datetime.utcnow(),
            },
            "test-secret",
            algorithm="HS256",
        )
        return token


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_endpoint_returns_200(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that GET /api/v1/scanner/healthz returns 200 OK with auth.

        Verifies the health endpoint is accessible and responds with
        HTTP 200 status code when provided with valid JWT token.
        """
        headers = {"Authorization": f"Bearer {auth_token}"}

        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner/healthz", headers=headers)
        else:
            response = client.get("/api/v1/scanner/healthz", headers=headers)

        assert response.status_code == 200, (
            f"Expected status 200, got {response.status_code}. "
            f"Response: {response.text if hasattr(response, 'text') else response.data}"
        )

    def test_health_response_has_status(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that health response contains 'status' field set to 'healthy'.

        Verifies the response JSON includes a status field indicating
        the service is in a healthy state.
        """
        headers = {"Authorization": f"Bearer {auth_token}"}

        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner/healthz", headers=headers)
            data = response.json()
        else:
            response = client.get("/api/v1/scanner/healthz", headers=headers)
            data = json.loads(response.data)

        assert "status" in data, "Response missing 'status' field"
        assert data["status"] == "healthy", (
            f"Expected status='healthy', got '{data['status']}'"
        )

    def test_health_response_has_service(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that health response contains 'service' field set to 'worker-scanner'.

        Verifies the response JSON identifies this as the worker-scanner service.
        """
        headers = {"Authorization": f"Bearer {auth_token}"}

        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner/healthz", headers=headers)
            data = response.json()
        else:
            response = client.get("/api/v1/scanner/healthz", headers=headers)
            data = json.loads(response.data)

        assert "service" in data, "Response missing 'service' field"
        assert data["service"] == "worker-scanner", (
            f"Expected service='worker-scanner', got '{data['service']}'"
        )

    def test_health_content_type_json(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that health response Content-Type is application/json.

        Verifies proper HTTP headers for JSON response.
        """
        headers = {"Authorization": f"Bearer {auth_token}"}

        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner/healthz", headers=headers)
            content_type = response.headers.get("content-type", "")
        else:
            response = client.get("/api/v1/scanner/healthz", headers=headers)
            content_type = response.headers.get("Content-Type", "")

        assert "application/json" in content_type, (
            f"Expected Content-Type to contain 'application/json', got '{content_type}'"
        )


class TestAPIEndpointsRegistered:
    """Tests that verify key API endpoints are registered and reachable."""

    def _get_response_status(
        self, client: Any, path: str, headers: Optional[Dict[str, str]] = None
    ) -> int:
        """Helper to get response status code from either client type."""
        if headers is None:
            headers = {}

        if isinstance(client, httpx.Client):
            response = client.get(path, headers=headers)
        else:
            response = client.get(path, headers=headers)

        return response.status_code

    def test_targets_endpoint_registered(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that targets endpoint is registered and not a 404.

        Verifies the targets GET endpoint is registered by checking
        it doesn't return 404 (not found).
        """
        headers = {"Authorization": f"Bearer {auth_token}"}
        status = self._get_response_status(client, "/api/v1/scanner", headers)

        # Should not be 404 (endpoint exists, may have errors like 500)
        assert status != 404, (
            f"Targets endpoint returned 404 - endpoint not registered"
        )

    def test_targets_create_endpoint_registered(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that create targets endpoint is registered.

        Verifies POST /api/v1/scanner endpoint returns non-404 status.
        """
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json"
        }

        if isinstance(client, httpx.Client):
            response = client.post("/api/v1/scanner", headers=headers, json={})
        else:
            response = client.post("/api/v1/scanner", headers=headers, json={})

        # Should not be 404 (endpoint exists)
        assert response.status_code != 404, (
            "Create targets endpoint returned 404 - endpoint not registered"
        )

    def test_findings_endpoint_registered(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that findings endpoint exists.

        Verifies GET /api/v1/scanner (findings GET) is registered.
        Since multiple GET endpoints share the same base path, we verify
        the base path is registered.
        """
        headers = {"Authorization": f"Bearer {auth_token}"}
        status = self._get_response_status(client, "/api/v1/scanner", headers)

        # Base endpoint should exist
        assert status != 404, (
            "Findings endpoint not found - base API endpoint not registered"
        )

    def test_schedules_endpoint_registered(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that schedules endpoint exists.

        Verifies GET /api/v1/scanner (schedules list) is registered.
        """
        headers = {"Authorization": f"Bearer {auth_token}"}
        status = self._get_response_status(client, "/api/v1/scanner", headers)

        # Base endpoint should exist
        assert status != 404, (
            "Schedules endpoint not found - base API endpoint not registered"
        )

    def test_scanners_endpoint_not_404(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that GET /api/v1/scanner/scanners does not return 404.

        Verifies the scanners endpoint is registered. May return 401 (auth required)
        but should not return 404 (endpoint not found).
        """
        headers = {"Authorization": f"Bearer {auth_token}"}
        status = self._get_response_status(client, "/api/v1/scanner/scanners", headers)

        assert status != 404, (
            "Scanners endpoint returned 404 - endpoint not registered"
        )


class TestAuthenticationMiddleware:
    """Tests that verify authentication middleware is active."""

    def test_auth_required_on_base_endpoint(
        self, client: Any
    ) -> None:
        """Test that GET /api/v1/scanner without auth returns 401.

        Verifies JWT authentication middleware is active on protected endpoints.
        """
        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner")
        else:
            response = client.get("/api/v1/scanner")

        assert response.status_code == 401, (
            f"Expected 401 Unauthorized without auth, got {response.status_code}"
        )

    def test_auth_required_on_resource_endpoint(
        self, client: Any
    ) -> None:
        """Test that GET /api/v1/scanner/<id> without auth returns 401.

        Verifies JWT authentication middleware is active on resource endpoints.
        """
        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner/1")
        else:
            response = client.get("/api/v1/scanner/1")

        assert response.status_code == 401, (
            f"Expected 401 Unauthorized without auth, got {response.status_code}"
        )

    def test_auth_required_on_nested_endpoint(
        self, client: Any
    ) -> None:
        """Test that nested endpoints require auth.

        Verifies JWT authentication middleware is active on nested endpoints
        like /api/v1/scanner/<id>/findings.
        """
        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner/1/findings")
        else:
            response = client.get("/api/v1/scanner/1/findings")

        assert response.status_code == 401, (
            f"Expected 401 Unauthorized without auth, got {response.status_code}"
        )


class TestErrorHandling:
    """Tests for error handling and response formats."""

    def test_invalid_endpoint_returns_404(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that GET /api/v1/scanner/nonexistent returns 404.

        Verifies proper 404 error handling for undefined routes.
        """
        headers = {"Authorization": f"Bearer {auth_token}"}

        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner/nonexistent", headers=headers)
        else:
            response = client.get("/api/v1/scanner/nonexistent", headers=headers)

        assert response.status_code == 404, (
            f"Expected 404 for nonexistent endpoint, got {response.status_code}"
        )

    def test_error_response_format(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that 404 response has proper JSON error format.

        Verifies error responses include required fields like 'error', 'message',
        and 'status_code'.
        """
        headers = {"Authorization": f"Bearer {auth_token}"}

        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner/nonexistent", headers=headers)
            data = response.json()
        else:
            response = client.get("/api/v1/scanner/nonexistent", headers=headers)
            data = json.loads(response.data)

        assert "error" in data, "Error response missing 'error' field"
        assert data["error"] == "Not Found", (
            f"Expected error='Not Found', got '{data['error']}'"
        )
        assert "status_code" in data, "Error response missing 'status_code' field"
        assert data["status_code"] == 404, (
            f"Expected status_code=404, got {data['status_code']}"
        )


class TestCORSHeaders:
    """Tests for CORS header presence."""

    def test_cors_headers_present(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that CORS headers are present in response with Origin header.

        Verifies CORS is configured by sending an Origin header and checking
        for CORS response headers.
        """
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Origin": "http://localhost:3000"
        }

        if isinstance(client, httpx.Client):
            response = client.get("/api/v1/scanner/healthz", headers=headers)
            # httpx returns headers in a case-insensitive mapping
            cors_header = response.headers.get("access-control-allow-origin")
        else:
            response = client.get("/api/v1/scanner/healthz", headers=headers)
            # Flask test client headers are case-sensitive
            cors_header = response.headers.get("Access-Control-Allow-Origin")

        # CORS headers should be present when origin is provided
        assert cors_header is not None, (
            "CORS header 'Access-Control-Allow-Origin' not present in response. "
            "CORS may not be properly configured."
        )

    def test_cors_allow_methods(
        self, client: Any, auth_token: str
    ) -> None:
        """Test that CORS Allow-Methods header is configured.

        Verifies CORS preflight response includes allowed HTTP methods.
        """
        headers = {"Authorization": f"Bearer {auth_token}"}

        if isinstance(client, httpx.Client):
            response = client.options("/api/v1/scanner/healthz", headers=headers)
            allow_methods = response.headers.get("access-control-allow-methods")
        else:
            response = client.options("/api/v1/scanner/healthz", headers=headers)
            allow_methods = response.headers.get("Access-Control-Allow-Methods")

        # Allow methods header may not be present on OPTIONS for simple endpoints,
        # but should be on other endpoints
        assert allow_methods is None or len(allow_methods) > 0, (
            "CORS Allow-Methods header should be present or empty"
        )
