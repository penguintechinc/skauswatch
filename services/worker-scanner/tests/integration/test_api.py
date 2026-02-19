"""Integration tests for Flask API routes.

This module provides comprehensive integration tests for all Flask API routes
in the worker-scanner service. Tests use an in-memory SQLite database for
isolation and mock Celery task dispatch to avoid external dependencies.

Test Coverage:
    - Health check endpoint
    - Targets API (CRUD operations)
    - Jobs API (CRUD operations with Celery mocking)
    - Findings API (list, get, update, stats)
    - Schedules API (CRUD operations)
    - Authentication and authorization
"""

import json
from datetime import datetime, timedelta
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import jwt
import pytest
from app import create_app


class TestIntegrationAPI:
    """Integration test suite for Flask API routes.

    Uses SQLite in-memory database for test isolation. Mocks Celery task
    dispatch to avoid Redis dependency. Tests all major API endpoints
    with comprehensive coverage of success and error cases.
    """

    @pytest.fixture
    def app(self):
        """Create a Flask test app with SQLite in-memory database.

        Configures test environment with SQLite database, JWT authentication,
        and enabled scanners. Returns configured Flask application instance.

        Returns:
            Flask application configured for testing
        """
        import os

        os.environ["DB_TYPE"] = "sqlite"
        os.environ["DB_NAME"] = ":memory:"
        os.environ["JWT_SECRET_KEY"] = "test-secret"
        os.environ["FLASK_ENV"] = "testing"
        os.environ["SCANNER_NUCLEI_ENABLED"] = "true"
        os.environ["SCANNER_ZAP_ENABLED"] = "true"
        os.environ["SCANNER_OPENVAS_ENABLED"] = "true"

        app = create_app()
        app.config["TESTING"] = True
        yield app

    @pytest.fixture
    def client(self, app):
        """Flask test client.

        Args:
            app: Flask application fixture

        Returns:
            Flask test client instance
        """
        return app.test_client()

    @pytest.fixture
    def auth_headers(self):
        """Generate valid JWT auth headers.

        Creates a JWT token with test user ID and appropriate expiration time.
        Returns headers dictionary suitable for Flask test client requests.

        Returns:
            Dictionary with Authorization and Content-Type headers
        """
        token = jwt.encode(
            {
                "sub": "test-user",
                "exp": datetime.utcnow() + timedelta(hours=1),
                "iat": datetime.utcnow(),
            },
            "test-secret",
            algorithm="HS256",
        )
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    # Health Check Tests

    def test_healthz_returns_200(self, client):
        """Test health check endpoint returns 200 OK.

        Verifies that the health check endpoint is accessible and returns
        a successful HTTP 200 status code.
        """
        response = client.get("/api/v1/scanner/healthz")
        assert response.status_code == 200

    def test_healthz_response_format(self, client):
        """Test health check response contains required fields.

        Verifies that health check response includes status, service name,
        version, environment, database info, and scanner configuration.
        """
        response = client.get("/api/v1/scanner/healthz")
        data = json.loads(response.data)

        assert "status" in data
        assert "service" in data
        assert data["status"] == "healthy"
        assert data["service"] == "worker-scanner"
        assert "version" in data
        assert "database" in data
        assert "scanners" in data

    # Targets API Tests

    def test_create_target(self, client, auth_headers):
        """Test creating a new scan target.

        Verifies successful creation of a scan target with valid data.
        Checks for HTTP 201 Created status and returned target data.
        """
        target_data = {
            "name": "example.com",
            "target_type": "domain",
            "target_value": "example.com",
            "description": "Test target",
            "enabled": True,
            "tags": ["production", "web"],
            "metadata": {"priority": "high"},
        }

        response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data["name"] == "example.com"
        assert data["target_type"] == "domain"
        assert data["target_value"] == "example.com"
        assert "id" in data
        assert "created_at" in data

    def test_create_target_invalid_type(self, client, auth_headers):
        """Test creating target with invalid target_type returns 400.

        Verifies validation error when target_type is not one of the
        allowed values (domain, ip, url, cidr).
        """
        target_data = {
            "name": "invalid-target",
            "target_type": "invalid_type",
            "target_value": "example.com",
        }

        response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )

        assert response.status_code == 400
        data = json.loads(response.data)
        assert "error" in data

    def test_create_target_duplicate_name(self, client, auth_headers):
        """Test creating target with duplicate name returns 409 Conflict.

        Verifies that attempting to create a target with an existing name
        results in an HTTP 409 Conflict error.
        """
        target_data = {
            "name": "duplicate-target",
            "target_type": "domain",
            "target_value": "example.com",
        }

        # Create first target
        response1 = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        assert response1.status_code == 201

        # Attempt to create duplicate
        response2 = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        assert response2.status_code == 409
        data = json.loads(response2.data)
        assert "already exists" in data["error"].lower()

    def test_list_targets(self, client, auth_headers):
        """Test listing all targets with pagination.

        Verifies that the list targets endpoint returns a paginated list
        with total count and page information.
        """
        # Create test targets
        for i in range(3):
            target_data = {
                "name": f"target-{i}",
                "target_type": "domain",
                "target_value": f"example{i}.com",
            }
            client.post(
                "/api/v1/scanner/targets",
                data=json.dumps(target_data),
                headers=auth_headers,
            )

        # List targets
        response = client.get("/api/v1/scanner/targets", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "targets" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data
        assert len(data["targets"]) == 3
        assert data["total"] == 3

    def test_get_target(self, client, auth_headers):
        """Test retrieving a specific target by ID.

        Verifies that a single target can be retrieved by ID and returns
        all expected fields.
        """
        # Create target
        target_data = {
            "name": "get-target",
            "target_type": "ip",
            "target_value": "192.168.1.1",
        }
        create_response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        target_id = json.loads(create_response.data)["id"]

        # Get target
        response = client.get(
            f"/api/v1/scanner/targets/{target_id}", headers=auth_headers
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["id"] == target_id
        assert data["name"] == "get-target"
        assert data["target_type"] == "ip"

    def test_get_target_not_found(self, client, auth_headers):
        """Test retrieving non-existent target returns 404.

        Verifies that requesting a target that doesn't exist returns
        HTTP 404 Not Found.
        """
        response = client.get("/api/v1/scanner/targets/999", headers=auth_headers)

        assert response.status_code == 404
        data = json.loads(response.data)
        assert "not found" in data["error"].lower()

    def test_update_target(self, client, auth_headers):
        """Test updating a target's fields.

        Verifies that target fields can be updated via PUT request and
        changes are persisted correctly.
        """
        # Create target
        target_data = {
            "name": "update-target",
            "target_type": "domain",
            "target_value": "example.com",
            "enabled": True,
        }
        create_response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        target_id = json.loads(create_response.data)["id"]

        # Update target
        update_data = {"description": "Updated description", "enabled": False}
        response = client.put(
            f"/api/v1/scanner/targets/{target_id}",
            data=json.dumps(update_data),
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["description"] == "Updated description"
        assert data["enabled"] is False

    def test_delete_target(self, client, auth_headers):
        """Test deleting a target.

        Verifies that a target can be deleted and returns HTTP 204 No Content.
        Confirms target is removed from database.
        """
        # Create target
        target_data = {
            "name": "delete-target",
            "target_type": "domain",
            "target_value": "example.com",
        }
        create_response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        target_id = json.loads(create_response.data)["id"]

        # Delete target
        response = client.delete(
            f"/api/v1/scanner/targets/{target_id}", headers=auth_headers
        )

        assert response.status_code == 204

        # Verify target is deleted
        get_response = client.get(
            f"/api/v1/scanner/targets/{target_id}", headers=auth_headers
        )
        assert get_response.status_code == 404

    # Jobs API Tests

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_create_job(self, mock_celery, client, auth_headers):
        """Test creating a new scan job.

        Mocks Celery task dispatch and verifies job creation with HTTP 202
        Accepted status. Confirms job is queued for async processing.

        Args:
            mock_celery: Mocked Celery task delay function
        """
        # Create target first
        target_data = {
            "name": "job-target",
            "target_type": "domain",
            "target_value": "example.com",
        }
        target_response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        target_id = json.loads(target_response.data)["id"]

        # Create job
        job_data = {
            "target_id": target_id,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "priority": 5,
            "config": {"severity": "high"},
        }

        response = client.post(
            "/api/v1/scanner/jobs", data=json.dumps(job_data), headers=auth_headers
        )

        assert response.status_code == 202
        data = json.loads(response.data)
        assert data["target_id"] == target_id
        assert data["scanner_type"] == "nuclei"
        assert data["status"] == "pending"
        assert "id" in data

        # Verify Celery task was dispatched
        mock_celery.assert_called_once()

    def test_create_job_target_not_found(self, client, auth_headers):
        """Test creating job with non-existent target returns 404.

        Verifies that attempting to create a job for a non-existent target
        results in HTTP 404 Not Found.
        """
        job_data = {
            "target_id": 999,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
        }

        response = client.post(
            "/api/v1/scanner/jobs", data=json.dumps(job_data), headers=auth_headers
        )

        assert response.status_code == 404
        data = json.loads(response.data)
        assert "not found" in data["error"].lower()

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_list_jobs(self, mock_celery, client, auth_headers):
        """Test listing all jobs with pagination.

        Verifies that jobs can be listed with pagination metadata. Creates
        multiple jobs and confirms they are returned in the list response.

        Args:
            mock_celery: Mocked Celery task delay function
        """
        # Create target
        target_data = {
            "name": "list-jobs-target",
            "target_type": "domain",
            "target_value": "example.com",
        }
        target_response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        target_id = json.loads(target_response.data)["id"]

        # Create jobs
        for i in range(3):
            job_data = {
                "target_id": target_id,
                "scanner_type": "nuclei",
                "scan_type": "baseline",
            }
            client.post(
                "/api/v1/scanner/jobs", data=json.dumps(job_data), headers=auth_headers
            )

        # List jobs
        response = client.get("/api/v1/scanner/jobs", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "jobs" in data
        assert "total" in data
        assert len(data["jobs"]) == 3

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_get_job(self, mock_celery, client, auth_headers):
        """Test retrieving a specific job by ID.

        Verifies that a single job can be retrieved by ID and returns all
        expected job details.

        Args:
            mock_celery: Mocked Celery task delay function
        """
        # Create target
        target_data = {
            "name": "get-job-target",
            "target_type": "domain",
            "target_value": "example.com",
        }
        target_response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        target_id = json.loads(target_response.data)["id"]

        # Create job
        job_data = {
            "target_id": target_id,
            "scanner_type": "zap",
            "scan_type": "full",
        }
        create_response = client.post(
            "/api/v1/scanner/jobs", data=json.dumps(job_data), headers=auth_headers
        )
        job_id = json.loads(create_response.data)["id"]

        # Get job
        response = client.get(f"/api/v1/scanner/jobs/{job_id}", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["id"] == job_id
        assert data["scanner_type"] == "zap"
        assert data["scan_type"] == "full"

    def test_get_job_not_found(self, client, auth_headers):
        """Test retrieving non-existent job returns 404.

        Verifies that requesting a job that doesn't exist returns
        HTTP 404 Not Found.
        """
        response = client.get("/api/v1/scanner/jobs/999", headers=auth_headers)

        assert response.status_code == 404
        data = json.loads(response.data)
        assert "not found" in data["error"].lower()

    # Findings API Tests

    def test_list_findings(self, client, auth_headers):
        """Test listing all findings with pagination.

        Verifies that findings can be listed with pagination metadata.
        Tests empty list case when no findings exist.
        """
        response = client.get("/api/v1/scanner/findings", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "findings" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data

    def test_get_finding_stats(self, client, auth_headers):
        """Test retrieving finding statistics.

        Verifies that statistics endpoint returns aggregated data including
        total count, breakdowns by severity, status, and scanner type.
        """
        response = client.get("/api/v1/scanner/findings/stats", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "total" in data
        assert "by_severity" in data
        assert "by_status" in data
        assert "by_scanner" in data

        # Verify severity categories
        severity_data = data["by_severity"]
        assert "critical" in severity_data
        assert "high" in severity_data
        assert "medium" in severity_data
        assert "low" in severity_data
        assert "info" in severity_data

        # Verify status categories
        status_data = data["by_status"]
        assert "open" in status_data
        assert "acknowledged" in status_data
        assert "false_positive" in status_data
        assert "fixed" in status_data

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_update_finding_status(self, mock_celery, client, auth_headers):
        """Test updating finding status.

        Creates a finding through job execution and verifies that the
        finding status can be updated (acknowledged, false_positive, fixed).

        Args:
            mock_celery: Mocked Celery task delay function
        """
        # Create target
        target_data = {
            "name": "finding-target",
            "target_type": "domain",
            "target_value": "example.com",
        }
        target_response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        target_id = json.loads(target_response.data)["id"]

        # Create job
        job_data = {
            "target_id": target_id,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
        }
        job_response = client.post(
            "/api/v1/scanner/jobs", data=json.dumps(job_data), headers=auth_headers
        )
        job_id = json.loads(job_response.data)["id"]

        # Insert finding directly into database for testing
        # This would normally be created by the scanner worker
        from database.models import get_configured_db

        db = get_configured_db()
        finding_id = db.scan_findings.insert(
            target_id=target_id,
            job_id=job_id,
            severity="high",
            title="Test vulnerability",
            description="Test description",
            affected_url="https://example.com/vuln",
            status="open",
            discovered_at=datetime.utcnow(),
        )
        db.commit()

        # Update finding status
        update_data = {"status": "acknowledged"}
        response = client.patch(
            f"/api/v1/scanner/findings/{finding_id}",
            data=json.dumps(update_data),
            headers=auth_headers,
        )

        assert response.status_code == 200
        data = json.loads(response.data)
        assert data["status"] == "acknowledged"

    # Authentication Tests

    def test_no_auth_returns_401(self, client):
        """Test request without Authorization header returns 401.

        Verifies that accessing protected endpoints without authentication
        results in HTTP 401 Unauthorized.
        """
        response = client.get("/api/v1/scanner/targets")

        assert response.status_code == 401

    def test_expired_token_returns_401(self, client):
        """Test request with expired JWT token returns 401.

        Verifies that authentication fails when JWT token is expired.
        """
        # Create expired token
        expired_token = jwt.encode(
            {
                "sub": "test-user",
                "exp": datetime.utcnow() - timedelta(hours=1),
                "iat": datetime.utcnow() - timedelta(hours=2),
            },
            "test-secret",
            algorithm="HS256",
        )
        headers = {
            "Authorization": f"Bearer {expired_token}",
            "Content-Type": "application/json",
        }

        response = client.get("/api/v1/scanner/targets", headers=headers)

        assert response.status_code == 401

    def test_invalid_token_returns_401(self, client):
        """Test request with invalid JWT token returns 401.

        Verifies that authentication fails when JWT token is malformed
        or has invalid signature.
        """
        headers = {
            "Authorization": "Bearer invalid-garbage-token",
            "Content-Type": "application/json",
        }

        response = client.get("/api/v1/scanner/targets", headers=headers)

        assert response.status_code == 401

    # Schedules API Tests

    def test_create_schedule(self, client, auth_headers):
        """Test creating a new scan schedule.

        Verifies successful creation of a scan schedule with valid cron
        expression and configuration. Checks HTTP 201 Created status.
        """
        # Create target first
        target_data = {
            "name": "schedule-target",
            "target_type": "domain",
            "target_value": "example.com",
        }
        target_response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        target_id = json.loads(target_response.data)["id"]

        # Create schedule
        schedule_data = {
            "name": "Daily scan",
            "target_id": target_id,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "cron_expression": "0 0 * * *",
            "config": {"severity": "high"},
            "enabled": True,
        }

        response = client.post(
            "/api/v1/scanner/schedules",
            data=json.dumps(schedule_data),
            headers=auth_headers,
        )

        assert response.status_code == 201
        data = json.loads(response.data)
        assert data["name"] == "Daily scan"
        assert data["target_id"] == target_id
        assert data["scanner_type"] == "nuclei"
        assert data["cron_expression"] == "0 0 * * *"
        assert "next_run" in data
        assert "id" in data

    def test_list_schedules(self, client, auth_headers):
        """Test listing all schedules with pagination.

        Verifies that schedules can be listed with pagination metadata.
        Creates multiple schedules and confirms they are returned.
        """
        # Create target
        target_data = {
            "name": "list-schedules-target",
            "target_type": "domain",
            "target_value": "example.com",
        }
        target_response = client.post(
            "/api/v1/scanner/targets",
            data=json.dumps(target_data),
            headers=auth_headers,
        )
        target_id = json.loads(target_response.data)["id"]

        # Create schedules
        for i in range(2):
            schedule_data = {
                "name": f"Schedule {i}",
                "target_id": target_id,
                "scanner_type": "nuclei",
                "scan_type": "baseline",
                "cron_expression": "0 0 * * *",
            }
            client.post(
                "/api/v1/scanner/schedules",
                data=json.dumps(schedule_data),
                headers=auth_headers,
            )

        # List schedules
        response = client.get("/api/v1/scanner/schedules", headers=auth_headers)

        assert response.status_code == 200
        data = json.loads(response.data)
        assert "schedules" in data
        assert "total" in data
        assert len(data["schedules"]) == 2
