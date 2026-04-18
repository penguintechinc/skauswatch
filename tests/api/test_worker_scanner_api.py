"""Worker-Scanner API tests.

Tests Flask REST endpoints for the worker-scanner service without requiring
external services (PostgreSQL, Redis, Celery).  Uses SQLite in-memory database
and mocks Celery task dispatch.

Test classes:
    TestWorkerScannerHealth  – GET /api/v1/scanner/healthz
    TestTargetsAPI           – CRUD for scan targets
    TestJobsAPI              – List, create, get status for scan jobs
    TestFindingsAPI          – CRUD for security findings
    TestSchedulesAPI         – CRUD for scan schedules
    TestScannersAPI          – Scanner status endpoint

URL base prefix: /api/v1/scanner
"""

import json
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import jwt
import pytest

pytestmark = pytest.mark.api

_SCANNER_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "services", "worker-scanner"
)
if _SCANNER_DIR not in sys.path:
    sys.path.insert(0, _SCANNER_DIR)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def scanner_app():
    """Flask app with SQLite in-memory database and enabled scanners."""
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
def scanner_client(scanner_app):
    """Flask test client for worker-scanner."""
    return scanner_app.test_client()


@pytest.fixture
def auth_headers():
    """Valid JWT auth headers for protected endpoints."""
    token = jwt.encode(
        {
            "sub": "test-user-api",
            "exp": datetime.utcnow() + timedelta(hours=1),
            "iat": datetime.utcnow(),
        },
        "test-secret",
        algorithm="HS256",
    )
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }


def _post_json(client, url, data, headers):
    """Helper: POST JSON body and return response."""
    return client.post(url, data=json.dumps(data), headers=headers)


def _create_target(client, headers, name="test-target", target_type="domain",
                   target_value="example.com"):
    """Create a scan target and return parsed response data."""
    resp = _post_json(
        client,
        "/api/v1/scanner/targets",
        {
            "name": name,
            "target_type": target_type,
            "target_value": target_value,
        },
        headers,
    )
    return json.loads(resp.data), resp.status_code


@patch(
    "workers.scan_worker.execute_scan.delay",
    return_value=MagicMock(id="mock-task-id"),
)
def _create_job(mock_celery, client, headers, target_id, scanner_type="nuclei"):
    """Create a scan job and return parsed response data."""
    resp = _post_json(
        client,
        "/api/v1/scanner/jobs",
        {
            "target_id": target_id,
            "scanner_type": scanner_type,
            "scan_type": "baseline",
        },
        headers,
    )
    return json.loads(resp.data), resp.status_code


# ---------------------------------------------------------------------------
# TestWorkerScannerHealth
# ---------------------------------------------------------------------------


class TestWorkerScannerHealth:
    """Health check endpoint (unauthenticated)."""

    def test_healthz_returns_200(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/healthz")
        assert resp.status_code == 200

    def test_healthz_response_has_status_field(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/healthz")
        data = json.loads(resp.data)
        assert data["status"] == "healthy"

    def test_healthz_response_has_service_field(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/healthz")
        data = json.loads(resp.data)
        assert data["service"] == "worker-scanner"

    def test_healthz_response_has_version_field(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/healthz")
        data = json.loads(resp.data)
        assert "version" in data

    def test_healthz_response_has_database_info(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/healthz")
        data = json.loads(resp.data)
        assert "database" in data

    def test_healthz_response_has_scanners_info(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/healthz")
        data = json.loads(resp.data)
        assert "scanners" in data
        assert "nuclei" in data["scanners"]
        assert "zap" in data["scanners"]
        assert "openvas" in data["scanners"]


# ---------------------------------------------------------------------------
# TestTargetsAPI
# ---------------------------------------------------------------------------


class TestTargetsAPI:
    """Scan target CRUD operations."""

    # --- List ---

    def test_list_targets_requires_auth(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/targets")
        assert resp.status_code == 401

    def test_list_targets_returns_200(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/targets", headers=auth_headers)
        assert resp.status_code == 200

    def test_list_targets_response_format(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/targets", headers=auth_headers)
        data = json.loads(resp.data)
        assert "targets" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data

    def test_list_targets_pagination_defaults(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/targets", headers=auth_headers)
        data = json.loads(resp.data)
        assert data["page"] == 1
        assert data["per_page"] == 20

    def test_list_targets_empty_initially(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/targets", headers=auth_headers)
        data = json.loads(resp.data)
        assert data["total"] == 0
        assert data["targets"] == []

    # --- Create ---

    def test_create_target_success(self, scanner_client, auth_headers):
        target_data = {
            "name": "create-test-target",
            "target_type": "domain",
            "target_value": "example.com",
            "description": "Test target",
            "enabled": True,
            "tags": ["production"],
            "metadata": {"priority": "high"},
        }
        resp = _post_json(
            scanner_client, "/api/v1/scanner/targets", target_data, auth_headers
        )
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert data["name"] == "create-test-target"
        assert data["target_type"] == "domain"
        assert "id" in data
        assert "created_at" in data

    def test_create_target_ip_type(self, scanner_client, auth_headers):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/targets",
            {"name": "ip-target", "target_type": "ip", "target_value": "10.0.0.1"},
            auth_headers,
        )
        assert resp.status_code == 201

    def test_create_target_url_type(self, scanner_client, auth_headers):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/targets",
            {
                "name": "url-target",
                "target_type": "url",
                "target_value": "https://example.com",
            },
            auth_headers,
        )
        assert resp.status_code == 201

    def test_create_target_cidr_type(self, scanner_client, auth_headers):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/targets",
            {
                "name": "cidr-target",
                "target_type": "cidr",
                "target_value": "192.168.1.0/24",
            },
            auth_headers,
        )
        assert resp.status_code == 201

    def test_create_target_invalid_type_returns_400(self, scanner_client, auth_headers):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/targets",
            {
                "name": "bad-type-target",
                "target_type": "invalid_type",
                "target_value": "example.com",
            },
            auth_headers,
        )
        assert resp.status_code == 400

    def test_create_target_duplicate_name_returns_409(
        self, scanner_client, auth_headers
    ):
        payload = {
            "name": "duplicate-name-target",
            "target_type": "domain",
            "target_value": "example.com",
        }
        resp1 = _post_json(
            scanner_client, "/api/v1/scanner/targets", payload, auth_headers
        )
        assert resp1.status_code == 201

        resp2 = _post_json(
            scanner_client, "/api/v1/scanner/targets", payload, auth_headers
        )
        assert resp2.status_code == 409

    def test_create_target_missing_required_fields(self, scanner_client, auth_headers):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/targets",
            {"name": "missing-fields-target"},
            auth_headers,
        )
        assert resp.status_code == 400

    def test_create_target_requires_auth(self, scanner_client):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/targets",
            {"name": "t", "target_type": "domain", "target_value": "x.com"},
            {"Content-Type": "application/json"},
        )
        assert resp.status_code == 401

    # --- Get ---

    def test_get_target_success(self, scanner_client, auth_headers):
        data, _ = _create_target(
            scanner_client, auth_headers, name="get-target-test"
        )
        target_id = data["id"]
        resp = scanner_client.get(
            f"/api/v1/scanner/targets/{target_id}", headers=auth_headers
        )
        assert resp.status_code == 200
        result = json.loads(resp.data)
        assert result["id"] == target_id
        assert result["name"] == "get-target-test"

    def test_get_target_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.get(
            "/api/v1/scanner/targets/99999", headers=auth_headers
        )
        assert resp.status_code == 404

    # --- Update ---

    def test_update_target_success(self, scanner_client, auth_headers):
        data, _ = _create_target(
            scanner_client, auth_headers, name="update-target-test"
        )
        target_id = data["id"]
        resp = scanner_client.put(
            f"/api/v1/scanner/targets/{target_id}",
            data=json.dumps({"description": "updated desc", "enabled": False}),
            headers=auth_headers,
        )
        assert resp.status_code == 200
        result = json.loads(resp.data)
        assert result["description"] == "updated desc"
        assert result["enabled"] is False

    def test_update_target_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.put(
            "/api/v1/scanner/targets/99999",
            data=json.dumps({"description": "nope"}),
            headers=auth_headers,
        )
        assert resp.status_code == 404

    # --- Delete ---

    def test_delete_target_success(self, scanner_client, auth_headers):
        data, _ = _create_target(
            scanner_client, auth_headers, name="delete-target-test"
        )
        target_id = data["id"]
        resp = scanner_client.delete(
            f"/api/v1/scanner/targets/{target_id}", headers=auth_headers
        )
        assert resp.status_code == 204

        # Verify the target is gone
        get_resp = scanner_client.get(
            f"/api/v1/scanner/targets/{target_id}", headers=auth_headers
        )
        assert get_resp.status_code == 404

    def test_delete_target_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.delete(
            "/api/v1/scanner/targets/99999", headers=auth_headers
        )
        assert resp.status_code == 404

    # --- History ---

    def test_get_target_history_empty(self, scanner_client, auth_headers):
        data, _ = _create_target(
            scanner_client, auth_headers, name="history-target-test"
        )
        target_id = data["id"]
        resp = scanner_client.get(
            f"/api/v1/scanner/targets/{target_id}/history", headers=auth_headers
        )
        assert resp.status_code == 200
        result = json.loads(resp.data)
        assert result["target_id"] == target_id
        assert result["jobs"] == []


# ---------------------------------------------------------------------------
# TestJobsAPI
# ---------------------------------------------------------------------------


class TestJobsAPI:
    """Scan job management endpoints."""

    # --- List ---

    def test_list_jobs_requires_auth(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/jobs")
        assert resp.status_code == 401

    def test_list_jobs_returns_200(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/jobs", headers=auth_headers)
        assert resp.status_code == 200

    def test_list_jobs_response_format(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/jobs", headers=auth_headers)
        data = json.loads(resp.data)
        assert "jobs" in data
        assert "total" in data

    # --- Create ---

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_create_job_success(self, mock_celery, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="job-creation-target"
        )
        target_id = target_data["id"]

        job_payload = {
            "target_id": target_id,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "priority": 5,
        }
        resp = _post_json(
            scanner_client, "/api/v1/scanner/jobs", job_payload, auth_headers
        )
        assert resp.status_code == 202
        data = json.loads(resp.data)
        assert data["target_id"] == target_id
        assert data["scanner_type"] == "nuclei"
        assert data["status"] == "pending"
        assert "id" in data

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_create_job_dispatches_celery_task(
        self, mock_celery, scanner_client, auth_headers
    ):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="job-celery-target"
        )
        _post_json(
            scanner_client,
            "/api/v1/scanner/jobs",
            {
                "target_id": target_data["id"],
                "scanner_type": "nuclei",
                "scan_type": "baseline",
            },
            auth_headers,
        )
        mock_celery.assert_called()

    def test_create_job_target_not_found_returns_404(
        self, scanner_client, auth_headers
    ):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/jobs",
            {"target_id": 99999, "scanner_type": "nuclei", "scan_type": "baseline"},
            auth_headers,
        )
        assert resp.status_code == 404

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_create_job_requires_auth(self, mock_celery, scanner_client):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/jobs",
            {"target_id": 1, "scanner_type": "nuclei", "scan_type": "baseline"},
            {"Content-Type": "application/json"},
        )
        assert resp.status_code == 401

    # --- Get ---

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_get_job_success(self, mock_celery, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="get-job-target"
        )
        job_data, _ = _create_job(
            mock_celery, scanner_client, auth_headers, target_data["id"]
        )
        job_id = job_data["id"]

        resp = scanner_client.get(
            f"/api/v1/scanner/jobs/{job_id}", headers=auth_headers
        )
        assert resp.status_code == 200
        result = json.loads(resp.data)
        assert result["id"] == job_id

    def test_get_job_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/jobs/99999", headers=auth_headers)
        assert resp.status_code == 404

    # --- Get job output ---

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_get_job_output(self, mock_celery, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="output-job-target"
        )
        job_data, _ = _create_job(
            mock_celery, scanner_client, auth_headers, target_data["id"]
        )
        job_id = job_data["id"]

        resp = scanner_client.get(
            f"/api/v1/scanner/jobs/{job_id}/output", headers=auth_headers
        )
        assert resp.status_code == 200
        result = json.loads(resp.data)
        assert result["job_id"] == job_id
        assert "status" in result

    # --- Get job findings ---

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_get_job_findings_empty(self, mock_celery, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="findings-job-target"
        )
        job_data, _ = _create_job(
            mock_celery, scanner_client, auth_headers, target_data["id"]
        )
        job_id = job_data["id"]

        resp = scanner_client.get(
            f"/api/v1/scanner/jobs/{job_id}/findings", headers=auth_headers
        )
        assert resp.status_code == 200
        result = json.loads(resp.data)
        assert result["job_id"] == job_id
        assert result["findings"] == []
        assert result["total"] == 0

    # --- Delete job ---

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_delete_pending_job(self, mock_celery, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="delete-job-target"
        )
        job_data, _ = _create_job(
            mock_celery, scanner_client, auth_headers, target_data["id"]
        )
        job_id = job_data["id"]

        resp = scanner_client.delete(
            f"/api/v1/scanner/jobs/{job_id}", headers=auth_headers
        )
        assert resp.status_code == 204

    def test_delete_job_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.delete(
            "/api/v1/scanner/jobs/99999", headers=auth_headers
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# TestFindingsAPI
# ---------------------------------------------------------------------------


class TestFindingsAPI:
    """Security findings CRUD and statistics endpoints."""

    # --- List ---

    def test_list_findings_requires_auth(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/findings")
        assert resp.status_code == 401

    def test_list_findings_returns_200(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/findings", headers=auth_headers)
        assert resp.status_code == 200

    def test_list_findings_response_format(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/findings", headers=auth_headers)
        data = json.loads(resp.data)
        assert "findings" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data

    def test_list_findings_empty_initially(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/findings", headers=auth_headers)
        data = json.loads(resp.data)
        assert data["total"] == 0

    def test_list_findings_severity_filter_accepted(
        self, scanner_client, auth_headers
    ):
        resp = scanner_client.get(
            "/api/v1/scanner/findings?severity=high", headers=auth_headers
        )
        assert resp.status_code == 200

    def test_list_findings_status_filter_accepted(self, scanner_client, auth_headers):
        resp = scanner_client.get(
            "/api/v1/scanner/findings?status=open", headers=auth_headers
        )
        assert resp.status_code == 200

    # --- Get by ID ---

    def test_get_finding_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.get(
            "/api/v1/scanner/findings/99999", headers=auth_headers
        )
        assert resp.status_code == 404

    # --- Stats ---

    def test_get_finding_stats_returns_200(self, scanner_client, auth_headers):
        resp = scanner_client.get(
            "/api/v1/scanner/findings/stats", headers=auth_headers
        )
        assert resp.status_code == 200

    def test_get_finding_stats_response_format(self, scanner_client, auth_headers):
        resp = scanner_client.get(
            "/api/v1/scanner/findings/stats", headers=auth_headers
        )
        data = json.loads(resp.data)
        assert "total" in data
        assert "by_severity" in data
        assert "by_status" in data
        assert "by_scanner" in data

    def test_get_finding_stats_severity_keys(self, scanner_client, auth_headers):
        resp = scanner_client.get(
            "/api/v1/scanner/findings/stats", headers=auth_headers
        )
        data = json.loads(resp.data)
        severity = data["by_severity"]
        for level in ("critical", "high", "medium", "low", "info"):
            assert level in severity

    def test_get_finding_stats_status_keys(self, scanner_client, auth_headers):
        resp = scanner_client.get(
            "/api/v1/scanner/findings/stats", headers=auth_headers
        )
        data = json.loads(resp.data)
        status = data["by_status"]
        for st in ("open", "acknowledged", "false_positive", "fixed"):
            assert st in status

    # --- Update (PATCH) ---

    def test_update_finding_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.patch(
            "/api/v1/scanner/findings/99999",
            data=json.dumps({"status": "acknowledged"}),
            headers=auth_headers,
        )
        assert resp.status_code == 404

    def test_update_finding_invalid_status_returns_400(
        self, scanner_client, auth_headers
    ):
        # First create a real finding via the DB helper used in integration tests
        from database.models import get_configured_db

        db = get_configured_db()
        # Create a minimal finding record directly so we can test PATCH validation
        target_id = db.scan_targets.insert(
            name="patch-finding-target",
            target_type="domain",
            target_value="example.com",
            enabled=True,
            tags=[],
            scan_metadata={},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        job_id = db.scan_jobs.insert(
            target_id=target_id,
            scanner_type="nuclei",
            scan_type="baseline",
            status="completed",
            priority=5,
            config={},
            created_at=datetime.utcnow(),
        )
        finding_id = db.scan_findings.insert(
            target_id=target_id,
            job_id=job_id,
            severity="high",
            title="Test vuln",
            description="desc",
            affected_url="https://example.com/path",
            status="open",
            discovered_at=datetime.utcnow(),
        )
        db.commit()

        resp = scanner_client.patch(
            f"/api/v1/scanner/findings/{finding_id}",
            data=json.dumps({"status": "NOT_A_VALID_STATUS"}),
            headers=auth_headers,
        )
        assert resp.status_code == 400

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_update_finding_status_acknowledged(
        self, mock_celery, scanner_client, auth_headers
    ):
        from database.models import get_configured_db

        db = get_configured_db()
        target_id = db.scan_targets.insert(
            name="ack-finding-target",
            target_type="domain",
            target_value="example.com",
            enabled=True,
            tags=[],
            scan_metadata={},
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        job_id = db.scan_jobs.insert(
            target_id=target_id,
            scanner_type="nuclei",
            scan_type="baseline",
            status="completed",
            priority=5,
            config={},
            created_at=datetime.utcnow(),
        )
        finding_id = db.scan_findings.insert(
            target_id=target_id,
            job_id=job_id,
            severity="critical",
            title="Critical vuln",
            description="Critical finding",
            affected_url="https://example.com/admin",
            status="open",
            discovered_at=datetime.utcnow(),
        )
        db.commit()

        resp = scanner_client.patch(
            f"/api/v1/scanner/findings/{finding_id}",
            data=json.dumps({"status": "acknowledged"}),
            headers=auth_headers,
        )
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "acknowledged"

    # --- Export ---

    def test_export_findings_json_format(self, scanner_client, auth_headers):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/findings/export",
            {"format": "json"},
            auth_headers,
        )
        assert resp.status_code == 200

    def test_export_findings_csv_format(self, scanner_client, auth_headers):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/findings/export",
            {"format": "csv"},
            auth_headers,
        )
        assert resp.status_code == 200
        assert "text/csv" in resp.content_type

    def test_export_findings_invalid_format_returns_400(
        self, scanner_client, auth_headers
    ):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/findings/export",
            {"format": "xml"},
            auth_headers,
        )
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# TestSchedulesAPI
# ---------------------------------------------------------------------------


class TestSchedulesAPI:
    """Scan schedule CRUD and manual trigger endpoints."""

    # --- List ---

    def test_list_schedules_requires_auth(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/schedules")
        assert resp.status_code == 401

    def test_list_schedules_returns_200(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/schedules", headers=auth_headers)
        assert resp.status_code == 200

    def test_list_schedules_response_format(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/schedules", headers=auth_headers)
        data = json.loads(resp.data)
        assert "schedules" in data
        assert "total" in data
        assert "page" in data
        assert "per_page" in data

    # --- Create ---

    def test_create_schedule_success(self, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="schedule-create-target"
        )
        payload = {
            "name": "Daily nuclei scan",
            "target_id": target_data["id"],
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "cron_expression": "0 0 * * *",
            "enabled": True,
        }
        resp = _post_json(
            scanner_client, "/api/v1/scanner/schedules", payload, auth_headers
        )
        assert resp.status_code == 201
        data = json.loads(resp.data)
        assert data["name"] == "Daily nuclei scan"
        assert data["cron_expression"] == "0 0 * * *"
        assert "next_run" in data
        assert "id" in data

    def test_create_schedule_invalid_cron_returns_400(
        self, scanner_client, auth_headers
    ):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="schedule-bad-cron-target"
        )
        payload = {
            "name": "Bad cron schedule",
            "target_id": target_data["id"],
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "cron_expression": "not-a-cron",
        }
        resp = _post_json(
            scanner_client, "/api/v1/scanner/schedules", payload, auth_headers
        )
        assert resp.status_code == 400

    def test_create_schedule_target_not_found_returns_404(
        self, scanner_client, auth_headers
    ):
        payload = {
            "name": "Orphan schedule",
            "target_id": 99999,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "cron_expression": "0 0 * * *",
        }
        resp = _post_json(
            scanner_client, "/api/v1/scanner/schedules", payload, auth_headers
        )
        assert resp.status_code == 404

    def test_create_schedule_missing_required_fields_returns_400(
        self, scanner_client, auth_headers
    ):
        resp = _post_json(
            scanner_client,
            "/api/v1/scanner/schedules",
            {"name": "Incomplete schedule"},
            auth_headers,
        )
        assert resp.status_code == 400

    # --- Get ---

    def test_get_schedule_success(self, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="schedule-get-target"
        )
        payload = {
            "name": "Get schedule test",
            "target_id": target_data["id"],
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "cron_expression": "0 2 * * *",
        }
        create_resp = _post_json(
            scanner_client, "/api/v1/scanner/schedules", payload, auth_headers
        )
        schedule_id = json.loads(create_resp.data)["id"]

        resp = scanner_client.get(
            f"/api/v1/scanner/schedules/{schedule_id}", headers=auth_headers
        )
        assert resp.status_code == 200
        result = json.loads(resp.data)
        assert result["id"] == schedule_id
        assert result["name"] == "Get schedule test"

    def test_get_schedule_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.get(
            "/api/v1/scanner/schedules/99999", headers=auth_headers
        )
        assert resp.status_code == 404

    # --- Update ---

    def test_update_schedule_success(self, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="schedule-update-target"
        )
        payload = {
            "name": "Update schedule test",
            "target_id": target_data["id"],
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "cron_expression": "0 3 * * *",
        }
        create_resp = _post_json(
            scanner_client, "/api/v1/scanner/schedules", payload, auth_headers
        )
        schedule_id = json.loads(create_resp.data)["id"]

        resp = scanner_client.put(
            f"/api/v1/scanner/schedules/{schedule_id}",
            data=json.dumps({"cron_expression": "0 6 * * 0", "enabled": False}),
            headers=auth_headers,
        )
        assert resp.status_code == 200
        result = json.loads(resp.data)
        assert result["cron_expression"] == "0 6 * * 0"
        assert result["enabled"] is False

    def test_update_schedule_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.put(
            "/api/v1/scanner/schedules/99999",
            data=json.dumps({"enabled": False}),
            headers=auth_headers,
        )
        assert resp.status_code == 404

    # --- Delete ---

    def test_delete_schedule_success(self, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="schedule-delete-target"
        )
        payload = {
            "name": "Delete schedule test",
            "target_id": target_data["id"],
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "cron_expression": "0 4 * * *",
        }
        create_resp = _post_json(
            scanner_client, "/api/v1/scanner/schedules", payload, auth_headers
        )
        schedule_id = json.loads(create_resp.data)["id"]

        resp = scanner_client.delete(
            f"/api/v1/scanner/schedules/{schedule_id}", headers=auth_headers
        )
        assert resp.status_code == 204

        # Verify gone
        get_resp = scanner_client.get(
            f"/api/v1/scanner/schedules/{schedule_id}", headers=auth_headers
        )
        assert get_resp.status_code == 404

    def test_delete_schedule_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.delete(
            "/api/v1/scanner/schedules/99999", headers=auth_headers
        )
        assert resp.status_code == 404

    # --- Manual run ---

    @patch(
        "workers.scan_worker.execute_scan.delay",
        return_value=MagicMock(id="mock-task-id"),
    )
    def test_run_schedule_manually(self, mock_celery, scanner_client, auth_headers):
        target_data, _ = _create_target(
            scanner_client, auth_headers, name="schedule-run-target"
        )
        payload = {
            "name": "Run schedule test",
            "target_id": target_data["id"],
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "cron_expression": "0 5 * * *",
        }
        create_resp = _post_json(
            scanner_client, "/api/v1/scanner/schedules", payload, auth_headers
        )
        schedule_id = json.loads(create_resp.data)["id"]

        resp = scanner_client.post(
            f"/api/v1/scanner/schedules/{schedule_id}/run",
            headers=auth_headers,
        )
        assert resp.status_code == 202
        result = json.loads(resp.data)
        assert result["status"] == "pending"
        assert result["scanner_type"] == "nuclei"

    def test_run_schedule_not_found_returns_404(self, scanner_client, auth_headers):
        resp = scanner_client.post(
            "/api/v1/scanner/schedules/99999/run", headers=auth_headers
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# TestScannersAPI
# ---------------------------------------------------------------------------


class TestScannersAPI:
    """Scanner status information endpoint."""

    def test_get_scanners_requires_auth(self, scanner_client):
        resp = scanner_client.get("/api/v1/scanner/scanners")
        assert resp.status_code == 401

    def test_get_scanners_returns_200(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/scanners", headers=auth_headers)
        assert resp.status_code == 200

    def test_get_scanners_response_has_scanners_list(
        self, scanner_client, auth_headers
    ):
        resp = scanner_client.get("/api/v1/scanner/scanners", headers=auth_headers)
        data = json.loads(resp.data)
        assert "scanners" in data
        assert isinstance(data["scanners"], list)

    def test_get_scanners_list_has_three_entries(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/scanners", headers=auth_headers)
        data = json.loads(resp.data)
        # nuclei, zap, openvas
        assert len(data["scanners"]) == 3

    def test_get_scanners_each_entry_has_required_fields(
        self, scanner_client, auth_headers
    ):
        resp = scanner_client.get("/api/v1/scanner/scanners", headers=auth_headers)
        data = json.loads(resp.data)
        for scanner in data["scanners"]:
            assert "name" in scanner
            assert "enabled" in scanner
            assert "available" in scanner
            assert "status" in scanner

    def test_get_scanners_nuclei_present(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/scanners", headers=auth_headers)
        data = json.loads(resp.data)
        names = [s["name"] for s in data["scanners"]]
        assert "nuclei" in names

    def test_get_scanners_zap_present(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/scanners", headers=auth_headers)
        data = json.loads(resp.data)
        names = [s["name"] for s in data["scanners"]]
        assert "zap" in names

    def test_get_scanners_openvas_present(self, scanner_client, auth_headers):
        resp = scanner_client.get("/api/v1/scanner/scanners", headers=auth_headers)
        data = json.loads(resp.data)
        names = [s["name"] for s in data["scanners"]]
        assert "openvas" in names


# ---------------------------------------------------------------------------
# Authentication edge cases (cross-cutting)
# ---------------------------------------------------------------------------


class TestAuthEdgeCases:
    """JWT authentication rejection cases shared across all protected routes."""

    def test_expired_token_returns_401(self, scanner_client):
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
        resp = scanner_client.get("/api/v1/scanner/targets", headers=headers)
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, scanner_client):
        headers = {
            "Authorization": "Bearer garbage.token.value",
            "Content-Type": "application/json",
        }
        resp = scanner_client.get("/api/v1/scanner/targets", headers=headers)
        assert resp.status_code == 401

    def test_missing_authorization_header_returns_401(self, scanner_client):
        resp = scanner_client.get(
            "/api/v1/scanner/targets",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 401
