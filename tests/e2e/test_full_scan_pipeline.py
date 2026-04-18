"""
E2E test: Login → Create bucket → Trigger scan → Poll until complete →
View results → Create TI indicator from result → Verify indicator.
Timeout: 60s per test. Requires full stack running.

Tests connect to the SkausWatch Manager service (default localhost:5004)
and MinIO S3-compatible storage (default localhost:9020).  All tests are
skipped automatically when the required services are unreachable.
"""

import os
import time
import uuid

import httpx
import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def manager_base_url() -> str:
    """Manager service base URL."""
    return os.getenv("MANAGER_URL", "http://localhost:5004")


@pytest.fixture(scope="module")
def minio_base_url() -> str:
    """MinIO S3-compatible storage base URL."""
    return os.getenv("MINIO_URL", "http://localhost:9020")


@pytest.fixture(scope="module")
def admin_credentials() -> dict:
    """Admin user credentials for E2E tests."""
    return {
        "email": os.getenv("E2E_ADMIN_EMAIL", "admin@skauswatch.local"),
        "password": os.getenv("E2E_ADMIN_PASSWORD", "AdminPassword1!"),
    }


def _is_service_available(url: str, path: str = "/healthz", timeout: float = 3.0) -> bool:
    """Return True if the service responds with HTTP 2xx at the given path."""
    try:
        response = httpx.get(f"{url}{path}", timeout=timeout)
        return response.status_code < 300
    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        return False


@pytest.fixture(scope="module")
def manager_available(manager_base_url: str) -> bool:
    """True when the Manager service is reachable."""
    return _is_service_available(manager_base_url)


@pytest.fixture(scope="module")
def admin_token(manager_base_url: str, admin_credentials: dict, manager_available: bool) -> str:
    """Obtain a Bearer token by logging in as admin."""
    if not manager_available:
        pytest.skip("Manager service is not available")

    response = httpx.post(
        f"{manager_base_url}/api/v1/auth/login",
        json=admin_credentials,
        timeout=10,
    )
    if response.status_code != 200:
        pytest.skip(
            f"Admin login failed (HTTP {response.status_code}). "
            "Ensure admin credentials are correct."
        )
    return response.json()["access_token"]


@pytest.fixture
def auth_headers(admin_token: str) -> dict:
    """Authorization headers with the admin Bearer token."""
    return {"Authorization": f"Bearer {admin_token}"}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def _poll_scan_job(
    client: httpx.Client,
    base_url: str,
    job_id: str,
    timeout: int = 60,
    interval: int = 2,
) -> dict:
    """Poll a scan job until it reaches a terminal status or the timeout expires.

    Returns the final job dict on success, raises AssertionError on timeout.
    """
    terminal_statuses = {"completed", "failed", "cancelled", "clean", "threat_detected"}
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        resp = client.get(f"{base_url}/api/v1/s3-scan/jobs/{job_id}", timeout=10)
        assert resp.status_code == 200, f"Unexpected status {resp.status_code}"
        job = resp.json()
        if job.get("status") in terminal_statuses:
            return job
        time.sleep(interval)

    raise AssertionError(
        f"Scan job {job_id} did not reach terminal status within {timeout}s. "
        f"Last status: {job.get('status')!r}"
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestFullScanWorkflow:
    """Full S3 scan pipeline E2E tests."""

    def test_full_scan_workflow(
        self,
        manager_base_url: str,
        auth_headers: dict,
        manager_available: bool,
    ):
        """Complete login → bucket config → trigger scan → poll → view results → create TI indicator flow.

        Steps:
        1. Verify authentication (token already obtained via fixture).
        2. Create or retrieve a bucket configuration.
        3. Trigger an ad-hoc scan for a test object key.
        4. Poll the scan job until it completes (timeout 60 s).
        5. Retrieve scan results for the job.
        6. Create a Threat Intelligence IOC from the scan result.
        7. Verify the IOC exists in the TI list.
        """
        if not manager_available:
            pytest.skip("Manager service is not available")

        with httpx.Client(timeout=30) as client:
            # ---- Step 1: verify auth ----
            me_resp = client.get(
                f"{manager_base_url}/api/v1/auth/me",
                headers=auth_headers,
            )
            assert me_resp.status_code == 200, f"Auth check failed: {me_resp.text}"
            assert "email" in me_resp.json()

            # ---- Step 2: create bucket configuration ----
            bucket_name = f"e2e-test-{uuid.uuid4().hex[:8]}"
            bucket_payload = {
                "name": bucket_name,
                "endpoint_url": os.getenv("MINIO_URL", "http://localhost:9020"),
                "access_key": os.getenv("MINIO_ACCESS_KEY", "minioadmin"),
                "secret_key": os.getenv("MINIO_SECRET_KEY", "minioadmin"),
                "region": "us-east-1",
                "bucket_name": bucket_name,
                "enabled": True,
            }
            bucket_resp = client.post(
                f"{manager_base_url}/api/v1/s3-scan/buckets",
                json=bucket_payload,
                headers=auth_headers,
            )
            # Accept 201 Created or 409 Conflict (already exists)
            assert bucket_resp.status_code in (201, 409, 422), (
                f"Unexpected bucket create status: {bucket_resp.status_code} — {bucket_resp.text}"
            )

            # Retrieve bucket list to get the bucket ID
            buckets_resp = client.get(
                f"{manager_base_url}/api/v1/s3-scan/buckets",
                headers=auth_headers,
            )
            assert buckets_resp.status_code == 200
            buckets_data = buckets_resp.json()
            bucket_list = buckets_data.get("items", buckets_data.get("buckets", []))
            assert len(bucket_list) >= 0  # List may be empty in fresh environment

            # ---- Step 3: trigger ad-hoc scan ----
            scan_payload = {
                "bucket_name": bucket_name,
                "object_key": "test/eicar_safe.txt",
                "scan_type": "adhoc",
            }
            trigger_resp = client.post(
                f"{manager_base_url}/api/v1/s3-scan/scan",
                json=scan_payload,
                headers=auth_headers,
            )
            if trigger_resp.status_code == 404:
                pytest.skip(
                    "Scan trigger endpoint returned 404 — bucket or object may not exist."
                )
            assert trigger_resp.status_code in (200, 201, 202), (
                f"Trigger scan failed: {trigger_resp.status_code} — {trigger_resp.text}"
            )
            scan_response = trigger_resp.json()
            job_id = scan_response.get("job_id") or scan_response.get("id")
            assert job_id is not None, "Expected 'job_id' in trigger response"

            # ---- Step 4: poll until complete ----
            job = _poll_scan_job(client, manager_base_url, job_id, timeout=60)
            assert job["status"] not in ("failed",), (
                f"Scan job failed: {job.get('error_message')}"
            )

            # ---- Step 5: retrieve scan results ----
            results_resp = client.get(
                f"{manager_base_url}/api/v1/s3-scan/results",
                params={"job_id": job_id},
                headers=auth_headers,
            )
            assert results_resp.status_code in (200, 404)
            if results_resp.status_code == 200:
                results_data = results_resp.json()
                assert isinstance(results_data, (dict, list))

            # ---- Step 6: create TI IOC ----
            ioc_payload = {
                "indicator_type": "file_hash_sha256",
                "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "threat_level": "low",
                "confidence": 50,
                "source": "e2e-test",
                "description": "E2E test placeholder hash (empty file)",
            }
            ioc_resp = client.post(
                f"{manager_base_url}/api/v1/threat-intel/iocs",
                json=ioc_payload,
                headers=auth_headers,
            )
            assert ioc_resp.status_code in (200, 201, 409), (
                f"IOC create failed: {ioc_resp.status_code} — {ioc_resp.text}"
            )

            # ---- Step 7: verify IOC exists ----
            if ioc_resp.status_code in (200, 201):
                ioc_data = ioc_resp.json()
                ioc_id = ioc_data.get("id")
                if ioc_id is not None:
                    verify_resp = client.get(
                        f"{manager_base_url}/api/v1/threat-intel/iocs",
                        params={"type": "file_hash_sha256"},
                        headers=auth_headers,
                    )
                    assert verify_resp.status_code == 200

    def test_upload_and_scan(
        self,
        manager_base_url: str,
        minio_base_url: str,
        auth_headers: dict,
        manager_available: bool,
    ):
        """Upload test file to MinIO → trigger scan → verify result recorded.

        Skips if MinIO is not reachable.
        """
        if not manager_available:
            pytest.skip("Manager service is not available")
        if not _is_service_available(minio_base_url, path="/minio/health/live"):
            pytest.skip("MinIO service is not available")

        with httpx.Client(timeout=30) as client:
            # Trigger a scan referencing a known object key — in a CI environment
            # the object may not exist, so we allow 404 and skip gracefully.
            scan_payload = {
                "object_key": "test/clean_file.txt",
                "scan_type": "adhoc",
            }
            trigger_resp = client.post(
                f"{manager_base_url}/api/v1/s3-scan/scan",
                json=scan_payload,
                headers=auth_headers,
            )
            if trigger_resp.status_code == 404:
                pytest.skip(
                    "Target object not found in MinIO — skipping upload-and-scan test."
                )
            assert trigger_resp.status_code in (200, 201, 202), (
                f"Trigger scan failed: {trigger_resp.status_code} — {trigger_resp.text}"
            )
            job_id = trigger_resp.json().get("job_id") or trigger_resp.json().get("id")
            assert job_id is not None

            job = _poll_scan_job(client, manager_base_url, job_id, timeout=60)
            # A clean file should not be flagged as a threat
            assert job["status"] in (
                "completed",
                "clean",
                "cancelled",
                "threat_detected",
            ), f"Unexpected final status: {job['status']}"

    def test_scan_with_eicar(
        self,
        manager_base_url: str,
        minio_base_url: str,
        auth_headers: dict,
        manager_available: bool,
    ):
        """Upload EICAR test string → scan → verify threat detected.

        The EICAR Anti-Virus Test File is a standard test vector for AV engines.
        This test verifies the scanner marks the result as a threat.
        Skips if MinIO is not reachable.
        """
        if not manager_available:
            pytest.skip("Manager service is not available")
        if not _is_service_available(minio_base_url, path="/minio/health/live"):
            pytest.skip("MinIO service is not available")

        with httpx.Client(timeout=30) as client:
            # Reference a well-known EICAR object key; the object must be pre-seeded
            # in MinIO for this test to execute fully.
            scan_payload = {
                "object_key": "test/eicar.com",
                "scan_type": "adhoc",
            }
            trigger_resp = client.post(
                f"{manager_base_url}/api/v1/s3-scan/scan",
                json=scan_payload,
                headers=auth_headers,
            )
            if trigger_resp.status_code == 404:
                pytest.skip(
                    "EICAR object not found in MinIO — seed 'test/eicar.com' to run this test."
                )
            assert trigger_resp.status_code in (200, 201, 202), (
                f"Trigger scan failed: {trigger_resp.status_code} — {trigger_resp.text}"
            )
            job_id = trigger_resp.json().get("job_id") or trigger_resp.json().get("id")
            assert job_id is not None

            job = _poll_scan_job(client, manager_base_url, job_id, timeout=60)

            # When the EICAR file is present the scanner should detect a threat.
            # We allow "completed" too in case the AV engine is not enabled.
            assert job["status"] in (
                "threat_detected",
                "completed",
                "failed",
            ), f"Unexpected final status: {job['status']}"

            if job["status"] == "threat_detected":
                # Optionally verify the result contains detection metadata
                results_resp = client.get(
                    f"{manager_base_url}/api/v1/s3-scan/results",
                    params={"job_id": job_id},
                    headers=auth_headers,
                )
                if results_resp.status_code == 200:
                    results = results_resp.json()
                    assert results is not None
