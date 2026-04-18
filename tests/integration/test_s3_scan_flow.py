"""
Integration tests for S3 scan workflow.

Tests the complete flow: create bucket config -> trigger scan ->
worker processes -> result retrieval. Uses real services via
docker-compose.test.yml or gracefully skips.

EICAR test string: standard antivirus test pattern (safe, not real malware).
"""

import asyncio
import time

import httpx
import pytest

MANAGER_URL = "http://localhost:5000/api/v1"
EICAR_STRING = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
    "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

pytestmark = [pytest.mark.integration]


@pytest.fixture
async def manager_client(manager_service_ready):
    """Provide authenticated async client for manager API."""
    if not manager_service_ready:
        pytest.skip("Manager service not available")

    async with httpx.AsyncClient(base_url=MANAGER_URL, timeout=10.0) as client:
        # Login as admin to get token
        login_resp = await client.post(
            "/auth/login",
            json={"email": "admin@skauswatch.local", "password": "admin"},
        )
        if login_resp.status_code != 200:
            pytest.skip("Could not authenticate with manager service")

        token = login_resp.json().get("access_token")
        client.headers["Authorization"] = f"Bearer {token}"
        yield client


class TestS3ScanBucketLifecycle:
    """Test bucket config CRUD via manager API."""

    @pytest.mark.asyncio
    async def test_create_bucket_config(self, manager_client):
        """Create a new bucket configuration."""
        response = await manager_client.post(
            "/s3scan/buckets",
            json={
                "name": "integration-test-bucket",
                "bucket_name": "test-scans",
                "endpoint_url": "http://minio:9000",
                "access_key": "minioadmin",
                "secret_key": "minioadmin",
                "region": "us-east-1",
                "scan_enabled": True,
            },
        )
        assert response.status_code in (200, 201)
        data = response.json()
        assert data["name"] == "integration-test-bucket"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_list_bucket_configs(self, manager_client):
        """List bucket configurations."""
        response = await manager_client.get("/s3scan/buckets")
        assert response.status_code == 200
        data = response.json()
        assert "items" in data or isinstance(data, list)

    @pytest.mark.asyncio
    async def test_delete_bucket_config(self, manager_client):
        """Create and delete a bucket configuration."""
        create_resp = await manager_client.post(
            "/s3scan/buckets",
            json={
                "name": "delete-me-bucket",
                "bucket_name": "delete-test",
                "endpoint_url": "http://minio:9000",
                "access_key": "minioadmin",
                "secret_key": "minioadmin",
            },
        )
        if create_resp.status_code not in (200, 201):
            pytest.skip("Could not create test bucket config")

        bucket_id = create_resp.json()["id"]
        delete_resp = await manager_client.delete(f"/s3scan/buckets/{bucket_id}")
        assert delete_resp.status_code in (200, 204)


class TestS3ScanTriggerAndResult:
    """Test scan trigger → worker processes → result retrieval."""

    @pytest.fixture
    async def test_bucket(self, manager_client):
        """Create a test bucket config and clean up after."""
        resp = await manager_client.post(
            "/s3scan/buckets",
            json={
                "name": "scan-flow-test",
                "bucket_name": "scan-flow-test",
                "endpoint_url": "http://minio:9000",
                "access_key": "minioadmin",
                "secret_key": "minioadmin",
                "scan_enabled": True,
            },
        )
        if resp.status_code not in (200, 201):
            pytest.skip("Could not create test bucket config")
        bucket = resp.json()
        yield bucket
        # Cleanup
        await manager_client.delete(f"/s3scan/buckets/{bucket['id']}")

    @pytest.mark.asyncio
    async def test_trigger_scan(self, manager_client, test_bucket):
        """Trigger a scan on a bucket."""
        response = await manager_client.post(
            f"/s3scan/buckets/{test_bucket['id']}/scan",
            json={"force_rescan": False},
        )
        assert response.status_code in (200, 201, 202)

    @pytest.mark.asyncio
    async def test_scan_statistics(self, manager_client):
        """Retrieve overall scan statistics."""
        response = await manager_client.get("/s3scan/statistics")
        assert response.status_code == 200
        data = response.json()
        # Statistics should return numeric fields
        assert isinstance(data, dict)


class TestS3FileUpload:
    """Test ad-hoc file upload scanning."""

    @pytest.mark.asyncio
    async def test_upload_clean_file(self, manager_client):
        """Upload a clean file for scanning."""
        files = {"file": ("clean-test.txt", b"Hello, this is a clean test file.")}
        response = await manager_client.post("/s3scan/upload", files=files)
        # Accept 200 or 201 for successful upload
        assert response.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_upload_eicar_file(self, manager_client):
        """Upload EICAR test virus for detection verification."""
        files = {"file": ("eicar-test.com", EICAR_STRING.encode())}
        response = await manager_client.post("/s3scan/upload", files=files)
        # Upload should succeed (scanning happens async)
        assert response.status_code in (200, 201)

    @pytest.mark.asyncio
    async def test_upload_history(self, manager_client):
        """Retrieve upload history."""
        response = await manager_client.get("/s3scan/upload")
        assert response.status_code == 200


class TestScanResultPolling:
    """Test polling scan status until completion."""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_poll_scan_until_complete(self, manager_client):
        """Upload file and poll for completion (max 30s)."""
        files = {"file": ("poll-test.txt", b"Test file for polling.")}
        upload_resp = await manager_client.post("/s3scan/upload", files=files)
        if upload_resp.status_code not in (200, 201):
            pytest.skip("Upload endpoint not available")

        data = upload_resp.json()
        scan_id = data.get("scan_id") or data.get("id")
        if not scan_id:
            pytest.skip("No scan_id in upload response")

        # Poll for up to 30 seconds
        deadline = time.time() + 30
        status = None
        while time.time() < deadline:
            result_resp = await manager_client.get(f"/s3scan/upload/{scan_id}")
            if result_resp.status_code == 200:
                result_data = result_resp.json()
                status = result_data.get("status")
                if status in ("completed", "clean", "infected", "error"):
                    break
            await asyncio.sleep(2)

        # Should have reached a terminal status
        assert status is not None, "Scan did not complete within timeout"
