"""Unit tests for manager-new S3 scan endpoints.

Tests: GET/POST/PUT/DELETE /api/v1/s3-scan/buckets, /results, /statistics, /upload
Uses Quart test client with SQLite :memory: database.
"""

import pytest

BUCKET_CONFIG_DATA = {
    "name": "test-bucket-1",
    "endpoint_url": "https://s3.amazonaws.com",
    "bucket_name": "my-bucket",
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "region": "us-east-1",
    "use_ssl": True,
    "max_file_size_mb": 100,
    "scan_enabled": True,
}


@pytest.mark.unit
class TestListBuckets:
    """GET /api/v1/s3-scan/buckets"""

    async def test_list_buckets_empty(self, client, admin_headers, seed_admin_user):
        """Empty bucket list returns valid pagination."""
        response = await client.get(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    async def test_list_buckets_after_create(
        self, client, admin_headers, seed_admin_user
    ):
        """Created buckets appear in list."""
        await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )

        response = await client.get(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["total"] >= 1
        assert len(data["items"]) >= 1
        assert data["items"][0]["name"] == "test-bucket-1"

    async def test_list_buckets_pagination(
        self, client, admin_headers, seed_admin_user
    ):
        """Pagination parameters are respected."""
        response = await client.get(
            "/api/v1/s3-scan/buckets?page=1&per_page=5",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["page"] == 1
        assert data["per_page"] == 5

    async def test_list_buckets_unauthenticated(self, client):
        """Unauthenticated request returns 401."""
        response = await client.get("/api/v1/s3-scan/buckets")
        assert response.status_code == 401


@pytest.mark.unit
class TestCreateBucket:
    """POST /api/v1/s3-scan/buckets"""

    async def test_create_bucket_success(
        self, client, admin_headers, seed_admin_user
    ):
        """Admin creates bucket config with valid data."""
        response = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert "bucket" in data
        assert data["bucket"]["name"] == "test-bucket-1"
        assert data["bucket"]["id"] is not None
        # Credentials should be masked in response
        assert data["bucket"]["access_key_id"].startswith("AKIA")
        assert "*" in data["bucket"]["access_key_id"]

    async def test_create_bucket_viewer_forbidden(self, client, viewer_headers):
        """Viewer cannot create bucket configs (403)."""
        response = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=viewer_headers,
            json=BUCKET_CONFIG_DATA,
        )
        assert response.status_code == 403

    async def test_create_bucket_duplicate_name(
        self, client, admin_headers, seed_admin_user
    ):
        """Duplicate endpoint_url + bucket_name returns 409."""
        # Create first
        await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )

        # Attempt duplicate
        response = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )
        assert response.status_code == 409
        data = await response.get_json()
        assert "error" in data

    async def test_create_bucket_missing_required_fields(
        self, client, admin_headers, seed_admin_user
    ):
        """Missing required fields return 400."""
        response = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json={"name": "incomplete-bucket"},
        )
        assert response.status_code == 400


@pytest.mark.unit
class TestGetBucket:
    """GET /api/v1/s3-scan/buckets/<bucket_id>"""

    async def test_get_bucket_by_id(self, client, admin_headers, seed_admin_user):
        """Get a specific bucket config by ID."""
        # Create first
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )
        create_data = await create_resp.get_json()
        bucket_id = create_data["bucket"]["id"]

        # Get by ID
        response = await client.get(
            f"/api/v1/s3-scan/buckets/{bucket_id}",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["name"] == "test-bucket-1"
        assert data["bucket_name"] == "my-bucket"
        assert data["region"] == "us-east-1"

    async def test_get_nonexistent_bucket(
        self, client, admin_headers, seed_admin_user
    ):
        """Non-existent bucket returns 404."""
        response = await client.get(
            "/api/v1/s3-scan/buckets/99999",
            headers=admin_headers,
        )
        assert response.status_code == 404


@pytest.mark.unit
class TestUpdateBucket:
    """PUT /api/v1/s3-scan/buckets/<bucket_id>"""

    async def test_update_bucket_success(
        self, client, admin_headers, seed_admin_user
    ):
        """Admin can update bucket config."""
        # Create
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )
        create_data = await create_resp.get_json()
        bucket_id = create_data["bucket"]["id"]

        # Update
        response = await client.put(
            f"/api/v1/s3-scan/buckets/{bucket_id}",
            headers=admin_headers,
            json={"name": "updated-bucket-name"},
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["bucket"]["name"] == "updated-bucket-name"

    async def test_update_bucket_viewer_forbidden(
        self,
        client,
        admin_headers,
        viewer_headers,
        seed_admin_user,
        seed_viewer_user,
    ):
        """Viewer cannot update bucket configs (403)."""
        # Create as admin
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )
        create_data = await create_resp.get_json()
        bucket_id = create_data["bucket"]["id"]

        # Try to update as viewer
        response = await client.put(
            f"/api/v1/s3-scan/buckets/{bucket_id}",
            headers=viewer_headers,
            json={"name": "viewer-update"},
        )
        assert response.status_code == 403


@pytest.mark.unit
class TestDeleteBucket:
    """DELETE /api/v1/s3-scan/buckets/<bucket_id>"""

    async def test_delete_bucket_success(
        self, client, admin_headers, seed_admin_user
    ):
        """Admin can delete bucket config."""
        # Create
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )
        create_data = await create_resp.get_json()
        bucket_id = create_data["bucket"]["id"]

        # Delete
        response = await client.delete(
            f"/api/v1/s3-scan/buckets/{bucket_id}",
            headers=admin_headers,
        )
        assert response.status_code == 200

        # Verify it is gone
        get_resp = await client.get(
            f"/api/v1/s3-scan/buckets/{bucket_id}",
            headers=admin_headers,
        )
        assert get_resp.status_code == 404

    async def test_delete_bucket_viewer_forbidden(
        self,
        client,
        admin_headers,
        viewer_headers,
        seed_admin_user,
        seed_viewer_user,
    ):
        """Viewer cannot delete bucket configs (403)."""
        # Create as admin
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )
        create_data = await create_resp.get_json()
        bucket_id = create_data["bucket"]["id"]

        # Try to delete as viewer
        response = await client.delete(
            f"/api/v1/s3-scan/buckets/{bucket_id}",
            headers=viewer_headers,
        )
        assert response.status_code == 403

    async def test_delete_nonexistent_bucket(
        self, client, admin_headers, seed_admin_user
    ):
        """Deleting non-existent bucket returns 404."""
        response = await client.delete(
            "/api/v1/s3-scan/buckets/99999",
            headers=admin_headers,
        )
        assert response.status_code == 404


@pytest.mark.unit
class TestTriggerScan:
    """POST /api/v1/s3-scan/buckets/<bucket_id>/scan"""

    async def test_trigger_scan_success(
        self, client, admin_headers, seed_admin_user
    ):
        """Admin can trigger a scan for a bucket."""
        # Create bucket first
        create_resp = await client.post(
            "/api/v1/s3-scan/buckets",
            headers=admin_headers,
            json=BUCKET_CONFIG_DATA,
        )
        create_data = await create_resp.get_json()
        bucket_id = create_data["bucket"]["id"]

        # Trigger scan
        response = await client.post(
            f"/api/v1/s3-scan/buckets/{bucket_id}/scan",
            headers=admin_headers,
            json={},
        )
        assert response.status_code == 201
        data = await response.get_json()
        assert "job" in data
        assert data["job"]["bucket_config_id"] == bucket_id
        assert data["job"]["status"] == "pending"

    async def test_trigger_scan_nonexistent_bucket(
        self, client, admin_headers, seed_admin_user
    ):
        """Triggering scan for non-existent bucket returns 404."""
        response = await client.post(
            "/api/v1/s3-scan/buckets/99999/scan",
            headers=admin_headers,
            json={},
        )
        assert response.status_code == 404


@pytest.mark.unit
class TestScanResults:
    """GET /api/v1/s3-scan/results and /statistics"""

    async def test_list_results_empty(self, client, admin_headers, seed_admin_user):
        """Empty results list returns valid pagination."""
        response = await client.get(
            "/api/v1/s3-scan/results",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["items"] == []
        assert data["total"] == 0

    async def test_statistics_empty(self, client, admin_headers, seed_admin_user):
        """Statistics with no scans returns zero counts."""
        response = await client.get(
            "/api/v1/s3-scan/statistics",
            headers=admin_headers,
        )
        assert response.status_code == 200
        data = await response.get_json()
        assert data["total_scanned"] == 0
        assert data["total_infected"] == 0
        assert "by_file_type" in data


@pytest.mark.unit
class TestAdhocUpload:
    """POST /api/v1/s3-scan/upload"""

    async def test_upload_no_file(self, client, admin_headers, seed_admin_user):
        """Upload without file returns 400."""
        response = await client.post(
            "/api/v1/s3-scan/upload",
            headers=admin_headers,
        )
        assert response.status_code == 400
