"""E2E tests for the full S3 malware scanning pipeline.

Tests the complete workflow:
1. Connectivity to MinIO storage
2. File upload to MinIO
3. Manager service health
4. Worker scanner health (if available)
"""

import logging
import time
from io import BytesIO

import boto3
import botocore.exceptions
import pytest
import requests

logger = logging.getLogger(__name__)

TEST_BUCKET = "skauswatch-e2e-test"
SAFE_TEST_CONTENT = b"This is a safe test file for E2E testing. No malware here."


@pytest.mark.e2e
class TestFullScanPipeline:
    """Full scan pipeline end-to-end tests."""

    @pytest.fixture(autouse=True)
    def skip_if_manager_unavailable(self, check_services_available):
        """Skip tests if Manager service is not available."""
        if not check_services_available.get("manager"):
            pytest.skip("Manager service is not available")

    def test_manager_health(self, manager_url: str):
        """Verify Manager service is healthy."""
        response = requests.get(f"{manager_url}/healthz", timeout=5)
        assert response.status_code == 200

    def test_minio_connectivity(self, minio_url: str, minio_credentials: dict):
        """Verify MinIO S3 storage is reachable and credentials are valid."""
        s3 = boto3.client(
            "s3",
            endpoint_url=minio_url,
            aws_access_key_id=minio_credentials["access_key"],
            aws_secret_access_key=minio_credentials["secret_key"],
            region_name="us-east-1",
        )
        try:
            s3.list_buckets()
        except botocore.exceptions.EndpointResolutionError:
            pytest.skip("MinIO endpoint not reachable")
        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] in ("403", "InvalidAccessKeyId"):
                pytest.fail(f"MinIO credential error: {e}")
            raise

    def test_upload_file_to_minio(self, minio_url: str, minio_credentials: dict):
        """Upload a safe test file to MinIO storage.

        This test verifies basic S3-compatible storage connectivity
        before attempting a full scan.
        """
        s3 = boto3.client(
            "s3",
            endpoint_url=minio_url,
            aws_access_key_id=minio_credentials["access_key"],
            aws_secret_access_key=minio_credentials["secret_key"],
            region_name="us-east-1",
        )
        try:
            # Create test bucket if needed
            try:
                s3.create_bucket(Bucket=TEST_BUCKET)
            except botocore.exceptions.ClientError as e:
                if e.response["Error"]["Code"] not in (
                    "BucketAlreadyExists",
                    "BucketAlreadyOwnedByYou",
                ):
                    raise

            # Upload test file
            key = f"e2e-test/{int(time.time())}/safe-test.txt"
            s3.upload_fileobj(BytesIO(SAFE_TEST_CONTENT), TEST_BUCKET, key)

            # Verify upload
            response = s3.head_object(Bucket=TEST_BUCKET, Key=key)
            assert response["ContentLength"] == len(SAFE_TEST_CONTENT)

            # Cleanup
            s3.delete_object(Bucket=TEST_BUCKET, Key=key)

        except botocore.exceptions.EndpointResolutionError:
            pytest.skip("MinIO endpoint not reachable")

    def test_worker_scanner_health(self):
        """Verify worker-scanner service is healthy if available.

        The worker-scanner service may not be running in all environments.
        This test gracefully skips if the service is not configured.
        """
        # Worker scanner URL not in conftest — would need to be added if service exists
        # Check environment variable or skip if not configured
        scanner_url = None
        import os

        if "WORKER_SCANNER_URL" in os.environ:
            scanner_url = os.getenv("WORKER_SCANNER_URL")
        elif "SCANNER_URL" in os.environ:
            scanner_url = os.getenv("SCANNER_URL")

        if not scanner_url:
            pytest.skip("Worker scanner URL not configured")

        try:
            response = requests.get(f"{scanner_url}/api/v1/scanner/healthz", timeout=5)
            assert response.status_code == 200
        except requests.exceptions.ConnectionError:
            pytest.skip("Worker scanner service not reachable")

    def test_clean_up_test_data(self, minio_url: str, minio_credentials: dict):
        """Clean up any leftover test data from previous E2E runs.

        This runs after all file upload tests to remove E2E test objects.
        """
        s3 = boto3.client(
            "s3",
            endpoint_url=minio_url,
            aws_access_key_id=minio_credentials["access_key"],
            aws_secret_access_key=minio_credentials["secret_key"],
            region_name="us-east-1",
        )
        try:
            paginator = s3.get_paginator("list_objects_v2")
            pages = paginator.paginate(Bucket=TEST_BUCKET, Prefix="e2e-test/")
            deleted = 0
            for page in pages:
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=TEST_BUCKET, Key=obj["Key"])
                    deleted += 1
            if deleted:
                logger.info(f"Cleaned up {deleted} E2E test objects from MinIO")
        except botocore.exceptions.ClientError:
            pass  # Bucket may not exist — nothing to clean
        except botocore.exceptions.EndpointResolutionError:
            pytest.skip("MinIO endpoint not reachable")
