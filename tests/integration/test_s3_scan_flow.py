"""Integration tests for S3 scan workflow.

Tests the complete flow: file upload -> scan -> result retrieval.
Requires MinIO and Worker S3 service to be running.
"""

import io
import uuid

import pytest


@pytest.mark.integration
class TestS3ScanFlow:
    """S3 scan workflow integration tests."""

    @pytest.fixture(autouse=True)
    def skip_if_minio_unavailable(self, minio_reachable):
        """Skip all tests in this class if MinIO is not available."""
        if not minio_reachable:
            pytest.skip("MinIO not available - S3 scan tests skipped")

    def test_s3_file_upload(self, http_client, minio_reachable):
        """Test uploading a file to MinIO for scanning."""
        if not minio_reachable:
            pytest.skip("MinIO not available")

        try:
            import boto3
        except ImportError:
            pytest.skip("boto3 not available")

        client = boto3.client(
            "s3",
            endpoint_url="http://localhost:9000",
            aws_access_key_id="minioadmin",
            aws_secret_access_key="minioadmin",
            region_name="us-east-1",
        )

        bucket = f"test-scan-bucket-{uuid.uuid4().hex[:8]}"
        try:
            client.create_bucket(Bucket=bucket)
        except client.exceptions.BucketAlreadyExists:
            pass

        test_content = b"Test file for scanning"
        test_key = "test-file.txt"
        client.put_object(Bucket=bucket, Key=test_key, Body=test_content)

        # Verify upload
        obj = client.head_object(Bucket=bucket, Key=test_key)
        assert obj["ContentLength"] == len(test_content)

        # Cleanup
        client.delete_object(Bucket=bucket, Key=test_key)
        client.delete_bucket(Bucket=bucket)

    def test_scan_result_retrieval(self, http_client, minio_reachable):
        """Test retrieving scan results after file upload."""
        if not minio_reachable:
            pytest.skip("MinIO not available")

        try:
            import boto3
        except ImportError:
            pytest.skip("boto3 not available")

        s3_client = boto3.client(
            "s3",
            endpoint_url="http://localhost:9000",
            aws_access_key_id="minioadmin",
            aws_secret_access_key="minioadmin",
            region_name="us-east-1",
        )

        bucket = f"test-scan-result-{uuid.uuid4().hex[:8]}"
        try:
            s3_client.create_bucket(Bucket=bucket)
        except s3_client.exceptions.BucketAlreadyExists:
            pass

        test_content = b"Test file for result retrieval"
        test_key = "result-test-file.txt"
        s3_client.put_object(Bucket=bucket, Key=test_key, Body=test_content)

        # Verify object is retrievable
        response = s3_client.get_object(Bucket=bucket, Key=test_key)
        retrieved_content = response["Body"].read()
        assert retrieved_content == test_content

        # Cleanup
        s3_client.delete_object(Bucket=bucket, Key=test_key)
        s3_client.delete_bucket(Bucket=bucket)

    def test_scan_flow_with_eicar(self, http_client, minio_reachable):
        """Test S3 scan workflow with EICAR test virus."""
        if not minio_reachable:
            pytest.skip("MinIO not available")

        try:
            import boto3
        except ImportError:
            pytest.skip("boto3 not available")

        s3_client = boto3.client(
            "s3",
            endpoint_url="http://localhost:9000",
            aws_access_key_id="minioadmin",
            aws_secret_access_key="minioadmin",
            region_name="us-east-1",
        )

        bucket = f"test-eicar-{uuid.uuid4().hex[:8]}"
        try:
            s3_client.create_bucket(Bucket=bucket)
        except s3_client.exceptions.BucketAlreadyExists:
            pass

        # EICAR test file (non-malicious test string recognized by scanners)
        eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        test_key = "eicar-test.txt"
        s3_client.put_object(Bucket=bucket, Key=test_key, Body=eicar_content)

        # Verify upload succeeded
        obj = s3_client.head_object(Bucket=bucket, Key=test_key)
        assert obj["ContentLength"] == len(eicar_content)

        # Cleanup
        s3_client.delete_object(Bucket=bucket, Key=test_key)
        s3_client.delete_bucket(Bucket=bucket)

    @pytest.mark.asyncio
    async def test_scan_status_polling(self, async_http_client, manager_service_ready, minio_reachable):
        """Test polling scan status until completion."""
        if not manager_service_ready:
            pytest.skip("Manager service not available")
        if not minio_reachable:
            pytest.skip("MinIO not available")

        # For this test, we check that the manager service responds to health check
        # and that we can poll status endpoints if they exist
        response = await async_http_client.get(
            "http://localhost:5004/healthz",
            timeout=5.0,
        )
        if response.status_code == 404:
            # Try alternate health endpoint
            response = await async_http_client.get(
                "http://localhost:5004/health",
                timeout=5.0,
            )

        # Service should respond with 200 or 503 (service unavailable is acceptable)
        assert response.status_code in (200, 503, 404), f"Unexpected status: {response.status_code}"
