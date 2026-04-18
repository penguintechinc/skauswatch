"""
Pytest configuration and fixtures for worker-s3 unit tests.
"""

import os
import sys

import pytest

# Ensure the service root is on the path so `from models import ...` works
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def valid_task_message_data():
    """Minimal valid data for ScanTaskMessage construction."""
    return {
        "task_id": "task-001",
        "job_id": "job-001",
        "bucket_config_id": "config-1",
        "object_key": "uploads/test.pdf",
        "object_size": 1024,
        "endpoint_url": "https://s3.example.com",
        "bucket_name": "test-bucket",
        "access_key": "AKIATEST",
        "secret_key": "test-secret",
    }


@pytest.fixture
def valid_result_message_data():
    """Minimal valid data for ScanResultMessage construction."""
    return {
        "task_id": "task-001",
        "job_id": "job-001",
        "object_key": "uploads/test.pdf",
        "scan_status": "completed",
        "is_malware": False,
        "is_pup": False,
        "is_threat": False,
        "detected_file_type": "application/pdf",
        "file_md5": "5d41402abc4b2a76b9719d911017c592",
        "file_sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "file_sha256": "2c26b46b09173bf4e46a8e6e3a5a" + "b1b1c4b6c4d4e4f4a4b4c4d4e4f4a4b4",
        "scan_duration_ms": 1234,
    }
