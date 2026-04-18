"""Test data factories for SkausWatch models.

Produces dicts matching the exact field names used in the manager-new
database models (services/manager-new/models/db.py) and Pydantic request
models (services/manager-new/validators/).
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_user(
    email: str = "testuser@example.com",
    full_name: str = "Test User",
    role: str = "viewer",
    password: str = "TestPassword123!",
    is_active: bool = True,
    **overrides: Any,
) -> dict:
    """Create a user registration/creation request body."""
    data = {
        "email": email,
        "full_name": full_name,
        "role": role,
        "password": password,
        "is_active": is_active,
    }
    data.update(overrides)
    return data


def make_alert(
    title: str = "Test Alert",
    description: str = "Suspicious activity detected in test environment",
    severity: str = "medium",
    source: str = "test-scanner",
    status: str = "pending",
    indicators: Optional[list] = None,
    **overrides: Any,
) -> dict:
    """Create an alert creation request body."""
    data = {
        "title": title,
        "description": description,
        "severity": severity,
        "source": source,
        "status": status,
        "indicators": indicators or [],
    }
    data.update(overrides)
    return data


def make_bucket_config(
    name: str = "test-bucket",
    endpoint_url: str = "https://s3.amazonaws.com",
    bucket_name: str = "my-test-bucket",
    access_key_id: str = "AKIAIOSFODNN7EXAMPLE",
    secret_access_key: str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: str = "us-east-1",
    use_ssl: bool = True,
    path_style: bool = False,
    prefix_filter: str = "",
    file_types_filter: Optional[list] = None,
    max_file_size_mb: int = 100,
    scan_enabled: bool = True,
    yara_enabled: bool = False,
    **overrides: Any,
) -> dict:
    """Create a bucket config creation request body."""
    data = {
        "name": name,
        "endpoint_url": endpoint_url,
        "bucket_name": bucket_name,
        "access_key_id": access_key_id,
        "secret_access_key": secret_access_key,
        "region": region,
        "use_ssl": use_ssl,
        "path_style": path_style,
        "prefix_filter": prefix_filter,
        "file_types_filter": file_types_filter or [],
        "max_file_size_mb": max_file_size_mb,
        "scan_enabled": scan_enabled,
        "yara_enabled": yara_enabled,
    }
    data.update(overrides)
    return data


def make_scan_result(
    object_key: str = "documents/test-file.pdf",
    object_size: int = 1024,
    content_type: str = "application/pdf",
    scan_status: str = "completed",
    is_malware: bool = False,
    is_threat: bool = False,
    file_md5: str = "d41d8cd98f00b204e9800998ecf8427e",
    file_sha1: str = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    file_sha256: str = "e3b0c44298fc1c149afbf4c8996fb924"
    "27ae41e4649b934ca495991b7852b855",
    **overrides: Any,
) -> dict:
    """Create a scan result dict (as returned from API)."""
    data = {
        "object_key": object_key,
        "object_size": object_size,
        "content_type": content_type,
        "scan_status": scan_status,
        "is_malware": is_malware,
        "is_threat": is_threat,
        "threat_names": [],
        "clamav_result": None,
        "yara_matches": None,
        "file_md5": file_md5,
        "file_sha1": file_sha1,
        "file_sha256": file_sha256,
        "ti_enrichment": None,
    }
    data.update(overrides)
    return data


def make_trigger_scan_request(
    prefix_filter: str = "",
    force_rescan: bool = False,
    **overrides: Any,
) -> dict:
    """Create a trigger scan request body."""
    data = {
        "prefix_filter": prefix_filter,
        "force_rescan": force_rescan,
    }
    data.update(overrides)
    return data


def make_ioc(
    indicator_type: str = "ip",
    value: str = "192.168.1.100",
    threat_type: str = "malware",
    confidence: float = 0.85,
    source: str = "manual",
    description: str = "Test IOC indicator",
    **overrides: Any,
) -> dict:
    """Create a threat intel IOC creation request body."""
    data = {
        "indicator_type": indicator_type,
        "value": value,
        "threat_type": threat_type,
        "confidence": confidence,
        "source": source,
        "description": description,
    }
    data.update(overrides)
    return data
