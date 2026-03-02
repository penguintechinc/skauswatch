import pytest
from datetime import timezone

from ocsf.normalizer import normalize


def test_normalize_auth_source():
    raw = {"message": "user login", "level": "info", "status": "success"}
    event = normalize(raw, source="login")
    assert event.class_uid == 3002
    assert event.severity_id == 1
    assert event.status_id == 1


def test_normalize_network_source():
    raw = {"src_ip": "10.0.0.1", "dst_port": 443, "level": "warning"}
    event = normalize(raw, source="network")
    assert event.class_uid == 4001
    assert event.severity_id == 2


def test_normalize_iso_timestamp():
    raw = {"timestamp": "2025-01-15T12:30:00Z", "message": "test"}
    event = normalize(raw, source="api")
    assert event.time.year == 2025
    assert event.time.tzinfo is not None


def test_normalize_unknown_level():
    raw = {"message": "raw log", "level": "trace"}
    event = normalize(raw, source="unknown")
    assert event.severity_id == 0  # Unknown


def test_normalize_failure_status():
    raw = {"message": "auth denied", "status": "failure"}
    event = normalize(raw, source="auth")
    assert event.status_id == 2


def test_normalize_file_source():
    raw = {"file_path": "/etc/passwd", "message": "file accessed"}
    event = normalize(raw, source="monitor")
    assert event.class_uid == 4003


def test_normalize_api_source():
    raw = {"endpoint": "/api/v1/users", "method": "GET"}
    event = normalize(raw, source="api")
    assert event.class_uid == 6003


def test_normalize_default_class():
    raw = {"message": "generic event"}
    event = normalize(raw, source="unknown")
    assert event.class_uid == 2001  # security_finding


def test_normalize_unix_timestamp():
    raw = {"time": 1705312200.0, "message": "test"}
    event = normalize(raw, source="unknown")
    assert event.time.year == 2024
    assert event.time.tzinfo is not None
