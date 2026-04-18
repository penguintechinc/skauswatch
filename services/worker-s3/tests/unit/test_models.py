"""
Unit tests for worker-s3 Pydantic models (models.py).

Tests cover ScanTaskMessage and ScanResultMessage validation including
required fields, default values, and field constraints.
"""

import pytest
from pydantic import ValidationError

from models import ScanResultMessage, ScanTaskMessage


# ---------------------------------------------------------------------------
# TestScanTaskMessage
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScanTaskMessage:
    """Tests for ScanTaskMessage Pydantic model."""

    def test_valid_task_message(self, valid_task_message_data):
        msg = ScanTaskMessage(**valid_task_message_data)
        assert msg.task_id == "task-001"
        assert msg.job_id == "job-001"
        assert msg.bucket_config_id == "config-1"
        assert msg.object_key == "uploads/test.pdf"
        assert msg.object_size == 1024
        assert msg.endpoint_url == "https://s3.example.com"
        assert msg.bucket_name == "test-bucket"
        assert msg.access_key == "AKIATEST"
        assert msg.secret_key == "test-secret"

    def test_default_region(self, valid_task_message_data):
        msg = ScanTaskMessage(**valid_task_message_data)
        assert msg.region == "us-east-1"

    def test_default_use_ssl_true(self, valid_task_message_data):
        msg = ScanTaskMessage(**valid_task_message_data)
        assert msg.use_ssl is True

    def test_default_path_style_false(self, valid_task_message_data):
        msg = ScanTaskMessage(**valid_task_message_data)
        assert msg.path_style is False

    def test_default_yara_enabled_false(self, valid_task_message_data):
        msg = ScanTaskMessage(**valid_task_message_data)
        assert msg.yara_enabled is False

    def test_custom_region(self, valid_task_message_data):
        data = {**valid_task_message_data, "region": "eu-west-1"}
        msg = ScanTaskMessage(**data)
        assert msg.region == "eu-west-1"

    def test_custom_use_ssl_false(self, valid_task_message_data):
        data = {**valid_task_message_data, "use_ssl": False}
        msg = ScanTaskMessage(**data)
        assert msg.use_ssl is False

    def test_custom_path_style_true(self, valid_task_message_data):
        data = {**valid_task_message_data, "path_style": True}
        msg = ScanTaskMessage(**data)
        assert msg.path_style is True

    def test_yara_enabled_true(self, valid_task_message_data):
        data = {**valid_task_message_data, "yara_enabled": True}
        msg = ScanTaskMessage(**data)
        assert msg.yara_enabled is True

    def test_zero_object_size_accepted(self, valid_task_message_data):
        """object_size == 0 should be accepted (ge=0 constraint)."""
        data = {**valid_task_message_data, "object_size": 0}
        msg = ScanTaskMessage(**data)
        assert msg.object_size == 0

    def test_negative_object_size_rejected(self, valid_task_message_data):
        """Negative object_size violates ge=0 constraint."""
        data = {**valid_task_message_data, "object_size": -1}
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_missing_task_id_raises(self, valid_task_message_data):
        data = {k: v for k, v in valid_task_message_data.items() if k != "task_id"}
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_missing_job_id_raises(self, valid_task_message_data):
        data = {k: v for k, v in valid_task_message_data.items() if k != "job_id"}
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_missing_bucket_config_id_raises(self, valid_task_message_data):
        data = {
            k: v
            for k, v in valid_task_message_data.items()
            if k != "bucket_config_id"
        }
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_missing_object_key_raises(self, valid_task_message_data):
        data = {k: v for k, v in valid_task_message_data.items() if k != "object_key"}
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_missing_object_size_raises(self, valid_task_message_data):
        data = {
            k: v for k, v in valid_task_message_data.items() if k != "object_size"
        }
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_missing_endpoint_url_raises(self, valid_task_message_data):
        data = {
            k: v for k, v in valid_task_message_data.items() if k != "endpoint_url"
        }
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_missing_bucket_name_raises(self, valid_task_message_data):
        data = {
            k: v for k, v in valid_task_message_data.items() if k != "bucket_name"
        }
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_missing_access_key_raises(self, valid_task_message_data):
        data = {k: v for k, v in valid_task_message_data.items() if k != "access_key"}
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_missing_secret_key_raises(self, valid_task_message_data):
        data = {k: v for k, v in valid_task_message_data.items() if k != "secret_key"}
        with pytest.raises(ValidationError):
            ScanTaskMessage(**data)

    def test_large_object_size_accepted(self, valid_task_message_data):
        data = {**valid_task_message_data, "object_size": 10 * 1024 ** 3}
        msg = ScanTaskMessage(**data)
        assert msg.object_size == 10 * 1024 ** 3

    def test_model_is_not_mutable_by_default(self, valid_task_message_data):
        """Pydantic v1 models are mutable unless frozen=True; just check roundtrip."""
        msg = ScanTaskMessage(**valid_task_message_data)
        assert msg.dict()["task_id"] == "task-001"


# ---------------------------------------------------------------------------
# TestScanResultMessage
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestScanResultMessage:
    """Tests for ScanResultMessage Pydantic model."""

    def test_valid_result_message(self, valid_result_message_data):
        msg = ScanResultMessage(**valid_result_message_data)
        assert msg.task_id == "task-001"
        assert msg.scan_status == "completed"
        assert msg.is_malware is False
        assert msg.is_threat is False
        assert msg.scan_duration_ms == 1234

    def test_default_threat_names_empty(self, valid_result_message_data):
        msg = ScanResultMessage(**valid_result_message_data)
        assert msg.threat_names == []

    def test_default_tags_applied_empty(self, valid_result_message_data):
        msg = ScanResultMessage(**valid_result_message_data)
        assert msg.tags_applied == []

    def test_default_clamav_result_none(self, valid_result_message_data):
        msg = ScanResultMessage(**valid_result_message_data)
        assert msg.clamav_result is None

    def test_default_yara_matches_none(self, valid_result_message_data):
        msg = ScanResultMessage(**valid_result_message_data)
        assert msg.yara_matches is None

    def test_default_ti_enrichment_none(self, valid_result_message_data):
        msg = ScanResultMessage(**valid_result_message_data)
        assert msg.ti_enrichment is None

    def test_default_error_message_none(self, valid_result_message_data):
        msg = ScanResultMessage(**valid_result_message_data)
        assert msg.error_message is None

    def test_scan_status_completed(self, valid_result_message_data):
        msg = ScanResultMessage(**{**valid_result_message_data, "scan_status": "completed"})
        assert msg.scan_status == "completed"

    def test_scan_status_failed(self, valid_result_message_data):
        msg = ScanResultMessage(**{**valid_result_message_data, "scan_status": "failed"})
        assert msg.scan_status == "failed"

    def test_scan_status_timeout(self, valid_result_message_data):
        msg = ScanResultMessage(**{**valid_result_message_data, "scan_status": "timeout"})
        assert msg.scan_status == "timeout"

    def test_scan_status_skipped(self, valid_result_message_data):
        msg = ScanResultMessage(**{**valid_result_message_data, "scan_status": "skipped"})
        assert msg.scan_status == "skipped"

    def test_invalid_scan_status_rejected(self, valid_result_message_data):
        data = {**valid_result_message_data, "scan_status": "running"}
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_empty_scan_status_rejected(self, valid_result_message_data):
        data = {**valid_result_message_data, "scan_status": ""}
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_uppercase_scan_status_rejected(self, valid_result_message_data):
        data = {**valid_result_message_data, "scan_status": "COMPLETED"}
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_zero_scan_duration_accepted(self, valid_result_message_data):
        data = {**valid_result_message_data, "scan_duration_ms": 0}
        msg = ScanResultMessage(**data)
        assert msg.scan_duration_ms == 0

    def test_negative_scan_duration_rejected(self, valid_result_message_data):
        data = {**valid_result_message_data, "scan_duration_ms": -1}
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_missing_task_id_raises(self, valid_result_message_data):
        data = {k: v for k, v in valid_result_message_data.items() if k != "task_id"}
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_missing_job_id_raises(self, valid_result_message_data):
        data = {k: v for k, v in valid_result_message_data.items() if k != "job_id"}
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_missing_object_key_raises(self, valid_result_message_data):
        data = {k: v for k, v in valid_result_message_data.items() if k != "object_key"}
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_missing_scan_status_raises(self, valid_result_message_data):
        data = {
            k: v for k, v in valid_result_message_data.items() if k != "scan_status"
        }
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_missing_is_malware_raises(self, valid_result_message_data):
        data = {
            k: v for k, v in valid_result_message_data.items() if k != "is_malware"
        }
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_missing_scan_duration_ms_raises(self, valid_result_message_data):
        data = {
            k: v
            for k, v in valid_result_message_data.items()
            if k != "scan_duration_ms"
        }
        with pytest.raises(ValidationError):
            ScanResultMessage(**data)

    def test_custom_threat_names(self, valid_result_message_data):
        data = {
            **valid_result_message_data,
            "is_malware": True,
            "is_threat": True,
            "threat_names": ["Win.Trojan.Generic", "Heuristics.Suspicious"],
        }
        msg = ScanResultMessage(**data)
        assert len(msg.threat_names) == 2
        assert "Win.Trojan.Generic" in msg.threat_names

    def test_custom_clamav_result(self, valid_result_message_data):
        clamav = {"status": "FOUND", "virus": "Eicar-Test-Signature"}
        data = {**valid_result_message_data, "clamav_result": clamav}
        msg = ScanResultMessage(**data)
        assert msg.clamav_result["status"] == "FOUND"

    def test_custom_tags_applied(self, valid_result_message_data):
        data = {
            **valid_result_message_data,
            "tags_applied": ["malware=false", "scanned=true"],
        }
        msg = ScanResultMessage(**data)
        assert "malware=false" in msg.tags_applied

    def test_error_message_set_on_failure(self, valid_result_message_data):
        data = {
            **valid_result_message_data,
            "scan_status": "failed",
            "error_message": "Connection timeout",
        }
        msg = ScanResultMessage(**data)
        assert msg.error_message == "Connection timeout"

    def test_ti_enrichment_dict(self, valid_result_message_data):
        ti = {"vt_score": 0, "severity": "unknown"}
        data = {**valid_result_message_data, "ti_enrichment": ti}
        msg = ScanResultMessage(**data)
        assert msg.ti_enrichment["vt_score"] == 0
