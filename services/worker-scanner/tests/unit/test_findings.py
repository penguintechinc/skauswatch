"""Unit tests for finding models and schemas.

This module tests the marshmallow schemas used for finding validation
and serialization: FindingResponseSchema, UpdateFindingSchema,
FindingFilterSchema, FindingStatsSchema, and FindingExportSchema.
Severity and status enumerations are tested exhaustively.
"""

import pytest
from marshmallow import ValidationError

from api.schemas.finding import (
    FindingExportSchema,
    FindingFilterSchema,
    FindingResponseSchema,
    FindingStatsSchema,
    UpdateFindingSchema,
)


# =============================================================================
# Severity values
# =============================================================================

VALID_SEVERITIES = ["info", "low", "medium", "high", "critical"]
INVALID_SEVERITIES = ["unknown", "severe", "blocker", "informational", ""]

# =============================================================================
# Finding status values
# =============================================================================

VALID_FINDING_STATUSES = ["open", "acknowledged", "false_positive", "fixed"]
INVALID_FINDING_STATUSES = ["closed", "resolved", "pending", "new", ""]


# =============================================================================
# FindingSeverity — enum values via schema
# =============================================================================


@pytest.mark.unit
class TestFindingSeverityEnum:
    """Tests for finding severity enum values."""

    def test_info_severity_is_valid(self):
        """'info' is a valid severity."""
        schema = FindingFilterSchema()
        data = schema.load({"severity": "info"})
        assert data["severity"] == "info"

    def test_low_severity_is_valid(self):
        """'low' is a valid severity."""
        schema = FindingFilterSchema()
        data = schema.load({"severity": "low"})
        assert data["severity"] == "low"

    def test_medium_severity_is_valid(self):
        """'medium' is a valid severity."""
        schema = FindingFilterSchema()
        data = schema.load({"severity": "medium"})
        assert data["severity"] == "medium"

    def test_high_severity_is_valid(self):
        """'high' is a valid severity."""
        schema = FindingFilterSchema()
        data = schema.load({"severity": "high"})
        assert data["severity"] == "high"

    def test_critical_severity_is_valid(self):
        """'critical' is a valid severity."""
        schema = FindingFilterSchema()
        data = schema.load({"severity": "critical"})
        assert data["severity"] == "critical"

    @pytest.mark.parametrize("severity", VALID_SEVERITIES)
    def test_all_valid_severities_accepted(self, severity: str):
        """All five documented severity levels are accepted."""
        schema = FindingFilterSchema()
        data = schema.load({"severity": severity})
        assert data["severity"] == severity

    @pytest.mark.parametrize("severity", INVALID_SEVERITIES)
    def test_invalid_severities_rejected(self, severity: str):
        """Unknown severity values are rejected."""
        schema = FindingFilterSchema()
        with pytest.raises(ValidationError) as exc_info:
            schema.load({"severity": severity})
        assert "severity" in exc_info.value.messages

    def test_severity_count_is_five(self):
        """Exactly five severity levels are defined."""
        assert len(VALID_SEVERITIES) == 5

    def test_severity_ordering_by_impact(self):
        """Severities are ordered from lowest to highest impact."""
        expected_order = ["info", "low", "medium", "high", "critical"]
        assert VALID_SEVERITIES == expected_order


# =============================================================================
# FindingStatus — enum values via schema
# =============================================================================


@pytest.mark.unit
class TestFindingStatusEnum:
    """Tests for finding status enum values."""

    def test_open_status_is_valid(self):
        """'open' is a valid finding status."""
        schema = FindingFilterSchema()
        data = schema.load({"status": "open"})
        assert data["status"] == "open"

    def test_acknowledged_status_is_valid(self):
        """'acknowledged' is a valid finding status."""
        schema = FindingFilterSchema()
        data = schema.load({"status": "acknowledged"})
        assert data["status"] == "acknowledged"

    def test_false_positive_status_is_valid(self):
        """'false_positive' is a valid finding status."""
        schema = FindingFilterSchema()
        data = schema.load({"status": "false_positive"})
        assert data["status"] == "false_positive"

    def test_fixed_status_is_valid(self):
        """'fixed' is a valid finding status."""
        schema = FindingFilterSchema()
        data = schema.load({"status": "fixed"})
        assert data["status"] == "fixed"

    @pytest.mark.parametrize("status", VALID_FINDING_STATUSES)
    def test_all_valid_statuses_accepted(self, status: str):
        """All four documented finding statuses are accepted."""
        schema = FindingFilterSchema()
        data = schema.load({"status": status})
        assert data["status"] == status

    @pytest.mark.parametrize("status", INVALID_FINDING_STATUSES)
    def test_invalid_statuses_rejected(self, status: str):
        """Unknown finding status values are rejected."""
        schema = FindingFilterSchema()
        with pytest.raises(ValidationError) as exc_info:
            schema.load({"status": status})
        assert "status" in exc_info.value.messages

    def test_status_count_is_four(self):
        """Exactly four finding statuses are defined."""
        assert len(VALID_FINDING_STATUSES) == 4


# =============================================================================
# UpdateFindingSchema — status update validation
# =============================================================================


@pytest.mark.unit
class TestUpdateFindingSchema:
    """Tests for finding status update schema."""

    def setup_method(self):
        self.schema = UpdateFindingSchema()

    def test_update_to_open_succeeds(self):
        """Updating status to 'open' is valid."""
        data = self.schema.load({"status": "open"})
        assert data["status"] == "open"

    def test_update_to_acknowledged_succeeds(self):
        """Updating status to 'acknowledged' is valid."""
        data = self.schema.load({"status": "acknowledged"})
        assert data["status"] == "acknowledged"

    def test_update_to_false_positive_succeeds(self):
        """Updating status to 'false_positive' is valid."""
        data = self.schema.load({"status": "false_positive"})
        assert data["status"] == "false_positive"

    def test_update_to_fixed_succeeds(self):
        """Updating status to 'fixed' is valid."""
        data = self.schema.load({"status": "fixed"})
        assert data["status"] == "fixed"

    def test_status_is_required(self):
        """Missing status field raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({})
        assert "status" in exc_info.value.messages

    def test_invalid_status_raises_validation_error(self):
        """Unknown status value raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"status": "resolved"})
        assert "status" in exc_info.value.messages

    @pytest.mark.parametrize("status", VALID_FINDING_STATUSES)
    def test_all_valid_statuses_accepted(self, status: str):
        """All four valid statuses are accepted by UpdateFindingSchema."""
        data = self.schema.load({"status": status})
        assert data["status"] == status


# =============================================================================
# FindingFilterSchema — list/query parameter validation
# =============================================================================


@pytest.mark.unit
class TestFindingFilterSchema:
    """Tests for finding filter/listing schema."""

    def setup_method(self):
        self.schema = FindingFilterSchema()

    def test_empty_filter_uses_defaults(self):
        """Empty filter params use default pagination values."""
        data = self.schema.load({})
        assert data["page"] == 1
        assert data["per_page"] == 20

    def test_filter_by_severity_info(self):
        """Filter by 'info' severity is accepted."""
        data = self.schema.load({"severity": "info"})
        assert data["severity"] == "info"

    def test_filter_by_severity_critical(self):
        """Filter by 'critical' severity is accepted."""
        data = self.schema.load({"severity": "critical"})
        assert data["severity"] == "critical"

    def test_filter_by_status_open(self):
        """Filter by 'open' status is accepted."""
        data = self.schema.load({"status": "open"})
        assert data["status"] == "open"

    def test_filter_by_scanner_type_nuclei(self):
        """Filter by 'nuclei' scanner_type is accepted."""
        data = self.schema.load({"scanner_type": "nuclei"})
        assert data["scanner_type"] == "nuclei"

    def test_filter_by_scanner_type_zap(self):
        """Filter by 'zap' scanner_type is accepted."""
        data = self.schema.load({"scanner_type": "zap"})
        assert data["scanner_type"] == "zap"

    def test_filter_by_scanner_type_openvas(self):
        """Filter by 'openvas' scanner_type is accepted."""
        data = self.schema.load({"scanner_type": "openvas"})
        assert data["scanner_type"] == "openvas"

    def test_invalid_scanner_type_raises_validation_error(self):
        """Unknown scanner_type raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"scanner_type": "burpsuite"})
        assert "scanner_type" in exc_info.value.messages

    def test_filter_by_target_id(self):
        """Filter by target_id integer is accepted."""
        data = self.schema.load({"target_id": 10})
        assert data["target_id"] == 10

    def test_filter_by_job_id(self):
        """Filter by job_id integer is accepted."""
        data = self.schema.load({"job_id": 5})
        assert data["job_id"] == 5

    def test_pagination_custom_values(self):
        """Custom page and per_page values are accepted."""
        data = self.schema.load({"page": 4, "per_page": 50})
        assert data["page"] == 4
        assert data["per_page"] == 50

    def test_per_page_maximum_boundary(self):
        """per_page of exactly 100 is accepted."""
        data = self.schema.load({"per_page": 100})
        assert data["per_page"] == 100

    def test_per_page_exceeds_maximum_raises_error(self):
        """per_page above 100 raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"per_page": 101})
        assert "per_page" in exc_info.value.messages

    def test_page_below_minimum_raises_error(self):
        """page below 1 raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"page": 0})
        assert "page" in exc_info.value.messages

    def test_combined_filters_accepted(self):
        """Multiple filters combined are accepted."""
        data = self.schema.load(
            {
                "severity": "high",
                "status": "open",
                "scanner_type": "nuclei",
                "target_id": 3,
                "job_id": 7,
                "page": 2,
                "per_page": 10,
            }
        )
        assert data["severity"] == "high"
        assert data["status"] == "open"
        assert data["scanner_type"] == "nuclei"
        assert data["target_id"] == 3
        assert data["job_id"] == 7
        assert data["page"] == 2
        assert data["per_page"] == 10


# =============================================================================
# FindingResponseSchema — serialization
# =============================================================================


@pytest.mark.unit
class TestFindingResponseSchema:
    """Tests for finding response serialization schema."""

    def setup_method(self):
        self.schema = FindingResponseSchema()

    def test_serializes_complete_finding_dict(self):
        """Complete finding dictionary serializes correctly."""
        from datetime import datetime

        now = datetime.utcnow()
        finding_dict = {
            "id": 1,
            "job_id": 10,
            "target_id": 2,
            "finding_id": "nuclei_cve-2021-44228_example.com",
            "severity": "critical",
            "title": "Log4Shell RCE",
            "description": "Remote code execution via JNDI injection.",
            "remediation": "Upgrade Log4j to 2.17.0+",
            "affected_url": "https://example.com/api",
            "cvss_score": 10.0,
            "cve_ids": ["CVE-2021-44228"],
            "cwe_ids": ["CWE-502"],
            "evidence": "Matcher: jndi-injection",
            "raw_finding": {"template-id": "cve-2021-44228"},
            "status": "open",
            "discovered_at": now,
            "updated_at": now,
        }
        result = self.schema.dump(finding_dict)
        assert result["id"] == 1
        assert result["severity"] == "critical"
        assert result["title"] == "Log4Shell RCE"
        assert result["cve_ids"] == ["CVE-2021-44228"]
        assert result["cwe_ids"] == ["CWE-502"]
        assert result["cvss_score"] == 10.0
        assert result["status"] == "open"

    def test_serializes_finding_with_null_optional_fields(self):
        """Finding with null optional fields serializes without error."""
        from datetime import datetime

        now = datetime.utcnow()
        finding_dict = {
            "id": 2,
            "job_id": 5,
            "target_id": 1,
            "finding_id": None,
            "severity": "low",
            "title": "Minimal finding",
            "description": None,
            "remediation": None,
            "affected_url": None,
            "cvss_score": 0.0,
            "cve_ids": [],
            "cwe_ids": [],
            "evidence": None,
            "raw_finding": {},
            "status": "open",
            "discovered_at": now,
            "updated_at": now,
        }
        result = self.schema.dump(finding_dict)
        assert result["finding_id"] is None
        assert result["description"] is None
        assert result["remediation"] is None
        assert result["cve_ids"] == []
        assert result["cwe_ids"] == []

    def test_severity_field_is_string(self):
        """Serialized severity is always a string."""
        from datetime import datetime

        finding_dict = {
            "id": 3,
            "job_id": 1,
            "target_id": 1,
            "finding_id": "test-id",
            "severity": "medium",
            "title": "Test",
            "cvss_score": 5.0,
            "cve_ids": [],
            "cwe_ids": [],
            "status": "open",
            "discovered_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        result = self.schema.dump(finding_dict)
        assert isinstance(result["severity"], str)

    def test_cvss_score_is_float(self):
        """Serialized cvss_score is a float."""
        from datetime import datetime

        finding_dict = {
            "id": 4,
            "job_id": 1,
            "target_id": 1,
            "finding_id": "test-id",
            "severity": "high",
            "title": "Test",
            "cvss_score": 7.5,
            "cve_ids": [],
            "cwe_ids": [],
            "status": "open",
            "discovered_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        result = self.schema.dump(finding_dict)
        assert isinstance(result["cvss_score"], float)


# =============================================================================
# FindingStatsSchema — statistics response
# =============================================================================


@pytest.mark.unit
class TestFindingStatsSchema:
    """Tests for finding statistics schema."""

    def setup_method(self):
        self.schema = FindingStatsSchema()

    def test_serializes_statistics_dict(self):
        """Statistics dictionary serializes without error."""
        stats = {
            "total": 150,
            "by_severity": {
                "critical": 10,
                "high": 30,
                "medium": 60,
                "low": 40,
                "info": 10,
            },
            "by_status": {
                "open": 100,
                "acknowledged": 20,
                "false_positive": 10,
                "fixed": 20,
            },
            "by_scanner": {
                "nuclei": 80,
                "zap": 50,
                "openvas": 20,
            },
        }
        result = self.schema.dump(stats)
        assert result["total"] == 150
        assert result["by_severity"]["critical"] == 10
        assert result["by_status"]["open"] == 100
        assert result["by_scanner"]["nuclei"] == 80

    def test_serializes_empty_stats(self):
        """Empty statistics dictionary serializes without error."""
        stats = {
            "total": 0,
            "by_severity": {},
            "by_status": {},
            "by_scanner": {},
        }
        result = self.schema.dump(stats)
        assert result["total"] == 0
        assert result["by_severity"] == {}


# =============================================================================
# FindingExportSchema — export request validation
# =============================================================================


@pytest.mark.unit
class TestFindingExportSchema:
    """Tests for finding export request schema."""

    def setup_method(self):
        self.schema = FindingExportSchema()

    def test_export_json_format_accepted(self):
        """Export with 'json' format is accepted."""
        data = self.schema.load({"format": "json"})
        assert data["format"] == "json"

    def test_export_csv_format_accepted(self):
        """Export with 'csv' format is accepted."""
        data = self.schema.load({"format": "csv"})
        assert data["format"] == "csv"

    def test_export_invalid_format_raises_error(self):
        """Export with unknown format raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"format": "xml"})
        assert "format" in exc_info.value.messages

    def test_format_is_required(self):
        """Missing format field raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({})
        assert "format" in exc_info.value.messages

    def test_export_with_severity_filter(self):
        """Export with valid severity list is accepted."""
        data = self.schema.load({"format": "json", "severity": ["high", "critical"]})
        assert "high" in data["severity"]
        assert "critical" in data["severity"]

    def test_export_with_invalid_severity_raises_error(self):
        """Export with invalid severity value raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"format": "json", "severity": ["extreme"]})
        assert "severity" in exc_info.value.messages

    def test_export_with_status_filter(self):
        """Export with valid status list is accepted."""
        data = self.schema.load({"format": "csv", "status": ["open", "fixed"]})
        assert "open" in data["status"]
        assert "fixed" in data["status"]

    def test_export_with_invalid_status_raises_error(self):
        """Export with invalid status value raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"format": "json", "status": ["resolved"]})
        assert "status" in exc_info.value.messages

    def test_export_defaults_empty_severity_and_status(self):
        """Default severity and status lists are empty when not provided."""
        data = self.schema.load({"format": "json"})
        assert data["severity"] == []
        assert data["status"] == []

    def test_export_with_target_id_filter(self):
        """Export with target_id filter is accepted."""
        data = self.schema.load({"format": "json", "target_id": 3})
        assert data["target_id"] == 3

    def test_export_with_job_id_filter(self):
        """Export with job_id filter is accepted."""
        data = self.schema.load({"format": "csv", "job_id": 8})
        assert data["job_id"] == 8

    def test_export_with_all_filters(self):
        """Export with all filters combined is accepted."""
        data = self.schema.load(
            {
                "format": "json",
                "severity": ["high", "critical"],
                "status": ["open"],
                "target_id": 2,
                "job_id": 5,
            }
        )
        assert data["format"] == "json"
        assert "high" in data["severity"]
        assert "open" in data["status"]
        assert data["target_id"] == 2
        assert data["job_id"] == 5
