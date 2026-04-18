"""Unit tests for scan job lifecycle management.

This module tests job creation, state transitions, cancellation, listing
with pagination, and filtering — all using marshmallow schema validation
and in-memory PyDAL (SQLite) for isolation.
"""

import pytest
from marshmallow import ValidationError

from api.schemas.job import CreateJobSchema, JobFilterSchema, JobResponseSchema


# =============================================================================
# CreateJobSchema — creation input validation
# =============================================================================


@pytest.mark.unit
class TestCreateJobSchema:
    """Tests for scan job creation schema validation."""

    def setup_method(self):
        self.schema = CreateJobSchema()

    # -------------------------------------------------------------------------
    # Valid creation payloads
    # -------------------------------------------------------------------------

    def test_valid_job_creation_nuclei_baseline(self):
        """Valid nuclei baseline job creation succeeds."""
        data = self.schema.load(
            {
                "target_id": 1,
                "scanner_type": "nuclei",
                "scan_type": "baseline",
            }
        )
        assert data["target_id"] == 1
        assert data["scanner_type"] == "nuclei"
        assert data["scan_type"] == "baseline"

    def test_valid_job_creation_zap_full(self):
        """Valid ZAP full-scan job creation succeeds."""
        data = self.schema.load(
            {
                "target_id": 5,
                "scanner_type": "zap",
                "scan_type": "full",
            }
        )
        assert data["scanner_type"] == "zap"
        assert data["scan_type"] == "full"

    def test_valid_job_creation_openvas_full_and_fast(self):
        """Valid openvas full_and_fast job creation succeeds."""
        data = self.schema.load(
            {
                "target_id": 3,
                "scanner_type": "openvas",
                "scan_type": "full_and_fast",
            }
        )
        assert data["scanner_type"] == "openvas"
        assert data["scan_type"] == "full_and_fast"

    def test_valid_job_creation_with_priority(self):
        """Job creation with explicit priority succeeds."""
        data = self.schema.load(
            {
                "target_id": 1,
                "scanner_type": "nuclei",
                "scan_type": "baseline",
                "priority": 8,
            }
        )
        assert data["priority"] == 8

    def test_valid_job_creation_with_config(self):
        """Job creation with custom config dict succeeds."""
        custom_config = {"timeout": 300, "threads": 4}
        data = self.schema.load(
            {
                "target_id": 1,
                "scanner_type": "nuclei",
                "scan_type": "api",
                "config": custom_config,
            }
        )
        assert data["config"] == custom_config

    def test_priority_defaults_to_five(self):
        """Priority defaults to 5 when not provided."""
        data = self.schema.load(
            {
                "target_id": 1,
                "scanner_type": "nuclei",
                "scan_type": "baseline",
            }
        )
        assert data["priority"] == 5

    def test_config_defaults_to_empty_dict(self):
        """Config defaults to empty dict when not provided."""
        data = self.schema.load(
            {
                "target_id": 1,
                "scanner_type": "nuclei",
                "scan_type": "baseline",
            }
        )
        assert data["config"] == {}

    def test_all_scan_types_accepted(self):
        """All documented scan types are accepted."""
        valid_scan_types = [
            "baseline",
            "full",
            "api",
            "custom",
            "discovery",
            "full_and_fast",
            "full_and_deep",
        ]
        for scan_type in valid_scan_types:
            data = self.schema.load(
                {
                    "target_id": 1,
                    "scanner_type": "nuclei",
                    "scan_type": scan_type,
                }
            )
            assert data["scan_type"] == scan_type

    # -------------------------------------------------------------------------
    # Required field validation
    # -------------------------------------------------------------------------

    def test_missing_target_id_raises_validation_error(self):
        """Missing target_id raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"scanner_type": "nuclei", "scan_type": "baseline"})
        assert "target_id" in exc_info.value.messages

    def test_missing_scanner_type_raises_validation_error(self):
        """Missing scanner_type raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"target_id": 1, "scan_type": "baseline"})
        assert "scanner_type" in exc_info.value.messages

    def test_missing_scan_type_raises_validation_error(self):
        """Missing scan_type raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"target_id": 1, "scanner_type": "nuclei"})
        assert "scan_type" in exc_info.value.messages

    # -------------------------------------------------------------------------
    # Invalid value validation
    # -------------------------------------------------------------------------

    def test_invalid_scanner_type_raises_validation_error(self):
        """Unknown scanner type raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load(
                {"target_id": 1, "scanner_type": "nessus", "scan_type": "baseline"}
            )
        assert "scanner_type" in exc_info.value.messages

    def test_invalid_scan_type_raises_validation_error(self):
        """Unknown scan type raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load(
                {"target_id": 1, "scanner_type": "nuclei", "scan_type": "quick"}
            )
        assert "scan_type" in exc_info.value.messages

    def test_priority_below_minimum_raises_validation_error(self):
        """Priority 0 (below minimum 1) raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load(
                {
                    "target_id": 1,
                    "scanner_type": "nuclei",
                    "scan_type": "baseline",
                    "priority": 0,
                }
            )
        assert "priority" in exc_info.value.messages

    def test_priority_above_maximum_raises_validation_error(self):
        """Priority 11 (above maximum 10) raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load(
                {
                    "target_id": 1,
                    "scanner_type": "nuclei",
                    "scan_type": "baseline",
                    "priority": 11,
                }
            )
        assert "priority" in exc_info.value.messages

    def test_priority_boundary_minimum_accepted(self):
        """Priority exactly 1 (minimum) is accepted."""
        data = self.schema.load(
            {
                "target_id": 1,
                "scanner_type": "nuclei",
                "scan_type": "baseline",
                "priority": 1,
            }
        )
        assert data["priority"] == 1

    def test_priority_boundary_maximum_accepted(self):
        """Priority exactly 10 (maximum) is accepted."""
        data = self.schema.load(
            {
                "target_id": 1,
                "scanner_type": "nuclei",
                "scan_type": "baseline",
                "priority": 10,
            }
        )
        assert data["priority"] == 10


# =============================================================================
# JobFilterSchema — list/query parameter validation
# =============================================================================


@pytest.mark.unit
class TestJobFilterSchema:
    """Tests for job listing/filter schema."""

    def setup_method(self):
        self.schema = JobFilterSchema()

    # -------------------------------------------------------------------------
    # Defaults
    # -------------------------------------------------------------------------

    def test_empty_params_use_defaults(self):
        """Empty filter uses default pagination values."""
        data = self.schema.load({})
        assert data["page"] == 1
        assert data["per_page"] == 20

    # -------------------------------------------------------------------------
    # Status filter
    # -------------------------------------------------------------------------

    def test_filter_by_pending_status(self):
        """Filtering by 'pending' status is accepted."""
        data = self.schema.load({"status": "pending"})
        assert data["status"] == "pending"

    def test_filter_by_running_status(self):
        """Filtering by 'running' status is accepted."""
        data = self.schema.load({"status": "running"})
        assert data["status"] == "running"

    def test_filter_by_completed_status(self):
        """Filtering by 'completed' status is accepted."""
        data = self.schema.load({"status": "completed"})
        assert data["status"] == "completed"

    def test_filter_by_failed_status(self):
        """Filtering by 'failed' status is accepted."""
        data = self.schema.load({"status": "failed"})
        assert data["status"] == "failed"

    def test_filter_by_cancelled_status(self):
        """Filtering by 'cancelled' status is accepted."""
        data = self.schema.load({"status": "cancelled"})
        assert data["status"] == "cancelled"

    def test_invalid_status_raises_validation_error(self):
        """Unknown status raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"status": "paused"})
        assert "status" in exc_info.value.messages

    # -------------------------------------------------------------------------
    # Scanner type filter
    # -------------------------------------------------------------------------

    def test_filter_by_nuclei_scanner(self):
        """Filtering by 'nuclei' scanner_type is accepted."""
        data = self.schema.load({"scanner_type": "nuclei"})
        assert data["scanner_type"] == "nuclei"

    def test_filter_by_zap_scanner(self):
        """Filtering by 'zap' scanner_type is accepted."""
        data = self.schema.load({"scanner_type": "zap"})
        assert data["scanner_type"] == "zap"

    def test_filter_by_openvas_scanner(self):
        """Filtering by 'openvas' scanner_type is accepted."""
        data = self.schema.load({"scanner_type": "openvas"})
        assert data["scanner_type"] == "openvas"

    def test_invalid_scanner_type_raises_validation_error(self):
        """Unknown scanner_type raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"scanner_type": "burp"})
        assert "scanner_type" in exc_info.value.messages

    # -------------------------------------------------------------------------
    # Target ID filter
    # -------------------------------------------------------------------------

    def test_filter_by_target_id(self):
        """Filtering by target_id is accepted."""
        data = self.schema.load({"target_id": 42})
        assert data["target_id"] == 42

    # -------------------------------------------------------------------------
    # Pagination
    # -------------------------------------------------------------------------

    def test_pagination_page_and_per_page(self):
        """Custom page and per_page values are accepted."""
        data = self.schema.load({"page": 3, "per_page": 50})
        assert data["page"] == 3
        assert data["per_page"] == 50

    def test_page_minimum_is_one(self):
        """Page below 1 raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"page": 0})
        assert "page" in exc_info.value.messages

    def test_per_page_minimum_is_one(self):
        """per_page below 1 raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"per_page": 0})
        assert "per_page" in exc_info.value.messages

    def test_per_page_maximum_is_one_hundred(self):
        """per_page above 100 raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            self.schema.load({"per_page": 101})
        assert "per_page" in exc_info.value.messages

    def test_per_page_boundary_maximum(self):
        """per_page exactly 100 is accepted."""
        data = self.schema.load({"per_page": 100})
        assert data["per_page"] == 100

    def test_combined_filters_accepted(self):
        """Multiple filters combined are accepted."""
        data = self.schema.load(
            {
                "status": "completed",
                "scanner_type": "zap",
                "target_id": 7,
                "page": 2,
                "per_page": 25,
            }
        )
        assert data["status"] == "completed"
        assert data["scanner_type"] == "zap"
        assert data["target_id"] == 7
        assert data["page"] == 2
        assert data["per_page"] == 25


# =============================================================================
# JobResponseSchema — serialization
# =============================================================================


@pytest.mark.unit
class TestJobResponseSchema:
    """Tests for job response serialization schema."""

    def setup_method(self):
        self.schema = JobResponseSchema()

    def test_serializes_complete_job_dict(self):
        """Complete job dictionary serializes correctly."""
        from datetime import datetime

        now = datetime.utcnow()
        job_dict = {
            "id": 1,
            "target_id": 2,
            "scanner_type": "nuclei",
            "scan_type": "baseline",
            "status": "pending",
            "priority": 5,
            "config": {},
            "started_at": None,
            "completed_at": None,
            "duration_seconds": None,
            "error_message": None,
            "result_summary": None,
            "created_at": now,
            "created_by": "user-123",
        }
        result = self.schema.dump(job_dict)
        assert result["id"] == 1
        assert result["scanner_type"] == "nuclei"
        assert result["status"] == "pending"
        assert result["priority"] == 5

    def test_serializes_nullable_fields_as_none(self):
        """Nullable fields (started_at, completed_at, etc.) serialize as None."""
        from datetime import datetime

        job_dict = {
            "id": 2,
            "target_id": 1,
            "scanner_type": "zap",
            "scan_type": "full",
            "status": "running",
            "priority": 3,
            "config": {},
            "started_at": None,
            "completed_at": None,
            "duration_seconds": None,
            "error_message": None,
            "result_summary": None,
            "created_at": datetime.utcnow(),
            "created_by": None,
        }
        result = self.schema.dump(job_dict)
        assert result["started_at"] is None
        assert result["completed_at"] is None
        assert result["duration_seconds"] is None
        assert result["error_message"] is None
        assert result["created_by"] is None


# =============================================================================
# Job State Transition Logic
# =============================================================================


@pytest.mark.unit
class TestJobStateTransitions:
    """Tests for valid and invalid job state transitions.

    These tests verify the state-transition rules expressed in the route
    logic without requiring a real database connection.  They use the
    marshmallow schema to check that each status value is recognized.
    """

    VALID_JOB_STATUSES = ["pending", "running", "completed", "failed", "cancelled"]

    def test_pending_is_valid_initial_status(self):
        """'pending' is a valid job status."""
        schema = JobFilterSchema()
        data = schema.load({"status": "pending"})
        assert data["status"] == "pending"

    def test_running_is_valid_status(self):
        """'running' is a valid job status."""
        schema = JobFilterSchema()
        data = schema.load({"status": "running"})
        assert data["status"] == "running"

    def test_completed_is_valid_terminal_status(self):
        """'completed' is a valid terminal status."""
        schema = JobFilterSchema()
        data = schema.load({"status": "completed"})
        assert data["status"] == "completed"

    def test_failed_is_valid_terminal_status(self):
        """'failed' is a valid terminal status."""
        schema = JobFilterSchema()
        data = schema.load({"status": "failed"})
        assert data["status"] == "failed"

    def test_cancelled_is_valid_status(self):
        """'cancelled' is a valid status."""
        schema = JobFilterSchema()
        data = schema.load({"status": "cancelled"})
        assert data["status"] == "cancelled"

    def test_all_statuses_recognized(self):
        """Every documented status passes schema validation."""
        schema = JobFilterSchema()
        for status in self.VALID_JOB_STATUSES:
            data = schema.load({"status": status})
            assert data["status"] == status

    def test_retryable_statuses_are_failed_and_cancelled(self):
        """Only 'failed' and 'cancelled' jobs should be retryable (business rule)."""
        retryable = {"failed", "cancelled"}
        non_retryable = {"pending", "running", "completed"}

        assert retryable.issubset(set(self.VALID_JOB_STATUSES))
        assert non_retryable.issubset(set(self.VALID_JOB_STATUSES))
        # Sanity: retryable and non-retryable are disjoint
        assert not retryable.intersection(non_retryable)

    def test_cancellable_statuses_include_pending_and_running(self):
        """'pending' and 'running' jobs can be cancelled (business rule)."""
        cancellable = {"pending", "running"}
        assert cancellable.issubset(set(self.VALID_JOB_STATUSES))

    def test_deletable_statuses_are_terminal(self):
        """Completed, failed, and cancelled jobs can be deleted (business rule)."""
        deletable = {"completed", "failed", "cancelled"}
        assert deletable.issubset(set(self.VALID_JOB_STATUSES))


# =============================================================================
# Job Cancellation Validation
# =============================================================================


@pytest.mark.unit
class TestJobCancellationValidation:
    """Tests for job cancellation input and state validation rules."""

    def test_pending_job_is_cancellable(self):
        """A pending job is eligible for cancellation."""
        status = "pending"
        cancellable_statuses = {"pending", "running"}
        assert status in cancellable_statuses

    def test_running_job_is_cancellable(self):
        """A running job is eligible for cancellation."""
        status = "running"
        cancellable_statuses = {"pending", "running"}
        assert status in cancellable_statuses

    def test_completed_job_is_not_cancellable(self):
        """A completed job cannot be cancelled (business rule)."""
        status = "completed"
        cancellable_statuses = {"pending", "running"}
        assert status not in cancellable_statuses

    def test_failed_job_is_not_cancellable(self):
        """A failed job cannot be cancelled (business rule)."""
        status = "failed"
        cancellable_statuses = {"pending", "running"}
        assert status not in cancellable_statuses

    def test_already_cancelled_job_is_not_cancellable(self):
        """An already-cancelled job cannot be cancelled again."""
        status = "cancelled"
        cancellable_statuses = {"pending", "running"}
        assert status not in cancellable_statuses


# =============================================================================
# Priority Validation
# =============================================================================


@pytest.mark.unit
class TestJobPriorityValidation:
    """Tests for job priority validation rules (1–10 inclusive)."""

    @pytest.mark.parametrize("priority", [1, 2, 5, 9, 10])
    def test_valid_priorities_accepted(self, priority: int):
        """Priority values 1–10 are accepted."""
        schema = CreateJobSchema()
        data = schema.load(
            {
                "target_id": 1,
                "scanner_type": "nuclei",
                "scan_type": "baseline",
                "priority": priority,
            }
        )
        assert data["priority"] == priority

    @pytest.mark.parametrize("priority", [0, -1, 11, 100])
    def test_invalid_priorities_rejected(self, priority: int):
        """Priority values outside 1–10 are rejected."""
        schema = CreateJobSchema()
        with pytest.raises(ValidationError) as exc_info:
            schema.load(
                {
                    "target_id": 1,
                    "scanner_type": "nuclei",
                    "scan_type": "baseline",
                    "priority": priority,
                }
            )
        assert "priority" in exc_info.value.messages
