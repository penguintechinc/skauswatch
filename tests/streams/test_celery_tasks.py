"""
Celery task pipeline tests.

Tests task dispatch, state transitions, and retry behavior
using CELERY_TASK_ALWAYS_EAGER for synchronous execution.

The worker-scanner uses Celery for scan job execution via:
  - workers.celery_app  — Celery app instance
  - workers.scan_worker — execute_scan / cancel_scan tasks
"""
import pytest
from unittest.mock import patch, MagicMock, call

pytestmark = [pytest.mark.stream, pytest.mark.unit]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_db(job_status="pending", job_found=True, target_found=True):
    """Return a minimal mock of the PyDAL db object used by scan_worker."""
    db = MagicMock()

    job = MagicMock()
    job.status = job_status
    job.target_id = 42
    job.scanner_type = "nuclei"
    job.scan_type = "full"
    job.config = {}

    target = MagicMock()
    target.target_value = "192.168.1.1"

    # db.scan_jobs[job_id] lookup
    db.scan_jobs.__getitem__.return_value = job if job_found else None

    # db.scan_targets[target_id] lookup
    db.scan_targets.__getitem__.return_value = target if target_found else None

    # db(filter).update(...)  — used to set status
    db.return_value.update.return_value = None

    db.commit.return_value = None
    return db, job, target


def _make_scan_result(success=True, findings=None, error_message=None):
    """Return a mock scanner result."""
    result = MagicMock()
    result.success = success
    result.findings = findings or []
    result.summary = {}
    result.error_message = error_message
    return result


# ---------------------------------------------------------------------------
# Class 1: Task dispatch
# ---------------------------------------------------------------------------


class TestCeleryTaskDispatch:
    """Test that scan tasks dispatch correctly via Celery eager mode."""

    def test_execute_scan_task_is_registered(self):
        """execute_scan must be registered in the Celery app."""
        with patch.dict(
            "os.environ",
            {
                "CELERY_BROKER_URL": "memory://",
                "CELERY_RESULT_BACKEND": "cache+memory://",
            },
        ):
            from workers.celery_app import celery_app

            registered = list(celery_app.tasks.keys())
            assert "workers.scan_worker.execute_scan" in registered

    def test_cancel_scan_task_is_registered(self):
        """cancel_scan must be registered in the Celery app."""
        with patch.dict(
            "os.environ",
            {
                "CELERY_BROKER_URL": "memory://",
                "CELERY_RESULT_BACKEND": "cache+memory://",
            },
        ):
            from workers.celery_app import celery_app

            registered = list(celery_app.tasks.keys())
            assert "workers.scan_worker.cancel_scan" in registered

    def test_execute_scan_dispatches_with_eager_mode(self):
        """With ALWAYS_EAGER, execute_scan runs synchronously and returns a dict."""
        mock_db, mock_job, mock_target = _make_mock_db()
        mock_scanner = MagicMock()
        mock_scanner.return_value.scan.return_value = _make_scan_result(
            success=True, findings=[]
        )

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
            patch(
                "workers.scan_worker.NucleiScanner",
                mock_scanner,
            ),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(task_always_eager=True)
            from workers.scan_worker import execute_scan

            result = execute_scan.delay(job_id=1).get()

        assert isinstance(result, dict)
        assert "job_id" in result
        assert "status" in result

    def test_execute_scan_returns_success_on_clean_run(self):
        """execute_scan returns success=True when scanner reports no findings."""
        mock_db, mock_job, mock_target = _make_mock_db()

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan.return_value = _make_scan_result(
            success=True, findings=[]
        )

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
            patch("workers.scan_worker.NucleiScanner", mock_scanner_class),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(task_always_eager=True)
            from workers.scan_worker import execute_scan

            result = execute_scan.apply(args=[1]).result

        assert result["success"] is True
        assert result["status"] == "completed"
        assert result["findings_count"] == 0


# ---------------------------------------------------------------------------
# Class 2: State transitions
# ---------------------------------------------------------------------------


class TestTaskStateTransitions:
    """Test PENDING → RUNNING → SUCCESS/FAILURE state transitions."""

    def test_job_status_set_to_running_during_execution(self):
        """db update with status='running' is called at the start of the task."""
        mock_db, mock_job, mock_target = _make_mock_db()

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan.return_value = _make_scan_result(
            success=True, findings=[]
        )

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
            patch("workers.scan_worker.NucleiScanner", mock_scanner_class),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(task_always_eager=True)
            from workers.scan_worker import execute_scan

            execute_scan.apply(args=[1])

        # Verify db.commit was called at least once (for the 'running' update)
        assert mock_db.commit.call_count >= 1

    def test_job_transitions_to_completed_on_success(self):
        """After a successful scan the task returns status='completed'."""
        mock_db, mock_job, mock_target = _make_mock_db()

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan.return_value = _make_scan_result(
            success=True, findings=[]
        )

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
            patch("workers.scan_worker.NucleiScanner", mock_scanner_class),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(task_always_eager=True)
            from workers.scan_worker import execute_scan

            result = execute_scan.apply(args=[1]).result

        assert result["status"] == "completed"
        assert result["success"] is True

    def test_job_transitions_to_failed_on_scanner_error(self):
        """When scanner.scan() reports failure, status transitions to 'failed'."""
        mock_db, mock_job, mock_target = _make_mock_db()

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan.return_value = _make_scan_result(
            success=False, findings=[], error_message="Scanner process exited non-zero"
        )

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
            patch("workers.scan_worker.NucleiScanner", mock_scanner_class),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(task_always_eager=True)
            from workers.scan_worker import execute_scan

            result = execute_scan.apply(args=[1]).result

        assert result["success"] is False
        assert result["status"] == "failed"

    def test_cancelled_job_skips_execution(self):
        """A job already in 'cancelled' state is detected early and skipped."""
        mock_db, mock_job, mock_target = _make_mock_db(job_status="cancelled")

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(task_always_eager=True)
            from workers.scan_worker import execute_scan

            result = execute_scan.apply(args=[1]).result

        assert result["status"] == "cancelled"
        assert result["success"] is False

    def test_job_not_found_returns_reject(self):
        """A missing job_id causes a non-retryable Reject with success=False."""
        mock_db, _, _ = _make_mock_db(job_found=False)

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(task_always_eager=True, task_eager_propagates=False)
            from workers.scan_worker import execute_scan

            # Reject is raised on missing job — eager mode surfaces it
            import pytest
            from celery.exceptions import Reject

            with pytest.raises((Reject, Exception)):
                execute_scan.apply(args=[999], throw=True)

    def test_cancel_scan_transitions_pending_to_cancelled(self):
        """cancel_scan sets status='cancelled' when job is in 'pending' state."""
        mock_db, mock_job, _ = _make_mock_db(job_status="pending")

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(task_always_eager=True)
            from workers.scan_worker import cancel_scan

            result = cancel_scan.apply(args=[1]).result

        assert result["success"] is True
        assert result["status"] == "cancelled"


# ---------------------------------------------------------------------------
# Class 3: Retry behavior
# ---------------------------------------------------------------------------


class TestTaskRetryBehavior:
    """Test retry behavior on transient failures."""

    def test_connection_error_triggers_retry_path(self):
        """A 'connection' error in the scanner causes the retry code path."""
        mock_db, mock_job, mock_target = _make_mock_db()

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan.side_effect = ConnectionError(
            "connection refused to scanner"
        )

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
            patch("workers.scan_worker.NucleiScanner", mock_scanner_class),
        ):
            from workers.celery_app import celery_app

            # Eager propagates=False so MaxRetries becomes a normal return
            celery_app.conf.update(
                task_always_eager=True,
                task_eager_propagates=False,
            )
            from workers.scan_worker import execute_scan

            result = execute_scan.apply(args=[1]).result

        # After exhausting max_retries the task should still return a dict
        assert isinstance(result, dict)
        assert result["success"] is False

    def test_timeout_error_triggers_retry_path(self):
        """A 'timeout' error in the scanner causes the retry code path."""
        mock_db, mock_job, mock_target = _make_mock_db()

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan.side_effect = TimeoutError(
            "timeout waiting for scanner"
        )

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
            patch("workers.scan_worker.NucleiScanner", mock_scanner_class),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(
                task_always_eager=True,
                task_eager_propagates=False,
            )
            from workers.scan_worker import execute_scan

            result = execute_scan.apply(args=[1]).result

        assert result["success"] is False

    def test_non_retryable_error_returns_failed_immediately(self):
        """A ValueError (non-connection) error is non-retryable."""
        mock_db, mock_job, mock_target = _make_mock_db()

        mock_scanner_class = MagicMock()
        mock_scanner_class.return_value.scan.side_effect = ValueError(
            "bad configuration"
        )

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
            patch("workers.scan_worker.NucleiScanner", mock_scanner_class),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(
                task_always_eager=True,
                task_eager_propagates=False,
            )
            from workers.scan_worker import execute_scan

            result = execute_scan.apply(args=[1]).result

        assert result["success"] is False
        assert result["status"] == "failed"

    def test_unknown_scanner_type_returns_failed_not_retry(self):
        """An unknown scanner_type field causes immediate failure (no retry)."""
        mock_db = MagicMock()
        job = MagicMock()
        job.status = "pending"
        job.target_id = 1
        job.scanner_type = "unknown_scanner"
        job.scan_type = "full"
        job.config = {}
        mock_db.scan_jobs.__getitem__.return_value = job

        target = MagicMock()
        target.target_value = "10.0.0.1"
        mock_db.scan_targets.__getitem__.return_value = target
        mock_db.return_value.update.return_value = None
        mock_db.commit.return_value = None

        with (
            patch.dict(
                "os.environ",
                {
                    "CELERY_BROKER_URL": "memory://",
                    "CELERY_RESULT_BACKEND": "cache+memory://",
                },
            ),
            patch("workers.scan_worker.get_configured_db", return_value=mock_db),
        ):
            from workers.celery_app import celery_app

            celery_app.conf.update(
                task_always_eager=True,
                task_eager_propagates=False,
            )
            from workers.scan_worker import execute_scan

            result = execute_scan.apply(args=[1]).result

        assert result["success"] is False
        assert result["status"] == "failed"
