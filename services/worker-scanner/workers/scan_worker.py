"""
Celery async scan execution worker.

This module implements the core Celery tasks for executing security scans
asynchronously. It handles job lifecycle management, scanner selection,
result processing, and error handling with automatic retries.
"""

from datetime import datetime
from typing import Any, Dict

from celery.exceptions import Reject
from celery.utils.log import get_task_logger

from database.models import get_configured_db
from scanners.nuclei import NucleiScanner
from scanners.openvas import OpenvasScanner
from scanners.zap import ZapScanner
from utils.logger import get_logger
from workers.celery_app import celery_app

logger = get_logger(__name__)
task_logger = get_task_logger(__name__)


@celery_app.task(
    bind=True,
    name="workers.scan_worker.execute_scan",
    max_retries=2,
    default_retry_delay=60
)
def execute_scan(self, job_id: int) -> Dict[str, Any]:
    """
    Execute a security scan asynchronously via Celery.

    This task handles the complete lifecycle of a scan job:
    1. Load job from database
    2. Update status to running
    3. Select and instantiate appropriate scanner
    4. Execute scan
    5. Process and store results
    6. Update job status and summary

    Args:
        self: Celery task instance (bound)
        job_id: Primary key of the scan_jobs record to execute

    Returns:
        Dictionary containing:
            - success (bool): Whether scan completed successfully
            - job_id (int): The job ID
            - status (str): Final job status
            - findings_count (int): Number of findings discovered
            - error (str, optional): Error message if failed

    Raises:
        Retry: On retryable errors (connection issues, timeouts)
        Reject: On non-retryable errors (job not found, invalid config)
    """
    db = None
    start_time = datetime.utcnow()

    try:
        # Get database connection
        db = get_configured_db()
        if db is None:
            error_msg = "Failed to get database connection"
            logger.error(error_msg)
            raise Reject(error_msg, requeue=False)

        # Load job from database
        job = db.scan_jobs[job_id]
        if job is None:
            error_msg = f"Job {job_id} not found in database"
            logger.error(error_msg)
            raise Reject(error_msg, requeue=False)

        # Check if job was cancelled before we started
        if job.status == "cancelled":
            logger.info(f"Job {job_id} was cancelled before execution")
            return {
                "success": False,
                "job_id": job_id,
                "status": "cancelled",
                "findings_count": 0,
                "error": "Job was cancelled"
            }

        # Update job status to running
        logger.info(f"Starting execution of job {job_id}")
        db(db.scan_jobs.id == job_id).update(
            status="running",
            started_at=datetime.utcnow()
        )
        db.commit()

        # Load target
        target = db.scan_targets[job.target_id]
        if target is None:
            error_msg = f"Target {job.target_id} not found for job {job_id}"
            logger.error(error_msg)
            db(db.scan_jobs.id == job_id).update(
                status="failed",
                error_message=error_msg,
                completed_at=datetime.utcnow(),
                duration_seconds=(datetime.utcnow() - start_time).total_seconds()
            )
            db.commit()
            return {
                "success": False,
                "job_id": job_id,
                "status": "failed",
                "findings_count": 0,
                "error": error_msg
            }

        # Select scanner based on scanner_type
        scanner_map = {
            "nuclei": NucleiScanner,
            "zap": ZapScanner,
            "openvas": OpenvasScanner,
        }

        scanner_class = scanner_map.get(job.scanner_type)
        if scanner_class is None:
            error_msg = (
                f"Unknown scanner type '{job.scanner_type}' for job {job_id}"
            )
            logger.error(error_msg)
            db(db.scan_jobs.id == job_id).update(
                status="failed",
                error_message=error_msg,
                completed_at=datetime.utcnow(),
                duration_seconds=(datetime.utcnow() - start_time).total_seconds()
            )
            db.commit()
            return {
                "success": False,
                "job_id": job_id,
                "status": "failed",
                "findings_count": 0,
                "error": error_msg
            }

        # Parse job config (stored as JSON in database)
        job_config = job.config if job.config else {}

        # Instantiate scanner
        logger.info(
            f"Instantiating {job.scanner_type} scanner for job {job_id}"
        )
        scanner = scanner_class(config=job_config)

        # Execute scan
        logger.info(
            f"Executing {job.scan_type} scan on target {target.target_value}"
        )
        result = scanner.scan(
            target=target.target_value,
            scan_type=job.scan_type,
            config=job_config
        )

        # Calculate duration
        end_time = datetime.utcnow()
        duration_seconds = (end_time - start_time).total_seconds()

        # Process results
        if result.success:
            logger.info(
                f"Scan completed successfully for job {job_id}, "
                f"processing {len(result.findings)} findings"
            )

            # Store findings in database
            findings_count = 0
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0
            }

            for finding in result.findings:
                try:
                    db.scan_findings.insert(
                        job_id=job_id,
                        target_id=job.target_id,
                        finding_id=finding.finding_id,
                        severity=finding.severity,
                        title=finding.title,
                        description=finding.description,
                        remediation=finding.remediation,
                        affected_url=finding.affected_url,
                        cvss_score=finding.cvss_score,
                        cve_ids=finding.cve_ids,
                        cwe_ids=finding.cwe_ids,
                        evidence=finding.evidence,
                        raw_finding=finding.raw_finding,
                        status="open",
                        discovered_at=finding.discovered_at,
                        updated_at=datetime.utcnow(),
                    )
                    findings_count += 1

                    # Count by severity
                    severity = finding.severity.lower()
                    if severity in severity_counts:
                        severity_counts[severity] += 1

                except Exception as e:
                    logger.error(
                        f"Failed to insert finding {finding.finding_id} "
                        f"for job {job_id}: {e}"
                    )
                    # Continue processing other findings

            # Build result summary
            result_summary = {
                "total_findings": findings_count,
                "by_severity": severity_counts,
                "scanner": job.scanner_type,
                "scan_type": job.scan_type,
                "duration_seconds": duration_seconds,
                "raw_summary": result.summary if result.summary else {}
            }

            # Update job to completed
            db(db.scan_jobs.id == job_id).update(
                status="completed",
                completed_at=end_time,
                duration_seconds=duration_seconds,
                result_summary=result_summary
            )
            db.commit()

            logger.info(
                f"Job {job_id} completed successfully with "
                f"{findings_count} findings"
            )

            return {
                "success": True,
                "job_id": job_id,
                "status": "completed",
                "findings_count": findings_count,
                "severity_counts": severity_counts
            }

        else:
            # Scan failed
            error_msg = result.error_message or "Scan failed without error message"
            logger.error(f"Scan failed for job {job_id}: {error_msg}")

            db(db.scan_jobs.id == job_id).update(
                status="failed",
                error_message=error_msg,
                completed_at=end_time,
                duration_seconds=duration_seconds
            )
            db.commit()

            return {
                "success": False,
                "job_id": job_id,
                "status": "failed",
                "findings_count": 0,
                "error": error_msg
            }

    except Reject:
        # Re-raise Reject exceptions (non-retryable)
        raise

    except Exception as exc:
        # Handle unexpected errors
        error_msg = f"Unexpected error executing job {job_id}: {exc}"
        logger.exception(error_msg)

        # Update job to failed if we have database connection
        if db is not None:
            try:
                end_time = datetime.utcnow()
                duration_seconds = (end_time - start_time).total_seconds()

                db(db.scan_jobs.id == job_id).update(
                    status="failed",
                    error_message=str(exc),
                    completed_at=end_time,
                    duration_seconds=duration_seconds
                )
                db.commit()
            except Exception as db_error:
                logger.error(
                    f"Failed to update job {job_id} status after error: "
                    f"{db_error}"
                )

        # Determine if error is retryable
        retryable_errors = (
            "connection",
            "timeout",
            "network",
            "temporary"
        )
        error_str = str(exc).lower()

        if any(keyword in error_str for keyword in retryable_errors):
            # Retry on connection/network errors
            logger.info(
                f"Retrying job {job_id} due to retryable error: {exc}"
            )
            try:
                raise self.retry(exc=exc)
            except self.MaxRetriesExceededError:
                logger.error(
                    f"Max retries exceeded for job {job_id}"
                )
                return {
                    "success": False,
                    "job_id": job_id,
                    "status": "failed",
                    "findings_count": 0,
                    "error": "Max retries exceeded"
                }
        else:
            # Non-retryable error
            return {
                "success": False,
                "job_id": job_id,
                "status": "failed",
                "findings_count": 0,
                "error": str(exc)
            }


@celery_app.task(name="workers.scan_worker.cancel_scan")
def cancel_scan(job_id: int) -> Dict[str, Any]:
    """
    Cancel a running or pending scan job.

    Updates the job status to 'cancelled' if the job is currently in
    'pending' or 'running' state. Jobs that are already completed or
    failed cannot be cancelled.

    Args:
        job_id: Primary key of the scan_jobs record to cancel

    Returns:
        Dictionary containing:
            - success (bool): Whether cancellation was successful
            - job_id (int): The job ID
            - status (str): Current job status after cancellation attempt
            - message (str): Human-readable status message

    Raises:
        None: All errors are caught and returned in the result dict
    """
    db = None

    try:
        # Get database connection
        db = get_configured_db()
        if db is None:
            error_msg = "Failed to get database connection"
            logger.error(error_msg)
            return {
                "success": False,
                "job_id": job_id,
                "status": "unknown",
                "message": error_msg
            }

        # Load job from database
        job = db.scan_jobs[job_id]
        if job is None:
            error_msg = f"Job {job_id} not found in database"
            logger.error(error_msg)
            return {
                "success": False,
                "job_id": job_id,
                "status": "unknown",
                "message": error_msg
            }

        # Check current status
        current_status = job.status

        if current_status in ("pending", "running"):
            # Cancel the job
            logger.info(f"Cancelling job {job_id} (status: {current_status})")
            db(db.scan_jobs.id == job_id).update(
                status="cancelled",
                completed_at=datetime.utcnow(),
                error_message="Job cancelled by user"
            )
            db.commit()

            return {
                "success": True,
                "job_id": job_id,
                "status": "cancelled",
                "message": "Job cancelled successfully"
            }

        elif current_status == "cancelled":
            logger.info(f"Job {job_id} is already cancelled")
            return {
                "success": True,
                "job_id": job_id,
                "status": "cancelled",
                "message": "Job was already cancelled"
            }

        else:
            # Job is completed or failed, cannot cancel
            logger.warning(
                f"Cannot cancel job {job_id} with status '{current_status}'"
            )
            return {
                "success": False,
                "job_id": job_id,
                "status": current_status,
                "message": (
                    f"Cannot cancel job with status '{current_status}'. "
                    "Only pending or running jobs can be cancelled."
                )
            }

    except Exception as exc:
        error_msg = f"Error cancelling job {job_id}: {exc}"
        logger.exception(error_msg)
        return {
            "success": False,
            "job_id": job_id,
            "status": "unknown",
            "message": error_msg
        }
