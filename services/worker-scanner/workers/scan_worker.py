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
    default_retry_delay=60,
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
                "error": "Job was cancelled",
            }

        # Update job status to running
        logger.info(f"Starting execution of job {job_id}")
        db(db.scan_jobs.id == job_id).update(
            status="running", started_at=datetime.utcnow()
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
                duration_seconds=(datetime.utcnow() - start_time).total_seconds(),
            )
            db.commit()
            return {
                "success": False,
                "job_id": job_id,
                "status": "failed",
                "findings_count": 0,
                "error": error_msg,
            }

        # Select scanner based on scanner_type
        scanner_map = {
            "nuclei": NucleiScanner,
            "zap": ZapScanner,
            "openvas": OpenvasScanner,
        }

        scanner_class = scanner_map.get(job.scanner_type)
        if scanner_class is None:
            error_msg = f"Unknown scanner type '{job.scanner_type}' for job {job_id}"
            logger.error(error_msg)
            db(db.scan_jobs.id == job_id).update(
                status="failed",
                error_message=error_msg,
                completed_at=datetime.utcnow(),
                duration_seconds=(datetime.utcnow() - start_time).total_seconds(),
            )
            db.commit()
            return {
                "success": False,
                "job_id": job_id,
                "status": "failed",
                "findings_count": 0,
                "error": error_msg,
            }

        # Parse job config (stored as JSON in database)
        job_config = job.config if job.config else {}

        # Instantiate scanner
        logger.info(f"Instantiating {job.scanner_type} scanner for job {job_id}")
        scanner = scanner_class(config=job_config)

        # Execute scan
        logger.info(f"Executing {job.scan_type} scan on target {target.target_value}")
        result = scanner.scan(
            target=target.target_value, scan_type=job.scan_type, config=job_config
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
                "info": 0,
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
                "raw_summary": result.summary if result.summary else {},
            }

            # Update job to completed
            db(db.scan_jobs.id == job_id).update(
                status="completed",
                completed_at=end_time,
                duration_seconds=duration_seconds,
                result_summary=result_summary,
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
                "severity_counts": severity_counts,
            }

        else:
            # Scan failed
            error_msg = result.error_message or "Scan failed without error message"
            logger.error(f"Scan failed for job {job_id}: {error_msg}")

            db(db.scan_jobs.id == job_id).update(
                status="failed",
                error_message=error_msg,
                completed_at=end_time,
                duration_seconds=duration_seconds,
            )
            db.commit()

            return {
                "success": False,
                "job_id": job_id,
                "status": "failed",
                "findings_count": 0,
                "error": error_msg,
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
                    duration_seconds=duration_seconds,
                )
                db.commit()
            except Exception as db_error:
                logger.error(
                    f"Failed to update job {job_id} status after error: " f"{db_error}"
                )

        # Determine if error is retryable
        retryable_errors = ("connection", "timeout", "network", "temporary")
        error_str = str(exc).lower()

        if any(keyword in error_str for keyword in retryable_errors):
            # Retry on connection/network errors
            logger.info(f"Retrying job {job_id} due to retryable error: {exc}")
            try:
                raise self.retry(exc=exc)
            except self.MaxRetriesExceededError:
                logger.error(f"Max retries exceeded for job {job_id}")
                return {
                    "success": False,
                    "job_id": job_id,
                    "status": "failed",
                    "findings_count": 0,
                    "error": "Max retries exceeded",
                }
        else:
            # Non-retryable error
            return {
                "success": False,
                "job_id": job_id,
                "status": "failed",
                "findings_count": 0,
                "error": str(exc),
            }


@celery_app.task(
    bind=True,
    name="workers.scan_worker.execute_asm_scan",
    max_retries=1,
    default_retry_delay=30,
)
def execute_asm_scan(self, scan_id: int) -> Dict[str, Any]:
    """
    Execute an ASM (Attack Surface Management) scan asynchronously.

    Orchestrates: masscan → banner grabbing → screenshots → cert inspection
    Persists all results to ASM database tables.

    Args:
        self: Celery task instance (bound)
        scan_id: Primary key of the asm_scans record to execute

    Returns:
        Dictionary with success, scan_id, status, and summary.
    """
    db = None
    start_time = datetime.utcnow()

    try:
        db = get_configured_db()
        if db is None:
            raise Reject("Failed to get database connection", requeue=False)

        scan = db.asm_scans[scan_id]
        if scan is None:
            raise Reject(f"ASM scan {scan_id} not found", requeue=False)

        if scan.status == "cancelled":
            return {"success": False, "scan_id": scan_id, "status": "cancelled"}

        # Mark running
        db(db.asm_scans.id == scan_id).update(
            status="running", started_at=datetime.utcnow()
        )
        db.commit()

        # Load target
        target = db.scan_targets[scan.target_id]
        if target is None:
            raise Reject(
                f"Target {scan.target_id} not found for ASM scan {scan_id}",
                requeue=False,
            )

        # Build config
        ports_config = scan.ports_config or {}
        ports_config["scan_id"] = scan_id
        ports_config["mode"] = scan.mode

        # Run ASM scanner
        from scanners.asm_scanner import ASMScanner

        scanner = ASMScanner(config=ports_config)
        result = scanner.scan(
            target=target.target_value,
            scan_type=scan.mode,
            config=ports_config,
        )

        end_time = datetime.utcnow()

        if result.success:
            # Persist results to ASM tables
            summary = result.summary or {}
            open_ports = summary.get("open_ports_data", [])
            banners_data = summary.get("banners_data", [])
            screenshot_data = summary.get("screenshot_data", [])
            cert_data = summary.get("cert_data", [])

            # Build banner lookup: {(ip, port): banner_dict}
            banner_lookup = {(b["ip"], b["port"]): b for b in banners_data}

            # Group ports by IP → create asm_hosts + asm_services
            hosts_map: Dict[str, int] = {}  # ip → host_id

            for entry in open_ports:
                ip = entry["ip"]
                port = entry["port"]
                proto = entry.get("proto", "tcp")

                # Get or create host record
                if ip not in hosts_map:
                    host_id = db.asm_hosts.insert(
                        scan_id=scan_id,
                        ip_address=ip,
                        is_alive=True,
                        created_at=datetime.utcnow(),
                    )
                    db.commit()
                    hosts_map[ip] = host_id
                else:
                    host_id = hosts_map[ip]

                # Get banner info
                banner_info = banner_lookup.get((ip, port), {})

                # Create service record
                svc_id = db.asm_services.insert(
                    host_id=host_id,
                    port=port,
                    protocol=proto,
                    state="open",
                    service_name=banner_info.get("service_name", ""),
                    banner=banner_info.get("banner", ""),
                    version=banner_info.get("version", ""),
                    created_at=datetime.utcnow(),
                )
                db.commit()

                # Find screenshot for this service
                for ss in screenshot_data:
                    s3_key = ss.get("s3_key", "")
                    if f"/{ip}/{port}-" in s3_key:
                        captured_at = None
                        try:
                            captured_at = datetime.fromisoformat(
                                ss.get("captured_at", "")
                            )
                        except Exception:
                            pass

                        db.asm_screenshots.insert(
                            service_id=svc_id,
                            s3_key=s3_key,
                            url=ss.get("url", ""),
                            tool=ss.get("tool", "unknown"),
                            file_size_bytes=ss.get("file_size_bytes"),
                            captured_at=captured_at,
                            created_at=datetime.utcnow(),
                        )
                        db.commit()

                # Find cert for this TLS service
                for cert in cert_data:
                    if cert.get("ip") == ip and cert.get("port") == port:
                        not_before = None
                        not_after = None
                        try:
                            not_before = datetime.fromisoformat(
                                cert.get("not_before", "")
                            )
                            not_after = datetime.fromisoformat(
                                cert.get("not_after", "")
                            )
                        except Exception:
                            pass

                        db.asm_certs.insert(
                            service_id=svc_id,
                            subject=cert.get("subject", ""),
                            issuer=cert.get("issuer", ""),
                            not_before=not_before,
                            not_after=not_after,
                            is_expired=cert.get("is_expired", False),
                            days_until_expiry=cert.get("days_until_expiry"),
                            sans=cert.get("sans", []),
                            fingerprint_sha256=cert.get("fingerprint_sha256", ""),
                            created_at=datetime.utcnow(),
                        )
                        db.commit()

            # Compute diff vs previous scan for same target
            prev_scan = (
                db(
                    (db.asm_scans.target_id == scan.target_id)
                    & (db.asm_scans.id != scan_id)
                    & (db.asm_scans.status == "completed")
                )
                .select(orderby=~db.asm_scans.created_at, limitby=(0, 1))
                .first()
            )

            new_services = []
            removed_services = []
            expired_certs = [c for c in cert_data if c.get("is_expired")]

            if prev_scan:
                # Get previous scan's services
                prev_hosts = db(db.asm_hosts.scan_id == prev_scan.id).select()
                prev_service_keys: set = set()
                for ph in prev_hosts:
                    prev_svcs = db(db.asm_services.host_id == ph.id).select()
                    for ps in prev_svcs:
                        prev_service_keys.add(f"{ph.ip_address}:{ps.port}")

                # Current scan services
                curr_service_keys: set = set()
                for entry in open_ports:
                    curr_service_keys.add(f"{entry['ip']}:{entry['port']}")

                new_services = [
                    {"service": s} for s in curr_service_keys - prev_service_keys
                ]
                removed_services = [
                    {"service": s} for s in prev_service_keys - curr_service_keys
                ]

            # Insert diff record
            if prev_scan or new_services or removed_services or expired_certs:
                db.asm_diffs.insert(
                    scan_id=scan_id,
                    prev_scan_id=prev_scan.id if prev_scan else None,
                    new_services=new_services,
                    removed_services=removed_services,
                    new_certs=[],
                    expired_certs=expired_certs,
                    created_at=datetime.utcnow(),
                )
                db.commit()

            # Mark scan completed
            db(db.asm_scans.id == scan_id).update(
                status="completed",
                completed_at=end_time,
            )
            db.commit()

            logger.info(
                f"ASM scan {scan_id} completed: {len(open_ports)} ports, "
                f"{len(screenshot_data)} screenshots, {len(cert_data)} certs"
            )

            return {
                "success": True,
                "scan_id": scan_id,
                "status": "completed",
                "open_ports": len(open_ports),
                "screenshots": len(screenshot_data),
                "certs": len(cert_data),
                "new_services": len(new_services),
                "removed_services": len(removed_services),
            }

        else:
            error_msg = result.error_message or "ASM scan failed"
            db(db.asm_scans.id == scan_id).update(
                status="failed",
                completed_at=end_time,
            )
            db.commit()
            return {
                "success": False,
                "scan_id": scan_id,
                "status": "failed",
                "error": error_msg,
            }

    except Reject:
        raise
    except Exception as exc:
        error_msg = f"Unexpected error in ASM scan {scan_id}: {exc}"
        logger.exception(error_msg)
        if db is not None:
            try:
                db(db.asm_scans.id == scan_id).update(status="failed")
                db.commit()
            except Exception:
                pass
        return {
            "success": False,
            "scan_id": scan_id,
            "status": "failed",
            "error": str(exc),
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
                "message": error_msg,
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
                "message": error_msg,
            }

        # Check current status
        current_status = job.status

        if current_status in ("pending", "running"):
            # Cancel the job
            logger.info(f"Cancelling job {job_id} (status: {current_status})")
            db(db.scan_jobs.id == job_id).update(
                status="cancelled",
                completed_at=datetime.utcnow(),
                error_message="Job cancelled by user",
            )
            db.commit()

            return {
                "success": True,
                "job_id": job_id,
                "status": "cancelled",
                "message": "Job cancelled successfully",
            }

        elif current_status == "cancelled":
            logger.info(f"Job {job_id} is already cancelled")
            return {
                "success": True,
                "job_id": job_id,
                "status": "cancelled",
                "message": "Job was already cancelled",
            }

        else:
            # Job is completed or failed, cannot cancel
            logger.warning(f"Cannot cancel job {job_id} with status '{current_status}'")
            return {
                "success": False,
                "job_id": job_id,
                "status": current_status,
                "message": (
                    f"Cannot cancel job with status '{current_status}'. "
                    "Only pending or running jobs can be cancelled."
                ),
            }

    except Exception as exc:
        error_msg = f"Error cancelling job {job_id}: {exc}"
        logger.exception(error_msg)
        return {
            "success": False,
            "job_id": job_id,
            "status": "unknown",
            "message": error_msg,
        }
