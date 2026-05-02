"""
gRPC Server Implementation for S3 Scan Service.

Handles inter-service communication for S3 scanning operations including:
- Scan task submission and dispatch to workers
- Scan result reporting from workers
- Ad-hoc file scanning
- Streaming scan results
- Job status queries
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime
from typing import Dict, Optional

import grpc
import structlog

logger = structlog.get_logger(__name__)


class S3ScanServicer:
    """
    gRPC servicer for S3 scan operations.

    Implements the S3ScanService defined in proto/s3_scan.proto.
    Handles all RPC methods for S3 scanning coordination between manager and workers.
    """

    def __init__(self, job_manager, results_manager, adhoc_manager, bucket_manager):
        """
        Initialize the S3 scan servicer.

        Args:
            job_manager: ScanJobManager instance for job lifecycle
            results_manager: ScanResultsManager for result storage
            adhoc_manager: AdhocScanManager for ad-hoc file scanning
            bucket_manager: BucketConfigManager for S3 bucket configs
        """
        self.job_manager = job_manager
        self.results_manager = results_manager
        self.adhoc_manager = adhoc_manager
        self.bucket_manager = bucket_manager
        logger.info("S3ScanServicer initialized")

    async def SubmitScanTask(self, request, context):
        """
        Submit a scan task (called by manager to dispatch to workers).

        Args:
            request: ScanTask message containing task details
            context: gRPC context

        Returns:
            TaskAck message indicating acceptance
        """
        try:
            from grpc.generated import s3_scan_pb2

            # Validate required fields
            if not request.task_id:
                logger.error("SubmitScanTask: Missing task_id")
                return s3_scan_pb2.TaskAck(
                    accepted=False, message="Missing required field: task_id"
                )

            if not request.job_id:
                logger.error("SubmitScanTask: Missing job_id", task_id=request.task_id)
                return s3_scan_pb2.TaskAck(
                    accepted=False, message="Missing required field: job_id"
                )

            if not request.object_key:
                logger.error(
                    "SubmitScanTask: Missing object_key", task_id=request.task_id
                )
                return s3_scan_pb2.TaskAck(
                    accepted=False, message="Missing required field: object_key"
                )

            # Create scan task dict from protobuf message
            task_data = {
                "task_id": request.task_id,
                "job_id": request.job_id,
                "bucket_config_id": request.bucket_config_id,
                "object_key": request.object_key,
                "object_size": request.object_size,
                "endpoint_url": request.endpoint_url,
                "bucket_name": request.bucket_name,
                "access_key": request.access_key,
                "secret_key": request.secret_key,
                "region": request.region,
                "use_ssl": request.use_ssl,
                "path_style": request.path_style,
                "yara_enabled": request.yara_enabled,
            }

            # Publish task to Redis stream via job manager
            await self.job_manager.scan_publisher.publish_scan_task(task_data)

            logger.info(
                "Published scan task to stream",
                task_id=request.task_id,
                job_id=request.job_id,
                object_key=request.object_key,
            )

            return s3_scan_pb2.TaskAck(
                accepted=True, message="Scan task published successfully"
            )

        except Exception as e:
            logger.error(
                "Error submitting scan task",
                task_id=getattr(request, "task_id", "unknown"),
                error=str(e),
                exc_info=True,
            )
            return s3_scan_pb2.TaskAck(accepted=False, message=f"Error: {str(e)}")

    async def ReportScanResult(self, request, context):
        """
        Receive scan result from worker.

        Args:
            request: ScanResult message containing scan outcome
            context: gRPC context

        Returns:
            ResultAck message confirming receipt
        """
        try:
            from grpc.generated import s3_scan_pb2

            # Validate required fields
            if not request.task_id:
                logger.error("ReportScanResult: Missing task_id")
                return s3_scan_pb2.ResultAck(accepted=False)

            if not request.job_id:
                logger.error(
                    "ReportScanResult: Missing job_id", task_id=request.task_id
                )
                return s3_scan_pb2.ResultAck(accepted=False)

            # Convert protobuf result to dict for database storage
            result_data = {
                "job_id": request.job_id,
                "bucket_config_id": 0,  # Will be looked up from job
                "object_key": request.object_key,
                "scan_status": request.scan_status,
                "is_malware": request.is_malware,
                "is_pup": request.is_pup,
                "is_threat": request.is_threat,
                "detected_file_type": (
                    request.detected_file_type if request.detected_file_type else None
                ),
                "threat_details": (
                    list(request.threat_names) if request.threat_names else []
                ),
                "file_hash": (
                    request.file_sha256 if request.file_sha256 else request.file_sha1
                ),
                "scan_duration_ms": request.scan_duration_ms,
                "error_message": (
                    request.error_message if request.error_message else None
                ),
            }

            # Store additional hash fields if available
            if request.file_md5:
                result_data["file_md5"] = request.file_md5
            if request.file_sha1:
                result_data["file_sha1"] = request.file_sha1
            if request.file_sha256:
                result_data["file_sha256"] = request.file_sha256

            # Store JSON fields if present
            if request.clamav_result_json:
                result_data["clamav_result_json"] = request.clamav_result_json
            if request.yara_matches_json:
                result_data["yara_matches_json"] = request.yara_matches_json
            if request.ti_enrichment_json:
                result_data["ti_enrichment_json"] = request.ti_enrichment_json

            # Look up bucket_config_id from job
            job = await self.job_manager.get_job_status(request.job_id)
            if job:
                result_data["bucket_config_id"] = job["bucket_config_id"]

            # Save result to database
            result_id = await self.results_manager.save_scan_result(result_data)

            # Update job progress counters
            await self.job_manager.update_job_progress(
                job_id=request.job_id,
                scanned_count=1,
                infected_count=1 if request.is_malware else 0,
                pup_count=1 if request.is_pup else 0,
                error_count=1 if request.scan_status == "error" else 0,
            )

            logger.info(
                "Saved scan result",
                result_id=result_id,
                task_id=request.task_id,
                job_id=request.job_id,
                object_key=request.object_key,
                scan_status=request.scan_status,
                is_malware=request.is_malware,
            )

            return s3_scan_pb2.ResultAck(accepted=True)

        except Exception as e:
            logger.error(
                "Error reporting scan result",
                task_id=getattr(request, "task_id", "unknown"),
                error=str(e),
                exc_info=True,
            )
            return s3_scan_pb2.ResultAck(accepted=False)

    async def ScanAdhocFile(self, request, context):
        """
        Handle ad-hoc file scan request.

        Uploads file to Minio, triggers scan, and waits for result or returns pending status.

        Args:
            request: AdhocScanRequest containing file content and metadata
            context: gRPC context

        Returns:
            AdhocScanResponse with scan ID and status
        """
        try:
            from grpc.generated import s3_scan_pb2

            # Validate request
            if not request.file_content:
                logger.error("ScanAdhocFile: Missing file_content")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Missing file content")
                return s3_scan_pb2.AdhocScanResponse(
                    scan_id="",
                    status="error",
                )

            if not request.filename:
                logger.error("ScanAdhocFile: Missing filename")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Missing filename")
                return s3_scan_pb2.AdhocScanResponse(
                    scan_id="",
                    status="error",
                )

            # Use provided scan_id or generate new one
            scan_id = request.scan_id if request.scan_id else str(uuid.uuid4())

            logger.info(
                "Processing ad-hoc scan request",
                scan_id=scan_id,
                filename=request.filename,
                file_size=len(request.file_content),
                user_id=request.uploaded_by,
            )

            # Upload file and trigger scan via adhoc manager
            result = await self.adhoc_manager.upload_and_scan(
                file_content=request.file_content,
                filename=request.filename,
                user_id=request.uploaded_by if request.uploaded_by else 0,
            )

            # Check if scan completed immediately or is pending
            if result.get("scan_status") == "completed":
                # Scan completed, populate full result
                scan_result = s3_scan_pb2.ScanResult(
                    task_id=result.get("task_id", ""),
                    job_id="adhoc",
                    object_key=result.get("object_key", ""),
                    scan_status=result.get("scan_status", "completed"),
                    is_malware=result.get("is_malware", False),
                    is_pup=result.get("is_pup", False),
                    is_threat=result.get("is_threat", False),
                    detected_file_type=result.get("detected_file_type", ""),
                    threat_names=result.get("threat_details", []),
                    file_md5=result.get("file_md5", ""),
                    file_sha1=result.get("file_sha1", ""),
                    file_sha256=result.get("file_sha256", ""),
                    clamav_result_json=result.get("clamav_result_json", ""),
                    yara_matches_json=result.get("yara_matches_json", ""),
                    ti_enrichment_json=result.get("ti_enrichment_json", ""),
                    scan_duration_ms=result.get("scan_duration_ms", 0),
                    tags_applied=result.get("tags_applied", False),
                    error_message=result.get("error_message", ""),
                )

                return s3_scan_pb2.AdhocScanResponse(
                    scan_id=scan_id,
                    status="complete",
                    result=scan_result,
                )
            else:
                # Scan is pending or in progress
                return s3_scan_pb2.AdhocScanResponse(
                    scan_id=scan_id,
                    status=result.get("scan_status", "pending"),
                )

        except Exception as e:
            logger.error(
                "Error processing ad-hoc scan",
                scan_id=getattr(request, "scan_id", "unknown"),
                filename=getattr(request, "filename", "unknown"),
                error=str(e),
                exc_info=True,
            )
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Error: {str(e)}")
            return s3_scan_pb2.AdhocScanResponse(
                scan_id=getattr(request, "scan_id", ""),
                status="error",
            )

    async def StreamScanResults(self, request_iterator, context):
        """
        Stream scan results from workers (bidirectional streaming).

        Processes incoming stream of results and saves each to database.

        Args:
            request_iterator: Async iterator of ScanResult messages
            context: gRPC context

        Returns:
            StreamAck with count of results received
        """
        try:
            from grpc.generated import s3_scan_pb2

            results_count = 0

            async for result in request_iterator:
                try:
                    # Process each result using ReportScanResult logic
                    ack = await self.ReportScanResult(result, context)

                    if ack.accepted:
                        results_count += 1
                    else:
                        logger.warning(
                            "Failed to process streamed result",
                            task_id=result.task_id,
                            job_id=result.job_id,
                        )

                except Exception as e:
                    logger.error(
                        "Error processing streamed result",
                        task_id=getattr(result, "task_id", "unknown"),
                        error=str(e),
                        exc_info=True,
                    )
                    continue

            logger.info(
                "Completed streaming scan results",
                results_received=results_count,
            )

            return s3_scan_pb2.StreamAck(results_received=results_count)

        except Exception as e:
            logger.error(
                "Error in StreamScanResults",
                error=str(e),
                exc_info=True,
            )
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Error: {str(e)}")
            return s3_scan_pb2.StreamAck(results_received=0)

    async def GetScanStatus(self, request, context):
        """
        Get scan job status.

        Args:
            request: ScanStatusRequest containing job_id
            context: gRPC context

        Returns:
            ScanStatusResponse with job status and progress
        """
        try:
            from grpc.generated import s3_scan_pb2

            # Validate request
            if not request.job_id:
                logger.error("GetScanStatus: Missing job_id")
                context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
                context.set_details("Missing job_id")
                return s3_scan_pb2.ScanStatusResponse(
                    job_id="",
                    status="error",
                    total=0,
                    scanned=0,
                    infected=0,
                )

            # Fetch job from job_manager
            job = await self.job_manager.get_job_status(request.job_id)

            if not job:
                logger.warning("Job not found", job_id=request.job_id)
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details(f"Job not found: {request.job_id}")
                return s3_scan_pb2.ScanStatusResponse(
                    job_id=request.job_id,
                    status="not_found",
                    total=0,
                    scanned=0,
                    infected=0,
                )

            logger.info(
                "Retrieved job status",
                job_id=request.job_id,
                status=job["status"],
                scanned=job.get("scanned_objects", 0),
                total=job.get("total_objects", 0),
            )

            return s3_scan_pb2.ScanStatusResponse(
                job_id=request.job_id,
                status=job["status"],
                total=job.get("total_objects", 0),
                scanned=job.get("scanned_objects", 0),
                infected=job.get("infected_objects", 0),
            )

        except Exception as e:
            logger.error(
                "Error getting scan status",
                job_id=getattr(request, "job_id", "unknown"),
                error=str(e),
                exc_info=True,
            )
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(f"Error: {str(e)}")
            return s3_scan_pb2.ScanStatusResponse(
                job_id=getattr(request, "job_id", ""),
                status="error",
                total=0,
                scanned=0,
                infected=0,
            )
