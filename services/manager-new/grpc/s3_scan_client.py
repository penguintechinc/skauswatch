"""
gRPC Client for S3 Scan Service.

Provides client-side interface for workers to communicate with manager service.
Handles result reporting, status queries, and connection management.
"""

import asyncio
import logging
from typing import Dict, Optional

import grpc
import structlog

logger = structlog.get_logger(__name__)


class S3ScanClient:
    """
    gRPC client for S3 scan operations.

    Used by worker services to communicate with the manager service.
    Supports result reporting, status queries, and streaming results.
    """

    def __init__(self, server_address: str, timeout: int = 30):
        """
        Initialize the S3 scan client.

        Args:
            server_address: Manager gRPC server address (host:port)
            timeout: Default RPC timeout in seconds
        """
        self.server_address = server_address
        self.timeout = timeout
        self.channel: Optional[grpc.aio.Channel] = None
        self.stub = None
        logger.info("S3ScanClient initialized", server_address=server_address)

    async def connect(self) -> None:
        """
        Establish connection to manager gRPC server.

        Raises:
            grpc.RpcError: If connection fails
        """
        try:
            # Create insecure async channel
            self.channel = grpc.aio.insecure_channel(
                self.server_address,
                options=[
                    ("grpc.max_send_message_length", 50 * 1024 * 1024),  # 50MB
                    ("grpc.max_receive_message_length", 50 * 1024 * 1024),  # 50MB
                    ("grpc.keepalive_time_ms", 30000),  # 30 seconds
                    ("grpc.keepalive_timeout_ms", 10000),  # 10 seconds
                    ("grpc.keepalive_permit_without_calls", True),
                    ("grpc.http2.max_pings_without_data", 0),
                ],
            )

            # Import generated stubs
            from grpc.generated import s3_scan_pb2_grpc

            # Create stub
            self.stub = s3_scan_pb2_grpc.S3ScanServiceStub(self.channel)

            # Test connection with a simple call (wait for channel to be ready)
            await self.channel.channel_ready()

            logger.info(
                "Connected to manager gRPC server", server_address=self.server_address
            )

        except Exception as e:
            logger.error(
                "Failed to connect to manager gRPC server",
                server_address=self.server_address,
                error=str(e),
                exc_info=True,
            )
            raise

    async def close(self) -> None:
        """
        Close connection to manager gRPC server.
        """
        if self.channel:
            await self.channel.close()
            self.channel = None
            self.stub = None
            logger.info("Closed connection to manager gRPC server")

    async def report_scan_result(self, result: Dict) -> bool:
        """
        Send scan result to manager.

        Args:
            result: Dictionary containing scan result data with fields:
                - task_id: Task identifier
                - job_id: Job identifier
                - object_key: S3 object key
                - scan_status: Scan status (clean, infected, pup, error, skipped)
                - is_malware: Boolean indicating malware detection
                - is_pup: Boolean indicating PUP detection
                - is_threat: Boolean indicating any threat
                - detected_file_type: Detected file type
                - threat_names: List of threat names
                - file_md5: MD5 hash
                - file_sha1: SHA1 hash
                - file_sha256: SHA256 hash
                - clamav_result_json: ClamAV result JSON
                - yara_matches_json: YARA matches JSON
                - ti_enrichment_json: Threat intel enrichment JSON
                - scan_duration_ms: Scan duration in milliseconds
                - tags_applied: Boolean indicating if tags were applied
                - error_message: Error message if scan failed

        Returns:
            True if result accepted, False otherwise
        """
        if not self.stub:
            logger.error("Client not connected, call connect() first")
            return False

        try:
            from grpc.generated import s3_scan_pb2

            # Build ScanResult message
            scan_result = s3_scan_pb2.ScanResult(
                task_id=result.get("task_id", ""),
                job_id=result.get("job_id", ""),
                object_key=result.get("object_key", ""),
                scan_status=result.get("scan_status", "error"),
                is_malware=result.get("is_malware", False),
                is_pup=result.get("is_pup", False),
                is_threat=result.get("is_threat", False),
                detected_file_type=result.get("detected_file_type", ""),
                threat_names=result.get("threat_names", []),
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

            # Call ReportScanResult RPC
            response = await self.stub.ReportScanResult(
                scan_result,
                timeout=self.timeout,
            )

            if response.accepted:
                logger.info(
                    "Scan result reported successfully",
                    task_id=result.get("task_id"),
                    job_id=result.get("job_id"),
                    object_key=result.get("object_key"),
                )
                return True
            else:
                logger.warning(
                    "Scan result rejected by manager",
                    task_id=result.get("task_id"),
                    job_id=result.get("job_id"),
                )
                return False

        except grpc.RpcError as e:
            logger.error(
                "gRPC error reporting scan result",
                task_id=result.get("task_id"),
                error_code=e.code(),
                error_details=e.details(),
                exc_info=True,
            )
            return False
        except Exception as e:
            logger.error(
                "Error reporting scan result",
                task_id=result.get("task_id"),
                error=str(e),
                exc_info=True,
            )
            return False

    async def get_scan_status(self, job_id: str) -> Optional[Dict]:
        """
        Get job status from manager.

        Args:
            job_id: Job identifier

        Returns:
            Dictionary with status information:
                - job_id: Job identifier
                - status: Job status (pending, running, completed, failed, cancelled)
                - total: Total objects to scan
                - scanned: Number of objects scanned
                - infected: Number of infected objects
            Returns None if job not found or error occurs
        """
        if not self.stub:
            logger.error("Client not connected, call connect() first")
            return None

        try:
            from grpc.generated import s3_scan_pb2

            # Build request
            request = s3_scan_pb2.ScanStatusRequest(job_id=job_id)

            # Call GetScanStatus RPC
            response = await self.stub.GetScanStatus(
                request,
                timeout=self.timeout,
            )

            status = {
                "job_id": response.job_id,
                "status": response.status,
                "total": response.total,
                "scanned": response.scanned,
                "infected": response.infected,
            }

            logger.info(
                "Retrieved job status",
                job_id=job_id,
                status=status["status"],
                scanned=status["scanned"],
                total=status["total"],
            )

            return status

        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.NOT_FOUND:
                logger.warning("Job not found", job_id=job_id)
            else:
                logger.error(
                    "gRPC error getting scan status",
                    job_id=job_id,
                    error_code=e.code(),
                    error_details=e.details(),
                    exc_info=True,
                )
            return None
        except Exception as e:
            logger.error(
                "Error getting scan status",
                job_id=job_id,
                error=str(e),
                exc_info=True,
            )
            return None

    async def stream_scan_results(self, results: list) -> int:
        """
        Stream multiple scan results to manager (batch submission).

        Args:
            results: List of result dictionaries (same format as report_scan_result)

        Returns:
            Number of results successfully streamed
        """
        if not self.stub:
            logger.error("Client not connected, call connect() first")
            return 0

        try:
            from grpc.generated import s3_scan_pb2

            # Generator function to yield results
            async def result_generator():
                for result in results:
                    scan_result = s3_scan_pb2.ScanResult(
                        task_id=result.get("task_id", ""),
                        job_id=result.get("job_id", ""),
                        object_key=result.get("object_key", ""),
                        scan_status=result.get("scan_status", "error"),
                        is_malware=result.get("is_malware", False),
                        is_pup=result.get("is_pup", False),
                        is_threat=result.get("is_threat", False),
                        detected_file_type=result.get("detected_file_type", ""),
                        threat_names=result.get("threat_names", []),
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
                    yield scan_result
                    await asyncio.sleep(0)  # Yield control

            # Call StreamScanResults RPC
            response = await self.stub.StreamScanResults(
                result_generator(),
                timeout=self.timeout * len(results),  # Scale timeout with batch size
            )

            logger.info(
                "Streamed scan results",
                batch_size=len(results),
                results_received=response.results_received,
            )

            return response.results_received

        except grpc.RpcError as e:
            logger.error(
                "gRPC error streaming scan results",
                batch_size=len(results),
                error_code=e.code(),
                error_details=e.details(),
                exc_info=True,
            )
            return 0
        except Exception as e:
            logger.error(
                "Error streaming scan results",
                batch_size=len(results),
                error=str(e),
                exc_info=True,
            )
            return 0

    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
