"""
Main S3 scan worker using async + ThreadPoolExecutor pattern.

This module implements the core S3ScanWorker class that consumes scan tasks
from Redis Streams, processes them through a pipeline of scanning operations,
and publishes results back to the system.
"""

import asyncio
import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional

from config import WorkerConfig
from models import ScanResultMessage, ScanTaskMessage
from s3.client import S3Client
from s3.downloader import S3Downloader
from s3.tagger import S3Tagger
from scanner.clamav import ClamAVScanner
from scanner.file_type import FileTypeDetector
from scanner.hasher import FileHasher
from scanner.yara_scanner import YaraScanner
from streams.consumer import StreamConsumer
from streams.publisher import ResultPublisher
from ti.enricher import TIEnricher

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class S3ScanWorker:
    """
    S3 scan worker with async event loop + ThreadPoolExecutor pattern.

    Consumes scan tasks from Redis Streams, orchestrates file download,
    scanning, and analysis, then publishes results back to the system.
    The worker uses async/await for I/O operations and ThreadPoolExecutor
    for CPU-bound blocking operations (hashing, scanning, file type detection).
    """

    def __init__(self, config: WorkerConfig):
        """Initialize S3 scan worker with configuration.

        Args:
            config: WorkerConfig instance with all settings
        """
        self.config = config
        self.running = False

        # Async clients
        self.redis_client: Optional[redis.Redis] = None
        self.stream_consumer: Optional[StreamConsumer] = None
        self.result_publisher: Optional[ResultPublisher] = None
        self.ti_enricher: Optional[TIEnricher] = None

        # Thread pool for blocking operations
        self.executor = ThreadPoolExecutor(max_workers=config.thread_pool_size)

        # Scanner instances
        self.file_detector: Optional[FileTypeDetector] = None
        self.clamav_scanner: Optional[ClamAVScanner] = None
        self.yara_scanner: Optional[YaraScanner] = None

        # S3 operations
        self.downloader: Optional[S3Downloader] = None

        # Semaphore to limit concurrent tasks
        self.task_semaphore = asyncio.Semaphore(config.max_concurrent_tasks)

        logger.info(
            f"S3ScanWorker initialized: {config.consumer_name}, "
            f"max_concurrent={config.max_concurrent_tasks}, "
            f"thread_pool={config.thread_pool_size}"
        )

    async def start(self) -> None:
        """Start the worker and begin consuming tasks.

        Initializes all async clients, scanners, and begins the main
        consumption loop. Blocks until worker is stopped.

        Raises:
            RuntimeError: If initialization fails or critical components unavailable
        """
        try:
            logger.info("Starting S3ScanWorker...")

            # Initialize Redis and stream consumer
            self.redis_client = await redis.from_url(
                self.config.redis_url, decode_responses=True
            )
            await self.redis_client.ping()
            logger.info(f"Connected to Redis: {self.config.redis_url}")

            self.stream_consumer = StreamConsumer(
                redis_url=self.config.redis_url,
                prefix=self.config.redis_prefix,
                group=self.config.consumer_group,
                consumer_name=self.config.consumer_name,
            )
            await self.stream_consumer.connect()

            self.result_publisher = ResultPublisher(
                redis_client=self.redis_client, prefix=self.config.redis_prefix
            )

            # Initialize TI enricher
            self.ti_enricher = TIEnricher(
                vt_api_key=self.config.virustotal_api_key,
                otx_api_key=self.config.otx_api_key,
            )
            await self.ti_enricher.__aenter__()

            # Initialize scanners in thread pool (blocking initialization)
            await asyncio.get_event_loop().run_in_executor(
                self.executor, self._init_scanners
            )

            # Initialize S3 downloader
            self.downloader = S3Downloader(temp_dir="/tmp/s3-scan")

            self.running = True
            logger.info("S3ScanWorker started successfully")

            # Run consumption loop
            await self._consume_loop()

        except Exception as e:
            logger.error(f"Fatal error starting worker: {e}", exc_info=True)
            await self.stop()
            raise

    async def stop(self) -> None:
        """Stop the worker and clean up resources.

        Closes all connections, shuts down thread pool, and stops
        the consumption loop.
        """
        logger.info("Stopping S3ScanWorker...")
        self.running = False

        # Close stream consumer
        if self.stream_consumer:
            await self.stream_consumer.close()

        # Close Redis client
        if self.redis_client:
            await self.redis_client.close()

        # Close TI enricher
        if self.ti_enricher:
            await self.ti_enricher.__aexit__(None, None, None)

        # Shutdown thread pool
        self.executor.shutdown(wait=True)

        logger.info("S3ScanWorker stopped")

    async def _consume_loop(self) -> None:
        """Main consumption loop for Redis Streams.

        Continuously consumes scan task messages from Redis Streams,
        processes them with the task semaphore to limit concurrency,
        and handles graceful shutdown.

        Raises:
            RuntimeError: If stream consumer not initialized
        """
        if not self.stream_consumer:
            raise RuntimeError("Stream consumer not initialized")

        logger.info("Starting consumption loop...")

        try:
            async for msg_id, msg_data in self.stream_consumer.consume(
                stream=":tasks", count=1, block=5000
            ):
                if not self.running:
                    break

                try:
                    # Parse and validate task message
                    task = ScanTaskMessage(**msg_data)

                    # Process with semaphore to limit concurrency
                    async with self.task_semaphore:
                        logger.debug(
                            f"Processing task {task.task_id}: {task.object_key}"
                        )
                        await self._process_task(msg_id, task)

                    # Acknowledge message
                    await self.stream_consumer.ack(stream=":tasks", message_id=msg_id)

                except Exception as e:
                    logger.error(
                        f"Error processing message {msg_id}: {e}", exc_info=True
                    )
                    # Still acknowledge to avoid reprocessing
                    await self.stream_consumer.ack(stream=":tasks", message_id=msg_id)

        except Exception as e:
            logger.error(f"Fatal error in consumption loop: {e}", exc_info=True)
            raise

    async def _process_task(self, msg_id: str, task: ScanTaskMessage) -> None:
        """Process a single scan task through the complete pipeline.

        Orchestrates the scanning pipeline:
        1. Download file from S3 (async)
        2. Detect file type (sync, thread pool)
        3. Compute hashes (sync, thread pool)
        4. Scan with ClamAV (sync, thread pool)
        5. Optional YARA scan (sync, thread pool)
        6. TI enrichment (async)
        7. Apply S3 tags (async)
        8. Publish result (async)
        9. Cleanup temp file

        Args:
            msg_id: Redis stream message ID
            task: ScanTaskMessage with task details

        Returns:
            None (publishes result via ResultPublisher)
        """
        start_time = time.time()
        temp_file_path: Optional[str] = None
        scan_result = {
            "task_id": task.task_id,
            "job_id": task.job_id,
            "object_key": task.object_key,
            "scan_status": "failed",
            "is_malware": False,
            "is_pup": False,
            "is_threat": False,
            "detected_file_type": "unknown",
            "threat_names": [],
            "file_md5": "",
            "file_sha1": "",
            "file_sha256": "",
            "clamav_result": None,
            "yara_matches": None,
            "ti_enrichment": None,
            "tags_applied": [],
            "error_message": None,
        }

        try:
            # 1. Download file from S3 (async)
            logger.debug(f"Downloading {task.object_key} from {task.bucket_name}")
            s3_client = S3Client(
                endpoint_url=task.endpoint_url,
                access_key=task.access_key,
                secret_key=task.secret_key,
                region=task.region,
                use_ssl=task.use_ssl,
                path_style=task.path_style,
            )

            temp_file_path = await self.downloader.download_object(
                s3_client=s3_client,
                bucket=task.bucket_name,
                key=task.object_key,
                max_size_mb=self.config.max_file_size_mb,
            )

            if not temp_file_path:
                raise RuntimeError(
                    f"Failed to download {task.object_key} or file exceeds size limit"
                )

            logger.debug(f"Downloaded to {temp_file_path}")

            # 2. Detect file type (sync, thread pool)
            logger.debug("Detecting file type...")
            mime_type = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                self.file_detector.detect,
                temp_file_path,
            )
            scan_result["detected_file_type"] = mime_type
            logger.debug(f"Detected MIME type: {mime_type}")

            # 3. Compute hashes (sync, thread pool)
            logger.debug("Computing file hashes...")
            hashes = await asyncio.get_event_loop().run_in_executor(
                self.executor,
                FileHasher.compute_all,
                temp_file_path,
            )
            scan_result["file_md5"] = hashes.get("md5", "")
            scan_result["file_sha1"] = hashes.get("sha1", "")
            scan_result["file_sha256"] = hashes.get("sha256", "")
            logger.debug(f"Hashes computed: SHA256={hashes.get('sha256', '')[:16]}...")

            # 4. Scan with ClamAV (sync, thread pool)
            logger.debug("Scanning with ClamAV...")
            try:
                clamav_result = await asyncio.get_event_loop().run_in_executor(
                    self.executor,
                    self.clamav_scanner.scan_file,
                    temp_file_path,
                )
                scan_result["is_malware"] = clamav_result.is_malware
                scan_result["is_pup"] = clamav_result.is_pup
                scan_result["threat_names"].extend(clamav_result.threat_names)
                scan_result["clamav_result"] = {
                    "is_malware": clamav_result.is_malware,
                    "is_pup": clamav_result.is_pup,
                    "threats": clamav_result.threat_names,
                }
                logger.debug(
                    f"ClamAV: malware={clamav_result.is_malware}, "
                    f"pup={clamav_result.is_pup}, "
                    f"threats={len(clamav_result.threat_names)}"
                )
            except Exception as e:
                logger.warning(f"ClamAV scan failed: {e}")

            # 5. Optional YARA scan (sync, thread pool)
            if task.yara_enabled and self.yara_scanner:
                logger.debug("Scanning with YARA...")
                try:
                    yara_matches = await asyncio.get_event_loop().run_in_executor(
                        self.executor,
                        self.yara_scanner.scan_file,
                        temp_file_path,
                    )

                    if yara_matches:
                        scan_result["yara_matches"] = [
                            {
                                "rule_name": match.rule_name,
                                "namespace": match.namespace,
                                "tags": match.tags,
                                "matched_strings_count": len(match.matched_strings),
                            }
                            for match in yara_matches
                        ]
                        # Add YARA rule names to threat names
                        for match in yara_matches:
                            if match.rule_name not in scan_result["threat_names"]:
                                scan_result["threat_names"].append(match.rule_name)
                        logger.debug(f"YARA: {len(yara_matches)} rule(s) matched")
                except Exception as e:
                    logger.warning(f"YARA scan failed: {e}")

            # 6. TI enrichment (async)
            if self.config.ti_enabled:
                logger.debug("Enriching with threat intelligence...")
                try:
                    ti_result = await self.ti_enricher.enrich(
                        sha256=scan_result["file_sha256"],
                        md5=scan_result["file_md5"],
                        threat_names=scan_result["threat_names"],
                    )
                    scan_result["ti_enrichment"] = ti_result
                    logger.debug(
                        f"TI enrichment: vt_score={ti_result.get('vt_score')}, "
                        f"severity={ti_result.get('severity')}"
                    )
                except Exception as e:
                    logger.warning(f"TI enrichment failed: {e}")

            # 7. Apply S3 tags (async)
            logger.debug("Applying S3 tags...")
            try:
                async with s3_client.session.client("s3") as s3:
                    tagger = S3Tagger(s3_client.session)

                    # Calculate overall threat status
                    is_threat = scan_result["is_malware"] or scan_result["is_pup"]
                    scan_result["is_threat"] = is_threat

                    tags_applied = await tagger.apply_scan_tags(
                        bucket=task.bucket_name,
                        key=task.object_key,
                        is_malware=scan_result["is_malware"],
                        is_pup=scan_result["is_pup"],
                        file_type=mime_type,
                        scan_time=int(time.time() * 1000),
                    )

                    if tags_applied:
                        scan_result["tags_applied"] = [
                            f"malware={str(scan_result['is_malware']).lower()}",
                            f"pup={str(scan_result['is_pup']).lower()}",
                            f"threat={('malware' if scan_result['is_malware'] else 'pup' if scan_result['is_pup'] else 'clean')}",
                        ]
                        logger.debug(f"Tags applied: {scan_result['tags_applied']}")
                    else:
                        logger.warning("Failed to apply S3 tags")

            except Exception as e:
                logger.warning(f"Failed to apply tags: {e}")

            # 8. Publish result (async)
            scan_result["scan_status"] = "completed"
            scan_result["scan_duration_ms"] = int((time.time() - start_time) * 1000)

            logger.debug(f"Publishing result for {task.task_id}...")
            result_message = ScanResultMessage(**scan_result)
            result_dict = result_message.dict()
            await self.result_publisher.publish_result(result_dict)

            if scan_result["is_threat"]:
                await self.result_publisher.publish_threat_detected(
                    job_id=task.job_id,
                    object_key=task.object_key,
                    threat_names=scan_result["threat_names"],
                )

            logger.info(
                f"Task {task.task_id} completed: "
                f"malware={scan_result['is_malware']}, "
                f"pup={scan_result['is_pup']}, "
                f"duration={scan_result['scan_duration_ms']}ms"
            )

        except Exception as e:
            logger.error(
                f"Error processing task {task.task_id}: {e}", exc_info=True
            )
            scan_result["scan_status"] = "failed"
            scan_result["error_message"] = str(e)
            scan_result["scan_duration_ms"] = int((time.time() - start_time) * 1000)

            try:
                result_message = ScanResultMessage(**scan_result)
                result_dict = result_message.dict()
                await self.result_publisher.publish_result(result_dict)
            except Exception as pub_error:
                logger.error(f"Failed to publish error result: {pub_error}")

        finally:
            # 9. Cleanup temp file
            if temp_file_path:
                try:
                    if self.downloader:
                        self.downloader.cleanup(temp_file_path)
                    logger.debug(f"Cleaned up temp file: {temp_file_path}")
                except Exception as e:
                    logger.warning(f"Failed to cleanup temp file: {e}")

    def _init_scanners(self) -> None:
        """Initialize scanner instances (blocking, runs in thread pool).

        Initializes file type detector, ClamAV scanner, and optionally
        YARA scanner. Called in thread pool to avoid blocking event loop.

        Raises:
            RuntimeError: If critical scanners fail to initialize
        """
        try:
            # Initialize file type detector
            self.file_detector = FileTypeDetector()
            logger.info("FileTypeDetector initialized")

            # Initialize ClamAV scanner
            try:
                self.clamav_scanner = ClamAVScanner(
                    socket_path=self.config.clamd_socket,
                    timeout=self.config.clamd_timeout,
                )
                # Test connectivity
                if self.clamav_scanner.ping():
                    logger.info(f"ClamAV scanner initialized: {self.config.clamd_socket}")
                else:
                    raise RuntimeError("ClamAV daemon not responding to ping")
            except Exception as e:
                logger.error(f"Failed to initialize ClamAV: {e}")
                raise

            # Initialize YARA scanner (optional)
            if self.config.yara_enabled:
                try:
                    self.yara_scanner = YaraScanner(
                        rules_path=self.config.yara_rules_path
                    )
                    logger.info(
                        f"YARA scanner initialized: {self.config.yara_rules_path}"
                    )
                except Exception as e:
                    logger.warning(f"Failed to initialize YARA scanner: {e}")
                    self.yara_scanner = None

        except Exception as e:
            logger.error(f"Scanner initialization failed: {e}", exc_info=True)
            raise
