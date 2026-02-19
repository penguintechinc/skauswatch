"""
S3 Scan Job Manager.

Handles scan job lifecycle: creation, execution, progress tracking, completion.
"""

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from aiobotocore.session import get_session
from pydal import DAL

from services.streams.redis_streams import RedisStreamManager, S3ScanPublisher

from .bucket_manager import BucketConfigManager

logger = logging.getLogger(__name__)


class ScanJobManager:
    """
    Manages S3 scan job lifecycle.

    Features:
    - Create scan jobs with UUID
    - List objects from S3 and publish scan tasks to Redis streams
    - Track job progress (scanned, infected, pup, skipped, errors)
    - Cancel running jobs
    - Query job status and history
    """

    VALID_JOB_TYPES = ["full_scan", "incremental_scan", "prefix_scan"]
    VALID_STATUSES = ["pending", "running", "completed", "failed", "cancelled"]

    def __init__(
        self,
        db: DAL,
        stream_manager: RedisStreamManager,
        bucket_manager: BucketConfigManager,
    ):
        """
        Initialize the scan job manager.

        Args:
            db: PyDAL database instance
            stream_manager: Redis stream manager for publishing tasks
            bucket_manager: Bucket config manager for S3 access
        """
        self.db = db
        self.stream_manager = stream_manager
        self.bucket_manager = bucket_manager
        self.scan_publisher = S3ScanPublisher(stream_manager)

    async def create_scan_job(
        self,
        bucket_config_id: int,
        job_type: str,
        user_id: int,
        prefix_filter: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> Dict:
        """
        Create a new scan job.

        Args:
            bucket_config_id: S3 bucket configuration ID
            job_type: Type of scan (full_scan, incremental_scan, prefix_scan)
            user_id: User ID triggering the scan
            prefix_filter: Optional prefix filter (overrides bucket config)
            metadata: Optional metadata dict

        Returns:
            Created job record
        """
        # Validate job type
        if job_type not in self.VALID_JOB_TYPES:
            raise ValueError(
                f"Invalid job_type: {job_type}. Must be one of {self.VALID_JOB_TYPES}"
            )

        # Validate bucket config exists
        config = await self.bucket_manager.get_bucket_config(bucket_config_id)
        if not config:
            raise ValueError(f"Bucket config {bucket_config_id} not found")

        # Generate unique job ID
        job_id = str(uuid.uuid4())

        # Insert job record
        db_job_id = self.db.s3_scan_jobs.insert(
            job_id=job_id,
            bucket_config_id=bucket_config_id,
            job_type=job_type,
            status="pending",
            total_objects=0,
            scanned_objects=0,
            infected_objects=0,
            pup_objects=0,
            skipped_objects=0,
            error_count=0,
            triggered_by=user_id,
            metadata=metadata or {},
        )
        self.db.commit()

        logger.info(f"Created scan job {job_id} for bucket config {bucket_config_id}")

        # Get created record
        job = self.db(self.db.s3_scan_jobs.id == db_job_id).select().first()
        return job.as_dict()

    async def start_scan_job(self, job_id: str) -> bool:
        """
        Start a scan job by listing S3 objects and publishing scan tasks.

        Args:
            job_id: Job UUID

        Returns:
            True if started successfully, False otherwise
        """
        # Get job
        job = self.db(self.db.s3_scan_jobs.job_id == job_id).select().first()
        if not job:
            logger.error(f"Job {job_id} not found")
            return False

        if job.status != "pending":
            logger.error(
                f"Job {job_id} is not in pending state (current: {job.status})"
            )
            return False

        # Get bucket config with decrypted credentials
        config = await self.bucket_manager.get_bucket_config(job.bucket_config_id)
        if not config:
            logger.error(f"Bucket config {job.bucket_config_id} not found")
            await self.complete_job(
                job_id, error_message="Bucket configuration not found"
            )
            return False

        # Update job status to running
        self.db(self.db.s3_scan_jobs.job_id == job_id).update(
            status="running",
            started_at=datetime.utcnow(),
        )
        self.db.commit()

        logger.info(f"Starting scan job {job_id} for bucket {config['bucket_name']}")

        # List S3 objects and publish scan tasks
        try:
            total_objects = await self._list_and_publish_scan_tasks(job_id, config, job)

            # Update job with total object count
            self.db(self.db.s3_scan_jobs.job_id == job_id).update(
                total_objects=total_objects,
            )
            self.db.commit()

            logger.info(f"Published {total_objects} scan tasks for job {job_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to start scan job {job_id}: {e}", exc_info=True)
            await self.complete_job(job_id, error_message=str(e))
            return False

    async def _list_and_publish_scan_tasks(
        self,
        job_id: str,
        config: Dict,
        job: any,
    ) -> int:
        """
        List S3 objects and publish scan tasks to Redis stream.

        Args:
            job_id: Job UUID
            config: Bucket configuration with decrypted credentials
            job: Job database record

        Returns:
            Total number of objects published
        """
        session = get_session()
        total_objects = 0

        # Determine prefix filter
        prefix_filter = ""
        if (
            job.job_type == "prefix_scan"
            and job.metadata
            and "prefix_filter" in job.metadata
        ):
            prefix_filter = job.metadata["prefix_filter"]
        elif config.get("prefix_filter"):
            prefix_filter = config["prefix_filter"]

        async with session.create_client(
            "s3",
            endpoint_url=config["endpoint_url"],
            aws_access_key_id=config["access_key_id"],
            aws_secret_access_key=config["secret_access_key"],
            region_name=config.get("region"),
            use_ssl=config.get("use_ssl", True),
            config={
                "s3": {
                    "addressing_style": "path" if config.get("path_style") else "auto"
                }
            },
        ) as s3_client:
            # Paginate through all objects
            paginator = s3_client.get_paginator("list_objects_v2")

            async for page in paginator.paginate(
                Bucket=config["bucket_name"],
                Prefix=prefix_filter,
            ):
                if "Contents" not in page:
                    continue

                for obj in page["Contents"]:
                    object_key = obj["Key"]
                    object_size = obj.get("Size", 0)
                    object_etag = obj.get("ETag", "").strip('"')

                    # Check file size limit
                    max_size_bytes = config.get("max_file_size_mb", 100) * 1024 * 1024
                    if object_size > max_size_bytes:
                        logger.debug(
                            f"Skipping {object_key}: size {object_size} exceeds limit {max_size_bytes}"
                        )
                        await self.update_job_progress(job_id, skipped=1)
                        continue

                    # Check file type filter
                    file_types_filter = config.get("file_types_filter", [])
                    if file_types_filter:
                        extension = (
                            object_key.split(".")[-1].lower()
                            if "." in object_key
                            else ""
                        )
                        if extension not in file_types_filter:
                            logger.debug(
                                f"Skipping {object_key}: extension {extension} not in filter"
                            )
                            await self.update_job_progress(job_id, skipped=1)
                            continue

                    # Publish scan task
                    scan_task = {
                        "job_id": job_id,
                        "bucket_config_id": config["id"],
                        "object_key": object_key,
                        "object_size": object_size,
                        "object_etag": object_etag,
                        "scan_enabled": config.get("scan_enabled", True),
                        "yara_enabled": config.get("yara_enabled", False),
                    }

                    await self.scan_publisher.publish_scan_task(scan_task)
                    total_objects += 1

                    # Log progress every 100 objects
                    if total_objects % 100 == 0:
                        logger.info(
                            f"Job {job_id}: Published {total_objects} scan tasks"
                        )

        return total_objects

    async def get_job(self, job_id: str) -> Optional[Dict]:
        """
        Get a scan job by ID.

        Args:
            job_id: Job UUID

        Returns:
            Job record dict, or None if not found
        """
        job = self.db(self.db.s3_scan_jobs.job_id == job_id).select().first()
        if not job:
            return None
        return job.as_dict()

    async def list_jobs(
        self,
        bucket_config_id: Optional[int] = None,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> Tuple[List[Dict], int]:
        """
        List scan jobs with pagination and filters.

        Args:
            bucket_config_id: Optional filter by bucket config ID
            status: Optional filter by job status
            page: Page number (1-indexed)
            per_page: Items per page

        Returns:
            Tuple of (jobs list, total count)
        """
        # Build query
        query = self.db.s3_scan_jobs.id > 0

        if bucket_config_id is not None:
            query &= self.db.s3_scan_jobs.bucket_config_id == bucket_config_id

        if status is not None:
            if status not in self.VALID_STATUSES:
                raise ValueError(
                    f"Invalid status: {status}. Must be one of {self.VALID_STATUSES}"
                )
            query &= self.db.s3_scan_jobs.status == status

        # Get total count
        total = self.db(query).count()

        # Get paginated results
        offset = (page - 1) * per_page
        rows = self.db(query).select(
            orderby=~self.db.s3_scan_jobs.created_at,
            limitby=(offset, offset + per_page),
        )

        jobs = [row.as_dict() for row in rows]
        return jobs, total

    async def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a running or pending job.

        Args:
            job_id: Job UUID

        Returns:
            True if cancelled, False if not found or already completed
        """
        job = self.db(self.db.s3_scan_jobs.job_id == job_id).select().first()
        if not job:
            return False

        # Can only cancel pending or running jobs
        if job.status not in ["pending", "running"]:
            logger.warning(f"Cannot cancel job {job_id} with status {job.status}")
            return False

        # Update status
        self.db(self.db.s3_scan_jobs.job_id == job_id).update(
            status="cancelled",
            completed_at=datetime.utcnow(),
        )
        self.db.commit()

        logger.info(f"Cancelled scan job {job_id}")
        return True

    async def update_job_progress(
        self,
        job_id: str,
        scanned: Optional[int] = None,
        infected: Optional[int] = None,
        pup: Optional[int] = None,
        skipped: Optional[int] = None,
        errors: Optional[int] = None,
    ) -> None:
        """
        Update job progress counters.

        Args:
            job_id: Job UUID
            scanned: Increment scanned_objects count
            infected: Increment infected_objects count
            pup: Increment pup_objects count
            skipped: Increment skipped_objects count
            errors: Increment error_count
        """
        job = self.db(self.db.s3_scan_jobs.job_id == job_id).select().first()
        if not job:
            logger.warning(f"Job {job_id} not found for progress update")
            return

        # Build update dict
        update_fields = {}
        if scanned is not None:
            update_fields["scanned_objects"] = job.scanned_objects + scanned
        if infected is not None:
            update_fields["infected_objects"] = job.infected_objects + infected
        if pup is not None:
            update_fields["pup_objects"] = job.pup_objects + pup
        if skipped is not None:
            update_fields["skipped_objects"] = job.skipped_objects + skipped
        if errors is not None:
            update_fields["error_count"] = job.error_count + errors

        if update_fields:
            self.db(self.db.s3_scan_jobs.job_id == job_id).update(**update_fields)
            self.db.commit()

    async def complete_job(
        self,
        job_id: str,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Mark a job as completed or failed.

        Args:
            job_id: Job UUID
            error_message: Optional error message (marks job as failed)
        """
        job = self.db(self.db.s3_scan_jobs.job_id == job_id).select().first()
        if not job:
            logger.warning(f"Job {job_id} not found for completion")
            return

        # Determine final status
        if error_message:
            status = "failed"
        else:
            status = "completed"

        # Update job
        self.db(self.db.s3_scan_jobs.job_id == job_id).update(
            status=status,
            completed_at=datetime.utcnow(),
            error_message=error_message,
        )
        self.db.commit()

        logger.info(f"Job {job_id} marked as {status}")

    async def get_job_statistics(self, job_id: str) -> Optional[Dict]:
        """
        Get statistics for a scan job.

        Args:
            job_id: Job UUID

        Returns:
            Dict with statistics, or None if job not found
        """
        job = await self.get_job(job_id)
        if not job:
            return None

        # Calculate derived statistics
        total = job.get("total_objects", 0)
        scanned = job.get("scanned_objects", 0)
        infected = job.get("infected_objects", 0)
        pup = job.get("pup_objects", 0)
        skipped = job.get("skipped_objects", 0)
        errors = job.get("error_count", 0)

        progress_pct = (scanned / total * 100) if total > 0 else 0
        clean = scanned - infected - pup if scanned > 0 else 0

        # Calculate duration
        duration_seconds = None
        if job.get("started_at") and job.get("completed_at"):
            started = job["started_at"]
            completed = job["completed_at"]
            if isinstance(started, str):
                started = datetime.fromisoformat(started.replace("Z", "+00:00"))
            if isinstance(completed, str):
                completed = datetime.fromisoformat(completed.replace("Z", "+00:00"))
            duration_seconds = (completed - started).total_seconds()

        return {
            "job_id": job_id,
            "status": job.get("status"),
            "total_objects": total,
            "scanned_objects": scanned,
            "clean_objects": clean,
            "infected_objects": infected,
            "pup_objects": pup,
            "skipped_objects": skipped,
            "error_count": errors,
            "progress_percentage": round(progress_pct, 2),
            "duration_seconds": duration_seconds,
            "started_at": job.get("started_at"),
            "completed_at": job.get("completed_at"),
        }
