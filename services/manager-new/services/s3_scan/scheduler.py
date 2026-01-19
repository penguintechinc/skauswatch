"""
S3 Scan Scheduler

Manages scheduled scanning of S3 buckets using cron expressions.
Handles creation, updating, and execution of scheduled scans.
"""

from typing import Dict, Optional
from datetime import datetime, timezone
import logging
from croniter import croniter
import pytz

logger = logging.getLogger(__name__)


class ScanScheduler:
    """Manages scheduled S3 bucket scans"""

    def __init__(self, db, job_manager):
        """
        Initialize the scan scheduler

        Args:
            db: PyDAL database instance
            job_manager: ScanJobManager instance for creating scan jobs
        """
        self.db = db
        self.job_manager = job_manager

    async def set_schedule(
        self,
        bucket_config_id: int,
        cron_expression: str,
        timezone_str: str = 'UTC',
        enabled: bool = True
    ) -> dict:
        """
        Set or update a scan schedule for a bucket configuration

        Args:
            bucket_config_id: ID of the bucket configuration
            cron_expression: Cron expression (e.g., "0 2 * * *" for daily at 2 AM)
            timezone_str: Timezone string (e.g., "UTC", "America/New_York")
            enabled: Whether the schedule is enabled

        Returns:
            Dictionary containing the schedule data
        """
        try:
            # Validate cron expression
            if not croniter.is_valid(cron_expression):
                raise ValueError(f"Invalid cron expression: {cron_expression}")

            # Validate timezone
            try:
                tz = pytz.timezone(timezone_str)
            except pytz.exceptions.UnknownTimeZoneError:
                raise ValueError(f"Invalid timezone: {timezone_str}")

            # Calculate next run time
            next_run_at = self._calculate_next_run(cron_expression, timezone_str)

            # Check if schedule already exists
            existing = self.db(
                self.db.s3_scan_schedules.bucket_config_id == bucket_config_id
            ).select().first()

            if existing:
                # Update existing schedule
                self.db(
                    self.db.s3_scan_schedules.bucket_config_id == bucket_config_id
                ).update(
                    cron_expression=cron_expression,
                    timezone=timezone_str,
                    enabled=enabled,
                    next_run_at=next_run_at,
                    updated_at=datetime.utcnow()
                )
                schedule_id = existing.id
                logger.info(f"Updated scan schedule {schedule_id} for bucket config {bucket_config_id}")
            else:
                # Create new schedule
                schedule_id = self.db.s3_scan_schedules.insert(
                    bucket_config_id=bucket_config_id,
                    cron_expression=cron_expression,
                    timezone=timezone_str,
                    enabled=enabled,
                    next_run_at=next_run_at,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                logger.info(f"Created scan schedule {schedule_id} for bucket config {bucket_config_id}")

            self.db.commit()

            # Fetch and return the schedule
            schedule = self.db(
                self.db.s3_scan_schedules.id == schedule_id
            ).select().first()

            return schedule.as_dict()

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error setting schedule for bucket config {bucket_config_id}: {str(e)}")
            raise

    async def get_schedule(self, bucket_config_id: int) -> Optional[dict]:
        """
        Get the scan schedule for a bucket configuration

        Args:
            bucket_config_id: ID of the bucket configuration

        Returns:
            Dictionary containing schedule data, or None if not found
        """
        try:
            schedule = self.db(
                self.db.s3_scan_schedules.bucket_config_id == bucket_config_id
            ).select().first()

            if not schedule:
                return None

            return schedule.as_dict()

        except Exception as e:
            logger.error(f"Error fetching schedule for bucket config {bucket_config_id}: {str(e)}")
            raise

    async def delete_schedule(self, bucket_config_id: int) -> bool:
        """
        Delete a scan schedule

        Args:
            bucket_config_id: ID of the bucket configuration

        Returns:
            True if deleted, False if not found
        """
        try:
            deleted = self.db(
                self.db.s3_scan_schedules.bucket_config_id == bucket_config_id
            ).delete()

            self.db.commit()

            if deleted:
                logger.info(f"Deleted scan schedule for bucket config {bucket_config_id}")
                return True
            else:
                logger.warning(f"No schedule found for bucket config {bucket_config_id}")
                return False

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error deleting schedule for bucket config {bucket_config_id}: {str(e)}")
            raise

    async def check_and_run_due_schedules(self) -> int:
        """
        Check for schedules that are due to run and start scan jobs for them

        Returns:
            Number of jobs started
        """
        try:
            current_time = datetime.utcnow()

            # Find schedules that are due
            query = (
                (self.db.s3_scan_schedules.enabled == True) &
                (self.db.s3_scan_schedules.next_run_at <= current_time)
            )

            due_schedules = self.db(query).select()

            jobs_started = 0

            for schedule in due_schedules:
                try:
                    # Get bucket configuration
                    bucket_config = self.db(
                        self.db.s3_bucket_configs.id == schedule.bucket_config_id
                    ).select().first()

                    if not bucket_config:
                        logger.warning(
                            f"Bucket config {schedule.bucket_config_id} not found "
                            f"for schedule {schedule.id}"
                        )
                        continue

                    # Create and start scan job
                    job = await self.job_manager.create_job(
                        bucket_config_id=schedule.bucket_config_id,
                        scan_type='scheduled',
                        scan_options={
                            'schedule_id': schedule.id,
                            'cron_expression': schedule.cron_expression
                        }
                    )

                    logger.info(
                        f"Started scheduled scan job {job['job_id']} "
                        f"for bucket config {schedule.bucket_config_id}"
                    )

                    jobs_started += 1

                    # Update schedule
                    last_run_at = current_time
                    next_run_at = self._calculate_next_run(
                        schedule.cron_expression,
                        schedule.timezone,
                        from_time=current_time
                    )

                    self.db(self.db.s3_scan_schedules.id == schedule.id).update(
                        last_run_at=last_run_at,
                        next_run_at=next_run_at,
                        last_job_id=job['job_id'],
                        updated_at=current_time
                    )

                except Exception as schedule_error:
                    logger.error(
                        f"Error processing schedule {schedule.id}: {str(schedule_error)}"
                    )
                    continue

            self.db.commit()

            logger.info(f"Started {jobs_started} scheduled scan jobs")

            return jobs_started

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error checking and running due schedules: {str(e)}")
            raise

    def _calculate_next_run(
        self,
        cron_expression: str,
        timezone_str: str,
        from_time: datetime = None
    ) -> datetime:
        """
        Calculate the next run time for a cron expression

        Args:
            cron_expression: Cron expression
            timezone_str: Timezone string
            from_time: Calculate from this time (defaults to now)

        Returns:
            Next run time as a UTC datetime
        """
        try:
            # Get timezone
            tz = pytz.timezone(timezone_str)

            # Use provided time or current time
            if from_time:
                base_time = from_time
            else:
                base_time = datetime.utcnow()

            # Convert to target timezone
            base_time_tz = tz.localize(
                base_time.replace(tzinfo=None)
            ) if base_time.tzinfo is None else base_time.astimezone(tz)

            # Calculate next run
            cron = croniter(cron_expression, base_time_tz)
            next_run_tz = cron.get_next(datetime)

            # Convert back to UTC
            next_run_utc = next_run_tz.astimezone(pytz.UTC).replace(tzinfo=None)

            return next_run_utc

        except Exception as e:
            logger.error(
                f"Error calculating next run for cron '{cron_expression}' "
                f"in timezone '{timezone_str}': {str(e)}"
            )
            raise

    async def list_schedules(
        self,
        enabled_only: bool = False
    ) -> list:
        """
        List all scan schedules

        Args:
            enabled_only: If True, only return enabled schedules

        Returns:
            List of schedule dictionaries
        """
        try:
            if enabled_only:
                query = self.db.s3_scan_schedules.enabled == True
            else:
                query = self.db.s3_scan_schedules.id > 0

            schedules = self.db(query).select(
                orderby=self.db.s3_scan_schedules.next_run_at
            )

            return [schedule.as_dict() for schedule in schedules]

        except Exception as e:
            logger.error(f"Error listing schedules: {str(e)}")
            raise

    async def pause_schedule(self, bucket_config_id: int) -> bool:
        """
        Pause a schedule (set enabled=False)

        Args:
            bucket_config_id: ID of the bucket configuration

        Returns:
            True if paused, False if not found
        """
        try:
            updated = self.db(
                self.db.s3_scan_schedules.bucket_config_id == bucket_config_id
            ).update(
                enabled=False,
                updated_at=datetime.utcnow()
            )

            self.db.commit()

            if updated:
                logger.info(f"Paused schedule for bucket config {bucket_config_id}")
                return True
            else:
                logger.warning(f"No schedule found for bucket config {bucket_config_id}")
                return False

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error pausing schedule for bucket config {bucket_config_id}: {str(e)}")
            raise

    async def resume_schedule(self, bucket_config_id: int) -> bool:
        """
        Resume a paused schedule (set enabled=True)

        Args:
            bucket_config_id: ID of the bucket configuration

        Returns:
            True if resumed, False if not found
        """
        try:
            # Get the schedule
            schedule = self.db(
                self.db.s3_scan_schedules.bucket_config_id == bucket_config_id
            ).select().first()

            if not schedule:
                logger.warning(f"No schedule found for bucket config {bucket_config_id}")
                return False

            # Recalculate next run time
            next_run_at = self._calculate_next_run(
                schedule.cron_expression,
                schedule.timezone
            )

            # Update schedule
            self.db(
                self.db.s3_scan_schedules.bucket_config_id == bucket_config_id
            ).update(
                enabled=True,
                next_run_at=next_run_at,
                updated_at=datetime.utcnow()
            )

            self.db.commit()

            logger.info(f"Resumed schedule for bucket config {bucket_config_id}")
            return True

        except Exception as e:
            self.db.rollback()
            logger.error(f"Error resuming schedule for bucket config {bucket_config_id}: {str(e)}")
            raise

    async def get_next_runs(self, limit: int = 10) -> list:
        """
        Get the next scheduled runs

        Args:
            limit: Maximum number of schedules to return

        Returns:
            List of schedule dictionaries with bucket configuration details
        """
        try:
            schedules = self.db(
                self.db.s3_scan_schedules.enabled == True
            ).select(
                orderby=self.db.s3_scan_schedules.next_run_at,
                limitby=(0, limit)
            )

            results = []

            for schedule in schedules:
                # Get bucket configuration
                bucket_config = self.db(
                    self.db.s3_bucket_configs.id == schedule.bucket_config_id
                ).select().first()

                schedule_dict = schedule.as_dict()

                if bucket_config:
                    schedule_dict['bucket_name'] = bucket_config.bucket_name
                    schedule_dict['endpoint'] = bucket_config.endpoint

                results.append(schedule_dict)

            return results

        except Exception as e:
            logger.error(f"Error getting next runs: {str(e)}")
            raise
