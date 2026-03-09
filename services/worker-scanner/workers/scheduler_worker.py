"""Celery beat task for processing due scan schedules.

This module implements the periodic scheduler worker that checks for scan schedules
whose next_run time has passed and creates corresponding scan jobs. It is invoked
by Celery Beat every 60 seconds as configured in celery_app.py.

The scheduler:
- Queries for enabled schedules where next_run <= current time
- Creates scan jobs for each due schedule
- Dispatches Celery tasks to execute the scans
- Calculates and updates the next run time using cron expressions
- Handles errors gracefully to avoid stopping processing of other schedules
"""

from datetime import datetime
from typing import Any

from croniter import croniter
from database.models import get_configured_db
from utils.logger import get_logger
from workers.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="workers.scheduler_worker.process_due_schedules")
def process_due_schedules() -> dict[str, Any]:
    """Process all scan schedules that are due to run.

    This task is invoked periodically by Celery Beat to check for schedules
    whose next_run time has passed. For each due schedule, it:
    1. Creates a new scan job
    2. Dispatches a Celery task to execute the scan
    3. Calculates the next run time using the cron expression
    4. Updates the schedule with last_run and next_run times

    Returns:
        dict: Processing results containing:
            - processed: Number of schedules processed
            - errors: Number of errors encountered
            - jobs_created: List of scan job IDs created

    Raises:
        Exception: Individual schedule errors are caught and logged but don't
                  stop processing of other schedules.
    """
    logger.info("Starting process_due_schedules task")

    processed_count = 0
    error_count = 0
    jobs_created = []

    try:
        # Get database connection
        db = get_configured_db()

        # Find all enabled schedules that are due to run
        current_time = datetime.utcnow()
        due_schedules = db(
            (db.scan_schedules.enabled == True)  # noqa: E712
            & (db.scan_schedules.next_run <= current_time)
        ).select()

        logger.info(f"Found {len(due_schedules)} due schedules to process")

        # Import scan_worker here to avoid circular imports
        from workers.scan_worker import execute_scan

        # Process each due schedule
        for schedule in due_schedules:
            try:
                logger.info(
                    f"Processing schedule {schedule.id} for target "
                    f"{schedule.target_id}, scanner: {schedule.scanner_type}"
                )

                # Create a new scan job
                job_id = db.scan_jobs.insert(
                    target_id=schedule.target_id,
                    scanner_type=schedule.scanner_type,
                    scan_type=schedule.scan_type,
                    status="pending",
                    priority=5,
                    config=schedule.config,
                    created_at=current_time,
                    created_by="scheduler",
                )
                db.commit()

                logger.info(f"Created scan job {job_id} for schedule {schedule.id}")
                jobs_created.append(job_id)

                # Dispatch Celery task to execute the scan
                execute_scan.delay(job_id)
                logger.info(f"Dispatched scan task for job {job_id}")

                # Calculate next run time using croniter
                try:
                    cron = croniter(schedule.cron_expression, current_time)
                    next_run = cron.get_next(datetime)
                    logger.info(
                        f"Schedule {schedule.id}: next_run calculated as {next_run}"
                    )
                except Exception as cron_error:
                    logger.error(
                        f"Error calculating next_run for schedule {schedule.id} "
                        f"with cron '{schedule.cron_expression}': {cron_error}"
                    )
                    # Default to 1 hour from now if cron parsing fails
                    from datetime import timedelta

                    next_run = current_time + timedelta(hours=1)
                    logger.warning(
                        f"Defaulting next_run to 1 hour from now: {next_run}"
                    )

                # Update schedule with last_run and next_run
                db(db.scan_schedules.id == schedule.id).update(
                    last_run=current_time, next_run=next_run
                )
                db.commit()

                logger.info(
                    f"Updated schedule {schedule.id}: last_run={current_time}, "
                    f"next_run={next_run}"
                )

                processed_count += 1

            except Exception as schedule_error:
                error_count += 1
                logger.error(
                    f"Error processing schedule {schedule.id}: {schedule_error}",
                    exc_info=True,
                )
                # Rollback this schedule's transaction but continue processing others
                db.rollback()
                continue

        logger.info(
            f"Completed process_due_schedules: processed={processed_count}, "
            f"errors={error_count}, jobs_created={len(jobs_created)}"
        )

    except Exception as global_error:
        logger.error(
            f"Critical error in process_due_schedules: {global_error}", exc_info=True
        )
        error_count += 1

    return {
        "processed": processed_count,
        "errors": error_count,
        "jobs_created": jobs_created,
    }


def recalculate_next_runs() -> int:
    """Recalculate next_run for all enabled schedules from current time.

    This utility function is useful after system restarts, clock changes, or
    when schedules need to be resynchronized. It iterates through all enabled
    schedules and recalculates their next_run time based on their cron expression
    and the current time.

    Returns:
        int: Number of schedules updated successfully

    Raises:
        Exception: Database or cron parsing errors are logged but don't stop
                  processing of other schedules.
    """
    logger.info("Starting recalculate_next_runs utility")

    updated_count = 0
    error_count = 0

    try:
        # Get database connection
        db = get_configured_db()

        # Find all enabled schedules
        current_time = datetime.utcnow()
        enabled_schedules = db(db.scan_schedules.enabled == True).select()  # noqa: E712

        logger.info(f"Found {len(enabled_schedules)} enabled schedules to recalculate")

        for schedule in enabled_schedules:
            try:
                # Calculate next run time using croniter
                cron = croniter(schedule.cron_expression, current_time)
                next_run = cron.get_next(datetime)

                # Update schedule with new next_run
                db(db.scan_schedules.id == schedule.id).update(next_run=next_run)
                db.commit()

                logger.info(f"Recalculated schedule {schedule.id}: next_run={next_run}")

                updated_count += 1

            except Exception as schedule_error:
                error_count += 1
                logger.error(
                    f"Error recalculating next_run for schedule {schedule.id}: "
                    f"{schedule_error}",
                    exc_info=True,
                )
                # Rollback this schedule's transaction but continue processing others
                db.rollback()
                continue

        logger.info(
            f"Completed recalculate_next_runs: updated={updated_count}, "
            f"errors={error_count}"
        )

    except Exception as global_error:
        logger.error(
            f"Critical error in recalculate_next_runs: {global_error}", exc_info=True
        )
        error_count += 1

    return updated_count


if __name__ == "__main__":
    # Allow manual testing of the scheduler worker
    print("Testing process_due_schedules...")
    result = process_due_schedules()
    print(f"Result: {result}")

    print("\nTesting recalculate_next_runs...")
    updated = recalculate_next_runs()
    print(f"Updated {updated} schedules")
