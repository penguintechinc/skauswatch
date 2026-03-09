"""Celery application configuration for worker-scanner.

This module configures the Celery application instance with appropriate
settings for distributed task processing, including broker configuration,
serialization, timeouts, and scheduled tasks.
"""

import os

from celery import Celery
from celery.schedules import crontab

# Read configuration from environment variables
CELERY_BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0")
CELERY_RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", "redis://redis:6379/1")

# Create Celery application instance
celery_app = Celery(
    "worker-scanner",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND,
    include=["workers.scan_worker", "workers.scheduler_worker"],
)

# Configure Celery settings
celery_app.conf.update(
    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    # Timezone
    timezone="UTC",
    enable_utc=True,
    # Task tracking and reliability
    task_track_started=True,
    task_acks_late=True,  # Acknowledge after execution for reliability
    # Worker performance settings
    worker_prefetch_multiplier=1,  # One task at a time for resource-intensive scans
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks to prevent memory leaks
    # Task time limits (2 hours soft, 2h 10m hard)
    task_soft_time_limit=7200,  # 2 hours in seconds
    task_time_limit=7800,  # 2 hours 10 minutes in seconds
    # Result expiration (24 hours)
    result_expires=86400,  # 24 hours in seconds
)

# Configure Celery Beat schedule for periodic tasks
celery_app.conf.beat_schedule = {
    "check-schedules": {
        "task": "workers.scheduler_worker.process_due_schedules",
        "schedule": 60.0,  # Run every 60 seconds
        "options": {
            "expires": 55.0,  # Expire if not executed within 55 seconds
        },
    },
}

# Auto-discover tasks from workers package
celery_app.autodiscover_tasks(["workers"])
