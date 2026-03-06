"""Celery Configuration and Factory."""

import os
from celery import Celery
from celery.schedules import crontab


def make_celery(app=None):
    """
    Create and configure Celery instance with Flask app context.

    Args:
        app: Flask application instance (optional)

    Returns:
        Celery instance configured for Darwin
    """
    # Get Redis URL from environment
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    broker_url = os.getenv("CELERY_BROKER_URL", redis_url)
    result_backend = os.getenv("CELERY_RESULT_BACKEND", redis_url)

    # Create Celery instance
    celery = Celery(
        "darwin",
        broker=broker_url,
        backend=result_backend,
        include=[
            "app.tasks.review_worker",
            "app.tasks.poll_worker",
        ],
    )

    # Configure Celery
    celery.conf.update(
        # Task serialization
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,

        # Task routing
        task_routes={
            "app.tasks.review_worker.*": {"queue": "reviews"},
            "app.tasks.poll_worker.*": {"queue": "polling"},
        },

        # Task execution
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        worker_prefetch_multiplier=1,

        # Result backend
        result_expires=3600,  # 1 hour
        result_extended=True,

        # Beat schedule for periodic tasks
        beat_schedule={
            "poll-repositories": {
                "task": "app.tasks.poll_worker.poll_repositories",
                "schedule": crontab(
                    minute=f"*/{os.getenv('DEFAULT_POLLING_INTERVAL_MINUTES', '5')}"
                ),
            },
        },
    )

    # Integrate with Flask app context if provided
    if app:
        class ContextTask(celery.Task):
            """Custom task class that runs within Flask app context."""

            def __call__(self, *args, **kwargs):
                with app.app_context():
                    return self.run(*args, **kwargs)

        celery.Task = ContextTask

    return celery
