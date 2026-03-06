"""Celery application instance for worker-darwin.

Uses Redis DB 2 to avoid collision with worker-scanner (DB 1).
Queues: darwin_reviews, darwin_plans, darwin_polling
"""

from celery import Celery

from config.settings import settings


def make_celery() -> Celery:
    """Create and configure the Celery application instance.

    Returns:
        Celery: Configured Celery application
    """
    celery_app = Celery(
        "worker_darwin",
        broker=settings.redis.celery_broker_url,
        backend=settings.redis.celery_result_backend,
        include=[
            "workers.review_worker",
            "workers.plan_worker",
            "workers.poll_worker",
        ],
    )

    celery_app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_track_started=True,
        task_acks_late=True,
        worker_prefetch_multiplier=1,
        # Queue routing
        task_routes={
            "workers.review_worker.process_review": {"queue": "darwin_reviews"},
            "workers.plan_worker.generate_plan": {"queue": "darwin_plans"},
            "workers.poll_worker.poll_repositories": {"queue": "darwin_polling"},
        },
        # Beat schedule: poll repositories every 5 minutes
        beat_schedule={
            "poll-repositories": {
                "task": "workers.poll_worker.poll_repositories",
                "schedule": 300.0,
                "options": {"queue": "darwin_polling"},
            },
        },
    )

    return celery_app


# Module-level singleton
celery_app = make_celery()
