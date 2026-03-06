#!/usr/bin/env python3
"""Celery Worker Entrypoint for Darwin Background Processing."""

from app import create_app

# Create Flask app
app = create_app()

# Get Celery instance from app
celery = app.celery

if __name__ == "__main__":
    # This is for direct execution (not typical for Celery workers)
    # Workers are usually started with: celery -A celery_worker.celery worker
    print("Use 'celery -A celery_worker.celery worker' to start the worker")
