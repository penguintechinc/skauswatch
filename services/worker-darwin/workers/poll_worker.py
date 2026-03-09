"""Repository Polling Worker — periodic task to check for new PRs needing review."""

import logging
from typing import Any

from database.models import get_configured_db
from workers.celery_app import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="workers.poll_worker.poll_repositories")
def poll_repositories() -> dict[str, Any]:
    """Periodic task to poll active repositories for new PRs.

    Runs every 300 seconds via Celery Beat.
    For repos with auto_review=True, queues new reviews for unprocessed PRs.

    Returns:
        dict with polling summary
    """
    db = get_configured_db()
    try:
        active_repos = db(
            (db.darwin_repo_configs.is_active == True)  # noqa: E712
            & (db.darwin_repo_configs.auto_review == True)  # noqa: E712
        ).select()

        queued = 0
        errors = 0

        for repo in active_repos:
            try:
                _poll_repo(db, repo)
                queued += 1
            except Exception as exc:
                logger.warning("Failed to poll repo %s: %s", repo.repo_name, exc)
                errors += 1

        logger.info("Poll complete: %d repos checked, %d errors", queued, errors)
        return {"status": "completed", "repos_checked": queued, "errors": errors}

    finally:
        db.close()


def _poll_repo(db: Any, repo: Any) -> None:
    """Poll a single repository for new unreviewed PRs.

    In a full implementation this would call the GitHub/GitLab API.
    Currently a no-op placeholder — PR reviews are triggered via webhook.

    Args:
        db: PyDAL connection
        repo: darwin_repo_configs record
    """
    # Placeholder: real implementation would:
    # 1. Fetch open PRs from GitHub/GitLab API using stored credentials
    # 2. Check darwin_reviews for already-processed PR numbers
    # 3. Queue process_review for any unprocessed PRs
    logger.debug("Polling repo: %s (%s)", repo.repo_name, repo.provider)
