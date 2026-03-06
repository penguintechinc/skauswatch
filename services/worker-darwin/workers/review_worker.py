"""Review Processing Worker — processes queued code reviews via Celery."""

import asyncio
import logging
import traceback
from datetime import datetime, timezone
from typing import Any

from celery import Task

from workers.celery_app import celery_app
from database.models import get_configured_db
from scanners.ai_provider import create_provider
from scanners.review_engine import ReviewEngine

logger = logging.getLogger(__name__)


class ReviewWorkerTask(Task):
    """Custom task class with retry logic and error handling."""

    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 3}
    retry_backoff = True
    retry_backoff_max = 240
    retry_jitter = True


@celery_app.task(bind=True, base=ReviewWorkerTask, name="workers.review_worker.process_review")
def process_review(self: Task, review_id: int) -> dict[str, Any]:
    """Process a queued code review.

    Args:
        review_id: Database review ID

    Returns:
        dict with status and metrics
    """
    db = get_configured_db()
    try:
        review = db(db.darwin_reviews.id == review_id).select().first()
        if not review:
            return {"status": "error", "message": f"Review {review_id} not found"}

        if review.status != "pending":
            return {"status": "skipped", "message": f"Review {review_id} already processed"}

        # Mark in progress
        db(db.darwin_reviews.id == review_id).update(status="processing")
        db.commit()

        repo = db(db.darwin_repo_configs.id == review.repo_config_id).select().first()
        if not repo:
            db(db.darwin_reviews.id == review_id).update(status="failed")
            db.commit()
            return {"status": "failed", "message": "Repo config not found"}

        cred = (
            db(db.darwin_git_credentials.tenant_id == repo.tenant_id)
            .select()
            .first()
        )
        if not cred:
            db(db.darwin_reviews.id == review_id).update(status="failed")
            db.commit()
            return {"status": "failed", "message": "No credentials configured"}

        result = asyncio.run(_execute_review(db, review, repo, cred))

        db(db.darwin_reviews.id == review_id).update(
            status="completed",
            completed_at=datetime.now(timezone.utc),
            summary=result.get("summary", ""),
        )
        db.commit()

        return {
            "status": "completed",
            "review_id": review_id,
            "comments_posted": result.get("comments_posted", 0),
        }

    except Exception as exc:
        logger.error("Review %d failed: %s\n%s", review_id, exc, traceback.format_exc())
        try:
            db(db.darwin_reviews.id == review_id).update(status="failed")
            db.commit()
        except Exception:
            pass
        raise

    finally:
        db.close()


async def _execute_review(
    db: Any,
    review: Any,
    repo: Any,
    cred: Any,
) -> dict[str, Any]:
    """Execute the review using ReviewEngine.

    Args:
        db: PyDAL connection
        review: darwin_reviews record
        repo: darwin_repo_configs record
        cred: darwin_git_credentials record

    Returns:
        dict with summary and comments_posted count
    """
    from config.settings import settings

    engine = ReviewEngine()
    ai_provider = None

    provider_name = review.ai_provider or settings.ai.provider
    try:
        ai_provider = create_provider(provider_name)
    except Exception as exc:
        logger.warning("Could not create AI provider %s: %s", provider_name, exc)

    # For now, we submit a minimal differential review with no files
    # (actual PR file fetching requires git integration which is a follow-on)
    result = await engine.review_pr(
        platform=repo.provider,
        repository=repo.repo_name,
        pr_files=[],
        config={"categories": ["security", "best_practices"]},
        ai_provider=ai_provider,
        review_id=review.id,
    )

    # Persist comments
    comments_posted = 0
    for comment in result.comments:
        db.darwin_review_comments.insert(
            review_id=review.id,
            file_path=comment.file_path,
            line_number=comment.line_start,
            comment=f"**{comment.title}**\n\n{comment.body}",
            severity=comment.severity,
            created_at=datetime.now(timezone.utc),
        )
        comments_posted += 1

    db.commit()

    return {
        "summary": f"Reviewed {result.files_reviewed} files, {comments_posted} comments",
        "comments_posted": comments_posted,
    }
