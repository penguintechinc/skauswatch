"""Issue Plan Worker — generates AI-powered issue implementation plans."""

import logging
import traceback
from typing import Any

from celery import Task
from database.models import get_configured_db
from scanners.ai_provider import create_provider
from workers.celery_app import celery_app

logger = logging.getLogger(__name__)


class PlanWorkerTask(Task):
    """Custom task class with retry logic."""

    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 3}
    retry_backoff = True
    retry_backoff_max = 240
    retry_jitter = True


@celery_app.task(
    bind=True, base=PlanWorkerTask, name="workers.plan_worker.generate_plan"
)
def generate_plan(self: Task, plan_id: int) -> dict[str, Any]:
    """Generate an AI implementation plan for a GitHub/GitLab issue.

    Args:
        plan_id: darwin_issue_plans record ID

    Returns:
        dict with status and plan content
    """
    from config.settings import settings

    db = get_configured_db()
    try:
        plan = db(db.darwin_issue_plans.id == plan_id).select().first()
        if not plan:
            return {"status": "error", "message": f"Plan {plan_id} not found"}

        if plan.status != "pending":
            return {"status": "skipped", "message": f"Plan {plan_id} already processed"}

        db(db.darwin_issue_plans.id == plan_id).update(status="processing")
        db.commit()

        repo = db(db.darwin_repo_configs.id == plan.repo_config_id).select().first()
        if not repo:
            db(db.darwin_issue_plans.id == plan_id).update(status="failed")
            db.commit()
            return {"status": "failed", "message": "Repo config not found"}

        # Build prompt
        prompt = (
            f"Generate a detailed implementation plan for issue #{plan.issue_number} "
            f"in repository {repo.repo_name}.\n\n"
            f"Issue URL: {plan.issue_url}\n\n"
            "Provide:\n"
            "1. High-level approach\n"
            "2. Step-by-step implementation steps\n"
            "3. Files likely to be modified\n"
            "4. Testing considerations\n"
            "5. Potential risks and mitigations\n"
        )

        import asyncio

        ai_provider = create_provider(settings.ai.provider)
        response = asyncio.run(ai_provider.complete(prompt=prompt))

        db(db.darwin_issue_plans.id == plan_id).update(
            status="completed",
            plan_content=response.content,
            ai_provider=settings.ai.provider,
        )
        db.commit()

        return {"status": "completed", "plan_id": plan_id}

    except Exception as exc:
        logger.error("Plan %d failed: %s\n%s", plan_id, exc, traceback.format_exc())
        try:
            db(db.darwin_issue_plans.id == plan_id).update(status="failed")
            db.commit()
        except Exception:
            pass
        raise

    finally:
        db.close()
