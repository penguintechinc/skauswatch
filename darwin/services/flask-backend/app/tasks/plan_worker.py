"""Plan Generation Worker - Process queued issue plan generation."""

import asyncio
import json
import logging
import traceback
from typing import Any
from celery import Task

from ..celery_config import make_celery
from ..models import (
    get_issue_plan_by_id,
    update_issue_plan_status,
    get_repo_config,
    get_credential_by_id,
    create_provider_usage,
)
from ..core.plan_generator import PlanGenerator
from ..integrations.github import GitHubClient, GitHubConfig
from ..integrations.gitlab import GitLabClient, GitLabConfig


# Create Celery instance
celery = make_celery()
logger = logging.getLogger(__name__)


class PlanWorkerTask(Task):
    """Custom task class with retry logic and error handling."""

    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 3}
    retry_backoff = True
    retry_backoff_max = 240  # 4 minutes max
    retry_jitter = True


@celery.task(bind=True, base=PlanWorkerTask, name="app.tasks.plan_worker.process_issue_plan")
def process_issue_plan(self, plan_id: int) -> dict[str, Any]:
    """
    Process a queued issue plan generation.

    Args:
        plan_id: Database issue plan ID

    Returns:
        dict with status and metrics

    Raises:
        Exception: On processing failure (triggers retry)
    """
    try:
        # Fetch issue plan from database
        plan = get_issue_plan_by_id(plan_id)
        if not plan:
            return {"status": "error", "message": f"Issue plan {plan_id} not found"}

        # Skip if already processed
        if plan["status"] != "queued":
            return {
                "status": "skipped",
                "message": f"Issue plan {plan_id} already processed (status: {plan['status']})"
            }

        # Update status to in_progress
        update_issue_plan_status(plan_id, "in_progress")

        # Get repository configuration
        repo_config = get_repo_config(plan["platform"], plan["repository"])
        if not repo_config:
            update_issue_plan_status(
                plan_id,
                "failed",
                error_message="Repository configuration not found",
            )
            return {"status": "failed", "message": "Repository configuration not found"}

        # Get credentials if needed
        credential_id = repo_config.get("credential_id")
        credential = None
        if credential_id:
            credential = get_credential_by_id(credential_id)
            if not credential:
                update_issue_plan_status(
                    plan_id,
                    "failed",
                    error_message="Credential not found",
                )
                return {"status": "failed", "message": "Credential not found"}

        # Run plan generation
        result = asyncio.run(_execute_plan_generation(plan, repo_config, credential))

        # Update plan status with results
        update_issue_plan_status(
            plan_id,
            "completed",
            plan_content=result["plan_content"],
            plan_steps=result["plan_steps"],
            comment_posted=result["comment_posted"],
            platform_comment_id=result.get("platform_comment_id"),
            token_usage=result.get("token_usage"),
        )

        return {
            "status": "completed",
            "plan_id": plan_id,
            "comment_posted": result["comment_posted"],
        }

    except Exception as e:
        # Log error and update status
        error_message = f"Plan generation failed: {str(e)}\n{traceback.format_exc()}"
        logger.error(error_message)
        update_issue_plan_status(plan_id, "failed", error_message=error_message)

        # Reraise for Celery retry mechanism
        raise


async def _execute_plan_generation(
    plan: dict[str, Any],
    repo_config: dict[str, Any],
    credential: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Execute plan generation and post comment to issue.

    Args:
        plan: Issue plan record from database
        repo_config: Repository configuration
        credential: Decrypted credential or None

    Returns:
        dict with plan_content, plan_steps, comment_posted, platform_comment_id, token_usage
    """
    try:
        # Initialize PlanGenerator with configured AI provider
        ai_provider = plan.get("ai_provider", "claude")
        ai_model = plan.get("ai_model")

        logger.info(f"Initializing PlanGenerator with provider={ai_provider}, model={ai_model}")
        generator = PlanGenerator(ai_provider=ai_provider, ai_model=ai_model)

        # Generate implementation plan
        logger.info(f"Generating plan for issue: {plan['issue_title']}")
        implementation_plan = await generator.generate_plan(
            issue_title=plan["issue_title"],
            issue_body=plan["issue_body"],
            repository=plan["repository"],
            review_id=plan.get("id"),
        )

        # Format plan as markdown
        plan_markdown = generator.format_plan_as_markdown(implementation_plan)

        # Prepare plan steps as JSON
        plan_steps_json = json.dumps(implementation_plan.steps)

        # Post comment to platform if credential available and auto_comment enabled
        comment_posted = False
        platform_comment_id = None
        token_usage = None

        if credential and repo_config.get("auto_comment_on_plan", True):
            platform = plan["platform"]

            try:
                if platform == "github":
                    comment_result = await _post_github_comment(
                        credential, plan, plan_markdown
                    )
                    if comment_result:
                        comment_posted = True
                        platform_comment_id = str(comment_result.get("id"))

                elif platform == "gitlab":
                    comment_result = await _post_gitlab_comment(
                        credential, plan, plan_markdown
                    )
                    if comment_result:
                        comment_posted = True
                        platform_comment_id = str(comment_result.get("id"))

            except Exception as e:
                logger.warning(f"Failed to post comment to platform: {e}")
                # Don't fail the entire task if comment posting fails

        return {
            "plan_content": plan_markdown,
            "plan_steps": plan_steps_json,
            "comment_posted": comment_posted,
            "platform_comment_id": platform_comment_id,
            "token_usage": token_usage,
        }

    except Exception as e:
        logger.error(f"Plan generation execution failed: {e}")
        raise


async def _post_github_comment(
    credential: dict[str, Any],
    plan: dict[str, Any],
    plan_markdown: str,
) -> dict[str, Any] | None:
    """
    Post plan comment to GitHub issue.

    Args:
        credential: GitHub credential with token
        plan: Issue plan data
        plan_markdown: Formatted plan markdown

    Returns:
        Comment data with ID or None if failed
    """
    try:
        config = GitHubConfig(token=credential["token"])
        async with GitHubClient(config) as client:
            owner, repo = plan["repository"].split("/")
            issue_number = plan["issue_number"]

            logger.info(f"Posting plan comment to GitHub issue {owner}/{repo}#{issue_number}")

            comment_result = await client.create_issue_comment(
                owner=owner,
                repo=repo,
                issue_number=issue_number,
                body=plan_markdown,
            )

            return comment_result

    except Exception as e:
        logger.error(f"Failed to post comment to GitHub: {e}")
        raise


async def _post_gitlab_comment(
    credential: dict[str, Any],
    plan: dict[str, Any],
    plan_markdown: str,
) -> dict[str, Any] | None:
    """
    Post plan comment to GitLab issue.

    Args:
        credential: GitLab credential with token
        plan: Issue plan data
        plan_markdown: Formatted plan markdown

    Returns:
        Note data with ID or None if failed
    """
    try:
        config = GitLabConfig(
            token=credential["token"],
            base_url=credential.get("base_url", "https://gitlab.com")
        )
        async with GitLabClient(config) as client:
            project_id = plan["repository"]
            issue_iid = plan["issue_number"]

            logger.info(f"Posting plan comment to GitLab issue {project_id}#{issue_iid}")

            comment_result = await client.create_issue_note(
                project_id=project_id,
                issue_iid=issue_iid,
                body=plan_markdown,
            )

            return comment_result

    except Exception as e:
        logger.error(f"Failed to post comment to GitLab: {e}")
        raise
