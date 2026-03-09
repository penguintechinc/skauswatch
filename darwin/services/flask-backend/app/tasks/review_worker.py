"""Review Processing Worker - Process queued code reviews."""

import asyncio
import traceback
from typing import Any
from celery import Task

from ..celery_config import make_celery
from ..models import (
    get_review_by_id,
    update_review_status,
    create_comment,
    get_repo_config,
    get_credential_by_id,
)
from ..core.reviewer import ReviewEngine, PRFile
from ..integrations.github import GitHubClient, GitHubConfig
from ..integrations.gitlab import GitLabClient, GitLabConfig
from ..providers import create_provider


# Create Celery instance
celery = make_celery()


class ReviewWorkerTask(Task):
    """Custom task class with retry logic and error handling."""

    autoretry_for = (Exception,)
    retry_kwargs = {"max_retries": 3}
    retry_backoff = True
    retry_backoff_max = 240  # 4 minutes max
    retry_jitter = True


@celery.task(bind=True, base=ReviewWorkerTask, name="app.tasks.review_worker.process_review")
def process_review(self, review_id: int) -> dict[str, Any]:
    """
    Process a queued code review.

    Args:
        review_id: Database review ID

    Returns:
        dict with status and metrics

    Raises:
        Exception: On processing failure (triggers retry)
    """
    try:
        # Fetch review from database
        review = get_review_by_id(review_id)
        if not review:
            return {"status": "error", "message": f"Review {review_id} not found"}

        # Skip if already processed
        if review["status"] != "queued":
            return {
                "status": "skipped",
                "message": f"Review {review_id} already processed (status: {review['status']})"
            }

        # Update status to in_progress
        update_review_status(review_id, "in_progress")

        # Get repository configuration
        repo_config = get_repo_config(review["platform"], review["repository"])
        if not repo_config:
            update_review_status(
                review_id,
                "failed",
                error_message="Repository configuration not found",
            )
            return {"status": "failed", "message": "Repository configuration not found"}

        # Get credentials
        credential_id = repo_config.get("credential_id")
        if not credential_id:
            update_review_status(
                review_id,
                "failed",
                error_message="No credentials configured for repository",
            )
            return {"status": "failed", "message": "No credentials configured"}

        credential = get_credential_by_id(credential_id)
        if not credential:
            update_review_status(
                review_id,
                "failed",
                error_message="Credential not found",
            )
            return {"status": "failed", "message": "Credential not found"}

        # Run review based on type
        result = asyncio.run(_execute_review(review, repo_config, credential))

        # Update review status with results
        update_review_status(
            review_id,
            "completed",
            files_reviewed=result["files_reviewed"],
            comments_posted=result["comments_posted"],
        )

        return {
            "status": "completed",
            "review_id": review_id,
            "files_reviewed": result["files_reviewed"],
            "comments_posted": result["comments_posted"],
        }

    except Exception as e:
        # Log error and update status
        error_message = f"Review processing failed: {str(e)}\n{traceback.format_exc()}"
        update_review_status(review_id, "failed", error_message=error_message)

        # Reraise for Celery retry mechanism
        raise


async def _execute_review(
    review: dict[str, Any],
    repo_config: dict[str, Any],
    credential: dict[str, Any],
) -> dict[str, Any]:
    """
    Execute the review using ReviewEngine and post comments.

    Args:
        review: Review record from database
        repo_config: Repository configuration
        credential: Decrypted credential

    Returns:
        dict with files_reviewed and comments_posted counts
    """
    # Initialize ReviewEngine
    engine = ReviewEngine()

    # Create AI provider
    ai_provider = None
    ai_provider_type = review.get("ai_provider")
    if ai_provider_type:
        ai_provider = create_provider(ai_provider_type)

    # Get platform client and execute review
    platform = review["platform"]

    if platform == "github":
        config = GitHubConfig(token=credential["token"])
        async with GitHubClient(config) as client:
            owner, repo = review["repository"].split("/")
            pr_number = review["pull_request_id"]

            # Fetch PR files
            pr_data = await client.get_pull_request(owner, repo, pr_number)
            pr_files_data = await client.get_pull_request_files(owner, repo, pr_number)

            # Convert to PRFile objects
            pr_files = [
                PRFile(
                    path=f.filename,
                    status=f.status,
                    additions=f.additions,
                    deletions=f.deletions,
                    patch=f.patch or "",
                    old_path=None,
                )
                for f in pr_files_data
            ]

            # Execute review
            review_config = {
                "categories": review.get("categories", ["security", "best_practices"]),
            }
            review_result = await engine.review_pr(
                platform=platform,
                repository=review["repository"],
                pr_files=pr_files,
                config=review_config,
                ai_provider=ai_provider,
                review_id=review["id"],
            )

            # Store comments in database
            comments_posted = 0
            for comment in review_result.comments:
                create_comment(
                    review_id=review["id"],
                    file_path=comment.file_path,
                    line_start=comment.line_start,
                    line_end=comment.line_end,
                    category=comment.category,
                    severity=comment.severity,
                    title=comment.title,
                    body=comment.body,
                    review_source=comment.source,
                    suggestion=comment.suggestion,
                    linter_rule_id=comment.linter_rule_id,
                )
                comments_posted += 1

            # Post comments to platform
            if repo_config.get("auto_review", True):
                for comment in review_result.comments:
                    try:
                        # Format body with GitHub's native suggestion format
                        body = f"**{comment.title}**\n\n{comment.body}"

                        # Add GitHub suggested change if available
                        if comment.suggestion:
                            body += f"\n\n```suggestion\n{comment.suggestion}\n```"

                        await client.create_review_comment(
                            owner=owner,
                            repo=repo,
                            pr_number=pr_number,
                            commit_sha=review["head_sha"],
                            path=comment.file_path,
                            line=comment.line_end,
                            body=body,
                        )
                    except Exception as e:
                        print(f"Failed to post comment to GitHub: {e}")

    elif platform == "gitlab":
        config = GitLabConfig(
            token=credential["token"],
            base_url=credential.get("base_url", "https://gitlab.com")
        )
        async with GitLabClient(config) as client:
            project_id = review["repository"]
            mr_number = review["pull_request_id"]

            # Fetch MR files
            mr_data = await client.get_merge_request(project_id, mr_number)
            mr_changes = await client.get_mr_changes(project_id, mr_number)

            # Convert to PRFile objects
            pr_files = []
            for file_data in mr_changes:
                pr_file = PRFile(
                    path=file_data.get("new_path") or file_data.get("path"),
                    status=file_data.get("status", "modified"),
                    additions=file_data.get("additions", 0),
                    deletions=file_data.get("deletions", 0),
                    patch=file_data.get("patch", ""),
                    old_path=file_data.get("old_path"),
                )
                pr_files.append(pr_file)

            # Execute review
            review_config = {
                "categories": review.get("categories", ["security", "best_practices"]),
            }
            review_result = await engine.review_pr(
                platform=platform,
                repository=review["repository"],
                pr_files=pr_files,
                config=review_config,
                ai_provider=ai_provider,
                review_id=review["id"],
            )

            # Store comments in database
            comments_posted = 0
            for comment in review_result.comments:
                create_comment(
                    review_id=review["id"],
                    file_path=comment.file_path,
                    line_start=comment.line_start,
                    line_end=comment.line_end,
                    category=comment.category,
                    severity=comment.severity,
                    title=comment.title,
                    body=comment.body,
                    review_source=comment.source,
                    suggestion=comment.suggestion,
                    linter_rule_id=comment.linter_rule_id,
                )
                comments_posted += 1

            # Post comments to platform
            if repo_config.get("auto_review", True):
                for comment in review_result.comments:
                    try:
                        # Format body with GitLab's native suggestion format
                        body = f"**{comment.title}**\n\n{comment.body}"

                        # Add GitLab suggested change if available
                        # GitLab uses ```suggestion:-X+Y syntax where X=lines to remove, Y=lines to add
                        if comment.suggestion:
                            # Calculate line range
                            lines_affected = comment.line_end - comment.line_start + 1
                            # Suggestion replaces the affected lines
                            body += f"\n\n```suggestion:-{lines_affected}+0\n{comment.suggestion}\n```"

                        await client.create_discussion(
                            project_id=project_id,
                            mr_number=mr_number,
                            body=body,
                            position={
                                "base_sha": review["base_sha"],
                                "start_sha": review["base_sha"],
                                "head_sha": review["head_sha"],
                                "new_path": comment.file_path,
                                "new_line": comment.line_end,
                            },
                        )
                    except Exception as e:
                        print(f"Failed to post comment to GitLab: {e}")
    else:
        raise ValueError(f"Unsupported platform: {platform}")

    return {
        "files_reviewed": review_result.files_reviewed,
        "comments_posted": comments_posted,
    }
