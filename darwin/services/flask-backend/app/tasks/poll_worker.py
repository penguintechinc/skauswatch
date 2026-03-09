"""Repository Polling Worker - Check for new/updated PRs and MRs."""

import asyncio
from datetime import datetime
from typing import Any

from ..celery_config import make_celery
from ..models import (
    get_db,
    get_repo_config,
    get_credential_by_id,
    create_review,
    get_review_by_external_id,
)
from ..integrations.github import GitHubClient, GitHubConfig
from ..integrations.gitlab import GitLabClient, GitLabConfig
from .review_worker import process_review


# Create Celery instance
celery = make_celery()


@celery.task(name="app.tasks.poll_worker.poll_repositories")
def poll_repositories() -> dict[str, Any]:
    """
    Beat schedule task to poll all enabled repositories.

    Queries database for repositories with polling_enabled=True
    and queues individual poll tasks for each.

    Returns:
        dict with count of repositories queued for polling
    """
    db = get_db()

    # Query enabled repositories with polling enabled
    query = (db.repo_configs.enabled == True) & (db.repo_configs.polling_enabled == True)  # noqa: E712
    repos = db(query).select()

    queued_count = 0
    for repo in repos:
        # Queue individual poll task
        poll_repository.delay(repo.id)
        queued_count += 1

    return {
        "status": "completed",
        "repositories_queued": queued_count,
        "timestamp": datetime.utcnow().isoformat(),
    }


@celery.task(name="app.tasks.poll_worker.poll_repository")
def poll_repository(repo_id: int) -> dict[str, Any]:
    """
    Poll a single repository for new/updated PRs or MRs.

    Args:
        repo_id: Repository configuration ID

    Returns:
        dict with status and reviews created count
    """
    try:
        # Get repository configuration
        repo_config = _get_repo_config_by_id(repo_id)
        if not repo_config:
            return {"status": "error", "message": f"Repository {repo_id} not found"}

        if not repo_config.get("enabled") or not repo_config.get("polling_enabled"):
            return {"status": "skipped", "message": "Repository polling disabled"}

        # Get credentials
        credential_id = repo_config.get("credential_id")
        if not credential_id:
            return {"status": "error", "message": "No credentials configured"}

        credential = get_credential_by_id(credential_id)
        if not credential:
            return {"status": "error", "message": "Credential not found"}

        # Poll based on platform
        platform = repo_config["platform"]
        repository = repo_config["repository"]

        if platform == "github":
            result = asyncio.run(_poll_github(repository, credential, repo_config))
        elif platform == "gitlab":
            result = asyncio.run(_poll_gitlab(repository, credential, repo_config))
        else:
            return {"status": "error", "message": f"Unsupported platform: {platform}"}

        # Update last_poll_at timestamp
        db = get_db()
        db(db.repo_configs.id == repo_id).update(last_poll_at=datetime.utcnow())
        db.commit()

        return result

    except Exception as e:
        return {"status": "error", "message": str(e)}


async def _poll_github(
    repository: str,
    credential: dict[str, Any],
    repo_config: dict[str, Any],
) -> dict[str, Any]:
    """
    Poll GitHub repository for open pull requests.

    Args:
        repository: Repository in "owner/repo" format
        credential: GitHub credentials
        repo_config: Repository configuration

    Returns:
        dict with reviews_created count
    """
    config = GitHubConfig(token=credential["token"])
    owner, repo = repository.split("/")

    async with GitHubClient(config) as client:
        # Fetch open pull requests
        prs = await client.list_pull_requests(owner, repo, state="open")

        reviews_created = 0
        for pr in prs:
            pr_id = pr.get("id")
            pr_number = pr.get("number")
            head_sha = pr.get("head", {}).get("sha")
            base_sha = pr.get("base", {}).get("sha")

            if not all([pr_id, pr_number, head_sha, base_sha]):
                continue

            # Check if we've already reviewed this SHA
            external_id = f"github-{pr_id}-{head_sha}"
            existing_review = get_review_by_external_id(external_id)

            if existing_review:
                # Already reviewed this commit
                continue

            # Create new review
            review = create_review(
                external_id=external_id,
                platform="github",
                repository=repository,
                pull_request_id=pr_number,
                pull_request_url=pr.get("html_url"),
                base_sha=base_sha,
                head_sha=head_sha,
                review_type="differential",
                categories=repo_config.get("default_categories", ["security", "best_practices"]),
                ai_provider=repo_config.get("default_ai_provider", "ollama"),
            )

            # Queue for processing
            process_review.delay(review["id"])
            reviews_created += 1

        return {
            "status": "completed",
            "prs_checked": len(prs),
            "reviews_created": reviews_created,
        }


async def _poll_gitlab(
    project_id: str,
    credential: dict[str, Any],
    repo_config: dict[str, Any],
) -> dict[str, Any]:
    """
    Poll GitLab project for open merge requests.

    Args:
        project_id: GitLab project ID
        credential: GitLab credentials
        repo_config: Repository configuration

    Returns:
        dict with reviews_created count
    """
    config = GitLabConfig(
        token=credential["token"],
        base_url=credential.get("base_url", "https://gitlab.com")
    )

    async with GitLabClient(config) as client:
        # Fetch open merge requests
        mrs = await client.list_merge_requests(project_id, state="opened")

        reviews_created = 0
        for mr in mrs:
            mr_id = mr.get("id")
            mr_iid = mr.get("iid")
            head_sha = mr.get("sha")
            base_sha = mr.get("diff_refs", {}).get("base_sha")

            if not all([mr_id, mr_iid, head_sha, base_sha]):
                continue

            # Check if we've already reviewed this SHA
            external_id = f"gitlab-{mr_id}-{head_sha}"
            existing_review = get_review_by_external_id(external_id)

            if existing_review:
                # Already reviewed this commit
                continue

            # Create new review
            review = create_review(
                external_id=external_id,
                platform="gitlab",
                repository=project_id,
                pull_request_id=mr_iid,
                pull_request_url=mr.get("web_url"),
                base_sha=base_sha,
                head_sha=head_sha,
                review_type="differential",
                categories=repo_config.get("default_categories", ["security", "best_practices"]),
                ai_provider=repo_config.get("default_ai_provider", "ollama"),
            )

            # Queue for processing
            process_review.delay(review["id"])
            reviews_created += 1

        return {
            "status": "completed",
            "mrs_checked": len(mrs),
            "reviews_created": reviews_created,
        }


def _get_repo_config_by_id(repo_id: int) -> dict[str, Any] | None:
    """Get repository configuration by ID."""
    db = get_db()
    repo = db(db.repo_configs.id == repo_id).select().first()
    return repo.as_dict() if repo else None
