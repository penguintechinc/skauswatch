"""
Comment publisher module for posting reviews to GitHub and GitLab.

Formats and publishes code review comments to GitHub/GitLab with severity
badges, code suggestions, and summary information. Handles batching to
respect platform rate limits.
"""

from dataclasses import dataclass, field
from datetime import datetime
import asyncio
import logging
from typing import Optional

from ..integrations.github import GitHubClient, GitHubRateLimitError
from ..integrations.gitlab import GitLabClient, GitLabRateLimitError

logger = logging.getLogger(__name__)

# Severity badge emojis for visual distinction
SEVERITY_BADGES = {
    "critical": "🔴",
    "major": "🟠",
    "minor": "🟡",
    "suggestion": "💡",
}

# Severity to GitHub review event mapping
SEVERITY_TO_EVENT = {
    "critical": "REQUEST_CHANGES",
    "major": "REQUEST_CHANGES",
    "minor": "COMMENT",
    "suggestion": "COMMENT",
}


@dataclass(slots=True)
class ReviewComment:
    """Represents a single review comment to be published."""

    file_path: str
    line_start: int
    line_end: int
    category: str  # security, best_practices, framework, iac
    severity: str  # critical, major, minor, suggestion
    title: str
    body: str
    suggestion: Optional[str] = None
    source: str = ""
    linter_rule_id: Optional[str] = None


@dataclass(slots=True)
class PublishResult:
    """Result of publishing a review."""

    success: bool
    platform: str
    pr_id: str
    total_comments: int
    published_comments: int
    failed_comments: int
    errors: list[str] = field(default_factory=list)
    comment_ids: list[str] = field(default_factory=list)
    published_at: Optional[datetime] = None


class CommentPublisher:
    """Publisher for posting code review comments to GitHub/GitLab."""

    # Batch size to avoid rate limiting (GitHub: 30 req/min, GitLab: 600 req/min)
    GITHUB_BATCH_SIZE = 10
    GITLAB_BATCH_SIZE = 20
    RATE_LIMIT_DELAY = 2.0  # seconds between batches

    def __init__(self):
        """Initialize the comment publisher."""
        self._github_client: Optional[GitHubClient] = None
        self._gitlab_client: Optional[GitLabClient] = None

    def set_github_client(self, client: GitHubClient) -> None:
        """Set the GitHub client for publishing."""
        self._github_client = client

    def set_gitlab_client(self, client: GitLabClient) -> None:
        """Set the GitLab client for publishing."""
        self._gitlab_client = client

    async def publish_review(
        self,
        platform: str,
        repo: str,
        pr_id: str,
        comments: list[ReviewComment],
        summary: Optional[str] = None,
    ) -> PublishResult:
        """
        Publish a review with comments to the appropriate platform.

        Args:
            platform: "github" or "gitlab"
            repo: Repository identifier (owner/repo for GitHub, project_id for GitLab)
            pr_id: Pull request/merge request ID
            comments: List of ReviewComment objects
            summary: Optional summary comment to post

        Returns:
            PublishResult with details about the publication
        """
        if not comments:
            return PublishResult(
                success=True,
                platform=platform,
                pr_id=pr_id,
                total_comments=0,
                published_comments=0,
                failed_comments=0,
                published_at=datetime.utcnow(),
            )

        result = PublishResult(
            success=True,
            platform=platform,
            pr_id=pr_id,
            total_comments=len(comments),
            published_comments=0,
            failed_comments=0,
        )

        try:
            if platform == "github":
                result = await self._publish_to_github(
                    repo, pr_id, comments, summary, result
                )
            elif platform == "gitlab":
                result = await self._publish_to_gitlab(
                    repo, pr_id, comments, summary, result
                )
            else:
                result.success = False
                result.errors.append(f"Unknown platform: {platform}")

            result.published_at = datetime.utcnow()
            return result

        except Exception as e:
            logger.error(f"Error publishing review: {str(e)}")
            result.success = False
            result.errors.append(str(e))
            result.published_at = datetime.utcnow()
            return result

    async def _publish_to_github(
        self,
        repo: str,
        pr_id: str,
        comments: list[ReviewComment],
        summary: Optional[str],
        result: PublishResult,
    ) -> PublishResult:
        """
        Publish comments to GitHub.

        Args:
            repo: owner/repo format
            pr_id: Pull request number
            comments: List of ReviewComment objects
            summary: Optional summary comment
            result: PublishResult to update

        Returns:
            Updated PublishResult
        """
        if not self._github_client:
            result.errors.append("GitHub client not initialized")
            result.success = False
            return result

        try:
            owner, repo_name = repo.split("/", 1)
            pr_number = int(pr_id)

            # Get PR details
            pr = await self._github_client.get_pull_request(owner, repo_name, pr_number)

            # Format and batch comments
            github_comments = []
            for comment in comments:
                formatted = self._format_github_comment(comment)
                github_comments.append(formatted)

            # Publish comments in batches
            batch_size = self.GITHUB_BATCH_SIZE
            for i in range(0, len(github_comments), batch_size):
                batch = github_comments[i : i + batch_size]

                try:
                    for comment_data in batch:
                        comment_result = await self._github_client.create_review_comment(
                            owner=owner,
                            repo=repo_name,
                            pr_number=pr_number,
                            body=comment_data["body"],
                            commit_id=pr.head_sha,
                            path=comment_data["path"],
                            line=comment_data["line"],
                        )
                        result.published_comments += 1
                        result.comment_ids.append(str(comment_result.get("id", "")))

                    # Rate limit delay between batches
                    if i + batch_size < len(github_comments):
                        await asyncio.sleep(self.RATE_LIMIT_DELAY)

                except GitHubRateLimitError as e:
                    logger.warning(f"GitHub rate limit hit: {str(e)}")
                    result.failed_comments += len(batch)
                    result.errors.append(f"Rate limit exceeded: {str(e)}")
                except Exception as e:
                    logger.error(f"Error publishing GitHub batch: {str(e)}")
                    result.failed_comments += len(batch)
                    result.errors.append(str(e))

            # Post summary if provided
            if summary:
                try:
                    summary_body = self._create_summary(comments, summary)
                    await self._github_client.create_review_comment(
                        owner=owner,
                        repo=repo_name,
                        pr_number=pr_number,
                        body=summary_body,
                        commit_id=pr.head_sha,
                        path=comments[0].file_path if comments else "",
                        line=comments[0].line_start if comments else 1,
                    )
                except Exception as e:
                    logger.error(f"Error publishing GitHub summary: {str(e)}")
                    result.errors.append(f"Summary failed: {str(e)}")

            result.success = result.failed_comments == 0
            return result

        except Exception as e:
            logger.error(f"Error in GitHub publish: {str(e)}")
            result.errors.append(str(e))
            result.success = False
            return result

    async def _publish_to_gitlab(
        self,
        repo: str,
        mr_id: str,
        comments: list[ReviewComment],
        summary: Optional[str],
        result: PublishResult,
    ) -> PublishResult:
        """
        Publish comments to GitLab.

        Args:
            repo: Project ID or path
            mr_id: Merge request internal ID
            comments: List of ReviewComment objects
            summary: Optional summary comment
            result: PublishResult to update

        Returns:
            Updated PublishResult
        """
        if not self._gitlab_client:
            result.errors.append("GitLab client not initialized")
            result.success = False
            return result

        try:
            mr_iid = int(mr_id)

            # Get MR details for diff refs
            mr = await self._gitlab_client.get_merge_request(repo, mr_iid)

            # Format and batch comments
            gitlab_comments = []
            for comment in comments:
                formatted = self._format_gitlab_comment(comment, mr)
                gitlab_comments.append(formatted)

            # Publish comments in batches
            batch_size = self.GITLAB_BATCH_SIZE
            for i in range(0, len(gitlab_comments), batch_size):
                batch = gitlab_comments[i : i + batch_size]

                try:
                    for comment_data in batch:
                        # GitLab uses discussions for line-specific comments
                        if comment_data.get("position"):
                            discussion_result = (
                                await self._gitlab_client.create_mr_discussion(
                                    repo,
                                    mr_iid,
                                    comment_data["body"],
                                    comment_data["position"],
                                )
                            )
                            result.published_comments += 1
                            result.comment_ids.append(
                                str(discussion_result.get("id", ""))
                            )
                        else:
                            # Fall back to general note if position missing
                            note_result = await self._gitlab_client.create_mr_note(
                                repo, mr_iid, comment_data["body"]
                            )
                            result.published_comments += 1
                            result.comment_ids.append(str(note_result.get("id", "")))

                    # Rate limit delay between batches
                    if i + batch_size < len(gitlab_comments):
                        await asyncio.sleep(self.RATE_LIMIT_DELAY)

                except GitLabRateLimitError as e:
                    logger.warning(f"GitLab rate limit hit: {str(e)}")
                    result.failed_comments += len(batch)
                    result.errors.append(f"Rate limit exceeded: {str(e)}")
                except Exception as e:
                    logger.error(f"Error publishing GitLab batch: {str(e)}")
                    result.failed_comments += len(batch)
                    result.errors.append(str(e))

            # Post summary if provided
            if summary:
                try:
                    summary_body = self._create_summary(comments, summary)
                    await self._gitlab_client.create_mr_note(
                        repo, mr_iid, summary_body
                    )
                except Exception as e:
                    logger.error(f"Error publishing GitLab summary: {str(e)}")
                    result.errors.append(f"Summary failed: {str(e)}")

            result.success = result.failed_comments == 0
            return result

        except Exception as e:
            logger.error(f"Error in GitLab publish: {str(e)}")
            result.errors.append(str(e))
            result.success = False
            return result

    def _format_github_comment(self, comment: ReviewComment) -> dict:
        """
        Format a ReviewComment for GitHub.

        Args:
            comment: ReviewComment to format

        Returns:
            Dict with body, path, and line for GitHub API
        """
        body = self._format_comment_body(comment, "github")

        return {
            "body": body,
            "path": comment.file_path,
            "line": comment.line_start,
        }

    def _format_gitlab_comment(
        self, comment: ReviewComment, mr: object
    ) -> dict:
        """
        Format a ReviewComment for GitLab.

        Args:
            comment: ReviewComment to format
            mr: Merge request object with diff_refs

        Returns:
            Dict with body and position for GitLab API
        """
        body = self._format_comment_body(comment, "gitlab")

        # Build position object for line-specific comment
        position = None
        if hasattr(mr, "diff_refs") and mr.diff_refs:
            position = {
                "base_sha": mr.diff_refs.get("base_sha", ""),
                "head_sha": mr.diff_refs.get("head_sha", ""),
                "start_sha": mr.diff_refs.get("start_sha", ""),
                "position_type": "text",
                "new_path": comment.file_path,
                "new_line": comment.line_start,
            }

        return {"body": body, "position": position}

    def _format_comment_body(self, comment: ReviewComment, platform: str) -> str:
        """
        Format comment body with severity badge, title, and details.

        Args:
            comment: ReviewComment to format
            platform: "github" or "gitlab"

        Returns:
            Formatted comment body string
        """
        badge = SEVERITY_BADGES.get(comment.severity, "")
        parts = []

        # Header with severity and title
        parts.append(f"{badge} **{comment.title}**")

        # Category and severity info
        parts.append(
            f"**Category:** {comment.category.title()} | "
            f"**Severity:** {comment.severity.upper()}"
        )

        # Main body
        if comment.body:
            parts.append("")
            parts.append(comment.body)

        # Code suggestion if available
        if comment.suggestion:
            parts.append("")
            parts.append("**Suggestion:**")
            parts.append("")
            if platform == "github":
                parts.append("```")
                parts.append(comment.suggestion)
                parts.append("```")
            else:  # gitlab
                parts.append("```")
                parts.append(comment.suggestion)
                parts.append("```")

        # Source and rule ID
        if comment.source or comment.linter_rule_id:
            parts.append("")
            parts.append("---")
            if comment.source:
                parts.append(f"**Source:** {comment.source}")
            if comment.linter_rule_id:
                parts.append(f"**Rule ID:** {comment.linter_rule_id}")

        return "\n".join(parts)

    def _create_summary(
        self, comments: list[ReviewComment], summary_text: str
    ) -> str:
        """
        Create a summary comment with statistics and details.

        Args:
            comments: List of ReviewComment objects
            summary_text: Summary text to include

        Returns:
            Formatted summary comment body
        """
        # Count by severity
        severity_counts = {
            "critical": 0,
            "major": 0,
            "minor": 0,
            "suggestion": 0,
        }
        category_counts = {}

        for comment in comments:
            severity_counts[comment.severity] = severity_counts.get(
                comment.severity, 0
            ) + 1
            category_counts[comment.category] = category_counts.get(
                comment.category, 0
            ) + 1

        # Build summary
        parts = [
            "## Code Review Summary",
            "",
            summary_text,
            "",
            "### Issues Found",
            "",
        ]

        # Severity breakdown
        if any(severity_counts.values()):
            parts.append("**By Severity:**")
            for severity, count in severity_counts.items():
                if count > 0:
                    badge = SEVERITY_BADGES.get(severity, "")
                    parts.append(f"- {badge} {severity.capitalize()}: {count}")
            parts.append("")

        # Category breakdown
        if category_counts:
            parts.append("**By Category:**")
            for category in sorted(category_counts.keys()):
                count = category_counts[category]
                parts.append(f"- {category.replace('_', ' ').title()}: {count}")
            parts.append("")

        # Statistics
        total = len(comments)
        critical = severity_counts.get("critical", 0)
        major = severity_counts.get("major", 0)
        blocking = critical + major

        parts.append("### Statistics")
        parts.append(f"- **Total Issues:** {total}")
        parts.append(f"- **Blocking Issues:** {blocking}")
        if total > 0:
            parts.append(f"- **Review Coverage:** {total} file(s) reviewed")

        return "\n".join(parts)
