"""
GitLab API integration client.

Provides async methods for interacting with GitLab's REST API v4,
including merge requests, discussions, notes, and webhooks.
"""

from dataclasses import dataclass
from typing import Any
import logging
import httpx

logger = logging.getLogger(__name__)


class GitLabAPIError(Exception):
    """Base exception for GitLab API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        self.status_code = status_code
        super().__init__(message)


class GitLabRateLimitError(GitLabAPIError):
    """Exception raised when rate limit is exceeded."""

    pass


@dataclass(slots=True)
class GitLabConfig:
    """Configuration for GitLab API client."""

    token: str
    base_url: str = "https://gitlab.com"


@dataclass(slots=True)
class MergeRequest:
    """Represents a GitLab merge request."""

    iid: int
    title: str
    state: str
    source_branch: str
    target_branch: str
    sha: str
    web_url: str
    diff_refs: dict


@dataclass(slots=True)
class MRChange:
    """Represents a file change in a merge request."""

    old_path: str
    new_path: str
    diff: str
    new_file: bool
    renamed_file: bool
    deleted_file: bool


class GitLabClient:
    """Async client for GitLab API operations."""

    def __init__(self, config: GitLabConfig):
        """
        Initialize GitLab client.

        Args:
            config: GitLab configuration with token and base URL
        """
        self.config = config
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        """Context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=f"{self.config.base_url}/api/v4",
            headers={
                "PRIVATE-TOKEN": self.config.token,
                "User-Agent": "Darwin-AI-CodeReviewer",
            },
            timeout=30.0,
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self._client:
            await self._client.aclose()

    async def _request(
        self, method: str, path: str, **kwargs
    ) -> dict[str, Any] | list[Any]:
        """
        Make an authenticated request to GitLab API.

        Args:
            method: HTTP method
            path: API path
            **kwargs: Additional request parameters

        Returns:
            JSON response data

        Raises:
            GitLabAPIError: On API errors
            GitLabRateLimitError: On rate limit exceeded
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        try:
            response = await self._client.request(method, path, **kwargs)
            response.raise_for_status()

            # GitLab returns empty response for some endpoints
            if response.status_code == 204 or not response.content:
                return {}

            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise GitLabRateLimitError(
                    "GitLab API rate limit exceeded", e.response.status_code
                )
            logger.error(
                f"GitLab API error: {e.response.status_code} - {e.response.text}"
            )
            raise GitLabAPIError(
                f"GitLab API request failed: {e.response.status_code}",
                e.response.status_code,
            )
        except httpx.RequestError as e:
            logger.error(f"GitLab API request error: {str(e)}")
            raise GitLabAPIError(f"Request failed: {str(e)}")

    async def get_merge_request(self, project_id: str, mr_iid: int) -> MergeRequest:
        """
        Retrieve merge request details.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID

        Returns:
            MergeRequest object with MR details
        """
        data = await self._request(
            "GET", f"/projects/{project_id}/merge_requests/{mr_iid}"
        )
        return MergeRequest(
            iid=data["iid"],
            title=data["title"],
            state=data["state"],
            source_branch=data["source_branch"],
            target_branch=data["target_branch"],
            sha=data["sha"],
            web_url=data["web_url"],
            diff_refs=data.get("diff_refs", {}),
        )

    async def get_merge_request_changes(
        self, project_id: str, mr_iid: int
    ) -> list[MRChange]:
        """
        Get list of files changed in a merge request.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID

        Returns:
            List of MRChange objects representing changed files
        """
        data = await self._request(
            "GET", f"/projects/{project_id}/merge_requests/{mr_iid}/changes"
        )

        changes = []
        for change_data in data.get("changes", []):
            changes.append(
                MRChange(
                    old_path=change_data["old_path"],
                    new_path=change_data["new_path"],
                    diff=change_data["diff"],
                    new_file=change_data["new_file"],
                    renamed_file=change_data["renamed_file"],
                    deleted_file=change_data["deleted_file"],
                )
            )

        return changes

    async def get_file_content(self, project_id: str, path: str, ref: str) -> str:
        """
        Get file content at a specific ref.

        Args:
            project_id: Project ID or URL-encoded path
            path: File path
            ref: Git ref (branch, tag, or commit SHA)

        Returns:
            File content as string
        """
        import urllib.parse

        encoded_path = urllib.parse.quote(path, safe="")
        data = await self._request(
            "GET", f"/projects/{project_id}/repository/files/{encoded_path}/raw",
            params={"ref": ref}
        )

        # Raw endpoint returns text directly, not JSON
        if isinstance(data, str):
            return data
        return str(data)

    async def create_mr_note(self, project_id: str, mr_iid: int, body: str) -> dict:
        """
        Create a general note (comment) on a merge request.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID
            body: Comment text

        Returns:
            Created note data
        """
        payload = {"body": body}

        return await self._request(
            "POST", f"/projects/{project_id}/merge_requests/{mr_iid}/notes",
            json=payload
        )

    async def create_issue_note(self, project_id: str, issue_iid: int, body: str) -> dict:
        """
        Create a note (comment) on a GitLab issue.

        Args:
            project_id: Project ID or URL-encoded path
            issue_iid: Issue IID (internal ID)
            body: Note body (markdown)

        Returns:
            Note data including note ID
        """
        payload = {"body": body}

        return await self._request(
            "POST", f"/projects/{project_id}/issues/{issue_iid}/notes",
            json=payload
        )

    async def create_mr_discussion(
        self, project_id: str, mr_iid: int, body: str, position: dict
    ) -> dict:
        """
        Create a discussion (threaded comment) on a specific line.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID
            body: Comment text
            position: Position object specifying file, line, etc.

        Position format:
            {
                "base_sha": "commit_sha",
                "head_sha": "commit_sha",
                "start_sha": "commit_sha",
                "position_type": "text",
                "new_path": "file/path",
                "new_line": 10,
                "old_path": "file/path",
                "old_line": null
            }

        Returns:
            Created discussion data
        """
        payload = {"body": body, "position": position}

        return await self._request(
            "POST", f"/projects/{project_id}/merge_requests/{mr_iid}/discussions",
            json=payload
        )

    async def resolve_discussion(
        self, project_id: str, mr_iid: int, discussion_id: str, resolved: bool = True
    ) -> dict:
        """
        Resolve or unresolve a discussion thread.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID
            discussion_id: Discussion ID
            resolved: True to resolve, False to unresolve

        Returns:
            Updated discussion data
        """
        payload = {"resolved": resolved}

        return await self._request(
            "PUT",
            f"/projects/{project_id}/merge_requests/{mr_iid}/discussions/{discussion_id}",
            json=payload
        )

    @staticmethod
    def verify_webhook_token(token: str, secret: str) -> bool:
        """
        Verify GitLab webhook token.

        Args:
            token: X-Gitlab-Token header value
            secret: Webhook secret token

        Returns:
            True if token matches secret
        """
        import hmac
        return hmac.compare_digest(token, secret)

    async def get_project(self, project_id: str) -> dict:
        """
        Get project information.

        Args:
            project_id: Project ID or URL-encoded path

        Returns:
            Project data
        """
        return await self._request("GET", f"/projects/{project_id}")

    async def get_default_branch(self, project_id: str) -> str:
        """
        Get the default branch name for a project.

        Args:
            project_id: Project ID or URL-encoded path

        Returns:
            Default branch name
        """
        project_data = await self.get_project(project_id)
        return project_data["default_branch"]

    async def get_commit_diff(self, project_id: str, sha: str) -> list[dict]:
        """
        Get diff for a specific commit.

        Args:
            project_id: Project ID or URL-encoded path
            sha: Commit SHA

        Returns:
            List of diff data for changed files
        """
        return await self._request("GET", f"/projects/{project_id}/repository/commits/{sha}/diff")

    async def create_commit_comment(
        self, project_id: str, sha: str, note: str, path: str | None = None,
        line: int | None = None, line_type: str | None = None
    ) -> dict:
        """
        Create a comment on a commit.

        Args:
            project_id: Project ID or URL-encoded path
            sha: Commit SHA
            note: Comment text
            path: File path (optional, for line-specific comment)
            line: Line number (optional)
            line_type: Line type - 'new' or 'old' (optional)

        Returns:
            Created comment data
        """
        payload = {"note": note}

        if path:
            payload["path"] = path
        if line:
            payload["line"] = line
        if line_type:
            payload["line_type"] = line_type

        return await self._request(
            "POST", f"/projects/{project_id}/repository/commits/{sha}/comments",
            json=payload
        )

    async def get_merge_request_commits(
        self, project_id: str, mr_iid: int
    ) -> list[dict]:
        """
        Get list of commits in a merge request.

        Args:
            project_id: Project ID or URL-encoded path
            mr_iid: Merge request internal ID

        Returns:
            List of commit data
        """
        commits = []
        page = 1
        per_page = 100

        while True:
            data = await self._request(
                "GET",
                f"/projects/{project_id}/merge_requests/{mr_iid}/commits",
                params={"page": page, "per_page": per_page}
            )

            if not data:
                break

            commits.extend(data)

            if len(data) < per_page:
                break

            page += 1

        return commits
