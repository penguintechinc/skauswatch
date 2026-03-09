"""
GitHub API integration client.

Provides async methods for interacting with GitHub's REST API v3,
including pull requests, reviews, check runs, and webhooks.
"""

from dataclasses import dataclass
from typing import Any
import hmac
import hashlib
import logging
import httpx

logger = logging.getLogger(__name__)


class GitHubAPIError(Exception):
    """Base exception for GitHub API errors."""

    def __init__(self, message: str, status_code: int | None = None):
        self.status_code = status_code
        super().__init__(message)


class GitHubRateLimitError(GitHubAPIError):
    """Exception raised when rate limit is exceeded."""

    pass


@dataclass(slots=True)
class GitHubConfig:
    """Configuration for GitHub API client."""

    token: str
    app_id: str | None = None
    app_private_key: str | None = None
    base_url: str = "https://api.github.com"


@dataclass(slots=True)
class PullRequest:
    """Represents a GitHub pull request."""

    number: int
    title: str
    state: str
    head_sha: str
    base_sha: str
    head_ref: str
    base_ref: str
    html_url: str
    diff_url: str


@dataclass(slots=True)
class PRFile:
    """Represents a file changed in a pull request."""

    filename: str
    status: str  # added, removed, modified, renamed
    additions: int
    deletions: int
    patch: str | None


class GitHubClient:
    """Async client for GitHub API operations."""

    def __init__(self, config: GitHubConfig):
        """
        Initialize GitHub client.

        Args:
            config: GitHub configuration with token and optional app credentials
        """
        self.config = config
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        """Context manager entry."""
        self._client = httpx.AsyncClient(
            base_url=self.config.base_url,
            headers={
                "Authorization": f"Bearer {self.config.token}",
                "Accept": "application/vnd.github.v3+json",
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
        Make an authenticated request to GitHub API.

        Args:
            method: HTTP method
            path: API path
            **kwargs: Additional request parameters

        Returns:
            JSON response data

        Raises:
            GitHubAPIError: On API errors
            GitHubRateLimitError: On rate limit exceeded
        """
        if not self._client:
            raise RuntimeError("Client not initialized. Use async context manager.")

        try:
            response = await self._client.request(method, path, **kwargs)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                # Check if rate limited
                if "rate limit" in e.response.text.lower():
                    raise GitHubRateLimitError(
                        "GitHub API rate limit exceeded", e.response.status_code
                    )
            logger.error(
                f"GitHub API error: {e.response.status_code} - {e.response.text}"
            )
            raise GitHubAPIError(
                f"GitHub API request failed: {e.response.status_code}",
                e.response.status_code,
            )
        except httpx.RequestError as e:
            logger.error(f"GitHub API request error: {str(e)}")
            raise GitHubAPIError(f"Request failed: {str(e)}")

    async def get_pull_request(
        self, owner: str, repo: str, pr_number: int
    ) -> PullRequest:
        """
        Retrieve pull request details.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            PullRequest object with PR details
        """
        data = await self._request(
            "GET", f"/repos/{owner}/{repo}/pulls/{pr_number}"
        )
        return PullRequest(
            number=data["number"],
            title=data["title"],
            state=data["state"],
            head_sha=data["head"]["sha"],
            base_sha=data["base"]["sha"],
            head_ref=data["head"]["ref"],
            base_ref=data["base"]["ref"],
            html_url=data["html_url"],
            diff_url=data["diff_url"],
        )

    async def get_pull_request_files(
        self, owner: str, repo: str, pr_number: int
    ) -> list[PRFile]:
        """
        Get list of files changed in a pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number

        Returns:
            List of PRFile objects representing changed files
        """
        files = []
        page = 1
        per_page = 100

        while True:
            data = await self._request(
                "GET",
                f"/repos/{owner}/{repo}/pulls/{pr_number}/files",
                params={"page": page, "per_page": per_page},
            )

            if not data:
                break

            for file_data in data:
                files.append(
                    PRFile(
                        filename=file_data["filename"],
                        status=file_data["status"],
                        additions=file_data["additions"],
                        deletions=file_data["deletions"],
                        patch=file_data.get("patch"),
                    )
                )

            if len(data) < per_page:
                break

            page += 1

        return files

    async def get_file_content(
        self, owner: str, repo: str, path: str, ref: str
    ) -> str:
        """
        Get file content at a specific ref.

        Args:
            owner: Repository owner
            repo: Repository name
            path: File path
            ref: Git ref (branch, tag, or commit SHA)

        Returns:
            File content as string
        """
        data = await self._request(
            "GET", f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref}
        )

        import base64

        return base64.b64decode(data["content"]).decode("utf-8")

    async def create_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        event: str,
        comments: list[dict],
    ) -> dict:
        """
        Create a review on a pull request.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            body: Review summary comment
            event: Review event (APPROVE, REQUEST_CHANGES, COMMENT)
            comments: List of inline comments

        Returns:
            Created review data
        """
        payload = {"body": body, "event": event, "comments": comments}

        return await self._request(
            "POST", f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews", json=payload
        )

    async def create_review_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        body: str,
        commit_id: str,
        path: str,
        line: int,
        side: str = "RIGHT",
    ) -> dict:
        """
        Create a single review comment on a specific line.

        Args:
            owner: Repository owner
            repo: Repository name
            pr_number: Pull request number
            body: Comment text
            commit_id: Commit SHA to comment on
            path: File path
            line: Line number
            side: Side of diff (RIGHT or LEFT)

        Returns:
            Created comment data
        """
        payload = {
            "body": body,
            "commit_id": commit_id,
            "path": path,
            "line": line,
            "side": side,
        }

        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/pulls/{pr_number}/comments",
            json=payload,
        )

    async def create_issue_comment(
        self, owner: str, repo: str, issue_number: int, body: str
    ) -> dict:
        """
        Create a comment on a GitHub issue.

        Args:
            owner: Repository owner
            repo: Repository name
            issue_number: Issue number
            body: Comment body (markdown)

        Returns:
            Comment data including comment ID
        """
        payload = {"body": body}

        return await self._request(
            "POST",
            f"/repos/{owner}/{repo}/issues/{issue_number}/comments",
            json=payload,
        )

    async def create_check_run(
        self,
        owner: str,
        repo: str,
        head_sha: str,
        name: str,
        status: str,
        conclusion: str | None,
        output: dict,
    ) -> dict:
        """
        Create a check run for commit status.

        Args:
            owner: Repository owner
            repo: Repository name
            head_sha: Commit SHA
            name: Check run name
            status: Status (queued, in_progress, completed)
            conclusion: Conclusion when status is completed
            output: Output details (title, summary, text)

        Returns:
            Created check run data
        """
        payload = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
            "output": output,
        }

        if conclusion:
            payload["conclusion"] = conclusion

        return await self._request(
            "POST", f"/repos/{owner}/{repo}/check-runs", json=payload
        )

    async def update_check_run(
        self,
        owner: str,
        repo: str,
        check_run_id: int,
        status: str,
        conclusion: str | None,
        output: dict,
    ) -> dict:
        """
        Update an existing check run.

        Args:
            owner: Repository owner
            repo: Repository name
            check_run_id: Check run ID
            status: Status (queued, in_progress, completed)
            conclusion: Conclusion when status is completed
            output: Output details (title, summary, text)

        Returns:
            Updated check run data
        """
        payload = {"status": status, "output": output}

        if conclusion:
            payload["conclusion"] = conclusion

        return await self._request(
            "PATCH", f"/repos/{owner}/{repo}/check-runs/{check_run_id}", json=payload
        )

    @staticmethod
    def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
        """
        Verify GitHub webhook signature.

        Args:
            payload: Raw webhook payload bytes
            signature: X-Hub-Signature-256 header value
            secret: Webhook secret

        Returns:
            True if signature is valid
        """
        if not signature.startswith("sha256="):
            return False

        expected_signature = signature[7:]  # Remove 'sha256=' prefix
        computed_signature = hmac.new(
            secret.encode(), payload, hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(computed_signature, expected_signature)

    async def get_repository(self, owner: str, repo: str) -> dict:
        """
        Get repository information.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            Repository data
        """
        return await self._request("GET", f"/repos/{owner}/{repo}")

    async def get_default_branch(self, owner: str, repo: str) -> str:
        """
        Get the default branch name for a repository.

        Args:
            owner: Repository owner
            repo: Repository name

        Returns:
            Default branch name
        """
        repo_data = await self.get_repository(owner, repo)
        return repo_data["default_branch"]
