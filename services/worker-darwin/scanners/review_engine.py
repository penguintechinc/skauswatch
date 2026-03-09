"""Core review engine for Darwin code review system.

Adapted from darwin/services/flask-backend/app/core/reviewer.py.
Dependency on Darwin's SQLAlchemy models replaced with no-op / PyDAL.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from scanners.ai_provider import AIProvider, AIResponse

logger = logging.getLogger(__name__)


# Review categories and their system prompts
CATEGORY_SYSTEM_PROMPTS: dict[str, str] = {
    "security": (
        "You are a security code reviewer. Analyze the provided diff for security vulnerabilities "
        "including SQL injection, XSS, SSRF, insecure deserialization, hardcoded secrets, "
        "authentication/authorization issues, and other OWASP Top 10 issues. "
        "Return a JSON array of findings. Each finding must have: "
        "line_start (int), line_end (int), severity (critical/major/minor/suggestion), "
        "title (str), body (str), suggestion (str or null)."
    ),
    "best_practices": (
        "You are a code quality reviewer. Analyze the provided diff for best practice violations "
        "including poor naming, missing error handling, code duplication, overly complex logic, "
        "missing tests, and maintainability issues. "
        "Return a JSON array of findings with: "
        "line_start (int), line_end (int), severity (critical/major/minor/suggestion), "
        "title (str), body (str), suggestion (str or null)."
    ),
    "performance": (
        "You are a performance code reviewer. Analyze the provided diff for performance issues "
        "including N+1 queries, unnecessary computations, blocking I/O in async contexts, "
        "memory leaks, and algorithmic inefficiencies. "
        "Return a JSON array of findings with: "
        "line_start (int), line_end (int), severity (critical/major/minor/suggestion), "
        "title (str), body (str), suggestion (str or null)."
    ),
}


@dataclass(slots=True)
class ReviewComment:
    """A single review comment on a file."""

    file_path: str
    line_start: int
    line_end: int
    category: str
    severity: str
    title: str
    body: str
    source: str  # "linter" or "ai:<provider_name>"
    suggestion: Optional[str] = None
    linter_rule_id: Optional[str] = None


@dataclass(slots=True)
class PRFile:
    """Pull request file with diff information."""

    path: str
    status: str  # added, modified, deleted, renamed
    additions: int
    deletions: int
    patch: str  # unified diff
    old_path: Optional[str] = None


@dataclass(slots=True)
class ReviewResult:
    """Result of a code review operation."""

    comments: list = field(default_factory=list)
    files_reviewed: int = 0
    ai_requests: int = 0
    total_tokens: int = 0
    errors: list = field(default_factory=list)


class ReviewEngine:
    """Coordinates AI-based review of pull request files."""

    async def review_pr(
        self,
        platform: str,
        repository: str,
        pr_files: list[PRFile],
        config: dict[str, Any],
        ai_provider: Optional[AIProvider] = None,
        review_id: Optional[int] = None,
    ) -> ReviewResult:
        """Review pull request files.

        Args:
            platform: Git platform (github, gitlab)
            repository: Repository identifier
            pr_files: List of changed files with diffs
            config: Review configuration (categories, etc.)
            ai_provider: AI provider instance (optional)
            review_id: DB review ID for usage tracking (optional)

        Returns:
            ReviewResult with comments and metadata
        """
        result = ReviewResult()
        file_paths = [f.path for f in pr_files if f.status != "deleted"]

        if not file_paths or not ai_provider:
            return result

        categories = config.get("categories", ["security", "best_practices"])
        ai_categories = [c for c in categories if c in CATEGORY_SYSTEM_PROMPTS]

        for pr_file in pr_files:
            if pr_file.status == "deleted" or not pr_file.patch:
                continue

            file_comments = await self._review_file(
                pr_file, ai_categories, ai_provider, review_id
            )
            result.comments.extend(file_comments)
            result.files_reviewed += 1

        return result

    async def _review_file(
        self,
        pr_file: PRFile,
        categories: list[str],
        ai_provider: AIProvider,
        review_id: Optional[int],
    ) -> list[ReviewComment]:
        """Review a single file across multiple categories.

        Args:
            pr_file: PR file with diff
            categories: Review categories to apply
            ai_provider: AI provider instance
            review_id: DB review ID for usage tracking

        Returns:
            List of ReviewComment objects
        """
        comments: list[ReviewComment] = []

        for category in categories:
            system_prompt = CATEGORY_SYSTEM_PROMPTS.get(category)
            if not system_prompt:
                continue

            prompt = (
                f"File: {pr_file.path}\n\n"
                f"Diff:\n```\n{pr_file.patch[:8000]}\n```\n\n"
                "Review this diff and return findings as a JSON array."
            )

            try:
                response = await ai_provider.complete(
                    prompt=prompt,
                    system_prompt=system_prompt,
                )

                # Track usage in DB if review_id provided
                if review_id is not None:
                    self._track_usage(review_id, ai_provider, response)

                parsed = self._parse_response(
                    response, category, pr_file.path, ai_provider.name
                )
                comments.extend(parsed)

            except Exception as exc:
                logger.warning(
                    "Error reviewing %s for %s: %s", pr_file.path, category, exc
                )

        return comments

    def _parse_response(
        self,
        response: AIResponse,
        category: str,
        file_path: str,
        provider_name: str,
    ) -> list[ReviewComment]:
        """Parse AI JSON response into ReviewComment objects.

        Args:
            response: AIResponse from provider
            category: Review category
            file_path: File being reviewed
            provider_name: Name of the AI provider

        Returns:
            List of ReviewComment objects
        """
        comments: list[ReviewComment] = []
        try:
            content = response.content.strip()
            # Strip markdown code fences if present
            json_match = re.search(
                r"```(?:json)?\s*(\[.*?\])\s*```", content, re.DOTALL
            )
            if json_match:
                content = json_match.group(1)

            findings = json.loads(content)
            if not isinstance(findings, list):
                return comments

            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                comment = ReviewComment(
                    file_path=file_path,
                    line_start=finding.get("line_start", 1),
                    line_end=finding.get("line_end", finding.get("line_start", 1)),
                    category=category,
                    severity=self._normalize_severity(
                        finding.get("severity", "suggestion")
                    ),
                    title=finding.get("title", "Code review finding"),
                    body=finding.get("body", ""),
                    source=f"ai:{provider_name}",
                    suggestion=finding.get("suggestion"),
                )
                comments.append(comment)

        except json.JSONDecodeError:
            pass  # AI did not return valid JSON — skip
        except Exception as exc:
            logger.warning("Error parsing AI response: %s", exc)

        return comments

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity string to one of: critical, major, minor, suggestion."""
        valid = {"critical", "major", "minor", "suggestion"}
        low = severity.lower()
        if low in valid:
            return low
        mapping = {
            "error": "major",
            "warning": "minor",
            "info": "suggestion",
            "high": "critical",
            "medium": "major",
            "low": "minor",
        }
        return mapping.get(low, "suggestion")

    def _track_usage(
        self,
        review_id: int,
        ai_provider: AIProvider,
        response: AIResponse,
    ) -> None:
        """Persist token usage to darwin_provider_usage via PyDAL.

        Runs inside Celery worker context — uses get_configured_db().

        Args:
            review_id: darwin_reviews ID
            ai_provider: Provider instance
            response: AI response with token counts
        """
        from datetime import datetime, timezone

        try:
            from database.models import get_configured_db

            db = get_configured_db()
            try:
                cost = ai_provider.estimate_cost(
                    response.prompt_tokens, response.completion_tokens
                )
                db.darwin_provider_usage.insert(
                    tenant_id=1,
                    provider=ai_provider.name,
                    model=response.model,
                    tokens_in=response.prompt_tokens,
                    tokens_out=response.completion_tokens,
                    cost_usd=cost,
                    recorded_at=datetime.now(timezone.utc),
                    created_at=datetime.now(timezone.utc),
                )
                db.commit()
            finally:
                db.close()
        except Exception as exc:
            logger.warning("Failed to track provider usage: %s", exc)
