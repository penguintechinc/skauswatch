"""Core review engine for Darwin code review system."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import asyncio
import json
import re

from .detector import LanguageDetector, DetectionResult
from .linter import LinterOrchestrator, OrchestratorResult
from .prompts import ReviewPrompts
from ..providers.base import AIProvider, AIResponse
from ..models import create_provider_usage


@dataclass(slots=True)
class ReviewComment:
    """Structured review comment."""

    file_path: str
    line_start: int
    line_end: int
    category: str
    severity: str
    title: str
    body: str
    source: str  # "linter" or "ai"
    suggestion: str | None = None
    linter_rule_id: str | None = None


@dataclass(slots=True)
class ReviewResult:
    """Result of a code review."""

    comments: list[ReviewComment] = field(default_factory=list)
    detection: DetectionResult | None = None
    linter_results: OrchestratorResult | None = None
    files_reviewed: int = 0
    ai_requests: int = 0
    total_tokens: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PRFile:
    """Pull request file with diff information."""

    path: str
    status: str  # added, modified, deleted, renamed
    additions: int
    deletions: int
    patch: str  # unified diff
    old_path: str | None = None  # for renames


class ReviewEngine:
    """Core engine that coordinates detection, linting, and AI review."""

    def __init__(self):
        self.detector = LanguageDetector()
        self.linter_orchestrator = LinterOrchestrator()

    async def review_pr(
        self,
        platform: str,
        repository: str,
        pr_files: list[PRFile],
        config: dict[str, Any],
        ai_provider: AIProvider | None = None,
        review_id: int | None = None,
    ) -> ReviewResult:
        """Review pull request files (differential review).

        Args:
            platform: Git platform (github, gitlab)
            repository: Repository name
            pr_files: List of changed files with diffs
            config: Review configuration
            ai_provider: AI provider for reviews (optional)
            review_id: Database review ID for tracking (optional)

        Returns:
            ReviewResult with comments and metadata
        """
        result = ReviewResult()

        # Get file paths for detection
        file_paths = [f.path for f in pr_files if f.status != "deleted"]
        if not file_paths:
            return result

        # Detect languages and frameworks
        result.detection = self.detector.detect_from_files(file_paths)

        # Run linters on changed files
        categories = config.get("categories", ["security", "best_practices"])
        include_linter = "linter" in categories

        if include_linter:
            # Create temporary dict of file contents from patches
            file_contents = {}
            for pr_file in pr_files:
                if pr_file.patch and pr_file.status != "deleted":
                    # Extract added lines from patch for basic content detection
                    lines = [
                        line[1:] for line in pr_file.patch.split("\n") if line.startswith("+")
                    ]
                    file_contents[pr_file.path] = "\n".join(lines)

            # Note: For real linting, we need the actual repository
            # This is a placeholder - actual implementation would clone repo
            # For now, we'll skip linting in PR mode
            pass

        # Review each file with AI
        if ai_provider:
            ai_categories = [c for c in categories if c != "linter"]
            for pr_file in pr_files:
                if pr_file.status == "deleted" or not pr_file.patch:
                    continue

                file_comments = await self._review_file_with_ai(
                    pr_file, result.detection, ai_categories, ai_provider, review_id
                )
                result.comments.extend(file_comments)
                result.files_reviewed += 1

        return result

    async def review_repository(
        self,
        repo_path: Path,
        config: dict[str, Any],
        ai_provider: AIProvider | None = None,
        review_id: int | None = None,
    ) -> ReviewResult:
        """Review entire repository (whole repo review).

        Args:
            repo_path: Path to repository
            config: Review configuration
            ai_provider: AI provider for reviews (optional)
            review_id: Database review ID for tracking (optional)

        Returns:
            ReviewResult with comments and metadata
        """
        result = ReviewResult()

        # Detect languages and frameworks
        result.detection = self.detector.detect_from_directory(repo_path)

        # Run linters
        categories = config.get("categories", ["security", "best_practices"])
        include_linter = "linter" in categories

        if include_linter:
            result.linter_results = await self.linter_orchestrator.run_linters(
                repo_path, result.detection, files=None, include_security=True
            )

            # Convert linter issues to review comments
            for lint_result in result.linter_results.results:
                for issue in lint_result.issues:
                    comment = ReviewComment(
                        file_path=issue.file,
                        line_start=issue.line,
                        line_end=issue.line,
                        category="linter",
                        severity=self._map_severity(issue.severity),
                        title=f"{lint_result.linter}: {issue.rule_id}",
                        body=issue.message,
                        source="linter",
                        suggestion=issue.suggestion,
                        linter_rule_id=issue.rule_id,
                    )
                    result.comments.append(comment)

        # AI review of specific files
        if ai_provider:
            ai_categories = [c for c in categories if c != "linter"]
            # For whole repo review, we'd need to select files intelligently
            # This is a placeholder for full implementation
            pass

        return result

    async def _review_file_with_ai(
        self,
        pr_file: PRFile,
        detection: DetectionResult,
        categories: list[str],
        ai_provider: AIProvider,
        review_id: int | None,
    ) -> list[ReviewComment]:
        """Review a single file using AI across multiple categories.

        Args:
            pr_file: PR file with diff
            detection: Detection result
            categories: Review categories to apply
            ai_provider: AI provider
            review_id: Review ID for tracking

        Returns:
            List of review comments
        """
        comments = []

        # Determine file language
        language = detection.file_mapping.get(pr_file.path, "unknown")

        # Determine primary framework
        framework = "none"
        if detection.frameworks:
            framework = max(detection.frameworks.items(), key=lambda x: x[1])[0]

        # Determine IaC tool if applicable
        iac_tool = detection.iac_tools[0] if detection.iac_tools else "none"

        # Review for each category
        for category in categories:
            try:
                prompt = self._build_prompt(
                    category=category,
                    file_path=pr_file.path,
                    diff_content=pr_file.patch,
                    language=language,
                    framework=framework,
                    iac_tool=iac_tool,
                    detection=detection,
                )

                template = ReviewPrompts.get_template(category)
                if not template:
                    continue

                # Call AI provider
                response = await ai_provider.complete(
                    prompt=prompt, system_prompt=template.system_prompt
                )

                # Track usage
                if review_id:
                    create_provider_usage(
                        review_id=review_id,
                        provider=ai_provider.name,
                        model=response.model,
                        prompt_tokens=response.prompt_tokens,
                        completion_tokens=response.completion_tokens,
                        latency_ms=response.latency_ms,
                        cost_estimate=ai_provider.estimate_cost(
                            response.prompt_tokens, response.completion_tokens
                        ),
                    )

                # Parse response
                category_comments = self._parse_ai_response(
                    response, category, pr_file.path, ai_provider.name
                )
                comments.extend(category_comments)

            except Exception as e:
                # Log error but continue with other categories
                print(f"Error reviewing {pr_file.path} for {category}: {e}")
                continue

        return comments

    def _build_prompt(
        self,
        category: str,
        file_path: str,
        diff_content: str,
        language: str,
        framework: str,
        iac_tool: str,
        detection: DetectionResult,
    ) -> str:
        """Build AI prompt for specific review category.

        Args:
            category: Review category
            file_path: Path to file being reviewed
            diff_content: Diff content
            language: Detected language
            framework: Detected framework
            iac_tool: Detected IaC tool
            detection: Full detection result

        Returns:
            Formatted prompt string
        """
        template = ReviewPrompts.get_template(category)
        if not template:
            return ""

        tech_stack = ReviewPrompts.format_tech_stack(
            detection.languages, detection.frameworks, detection.iac_tools
        )

        return template.user_template.format(
            file_path=file_path,
            language=language,
            framework=framework,
            iac_tool=iac_tool,
            diff_content=diff_content,
            tech_stack=tech_stack,
        )

    def _parse_ai_response(
        self, response: AIResponse, category: str, file_path: str, provider_name: str
    ) -> list[ReviewComment]:
        """Parse AI response into structured ReviewComment objects.

        Args:
            response: AI response
            category: Review category
            file_path: File being reviewed
            provider_name: Name of AI provider

        Returns:
            List of ReviewComment objects
        """
        comments = []

        try:
            # Extract JSON from response (may be wrapped in markdown code blocks)
            content = response.content.strip()

            # Remove markdown code blocks if present
            json_match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", content, re.DOTALL)
            if json_match:
                content = json_match.group(1)

            # Parse JSON array
            findings = json.loads(content)

            if not isinstance(findings, list):
                return comments

            # Convert to ReviewComment objects
            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                comment = ReviewComment(
                    file_path=file_path,
                    line_start=finding.get("line_start", 1),
                    line_end=finding.get("line_end", finding.get("line_start", 1)),
                    category=category,
                    severity=self._validate_severity(finding.get("severity", "suggestion")),
                    title=finding.get("title", "Code review finding"),
                    body=finding.get("body", ""),
                    source=f"ai:{provider_name}",
                    suggestion=finding.get("suggestion"),
                )
                comments.append(comment)

        except json.JSONDecodeError:
            # AI didn't return valid JSON - skip
            pass
        except Exception as e:
            print(f"Error parsing AI response: {e}")

        return comments

    def _validate_severity(self, severity: str) -> str:
        """Validate and normalize severity level.

        Args:
            severity: Raw severity string

        Returns:
            Normalized severity (critical, major, minor, suggestion)
        """
        valid_severities = {"critical", "major", "minor", "suggestion"}
        severity_lower = severity.lower()

        if severity_lower in valid_severities:
            return severity_lower

        # Map common variations
        severity_map = {
            "error": "major",
            "warning": "minor",
            "info": "suggestion",
            "high": "critical",
            "medium": "major",
            "low": "minor",
        }

        return severity_map.get(severity_lower, "suggestion")

    def _map_severity(self, linter_severity: str) -> str:
        """Map linter severity to review severity.

        Args:
            linter_severity: Linter severity (error, warning, info)

        Returns:
            Review severity (critical, major, minor, suggestion)
        """
        severity_map = {"error": "major", "warning": "minor", "info": "suggestion"}

        return severity_map.get(linter_severity.lower(), "suggestion")
