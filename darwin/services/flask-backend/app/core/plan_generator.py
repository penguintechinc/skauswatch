"""AI-powered implementation plan generator for GitHub/GitLab issues."""

from dataclasses import dataclass, field
import json
import logging
import re
from typing import Optional

from ..providers import AIProvider, get_provider
from ..models import create_provider_usage

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ImplementationPlan:
    """Structured implementation plan for an issue."""

    overview: str
    approach: str
    steps: list[dict] = field(default_factory=list)
    critical_files: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    testing_strategy: str = ""
    estimated_effort: str = ""
    complexity: str = ""


class PlanGenerator:
    """Generate AI-powered implementation plans for issues."""

    def __init__(self, ai_provider: str, ai_model: Optional[str] = None):
        """Initialize plan generator with AI provider.

        Args:
            ai_provider: AI provider name (claude, openai, ollama)
            ai_model: Optional model name override

        Raises:
            ValueError: If provider configuration is invalid
        """
        self.provider_name = ai_provider
        self.model_name = ai_model

        try:
            self.provider = get_provider(ai_provider)

            # Override model if specified
            if ai_model:
                self.provider.config.model = ai_model

        except Exception as e:
            logger.error(f"Failed to initialize AI provider {ai_provider}: {e}")
            raise ValueError(f"Invalid AI provider configuration: {e}") from e

    async def generate_plan(
        self,
        issue_title: str,
        issue_body: str,
        repository: str,
        review_id: Optional[int] = None,
    ) -> ImplementationPlan:
        """Generate implementation plan for an issue.

        Args:
            issue_title: Issue title
            issue_body: Issue body/description
            repository: Repository name (e.g., "owner/repo")
            review_id: Optional review ID for tracking token usage

        Returns:
            ImplementationPlan with structured implementation steps

        Raises:
            Exception: If plan generation fails
        """
        logger.info(f"Generating implementation plan for issue: {issue_title}")

        try:
            # Determine issue type
            issue_type = self._determine_issue_type(issue_title, issue_body)
            logger.debug(f"Detected issue type: {issue_type}")

            # Import here to avoid circular dependency
            from .prompts import PlanPrompts

            # Build prompt
            prompt = PlanPrompts.build_plan_prompt(
                issue_title=issue_title,
                issue_body=issue_body,
                issue_type=issue_type,
                repository=repository,
            )

            system_prompt = PlanPrompts.get_plan_system_prompt()

            # Call AI provider
            logger.debug(f"Calling AI provider: {self.provider_name}")
            response = await self.provider.complete(
                prompt=prompt, system_prompt=system_prompt
            )

            # Track usage if review_id provided
            if review_id:
                create_provider_usage(
                    review_id=review_id,
                    provider=self.provider_name,
                    model=response.model,
                    prompt_tokens=response.prompt_tokens,
                    completion_tokens=response.completion_tokens,
                    latency_ms=response.latency_ms,
                    cost_estimate=self.provider.estimate_cost(
                        response.prompt_tokens, response.completion_tokens
                    ),
                )

            # Parse response
            plan_data = self._parse_plan_response(response.content)

            # Create ImplementationPlan object
            plan = ImplementationPlan(
                overview=plan_data.get("overview", ""),
                approach=plan_data.get("approach", ""),
                steps=plan_data.get("steps", []),
                critical_files=plan_data.get("critical_files", []),
                risks=plan_data.get("risks", []),
                testing_strategy=plan_data.get("testing_strategy", ""),
                estimated_effort=plan_data.get("estimated_effort", "Unknown"),
                complexity=plan_data.get("complexity", "Medium"),
            )

            logger.info(
                f"Successfully generated plan with {len(plan.steps)} steps, "
                f"complexity: {plan.complexity}"
            )

            return plan

        except Exception as e:
            logger.error(f"Failed to generate plan: {e}")
            raise

    def _determine_issue_type(self, title: str, body: str) -> str:
        """Detect issue type based on keywords in title and body.

        Args:
            title: Issue title
            body: Issue body

        Returns:
            Issue type: "bug", "feature", or "enhancement"
        """
        text = f"{title} {body}".lower()

        # Bug indicators
        bug_keywords = [
            "bug",
            "error",
            "crash",
            "broken",
            "fix",
            "issue",
            "problem",
            "fail",
            "exception",
            "defect",
        ]

        # Feature indicators
        feature_keywords = [
            "feature",
            "add",
            "new",
            "implement",
            "support",
            "allow",
            "enable",
            "create",
        ]

        # Enhancement indicators
        enhancement_keywords = [
            "improve",
            "enhance",
            "optimization",
            "refactor",
            "update",
            "upgrade",
            "performance",
            "better",
        ]

        # Count keyword matches
        bug_count = sum(1 for kw in bug_keywords if kw in text)
        feature_count = sum(1 for kw in feature_keywords if kw in text)
        enhancement_count = sum(1 for kw in enhancement_keywords if kw in text)

        # Determine type based on highest count
        if bug_count > max(feature_count, enhancement_count):
            return "bug"
        elif feature_count > enhancement_count:
            return "feature"
        else:
            return "enhancement"

    def _parse_plan_response(self, response_text: str) -> dict:
        """Parse AI response into structured plan data.

        Args:
            response_text: Raw AI response text

        Returns:
            Dictionary with plan fields

        Raises:
            ValueError: If response cannot be parsed
        """
        try:
            # Extract JSON from response (may be wrapped in markdown code blocks)
            content = response_text.strip()

            # Remove markdown code blocks if present
            json_match = re.search(
                r"```(?:json)?\s*(\{.*?\})\s*```", content, re.DOTALL
            )
            if json_match:
                content = json_match.group(1)

            # Parse JSON
            plan_data = json.loads(content)

            if not isinstance(plan_data, dict):
                raise ValueError("Response is not a JSON object")

            # Validate required fields
            required_fields = ["overview", "approach", "steps"]
            for field in required_fields:
                if field not in plan_data:
                    raise ValueError(f"Missing required field: {field}")

            # Validate steps structure
            if not isinstance(plan_data["steps"], list):
                raise ValueError("Steps must be a list")

            # Normalize steps - ensure each step is a dict with required fields
            normalized_steps = []
            for i, step in enumerate(plan_data["steps"], 1):
                if isinstance(step, str):
                    # Convert string step to dict
                    normalized_steps.append(
                        {"number": i, "title": step, "description": step}
                    )
                elif isinstance(step, dict):
                    # Ensure required fields exist
                    normalized_steps.append(
                        {
                            "number": step.get("number", i),
                            "title": step.get("title", f"Step {i}"),
                            "description": step.get("description", ""),
                        }
                    )

            plan_data["steps"] = normalized_steps

            # Normalize lists
            for field in ["critical_files", "risks"]:
                if field in plan_data:
                    if not isinstance(plan_data[field], list):
                        plan_data[field] = []

            return plan_data

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON response: {e}")
            logger.debug(f"Response content: {response_text[:500]}")
            raise ValueError(f"Invalid JSON response: {e}") from e
        except Exception as e:
            logger.error(f"Failed to parse plan response: {e}")
            raise ValueError(f"Failed to parse plan response: {e}") from e

    def format_plan_as_markdown(self, plan: ImplementationPlan) -> str:
        """Format implementation plan as GitHub/GitLab markdown comment.

        Args:
            plan: Implementation plan

        Returns:
            Formatted markdown string
        """
        lines = [
            "## 🤖 AI-Generated Implementation Plan",
            "",
            f"**Estimated Effort:** {plan.estimated_effort}",
            f"**Complexity:** {plan.complexity}",
            "",
            "### 📋 Overview",
            plan.overview,
            "",
            "### 🎯 Approach",
            plan.approach,
            "",
        ]

        # Add steps
        if plan.steps:
            lines.extend(["### 📝 Implementation Steps", ""])
            for step in plan.steps:
                number = step.get("number", "")
                title = step.get("title", "")
                description = step.get("description", "")

                # Format step
                lines.append(f"{number}. **{title}**")
                if description and description != title:
                    lines.append(f"   {description}")
                lines.append("")

        # Add critical files
        if plan.critical_files:
            lines.extend(["### 📂 Critical Files", ""])
            for file_path in plan.critical_files:
                lines.append(f"- `{file_path}`")
            lines.append("")

        # Add risks
        if plan.risks:
            lines.extend(["### ⚠️ Potential Risks", ""])
            for risk in plan.risks:
                lines.append(f"- {risk}")
            lines.append("")

        # Add testing strategy
        if plan.testing_strategy:
            lines.extend(
                ["### 🧪 Testing Strategy", plan.testing_strategy, ""]
            )

        # Add footer
        lines.extend(
            [
                "---",
                "*Generated by Darwin AI - Review and adapt as needed*",
            ]
        )

        return "\n".join(lines)
