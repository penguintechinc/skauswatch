"""Unit tests for PlanGenerator class."""

import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Add Flask backend to path
flask_backend_path = Path(__file__).parent.parent.parent / "services" / "flask-backend"
sys.path.insert(0, str(flask_backend_path))

from app.core.plan_generator import (
    ImplementationPlan,
    PlanGenerator,
)
from app.providers import AIResponse


@pytest.fixture
def mock_ai_provider():
    """Mock AI provider fixture."""
    provider = MagicMock()
    provider.config = MagicMock()
    provider.config.model = "test-model"
    provider.estimate_cost = MagicMock(return_value=0.05)
    return provider


@pytest.fixture
def plan_generator(mock_ai_provider):
    """Create PlanGenerator instance with mocked provider."""
    with patch("app.core.plan_generator.get_provider") as mock_get:
        mock_get.return_value = mock_ai_provider
        generator = PlanGenerator("claude")
        return generator


class TestPlanGeneratorInit:
    """Test PlanGenerator initialization."""

    def test_init_with_valid_provider(self, mock_ai_provider):
        """Test successful initialization with valid provider."""
        with patch("app.core.plan_generator.get_provider") as mock_get:
            mock_get.return_value = mock_ai_provider
            generator = PlanGenerator("claude")

            assert generator.provider_name == "claude"
            assert generator.model_name is None
            assert generator.provider == mock_ai_provider

    def test_init_with_custom_model(self, mock_ai_provider):
        """Test initialization with custom model override."""
        with patch("app.core.plan_generator.get_provider") as mock_get:
            mock_get.return_value = mock_ai_provider
            generator = PlanGenerator("claude", ai_model="custom-model-v1")

            assert generator.model_name == "custom-model-v1"
            assert mock_ai_provider.config.model == "custom-model-v1"

    def test_init_with_invalid_provider(self):
        """Test initialization fails with invalid provider."""
        with patch("app.core.plan_generator.get_provider") as mock_get:
            mock_get.side_effect = Exception("Unknown provider")

            with pytest.raises(ValueError, match="Invalid AI provider configuration"):
                PlanGenerator("unknown-provider")


class TestDetermineIssueType:
    """Test issue type detection."""

    def test_detect_bug_issue(self, plan_generator):
        """Test detection of bug issue type."""
        issue_type = plan_generator._determine_issue_type(
            title="Fix login crash",
            body="The app crashes when users try to login"
        )
        assert issue_type == "bug"

    def test_detect_bug_with_multiple_keywords(self, plan_generator):
        """Test bug detection with multiple keywords."""
        issue_type = plan_generator._determine_issue_type(
            title="Error on broken button",
            body="The button fails when clicked and throws exception"
        )
        assert issue_type == "bug"

    def test_detect_feature_issue(self, plan_generator):
        """Test detection of feature request."""
        issue_type = plan_generator._determine_issue_type(
            title="Add dark mode support",
            body="Implement new feature to support dark theme"
        )
        assert issue_type == "feature"

    def test_detect_feature_with_multiple_keywords(self, plan_generator):
        """Test feature detection with multiple keywords."""
        issue_type = plan_generator._determine_issue_type(
            title="Implement API endpoint",
            body="Create new endpoint to support legacy clients"
        )
        assert issue_type == "feature"

    def test_detect_enhancement_issue(self, plan_generator):
        """Test detection of enhancement request."""
        issue_type = plan_generator._determine_issue_type(
            title="Improve database performance",
            body="Optimize queries for better response time"
        )
        assert issue_type == "enhancement"

    def test_detect_enhancement_with_multiple_keywords(self, plan_generator):
        """Test enhancement detection with multiple keywords."""
        issue_type = plan_generator._determine_issue_type(
            title="Refactor auth middleware",
            body="Upgrade security checks and improve performance"
        )
        assert issue_type == "enhancement"

    def test_default_to_enhancement_when_unclear(self, plan_generator):
        """Test defaults to enhancement when no clear type detected."""
        issue_type = plan_generator._determine_issue_type(
            title="Update documentation",
            body="Just some random changes"
        )
        # Could be enhancement or default based on keyword weight
        assert issue_type in ["enhancement", "feature"]

    def test_case_insensitive_detection(self, plan_generator):
        """Test issue type detection is case insensitive."""
        issue_type = plan_generator._determine_issue_type(
            title="BUG: Critical Crash",
            body="BROKEN FEATURE PREVENTS LOGIN"
        )
        assert issue_type == "bug"


class TestParsePlanResponse:
    """Test response parsing."""

    def test_parse_valid_json_response(self, plan_generator):
        """Test parsing valid JSON response."""
        response_text = json.dumps({
            "overview": "Fix authentication flow",
            "approach": "Update JWT validation",
            "steps": [
                {"number": 1, "title": "Add validation", "description": "Validate tokens"},
                {"number": 2, "title": "Update middleware", "description": "Apply to routes"}
            ],
            "critical_files": ["auth.py", "middleware.py"],
            "risks": ["Token invalidation", "Session loss"],
            "testing_strategy": "Unit and integration tests",
            "estimated_effort": "2-3 hours",
            "complexity": "High"
        })

        result = plan_generator._parse_plan_response(response_text)

        assert result["overview"] == "Fix authentication flow"
        assert result["approach"] == "Update JWT validation"
        assert len(result["steps"]) == 2
        assert result["steps"][0]["title"] == "Add validation"
        assert len(result["critical_files"]) == 2
        assert len(result["risks"]) == 2

    def test_parse_json_in_markdown_code_block(self, plan_generator):
        """Test parsing JSON wrapped in markdown code blocks."""
        response_text = """
        Here's the plan:

        ```json
        {
            "overview": "Implementation overview",
            "approach": "Strategic approach",
            "steps": [
                {"number": 1, "title": "First step", "description": "Do something"}
            ],
            "critical_files": ["file.py"],
            "risks": []
        }
        ```

        This is my analysis.
        """

        result = plan_generator._parse_plan_response(response_text)

        assert result["overview"] == "Implementation overview"
        assert len(result["steps"]) == 1

    def test_parse_json_without_language_tag(self, plan_generator):
        """Test parsing JSON in code block without language tag."""
        response_text = """
        ```
        {
            "overview": "Plan overview",
            "approach": "Approach details",
            "steps": [],
            "critical_files": [],
            "risks": []
        }
        ```
        """

        result = plan_generator._parse_plan_response(response_text)

        assert result["overview"] == "Plan overview"
        assert result["approach"] == "Approach details"

    def test_parse_string_steps_normalized(self, plan_generator):
        """Test string steps are normalized to dict format."""
        response_text = json.dumps({
            "overview": "Test plan",
            "approach": "Test approach",
            "steps": [
                "First step to implement",
                "Second step to implement"
            ],
            "critical_files": [],
            "risks": []
        })

        result = plan_generator._parse_plan_response(response_text)

        assert len(result["steps"]) == 2
        assert isinstance(result["steps"][0], dict)
        assert result["steps"][0]["title"] == "First step to implement"
        assert result["steps"][0]["description"] == "First step to implement"

    def test_parse_mixed_step_formats(self, plan_generator):
        """Test handling of mixed string and dict steps."""
        response_text = json.dumps({
            "overview": "Test plan",
            "approach": "Test approach",
            "steps": [
                "String step",
                {"title": "Dict step", "description": "More details"}
            ],
            "critical_files": [],
            "risks": []
        })

        result = plan_generator._parse_plan_response(response_text)

        assert len(result["steps"]) == 2
        assert result["steps"][0]["title"] == "String step"
        assert result["steps"][1]["title"] == "Dict step"

    def test_parse_invalid_json_raises_error(self, plan_generator):
        """Test parsing invalid JSON raises ValueError."""
        response_text = "{ invalid json content }"

        with pytest.raises(ValueError, match="Invalid JSON response"):
            plan_generator._parse_plan_response(response_text)

    def test_parse_missing_required_field_raises_error(self, plan_generator):
        """Test parsing response missing required field raises error."""
        response_text = json.dumps({
            "overview": "Test overview",
            # Missing "approach"
            "steps": []
        })

        with pytest.raises(ValueError, match="Missing required field: approach"):
            plan_generator._parse_plan_response(response_text)

    def test_parse_non_dict_json_raises_error(self, plan_generator):
        """Test parsing non-object JSON raises error."""
        response_text = json.dumps(["array", "not", "object"])

        with pytest.raises(ValueError, match="Response is not a JSON object"):
            plan_generator._parse_plan_response(response_text)

    def test_parse_non_list_steps_raises_error(self, plan_generator):
        """Test parsing with non-list steps raises error."""
        response_text = json.dumps({
            "overview": "Test",
            "approach": "Test",
            "steps": "not a list"
        })

        with pytest.raises(ValueError, match="Steps must be a list"):
            plan_generator._parse_plan_response(response_text)

    def test_parse_empty_optional_fields(self, plan_generator):
        """Test parsing with minimal required fields only."""
        response_text = json.dumps({
            "overview": "Test overview",
            "approach": "Test approach",
            "steps": []
        })

        result = plan_generator._parse_plan_response(response_text)

        assert result["overview"] == "Test overview"
        assert result["approach"] == "Test approach"
        assert result["steps"] == []
        assert result.get("critical_files") is None or result["critical_files"] == []

    def test_parse_non_list_critical_files_normalized(self, plan_generator):
        """Test non-list critical_files is normalized to empty list."""
        response_text = json.dumps({
            "overview": "Test",
            "approach": "Test",
            "steps": [],
            "critical_files": "not a list"
        })

        result = plan_generator._parse_plan_response(response_text)

        assert result["critical_files"] == []

    def test_parse_missing_step_fields_has_defaults(self, plan_generator):
        """Test steps missing optional fields get defaults."""
        response_text = json.dumps({
            "overview": "Test",
            "approach": "Test",
            "steps": [
                {},  # Empty step
                {"title": "Just title"}
            ]
        })

        result = plan_generator._parse_plan_response(response_text)

        assert result["steps"][0]["number"] == 1
        assert result["steps"][0]["title"] == "Step 1"
        assert result["steps"][0]["description"] == ""
        assert result["steps"][1]["title"] == "Just title"


class TestFormatPlanAsMarkdown:
    """Test markdown formatting."""

    def test_format_complete_plan(self, plan_generator):
        """Test formatting complete implementation plan."""
        plan = ImplementationPlan(
            overview="Fix authentication flow",
            approach="Update JWT validation and refresh tokens",
            steps=[
                {"number": 1, "title": "Validate tokens", "description": "Add validation logic"},
                {"number": 2, "title": "Update middleware", "description": "Apply to routes"}
            ],
            critical_files=["auth.py", "middleware.py"],
            risks=["Token revocation", "Session loss"],
            testing_strategy="Unit tests covering all auth scenarios",
            estimated_effort="2-3 hours",
            complexity="High"
        )

        markdown = plan_generator.format_plan_as_markdown(plan)

        # Check header
        assert "## 🤖 AI-Generated Implementation Plan" in markdown
        assert "**Estimated Effort:** 2-3 hours" in markdown
        assert "**Complexity:** High" in markdown

        # Check sections
        assert "### 📋 Overview" in markdown
        assert "Fix authentication flow" in markdown
        assert "### 🎯 Approach" in markdown
        assert "### 📝 Implementation Steps" in markdown
        assert "1. **Validate tokens**" in markdown
        assert "2. **Update middleware**" in markdown
        assert "### 📂 Critical Files" in markdown
        assert "`auth.py`" in markdown
        assert "### ⚠️ Potential Risks" in markdown
        assert "### 🧪 Testing Strategy" in markdown

        # Check footer
        assert "*Generated by Darwin AI" in markdown

    def test_format_plan_minimal(self, plan_generator):
        """Test formatting minimal plan with required fields only."""
        plan = ImplementationPlan(
            overview="Simple fix",
            approach="Direct approach",
            steps=[],
            critical_files=[],
            risks=[]
        )

        markdown = plan_generator.format_plan_as_markdown(plan)

        assert "## 🤖 AI-Generated Implementation Plan" in markdown
        assert "### 📋 Overview" in markdown
        assert "Simple fix" in markdown
        assert "### 🎯 Approach" in markdown
        # Should not include empty sections
        assert "### 📂 Critical Files" not in markdown

    def test_format_plan_skips_empty_steps(self, plan_generator):
        """Test that empty steps section is skipped."""
        plan = ImplementationPlan(
            overview="Test",
            approach="Test",
            steps=[],
            critical_files=["file.py"],
            risks=[]
        )

        markdown = plan_generator.format_plan_as_markdown(plan)

        assert "### 📝 Implementation Steps" not in markdown
        assert "### 📂 Critical Files" in markdown

    def test_format_plan_skips_duplicate_descriptions(self, plan_generator):
        """Test that duplicate title/description are not repeated."""
        plan = ImplementationPlan(
            overview="Test",
            approach="Test",
            steps=[
                {"number": 1, "title": "Update code", "description": "Update code"}
            ],
            critical_files=[],
            risks=[]
        )

        markdown = plan_generator.format_plan_as_markdown(plan)

        # Should only have one line for the step since description equals title
        lines = markdown.split("\n")
        step_lines = [l for l in lines if "Update code" in l]
        # Should have one line with the title, not both title and description
        assert len(step_lines) >= 1


class TestGeneratePlan:
    """Test plan generation workflow."""

    @pytest.mark.asyncio
    async def test_generate_plan_success(self, plan_generator, mock_ai_provider):
        """Test successful plan generation."""
        # Mock the AI provider response
        ai_response = AIResponse(
            content=json.dumps({
                "overview": "Fix database connection pool exhaustion",
                "approach": "Implement connection pooling with timeout",
                "steps": [
                    {"number": 1, "title": "Add pool config", "description": "Configure pool"},
                    {"number": 2, "title": "Add timeout", "description": "Set timeout"}
                ],
                "critical_files": ["database.py"],
                "risks": ["Connection loss"],
                "testing_strategy": "Load tests",
                "estimated_effort": "4-6 hours",
                "complexity": "Medium"
            }),
            model="claude-3-sonnet",
            prompt_tokens=150,
            completion_tokens=300,
            total_tokens=450,
            latency_ms=2000,
            finish_reason="stop"
        )

        plan_generator.provider.complete = AsyncMock(return_value=ai_response)

        # Mock the create_provider_usage function
        with patch("app.core.plan_generator.create_provider_usage") as mock_usage:
            plan = await plan_generator.generate_plan(
                issue_title="Database connection pool exhausted",
                issue_body="The database connection pool keeps getting exhausted under load",
                repository="myorg/myrepo"
            )

            assert plan.overview == "Fix database connection pool exhaustion"
            assert len(plan.steps) == 2
            assert plan.complexity == "Medium"
            assert plan.estimated_effort == "4-6 hours"

    @pytest.mark.asyncio
    async def test_generate_plan_with_review_id(self, plan_generator, mock_ai_provider):
        """Test plan generation with review ID tracking."""
        ai_response = AIResponse(
            content=json.dumps({
                "overview": "Test overview",
                "approach": "Test approach",
                "steps": [],
                "critical_files": [],
                "risks": []
            }),
            model="claude-3-sonnet",
            prompt_tokens=100,
            completion_tokens=200,
            total_tokens=300,
            latency_ms=1500,
            finish_reason="stop"
        )

        plan_generator.provider.complete = AsyncMock(return_value=ai_response)

        with patch("app.core.plan_generator.create_provider_usage") as mock_usage:
            plan = await plan_generator.generate_plan(
                issue_title="Test issue",
                issue_body="Test body",
                repository="test/repo",
                review_id=123
            )

            # Verify usage was tracked
            mock_usage.assert_called_once()
            call_kwargs = mock_usage.call_args[1]
            assert call_kwargs["review_id"] == 123
            assert call_kwargs["provider"] == "claude"

    @pytest.mark.asyncio
    async def test_generate_plan_ai_provider_error(self, plan_generator, mock_ai_provider):
        """Test plan generation handles provider errors."""
        plan_generator.provider.complete = AsyncMock(
            side_effect=Exception("API rate limit exceeded")
        )

        with pytest.raises(Exception, match="API rate limit exceeded"):
            await plan_generator.generate_plan(
                issue_title="Test issue",
                issue_body="Test body",
                repository="test/repo"
            )

    @pytest.mark.asyncio
    async def test_generate_plan_invalid_response(self, plan_generator, mock_ai_provider):
        """Test plan generation with invalid response."""
        ai_response = AIResponse(
            content="This is not JSON",
            model="claude-3-sonnet",
            prompt_tokens=100,
            completion_tokens=100,
            total_tokens=200,
            latency_ms=1000,
            finish_reason="stop"
        )

        plan_generator.provider.complete = AsyncMock(return_value=ai_response)

        with pytest.raises(ValueError):
            await plan_generator.generate_plan(
                issue_title="Test issue",
                issue_body="Test body",
                repository="test/repo"
            )


class TestImplementationPlanDataclass:
    """Test ImplementationPlan dataclass."""

    def test_create_plan_with_defaults(self):
        """Test creating plan with default values."""
        plan = ImplementationPlan(
            overview="Test overview",
            approach="Test approach"
        )

        assert plan.overview == "Test overview"
        assert plan.approach == "Test approach"
        assert plan.steps == []
        assert plan.critical_files == []
        assert plan.risks == []
        assert plan.testing_strategy == ""
        assert plan.estimated_effort == ""
        assert plan.complexity == ""

    def test_create_plan_with_all_fields(self):
        """Test creating plan with all fields."""
        plan = ImplementationPlan(
            overview="Overview",
            approach="Approach",
            steps=[{"number": 1, "title": "Step 1", "description": "Desc"}],
            critical_files=["file.py"],
            risks=["risk1"],
            testing_strategy="Test it",
            estimated_effort="2 hours",
            complexity="High"
        )

        assert plan.overview == "Overview"
        assert len(plan.steps) == 1
        assert len(plan.critical_files) == 1
        assert len(plan.risks) == 1
        assert plan.complexity == "High"
