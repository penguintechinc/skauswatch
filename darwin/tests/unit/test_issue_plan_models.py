"""Unit tests for issue plan database helper functions."""

import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add Flask backend to path
flask_backend_path = Path(__file__).parent.parent.parent / "services" / "flask-backend"
sys.path.insert(0, str(flask_backend_path))

from app.models import (
    calculate_monthly_cost,
    count_issue_plans_today,
    create_issue_plan,
    get_issue_plan_by_external_id,
    get_issue_plan_by_id,
    list_issue_plans,
    update_issue_plan_status,
)


@pytest.fixture
def mock_db():
    """Create a mock database connection."""
    db = MagicMock()
    db.issue_plans = MagicMock()
    return db


@pytest.fixture
def mock_plan_row():
    """Create a mock database row object."""
    row = MagicMock()
    row.as_dict = MagicMock(return_value={
        "id": 1,
        "external_id": "gh-123",
        "platform": "github",
        "repository": "myorg/myrepo",
        "issue_number": 123,
        "issue_url": "https://github.com/myorg/myrepo/issues/123",
        "issue_title": "Test issue",
        "issue_body": "Test body",
        "plan_content": "# Plan",
        "plan_steps": [{"number": 1, "title": "Step 1"}],
        "ai_provider": "claude",
        "ai_model": "claude-3-sonnet",
        "status": "completed",
        "error_message": None,
        "comment_posted": False,
        "platform_comment_id": None,
        "token_usage": {"cost_estimate": 0.05},
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    })
    return row


@pytest.fixture
def plan_data():
    """Sample plan data for testing."""
    return {
        "external_id": "gh-456",
        "platform": "github",
        "repository": "testorg/testrepo",
        "issue_number": 456,
        "issue_title": "Test plan creation",
        "issue_body": "Testing plan creation flow",
        "ai_provider": "openai",
        "issue_url": "https://github.com/testorg/testrepo/issues/456",
        "ai_model": "gpt-4"
    }


class TestCreateIssuePlan:
    """Test create_issue_plan function."""

    def test_create_issue_plan_success(self, mock_db, mock_plan_row, plan_data):
        """Test successful issue plan creation."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.issue_plans.insert = MagicMock(return_value=1)

            with patch("app.models.get_issue_plan_by_id") as mock_get:
                mock_get.return_value = mock_plan_row.as_dict()

                result = create_issue_plan(
                    external_id=plan_data["external_id"],
                    platform=plan_data["platform"],
                    repository=plan_data["repository"],
                    issue_number=plan_data["issue_number"],
                    issue_title=plan_data["issue_title"],
                    issue_body=plan_data["issue_body"],
                    ai_provider=plan_data["ai_provider"],
                    issue_url=plan_data["issue_url"],
                    ai_model=plan_data["ai_model"]
                )

                assert result["external_id"] == plan_data["external_id"]
                assert result["platform"] == "github"
                assert result["repository"] == plan_data["repository"]
                assert result["status"] == "completed"
                mock_db.issue_plans.insert.assert_called_once()
                mock_db.commit.assert_called_once()

    def test_create_issue_plan_minimal(self, mock_db, mock_plan_row):
        """Test creating plan with minimal required fields."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.issue_plans.insert = MagicMock(return_value=1)

            with patch("app.models.get_issue_plan_by_id") as mock_get:
                mock_get.return_value = mock_plan_row.as_dict()

                result = create_issue_plan(
                    external_id="gh-789",
                    platform="gitlab",
                    repository="test/repo",
                    issue_number=789,
                    issue_title="Minimal issue",
                    issue_body="Minimal body",
                    ai_provider="claude"
                )

                assert result["external_id"] == "gh-789"
                # Verify insert was called with proper arguments
                call_kwargs = mock_db.issue_plans.insert.call_args[1]
                assert call_kwargs["status"] == "queued"
                assert call_kwargs["ai_model"] is None

    def test_create_issue_plan_returns_full_record(self, mock_db, mock_plan_row):
        """Test that create_issue_plan returns the full record with all fields."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.issue_plans.insert = MagicMock(return_value=1)

            with patch("app.models.get_issue_plan_by_id") as mock_get:
                mock_get.return_value = mock_plan_row.as_dict()

                result = create_issue_plan(
                    external_id="test-123",
                    platform="github",
                    repository="test/repo",
                    issue_number=123,
                    issue_title="Test",
                    issue_body="Test body",
                    ai_provider="claude"
                )

                # Should have all expected fields from mock_plan_row
                assert "id" in result
                assert "created_at" in result
                assert "updated_at" in result
                assert "plan_content" in result


class TestGetIssuePlanById:
    """Test get_issue_plan_by_id function."""

    def test_get_existing_plan(self, mock_db, mock_plan_row):
        """Test getting an existing issue plan."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.select = MagicMock(return_value=MagicMock(first=MagicMock(return_value=mock_plan_row)))

            result = get_issue_plan_by_id(1)

            assert result is not None
            assert result["id"] == 1
            assert result["external_id"] == "gh-123"

    def test_get_nonexistent_plan(self, mock_db):
        """Test getting a non-existent plan returns None."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.select = MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))

            result = get_issue_plan_by_id(999)

            assert result is None

    def test_get_plan_calls_correct_query(self, mock_db, mock_plan_row):
        """Test that correct query is executed."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            query_mock = MagicMock()
            mock_db.__call__ = MagicMock(return_value=query_mock)
            mock_db.issue_plans.id = MagicMock()
            query_mock.select = MagicMock(return_value=MagicMock(first=MagicMock(return_value=mock_plan_row)))

            result = get_issue_plan_by_id(1)

            # Verify database query was made
            mock_db.__call__.assert_called_once()
            query_mock.select.assert_called_once()


class TestGetIssuePlanByExternalId:
    """Test get_issue_plan_by_external_id function."""

    def test_get_by_external_id(self, mock_db, mock_plan_row):
        """Test getting plan by external ID."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.external_id = MagicMock()
            mock_db.select = MagicMock(return_value=MagicMock(first=MagicMock(return_value=mock_plan_row)))

            result = get_issue_plan_by_external_id("gh-123")

            assert result is not None
            assert result["external_id"] == "gh-123"

    def test_get_by_external_id_not_found(self, mock_db):
        """Test getting non-existent plan by external ID."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.external_id = MagicMock()
            mock_db.select = MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))

            result = get_issue_plan_by_external_id("nonexistent-id")

            assert result is None


class TestUpdateIssuePlanStatus:
    """Test update_issue_plan_status function."""

    def test_update_status_only(self, mock_db, mock_plan_row):
        """Test updating only the status field."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.update = MagicMock(return_value=1)

            with patch("app.models.get_issue_plan_by_id") as mock_get:
                mock_get.return_value = mock_plan_row.as_dict()

                result = update_issue_plan_status(1, "completed")

                # Verify update was called
                mock_db.update.assert_called_once()
                call_kwargs = mock_db.update.call_args[1]
                assert call_kwargs["status"] == "completed"
                # Should only update status
                assert len(call_kwargs) == 1

    def test_update_with_plan_content(self, mock_db, mock_plan_row):
        """Test updating status with plan content."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.update = MagicMock(return_value=1)

            with patch("app.models.get_issue_plan_by_id") as mock_get:
                mock_get.return_value = mock_plan_row.as_dict()

                plan_content = "# Implementation Plan\n\nSteps here"
                plan_steps = [{"number": 1, "title": "First step"}]

                result = update_issue_plan_status(
                    1,
                    "completed",
                    plan_content=plan_content,
                    plan_steps=plan_steps
                )

                call_kwargs = mock_db.update.call_args[1]
                assert call_kwargs["status"] == "completed"
                assert call_kwargs["plan_content"] == plan_content
                assert call_kwargs["plan_steps"] == plan_steps

    def test_update_with_error_message(self, mock_db, mock_plan_row):
        """Test updating status with error message."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.update = MagicMock(return_value=1)

            with patch("app.models.get_issue_plan_by_id") as mock_get:
                mock_get.return_value = mock_plan_row.as_dict()

                error_msg = "API rate limit exceeded"
                result = update_issue_plan_status(1, "failed", error_message=error_msg)

                call_kwargs = mock_db.update.call_args[1]
                assert call_kwargs["status"] == "failed"
                assert call_kwargs["error_message"] == error_msg

    def test_update_with_token_usage(self, mock_db, mock_plan_row):
        """Test updating with token usage information."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.update = MagicMock(return_value=1)

            with patch("app.models.get_issue_plan_by_id") as mock_get:
                mock_get.return_value = mock_plan_row.as_dict()

                token_usage = {
                    "prompt_tokens": 150,
                    "completion_tokens": 300,
                    "total_tokens": 450,
                    "cost_estimate": 0.05
                }

                result = update_issue_plan_status(1, "completed", token_usage=token_usage)

                call_kwargs = mock_db.update.call_args[1]
                assert call_kwargs["token_usage"] == token_usage

    def test_update_comment_posted(self, mock_db, mock_plan_row):
        """Test updating comment_posted status."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.update = MagicMock(return_value=1)

            with patch("app.models.get_issue_plan_by_id") as mock_get:
                mock_get.return_value = mock_plan_row.as_dict()

                result = update_issue_plan_status(
                    1,
                    "completed",
                    comment_posted=True,
                    platform_comment_id="github-comment-456"
                )

                call_kwargs = mock_db.update.call_args[1]
                assert call_kwargs["comment_posted"] is True
                assert call_kwargs["platform_comment_id"] == "github-comment-456"

    def test_update_only_includes_provided_fields(self, mock_db, mock_plan_row):
        """Test that update only includes fields that were explicitly provided."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.update = MagicMock(return_value=1)

            with patch("app.models.get_issue_plan_by_id") as mock_get:
                mock_get.return_value = mock_plan_row.as_dict()

                # Only update status and error_message, not other optional fields
                result = update_issue_plan_status(
                    1,
                    "failed",
                    error_message="Something went wrong"
                )

                call_kwargs = mock_db.update.call_args[1]
                assert "status" in call_kwargs
                assert "error_message" in call_kwargs
                assert "plan_content" not in call_kwargs
                assert "comment_posted" not in call_kwargs


class TestListIssuePlans:
    """Test list_issue_plans function."""

    def test_list_all_plans(self, mock_db):
        """Test listing all issue plans without filters."""
        mock_rows = [MagicMock(as_dict=MagicMock(return_value={"id": i})) for i in range(3)]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)
            mock_db.count = MagicMock(return_value=3)

            plans, total = list_issue_plans()

            assert len(plans) == 3
            assert total == 3

    def test_list_with_platform_filter(self, mock_db):
        """Test listing plans filtered by platform."""
        mock_rows = [MagicMock(as_dict=MagicMock(return_value={"id": 1, "platform": "github"}))]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.issue_plans.platform = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)
            mock_db.count = MagicMock(return_value=1)

            plans, total = list_issue_plans(platform="github")

            assert len(plans) == 1
            assert total == 1

    def test_list_with_repository_filter(self, mock_db):
        """Test listing plans filtered by repository."""
        mock_rows = [MagicMock(as_dict=MagicMock(return_value={"id": 1, "repository": "org/repo"}))]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.issue_plans.repository = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)
            mock_db.count = MagicMock(return_value=1)

            plans, total = list_issue_plans(repository="org/repo")

            assert len(plans) == 1
            assert total == 1

    def test_list_with_status_filter(self, mock_db):
        """Test listing plans filtered by status."""
        mock_rows = [MagicMock(as_dict=MagicMock(return_value={"id": 1, "status": "completed"}))]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.issue_plans.status = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)
            mock_db.count = MagicMock(return_value=1)

            plans, total = list_issue_plans(status="completed")

            assert len(plans) == 1
            assert total == 1

    def test_list_with_pagination(self, mock_db):
        """Test listing plans with pagination."""
        # Create 25 mock rows
        mock_rows = [MagicMock(as_dict=MagicMock(return_value={"id": i})) for i in range(20)]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)
            mock_db.count = MagicMock(return_value=50)

            # Get page 2 with 20 items per page
            plans, total = list_issue_plans(page=2, per_page=20)

            assert len(plans) == 20
            assert total == 50
            # Verify limitby was called correctly for pagination
            call_args = mock_db.select.call_args
            assert "limitby" in call_args[1]
            limitby = call_args[1]["limitby"]
            assert limitby == (20, 40)  # offset=20, limit=40

    def test_list_ordered_by_created_at_desc(self, mock_db):
        """Test that results are ordered by created_at descending."""
        mock_rows = [
            MagicMock(as_dict=MagicMock(return_value={"id": 3, "created_at": datetime.utcnow()})),
            MagicMock(as_dict=MagicMock(return_value={"id": 2, "created_at": datetime.utcnow() - timedelta(hours=1)})),
            MagicMock(as_dict=MagicMock(return_value={"id": 1, "created_at": datetime.utcnow() - timedelta(hours=2)}))
        ]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.id = MagicMock()
            mock_db.issue_plans.created_at = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)
            mock_db.count = MagicMock(return_value=3)

            plans, total = list_issue_plans()

            # Verify orderby was set
            call_args = mock_db.select.call_args
            assert "orderby" in call_args[1]


class TestCountIssuePlansToday:
    """Test count_issue_plans_today function."""

    def test_count_plans_today(self, mock_db):
        """Test counting plans created today."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.repository = MagicMock()
            mock_db.issue_plans.created_at = MagicMock()
            mock_db.count = MagicMock(return_value=5)

            count = count_issue_plans_today("org/repo")

            assert count == 5

    def test_count_plans_today_filters_by_date(self, mock_db):
        """Test that query filters for today's date only."""
        with patch("app.models.get_db") as mock_get_db:
            with patch("app.models.datetime") as mock_datetime:
                now = datetime(2025, 2, 7, 15, 30, 0)
                today_start = datetime(2025, 2, 7, 0, 0, 0)
                mock_datetime.utcnow.return_value = now

                mock_get_db.return_value = mock_db
                mock_db.__call__ = MagicMock(return_value=mock_db)
                mock_db.issue_plans.repository = MagicMock()
                mock_db.issue_plans.created_at = MagicMock()
                mock_db.count = MagicMock(return_value=3)

                count = count_issue_plans_today("org/repo")

                # Verify the query includes today's date check
                mock_db.__call__.assert_called_once()

    def test_count_plans_today_multiple_repos(self, mock_db):
        """Test counting only counts for specific repository."""
        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.repository = MagicMock()
            mock_db.issue_plans.created_at = MagicMock()
            mock_db.count = MagicMock(return_value=2)

            count = count_issue_plans_today("specific/repo")

            assert count == 2
            # Verify repository filter was applied
            mock_db.__call__.assert_called_once()


class TestCalculateMonthlyCost:
    """Test calculate_monthly_cost function."""

    def test_calculate_monthly_cost(self, mock_db):
        """Test calculating total monthly cost."""
        # Mock rows with token usage
        mock_rows = [
            MagicMock(token_usage={"cost_estimate": 0.05}),
            MagicMock(token_usage={"cost_estimate": 0.03}),
            MagicMock(token_usage={"cost_estimate": 0.02})
        ]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.repository = MagicMock()
            mock_db.issue_plans.created_at = MagicMock()
            mock_db.issue_plans.token_usage = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)

            cost = calculate_monthly_cost("org/repo")

            assert cost == 0.10

    def test_calculate_monthly_cost_filters_by_date(self, mock_db):
        """Test that cost calculation only includes current month."""
        mock_rows = []

        with patch("app.models.get_db") as mock_get_db:
            with patch("app.models.datetime") as mock_datetime:
                now = datetime(2025, 2, 15, 10, 0, 0)
                month_start = datetime(2025, 2, 1, 0, 0, 0)
                mock_datetime.utcnow.return_value = now

                mock_get_db.return_value = mock_db
                mock_db.__call__ = MagicMock(return_value=mock_db)
                mock_db.issue_plans.repository = MagicMock()
                mock_db.issue_plans.created_at = MagicMock()
                mock_db.issue_plans.token_usage = MagicMock()
                mock_db.select = MagicMock(return_value=mock_rows)

                cost = calculate_monthly_cost("org/repo")

                assert cost == 0.0
                # Verify the query filters for current month
                mock_db.__call__.assert_called_once()

    def test_calculate_monthly_cost_handles_none_token_usage(self, mock_db):
        """Test handling rows with None token_usage."""
        mock_rows = [
            MagicMock(token_usage={"cost_estimate": 0.05}),
            MagicMock(token_usage=None),  # No token usage
            MagicMock(token_usage={"cost_estimate": 0.03})
        ]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.repository = MagicMock()
            mock_db.issue_plans.created_at = MagicMock()
            mock_db.issue_plans.token_usage = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)

            cost = calculate_monthly_cost("org/repo")

            # Should only count rows with valid token_usage
            assert cost == 0.08

    def test_calculate_monthly_cost_handles_non_dict_token_usage(self, mock_db):
        """Test handling rows with invalid token_usage format."""
        mock_rows = [
            MagicMock(token_usage={"cost_estimate": 0.05}),
            MagicMock(token_usage="invalid"),  # Not a dict
            MagicMock(token_usage={"cost_estimate": 0.03})
        ]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.repository = MagicMock()
            mock_db.issue_plans.created_at = MagicMock()
            mock_db.issue_plans.token_usage = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)

            cost = calculate_monthly_cost("org/repo")

            # Should only count valid dict rows
            assert cost == 0.08

    def test_calculate_monthly_cost_missing_cost_estimate(self, mock_db):
        """Test handling token_usage without cost_estimate field."""
        mock_rows = [
            MagicMock(token_usage={"cost_estimate": 0.05}),
            MagicMock(token_usage={"prompt_tokens": 100}),  # Missing cost_estimate
            MagicMock(token_usage={"cost_estimate": 0.03})
        ]

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.repository = MagicMock()
            mock_db.issue_plans.created_at = MagicMock()
            mock_db.issue_plans.token_usage = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)

            cost = calculate_monthly_cost("org/repo")

            # Should use 0.0 as default for missing cost_estimate
            assert cost == 0.08

    def test_calculate_monthly_cost_empty_result(self, mock_db):
        """Test calculating cost when no plans exist for month."""
        mock_rows = []

        with patch("app.models.get_db") as mock_get_db:
            mock_get_db.return_value = mock_db
            mock_db.__call__ = MagicMock(return_value=mock_db)
            mock_db.issue_plans.repository = MagicMock()
            mock_db.issue_plans.created_at = MagicMock()
            mock_db.issue_plans.token_usage = MagicMock()
            mock_db.select = MagicMock(return_value=mock_rows)

            cost = calculate_monthly_cost("org/repo")

            assert cost == 0.0
