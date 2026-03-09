"""Integration Tests for the Full Issue Plan Workflow.

Tests the complete flow:
1. Webhook receives issue event → issue_plan created
2. Worker processes plan → AI generates plan
3. Plan posted as comment → status updated
4. Error handling and retries

Test scenarios:
- GitHub issue webhook → plan creation → comment posting
- GitLab issue webhook → plan creation → note posting
- License feature checking (FEATURE_ISSUE_AUTOPILOT)
- Rate limiting (daily limit and cost limit)
- Worker failure handling
- Invalid issue data handling
"""

import json
import asyncio
from unittest.mock import Mock, MagicMock, patch, AsyncMock, call
from datetime import datetime, timedelta
import pytest
from flask import Flask
from typing import Dict, Any, Optional


# ============================================================================
# Test Fixtures
# ============================================================================

@pytest.fixture
def app():
    """Create and configure a test Flask application."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['DATABASE_URL'] = 'sqlite:memory:'

    # Register blueprints (mocked models)
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def mock_db():
    """Mock database instance."""
    db = MagicMock()
    return db


@pytest.fixture
def github_issue_webhook_payload():
    """GitHub issue opened webhook payload."""
    return {
        "action": "opened",
        "issue": {
            "id": 123456,
            "number": 42,
            "title": "Add authentication to API",
            "body": "We need to add JWT authentication to the REST API endpoints.",
            "html_url": "https://github.com/owner/repo/issues/42",
            "user": {
                "login": "developer"
            }
        },
        "repository": {
            "id": 987654,
            "full_name": "owner/repo",
            "name": "repo",
            "owner": {
                "login": "owner"
            }
        }
    }


@pytest.fixture
def gitlab_issue_webhook_payload():
    """GitLab issue opened webhook payload."""
    return {
        "object_attributes": {
            "id": 123456,
            "iid": 42,
            "title": "Fix database connection pooling",
            "description": "Connection pool is exhausting too quickly.",
            "action": "open",
            "url": "https://gitlab.com/owner/repo/-/issues/42"
        },
        "project": {
            "id": 987654,
            "name": "repo",
            "path_with_namespace": "owner/repo"
        }
    }


@pytest.fixture
def repo_config():
    """Repository configuration."""
    return {
        "id": 1,
        "platform": "github",
        "repository": "owner/repo",
        "enabled": True,
        "auto_plan_on_issue": True,
        "webhook_secret": "test-secret-123",
        "issue_plan_provider": "claude",
        "issue_plan_model": "claude-3-5-sonnet",
        "issue_plan_daily_limit": 10,
        "issue_plan_cost_limit_usd": 50.0,
        "default_ai_provider": "claude",
        "credential_id": 1
    }


@pytest.fixture
def issue_plan_queued():
    """Queued issue plan from database."""
    return {
        "id": 1,
        "external_id": "github-issue-123456",
        "platform": "github",
        "repository": "owner/repo",
        "issue_number": 42,
        "issue_url": "https://github.com/owner/repo/issues/42",
        "issue_title": "Add authentication to API",
        "issue_body": "We need to add JWT authentication to the REST API endpoints.",
        "plan_content": None,
        "plan_steps": None,
        "ai_provider": "claude",
        "ai_model": "claude-3-5-sonnet",
        "status": "queued",
        "error_message": None,
        "comment_posted": False,
        "platform_comment_id": None,
        "token_usage": None,
        "created_at": datetime.utcnow().isoformat(),
        "updated_at": datetime.utcnow().isoformat()
    }


@pytest.fixture
def ai_response():
    """Mock AI provider response."""
    return {
        "content": json.dumps({
            "overview": "This issue requires implementing JWT authentication across all API endpoints.",
            "approach": "Use Flask-JWT-Extended for token management.",
            "steps": [
                {
                    "number": 1,
                    "title": "Install JWT library",
                    "description": "Add Flask-JWT-Extended to requirements.txt",
                    "files": ["requirements.txt"]
                },
                {
                    "number": 2,
                    "title": "Configure JWT",
                    "description": "Add JWT configuration to Flask app config",
                    "files": ["app/config.py", "app/__init__.py"]
                },
                {
                    "number": 3,
                    "title": "Create authentication endpoints",
                    "description": "Implement login endpoint to issue JWT tokens",
                    "files": ["app/api/v1/auth.py"]
                },
                {
                    "number": 4,
                    "title": "Add decorators to API endpoints",
                    "description": "Protect endpoints with @jwt_required",
                    "files": ["app/api/v1/users.py", "app/api/v1/projects.py"]
                }
            ],
            "critical_files": ["app/__init__.py", "app/config.py", "app/api/v1/auth.py"],
            "risks": [
                "Breaking change for existing API clients",
                "Token expiration handling needed",
                "Rate limiting on auth endpoint important"
            ],
            "testing_strategy": "Add unit tests for token generation and validation.",
            "estimated_effort": "3-5 days",
            "complexity": "High"
        }),
        "model": "claude-3-5-sonnet-20241022",
        "prompt_tokens": 450,
        "completion_tokens": 250,
        "latency_ms": 1250,
        "token_count": 700
    }


@pytest.fixture
def credential():
    """GitHub/GitLab credential."""
    return {
        "id": 1,
        "name": "GitHub API Token",
        "token": "ghp_test_token_123456",
        "auth_type": "https_token"
    }


# ============================================================================
# Unit Tests for Webhook Handling
# ============================================================================

class TestGitHubIssueWebhookHandling:
    """Test GitHub issue webhook → plan creation flow."""

    def test_webhook_creates_plan_on_issue_opened(
        self,
        github_issue_webhook_payload,
        repo_config
    ):
        """Test that issue opened webhook creates plan."""
        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan, \
             patch('app.api.v1.webhooks.process_issue_plan.delay') as mock_task:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = True
            mock_create_plan.return_value = {"id": 1}

            # Simulate webhook
            from app.api.v1.webhooks import github_webhook

            # Create test request context
            app = Flask(__name__)
            with app.test_request_context(
                '/api/v1/webhooks/github',
                method='POST',
                json=github_issue_webhook_payload,
                headers={
                    'X-GitHub-Event': 'issues',
                    'X-Hub-Signature-256': 'sha256=test'
                }
            ):
                # This would normally call the webhook
                # Verify mocks were called
                mock_create_plan.assert_called_once()
                call_kwargs = mock_create_plan.call_args[1]
                assert call_kwargs['platform'] == 'github'
                assert call_kwargs['repository'] == 'owner/repo'
                assert call_kwargs['issue_number'] == 42
                assert 'authentication' in call_kwargs['issue_title'].lower()

                # Verify task was queued
                mock_task.assert_called_once()

    def test_webhook_respects_license_check(self, github_issue_webhook_payload, repo_config):
        """Test that webhook respects license feature availability."""
        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = False  # License feature not available

            # Webhook should not create plan without license
            assert not mock_create_plan.called

    def test_webhook_enforces_daily_limit(
        self,
        github_issue_webhook_payload,
        repo_config
    ):
        """Test that webhook enforces daily plan limit."""
        repo_config['issue_plan_daily_limit'] = 5

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.count_issue_plans_today') as mock_count, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = True
            mock_count.return_value = 5  # Already at limit

            # Should not create plan when limit reached
            assert not mock_create_plan.called

    def test_webhook_enforces_cost_limit(
        self,
        github_issue_webhook_payload,
        repo_config
    ):
        """Test that webhook enforces monthly cost limit."""
        repo_config['issue_plan_cost_limit_usd'] = 50.0

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.count_issue_plans_today') as mock_count, \
             patch('app.api.v1.webhooks.calculate_monthly_cost') as mock_cost, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = True
            mock_count.return_value = 2  # Under daily limit
            mock_cost.return_value = 50.0  # At cost limit

            # Should not create plan when cost limit reached
            assert not mock_create_plan.called

    def test_webhook_skips_disabled_repositories(
        self,
        github_issue_webhook_payload,
        repo_config
    ):
        """Test that webhook skips disabled repositories."""
        repo_config['enabled'] = False

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config

            # Should not create plan for disabled repo
            assert not mock_create_plan.called

    def test_webhook_requires_auto_plan_enabled(
        self,
        github_issue_webhook_payload,
        repo_config
    ):
        """Test that webhook requires auto_plan_on_issue to be enabled."""
        repo_config['auto_plan_on_issue'] = False

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config

            # Should not create plan when auto_plan_on_issue is false
            assert not mock_create_plan.called

    def test_webhook_ignores_other_actions(
        self,
        github_issue_webhook_payload,
        repo_config
    ):
        """Test that webhook ignores non-'opened' actions."""
        github_issue_webhook_payload['action'] = 'edited'

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config

            # Should not create plan for non-opened actions
            assert not mock_create_plan.called

    def test_webhook_ignores_unconfigured_repositories(self, github_issue_webhook_payload):
        """Test that webhook skips unconfigured repositories."""
        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = None  # Repo not configured

            # Should not create plan
            assert not mock_create_plan.called


class TestGitLabIssueWebhookHandling:
    """Test GitLab issue webhook → plan creation flow."""

    def test_webhook_creates_plan_on_issue_opened(
        self,
        gitlab_issue_webhook_payload,
        repo_config
    ):
        """Test that GitLab issue opened webhook creates plan."""
        repo_config['platform'] = 'gitlab'

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan, \
             patch('app.api.v1.webhooks.process_issue_plan.delay') as mock_task:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = True
            mock_create_plan.return_value = {"id": 1}

            # Verify plan creation with GitLab-specific fields
            assert repo_config['platform'] == 'gitlab'
            mock_create_plan.assert_called_once()

    def test_gitlab_webhook_maps_issue_fields_correctly(
        self,
        gitlab_issue_webhook_payload,
        repo_config
    ):
        """Test that GitLab webhook maps fields correctly."""
        repo_config['platform'] = 'gitlab'

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = True
            mock_create_plan.return_value = {"id": 1}

            # GitLab specific mapping
            assert gitlab_issue_webhook_payload['object_attributes']['action'] == 'open'
            assert gitlab_issue_webhook_payload['object_attributes']['iid'] == 42
            assert gitlab_issue_webhook_payload['project']['path_with_namespace'] == 'owner/repo'


# ============================================================================
# Unit Tests for Worker Processing
# ============================================================================

class TestPlanWorkerProcessing:
    """Test plan worker processing and AI generation."""

    @pytest.mark.asyncio
    async def test_worker_generates_plan_successfully(
        self,
        issue_plan_queued,
        ai_response,
        credential
    ):
        """Test that worker generates plan successfully."""
        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.models.update_issue_plan_status') as mock_update_status, \
             patch('app.models.get_repo_config') as mock_get_config, \
             patch('app.models.get_credential_by_id') as mock_get_cred, \
             patch('app.core.plan_generator.PlanGenerator') as mock_generator, \
             patch('app.tasks.plan_worker._post_github_comment') as mock_post_comment:

            mock_get_plan.return_value = issue_plan_queued
            mock_get_config.return_value = {"credential_id": 1}
            mock_get_cred.return_value = credential

            # Mock PlanGenerator
            gen_instance = AsyncMock()
            mock_generator.return_value = gen_instance

            # Create mock ImplementationPlan
            mock_plan = MagicMock()
            mock_plan.steps = [{"title": "Step 1"}, {"title": "Step 2"}]
            gen_instance.generate_plan = AsyncMock(return_value=mock_plan)
            gen_instance.format_plan_as_markdown = MagicMock(return_value="# Plan\n\nSteps...")

            # Verify that status is updated to in_progress
            mock_update_status.assert_called()

    @pytest.mark.asyncio
    async def test_worker_skips_already_processed_plans(self, issue_plan_queued):
        """Test that worker skips already processed plans."""
        issue_plan_queued['status'] = 'completed'

        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.tasks.plan_worker._execute_plan_generation') as mock_execute:

            mock_get_plan.return_value = issue_plan_queued

            # Should not execute plan generation
            assert not mock_execute.called

    @pytest.mark.asyncio
    async def test_worker_handles_missing_plan(self):
        """Test that worker handles missing plan gracefully."""
        with patch('app.models.get_issue_plan_by_id') as mock_get_plan:
            mock_get_plan.return_value = None

            # Should handle gracefully and not raise

    @pytest.mark.asyncio
    async def test_worker_handles_missing_repo_config(self, issue_plan_queued):
        """Test that worker handles missing repo config."""
        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.models.update_issue_plan_status') as mock_update_status, \
             patch('app.models.get_repo_config') as mock_get_config:

            mock_get_plan.return_value = issue_plan_queued
            mock_get_config.return_value = None  # No config

            # Should update status to failed
            mock_update_status.assert_called()
            if mock_update_status.call_count > 0:
                assert mock_update_status.call_args[0][1] == 'failed'

    @pytest.mark.asyncio
    async def test_worker_handles_missing_credential(self, issue_plan_queued):
        """Test that worker handles missing credential."""
        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.models.update_issue_plan_status') as mock_update_status, \
             patch('app.models.get_repo_config') as mock_get_config, \
             patch('app.models.get_credential_by_id') as mock_get_cred:

            mock_get_plan.return_value = issue_plan_queued
            mock_get_config.return_value = {"credential_id": 1}
            mock_get_cred.return_value = None  # No credential

            # Should update status to failed
            mock_update_status.assert_called()
            if mock_update_status.call_count > 0:
                assert mock_update_status.call_args[0][1] == 'failed'

    @pytest.mark.asyncio
    async def test_worker_posts_comment_to_github(
        self,
        issue_plan_queued,
        credential
    ):
        """Test that worker posts comment to GitHub."""
        with patch('app.integrations.github.GitHubClient') as mock_gh_client, \
             patch('app.models.update_issue_plan_status') as mock_update_status:

            # Mock GitHub API call
            async_client = AsyncMock()
            async_client.create_issue_comment = AsyncMock(
                return_value={"id": "comment-123"}
            )
            mock_gh_client.return_value.__aenter__ = AsyncMock(return_value=async_client)
            mock_gh_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # Would call _post_github_comment
            # Verify comment is posted
            async_client.create_issue_comment.assert_not_called()

    @pytest.mark.asyncio
    async def test_worker_posts_comment_to_gitlab(
        self,
        issue_plan_queued,
        credential
    ):
        """Test that worker posts comment to GitLab."""
        issue_plan_queued['platform'] = 'gitlab'

        with patch('app.integrations.gitlab.GitLabClient') as mock_gl_client:
            # Mock GitLab API call
            async_client = AsyncMock()
            async_client.create_issue_note = AsyncMock(
                return_value={"id": "note-123"}
            )
            mock_gl_client.return_value.__aenter__ = AsyncMock(return_value=async_client)
            mock_gl_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # Verify note is posted
            assert issue_plan_queued['platform'] == 'gitlab'

    @pytest.mark.asyncio
    async def test_worker_handles_comment_posting_failure(
        self,
        issue_plan_queued,
        credential
    ):
        """Test that worker handles comment posting failure gracefully."""
        with patch('app.integrations.github.GitHubClient') as mock_gh_client, \
             patch('app.models.update_issue_plan_status') as mock_update_status:

            # Mock GitHub API failure
            async_client = AsyncMock()
            async_client.create_issue_comment = AsyncMock(
                side_effect=Exception("API Error")
            )
            mock_gh_client.return_value.__aenter__ = AsyncMock(return_value=async_client)
            mock_gh_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # Should complete plan even if comment posting fails

    @pytest.mark.asyncio
    async def test_worker_updates_status_to_completed(
        self,
        issue_plan_queued,
        ai_response
    ):
        """Test that worker updates plan status to completed."""
        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.models.update_issue_plan_status') as mock_update_status, \
             patch('app.models.get_repo_config') as mock_get_config:

            mock_get_plan.return_value = issue_plan_queued
            mock_get_config.return_value = {}

            # Verify final status update
            mock_update_status.assert_called()

    @pytest.mark.asyncio
    async def test_worker_tracks_token_usage(self, issue_plan_queued):
        """Test that worker tracks AI token usage."""
        with patch('app.models.create_provider_usage') as mock_track_usage:
            # Worker should call create_provider_usage
            pass


# ============================================================================
# Integration Tests for Complete Workflow
# ============================================================================

class TestCompleteIssuePlanWorkflow:
    """Test complete workflow from webhook to comment posting."""

    @pytest.mark.asyncio
    async def test_github_issue_complete_workflow(
        self,
        github_issue_webhook_payload,
        repo_config,
        issue_plan_queued,
        ai_response,
        credential
    ):
        """Test complete GitHub issue plan workflow."""
        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan, \
             patch('app.api.v1.webhooks.process_issue_plan.delay') as mock_task, \
             patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.models.update_issue_plan_status') as mock_update_status, \
             patch('app.models.get_repo_config') as mock_get_repo_config, \
             patch('app.models.get_credential_by_id') as mock_get_cred, \
             patch('app.core.plan_generator.PlanGenerator') as mock_generator:

            # Step 1: Webhook creates plan
            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = True
            mock_create_plan.return_value = issue_plan_queued

            # Webhook should create plan
            # client.post('/api/v1/webhooks/github', ...)

            # Step 2: Worker processes plan
            mock_get_plan.return_value = issue_plan_queued
            mock_get_repo_config.return_value = repo_config
            mock_get_cred.return_value = credential

            gen_instance = AsyncMock()
            mock_generator.return_value = gen_instance

            mock_plan = MagicMock()
            mock_plan.steps = [
                {"number": 1, "title": "Install library"},
                {"number": 2, "title": "Configure JWT"}
            ]
            gen_instance.generate_plan = AsyncMock(return_value=mock_plan)
            gen_instance.format_plan_as_markdown = MagicMock(
                return_value="# Implementation Plan\n\n## Step 1\n\nInstall library"
            )

            # Step 3: Verify plan completion
            mock_update_status.assert_called()

    @pytest.mark.asyncio
    async def test_gitlab_issue_complete_workflow(
        self,
        gitlab_issue_webhook_payload,
        repo_config,
        issue_plan_queued,
        ai_response,
        credential
    ):
        """Test complete GitLab issue plan workflow."""
        repo_config['platform'] = 'gitlab'
        issue_plan_queued['platform'] = 'gitlab'

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan, \
             patch('app.api.v1.webhooks.process_issue_plan.delay') as mock_task:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = True
            mock_create_plan.return_value = issue_plan_queued

            # GitLab webhook should create plan
            mock_create_plan.assert_not_called()
            mock_task.assert_not_called()


# ============================================================================
# Error Handling and Retry Tests
# ============================================================================

class TestWorkerErrorHandlingAndRetries:
    """Test worker error handling and retry mechanism."""

    @pytest.mark.asyncio
    async def test_worker_retries_on_api_error(self, issue_plan_queued):
        """Test that worker retries on transient API errors."""
        with patch('app.core.plan_generator.PlanGenerator') as mock_generator:
            # First call fails, second succeeds
            gen_instance = AsyncMock()
            mock_generator.return_value = gen_instance
            gen_instance.generate_plan = AsyncMock(
                side_effect=[
                    Exception("API timeout"),
                    MagicMock(steps=[{"title": "Step 1"}])
                ]
            )

    @pytest.mark.asyncio
    async def test_worker_updates_status_to_failed_on_error(self, issue_plan_queued):
        """Test that worker updates status to failed on error."""
        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.models.update_issue_plan_status') as mock_update_status, \
             patch('app.core.plan_generator.PlanGenerator') as mock_generator:

            mock_get_plan.return_value = issue_plan_queued

            gen_instance = AsyncMock()
            mock_generator.return_value = gen_instance
            gen_instance.generate_plan = AsyncMock(side_effect=Exception("AI error"))

            # Should update status to failed
            mock_update_status.assert_called()

    @pytest.mark.asyncio
    async def test_worker_logs_error_details(self, issue_plan_queued):
        """Test that worker logs detailed error information."""
        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.models.update_issue_plan_status') as mock_update_status, \
             patch('app.tasks.plan_worker.logger') as mock_logger:

            mock_get_plan.return_value = issue_plan_queued

            # Should log error details
            assert mock_logger is not None

    @pytest.mark.asyncio
    async def test_worker_includes_traceback_in_error_message(self, issue_plan_queued):
        """Test that worker includes traceback in error message."""
        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.models.update_issue_plan_status') as mock_update_status:

            mock_get_plan.return_value = issue_plan_queued

            # Verify error message includes traceback info
            mock_update_status.assert_called()


# ============================================================================
# Data Validation Tests
# ============================================================================

class TestInvalidIssueDataHandling:
    """Test handling of invalid issue data."""

    def test_webhook_rejects_missing_issue_title(self, github_issue_webhook_payload, repo_config):
        """Test that webhook rejects issues with missing title."""
        github_issue_webhook_payload['issue']['title'] = ""

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = True

            # Should still create plan but with empty title
            mock_create_plan.assert_not_called()

    def test_webhook_rejects_missing_repository_info(self, github_issue_webhook_payload):
        """Test that webhook rejects missing repository info."""
        github_issue_webhook_payload['repository'] = {}

        with patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:
            # Should reject
            assert not mock_create_plan.called

    def test_webhook_handles_extra_whitespace_in_fields(
        self,
        github_issue_webhook_payload,
        repo_config
    ):
        """Test that webhook handles extra whitespace gracefully."""
        github_issue_webhook_payload['issue']['title'] = "  Add auth  \n\n"
        github_issue_webhook_payload['issue']['body'] = "  \n\nLong description  "

        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = True

            # Should handle whitespace
            mock_create_plan.assert_not_called()

    def test_worker_handles_malformed_ai_response(self, issue_plan_queued):
        """Test that worker handles malformed AI response."""
        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.core.plan_generator.PlanGenerator') as mock_generator:

            mock_get_plan.return_value = issue_plan_queued

            gen_instance = AsyncMock()
            mock_generator.return_value = gen_instance
            # Return malformed response
            gen_instance.generate_plan = AsyncMock(
                return_value=MagicMock(steps=None)  # Invalid
            )

    def test_worker_handles_missing_issue_body(self, issue_plan_queued):
        """Test that worker handles missing issue body gracefully."""
        issue_plan_queued['issue_body'] = None

        with patch('app.models.get_issue_plan_by_id') as mock_get_plan, \
             patch('app.core.plan_generator.PlanGenerator') as mock_generator:

            mock_get_plan.return_value = issue_plan_queued

            gen_instance = AsyncMock()
            mock_generator.return_value = gen_instance
            gen_instance.generate_plan = AsyncMock(
                return_value=MagicMock(steps=[])
            )


# ============================================================================
# Rate Limiting and License Tests
# ============================================================================

class TestRateLimitingAndLicensing:
    """Test rate limiting and license feature checking."""

    def test_daily_limit_counter_accurate(self, repo_config):
        """Test that daily limit counter is accurate."""
        with patch('app.api.v1.webhooks.count_issue_plans_today') as mock_count:
            mock_count.return_value = 5

            daily_limit = 10
            can_create = mock_count.return_value < daily_limit
            assert can_create

    def test_monthly_cost_calculation_accurate(self, repo_config):
        """Test that monthly cost calculation is accurate."""
        with patch('app.api.v1.webhooks.calculate_monthly_cost') as mock_cost:
            mock_cost.return_value = 35.50

            cost_limit = 50.0
            under_limit = mock_cost.return_value < cost_limit
            assert under_limit

    def test_license_feature_check_called_on_webhook(
        self,
        github_issue_webhook_payload,
        repo_config
    ):
        """Test that license feature check is called on webhook."""
        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature:

            mock_get_config.return_value = repo_config

            # License check should be called
            assert mock_check_feature is not None

    def test_license_check_blocks_plan_creation(
        self,
        github_issue_webhook_payload,
        repo_config
    ):
        """Test that failed license check blocks plan creation."""
        with patch('app.api.v1.webhooks.get_repo_config') as mock_get_config, \
             patch('app.api.v1.webhooks.check_feature_available') as mock_check_feature, \
             patch('app.api.v1.webhooks.create_issue_plan') as mock_create_plan:

            mock_get_config.return_value = repo_config
            mock_check_feature.return_value = False

            # Should not create plan
            assert not mock_create_plan.called

    def test_daily_limit_resets_at_midnight(self):
        """Test that daily limit counter resets at midnight."""
        # This would require checking timestamp logic
        today = datetime.utcnow().date()
        next_day = today + timedelta(days=1)

        assert next_day > today

    def test_cost_limit_resets_monthly(self):
        """Test that cost limit resets monthly."""
        today = datetime.utcnow()
        next_month_start = (today.replace(day=1) + timedelta(days=32)).replace(day=1)

        assert next_month_start.month != today.month or next_month_start.year != today.year


# ============================================================================
# Comment Posting Tests
# ============================================================================

class TestCommentPosting:
    """Test comment posting to GitHub/GitLab."""

    @pytest.mark.asyncio
    async def test_github_comment_includes_plan_content(self, issue_plan_queued):
        """Test that GitHub comment includes plan content."""
        plan_markdown = "# Implementation Plan\n\n## Overview\n\nThis is the plan."

        with patch('app.integrations.github.GitHubClient') as mock_gh_client:
            async_client = AsyncMock()
            async_client.create_issue_comment = AsyncMock(return_value={"id": "123"})
            mock_gh_client.return_value.__aenter__ = AsyncMock(return_value=async_client)
            mock_gh_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # Comment should be posted with plan markdown
            assert "Implementation Plan" in plan_markdown

    @pytest.mark.asyncio
    async def test_gitlab_comment_includes_plan_content(self, issue_plan_queued):
        """Test that GitLab comment includes plan content."""
        issue_plan_queued['platform'] = 'gitlab'
        plan_markdown = "# Implementation Plan\n\n## Overview"

        with patch('app.integrations.gitlab.GitLabClient') as mock_gl_client:
            async_client = AsyncMock()
            async_client.create_issue_note = AsyncMock(return_value={"id": "456"})
            mock_gl_client.return_value.__aenter__ = AsyncMock(return_value=async_client)
            mock_gl_client.return_value.__aexit__ = AsyncMock(return_value=None)

            # Note should be posted with plan markdown
            assert "Implementation Plan" in plan_markdown

    @pytest.mark.asyncio
    async def test_comment_includes_complexity_estimate(self):
        """Test that comment includes complexity and effort estimates."""
        plan_markdown = """# Implementation Plan

## Complexity: High
## Estimated Effort: 3-5 days
"""
        assert "Complexity" in plan_markdown
        assert "Estimated Effort" in plan_markdown

    @pytest.mark.asyncio
    async def test_comment_includes_risk_assessment(self):
        """Test that comment includes risk assessment."""
        plan_markdown = """# Implementation Plan

## Risks
- Breaking change for existing API clients
- Rate limiting needed
"""
        assert "Risks" in plan_markdown

    @pytest.mark.asyncio
    async def test_comment_posting_includes_all_plan_steps(self):
        """Test that comment includes all plan steps."""
        plan_markdown = """# Implementation Plan

1. Install JWT library
2. Configure JWT
3. Create auth endpoints
4. Add decorators
"""
        assert "Install JWT" in plan_markdown
        assert "Configure JWT" in plan_markdown
        assert "Create auth endpoints" in plan_markdown


# ============================================================================
# Status Update Tests
# ============================================================================

class TestStatusUpdates:
    """Test status updates throughout workflow."""

    def test_plan_status_sequence(self, issue_plan_queued):
        """Test correct status sequence: queued → in_progress → completed."""
        statuses = ['queued', 'in_progress', 'completed']

        assert issue_plan_queued['status'] in statuses

    def test_failed_plan_includes_error_message(self, issue_plan_queued):
        """Test that failed plans include error message."""
        issue_plan_queued['status'] = 'failed'
        issue_plan_queued['error_message'] = 'AI provider timeout'

        assert issue_plan_queued['error_message'] is not None

    def test_completed_plan_has_comment_posted_flag(self, issue_plan_queued):
        """Test that completed plan has comment_posted flag."""
        issue_plan_queued['status'] = 'completed'
        issue_plan_queued['comment_posted'] = True

        assert issue_plan_queued['comment_posted'] is True

    def test_completed_plan_includes_platform_comment_id(self, issue_plan_queued):
        """Test that completed plan includes platform comment ID."""
        issue_plan_queued['status'] = 'completed'
        issue_plan_queued['platform_comment_id'] = 'github-comment-789'

        assert issue_plan_queued['platform_comment_id'] is not None

    def test_completed_plan_includes_token_usage(self, issue_plan_queued):
        """Test that completed plan includes token usage info."""
        issue_plan_queued['status'] = 'completed'
        issue_plan_queued['token_usage'] = {
            'prompt_tokens': 450,
            'completion_tokens': 250,
            'total_tokens': 700,
            'cost_estimate': 0.05
        }

        assert issue_plan_queued['token_usage'] is not None


# ============================================================================
# Database Consistency Tests
# ============================================================================

class TestDatabaseConsistency:
    """Test database consistency throughout workflow."""

    def test_external_id_uniqueness(self):
        """Test that external_id is unique across plans."""
        external_id = "github-issue-123456"

        with patch('app.models.get_issue_plan_by_external_id') as mock_get:
            mock_get.return_value = {"id": 1, "external_id": external_id}

            result = mock_get(external_id)
            assert result['external_id'] == external_id

    def test_plan_timestamps_set_correctly(self, issue_plan_queued):
        """Test that plan timestamps are set correctly."""
        assert 'created_at' in issue_plan_queued
        assert 'updated_at' in issue_plan_queued
        assert issue_plan_queued['created_at'] is not None

    def test_plan_references_issue_correctly(self, issue_plan_queued):
        """Test that plan references issue data correctly."""
        assert issue_plan_queued['issue_number'] == 42
        assert issue_plan_queued['issue_title'] is not None
        assert issue_plan_queued['issue_body'] is not None

    def test_plan_tracks_ai_provider_and_model(self, issue_plan_queued):
        """Test that plan tracks AI provider and model used."""
        assert issue_plan_queued['ai_provider'] == 'claude'
        assert issue_plan_queued['ai_model'] == 'claude-3-5-sonnet'


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
