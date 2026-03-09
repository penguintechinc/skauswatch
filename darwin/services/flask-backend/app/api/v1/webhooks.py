"""Webhook Handlers - GitHub/GitLab webhook endpoints."""

import hashlib
import hmac
from flask import Blueprint, jsonify, request

from ...models import (
    create_review,
    get_repo_config,
    get_db,
    create_issue_plan,
    count_issue_plans_today,
    calculate_monthly_cost,
    resolve_platform_user,
)
from ...middleware.license import check_feature_available, FEATURE_ISSUE_AUTOPILOT

webhooks_bp = Blueprint("webhooks", __name__, url_prefix="/api/v1/webhooks")


def verify_github_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature."""
    if not signature:
        return False

    # GitHub uses sha256= prefix
    if not signature.startswith("sha256="):
        return False

    expected_hash = hmac.new(
        secret.encode(),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        signature[7:],  # Remove 'sha256=' prefix
        expected_hash,
    )


def verify_gitlab_signature(payload_body: bytes, signature: str, secret: str) -> bool:
    """Verify GitLab webhook signature."""
    if not signature:
        return False

    expected_hash = hmac.new(
        secret.encode(),
        payload_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature, expected_hash)


@webhooks_bp.route("/github", methods=["POST"])
def github_webhook():
    """GitHub webhook handler."""
    # Get headers
    signature = request.headers.get("X-Hub-Signature-256", "")
    event_type = request.headers.get("X-GitHub-Event", "")

    # Get payload
    payload_body = request.get_data()
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    # Extract repo info
    repo_name = data.get("repository", {}).get("full_name", "")
    if not repo_name:
        return jsonify({"error": "Repository information missing"}), 400

    # Get repository config
    repo_config = get_repo_config("github", repo_name)
    if not repo_config:
        return jsonify({"message": "Repository not configured"}), 200

    # Verify signature
    webhook_secret = repo_config.get("webhook_secret", "")
    if webhook_secret and not verify_github_signature(payload_body, signature, webhook_secret):
        return jsonify({"error": "Invalid signature"}), 401

    # Skip if repository is not enabled
    if not repo_config.get("enabled"):
        return jsonify({"message": "Repository disabled"}), 200

    # Resolve sender to Darwin user (if platform identity mapping exists)
    sender = data.get("sender", {})
    sender_login = sender.get("login", "")
    triggered_by = None
    if sender_login:
        darwin_user = resolve_platform_user("github", sender_login)
        if darwin_user:
            triggered_by = darwin_user.get("id")

    # Extract tenant/team context from repo config
    webhook_tenant_id = repo_config.get("tenant_id")
    webhook_team_id = repo_config.get("team_id")
    webhook_repo_id = repo_config.get("id")

    # Process pull request events
    if event_type == "pull_request":
        pr_data = data.get("pull_request", {})
        action = data.get("action", "")

        # Trigger review on open if configured
        if action == "opened" and repo_config.get("review_on_open"):
            review = create_review(
                external_id=f"github-{pr_data.get('id')}",
                platform="github",
                repository=repo_name,
                pull_request_id=pr_data.get("number"),
                pull_request_url=pr_data.get("html_url"),
                base_sha=data.get("pull_request", {}).get("base", {}).get("sha"),
                head_sha=data.get("pull_request", {}).get("head", {}).get("sha"),
                review_type="differential",
                categories=repo_config.get("default_categories", ["security", "best_practices"]),
                ai_provider=repo_config.get("default_ai_provider", "claude"),
                triggered_by=triggered_by,
                tenant_id=webhook_tenant_id,
                team_id=webhook_team_id,
                repo_id=webhook_repo_id,
            )
            return jsonify({"message": "Review created", "review_id": review.get("id")}), 202

        # Trigger review on synchronize if configured
        if action == "synchronize" and repo_config.get("review_on_sync"):
            review = create_review(
                external_id=f"github-{pr_data.get('id')}-sync",
                platform="github",
                repository=repo_name,
                pull_request_id=pr_data.get("number"),
                pull_request_url=pr_data.get("html_url"),
                base_sha=data.get("pull_request", {}).get("base", {}).get("sha"),
                head_sha=data.get("pull_request", {}).get("head", {}).get("sha"),
                review_type="differential",
                categories=repo_config.get("default_categories", ["security", "best_practices"]),
                ai_provider=repo_config.get("default_ai_provider", "claude"),
                triggered_by=triggered_by,
                tenant_id=webhook_tenant_id,
                team_id=webhook_team_id,
                repo_id=webhook_repo_id,
            )
            return jsonify({"message": "Review created", "review_id": review.get("id")}), 202

    # Process issue events
    if event_type == "issues":
        issue_data = data.get("issue", {})
        action = data.get("action", "")

        # Only process newly opened issues
        if action == "opened" and repo_config.get("auto_plan_on_issue"):
            # Check license feature
            if not check_feature_available(FEATURE_ISSUE_AUTOPILOT):
                return jsonify({"message": "Issue autopilot requires license upgrade"}), 403

            # Check rate limits if configured
            daily_limit = repo_config.get("issue_plan_daily_limit")
            if daily_limit is not None:
                today_count = count_issue_plans_today(repo_name)
                if today_count >= daily_limit:
                    return jsonify({"message": f"Daily limit exceeded ({daily_limit})"}), 429

            cost_limit = repo_config.get("issue_plan_cost_limit_usd")
            if cost_limit is not None:
                monthly_cost = calculate_monthly_cost(repo_name)
                if monthly_cost >= cost_limit:
                    return jsonify({"message": f"Monthly cost limit exceeded (${cost_limit})"}), 429

            # Create issue plan
            plan = create_issue_plan(
                external_id=f"github-issue-{issue_data.get('id')}",
                platform="github",
                repository=repo_name,
                issue_number=issue_data.get("number"),
                issue_url=issue_data.get("html_url"),
                issue_title=issue_data.get("title", ""),
                issue_body=issue_data.get("body", ""),
                ai_provider=repo_config.get("issue_plan_provider") or repo_config.get("default_ai_provider", "claude"),
                ai_model=repo_config.get("issue_plan_model"),
            )

            # Queue Celery worker task
            from ...tasks.plan_worker import process_issue_plan
            process_issue_plan.delay(plan.get("id"))

            return jsonify({"message": "Issue plan created", "plan_id": plan.get("id")}), 202

    return jsonify({"message": "Webhook received"}), 200


@webhooks_bp.route("/gitlab", methods=["POST"])
def gitlab_webhook():
    """GitLab webhook handler."""
    # Get headers
    signature = request.headers.get("X-Gitlab-Token", "")
    event_type = request.headers.get("X-Gitlab-Event", "")

    # Get payload
    payload_body = request.get_data()
    data = request.get_json()

    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    # Extract repo info
    project = data.get("project", {})
    repo_name = project.get("path_with_namespace", "")
    if not repo_name:
        return jsonify({"error": "Repository information missing"}), 400

    # Get repository config
    repo_config = get_repo_config("gitlab", repo_name)
    if not repo_config:
        return jsonify({"message": "Repository not configured"}), 200

    # Verify signature (GitLab uses token in header)
    webhook_secret = repo_config.get("webhook_secret", "")
    if webhook_secret and signature != webhook_secret:
        return jsonify({"error": "Invalid signature"}), 401

    # Skip if repository is not enabled
    if not repo_config.get("enabled"):
        return jsonify({"message": "Repository disabled"}), 200

    # Resolve sender to Darwin user (if platform identity mapping exists)
    gl_user = data.get("user", {})
    gl_username = gl_user.get("username", "")
    triggered_by = None
    if gl_username:
        darwin_user = resolve_platform_user("gitlab", gl_username)
        if darwin_user:
            triggered_by = darwin_user.get("id")

    # Extract tenant/team context from repo config
    webhook_tenant_id = repo_config.get("tenant_id")
    webhook_team_id = repo_config.get("team_id")
    webhook_repo_id = repo_config.get("id")

    # Process merge request events
    if event_type == "Merge Request Hook":
        mr_data = data.get("object_attributes", {})
        action = mr_data.get("action", "")

        # Trigger review on open if configured
        if action == "open" and repo_config.get("review_on_open"):
            review = create_review(
                external_id=f"gitlab-{mr_data.get('id')}",
                platform="gitlab",
                repository=repo_name,
                pull_request_id=mr_data.get("iid"),
                pull_request_url=mr_data.get("url"),
                base_sha=mr_data.get("target_branch"),
                head_sha=mr_data.get("source_branch"),
                review_type="differential",
                categories=repo_config.get("default_categories", ["security", "best_practices"]),
                ai_provider=repo_config.get("default_ai_provider", "claude"),
                triggered_by=triggered_by,
                tenant_id=webhook_tenant_id,
                team_id=webhook_team_id,
                repo_id=webhook_repo_id,
            )
            return jsonify({"message": "Review created", "review_id": review.get("id")}), 202

        # Trigger review on update if configured
        if action == "update" and repo_config.get("review_on_sync"):
            review = create_review(
                external_id=f"gitlab-{mr_data.get('id')}-update",
                platform="gitlab",
                repository=repo_name,
                pull_request_id=mr_data.get("iid"),
                pull_request_url=mr_data.get("url"),
                base_sha=mr_data.get("target_branch"),
                head_sha=mr_data.get("source_branch"),
                review_type="differential",
                categories=repo_config.get("default_categories", ["security", "best_practices"]),
                ai_provider=repo_config.get("default_ai_provider", "claude"),
                triggered_by=triggered_by,
                tenant_id=webhook_tenant_id,
                team_id=webhook_team_id,
                repo_id=webhook_repo_id,
            )
            return jsonify({"message": "Review created", "review_id": review.get("id")}), 202

    # Process issue events
    if event_type == "Issue Hook":
        issue_data = data.get("object_attributes", {})
        action = issue_data.get("action", "")

        # Only process newly opened issues
        if action == "open" and repo_config.get("auto_plan_on_issue"):
            # Check license feature
            if not check_feature_available(FEATURE_ISSUE_AUTOPILOT):
                return jsonify({"message": "Issue autopilot requires license upgrade"}), 403

            # Check rate limits if configured
            daily_limit = repo_config.get("issue_plan_daily_limit")
            if daily_limit is not None:
                today_count = count_issue_plans_today(repo_name)
                if today_count >= daily_limit:
                    return jsonify({"message": f"Daily limit exceeded ({daily_limit})"}), 429

            cost_limit = repo_config.get("issue_plan_cost_limit_usd")
            if cost_limit is not None:
                monthly_cost = calculate_monthly_cost(repo_name)
                if monthly_cost >= cost_limit:
                    return jsonify({"message": f"Monthly cost limit exceeded (${cost_limit})"}), 429

            # Create issue plan
            plan = create_issue_plan(
                external_id=f"gitlab-issue-{issue_data.get('id')}",
                platform="gitlab",
                repository=repo_name,
                issue_number=issue_data.get("iid"),
                issue_url=issue_data.get("url"),
                issue_title=issue_data.get("title", ""),
                issue_body=issue_data.get("description", ""),
                ai_provider=repo_config.get("issue_plan_provider") or repo_config.get("default_ai_provider", "claude"),
                ai_model=repo_config.get("issue_plan_model"),
            )

            # Queue Celery worker task
            from ...tasks.plan_worker import process_issue_plan
            process_issue_plan.delay(plan.get("id"))

            return jsonify({"message": "Issue plan created", "plan_id": plan.get("id")}), 202

    return jsonify({"message": "Webhook received"}), 200


@webhooks_bp.route("/github/test", methods=["POST"])
def github_webhook_test():
    """Test GitHub webhook configuration."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    repo_name = data.get("repository")
    if not repo_name:
        return jsonify({"error": "Repository name required"}), 400

    repo_config = get_repo_config("github", repo_name)

    return jsonify({
        "configured": repo_config is not None,
        "enabled": repo_config.get("enabled") if repo_config else False,
        "repository": repo_name,
    }), 200


@webhooks_bp.route("/gitlab/test", methods=["POST"])
def gitlab_webhook_test():
    """Test GitLab webhook configuration."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    repo_name = data.get("repository")
    if not repo_name:
        return jsonify({"error": "Repository name required"}), 400

    repo_config = get_repo_config("gitlab", repo_name)

    return jsonify({
        "configured": repo_config is not None,
        "enabled": repo_config.get("enabled") if repo_config else False,
        "repository": repo_name,
    }), 200
