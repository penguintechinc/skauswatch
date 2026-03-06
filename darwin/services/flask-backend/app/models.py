"""PyDAL Database Models."""

from datetime import datetime
from typing import Optional

from flask import Flask, g
from pydal import DAL, Field
from pydal.validators import IS_EMAIL, IS_IN_SET, IS_NOT_EMPTY, IS_JSON

from .config import Config

# Valid roles for the application
VALID_ROLES = ["admin", "maintainer", "viewer"]


def init_db(app: Flask) -> DAL:
    """Initialize database connection for runtime operations.

    NOTE: Tables should already exist from SQLAlchemy/Alembic migrations.
    PyDAL is used for runtime queries only, NOT for schema creation.
    """
    db_uri = Config.get_db_uri()

    db = DAL(
        db_uri,
        pool_size=Config.DB_POOL_SIZE,
        migrate=False,  # Disable migrations - use Alembic instead
        fake_migrate=True,  # Read existing schema without creating tables
        check_reserved=[],  # SQLAlchemy handles reserved keywords with quoting
        lazy_tables=False,
    )

    # Define tenants table - Multi-tenancy support
    db.define_table(
        "tenants",
        Field("name", "string", length=255, unique=True, requires=IS_NOT_EMPTY()),
        Field("slug", "string", length=128, unique=True, requires=IS_NOT_EMPTY()),
        Field("description", "text"),
        Field("is_active", "boolean", default=True),
        Field("max_users", "integer", default=0),
        Field("max_repositories", "integer", default=0),
        Field("max_teams", "integer", default=0),
        Field("settings", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(name)s",
    )

    # Define users table
    db.define_table(
        "users",
        Field("email", "string", length=255, unique=True, requires=[
            IS_NOT_EMPTY(error_message="Email is required"),
            IS_EMAIL(error_message="Invalid email format"),
        ]),
        Field("password_hash", "string", length=255, requires=IS_NOT_EMPTY()),
        Field("full_name", "string", length=255),
        Field("role", "string", length=50, default="viewer", requires=IS_IN_SET(
            VALID_ROLES,
            error_message=f"Role must be one of: {', '.join(VALID_ROLES)}"
        )),
        Field("global_role", "string", length=50, default="viewer"),
        Field("default_tenant_id", "reference tenants"),
        Field("is_active", "boolean", default=True),
        Field("email_confirmed", "boolean", default=False),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define refresh tokens table for token invalidation
    db.define_table(
        "refresh_tokens",
        Field("user_id", "reference users", requires=IS_NOT_EMPTY()),
        Field("token", "string", length=500, unique=True),
        Field("expires_at", "datetime"),
        Field("created_at", "datetime", default=datetime.utcnow),
    )

    # Define teams table - Team-based access control
    db.define_table(
        "teams",
        Field("tenant_id", "reference tenants", requires=IS_NOT_EMPTY()),
        Field("name", "string", length=255, requires=IS_NOT_EMPTY()),
        Field("slug", "string", length=128, requires=IS_NOT_EMPTY()),
        Field("description", "text"),
        Field("is_active", "boolean", default=True),
        Field("is_default", "boolean", default=False),
        Field("settings", "json", default={}),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(name)s",
    )

    # Define custom_roles table - RBAC with custom role definitions
    db.define_table(
        "custom_roles",
        Field("tenant_id", "reference tenants"),
        Field("team_id", "reference teams"),
        Field("name", "string", length=128, requires=IS_NOT_EMPTY()),
        Field("slug", "string", length=128, requires=IS_NOT_EMPTY()),
        Field("description", "text"),
        Field("role_level", "string", length=64),
        Field("scopes", "json", requires=IS_NOT_EMPTY()),
        Field("is_active", "boolean", default=True),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(name)s",
    )

    # Define tenant_members table - Tenant membership and roles
    db.define_table(
        "tenant_members",
        Field("tenant_id", "reference tenants", requires=IS_NOT_EMPTY()),
        Field("user_id", "reference users", requires=IS_NOT_EMPTY()),
        Field("role", "string", length=50, default="viewer"),
        Field("custom_role_id", "reference custom_roles"),
        Field("scopes", "json", default=[]),
        Field("is_active", "boolean", default=True),
        Field("joined_at", "datetime", default=datetime.utcnow),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define team_members table - Team membership and roles
    db.define_table(
        "team_members",
        Field("team_id", "reference teams", requires=IS_NOT_EMPTY()),
        Field("user_id", "reference users", requires=IS_NOT_EMPTY()),
        Field("role", "string", length=50, default="viewer"),
        Field("custom_role_id", "reference custom_roles"),
        Field("scopes", "json", default=[]),
        Field("is_active", "boolean", default=True),
        Field("joined_at", "datetime", default=datetime.utcnow),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define scopes table - Permission scope definitions
    db.define_table(
        "scopes",
        Field("permission_scope", "string", length=128, unique=True, requires=IS_NOT_EMPTY()),
        Field("description", "text"),
        Field("category", "string", length=64),
        Field("scope_level", "string", length=64),
        Field("created_at", "datetime", default=datetime.utcnow),
    )

    # Define platform_identities table - Map external platform users to Darwin users
    db.define_table(
        "platform_identities",
        Field("user_id", "reference users", requires=IS_NOT_EMPTY()),
        Field("platform", "string", length=64, requires=IS_IN_SET(["github", "gitlab"])),
        Field("platform_username", "string", length=255, requires=IS_NOT_EMPTY()),
        Field("platform_user_id", "string", length=128),
        Field("platform_avatar_url", "string", length=512),
        Field("is_verified", "boolean", default=False),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define reviews table - Main review requests
    db.define_table(
        "reviews",
        Field("external_id", "string", length=64, unique=True),
        Field("platform", "string", requires=IS_IN_SET(["github", "gitlab"])),
        Field("repository", "string", length=255, requires=IS_NOT_EMPTY()),
        Field("triggered_by", "reference users"),
        Field("tenant_id", "reference tenants"),
        Field("team_id", "reference teams"),
        Field("repo_id", "reference repo_configs"),
        Field("pull_request_id", "integer"),
        Field("pull_request_url", "string", length=512),
        Field("base_sha", "string", length=64),
        Field("head_sha", "string", length=64),
        Field("review_type", "string", requires=IS_IN_SET(["differential", "whole"])),
        Field("categories", "json"),
        Field("ai_provider", "string", length=64),
        Field("status", "string", default="queued", requires=IS_IN_SET(
            ["queued", "in_progress", "completed", "failed", "cancelled"]
        )),
        Field("error_message", "text"),
        Field("files_reviewed", "integer", default=0),
        Field("comments_posted", "integer", default=0),
        Field("started_at", "datetime"),
        Field("completed_at", "datetime"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define review_comments table - Individual review comments
    db.define_table(
        "review_comments",
        Field("review_id", "reference reviews", requires=IS_NOT_EMPTY()),
        Field("file_path", "string", length=512),
        Field("line_start", "integer"),
        Field("line_end", "integer"),
        Field("category", "string", requires=IS_IN_SET(
            ["security", "best_practices", "framework", "iac"]
        )),
        Field("severity", "string", requires=IS_IN_SET(
            ["critical", "major", "minor", "suggestion"]
        )),
        Field("title", "string", length=255),
        Field("body", "text"),
        Field("suggestion", "text"),
        Field("source", "string", length=64),
        Field("linter_rule_id", "string", length=128),
        Field("platform_comment_id", "string", length=128),
        Field("status", "string", default="open", requires=IS_IN_SET(
            ["open", "acknowledged", "fixed", "wont_fix", "false_positive"]
        )),
        Field("posted_at", "datetime"),
        Field("created_at", "datetime", default=datetime.utcnow),
    )

    # Define review_detections table - Detected languages/frameworks per review
    db.define_table(
        "review_detections",
        Field("review_id", "reference reviews", requires=IS_NOT_EMPTY()),
        Field("detection_type", "string"),
        Field("name", "string", length=128),
        Field("confidence", "double"),
        Field("file_count", "integer"),
    )

    # Define repo_configs table - Per-repository configuration
    db.define_table(
        "repo_configs",
        Field("tenant_id", "reference tenants"),
        Field("team_id", "reference teams"),
        Field("owner_id", "reference users"),
        Field("platform", "string", requires=IS_IN_SET(["github", "gitlab"])),
        Field("repository", "string", length=255, requires=IS_NOT_EMPTY()),
        Field("enabled", "boolean", default=True),
        Field("auto_review", "boolean", default=True),
        Field("review_on_open", "boolean", default=True),
        Field("review_on_sync", "boolean", default=False),
        Field("default_categories", "json"),
        Field("default_ai_provider", "string", length=64),
        Field("ignored_paths", "json"),
        Field("custom_rules", "json"),
        Field("webhook_secret", "string", length=255),
        Field("auto_plan_on_issue", "boolean", default=False),
        Field("issue_plan_provider", "string", length=64),
        Field("issue_plan_model", "string", length=128),
        Field("issue_plan_daily_limit", "integer"),
        Field("issue_plan_cost_limit_usd", "double"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(platform)s/%(repository)s",
    )

    # Define repository_members table - Repository-level access control
    db.define_table(
        "repository_members",
        Field("repository_id", "reference repo_configs"),
        Field("user_id", "reference users"),
        Field("role", "string", length=50, default="viewer"),
        Field("custom_role_id", "reference custom_roles"),
        Field("scopes", "json", default=[]),
        Field("personal_token_id", "reference git_credentials"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define provider_usage table - AI token usage tracking
    db.define_table(
        "provider_usage",
        Field("review_id", "reference reviews"),
        Field("provider", "string", length=64),
        Field("model", "string", length=128),
        Field("prompt_tokens", "integer"),
        Field("completion_tokens", "integer"),
        Field("total_tokens", "integer"),
        Field("latency_ms", "integer"),
        Field("cost_estimate", "double"),
        Field("created_at", "datetime", default=datetime.utcnow),
    )

    # Define git_credentials table - Secure credential storage
    db.define_table(
        "git_credentials",
        Field("name", "string", length=128),
        Field("git_url_pattern", "string", length=255),
        Field("auth_type", "string", requires=IS_IN_SET(["https_token", "ssh_key"])),
        Field("encrypted_credential", "blob"),
        Field("ssh_key_passphrase", "blob"),
        Field("created_by", "reference users"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define ai_model_config table - AI model preferences per category
    db.define_table(
        "ai_model_config",
        Field("config_name", "string", length=128, unique=True, default="default"),
        Field("security_enabled", "boolean", default=True),
        Field("security_model", "string", length=128, default="granite-code:34b"),
        Field("best_practices_enabled", "boolean", default=True),
        Field("best_practices_model", "string", length=128, default="llama3.3:70b"),
        Field("framework_enabled", "boolean", default=True),
        Field("framework_model", "string", length=128, default="codestral:22b"),
        Field("iac_enabled", "boolean", default=True),
        Field("iac_model", "string", length=128, default="granite-code:20b"),
        Field("fallback_model", "string", length=128, default="starcoder2:15b"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(config_name)s",
    )

    # Define license_policies table - License policy configuration
    db.define_table(
        "license_policies",
        Field("license_name", "string", length=255, unique=True, requires=IS_NOT_EMPTY()),
        Field("policy", "string", default="allowed", requires=IS_IN_SET(
            ["allowed", "blocked", "review_required"]
        )),
        Field("actions", "json", default=["warn"]),
        Field("description", "text"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(license_name)s",
    )

    # Define license_detections table - Detected licenses per review
    db.define_table(
        "license_detections",
        Field("review_id", "reference reviews", requires=IS_NOT_EMPTY()),
        Field("package_name", "string", length=255),
        Field("package_version", "string", length=128),
        Field("license_name", "string", length=255),
        Field("license_source", "string", length=64),
        Field("file_path", "string", length=512),
        Field("confidence", "double"),
        Field("policy_violation", "boolean", default=False),
        Field("created_at", "datetime", default=datetime.utcnow),
    )

    # Define license_violations table - License policy violations
    db.define_table(
        "license_violations",
        Field("review_id", "reference reviews", requires=IS_NOT_EMPTY()),
        Field("detection_id", "reference license_detections"),
        Field("license_name", "string", length=255),
        Field("package_name", "string", length=255),
        Field("policy", "string"),
        Field("severity", "string", default="warning", requires=IS_IN_SET(
            ["critical", "warning", "info"]
        )),
        Field("actions_taken", "json"),
        Field("status", "string", default="open", requires=IS_IN_SET(
            ["open", "acknowledged", "resolved", "suppressed"]
        )),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define installation_config table - Installation-level configuration
    db.define_table(
        "installation_config",
        Field("config_key", "string", length=128, unique=True, requires=IS_NOT_EMPTY()),
        Field("config_value", "text"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
        format="%(config_key)s",
    )

    # Define issue_plans table - AI-generated implementation plans for issues
    db.define_table(
        "issue_plans",
        Field("external_id", "string", length=128, unique=True, requires=IS_NOT_EMPTY()),
        Field("platform", "string", requires=IS_IN_SET(["github", "gitlab"])),
        Field("repository", "string", length=255, requires=IS_NOT_EMPTY()),
        Field("issue_number", "integer"),
        Field("issue_url", "string", length=512),
        Field("issue_title", "string", length=512),
        Field("issue_body", "text"),
        Field("plan_content", "text"),
        Field("plan_steps", "json"),
        Field("ai_provider", "string", length=64),
        Field("ai_model", "string", length=128),
        Field("status", "string", default="queued", requires=IS_IN_SET(
            ["queued", "in_progress", "completed", "failed"]
        )),
        Field("error_message", "text"),
        Field("comment_posted", "boolean", default=False),
        Field("platform_comment_id", "string", length=128),
        Field("token_usage", "json"),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Commit table definitions
    db.commit()

    # Store db instance in app
    app.config["db"] = db

    return db


def get_db() -> DAL:
    """Get database connection for current request context."""
    from flask import current_app

    if "db" not in g:
        g.db = current_app.config.get("db")
    return g.db


def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email address."""
    db = get_db()
    user = db(db.users.email == email).select().first()
    return user.as_dict() if user else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    """Get user by ID."""
    db = get_db()
    user = db(db.users.id == user_id).select().first()
    return user.as_dict() if user else None


def create_user(email: str, password_hash: str, full_name: str = "",
                role: str = "viewer", global_role: str = "viewer",
                default_tenant_id: Optional[int] = None) -> dict:
    """Create a new user."""
    db = get_db()
    user_id = db.users.insert(
        email=email,
        password_hash=password_hash,
        full_name=full_name,
        role=role,
        global_role=global_role,
        default_tenant_id=default_tenant_id,
        is_active=True,
    )
    db.commit()
    return get_user_by_id(user_id)


def update_user(user_id: int, **kwargs) -> Optional[dict]:
    """Update user by ID."""
    db = get_db()

    # Filter allowed fields
    allowed_fields = {"email", "password_hash", "full_name", "role", "global_role",
                      "default_tenant_id", "is_active"}
    update_data = {k: v for k, v in kwargs.items() if k in allowed_fields}

    if not update_data:
        return get_user_by_id(user_id)

    db(db.users.id == user_id).update(**update_data)
    db.commit()
    return get_user_by_id(user_id)


def delete_user(user_id: int) -> bool:
    """Delete user by ID."""
    db = get_db()
    deleted = db(db.users.id == user_id).delete()
    db.commit()
    return deleted > 0


def list_users(page: int = 1, per_page: int = 20) -> tuple[list[dict], int]:
    """List users with pagination."""
    db = get_db()
    offset = (page - 1) * per_page

    users = db(db.users).select(
        orderby=db.users.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(db.users).count()

    return [u.as_dict() for u in users], total


def store_refresh_token(user_id: int, token_hash: str, expires_at: datetime) -> int:
    """Store a refresh token hash."""
    db = get_db()
    token_id = db.refresh_tokens.insert(
        user_id=user_id,
        token=token_hash,
        expires_at=expires_at,
    )
    db.commit()
    return token_id


def revoke_refresh_token(token_hash: str) -> bool:
    """Revoke a refresh token by deleting it."""
    db = get_db()
    deleted = db(db.refresh_tokens.token == token_hash).delete()
    db.commit()
    return deleted > 0


def is_refresh_token_valid(token_hash: str) -> bool:
    """Check if refresh token is valid (exists and not expired)."""
    db = get_db()
    token = db(
        (db.refresh_tokens.token == token_hash) &
        (db.refresh_tokens.expires_at > datetime.utcnow())
    ).select().first()
    return token is not None


def revoke_all_user_tokens(user_id: int) -> int:
    """Revoke all refresh tokens for a user."""
    db = get_db()
    updated = db(db.refresh_tokens.user_id == user_id).update(revoked=True)
    db.commit()
    return updated


# ===========================
# Reviews Helper Functions
# ===========================


def create_review(external_id: str, platform: str, repository: str,
                  review_type: str, categories: list, ai_provider: str,
                  pull_request_id: Optional[int] = None,
                  pull_request_url: Optional[str] = None,
                  base_sha: Optional[str] = None,
                  head_sha: Optional[str] = None,
                  triggered_by: Optional[int] = None,
                  tenant_id: Optional[int] = None,
                  team_id: Optional[int] = None,
                  repo_id: Optional[int] = None) -> dict:
    """Create a new review request."""
    db = get_db()
    review_id = db.reviews.insert(
        external_id=external_id,
        platform=platform,
        repository=repository,
        triggered_by=triggered_by,
        tenant_id=tenant_id,
        team_id=team_id,
        repo_id=repo_id,
        pull_request_id=pull_request_id,
        pull_request_url=pull_request_url,
        base_sha=base_sha,
        head_sha=head_sha,
        review_type=review_type,
        categories=categories,
        ai_provider=ai_provider,
        status="queued",
    )
    db.commit()
    return get_review_by_id(review_id)


def get_review_by_id(review_id: int) -> Optional[dict]:
    """Get review by ID."""
    db = get_db()
    review = db(db.reviews.id == review_id).select().first()
    return review.as_dict() if review else None


def get_review_by_external_id(external_id: str) -> Optional[dict]:
    """Get review by external ID."""
    db = get_db()
    review = db(db.reviews.external_id == external_id).select().first()
    return review.as_dict() if review else None


def update_review_status(review_id: int, status: str,
                        error_message: Optional[str] = None,
                        files_reviewed: Optional[int] = None,
                        comments_posted: Optional[int] = None) -> Optional[dict]:
    """Update review status and metrics."""
    db = get_db()
    update_data = {"status": status}

    if error_message is not None:
        update_data["error_message"] = error_message
    if files_reviewed is not None:
        update_data["files_reviewed"] = files_reviewed
    if comments_posted is not None:
        update_data["comments_posted"] = comments_posted

    # Set timestamps based on status
    if status == "in_progress":
        update_data["started_at"] = datetime.utcnow()
    elif status in ["completed", "failed", "cancelled"]:
        update_data["completed_at"] = datetime.utcnow()

    db(db.reviews.id == review_id).update(**update_data)
    db.commit()
    return get_review_by_id(review_id)


def list_reviews(platform: Optional[str] = None,
                repository: Optional[str] = None,
                status: Optional[str] = None,
                tenant_id: Optional[int] = None,
                page: int = 1,
                per_page: int = 20) -> tuple[list[dict], int]:
    """List reviews with optional filtering and pagination."""
    db = get_db()
    offset = (page - 1) * per_page

    # Build query
    query = db.reviews.id > 0
    if platform:
        query &= db.reviews.platform == platform
    if repository:
        query &= db.reviews.repository == repository
    if status:
        query &= db.reviews.status == status
    if tenant_id:
        query &= db.reviews.tenant_id == tenant_id

    reviews = db(query).select(
        orderby=~db.reviews.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    return [r.as_dict() for r in reviews], total


# ===========================
# Review Comments Helper Functions
# ===========================


def create_comment(review_id: int, file_path: str, line_start: int,
                  line_end: int, category: str, severity: str,
                  title: str, body: str, source: str,
                  suggestion: Optional[str] = None,
                  linter_rule_id: Optional[str] = None) -> dict:
    """Create a new review comment."""
    db = get_db()
    comment_id = db.review_comments.insert(
        review_id=review_id,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        category=category,
        severity=severity,
        title=title,
        body=body,
        source=source,
        suggestion=suggestion,
        linter_rule_id=linter_rule_id,
    )
    db.commit()
    comment = db(db.review_comments.id == comment_id).select().first()
    return comment.as_dict() if comment else None


def get_comments_by_review(review_id: int,
                          category: Optional[str] = None,
                          severity: Optional[str] = None) -> list[dict]:
    """Get all comments for a review with optional filtering."""
    db = get_db()

    query = db.review_comments.review_id == review_id
    if category:
        query &= db.review_comments.category == category
    if severity:
        query &= db.review_comments.severity == severity

    comments = db(query).select(orderby=db.review_comments.created_at)
    return [c.as_dict() for c in comments]


def update_comment_status(comment_id: int, status: str,
                         platform_comment_id: Optional[str] = None) -> Optional[dict]:
    """Update comment status and optionally set platform comment ID."""
    db = get_db()
    update_data = {"status": status}

    if platform_comment_id:
        update_data["platform_comment_id"] = platform_comment_id
        update_data["posted_at"] = datetime.utcnow()

    db(db.review_comments.id == comment_id).update(**update_data)
    db.commit()
    comment = db(db.review_comments.id == comment_id).select().first()
    return comment.as_dict() if comment else None


# ===========================
# Review Detections Helper Functions
# ===========================


def create_detection(review_id: int, detection_type: str, name: str,
                    confidence: float, file_count: int) -> dict:
    """Create a new review detection."""
    db = get_db()
    detection_id = db.review_detections.insert(
        review_id=review_id,
        detection_type=detection_type,
        name=name,
        confidence=confidence,
        file_count=file_count,
    )
    db.commit()
    detection = db(db.review_detections.id == detection_id).select().first()
    return detection.as_dict() if detection else None


def get_detections_by_review(review_id: int,
                             detection_type: Optional[str] = None) -> list[dict]:
    """Get all detections for a review with optional type filtering."""
    db = get_db()

    query = db.review_detections.review_id == review_id
    if detection_type:
        query &= db.review_detections.detection_type == detection_type

    detections = db(query).select(orderby=~db.review_detections.confidence)
    return [d.as_dict() for d in detections]


# ===========================
# Repository Config Helper Functions
# ===========================


def get_repo_config(platform: str, repository: str) -> Optional[dict]:
    """Get repository configuration."""
    db = get_db()
    config = db(
        (db.repo_configs.platform == platform) &
        (db.repo_configs.repository == repository)
    ).select().first()
    return config.as_dict() if config else None


def create_or_update_repo_config(platform: str, repository: str, **kwargs) -> dict:
    """Create or update repository configuration."""
    db = get_db()

    # Check if config exists
    existing = db(
        (db.repo_configs.platform == platform) &
        (db.repo_configs.repository == repository)
    ).select().first()

    if existing:
        # Update existing config
        db(
            (db.repo_configs.platform == platform) &
            (db.repo_configs.repository == repository)
        ).update(**kwargs)
        db.commit()
    else:
        # Create new config
        db.repo_configs.insert(
            platform=platform,
            repository=repository,
            **kwargs
        )
        db.commit()

    return get_repo_config(platform, repository)


def list_repo_configs(platform: Optional[str] = None,
                     enabled_only: bool = False) -> list[dict]:
    """List repository configurations with optional filtering."""
    db = get_db()

    query = db.repo_configs.id > 0
    if platform:
        query &= db.repo_configs.platform == platform
    if enabled_only:
        query &= db.repo_configs.enabled == True

    configs = db(query).select(orderby=db.repo_configs.repository)
    return [c.as_dict() for c in configs]


# ===========================
# Provider Usage Helper Functions
# ===========================


def create_provider_usage(review_id: Optional[int], provider: str, model: str,
                         prompt_tokens: int, completion_tokens: int,
                         latency_ms: int, cost_estimate: float) -> dict:
    """Track AI provider usage."""
    db = get_db()
    total_tokens = prompt_tokens + completion_tokens

    usage_id = db.provider_usage.insert(
        review_id=review_id,
        provider=provider,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        latency_ms=latency_ms,
        cost_estimate=cost_estimate,
    )
    db.commit()
    usage = db(db.provider_usage.id == usage_id).select().first()
    return usage.as_dict() if usage else None


def get_usage_by_review(review_id: int) -> list[dict]:
    """Get all provider usage records for a review."""
    db = get_db()
    usage = db(db.provider_usage.review_id == review_id).select(
        orderby=db.provider_usage.created_at
    )
    return [u.as_dict() for u in usage]


def get_usage_stats(provider: Optional[str] = None,
                   start_date: Optional[datetime] = None,
                   end_date: Optional[datetime] = None) -> dict:
    """Get aggregate usage statistics."""
    db = get_db()

    query = db.provider_usage.id > 0
    if provider:
        query &= db.provider_usage.provider == provider
    if start_date:
        query &= db.provider_usage.created_at >= start_date
    if end_date:
        query &= db.provider_usage.created_at <= end_date

    stats = db(query).select(
        db.provider_usage.total_tokens.sum(),
        db.provider_usage.cost_estimate.sum(),
        db.provider_usage.id.count(),
    ).first()

    return {
        "total_tokens": stats[db.provider_usage.total_tokens.sum()] or 0,
        "total_cost": stats[db.provider_usage.cost_estimate.sum()] or 0.0,
        "total_requests": stats[db.provider_usage.id.count()] or 0,
    }


# ===========================
# Git Credentials Helper Functions
# ===========================


def store_credential(name: str, git_url_pattern: str, auth_type: str,
                    encrypted_credential: bytes,
                    ssh_key_passphrase: Optional[bytes] = None,
                    created_by: Optional[int] = None) -> dict:
    """Store a new git credential."""
    db = get_db()
    cred_id = db.git_credentials.insert(
        name=name,
        git_url_pattern=git_url_pattern,
        auth_type=auth_type,
        encrypted_credential=encrypted_credential,
        ssh_key_passphrase=ssh_key_passphrase,
        created_by=created_by,
    )
    db.commit()
    cred = db(db.git_credentials.id == cred_id).select().first()
    return cred.as_dict() if cred else None


def get_credentials(git_url_pattern: Optional[str] = None) -> list[dict]:
    """Get git credentials, optionally filtered by URL pattern."""
    db = get_db()

    if git_url_pattern:
        query = db.git_credentials.git_url_pattern == git_url_pattern
    else:
        query = db.git_credentials.id > 0

    credentials = db(query).select(orderby=db.git_credentials.name)
    return [c.as_dict() for c in credentials]


def get_credential_by_id(cred_id: int) -> Optional[dict]:
    """Get a git credential by its ID."""
    db = get_db()
    credential = db(db.git_credentials.id == cred_id).select().first()
    return credential.as_dict() if credential else None


def delete_credential(cred_id: int) -> bool:
    """Delete a git credential by ID."""
    db = get_db()
    deleted = db(db.git_credentials.id == cred_id).delete()
    db.commit()
    return deleted > 0


# ===========================
# License Policy Helper Functions
# ===========================


def create_license_policy(license_name: str, policy: str, actions: list[str],
                         description: str = "") -> dict:
    """Create or update a license policy."""
    db = get_db()

    existing = db(db.license_policies.license_name == license_name).select().first()

    if existing:
        db(db.license_policies.license_name == license_name).update(
            policy=policy,
            actions=actions,
            description=description,
        )
        policy_id = existing.id
    else:
        policy_id = db.license_policies.insert(
            license_name=license_name,
            policy=policy,
            actions=actions,
            description=description,
        )

    db.commit()
    return get_license_policy(license_name)


def get_license_policy(license_name: str) -> Optional[dict]:
    """Get license policy by name."""
    db = get_db()
    policy = db(db.license_policies.license_name == license_name).select().first()
    return policy.as_dict() if policy else None


def list_license_policies() -> list[dict]:
    """List all license policies."""
    db = get_db()
    policies = db(db.license_policies).select(orderby=db.license_policies.license_name)
    return [p.as_dict() for p in policies]


def delete_license_policy(license_name: str) -> bool:
    """Delete a license policy."""
    db = get_db()
    deleted = db(db.license_policies.license_name == license_name).delete()
    db.commit()
    return deleted > 0


def record_license_detection(review_id: int, package_name: str, package_version: str,
                            license_name: str, license_source: str, file_path: str,
                            confidence: float) -> dict:
    """Record a license detection."""
    db = get_db()

    # Check if this license violates policy
    policy = get_license_policy(license_name)
    policy_violation = policy and policy.get("policy") == "blocked"

    detection_id = db.license_detections.insert(
        review_id=review_id,
        package_name=package_name,
        package_version=package_version,
        license_name=license_name,
        license_source=license_source,
        file_path=file_path,
        confidence=confidence,
        policy_violation=policy_violation,
    )
    db.commit()

    # Create violation record if policy is blocked or review_required
    if policy and policy.get("policy") in ["blocked", "review_required"]:
        severity = "critical" if policy.get("policy") == "blocked" else "warning"
        db.license_violations.insert(
            review_id=review_id,
            detection_id=detection_id,
            license_name=license_name,
            package_name=package_name,
            policy=policy.get("policy"),
            severity=severity,
            actions_taken=policy.get("actions", []),
        )
        db.commit()

    detection = db(db.license_detections.id == detection_id).select().first()
    return detection.as_dict() if detection else None


def get_review_license_violations(review_id: int) -> list[dict]:
    """Get all license violations for a review."""
    db = get_db()
    violations = db(db.license_violations.review_id == review_id).select(
        orderby=~db.license_violations.severity
    )
    return [v.as_dict() for v in violations]


def update_violation_status(violation_id: int, status: str) -> Optional[dict]:
    """Update license violation status."""
    db = get_db()
    db(db.license_violations.id == violation_id).update(status=status)
    db.commit()
    violation = db(db.license_violations.id == violation_id).select().first()
    return violation.as_dict() if violation else None


# ===========================
# Installation Config Helper Functions
# ===========================


def get_config_value(key: str, default: Optional[str] = None) -> Optional[str]:
    """Get installation config value."""
    db = get_db()
    config = db(db.installation_config.config_key == key).select().first()
    return config.config_value if config else default


def set_config_value(key: str, value: str) -> None:
    """Set installation config value."""
    db = get_db()

    existing = db(db.installation_config.config_key == key).select().first()

    if existing:
        db(db.installation_config.config_key == key).update(config_value=value)
    else:
        db.installation_config.insert(config_key=key, config_value=value)

    db.commit()


def get_repo_count() -> int:
    """Get count of unique repositories configured."""
    db = get_db()
    return db(db.repo_configs).count()


def check_repo_limit(has_professional_license: bool) -> tuple[bool, int, int]:
    """
    Check if repo limit is reached.

    Returns:
        Tuple of (can_add_repo, current_count, limit)
    """
    current_count = get_repo_count()

    if has_professional_license:
        return True, current_count, -1  # -1 means unlimited

    free_limit = 3
    can_add = current_count < free_limit

    return can_add, current_count, free_limit


# ===========================
# Platform Identity Helper Functions
# ===========================


def resolve_platform_user(platform: str, username: str) -> Optional[dict]:
    """Look up Darwin user by platform identity.

    Returns the Darwin user dict if a mapping exists, otherwise None.
    """
    db = get_db()
    identity = db(
        (db.platform_identities.platform == platform) &
        (db.platform_identities.platform_username == username)
    ).select().first()

    if not identity:
        return None

    return get_user_by_id(identity.user_id)


def create_platform_identity(user_id: int, platform: str, username: str,
                             platform_user_id: Optional[str] = None,
                             avatar_url: Optional[str] = None) -> dict:
    """Create a platform identity mapping."""
    db = get_db()
    identity_id = db.platform_identities.insert(
        user_id=user_id,
        platform=platform,
        platform_username=username,
        platform_user_id=platform_user_id,
        platform_avatar_url=avatar_url,
        is_verified=False,
    )
    db.commit()
    identity = db(db.platform_identities.id == identity_id).select().first()
    return identity.as_dict() if identity else None


def get_platform_identities(user_id: int) -> list[dict]:
    """List all platform identities for a user."""
    db = get_db()
    identities = db(db.platform_identities.user_id == user_id).select(
        orderby=db.platform_identities.platform
    )
    return [i.as_dict() for i in identities]


def get_platform_identity_by_id(identity_id: int) -> Optional[dict]:
    """Get a platform identity by its ID."""
    db = get_db()
    identity = db(db.platform_identities.id == identity_id).select().first()
    return identity.as_dict() if identity else None


def delete_platform_identity(identity_id: int) -> bool:
    """Remove a platform identity mapping."""
    db = get_db()
    deleted = db(db.platform_identities.id == identity_id).delete()
    db.commit()
    return deleted > 0


def list_all_platform_identities(page: int = 1,
                                 per_page: int = 20) -> tuple[list[dict], int]:
    """List all platform identities with pagination (admin use)."""
    db = get_db()
    offset = (page - 1) * per_page

    identities = db(db.platform_identities).select(
        orderby=db.platform_identities.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(db.platform_identities).count()

    return [i.as_dict() for i in identities], total


# ===========================
# Issue Plans Helper Functions
# ===========================


def create_issue_plan(external_id: str, platform: str, repository: str,
                     issue_number: int, issue_title: str, issue_body: str,
                     ai_provider: str, issue_url: Optional[str] = None,
                     ai_model: Optional[str] = None) -> dict:
    """Create a new issue plan request."""
    db = get_db()
    plan_id = db.issue_plans.insert(
        external_id=external_id,
        platform=platform,
        repository=repository,
        issue_number=issue_number,
        issue_url=issue_url,
        issue_title=issue_title,
        issue_body=issue_body,
        ai_provider=ai_provider,
        ai_model=ai_model,
        status="queued",
    )
    db.commit()
    return get_issue_plan_by_id(plan_id)


def get_issue_plan_by_id(plan_id: int) -> Optional[dict]:
    """Get issue plan by ID."""
    db = get_db()
    plan = db(db.issue_plans.id == plan_id).select().first()
    return plan.as_dict() if plan else None


def get_issue_plan_by_external_id(external_id: str) -> Optional[dict]:
    """Get issue plan by external ID."""
    db = get_db()
    plan = db(db.issue_plans.external_id == external_id).select().first()
    return plan.as_dict() if plan else None


def update_issue_plan_status(plan_id: int, status: str,
                             plan_content: Optional[str] = None,
                             plan_steps: Optional[list] = None,
                             error_message: Optional[str] = None,
                             comment_posted: Optional[bool] = None,
                             platform_comment_id: Optional[str] = None,
                             token_usage: Optional[dict] = None) -> Optional[dict]:
    """Update issue plan status and content."""
    db = get_db()
    update_data = {"status": status}

    if plan_content is not None:
        update_data["plan_content"] = plan_content
    if plan_steps is not None:
        update_data["plan_steps"] = plan_steps
    if error_message is not None:
        update_data["error_message"] = error_message
    if comment_posted is not None:
        update_data["comment_posted"] = comment_posted
    if platform_comment_id is not None:
        update_data["platform_comment_id"] = platform_comment_id
    if token_usage is not None:
        update_data["token_usage"] = token_usage

    db(db.issue_plans.id == plan_id).update(**update_data)
    db.commit()
    return get_issue_plan_by_id(plan_id)


def list_issue_plans(platform: Optional[str] = None,
                    repository: Optional[str] = None,
                    status: Optional[str] = None,
                    page: int = 1,
                    per_page: int = 20) -> tuple[list[dict], int]:
    """List issue plans with optional filtering and pagination."""
    db = get_db()
    offset = (page - 1) * per_page

    # Build query
    query = db.issue_plans.id > 0
    if platform:
        query &= db.issue_plans.platform == platform
    if repository:
        query &= db.issue_plans.repository == repository
    if status:
        query &= db.issue_plans.status == status

    plans = db(query).select(
        orderby=~db.issue_plans.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    return [p.as_dict() for p in plans], total


def count_issue_plans_today(repository: str) -> int:
    """Count issue plans created today for a repository."""
    db = get_db()

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    count = db(
        (db.issue_plans.repository == repository) &
        (db.issue_plans.created_at >= today_start)
    ).count()

    return count


def calculate_monthly_cost(repository: str) -> float:
    """Calculate total token cost for the current month for a repository."""
    db = get_db()

    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    plans = db(
        (db.issue_plans.repository == repository) &
        (db.issue_plans.created_at >= month_start) &
        (db.issue_plans.token_usage != None)
    ).select()

    total_cost = 0.0
    for plan in plans:
        if plan.token_usage and isinstance(plan.token_usage, dict):
            total_cost += plan.token_usage.get("cost_estimate", 0.0)

    return total_cost
