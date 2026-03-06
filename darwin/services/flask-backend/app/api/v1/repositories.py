"""Repository Management API - CRUD endpoints for repository configurations."""

from flask import Blueprint, jsonify, request
from typing import Any

from ...middleware import auth_required, admin_required, role_required, get_current_user
from ...rbac import get_user_tenant_filter, get_user_teams, check_permission
from ...models import (
    create_repository,
    get_repository_by_id,
    list_repositories,
    update_repository,
    delete_repository,
    get_repositories_by_organization,
    get_unique_organizations,
    get_db,
)

repositories_bp = Blueprint("repositories", __name__)


@repositories_bp.route("", methods=["GET"])
@auth_required
def list_repositories_endpoint() -> tuple[dict[str, Any], int]:
    """
    List repositories with optional filtering and pagination.

    Filters repositories based on user's tenant/team access:
    - Tenant-level users see only their tenant's repositories
    - Team-level filtering applies if team_id query parameter provided
    - Global admin/maintainers see all repositories

    Query Parameters:
        platform: Filter by platform (github, gitlab, git)
        organization: Filter by organization
        enabled: Filter by enabled status (true/false)
        team_id: Optional filter by team ID (validates user access)
        page: Page number (default: 1)
        per_page: Results per page (default: 20, max: 100)

    Returns:
        JSON response with repositories list and pagination info
    """
    user = get_current_user()
    user_id = user.get("id")

    # Get query parameters
    platform = request.args.get("platform")
    organization = request.args.get("organization")
    enabled_str = request.args.get("enabled")
    team_id_param = request.args.get("team_id", type=int)
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 20)), 100)

    # Parse enabled parameter
    enabled = None
    if enabled_str is not None:
        enabled = enabled_str.lower() in ("true", "1", "yes")

    # Apply tenant filtering for tenant-level users
    tenant_filter = get_user_tenant_filter(user_id)
    if tenant_filter is None and team_id_param is None:
        # Global user without team filter - no additional restriction
        filtered_repositories, total = list_repositories(
            platform=platform,
            organization=organization,
            enabled=enabled,
            page=page,
            per_page=per_page,
        )
    else:
        # Need to apply tenant and/or team filtering
        db = get_db()
        offset = (page - 1) * per_page

        # Build query
        query = db.repo_configs.id > 0

        # Apply tenant filter for tenant-level users
        if tenant_filter is not None:
            query &= db.repo_configs.tenant_id == tenant_filter

        # Apply team filter if provided
        if team_id_param is not None:
            # Validate user has access to this team
            user_teams = get_user_teams(user_id)
            if team_id_param not in user_teams and tenant_filter is None:
                # Global user accessing specific team - allowed
                pass
            elif team_id_param not in user_teams:
                # Tenant user trying to access team they're not in
                return jsonify({
                    "error": "You do not have access to this team"
                }), 403

            query &= db.repo_configs.team_id == team_id_param

        # Apply other filters
        if platform:
            query &= db.repo_configs.platform == platform
        if organization:
            query &= db.repo_configs.platform_organization == organization
        if enabled is not None:
            query &= db.repo_configs.enabled == enabled

        # Execute query with pagination
        repos = db(query).select(
            orderby=~db.repo_configs.created_at,
            limitby=(offset, offset + per_page),
        )
        filtered_repositories = [r.as_dict() for r in repos]
        total = db(query).count()

    # Calculate pagination metadata
    pages = (total + per_page - 1) // per_page  # Ceiling division

    return jsonify({
        "repositories": filtered_repositories,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": pages,
        }
    }), 200


@repositories_bp.route("", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
def create_repository_endpoint() -> tuple[dict[str, Any], int]:
    """
    Create a new repository configuration.

    Validates user has access to specified tenant and team.

    Request Body:
        platform (required): github, gitlab, or git
        repository (required): Repository identifier
        tenant_id (required): Tenant ID for this repository
        team_id (required): Team ID for this repository
        platform_organization (optional): Organization name
        display_name (optional): Display name
        description (optional): Description
        enabled (optional): Enable repository (default: true)
        polling_enabled (optional): Enable polling (default: false)
        polling_interval_minutes (optional): Polling interval (default: 5)
        auto_review (optional): Auto-review enabled (default: true)
        credential_id (optional): Credential ID to use
        default_categories (optional): Default review categories
        default_ai_provider (optional): Default AI provider

    Returns:
        JSON response with created repository
    """
    user = get_current_user()
    user_id = user.get("id")
    data = request.get_json()

    # Validate required fields
    if not data or "platform" not in data or "repository" not in data:
        return jsonify({"error": "Missing required fields: platform, repository"}), 400

    if "tenant_id" not in data or "team_id" not in data:
        return jsonify({
            "error": "Missing required fields: tenant_id, team_id"
        }), 400

    if data["platform"] not in ["github", "gitlab", "git"]:
        return jsonify({"error": "Invalid platform. Must be: github, gitlab, or git"}), 400

    tenant_id = data.get("tenant_id")
    team_id = data.get("team_id")

    # Validate user has access to specified tenant
    user_tenant_filter = get_user_tenant_filter(user_id)
    if user_tenant_filter is not None and user_tenant_filter != tenant_id:
        # Tenant-level user can only create in their own tenant
        return jsonify({
            "error": "You do not have access to this tenant"
        }), 403

    # Validate user has access to specified team
    user_teams = get_user_teams(user_id)
    if team_id not in user_teams and user_tenant_filter is None:
        # Global admin can access any team (allow)
        pass
    elif team_id not in user_teams:
        # Tenant user trying to access team they're not in
        return jsonify({
            "error": "You do not have access to this team"
        }), 403

    try:
        repository = create_repository(
            platform=data["platform"],
            repository=data["repository"],
            organization=data.get("platform_organization"),
            credential_id=data.get("credential_id"),
            tenant_id=tenant_id,
            team_id=team_id,
            owner_id=user_id,
            display_name=data.get("display_name"),
            description=data.get("description"),
            enabled=data.get("enabled", True),
            polling_enabled=data.get("polling_enabled", False),
            polling_interval_minutes=data.get("polling_interval_minutes", 5),
            auto_review=data.get("auto_review", True),
            review_on_open=data.get("review_on_open", True),
            review_on_sync=data.get("review_on_sync", False),
            default_categories=data.get("default_categories", ["security", "best_practices"]),
            default_ai_provider=data.get("default_ai_provider", "ollama"),
        )
        return jsonify(repository), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@repositories_bp.route("/<int:repo_id>", methods=["GET"])
@auth_required
def get_repository_endpoint(repo_id: int) -> tuple[dict[str, Any], int]:
    """
    Get repository configuration by ID.

    Validates user has access to repository's tenant/team.

    Path Parameters:
        repo_id: Repository ID

    Returns:
        JSON response with repository details
    """
    user = get_current_user()
    user_id = user.get("id")

    repository = get_repository_by_id(repo_id)
    if not repository:
        return jsonify({"error": "Repository not found"}), 404

    # Validate tenant/team access
    repo_tenant_id = repository.get("tenant_id")
    repo_team_id = repository.get("team_id")

    # Check tenant access
    user_tenant_filter = get_user_tenant_filter(user_id)
    if user_tenant_filter is not None and user_tenant_filter != repo_tenant_id:
        return jsonify({"error": "You do not have access to this repository"}), 403

    # Check team access (if user is not a global admin)
    if repo_team_id is not None:
        user_teams = get_user_teams(user_id)
        if repo_team_id not in user_teams and user_tenant_filter is not None:
            # Tenant user trying to access repo from team they're not in
            return jsonify({"error": "You do not have access to this repository"}), 403

    return jsonify(repository), 200


@repositories_bp.route("/<int:repo_id>", methods=["PUT"])
@auth_required
@role_required("admin", "maintainer")
def update_repository_endpoint(repo_id: int) -> tuple[dict[str, Any], int]:
    """
    Update repository configuration.

    Validates user has access to repository's tenant/team.
    Prevents changing tenant_id and team_id after creation.

    Path Parameters:
        repo_id: Repository ID

    Request Body:
        Any repository fields to update (except tenant_id and team_id)

    Returns:
        JSON response with updated repository
    """
    user = get_current_user()
    user_id = user.get("id")

    # Check if repository exists
    existing = get_repository_by_id(repo_id)
    if not existing:
        return jsonify({"error": "Repository not found"}), 404

    # Validate tenant/team access
    repo_tenant_id = existing.get("tenant_id")
    repo_team_id = existing.get("team_id")

    # Check tenant access
    user_tenant_filter = get_user_tenant_filter(user_id)
    if user_tenant_filter is not None and user_tenant_filter != repo_tenant_id:
        return jsonify({"error": "You do not have access to this repository"}), 403

    # Check team access (if user is not a global admin)
    if repo_team_id is not None:
        user_teams = get_user_teams(user_id)
        if repo_team_id not in user_teams and user_tenant_filter is not None:
            # Tenant user trying to update repo from team they're not in
            return jsonify({"error": "You do not have access to this repository"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Prevent changing tenant_id and team_id after creation
    if "tenant_id" in data or "team_id" in data:
        return jsonify({
            "error": "Cannot change tenant_id or team_id after repository creation"
        }), 400

    # Validate platform if provided
    if "platform" in data and data["platform"] not in ["github", "gitlab", "git"]:
        return jsonify({"error": "Invalid platform. Must be: github, gitlab, or git"}), 400

    try:
        repository = update_repository(repo_id, **data)
        return jsonify(repository), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@repositories_bp.route("/<int:repo_id>", methods=["DELETE"])
@auth_required
@admin_required
def delete_repository_endpoint(repo_id: int) -> tuple[dict[str, Any], int]:
    """
    Delete repository configuration.

    Validates user has access to repository's tenant/team.

    Path Parameters:
        repo_id: Repository ID

    Returns:
        JSON response with success message
    """
    user = get_current_user()
    user_id = user.get("id")

    # Check if repository exists
    existing = get_repository_by_id(repo_id)
    if not existing:
        return jsonify({"error": "Repository not found"}), 404

    # Validate tenant/team access
    repo_tenant_id = existing.get("tenant_id")
    repo_team_id = existing.get("team_id")

    # Check tenant access
    user_tenant_filter = get_user_tenant_filter(user_id)
    if user_tenant_filter is not None and user_tenant_filter != repo_tenant_id:
        return jsonify({"error": "You do not have access to this repository"}), 403

    # Check team access (if user is not a global admin)
    if repo_team_id is not None:
        user_teams = get_user_teams(user_id)
        if repo_team_id not in user_teams and user_tenant_filter is not None:
            # Tenant user trying to delete repo from team they're not in
            return jsonify({"error": "You do not have access to this repository"}), 403

    try:
        success = delete_repository(repo_id)
        if success:
            return jsonify({"message": "Repository deleted successfully"}), 200
        else:
            return jsonify({"error": "Failed to delete repository"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@repositories_bp.route("/organizations", methods=["GET"])
@auth_required
def list_organizations_endpoint() -> tuple[dict[str, Any], int]:
    """
    Get list of unique organizations grouped by platform.

    Returns:
        JSON response with organizations grouped by platform
    """
    try:
        organizations = get_unique_organizations()
        return jsonify({"organizations": organizations}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
