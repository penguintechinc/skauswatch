"""Custom Roles and Scopes API - RBAC role and permission management."""

from flask import Blueprint, jsonify, request, g
from typing import Any, Optional
import logging

from ...middleware import auth_required
from ...models import get_db
from ...middleware import get_current_user

logger = logging.getLogger(__name__)

roles_bp = Blueprint("roles", __name__)

# Valid permission scopes - comprehensive permission categories
AVAILABLE_SCOPES = {
    # Repository-level scopes
    "repo:read": "Read repository configurations and metadata",
    "repo:write": "Write and update repository configurations",
    "repo:delete": "Delete repositories",
    "repo:admin": "Administer repository settings",

    # Review scopes
    "review:read": "View reviews and comments",
    "review:create": "Create and trigger reviews",
    "review:update": "Update review settings",
    "review:delete": "Delete reviews",
    "review:admin": "Administer review settings",

    # User management scopes
    "user:read": "View user information",
    "user:write": "Modify user information",
    "user:delete": "Delete users",
    "user:admin": "Administer users",

    # Role management scopes
    "role:read": "View roles and permissions",
    "role:write": "Create and modify roles",
    "role:delete": "Delete roles",
    "role:admin": "Administer role assignments",

    # Team scopes
    "team:read": "View team information",
    "team:write": "Modify team settings",
    "team:delete": "Delete teams",
    "team:admin": "Administer team membership",

    # Tenant scopes (admin-only)
    "tenant:read": "View tenant information",
    "tenant:write": "Modify tenant settings",
    "tenant:delete": "Delete tenants",
    "tenant:admin": "Administer tenant settings",

    # Credential scopes
    "credential:read": "View credentials",
    "credential:write": "Create and modify credentials",
    "credential:delete": "Delete credentials",

    # License scopes
    "license:read": "View license information",
    "license:admin": "Administer licenses",

    # System scopes (global admin only)
    "system:read": "View system information",
    "system:admin": "Administer system settings",
}


def get_user_tenant_id() -> Optional[int]:
    """Get current user's tenant ID."""
    user = g.get("current_user")
    return user.get("default_tenant_id") if user else None


def get_user_global_role() -> Optional[str]:
    """Get current user's global role."""
    user = g.get("current_user")
    return user.get("global_role") if user else None


def can_manage_global_roles() -> bool:
    """Check if user can manage global roles (global admin only)."""
    return get_user_global_role() == "admin"


def can_manage_tenant_roles(tenant_id: int) -> bool:
    """Check if user can manage roles for a specific tenant."""
    if can_manage_global_roles():
        return True

    user_tenant = get_user_tenant_id()
    if not user_tenant or user_tenant != tenant_id:
        return False

    # Check user's tenant role
    db = get_db()
    user = g.get("current_user")
    user_id = user.get("id")

    tenant_member = db(
        (db.tenant_members.tenant_id == tenant_id) &
        (db.tenant_members.user_id == user_id)
    ).select(db.tenant_members.role, limitby=(0, 1))

    if tenant_member:
        return tenant_member[0].role in ["admin", "maintainer"]

    return False


def can_manage_team_roles(team_id: int) -> bool:
    """Check if user can manage roles for a specific team."""
    if can_manage_global_roles():
        return True

    db = get_db()
    user = g.get("current_user")
    user_id = user.get("id")

    # Get team's tenant
    team = db(db.teams.id == team_id).select(db.teams.tenant_id, limitby=(0, 1))
    if not team:
        return False

    team_tenant_id = team[0].tenant_id

    # Check if user is team admin or tenant admin
    if can_manage_tenant_roles(team_tenant_id):
        return True

    team_member = db(
        (db.team_members.team_id == team_id) &
        (db.team_members.user_id == user_id)
    ).select(db.team_members.role, limitby=(0, 1))

    if team_member and team_member[0].role == "admin":
        return True

    return False


def validate_scopes(scopes: list) -> tuple[bool, Optional[str]]:
    """Validate that all provided scopes are valid."""
    if not isinstance(scopes, list):
        return False, "Scopes must be a list"

    if len(scopes) == 0:
        return False, "At least one scope is required"

    for scope in scopes:
        if not isinstance(scope, str):
            return False, f"Invalid scope type: {type(scope).__name__}"

        if scope not in AVAILABLE_SCOPES:
            return False, f"Invalid scope: {scope}"

    return True, None


@roles_bp.route("", methods=["GET"])
@auth_required
def list_roles() -> tuple[dict[str, Any], int]:
    """
    List available roles filtered by user's access level.

    Query Parameters:
        role_level: Filter by role level (global, tenant, team)
        tenant_id: Filter by tenant (tenant/team roles only)
        team_id: Filter by team
        active_only: Show only active roles (default: true)

    Returns:
        200: List of roles accessible to the user
        403: Insufficient permissions
    """
    db = get_db()

    role_level = request.args.get("role_level")
    tenant_id_str = request.args.get("tenant_id")
    team_id_str = request.args.get("team_id")
    active_only = request.args.get("active_only", "true").lower() == "true"

    # Validate role_level
    if role_level and role_level not in ["global", "tenant", "team", "resource"]:
        return jsonify({"error": "Invalid role_level"}), 400

    user_id = g.current_user.get("id")
    user_tenant = get_user_tenant_id()
    query_filters = []

    if active_only:
        query_filters.append(db.custom_roles.is_active == True)

    # Global roles: accessible to global admin
    if not role_level or role_level == "global":
        if can_manage_global_roles():
            global_query = db.custom_roles.role_level == "global"
            for f in query_filters:
                global_query &= f

            roles = db(global_query).select(orderby=db.custom_roles.name)
            if not role_level:
                return _format_roles_response(roles)
            return _format_roles_response(roles)

    # Tenant roles: filter by user's tenant
    if not role_level or role_level == "tenant":
        if tenant_id_str:
            try:
                tenant_id = int(tenant_id_str)
            except ValueError:
                return jsonify({"error": "Invalid tenant_id"}), 400

            if not can_manage_tenant_roles(tenant_id):
                return jsonify({"error": "Access denied"}), 403

            tenant_query = (db.custom_roles.role_level == "tenant") & \
                          (db.custom_roles.tenant_id == tenant_id)
            for f in query_filters:
                tenant_query &= f

            roles = db(tenant_query).select(orderby=db.custom_roles.name)
            if role_level:
                return _format_roles_response(roles)
        elif user_tenant:
            tenant_query = (db.custom_roles.role_level == "tenant") & \
                          (db.custom_roles.tenant_id == user_tenant)
            for f in query_filters:
                tenant_query &= f

            roles = db(tenant_query).select(orderby=db.custom_roles.name)
            if not role_level:
                return _format_roles_response(roles)

    # Team roles: filter by user's accessible teams
    if not role_level or role_level == "team":
        if team_id_str:
            try:
                team_id = int(team_id_str)
            except ValueError:
                return jsonify({"error": "Invalid team_id"}), 400

            if not can_manage_team_roles(team_id):
                return jsonify({"error": "Access denied"}), 403

            team_query = (db.custom_roles.role_level == "team") & \
                        (db.custom_roles.team_id == team_id)
            for f in query_filters:
                team_query &= f

            roles = db(team_query).select(orderby=db.custom_roles.name)
            if role_level:
                return _format_roles_response(roles)

    return _format_roles_response([])


@roles_bp.route("", methods=["POST"])
@auth_required
def create_role() -> tuple[dict[str, Any], int]:
    """
    Create a custom role.

    Role-level Authorization:
    - global: Requires global admin
    - tenant: Requires tenant admin for specified tenant
    - team: Requires team admin for specified team

    Request Body:
        {
            "name": "Custom Role Name",
            "slug": "custom-role",
            "description": "Role description",
            "role_level": "global" | "tenant" | "team",
            "tenant_id": <id> (required for tenant/team roles),
            "team_id": <id> (required for team roles),
            "scopes": ["scope1", "scope2"]
        }

    Returns:
        201: Created role with ID
        400: Invalid input
        403: Insufficient permissions
    """
    data = request.get_json() or {}
    db = get_db()

    # Validate required fields
    required = ["name", "slug", "role_level", "scopes"]
    for field in required:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    name = data.get("name", "").strip()
    slug = data.get("slug", "").strip()
    description = data.get("description", "").strip()
    role_level = data.get("role_level")
    scopes = data.get("scopes", [])

    # Validate role_level
    if role_level not in ["global", "tenant", "team", "resource"]:
        return jsonify({"error": "Invalid role_level"}), 400

    # Validate name and slug
    if not name or len(name) > 128:
        return jsonify({"error": "Invalid name length (1-128 chars)"}), 400

    if not slug or len(slug) > 128:
        return jsonify({"error": "Invalid slug length (1-128 chars)"}), 400

    # Validate scopes
    valid_scopes, scope_error = validate_scopes(scopes)
    if not valid_scopes:
        return jsonify({"error": f"Invalid scopes: {scope_error}"}), 400

    tenant_id = data.get("tenant_id")
    team_id = data.get("team_id")

    # Validate authorization by role level
    if role_level == "global":
        if not can_manage_global_roles():
            return jsonify({"error": "Only global admins can create global roles"}), 403
        tenant_id = None
        team_id = None

    elif role_level == "tenant":
        if not tenant_id:
            return jsonify({"error": "tenant_id required for tenant roles"}), 400

        if not can_manage_tenant_roles(tenant_id):
            return jsonify({"error": "Insufficient permissions for this tenant"}), 403

        team_id = None

    elif role_level == "team":
        if not team_id:
            return jsonify({"error": "team_id required for team roles"}), 400

        if not can_manage_team_roles(team_id):
            return jsonify({"error": "Insufficient permissions for this team"}), 403

        # Get tenant from team
        team = db(db.teams.id == team_id).select(db.teams.tenant_id, limitby=(0, 1))
        if not team:
            return jsonify({"error": "Team not found"}), 404

        tenant_id = team[0].tenant_id

    else:  # resource
        if not tenant_id:
            tenant_id = get_user_tenant_id()

        if not can_manage_tenant_roles(tenant_id):
            return jsonify({"error": "Insufficient permissions"}), 403

    # Check if slug already exists at this level
    existing = db(
        (db.custom_roles.slug == slug) &
        (db.custom_roles.role_level == role_level) &
        (db.custom_roles.tenant_id == tenant_id) &
        (db.custom_roles.team_id == team_id)
    ).select(limitby=(0, 1))

    if existing:
        return jsonify({"error": "Role with this slug already exists at this level"}), 409

    # Create role
    try:
        role_id = db.custom_roles.insert(
            name=name,
            slug=slug,
            description=description,
            role_level=role_level,
            tenant_id=tenant_id,
            team_id=team_id,
            scopes=scopes,
            is_active=True,
        )

        db.commit()

        return jsonify({
            "id": role_id,
            "name": name,
            "slug": slug,
            "description": description,
            "role_level": role_level,
            "tenant_id": tenant_id,
            "team_id": team_id,
            "scopes": scopes,
            "is_active": True,
        }), 201

    except Exception as e:
        logger.error(f"Error creating role: {str(e)}")
        db.rollback()
        return jsonify({"error": "Failed to create role"}), 500


@roles_bp.route("/<int:role_id>", methods=["GET"])
@auth_required
def get_role(role_id: int) -> tuple[dict[str, Any], int]:
    """
    Get role details by ID.

    Returns:
        200: Role details
        404: Role not found
        403: Access denied
    """
    db = get_db()

    role = db(db.custom_roles.id == role_id).select(limitby=(0, 1))
    if not role:
        return jsonify({"error": "Role not found"}), 404

    role = role[0]

    # Check access permissions
    if role.role_level == "global":
        if not can_manage_global_roles():
            return jsonify({"error": "Access denied"}), 403
    elif role.role_level == "tenant":
        if not can_manage_tenant_roles(role.tenant_id):
            return jsonify({"error": "Access denied"}), 403
    elif role.role_level == "team":
        if not can_manage_team_roles(role.team_id):
            return jsonify({"error": "Access denied"}), 403

    return jsonify({
        "id": role.id,
        "name": role.name,
        "slug": role.slug,
        "description": role.description,
        "role_level": role.role_level,
        "tenant_id": role.tenant_id,
        "team_id": role.team_id,
        "scopes": role.scopes,
        "is_active": role.is_active,
        "created_at": role.created_at.isoformat() if role.created_at else None,
        "updated_at": role.updated_at.isoformat() if role.updated_at else None,
    }), 200


@roles_bp.route("/<int:role_id>", methods=["PUT"])
@auth_required
def update_role(role_id: int) -> tuple[dict[str, Any], int]:
    """
    Update a custom role.

    Authorized users:
    - Global admins (all roles)
    - Tenant admins (tenant and team roles in their tenant)
    - Team admins (team roles in their team)

    Request Body:
        {
            "name": "Updated Name",
            "slug": "updated-slug",
            "description": "Updated description",
            "scopes": ["scope1", "scope2"],
            "is_active": true
        }

    Returns:
        200: Updated role
        400: Invalid input
        404: Role not found
        403: Insufficient permissions
    """
    db = get_db()
    data = request.get_json() or {}

    role = db(db.custom_roles.id == role_id).select(limitby=(0, 1))
    if not role:
        return jsonify({"error": "Role not found"}), 404

    role = role[0]

    # Check authorization
    if role.role_level == "global":
        if not can_manage_global_roles():
            return jsonify({"error": "Access denied"}), 403
    elif role.role_level == "tenant":
        if not can_manage_tenant_roles(role.tenant_id):
            return jsonify({"error": "Access denied"}), 403
    elif role.role_level == "team":
        if not can_manage_team_roles(role.team_id):
            return jsonify({"error": "Access denied"}), 403

    # Update allowed fields
    updates = {}

    if "name" in data:
        name = data.get("name", "").strip()
        if not name or len(name) > 128:
            return jsonify({"error": "Invalid name length (1-128 chars)"}), 400
        updates["name"] = name

    if "slug" in data:
        slug = data.get("slug", "").strip()
        if not slug or len(slug) > 128:
            return jsonify({"error": "Invalid slug length (1-128 chars)"}), 400

        existing = db(
            (db.custom_roles.slug == slug) &
            (db.custom_roles.id != role_id) &
            (db.custom_roles.role_level == role.role_level) &
            (db.custom_roles.tenant_id == role.tenant_id) &
            (db.custom_roles.team_id == role.team_id)
        ).select(limitby=(0, 1))

        if existing:
            return jsonify({"error": "Slug already exists at this level"}), 409

        updates["slug"] = slug

    if "description" in data:
        updates["description"] = data.get("description", "").strip()

    if "scopes" in data:
        scopes = data.get("scopes", [])
        valid_scopes, scope_error = validate_scopes(scopes)
        if not valid_scopes:
            return jsonify({"error": f"Invalid scopes: {scope_error}"}), 400
        updates["scopes"] = scopes

    if "is_active" in data:
        updates["is_active"] = bool(data.get("is_active"))

    if not updates:
        return jsonify({"error": "No fields to update"}), 400

    try:
        db(db.custom_roles.id == role_id).update(**updates)
        db.commit()

        # Fetch updated role
        updated = db(db.custom_roles.id == role_id).select(limitby=(0, 1))[0]

        return jsonify({
            "id": updated.id,
            "name": updated.name,
            "slug": updated.slug,
            "description": updated.description,
            "role_level": updated.role_level,
            "tenant_id": updated.tenant_id,
            "team_id": updated.team_id,
            "scopes": updated.scopes,
            "is_active": updated.is_active,
            "created_at": updated.created_at.isoformat() if updated.created_at else None,
            "updated_at": updated.updated_at.isoformat() if updated.updated_at else None,
        }), 200

    except Exception as e:
        logger.error(f"Error updating role: {str(e)}")
        db.rollback()
        return jsonify({"error": "Failed to update role"}), 500


@roles_bp.route("/<int:role_id>", methods=["DELETE"])
@auth_required
def delete_role(role_id: int) -> tuple[dict[str, Any], int]:
    """
    Delete a custom role.

    Authorized users:
    - Global admins (all roles)
    - Tenant admins (tenant and team roles in their tenant)
    - Team admins (team roles in their team)

    Returns:
        204: Role deleted
        404: Role not found
        403: Insufficient permissions
        409: Role in use (has assignments)
    """
    db = get_db()

    role = db(db.custom_roles.id == role_id).select(limitby=(0, 1))
    if not role:
        return jsonify({"error": "Role not found"}), 404

    role = role[0]

    # Check authorization
    if role.role_level == "global":
        if not can_manage_global_roles():
            return jsonify({"error": "Access denied"}), 403
    elif role.role_level == "tenant":
        if not can_manage_tenant_roles(role.tenant_id):
            return jsonify({"error": "Access denied"}), 403
    elif role.role_level == "team":
        if not can_manage_team_roles(role.team_id):
            return jsonify({"error": "Access denied"}), 403

    # Check if role has assignments
    in_use = db(db.repository_members.custom_role_id == role_id).count()
    if in_use > 0:
        return jsonify({"error": f"Role in use by {in_use} repository members"}), 409

    try:
        db(db.custom_roles.id == role_id).delete()
        db.commit()
        return "", 204

    except Exception as e:
        logger.error(f"Error deleting role: {str(e)}")
        db.rollback()
        return jsonify({"error": "Failed to delete role"}), 500


@roles_bp.route("/scopes", methods=["GET"])
@auth_required
def get_available_scopes() -> tuple[dict[str, Any], int]:
    """
    Get list of available permission scopes.

    Returns:
        200: Dictionary of scope: description pairs
    """
    return jsonify({
        "scopes": AVAILABLE_SCOPES,
        "total": len(AVAILABLE_SCOPES),
    }), 200


def _format_roles_response(roles: list) -> tuple[dict[str, Any], int]:
    """Format roles list for response."""
    formatted = []
    for role in roles:
        formatted.append({
            "id": role.id,
            "name": role.name,
            "slug": role.slug,
            "description": role.description,
            "role_level": role.role_level,
            "tenant_id": role.tenant_id,
            "team_id": role.team_id,
            "scopes": role.scopes,
            "is_active": role.is_active,
            "created_at": role.created_at.isoformat() if role.created_at else None,
            "updated_at": role.updated_at.isoformat() if role.updated_at else None,
        })

    return jsonify({
        "roles": formatted,
        "total": len(formatted),
    }), 200
