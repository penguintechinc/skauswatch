"""Tenants API Endpoints."""

import re
from flask import Blueprint, jsonify, request

from ...middleware import auth_required, get_current_user, role_required
from ...models import get_db

tenants_bp = Blueprint("tenants", __name__, url_prefix="/api/v1/tenants")


def _generate_slug(name: str) -> str:
    """Generate a URL-safe slug from a name."""
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[-\s]+", "-", slug)
    return slug.strip("-")


def _is_global_admin(user: dict) -> bool:
    """Check if user is global admin."""
    return user.get("role") == "admin"


def _is_tenant_admin(user_id: int, tenant_id: int) -> bool:
    """Check if user is admin of the specified tenant."""
    db = get_db()
    member = db(
        (db.tenant_members.tenant_id == tenant_id) &
        (db.tenant_members.user_id == user_id) &
        (db.tenant_members.role == "admin")
    ).select().first()
    return member is not None


def _is_tenant_member(user_id: int, tenant_id: int) -> bool:
    """Check if user is a member of the specified tenant."""
    db = get_db()
    member = db(
        (db.tenant_members.tenant_id == tenant_id) &
        (db.tenant_members.user_id == user_id) &
        (db.tenant_members.is_active == True)
    ).select().first()
    return member is not None


@tenants_bp.route("", methods=["GET"])
@auth_required
def list_tenants():
    """List all tenants (global admin only)."""
    user = get_current_user()

    if not _is_global_admin(user):
        return jsonify({
            "error": "Insufficient permissions",
            "required_role": "admin",
        }), 403

    db = get_db()
    tenants = db(db.tenants).select(orderby=db.tenants.created_at)

    # Enrich with member and team counts
    result = []
    for tenant in tenants:
        tenant_dict = tenant.as_dict()

        # Count members
        member_count = db(db.tenant_members.tenant_id == tenant.id).count()
        tenant_dict["member_count"] = member_count

        # Count teams
        team_count = db(db.teams.tenant_id == tenant.id).count()
        tenant_dict["team_count"] = team_count

        result.append(tenant_dict)

    return jsonify({
        "tenants": result,
        "total": len(result),
    }), 200


@tenants_bp.route("", methods=["POST"])
@auth_required
def create_tenant():
    """Create a new tenant (global admin only)."""
    user = get_current_user()

    if not _is_global_admin(user):
        return jsonify({
            "error": "Insufficient permissions",
            "required_role": "admin",
        }), 403

    data = request.get_json() or {}

    # Validate required fields
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Tenant name is required"}), 400

    if len(name) > 255:
        return jsonify({"error": "Tenant name must be 255 characters or less"}), 400

    # Generate slug from name
    slug = _generate_slug(name)
    if not slug:
        return jsonify({
            "error": "Tenant name must contain at least one alphanumeric character"
        }), 400

    db = get_db()

    # Check if tenant with this slug already exists
    existing = db(db.tenants.slug == slug).select().first()
    if existing:
        return jsonify({
            "error": f"Tenant with slug '{slug}' already exists"
        }), 409

    # Optional fields
    description = data.get("description", "").strip()
    is_active = data.get("is_active", True)
    if not isinstance(is_active, bool):
        return jsonify({"error": "is_active must be a boolean"}), 400

    max_users = data.get("max_users", 0)
    if not isinstance(max_users, int) or max_users < 0:
        return jsonify({"error": "max_users must be a non-negative integer"}), 400

    max_repositories = data.get("max_repositories", 0)
    if not isinstance(max_repositories, int) or max_repositories < 0:
        return jsonify({
            "error": "max_repositories must be a non-negative integer"
        }), 400

    max_teams = data.get("max_teams", 0)
    if not isinstance(max_teams, int) or max_teams < 0:
        return jsonify({"error": "max_teams must be a non-negative integer"}), 400

    settings = data.get("settings", {})
    if not isinstance(settings, dict):
        return jsonify({"error": "settings must be an object"}), 400

    # Create tenant
    tenant_id = db.tenants.insert(
        name=name,
        slug=slug,
        description=description,
        is_active=is_active,
        max_users=max_users,
        max_repositories=max_repositories,
        max_teams=max_teams,
        settings=settings,
    )

    # Create default team for the tenant
    team_id = db.teams.insert(
        tenant_id=tenant_id,
        name=name,
        slug="default",
        description=f"Default team for {name}",
        is_active=True,
        is_default=True,
        settings={},
    )

    db.commit()

    # Fetch and return the created tenant
    tenant = db(db.tenants.id == tenant_id).select().first()
    team = db(db.teams.id == team_id).select().first()

    return jsonify({
        "message": "Tenant created successfully",
        "tenant": tenant.as_dict(),
        "default_team": team.as_dict(),
    }), 201


@tenants_bp.route("/<int:tenant_id>", methods=["GET"])
@auth_required
def get_tenant(tenant_id: int):
    """Get tenant details (global admin or tenant member)."""
    user = get_current_user()
    db = get_db()

    # Fetch tenant
    tenant = db(db.tenants.id == tenant_id).select().first()
    if not tenant:
        return jsonify({"error": "Tenant not found"}), 404

    # Permission check: global admin OR tenant member
    is_admin = _is_global_admin(user)
    is_member = _is_tenant_member(user["id"], tenant_id)

    if not is_admin and not is_member:
        return jsonify({
            "error": "Insufficient permissions"
        }), 403

    return jsonify(tenant.as_dict()), 200


@tenants_bp.route("/<int:tenant_id>", methods=["PUT"])
@auth_required
def update_tenant(tenant_id: int):
    """Update tenant (global admin or tenant admin)."""
    user = get_current_user()
    db = get_db()

    # Fetch tenant
    tenant = db(db.tenants.id == tenant_id).select().first()
    if not tenant:
        return jsonify({"error": "Tenant not found"}), 404

    # Permission check: global admin OR tenant admin
    is_admin = _is_global_admin(user)
    is_tenant_admin = _is_tenant_admin(user["id"], tenant_id)

    if not is_admin and not is_tenant_admin:
        return jsonify({
            "error": "Insufficient permissions"
        }), 403

    data = request.get_json() or {}
    update_data = {}

    # Update name if provided
    if "name" in data:
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"error": "Tenant name cannot be empty"}), 400
        if len(name) > 255:
            return jsonify({
                "error": "Tenant name must be 255 characters or less"
            }), 400
        update_data["name"] = name

    # Update description if provided
    if "description" in data:
        description = data.get("description", "").strip()
        update_data["description"] = description

    # Update is_active if provided
    if "is_active" in data:
        is_active = data.get("is_active")
        if not isinstance(is_active, bool):
            return jsonify({"error": "is_active must be a boolean"}), 400
        update_data["is_active"] = is_active

    # Update max_users if provided
    if "max_users" in data:
        max_users = data.get("max_users")
        if not isinstance(max_users, int) or max_users < 0:
            return jsonify({
                "error": "max_users must be a non-negative integer"
            }), 400
        update_data["max_users"] = max_users

    # Update max_repositories if provided
    if "max_repositories" in data:
        max_repositories = data.get("max_repositories")
        if not isinstance(max_repositories, int) or max_repositories < 0:
            return jsonify({
                "error": "max_repositories must be a non-negative integer"
            }), 400
        update_data["max_repositories"] = max_repositories

    # Update max_teams if provided
    if "max_teams" in data:
        max_teams = data.get("max_teams")
        if not isinstance(max_teams, int) or max_teams < 0:
            return jsonify({
                "error": "max_teams must be a non-negative integer"
            }), 400
        update_data["max_teams"] = max_teams

    # Update settings if provided
    if "settings" in data:
        settings = data.get("settings", {})
        if not isinstance(settings, dict):
            return jsonify({"error": "settings must be an object"}), 400
        update_data["settings"] = settings

    if not update_data:
        return jsonify({"error": "No fields to update"}), 400

    # Update tenant
    db(db.tenants.id == tenant_id).update(**update_data)
    db.commit()

    # Fetch and return updated tenant
    updated_tenant = db(db.tenants.id == tenant_id).select().first()
    return jsonify(updated_tenant.as_dict()), 200


@tenants_bp.route("/<int:tenant_id>", methods=["DELETE"])
@auth_required
def delete_tenant(tenant_id: int):
    """Delete tenant (global admin only)."""
    user = get_current_user()

    if not _is_global_admin(user):
        return jsonify({
            "error": "Insufficient permissions",
            "required_role": "admin",
        }), 403

    db = get_db()

    # Fetch tenant
    tenant = db(db.tenants.id == tenant_id).select().first()
    if not tenant:
        return jsonify({"error": "Tenant not found"}), 404

    # Delete tenant (cascade will handle associated data)
    db(db.tenants.id == tenant_id).delete()
    db.commit()

    return jsonify({
        "message": "Tenant deleted successfully"
    }), 204


@tenants_bp.route("/<int:tenant_id>/members", methods=["GET"])
@auth_required
def list_tenant_members(tenant_id: int):
    """List tenant members (tenant admin)."""
    user = get_current_user()
    db = get_db()

    # Fetch tenant
    tenant = db(db.tenants.id == tenant_id).select().first()
    if not tenant:
        return jsonify({"error": "Tenant not found"}), 404

    # Permission check: global admin OR tenant admin
    is_admin = _is_global_admin(user)
    is_tenant_admin = _is_tenant_admin(user["id"], tenant_id)

    if not is_admin and not is_tenant_admin:
        return jsonify({
            "error": "Insufficient permissions"
        }), 403

    # Fetch members
    members = db(db.tenant_members.tenant_id == tenant_id).select(
        orderby=db.tenant_members.joined_at
    )

    result = []
    for member in members:
        member_dict = member.as_dict()
        # Fetch user details
        user_record = db(db.users.id == member.user_id).select().first()
        if user_record:
            member_dict["user"] = user_record.as_dict()
        result.append(member_dict)

    return jsonify({
        "tenant_id": tenant_id,
        "members": result,
        "total": len(result),
    }), 200


@tenants_bp.route("/<int:tenant_id>/members", methods=["POST"])
@auth_required
def add_tenant_member(tenant_id: int):
    """Add user to tenant (global admin or tenant admin)."""
    user = get_current_user()
    db = get_db()

    # Fetch tenant
    tenant = db(db.tenants.id == tenant_id).select().first()
    if not tenant:
        return jsonify({"error": "Tenant not found"}), 404

    # Permission check: global admin OR tenant admin
    is_admin = _is_global_admin(user)
    is_tenant_admin = _is_tenant_admin(user["id"], tenant_id)

    if not is_admin and not is_tenant_admin:
        return jsonify({
            "error": "Insufficient permissions"
        }), 403

    data = request.get_json() or {}

    # Validate required fields
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    if not isinstance(user_id, int) or user_id <= 0:
        return jsonify({"error": "user_id must be a positive integer"}), 400

    # Fetch user
    user_record = db(db.users.id == user_id).select().first()
    if not user_record:
        return jsonify({"error": "User not found"}), 404

    # Check if user is already a member
    existing = db(
        (db.tenant_members.tenant_id == tenant_id) &
        (db.tenant_members.user_id == user_id)
    ).select().first()

    if existing:
        return jsonify({
            "error": "User is already a member of this tenant"
        }), 409

    # Validate role
    role = data.get("role", "viewer").lower()
    if role not in ["admin", "maintainer", "viewer", "custom"]:
        return jsonify({
            "error": "Invalid role. Must be: admin, maintainer, viewer, or custom"
        }), 400

    scopes = data.get("scopes", [])
    if not isinstance(scopes, list):
        return jsonify({"error": "scopes must be a list"}), 400

    # Create tenant membership
    member_id = db.tenant_members.insert(
        tenant_id=tenant_id,
        user_id=user_id,
        role=role,
        scopes=scopes,
        is_active=True,
    )

    db.commit()

    # Fetch and return the created membership
    member = db(db.tenant_members.id == member_id).select().first()
    member_dict = member.as_dict()
    member_dict["user"] = user_record.as_dict()

    return jsonify({
        "message": "User added to tenant successfully",
        "membership": member_dict,
    }), 201


@tenants_bp.route("/<int:tenant_id>/members/<int:user_id>", methods=["DELETE"])
@auth_required
def remove_tenant_member(tenant_id: int, user_id: int):
    """Remove user from tenant (global admin or tenant admin)."""
    user = get_current_user()
    db = get_db()

    # Fetch tenant
    tenant = db(db.tenants.id == tenant_id).select().first()
    if not tenant:
        return jsonify({"error": "Tenant not found"}), 404

    # Permission check: global admin OR tenant admin
    is_admin = _is_global_admin(user)
    is_tenant_admin = _is_tenant_admin(user["id"], tenant_id)

    if not is_admin and not is_tenant_admin:
        return jsonify({
            "error": "Insufficient permissions"
        }), 403

    # Check membership exists
    member = db(
        (db.tenant_members.tenant_id == tenant_id) &
        (db.tenant_members.user_id == user_id)
    ).select().first()

    if not member:
        return jsonify({
            "error": "User is not a member of this tenant"
        }), 404

    # Delete membership
    db(
        (db.tenant_members.tenant_id == tenant_id) &
        (db.tenant_members.user_id == user_id)
    ).delete()
    db.commit()

    return jsonify({
        "message": "User removed from tenant successfully"
    }), 204
