"""User Management Endpoints (Admin Only)."""

from flask import Blueprint, jsonify, request

from .auth import hash_password
from .middleware import admin_required, auth_required, get_current_user
from .models import (
    VALID_ROLES,
    create_user,
    delete_user,
    get_db,
    get_user_by_email,
    get_user_by_id,
    list_users,
    update_user,
)
from .rbac import get_user_tenant_filter, require_scope

users_bp = Blueprint("users", __name__)


@users_bp.route("", methods=["GET"])
@auth_required
@require_scope("users:read")
def get_users():
    """List users with pagination and tenant filtering."""
    current_user = get_current_user()
    user_id = current_user.get("id")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    # Limit per_page to reasonable bounds
    per_page = min(max(per_page, 1), 100)

    # Get tenant filter for current user
    tenant_filter = get_user_tenant_filter(user_id)

    db = get_db()
    offset = (page - 1) * per_page

    # Build query based on tenant filter
    if tenant_filter is not None:
        # Tenant user - only see users in their tenant
        query = (
            (db.tenant_members.tenant_id == tenant_filter) &
            (db.tenant_members.is_active == True)
        )
        users_query = db(query).select(
            db.users.id,
            db.users.email,
            db.users.password_hash,
            db.users.full_name,
            db.users.role,
            db.users.global_role,
            db.users.default_tenant_id,
            db.users.is_active,
            db.users.created_at,
            db.users.updated_at,
            db.tenant_members.role,
            orderby=db.users.created_at,
            limitby=(offset, offset + per_page),
        )
        total_query = db(query)
        total = total_query.count()

        # Extract user records from joined query
        users = []
        for row in users_query:
            user_dict = row.users.as_dict()
            user_dict.pop("password_hash", None)
            users.append(user_dict)
    else:
        # Global user (admin/maintainer) - see all users
        users_query = db(db.users.id > 0).select(
            orderby=db.users.created_at,
            limitby=(offset, offset + per_page),
        )
        total = db(db.users.id > 0).count()

        users = []
        for user in users_query:
            user_dict = user.as_dict()
            user_dict.pop("password_hash", None)
            users.append(user_dict)

    return jsonify({
        "users": users,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }), 200


@users_bp.route("/<int:user_id>", methods=["GET"])
@auth_required
@require_scope("users:read")
def get_user(user_id: int):
    """Get single user by ID with tenant filtering."""
    current_user = get_current_user()
    current_user_id = current_user.get("id")
    tenant_filter = get_user_tenant_filter(current_user_id)

    user = get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check tenant isolation for tenant users
    if tenant_filter is not None:
        db = get_db()
        # Verify user is in same tenant
        user_in_tenant = db(
            (db.tenant_members.user_id == user_id) &
            (db.tenant_members.tenant_id == tenant_filter) &
            (db.tenant_members.is_active == True)
        ).select().first()

        if not user_in_tenant:
            return jsonify({"error": "Access denied"}), 403

    # Remove password hash from response
    user.pop("password_hash", None)

    return jsonify(user), 200


@users_bp.route("", methods=["POST"])
@auth_required
@require_scope("users:write")
def create_new_user():
    """Create new user with tenant assignment."""
    current_user = get_current_user()
    current_user_id = current_user.get("id")
    tenant_filter = get_user_tenant_filter(current_user_id)

    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    full_name = data.get("full_name", "").strip()
    role = data.get("role", "viewer")
    target_tenant_id = data.get("tenant_id")

    # Validation
    if not email:
        return jsonify({"error": "Email is required"}), 400

    if not password or len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    if role not in VALID_ROLES:
        return jsonify({
            "error": f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}"
        }), 400

    # Check if user exists
    existing = get_user_by_email(email)
    if existing:
        return jsonify({"error": "Email already registered"}), 409

    db = get_db()

    # Determine tenant assignment
    if target_tenant_id:
        # Global admin specified target tenant
        if tenant_filter is not None:
            # Tenant user cannot specify different tenant
            return jsonify({
                "error": "Tenant users can only add users to their own tenant"
            }), 403

        # Verify target tenant exists
        target_tenant = db(db.tenants.id == target_tenant_id).select().first()
        if not target_tenant:
            return jsonify({"error": "Target tenant not found"}), 404

        assigned_tenant_id = target_tenant_id
    else:
        # No tenant specified
        if tenant_filter is not None:
            # Tenant user - assign to their tenant
            assigned_tenant_id = tenant_filter
        else:
            # Global admin must specify tenant
            return jsonify({
                "error": "Global admins must specify tenant_id in request body"
            }), 400

    # Verify assigned tenant exists
    assigned_tenant = db(db.tenants.id == assigned_tenant_id).select().first()
    if not assigned_tenant:
        return jsonify({"error": "Assigned tenant not found"}), 500

    # Get default team for the tenant
    default_team = db(
        (db.teams.tenant_id == assigned_tenant_id) &
        (db.teams.is_default == True)
    ).select().first()

    if not default_team:
        return jsonify({
            "error": "Default team not found for tenant"
        }), 500

    # Create user with global role viewer and default tenant
    password_hash = hash_password(password)
    user_id = db.users.insert(
        email=email,
        password_hash=password_hash,
        full_name=full_name,
        role=role,
        global_role="viewer",  # Default global role
        default_tenant_id=assigned_tenant_id,
        is_active=True,
    )
    db.commit()

    # Add user to tenant as viewer
    db.tenant_members.insert(
        tenant_id=assigned_tenant_id,
        user_id=user_id,
        role="viewer",
        is_active=True,
    )
    db.commit()

    # Add user to default team as viewer
    db.team_members.insert(
        team_id=default_team.id,
        user_id=user_id,
        role="viewer",
        is_active=True,
    )
    db.commit()

    user = get_user_by_id(user_id)

    # Remove password hash from response
    user.pop("password_hash", None)

    return jsonify({
        "message": "User created successfully",
        "user": user,
    }), 201


@users_bp.route("/<int:user_id>", methods=["PUT"])
@auth_required
@require_scope("users:write")
def update_existing_user(user_id: int):
    """Update user by ID with tenant filtering."""
    current_user = get_current_user()
    current_user_id = current_user.get("id")
    tenant_filter = get_user_tenant_filter(current_user_id)

    user = get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check tenant isolation for tenant users
    if tenant_filter is not None:
        db = get_db()
        # Verify user is in same tenant
        user_in_tenant = db(
            (db.tenant_members.user_id == user_id) &
            (db.tenant_members.tenant_id == tenant_filter) &
            (db.tenant_members.is_active == True)
        ).select().first()

        if not user_in_tenant:
            return jsonify({"error": "Access denied"}), 403

    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    update_data = {}

    # Email update
    if "email" in data:
        email = data["email"].strip().lower()
        if email != user["email"]:
            existing = get_user_by_email(email)
            if existing:
                return jsonify({"error": "Email already in use"}), 409
            update_data["email"] = email

    # Full name update
    if "full_name" in data:
        update_data["full_name"] = data["full_name"].strip()

    # Role update
    if "role" in data:
        role = data["role"]
        if role not in VALID_ROLES:
            return jsonify({
                "error": f"Invalid role. Must be one of: {', '.join(VALID_ROLES)}"
            }), 400
        update_data["role"] = role

    # Active status update
    if "is_active" in data:
        update_data["is_active"] = bool(data["is_active"])

    # Password update
    if "password" in data:
        password = data["password"]
        if len(password) < 8:
            return jsonify({"error": "Password must be at least 8 characters"}), 400
        update_data["password_hash"] = hash_password(password)

    if not update_data:
        return jsonify({"error": "No valid fields to update"}), 400

    updated_user = update_user(user_id, **update_data)

    # Remove password hash from response
    updated_user.pop("password_hash", None)

    return jsonify({
        "message": "User updated successfully",
        "user": updated_user,
    }), 200


@users_bp.route("/<int:user_id>", methods=["DELETE"])
@auth_required
@require_scope("users:admin")
def delete_existing_user(user_id: int):
    """Delete user by ID with tenant filtering."""
    current_user = get_current_user()
    current_user_id = current_user.get("id")
    tenant_filter = get_user_tenant_filter(current_user_id)

    # Prevent self-deletion
    if current_user_id == user_id:
        return jsonify({"error": "Cannot delete your own account"}), 400

    user = get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Check tenant isolation for tenant users
    if tenant_filter is not None:
        db = get_db()
        # Verify user is in same tenant
        user_in_tenant = db(
            (db.tenant_members.user_id == user_id) &
            (db.tenant_members.tenant_id == tenant_filter) &
            (db.tenant_members.is_active == True)
        ).select().first()

        if not user_in_tenant:
            return jsonify({"error": "Access denied"}), 403

    success = delete_user(user_id)

    if not success:
        return jsonify({"error": "Failed to delete user"}), 500

    return jsonify({"message": "User deleted successfully"}), 200


@users_bp.route("/roles", methods=["GET"])
@auth_required
@require_scope("users:read")
def get_roles():
    """Get list of valid roles."""
    return jsonify({
        "roles": VALID_ROLES,
        "descriptions": {
            "admin": "Full access: user CRUD, settings, all features",
            "maintainer": "Read/write access to resources, no user management",
            "viewer": "Read-only access to resources",
        },
    }), 200
