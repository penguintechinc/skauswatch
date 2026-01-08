"""User Management Endpoints (Admin Only)."""

from flask import Blueprint, jsonify, request

from .auth import hash_password
from .middleware import admin_required, auth_required
from .models import (
    VALID_ROLES,
    create_user,
    delete_user,
    get_user_by_email,
    get_user_by_id,
    list_users,
    update_user,
)

users_bp = Blueprint("users", __name__)


@users_bp.route("", methods=["GET"])
@auth_required
@admin_required
def get_users():
    """List all users with pagination (Admin only)."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    # Limit per_page to reasonable bounds
    per_page = min(max(per_page, 1), 100)

    users, total = list_users(page=page, per_page=per_page)

    # Remove password hashes from response
    for user in users:
        user.pop("password_hash", None)

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
@admin_required
def get_user(user_id: int):
    """Get single user by ID (Admin only)."""
    user = get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    # Remove password hash from response
    user.pop("password_hash", None)

    return jsonify(user), 200


@users_bp.route("", methods=["POST"])
@auth_required
@admin_required
def create_new_user():
    """Create new user (Admin only)."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    full_name = data.get("full_name", "").strip()
    role = data.get("role", "viewer")

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

    # Create user
    password_hash = hash_password(password)
    user = create_user(
        email=email,
        password_hash=password_hash,
        full_name=full_name,
        role=role,
    )

    # Remove password hash from response
    user.pop("password_hash", None)

    return jsonify({
        "message": "User created successfully",
        "user": user,
    }), 201


@users_bp.route("/<int:user_id>", methods=["PUT"])
@auth_required
@admin_required
def update_existing_user(user_id: int):
    """Update user by ID (Admin only)."""
    user = get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

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
@admin_required
def delete_existing_user(user_id: int):
    """Delete user by ID (Admin only)."""
    from .middleware import get_current_user

    current_user = get_current_user()

    # Prevent self-deletion
    if current_user["id"] == user_id:
        return jsonify({"error": "Cannot delete your own account"}), 400

    user = get_user_by_id(user_id)

    if not user:
        return jsonify({"error": "User not found"}), 404

    success = delete_user(user_id)

    if not success:
        return jsonify({"error": "Failed to delete user"}), 500

    return jsonify({"message": "User deleted successfully"}), 200


@users_bp.route("/roles", methods=["GET"])
@auth_required
@admin_required
def get_roles():
    """Get list of valid roles (Admin only)."""
    return jsonify({
        "roles": VALID_ROLES,
        "descriptions": {
            "admin": "Full access: user CRUD, settings, all features",
            "maintainer": "Read/write access to resources, no user management",
            "viewer": "Read-only access to resources",
        },
    }), 200
