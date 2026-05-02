"""
User management API endpoints.

Provides:
- List users
- Get user by ID
- Create user (admin only)
- Update user
- Delete user (admin only)
"""

from datetime import datetime
from typing import Optional

from api.v1.auth import auth_required, hash_password, role_required
from models.db import get_db
from penguin_licensing import get_license_client
from pydantic import BaseModel, EmailStr, Field, ValidationError
from quart import Blueprint, current_app, g, jsonify, request
from validators.pydantic_models import UserResponse, UserRole

bp = Blueprint("users", __name__)


class UserCreateRequest(BaseModel):
    """User creation request."""

    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(default="", max_length=255)
    role: UserRole = Field(default=UserRole.VIEWER)
    is_active: bool = Field(default=True)


class UserUpdateRequest(BaseModel):
    """User update request."""

    email: Optional[EmailStr] = None
    full_name: Optional[str] = Field(None, max_length=255)
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=8, max_length=128)


@bp.route("", methods=["GET"])
@auth_required
@role_required("admin", "maintainer")
async def list_users():
    """List all users with pagination."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Get pagination params
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    per_page = min(per_page, 100)  # Limit max per page

    offset = (page - 1) * per_page

    # Query users
    users = db(db.users).select(
        orderby=db.users.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(db.users).count()

    # Convert to response format
    user_list = []
    for user in users:
        user_list.append(
            {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name or "",
                "role": user.role,
                "is_active": user.is_active,
                "mfa_enabled": user.mfa_enabled or False,
                "created_at": user.created_at.isoformat() if user.created_at else None,
            }
        )

    return (
        jsonify(
            {
                "items": user_list,
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page,
            }
        ),
        200,
    )


@bp.route("/<int:user_id>", methods=["GET"])
@auth_required
async def get_user(user_id: int):
    """Get user by ID."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Users can view their own profile, admins/maintainers can view any
    if g.current_user_id != user_id and g.current_user["role"] not in [
        "admin",
        "maintainer",
    ]:
        return jsonify({"error": "Forbidden"}), 403

    user = db(db.users.id == user_id).select().first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    return (
        jsonify(
            {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name or "",
                "role": user.role,
                "is_active": user.is_active,
                "mfa_enabled": user.mfa_enabled or False,
                "created_at": user.created_at.isoformat() if user.created_at else None,
                "updated_at": user.updated_at.isoformat() if user.updated_at else None,
            }
        ),
        200,
    )


@bp.route("", methods=["POST"])
@auth_required
@role_required("admin")
async def create_user():
    """Create a new user (admin only)."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        create_data = UserCreateRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    # Enforce free-tier user cap
    siem_cfg = config.siem
    try:
        lc = get_license_client()
        has_premium = lc.has_feature("premium")
    except Exception:
        has_premium = False

    if not has_premium:
        request_host = request.headers.get("Host", "")
        is_exempt = any(
            request_host == d or request_host.endswith(f".{d}")
            for d in siem_cfg.exempt_domains
        )
        if not is_exempt:
            user_count = db(db.users).count()
            if user_count >= siem_cfg.free_tier_user_cap:
                return (
                    jsonify(
                        {
                            "error": "User limit reached. Upgrade to premium for more than 5 users."
                        }
                    ),
                    403,
                )

    # Check if email already exists
    existing = db(db.users.email == create_data.email.lower()).select().first()
    if existing:
        return jsonify({"error": "Email already registered"}), 409

    # Create user
    password_hash = hash_password(create_data.password)
    user_id = db.users.insert(
        email=create_data.email.lower(),
        password_hash=password_hash,
        full_name=create_data.full_name,
        role=create_data.role.value,
        is_active=create_data.is_active,
    )
    db.commit()

    user = db(db.users.id == user_id).select().first()

    return (
        jsonify(
            {
                "message": "User created successfully",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name or "",
                    "role": user.role,
                    "is_active": user.is_active,
                },
            }
        ),
        201,
    )


@bp.route("/<int:user_id>", methods=["PUT"])
@auth_required
async def update_user(user_id: int):
    """Update a user."""
    config = current_app.config["MANAGER_CONFIG"]

    # Users can update their own profile (limited), admins can update anyone
    is_self = g.current_user_id == user_id
    is_admin = g.current_user["role"] == "admin"

    if not is_self and not is_admin:
        return jsonify({"error": "Forbidden"}), 403

    try:
        data = await request.get_json()
        update_data = UserUpdateRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    user = db(db.users.id == user_id).select().first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Build update dict
    updates = {}

    if update_data.full_name is not None:
        updates["full_name"] = update_data.full_name

    if update_data.password is not None:
        updates["password_hash"] = hash_password(update_data.password)

    # Only admins can change these
    if is_admin:
        if update_data.email is not None:
            # Check if new email already exists
            existing = (
                db(
                    (db.users.email == update_data.email.lower())
                    & (db.users.id != user_id)
                )
                .select()
                .first()
            )
            if existing:
                return jsonify({"error": "Email already in use"}), 409
            updates["email"] = update_data.email.lower()

        if update_data.role is not None:
            updates["role"] = update_data.role.value

        if update_data.is_active is not None:
            updates["is_active"] = update_data.is_active

    if updates:
        db(db.users.id == user_id).update(**updates)
        db.commit()

    # Fetch updated user
    user = db(db.users.id == user_id).select().first()

    return (
        jsonify(
            {
                "message": "User updated successfully",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name or "",
                    "role": user.role,
                    "is_active": user.is_active,
                },
            }
        ),
        200,
    )


@bp.route("/<int:user_id>", methods=["DELETE"])
@auth_required
@role_required("admin")
async def delete_user(user_id: int):
    """Delete a user (admin only)."""
    config = current_app.config["MANAGER_CONFIG"]

    # Prevent self-deletion
    if g.current_user_id == user_id:
        return jsonify({"error": "Cannot delete your own account"}), 400

    db = get_db(config.database.uri)

    user = db(db.users.id == user_id).select().first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Delete associated refresh tokens first
    db(db.refresh_tokens.user_id == user_id).delete()

    # Delete user
    db(db.users.id == user_id).delete()
    db.commit()

    return jsonify({"message": "User deleted successfully"}), 200
