"""Authentication Endpoints."""

import hashlib
from datetime import datetime, timedelta

import bcrypt
import jwt
from flask import Blueprint, current_app, jsonify, request

from .middleware import auth_required, get_current_user
from .models import (
    create_user,
    get_user_by_email,
    is_refresh_token_valid,
    revoke_all_user_tokens,
    revoke_refresh_token,
    store_refresh_token,
)

auth_bp = Blueprint("auth", __name__)


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(user_id: int, role: str) -> str:
    """Create JWT access token."""
    expires = datetime.utcnow() + current_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
    payload = {
        "sub": str(user_id),
        "role": role,
        "type": "access",
        "exp": expires,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")


def create_refresh_token(user_id: int) -> tuple[str, datetime]:
    """Create JWT refresh token and store hash in database."""
    expires = datetime.utcnow() + current_app.config["JWT_REFRESH_TOKEN_EXPIRES"]
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": expires,
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, current_app.config["JWT_SECRET_KEY"], algorithm="HS256")

    # Store hash of token in database for revocation
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    store_refresh_token(user_id, token_hash, expires)

    return token, expires


@auth_bp.route("/login", methods=["POST"])
def login():
    """Login endpoint - returns access and refresh tokens."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    # Find user
    user = get_user_by_email(email)
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    # Verify password
    if not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    # Check if user is active
    if not user.get("is_active"):
        return jsonify({"error": "Account is deactivated"}), 401

    # Generate tokens
    access_token = create_access_token(user["id"], user["role"])
    refresh_token, refresh_expires = create_refresh_token(user["id"])

    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user.get("full_name", ""),
            "role": user["role"],
        },
    }), 200


@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    """Refresh access token using refresh token."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    refresh_token = data.get("refresh_token", "")

    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400

    # Decode token
    try:
        payload = jwt.decode(
            refresh_token,
            current_app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401

    # Verify token type
    if payload.get("type") != "refresh":
        return jsonify({"error": "Invalid token type"}), 401

    # Check if token is revoked
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    if not is_refresh_token_valid(token_hash):
        return jsonify({"error": "Refresh token has been revoked"}), 401

    # Get user
    user_id = int(payload["sub"])
    user = get_user_by_email_by_id(user_id)
    if not user or not user.get("is_active"):
        return jsonify({"error": "User not found or deactivated"}), 401

    # Revoke old refresh token
    revoke_refresh_token(token_hash)

    # Generate new tokens
    access_token = create_access_token(user["id"], user["role"])
    new_refresh_token, refresh_expires = create_refresh_token(user["id"])

    return jsonify({
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "Bearer",
        "expires_in": int(current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()),
    }), 200


# Fix: Import the correct function
def get_user_by_email_by_id(user_id: int):
    """Get user by ID - wrapper for import issue."""
    from .models import get_user_by_id
    return get_user_by_id(user_id)


@auth_bp.route("/logout", methods=["POST"])
@auth_required
def logout():
    """Logout endpoint - revokes all refresh tokens for user."""
    user = get_current_user()

    # Revoke all user's refresh tokens
    revoked_count = revoke_all_user_tokens(user["id"])

    return jsonify({
        "message": "Successfully logged out",
        "tokens_revoked": revoked_count,
    }), 200


@auth_bp.route("/me", methods=["GET"])
@auth_required
def get_me():
    """Get current user profile."""
    user = get_current_user()

    return jsonify({
        "id": user["id"],
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "role": user["role"],
        "is_active": user["is_active"],
        "created_at": user["created_at"].isoformat() if user.get("created_at") else None,
    }), 200


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register new user (creates viewer role by default)."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    full_name = data.get("full_name", "").strip()

    # Validation
    if not email:
        return jsonify({"error": "Email is required"}), 400

    if not password or len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

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
        role="viewer",  # Default role for self-registration
    )

    return jsonify({
        "message": "Registration successful",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "full_name": user.get("full_name", ""),
            "role": user["role"],
        },
    }), 201
