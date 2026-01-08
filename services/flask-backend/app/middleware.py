"""Authentication and Authorization Middleware."""

from functools import wraps
from typing import Callable, Optional

import jwt
from flask import current_app, g, jsonify, request

from .models import get_user_by_id


def get_token_from_header() -> Optional[str]:
    """Extract JWT token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(
            token,
            current_app.config["JWT_SECRET_KEY"],
            algorithms=["HS256"],
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_current_user() -> Optional[dict]:
    """Get current authenticated user from request context."""
    return getattr(g, "current_user", None)


def auth_required(f: Callable) -> Callable:
    """Decorator to require authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()

        if not token:
            return jsonify({"error": "Missing authorization token"}), 401

        payload = decode_token(token)
        if not payload:
            return jsonify({"error": "Invalid or expired token"}), 401

        # Check token type
        if payload.get("type") != "access":
            return jsonify({"error": "Invalid token type"}), 401

        # Get user from database
        user_id = payload.get("sub")
        if not user_id:
            return jsonify({"error": "Invalid token payload"}), 401

        user = get_user_by_id(int(user_id))
        if not user:
            return jsonify({"error": "User not found"}), 401

        if not user.get("is_active"):
            return jsonify({"error": "User account is deactivated"}), 401

        # Store user in request context
        g.current_user = user

        return f(*args, **kwargs)

    return decorated


def role_required(*allowed_roles: str) -> Callable:
    """Decorator to require specific roles."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()

            if not user:
                return jsonify({"error": "Authentication required"}), 401

            user_role = user.get("role", "")
            if user_role not in allowed_roles:
                return jsonify({
                    "error": "Insufficient permissions",
                    "required_roles": list(allowed_roles),
                    "your_role": user_role,
                }), 403

            return f(*args, **kwargs)

        return decorated

    return decorator


def admin_required(f: Callable) -> Callable:
    """Decorator to require admin role."""
    return role_required("admin")(f)


def maintainer_or_admin_required(f: Callable) -> Callable:
    """Decorator to require maintainer or admin role."""
    return role_required("admin", "maintainer")(f)
