"""JWT authentication middleware for worker-scanner service.

This module provides JWT token validation middleware that integrates with
the flask-backend service's authentication system. It validates JWT tokens
from the Authorization header and makes user information available to routes.
"""

import os
from functools import wraps
from typing import Any, Callable, Dict, Optional

import jwt
from flask import g, jsonify, request


def jwt_required(f: Callable) -> Callable:
    """Decorator that requires a valid JWT token for route access.

    Extracts and validates JWT token from Authorization header.
    On success, stores decoded payload in flask.g.current_user.
    On failure, returns 401 JSON error response.

    Args:
        f: The Flask route function to wrap

    Returns:
        Wrapped function that validates JWT before execution

    Example:
        @app.route('/protected')
        @jwt_required
        def protected_route():
            user_id = get_current_user_id()
            return jsonify({"message": f"Hello {user_id}"})
    """

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return (
                jsonify({"error": "No authorization token provided", "code": 401}),
                401,
            )

        # Parse Bearer token
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return (
                jsonify({"error": "Invalid authorization header format", "code": 401}),
                401,
            )

        token = parts[1]

        # Get JWT configuration from environment
        secret_key = os.environ.get("JWT_SECRET_KEY", "dev-secret-key")
        algorithm = os.environ.get("JWT_ALGORITHM", "HS256")

        # Validate and decode token
        try:
            payload = jwt.decode(
                token,
                secret_key,
                algorithms=[algorithm],
                options={
                    "verify_exp": True,  # Verify expiration
                    "verify_iat": True,  # Verify issued-at
                },
            )
            # Store decoded payload in flask.g for route access
            g.current_user = payload
            return f(*args, **kwargs)

        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired", "code": 401}), 401

        except jwt.InvalidTokenError as e:
            return jsonify({"error": f"Invalid token: {str(e)}", "code": 401}), 401

        except Exception as e:
            return (
                jsonify({"error": f"Token decoding failed: {str(e)}", "code": 401}),
                401,
            )

    return decorated_function


def optional_jwt(f: Callable) -> Callable:
    """Decorator that optionally validates JWT token if present.

    Similar to jwt_required but doesn't return 401 if no token is provided.
    Sets g.current_user to None if no token and proceeds with route execution.

    Args:
        f: The Flask route function to wrap

    Returns:
        Wrapped function that optionally validates JWT

    Example:
        @app.route('/public')
        @optional_jwt
        def public_route():
            user = get_current_user()
            if user:
                return jsonify({"message": f"Hello {user['sub']}"})
            return jsonify({"message": "Hello anonymous"})
    """

    @wraps(f)
    def decorated_function(*args: Any, **kwargs: Any) -> Any:
        # Extract token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            g.current_user = None
            return f(*args, **kwargs)

        # Parse Bearer token
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            g.current_user = None
            return f(*args, **kwargs)

        token = parts[1]

        # Get JWT configuration from environment
        secret_key = os.environ.get("JWT_SECRET_KEY", "dev-secret-key")
        algorithm = os.environ.get("JWT_ALGORITHM", "HS256")

        # Validate and decode token
        try:
            payload = jwt.decode(
                token,
                secret_key,
                algorithms=[algorithm],
                options={
                    "verify_exp": True,  # Verify expiration
                    "verify_iat": True,  # Verify issued-at
                },
            )
            # Store decoded payload in flask.g for route access
            g.current_user = payload

        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, Exception):
            # Silently fail and set current_user to None
            g.current_user = None

        return f(*args, **kwargs)

    return decorated_function


def get_current_user() -> Optional[Dict[str, Any]]:
    """Get the current authenticated user from flask.g.

    Returns:
        Decoded JWT payload dictionary if user is authenticated, None otherwise

    Example:
        user = get_current_user()
        if user:
            print(f"User ID: {user['sub']}")
            print(f"Email: {user.get('email')}")
    """
    return getattr(g, "current_user", None)


def get_current_user_id() -> str:
    """Get the current user ID from JWT payload.

    Returns:
        User ID from 'sub' claim if authenticated, 'anonymous' otherwise

    Example:
        user_id = get_current_user_id()
        print(f"Current user: {user_id}")
    """
    user = get_current_user()
    if user and "sub" in user:
        return user["sub"]
    return "anonymous"
