"""
Authentication API endpoints.

Provides:
- Login/Logout
- Token refresh
- User registration
- Current user profile
"""

import hashlib
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional

import bcrypt
import jwt
from models.db import get_db
from pydantic import ValidationError
from quart import Blueprint, current_app, g, jsonify, request
from validators.pydantic_models import (
    LoginRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

bp = Blueprint("auth", __name__)


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(user_id: int, role: str, config) -> str:
    """Create JWT access token."""
    expires = datetime.utcnow() + config.auth.access_token_expires
    payload = {
        "sub": str(user_id),
        "role": role,
        "type": "access",
        "exp": expires,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(
        payload, config.auth.jwt_secret, algorithm=config.auth.jwt_algorithm
    )


def create_refresh_token(user_id: int, config, db) -> tuple[str, datetime]:
    """Create JWT refresh token and store hash in database."""
    expires = datetime.utcnow() + config.auth.refresh_token_expires
    payload = {
        "sub": str(user_id),
        "type": "refresh",
        "exp": expires,
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(
        payload, config.auth.jwt_secret, algorithm=config.auth.jwt_algorithm
    )

    # Store hash of token in database for revocation
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db.refresh_tokens.insert(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires,
    )
    db.commit()

    return token, expires


def auth_required(f):
    """Decorator to require authentication."""

    @wraps(f)
    async def decorated(*args, **kwargs):
        config = current_app.config["MANAGER_CONFIG"]

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization header"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = jwt.decode(
                token,
                config.auth.jwt_secret,
                algorithms=[config.auth.jwt_algorithm],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401

        if payload.get("type") != "access":
            return jsonify({"error": "Invalid token type"}), 401

        # Get user from database
        db = get_db(config.database.uri)
        user = db(db.users.id == int(payload["sub"])).select().first()

        if not user or not user.is_active:
            return jsonify({"error": "User not found or inactive"}), 401

        g.current_user = user.as_dict()
        g.current_user_id = user.id

        return await f(*args, **kwargs)

    return decorated


def role_required(*roles):
    """Decorator to require specific roles."""

    def decorator(f):
        @wraps(f)
        async def decorated(*args, **kwargs):
            if not hasattr(g, "current_user"):
                return jsonify({"error": "Authentication required"}), 401

            if g.current_user["role"] not in roles:
                return jsonify({"error": "Insufficient permissions"}), 403

            return await f(*args, **kwargs)

        return decorated

    return decorator


@bp.route("/login", methods=["POST"])
async def login():
    """Login endpoint - returns access and refresh tokens."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        login_data = LoginRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    # Find user
    user = db(db.users.email == login_data.email.lower()).select().first()
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    # Check account lockout
    if user.account_locked_until and user.account_locked_until > datetime.utcnow():
        return jsonify({"error": "Account is locked. Please try again later."}), 401

    # Verify password
    if not verify_password(login_data.password, user.password_hash):
        # Increment failed attempts
        db(db.users.id == user.id).update(
            failed_login_attempts=user.failed_login_attempts + 1
        )

        # Lock account if too many failures
        if user.failed_login_attempts + 1 >= config.auth.max_login_attempts:
            lockout_until = datetime.utcnow() + timedelta(
                minutes=config.auth.lockout_duration_minutes
            )
            db(db.users.id == user.id).update(account_locked_until=lockout_until)

        db.commit()
        return jsonify({"error": "Invalid email or password"}), 401

    # Check if user is active
    if not user.is_active:
        return jsonify({"error": "Account is deactivated"}), 401

    # Reset failed attempts on successful login
    db(db.users.id == user.id).update(
        failed_login_attempts=0,
        account_locked_until=None,
    )
    db.commit()

    # Generate tokens
    access_token = create_access_token(user.id, user.role, config)
    refresh_token, refresh_expires = create_refresh_token(user.id, config, db)

    return (
        jsonify(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": int(config.auth.access_token_expires.total_seconds()),
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name or "",
                    "role": user.role,
                },
            }
        ),
        200,
    )


@bp.route("/refresh", methods=["POST"])
async def refresh():
    """Refresh access token using refresh token."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        refresh_data = RefreshTokenRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    # Decode token
    try:
        payload = jwt.decode(
            refresh_data.refresh_token,
            config.auth.jwt_secret,
            algorithms=[config.auth.jwt_algorithm],
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401

    if payload.get("type") != "refresh":
        return jsonify({"error": "Invalid token type"}), 401

    db = get_db(config.database.uri)

    # Check if token is revoked
    token_hash = hashlib.sha256(refresh_data.refresh_token.encode()).hexdigest()
    stored_token = (
        db(
            (db.refresh_tokens.token_hash == token_hash)
            & (db.refresh_tokens.revoked == False)
            & (db.refresh_tokens.expires_at > datetime.utcnow())
        )
        .select()
        .first()
    )

    if not stored_token:
        return jsonify({"error": "Refresh token has been revoked"}), 401

    # Get user
    user_id = int(payload["sub"])
    user = db(db.users.id == user_id).select().first()
    if not user or not user.is_active:
        return jsonify({"error": "User not found or deactivated"}), 401

    # Revoke old refresh token
    db(db.refresh_tokens.token_hash == token_hash).update(revoked=True)
    db.commit()

    # Generate new tokens
    access_token = create_access_token(user.id, user.role, config)
    new_refresh_token, refresh_expires = create_refresh_token(user.id, config, db)

    return (
        jsonify(
            {
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer",
                "expires_in": int(config.auth.access_token_expires.total_seconds()),
            }
        ),
        200,
    )


@bp.route("/logout", methods=["POST"])
@auth_required
async def logout():
    """Logout endpoint - revokes all refresh tokens for user."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Revoke all user's refresh tokens
    revoked_count = db(db.refresh_tokens.user_id == g.current_user_id).update(
        revoked=True
    )
    db.commit()

    return (
        jsonify(
            {
                "message": "Successfully logged out",
                "tokens_revoked": revoked_count,
            }
        ),
        200,
    )


@bp.route("/me", methods=["GET"])
@auth_required
async def get_me():
    """Get current user profile."""
    user = g.current_user

    return (
        jsonify(
            {
                "id": user["id"],
                "email": user["email"],
                "full_name": user.get("full_name", ""),
                "role": user["role"],
                "is_active": user["is_active"],
                "mfa_enabled": user.get("mfa_enabled", False),
                "created_at": (
                    user["created_at"].isoformat() if user.get("created_at") else None
                ),
            }
        ),
        200,
    )


@bp.route("/register", methods=["POST"])
async def register():
    """Register new user (creates viewer role by default)."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        register_data = RegisterRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    # Check if user exists
    existing = db(db.users.email == register_data.email.lower()).select().first()
    if existing:
        return jsonify({"error": "Email already registered"}), 409

    # Create user
    password_hash = hash_password(register_data.password)
    user_id = db.users.insert(
        email=register_data.email.lower(),
        password_hash=password_hash,
        full_name=register_data.full_name,
        role="viewer",
        is_active=True,
    )
    db.commit()

    user = db(db.users.id == user_id).select().first()

    return (
        jsonify(
            {
                "message": "Registration successful",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name or "",
                    "role": user.role,
                },
            }
        ),
        201,
    )
