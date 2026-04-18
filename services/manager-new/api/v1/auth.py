"""
Authentication API endpoints using penguin-aaa OIDC provider.

Provides:
- Login/Logout with RS256 JWT tokens via OIDCProvider
- Token refresh with database-backed revocation
- User registration
- Current user profile
- OIDC discovery endpoints (/.well-known/openid-configuration, /jwks)
"""

import hashlib
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Optional

import bcrypt
from models.db import get_db
from penguin_aaa.authn import Claims, OIDCProvider, OIDCProviderConfig, TokenSet
from penguin_aaa.crypto import FileKeyStore, MemoryKeyStore
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


# ============================================
# OIDC Provider (lazy initialization)
# ============================================


def _get_oidc_components():
    """Get or create OIDC provider and keystore (lazy init per-app)."""
    if "OIDC_PROVIDER" not in current_app.config:
        config = current_app.config["MANAGER_CONFIG"]

        # Create keystore (file-backed for persistence, or in-memory)
        if config.auth.oidc_keystore_path:
            keystore = FileKeyStore(
                path=Path(config.auth.oidc_keystore_path),
                algorithm=config.auth.oidc_algorithm,
            )
        else:
            keystore = MemoryKeyStore(algorithm=config.auth.oidc_algorithm)

        # Create OIDC provider
        provider_config = OIDCProviderConfig(
            issuer=config.auth.oidc_issuer,
            audiences=config.auth.oidc_audiences,
            algorithm=config.auth.oidc_algorithm,
            token_ttl=config.auth.access_token_expires,
            refresh_ttl=config.auth.refresh_token_expires,
        )
        provider = OIDCProvider(config=provider_config, keystore=keystore)

        current_app.config["OIDC_PROVIDER"] = provider
        current_app.config["OIDC_KEYSTORE"] = keystore
        current_app.config["OIDC_PROVIDER_CONFIG"] = provider_config

    return (
        current_app.config["OIDC_PROVIDER"],
        current_app.config["OIDC_KEYSTORE"],
        current_app.config["OIDC_PROVIDER_CONFIG"],
    )


# ============================================
# Password utilities (bcrypt stays in app)
# ============================================


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


# ============================================
# Token creation via OIDCProvider
# ============================================


def create_token_set(user_id: int, role: str) -> TokenSet:
    """Create OIDC token set (access + refresh) using penguin-aaa provider."""
    provider, keystore, provider_config = _get_oidc_components()

    claims = Claims(
        sub=str(user_id),
        iss=provider_config.issuer,
        aud=provider_config.audiences,
        iat=datetime.utcnow(),
        exp=datetime.utcnow() + provider_config.token_ttl,
        scope=["openid", "profile"],
        roles=[role],
        tenant="default",
    )

    return provider.issue_token_set(claims)


def create_access_token(user_id: int, role: str, config=None) -> str:
    """Create JWT access token via OIDC provider.

    The config parameter is accepted for backward compatibility but ignored
    (configuration comes from the app's OIDC provider).
    """
    token_set = create_token_set(user_id, role)
    return token_set.access_token


def create_refresh_token(user_id: int, config, db) -> tuple[str, datetime]:
    """Create refresh token and store hash in database for revocation."""
    provider, keystore, provider_config = _get_oidc_components()

    # Create a token set — we use the refresh_token from it
    token_set = create_token_set(user_id, "refresh")
    refresh_token = token_set.refresh_token

    expires = datetime.utcnow() + provider_config.refresh_ttl

    # Store hash of token in database for revocation
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    db.refresh_tokens.insert(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires,
    )
    db.commit()

    return refresh_token, expires


# ============================================
# Auth decorators
# ============================================


def _validate_token(token: str) -> dict:
    """Validate a JWT token using the OIDC keystore.

    Returns the decoded payload dict.
    Raises ValueError or jwt exceptions on failure.
    """
    import jwt as pyjwt

    provider, keystore, provider_config = _get_oidc_components()

    # Get the public key from our keystore for verification
    signing_key, kid = keystore.get_signing_key()
    public_key = signing_key.public_key()

    payload = pyjwt.decode(
        token,
        public_key,
        algorithms=[provider_config.algorithm],
        audience=provider_config.audiences,
        issuer=provider_config.issuer,
    )

    return payload


def auth_required(f):
    """Decorator to require authentication via OIDC JWT."""

    @wraps(f)
    async def decorated(*args, **kwargs):
        import jwt as pyjwt

        config = current_app.config["MANAGER_CONFIG"]

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid authorization header"}), 401

        token = auth_header.split(" ")[1]

        try:
            payload = _validate_token(token)
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception:
            return jsonify({"error": "Token validation failed"}), 401

        # Extract user ID from claims
        user_id = int(payload["sub"])

        # Get user from database
        db = get_db(config.database.uri)
        user = db(db.users.id == user_id).select().first()

        if not user or not user.is_active:
            return jsonify({"error": "User not found or inactive"}), 401

        g.current_user = user.as_dict()
        g.current_user_id = user.id
        # Store roles from JWT claims for RBAC
        g.current_user_roles = payload.get("roles", [])

        return await f(*args, **kwargs)

    return decorated


def role_required(*roles):
    """Decorator to require specific roles.

    Checks both the database role and JWT claims roles.
    """

    def decorator(f):
        @wraps(f)
        async def decorated(*args, **kwargs):
            if not hasattr(g, "current_user"):
                return jsonify({"error": "Authentication required"}), 401

            user_role = g.current_user["role"]
            jwt_roles = getattr(g, "current_user_roles", [])

            # Allow if user's DB role or any JWT role matches
            if user_role not in roles and not any(r in roles for r in jwt_roles):
                return jsonify({"error": "Insufficient permissions"}), 403

            return await f(*args, **kwargs)

        return decorated

    return decorator


# ============================================
# Auth endpoints
# ============================================


@bp.route("/login", methods=["POST"])
async def login():
    """Login endpoint - returns OIDC access and refresh tokens."""
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

    # Verify password (bcrypt stays in app, not in penguin-aaa)
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

    # Generate OIDC tokens
    access_token = create_access_token(user.id, user.role)
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
    import jwt as pyjwt

    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        refresh_data = RefreshTokenRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    # Decode token using OIDC keystore
    try:
        payload = _validate_token(refresh_data.refresh_token)
    except pyjwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except pyjwt.InvalidTokenError:
        return jsonify({"error": "Invalid refresh token"}), 401

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

    # Generate new OIDC tokens
    access_token = create_access_token(user.id, user.role)
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


# ============================================
# OIDC Discovery Endpoints
# ============================================


@bp.route("/.well-known/openid-configuration", methods=["GET"])
async def oidc_discovery():
    """OIDC discovery document endpoint."""
    provider, _, _ = _get_oidc_components()
    return jsonify(provider.discovery_document()), 200


@bp.route("/jwks", methods=["GET"])
async def jwks():
    """JWKS endpoint for public key distribution."""
    provider, _, _ = _get_oidc_components()
    return jsonify(provider.jwks()), 200
