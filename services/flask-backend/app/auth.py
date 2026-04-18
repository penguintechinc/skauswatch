"""Authentication Endpoints."""

import hashlib
from datetime import datetime

import bcrypt
import jwt
from flask import Blueprint, current_app, jsonify, request
from penguin_aaa.authn import Claims, OIDCProvider, OIDCProviderConfig
from penguin_aaa.crypto import MemoryKeyStore
from penguin_libs.validation import IsEmail, IsStrongPassword, chain

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


def _get_oidc_components():
    """Lazy-init OIDC provider and return (provider, keystore, provider_config)."""
    if "OIDC_PROVIDER" not in current_app.config:
        keystore = MemoryKeyStore(algorithm="RS256")
        provider_config = OIDCProviderConfig(
            issuer=current_app.config.get("OIDC_ISSUER", "https://skauswatch.local"),
            audiences=["skauswatch"],
            algorithm="RS256",
            token_ttl=current_app.config["JWT_ACCESS_TOKEN_EXPIRES"],
            refresh_ttl=current_app.config["JWT_REFRESH_TOKEN_EXPIRES"],
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


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_access_token(user_id: int, role: str) -> str:
    """Create JWT access token using OIDCProvider (RS256)."""
    provider, keystore, config = _get_oidc_components()
    claims = Claims(
        subject=str(user_id),
        extra={"role": role, "type": "access"},
    )
    token_set = provider.issue_token_set(claims)
    return token_set.access_token


def create_refresh_token(user_id: int) -> tuple[str, datetime]:
    """Create JWT refresh token (RS256) and store hash in database."""
    provider, keystore, config = _get_oidc_components()
    claims = Claims(
        subject=str(user_id),
        extra={"type": "refresh"},
    )
    token_set = provider.issue_token_set(claims)
    token = token_set.refresh_token

    # Store hash of token in database for revocation
    expires = datetime.utcnow() + current_app.config["JWT_REFRESH_TOKEN_EXPIRES"]
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

    return (
        jsonify(
            {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_type": "Bearer",
                "expires_in": int(
                    current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
                ),
                "user": {
                    "id": user["id"],
                    "email": user["email"],
                    "full_name": user.get("full_name", ""),
                    "role": user["role"],
                },
            }
        ),
        200,
    )


@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    """Refresh access token using refresh token."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    refresh_token = data.get("refresh_token", "")

    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400

    # Decode token using RS256 public key from OIDC keystore
    try:
        provider, keystore, config = _get_oidc_components()
        signing_key, _kid = keystore.get_signing_key()
        public_key = signing_key.public_key()
        payload = jwt.decode(
            refresh_token,
            public_key,
            algorithms=["RS256"],
            audience=["skauswatch"],
            issuer=config.issuer,
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

    return (
        jsonify(
            {
                "access_token": access_token,
                "refresh_token": new_refresh_token,
                "token_type": "Bearer",
                "expires_in": int(
                    current_app.config["JWT_ACCESS_TOKEN_EXPIRES"].total_seconds()
                ),
            }
        ),
        200,
    )


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

    return (
        jsonify(
            {
                "message": "Successfully logged out",
                "tokens_revoked": revoked_count,
            }
        ),
        200,
    )


@auth_bp.route("/me", methods=["GET"])
@auth_required
def get_me():
    """Get current user profile."""
    user = get_current_user()

    return (
        jsonify(
            {
                "id": user["id"],
                "email": user["email"],
                "full_name": user.get("full_name", ""),
                "role": user["role"],
                "is_active": user["is_active"],
                "created_at": (
                    user["created_at"].isoformat() if user.get("created_at") else None
                ),
            }
        ),
        200,
    )


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register new user (creates viewer role by default)."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    full_name = data.get("full_name", "").strip()

    # Validation — email
    if not email:
        return jsonify({"error": "Email is required"}), 400

    email_result = IsEmail()(email)
    if not email_result.is_valid:
        return jsonify({"error": email_result.error}), 400
    email = email_result.value  # use normalized value from validator

    # Validation — password strength (replaces simple length check)
    password_validator = chain(IsStrongPassword())
    password_result = password_validator(password)
    if not password_result.is_valid:
        return jsonify({"error": password_result.error}), 400

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

    return (
        jsonify(
            {
                "message": "Registration successful",
                "user": {
                    "id": user["id"],
                    "email": user["email"],
                    "full_name": user.get("full_name", ""),
                    "role": user["role"],
                },
            }
        ),
        201,
    )
