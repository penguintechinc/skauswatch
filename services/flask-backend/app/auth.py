"""Authentication Endpoints."""

from datetime import datetime, timedelta, timezone

import bcrypt
from penguin_aaa import Claims
from quart import Blueprint, current_app, jsonify, request

from .middleware import auth_required, get_current_user
from .models import create_user, get_user_by_email, get_user_by_id

auth_bp = Blueprint("auth", __name__)

# Scope mapping for roles
ROLE_SCOPES: dict[str, list[str]] = {
    "admin": ["*:read", "*:write", "*:admin", "*:delete", "settings:write", "users:admin"],
    "maintainer": ["*:read", "*:write", "teams:read", "reports:read", "analytics:read"],
    "viewer": ["*:read"],
}

DEFAULT_TENANT = "default"


def hash_password(password: str) -> str:
    """Hash password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify password against hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def _build_claims(user: dict) -> Claims:
    """Build OIDC Claims from user data."""
    role = user.get("role", "viewer")
    return Claims(
        sub=str(user["id"]),
        iss=current_app.config["ISSUER_URL"],
        aud=[current_app.config["JWT_AUDIENCE"]],
        iat=datetime.now(timezone.utc),
        exp=datetime.now(timezone.utc) + timedelta(minutes=30),  # OIDCProvider sets real exp
        scope=ROLE_SCOPES.get(role, ["*:read"]),
        roles=[role],
        tenant=DEFAULT_TENANT,
        teams=[],
        ext={},
    )


@auth_bp.route("/login", methods=["POST"])
async def login():
    """Login endpoint - returns access and refresh tokens."""
    data = await request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    # Find user
    user = await get_user_by_email(email)
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    # Verify password
    if not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid email or password"}), 401

    # Check if user is active
    if not user.get("is_active"):
        return jsonify({"error": "Account is deactivated"}), 401

    # Generate tokens via OIDCProvider
    provider = current_app.extensions["oidc_provider"]
    claims = _build_claims(user)
    token_set = provider.issue_token_set(claims)

    return (
        jsonify(
            {
                "access_token": token_set.access_token,
                "refresh_token": token_set.refresh_token,
                "token_type": "Bearer",
                "expires_in": token_set.expires_in,
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
async def refresh():
    """Refresh access token using refresh token."""
    data = await request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    refresh_token = data.get("refresh_token", "")

    if not refresh_token:
        return jsonify({"error": "Refresh token required"}), 400

    # Use OIDCProvider to refresh token
    try:
        provider = current_app.extensions["oidc_provider"]
        token_set = provider.refresh(refresh_token)
        return (
            jsonify(
                {
                    "access_token": token_set.access_token,
                    "refresh_token": token_set.refresh_token,
                    "token_type": "Bearer",
                    "expires_in": token_set.expires_in,
                }
            ),
            200,
        )
    except ValueError as e:
        return jsonify({"error": str(e)}), 401


@auth_bp.route("/logout", methods=["POST"])
@auth_required
async def logout():
    """Logout endpoint - revokes token."""
    # Get the token from Authorization header and revoke it
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:] if auth_header.startswith("Bearer ") else ""
    if token:
        provider = current_app.extensions["oidc_provider"]
        provider.revoke(token)
    return (
        jsonify({"message": "Successfully logged out"}),
        200,
    )


@auth_bp.route("/me", methods=["GET"])
@auth_required
async def get_me():
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
async def register():
    """Register new user (creates viewer role by default)."""
    data = await request.get_json()

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
    existing = await get_user_by_email(email)
    if existing:
        return jsonify({"error": "Email already registered"}), 409

    # Create user
    password_hash = hash_password(password)
    user = await create_user(
        email=email,
        password_hash=password_hash,
        full_name=full_name,
        role="viewer",  # Default role for self-registration
    )

    # Generate tokens via OIDCProvider
    provider = current_app.extensions["oidc_provider"]
    claims = _build_claims(user)
    token_set = provider.issue_token_set(claims)

    return (
        jsonify(
            {
                "message": "Registration successful",
                "access_token": token_set.access_token,
                "refresh_token": token_set.refresh_token,
                "token_type": "Bearer",
                "expires_in": token_set.expires_in,
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
