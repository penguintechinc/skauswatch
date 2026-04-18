"""
Authentication API endpoints.

Provides:
- Login/Logout
- Token refresh
- User registration
- Current user profile
- Identity provider endpoints (Checkpoint sub-module)
"""

import hashlib
import os
from datetime import datetime, timedelta
from functools import wraps
from typing import Optional
from uuid import uuid4

import bcrypt
import jwt
from models.db import get_db
from models.identity import init_identity_tables
from penguin_licensing import get_license_client
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


def _require_sso_license(request_host: str = "") -> tuple[dict, int] | None:
    """Check SSO license. Returns error response tuple if not licensed, None if allowed.

    Call at the start of SSO/OIDC route handlers:
        err = _require_sso_license(request.headers.get("Host", ""))
        if err:
            return err
    """
    config = current_app.config["MANAGER_CONFIG"]
    exempt_domains = config.siem.exempt_domains
    is_exempt = any(
        request_host == d or request_host.endswith(f".{d}") for d in exempt_domains
    )
    if is_exempt:
        return None

    try:
        lc = get_license_client()
        if lc.has_feature("sso"):
            return None
    except Exception:
        pass

    return jsonify({"error": "SSO requires a premium license"}), 402


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


# ============================================================
# Checkpoint Identity Provider endpoints
# ============================================================


def _checkpoint_enabled() -> bool:
    """Return True when the Checkpoint sub-module is enabled."""
    return os.getenv("CHECKPOINT_ENABLED", "false").strip().lower() == "true"


def _get_identity_db(database_uri: str):
    """
    Get a DB instance with identity tables defined.

    Returns a penguin-dal DB instance with identity tables auto-reflected
    from the database schema (defined in Alembic migration).
    """
    return init_identity_tables(database_uri)


def _build_identity_scopes(db, user_uuid: str) -> list[str]:
    """
    Derive OIDC scopes from the user's group memberships.

    Scope convention:
      - Every group whose name starts with "scope:" contributes the rest as a scope
      - The "admin" group grants the "admin" bundle scope
      - The "maintainer" group grants the "maintainer" bundle scope
      - All authenticated users get "identity:read"

    Args:
        db: DAL instance with identity tables defined.
        user_uuid: UUID of the authenticated identity user.

    Returns:
        Sorted, deduplicated list of scope strings.
    """
    scopes: set[str] = {"identity:read"}

    memberships = (
        db(db.identity_memberships.user_uuid == user_uuid)
        .select(db.identity_memberships.group_uuid)
        .as_list()
    )
    group_uuids = [m["group_uuid"] for m in memberships]

    if not group_uuids:
        return sorted(scopes)

    groups = db(db.identity_groups.uuid.belongs(group_uuids)).select(
        db.identity_groups.name
    )

    for group in groups:
        name: str = group.name or ""
        if name == "admin":
            scopes.update(
                [
                    "users:read",
                    "users:write",
                    "users:admin",
                    "users:delete",
                    "settings:write",
                    "identity:admin",
                ]
            )
        elif name == "maintainer":
            scopes.update(["users:read", "users:write", "identity:write"])
        elif name.startswith("scope:"):
            # e.g. group "scope:reports:read" → scope "reports:read"
            scopes.add(name[len("scope:"):])

    return sorted(scopes)


def _create_identity_access_token(
    user_uuid: str,
    scopes: list[str],
    groups: list[str],
    config,
) -> tuple[str, str, datetime]:
    """
    Create a JWT access token for an identity user.

    Args:
        user_uuid: UUID of the identity user (sub claim).
        scopes: List of OIDC scopes.
        groups: List of group names for informational roles claim.
        config: ManagerConfig instance.

    Returns:
        Tuple of (token, jti, expires_at).
    """
    jti: str = str(uuid4())
    expires: datetime = datetime.utcnow() + config.auth.access_token_expires
    payload: dict = {
        "sub": user_uuid,
        "jti": jti,
        "type": "identity_access",
        "scope": " ".join(scopes),
        "roles": groups,
        "iss": "checkpoint",
        "exp": expires,
        "iat": datetime.utcnow(),
    }
    token: str = jwt.encode(
        payload, config.auth.jwt_secret, algorithm=config.auth.jwt_algorithm
    )
    return token, jti, expires


@bp.route("/identity/login", methods=["POST"])
async def identity_login() -> tuple:
    """
    Login via Checkpoint identity provider.

    Authenticates against identity_users (not the legacy users table).
    Returns a JWT whose scope claim is derived from group memberships.

    Request body:
        email    (str, required) — identity user email
        password (str, required) — plain-text password

    Returns:
        200 with access_token, token_type, expires_in, scopes, user
        401 on bad credentials or inactive/suspended account
        503 when Checkpoint sub-module is disabled
    """
    if not _checkpoint_enabled():
        return (
            jsonify(
                {
                    "error": "Checkpoint identity module is not enabled on this instance"
                }
            ),
            503,
        )

    config = current_app.config["MANAGER_CONFIG"]

    data = await request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    email: str = (data.get("email") or "").strip().lower()
    password: str = data.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email and password are required"}), 400

    db = _get_identity_db(config.database.uri)

    # Fetch user — PII lookup is only in identity_users
    user = (
        db(db.identity_users.email == email)
        .select(
            db.identity_users.uuid,
            db.identity_users.password_hash,
            db.identity_users.status,
            db.identity_users.mfa_enabled,
            db.identity_users.display_name,
            db.identity_users.given_name,
            db.identity_users.family_name,
            db.identity_users.locale,
            db.identity_users.timezone,
        )
        .first()
    )

    if not user:
        # Constant-time response to prevent user enumeration
        bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
        return jsonify({"error": "Invalid email or password"}), 401

    # Verify account status
    if user.status != "active":
        return (
            jsonify(
                {
                    "error": (
                        "Account is suspended"
                        if user.status == "suspended"
                        else "Account is pending activation"
                    )
                }
            ),
            401,
        )

    # Verify password
    if not user.password_hash or not verify_password(password, user.password_hash):
        return jsonify({"error": "Invalid email or password"}), 401

    # Derive scopes from group memberships
    scopes: list[str] = _build_identity_scopes(db, user.uuid)

    # Collect group names for informational roles claim
    memberships = (
        db(db.identity_memberships.user_uuid == user.uuid)
        .select(db.identity_memberships.group_uuid)
        .as_list()
    )
    group_uuids = [m["group_uuid"] for m in memberships]
    group_names: list[str] = []
    if group_uuids:
        groups_rows = db(db.identity_groups.uuid.belongs(group_uuids)).select(
            db.identity_groups.name
        )
        group_names = [g.name for g in groups_rows if g.name]

    # Create access token
    token, jti, expires = _create_identity_access_token(
        user.uuid, scopes, group_names, config
    )

    # Store session record — token_hash = SHA-256(jti) for revocation
    token_hash: str = hashlib.sha256(jti.encode()).hexdigest()
    ip_address: str = (
        request.headers.get("X-Forwarded-For", request.remote_addr or "") or ""
    )
    # Truncate to 45 chars for IPv6 safety
    ip_address = ip_address.split(",")[0].strip()[:45]
    user_agent: str = (request.headers.get("User-Agent") or "")[:512]

    db.identity_sessions.insert(
        uuid=str(uuid4()),
        user_uuid=user.uuid,
        token_hash=token_hash,
        scopes=" ".join(scopes),
        expires_at=expires,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Update last_login_at
    db(db.identity_users.uuid == user.uuid).update(
        last_login_at=datetime.utcnow()
    )
    db.commit()

    return (
        jsonify(
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": int(config.auth.access_token_expires.total_seconds()),
                "scopes": scopes,
                "user": {
                    "uuid": user.uuid,
                    "display_name": user.display_name or "",
                    "given_name": user.given_name or "",
                    "family_name": user.family_name or "",
                    "locale": user.locale or "en",
                    "timezone": user.timezone or "UTC",
                    "mfa_enabled": bool(user.mfa_enabled),
                    "groups": group_names,
                },
            }
        ),
        200,
    )


@bp.route("/identity/me", methods=["GET"])
async def identity_me() -> tuple:
    """
    Return the current identity user's profile.

    Requires a valid Checkpoint identity JWT (type=identity_access) in the
    Authorization: Bearer header.

    Returns:
        200 with user profile and scopes
        401 on missing/invalid/expired token or revoked session
        503 when Checkpoint sub-module is disabled
    """
    if not _checkpoint_enabled():
        return (
            jsonify(
                {
                    "error": "Checkpoint identity module is not enabled on this instance"
                }
            ),
            503,
        )

    config = current_app.config["MANAGER_CONFIG"]

    auth_header: str = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    raw_token: str = auth_header.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            raw_token,
            config.auth.jwt_secret,
            algorithms=[config.auth.jwt_algorithm],
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    if payload.get("type") != "identity_access":
        return jsonify({"error": "Invalid token type"}), 401

    jti: str = payload.get("jti", "")
    if not jti:
        return jsonify({"error": "Token missing jti claim"}), 401

    user_uuid: str = payload.get("sub", "")
    if not user_uuid:
        return jsonify({"error": "Token missing sub claim"}), 401

    db = _get_identity_db(config.database.uri)

    # Check session is active (not revoked)
    token_hash: str = hashlib.sha256(jti.encode()).hexdigest()
    session = (
        db(
            (db.identity_sessions.token_hash == token_hash)
            & (db.identity_sessions.revoked_at == None)  # noqa: E711
            & (db.identity_sessions.expires_at > datetime.utcnow())
        )
        .select()
        .first()
    )
    if not session:
        return jsonify({"error": "Session not found or has been revoked"}), 401

    # Fetch user profile (PII from identity_users)
    user = (
        db(db.identity_users.uuid == user_uuid)
        .select(
            db.identity_users.uuid,
            db.identity_users.email,
            db.identity_users.display_name,
            db.identity_users.given_name,
            db.identity_users.family_name,
            db.identity_users.phone,
            db.identity_users.status,
            db.identity_users.mfa_enabled,
            db.identity_users.locale,
            db.identity_users.timezone,
            db.identity_users.avatar_url,
            db.identity_users.created_at,
            db.identity_users.last_login_at,
        )
        .first()
    )
    if not user:
        return jsonify({"error": "User not found"}), 401

    scopes: list[str] = _build_identity_scopes(db, user_uuid)

    return (
        jsonify(
            {
                "uuid": user.uuid,
                "email": user.email,
                "display_name": user.display_name or "",
                "given_name": user.given_name or "",
                "family_name": user.family_name or "",
                "phone": user.phone or "",
                "status": user.status,
                "mfa_enabled": bool(user.mfa_enabled),
                "locale": user.locale or "en",
                "timezone": user.timezone or "UTC",
                "avatar_url": user.avatar_url or "",
                "created_at": (
                    user.created_at.isoformat() if user.created_at else None
                ),
                "last_login_at": (
                    user.last_login_at.isoformat() if user.last_login_at else None
                ),
                "scopes": scopes,
            }
        ),
        200,
    )


@bp.route("/identity/logout", methods=["POST"])
async def identity_logout() -> tuple:
    """
    Revoke the current Checkpoint identity session.

    Sets revoked_at on the matching identity_sessions record so subsequent
    calls to /identity/me return 401.

    Requires a valid Checkpoint identity JWT (type=identity_access).

    Returns:
        200 on successful revocation
        401 on missing/invalid token
        503 when Checkpoint sub-module is disabled
    """
    if not _checkpoint_enabled():
        return (
            jsonify(
                {
                    "error": "Checkpoint identity module is not enabled on this instance"
                }
            ),
            503,
        )

    config = current_app.config["MANAGER_CONFIG"]

    auth_header: str = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    raw_token: str = auth_header.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            raw_token,
            config.auth.jwt_secret,
            algorithms=[config.auth.jwt_algorithm],
        )
    except jwt.ExpiredSignatureError:
        # Allow logout of already-expired tokens — still revoke the session
        payload = jwt.decode(
            raw_token,
            config.auth.jwt_secret,
            algorithms=[config.auth.jwt_algorithm],
            options={"verify_exp": False},
        )
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    if payload.get("type") != "identity_access":
        return jsonify({"error": "Invalid token type"}), 401

    jti: str = payload.get("jti", "")
    if not jti:
        return jsonify({"error": "Token missing jti claim"}), 401

    db = _get_identity_db(config.database.uri)

    token_hash: str = hashlib.sha256(jti.encode()).hexdigest()
    revoked_count: int = db(
        (db.identity_sessions.token_hash == token_hash)
        & (db.identity_sessions.revoked_at == None)  # noqa: E711
    ).update(revoked_at=datetime.utcnow())
    db.commit()

    return (
        jsonify(
            {
                "message": "Successfully logged out",
                "sessions_revoked": revoked_count,
            }
        ),
        200,
    )
