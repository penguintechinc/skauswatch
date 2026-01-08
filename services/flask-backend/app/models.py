"""PyDAL Database Models."""

from datetime import datetime
from typing import Optional

from flask import Flask, g
from pydal import DAL, Field
from pydal.validators import IS_EMAIL, IS_IN_SET, IS_NOT_EMPTY

from .config import Config

# Valid roles for the application
VALID_ROLES = ["admin", "maintainer", "viewer"]


def init_db(app: Flask) -> DAL:
    """Initialize database connection and define tables."""
    db_uri = Config.get_db_uri()

    db = DAL(
        db_uri,
        pool_size=Config.DB_POOL_SIZE,
        migrate=True,
        check_reserved=["all"],
        lazy_tables=False,
    )

    # Define users table
    db.define_table(
        "users",
        Field("email", "string", length=255, unique=True, requires=[
            IS_NOT_EMPTY(error_message="Email is required"),
            IS_EMAIL(error_message="Invalid email format"),
        ]),
        Field("password_hash", "string", length=255, requires=IS_NOT_EMPTY()),
        Field("full_name", "string", length=255),
        Field("role", "string", length=50, default="viewer", requires=IS_IN_SET(
            VALID_ROLES,
            error_message=f"Role must be one of: {', '.join(VALID_ROLES)}"
        )),
        Field("is_active", "boolean", default=True),
        Field("created_at", "datetime", default=datetime.utcnow),
        Field("updated_at", "datetime", default=datetime.utcnow, update=datetime.utcnow),
    )

    # Define refresh tokens table for token invalidation
    db.define_table(
        "refresh_tokens",
        Field("user_id", "reference users", requires=IS_NOT_EMPTY()),
        Field("token_hash", "string", length=255, unique=True),
        Field("expires_at", "datetime"),
        Field("revoked", "boolean", default=False),
        Field("created_at", "datetime", default=datetime.utcnow),
    )

    # Commit table definitions
    db.commit()

    # Store db instance in app
    app.config["db"] = db

    return db


def get_db() -> DAL:
    """Get database connection for current request context."""
    from flask import current_app

    if "db" not in g:
        g.db = current_app.config.get("db")
    return g.db


def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email address."""
    db = get_db()
    user = db(db.users.email == email).select().first()
    return user.as_dict() if user else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    """Get user by ID."""
    db = get_db()
    user = db(db.users.id == user_id).select().first()
    return user.as_dict() if user else None


def create_user(email: str, password_hash: str, full_name: str = "",
                role: str = "viewer") -> dict:
    """Create a new user."""
    db = get_db()
    user_id = db.users.insert(
        email=email,
        password_hash=password_hash,
        full_name=full_name,
        role=role,
        is_active=True,
    )
    db.commit()
    return get_user_by_id(user_id)


def update_user(user_id: int, **kwargs) -> Optional[dict]:
    """Update user by ID."""
    db = get_db()

    # Filter allowed fields
    allowed_fields = {"email", "password_hash", "full_name", "role", "is_active"}
    update_data = {k: v for k, v in kwargs.items() if k in allowed_fields}

    if not update_data:
        return get_user_by_id(user_id)

    db(db.users.id == user_id).update(**update_data)
    db.commit()
    return get_user_by_id(user_id)


def delete_user(user_id: int) -> bool:
    """Delete user by ID."""
    db = get_db()
    deleted = db(db.users.id == user_id).delete()
    db.commit()
    return deleted > 0


def list_users(page: int = 1, per_page: int = 20) -> tuple[list[dict], int]:
    """List users with pagination."""
    db = get_db()
    offset = (page - 1) * per_page

    users = db(db.users).select(
        orderby=db.users.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(db.users).count()

    return [u.as_dict() for u in users], total


def store_refresh_token(user_id: int, token_hash: str, expires_at: datetime) -> int:
    """Store a refresh token."""
    db = get_db()
    token_id = db.refresh_tokens.insert(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.commit()
    return token_id


def revoke_refresh_token(token_hash: str) -> bool:
    """Revoke a refresh token."""
    db = get_db()
    updated = db(db.refresh_tokens.token_hash == token_hash).update(revoked=True)
    db.commit()
    return updated > 0


def is_refresh_token_valid(token_hash: str) -> bool:
    """Check if refresh token is valid (not revoked and not expired)."""
    db = get_db()
    token = db(
        (db.refresh_tokens.token_hash == token_hash) &
        (db.refresh_tokens.revoked == False) &
        (db.refresh_tokens.expires_at > datetime.utcnow())
    ).select().first()
    return token is not None


def revoke_all_user_tokens(user_id: int) -> int:
    """Revoke all refresh tokens for a user."""
    db = get_db()
    updated = db(db.refresh_tokens.user_id == user_id).update(revoked=True)
    db.commit()
    return updated
