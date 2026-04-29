"""penguin-dal Database Models."""

from datetime import datetime, timezone
from typing import Optional

from penguin_dal.quart_ext import get_db as _get_dal_db
from sqlalchemy import true

# Valid roles for the application
VALID_ROLES = ["admin", "maintainer", "viewer"]


def get_db():
    """Get database connection for current request context."""
    return _get_dal_db()


def _all(table_proxy):
    """Helper to create a full-table query with no WHERE clause."""
    from penguin_dal.query import Query

    return Query(true(), table=table_proxy.table)


async def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email address."""
    db = get_db()
    rows = await db(db.users.email == email).select()
    row = rows.first()
    return row.as_dict() if row else None


async def get_user_by_id(user_id: int) -> Optional[dict]:
    """Get user by ID."""
    db = get_db()
    rows = await db(db.users.id == user_id).select()
    row = rows.first()
    return row.as_dict() if row else None


async def create_user(
    email: str, password_hash: str, full_name: str = "", role: str = "viewer"
) -> dict:
    """Create a new user."""
    db = get_db()
    now = datetime.now(timezone.utc)
    user_id = await db.users.async_insert(
        email=email,
        password_hash=password_hash,
        full_name=full_name,
        role=role,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    user = await get_user_by_id(user_id)
    return user


async def update_user(user_id: int, **kwargs) -> Optional[dict]:
    """Update user by ID."""
    db = get_db()

    # Filter allowed fields
    allowed_fields = {"email", "password_hash", "full_name", "role", "is_active"}
    update_data = {k: v for k, v in kwargs.items() if k in allowed_fields}

    if not update_data:
        return await get_user_by_id(user_id)

    update_data["updated_at"] = datetime.now(timezone.utc)
    await db(db.users.id == user_id).update(**update_data)
    return await get_user_by_id(user_id)


async def delete_user(user_id: int) -> bool:
    """Delete user by ID."""
    db = get_db()
    deleted = await db(db.users.id == user_id).delete()
    return deleted > 0


async def list_users(page: int = 1, per_page: int = 20) -> tuple[list[dict], int]:
    """List users with pagination."""
    db = get_db()
    offset = (page - 1) * per_page

    all_q = _all(db.users)
    rows = await db(all_q).select(
        orderby=db.users.created_at,
        limitby=(offset, per_page),
    )
    total = await db(all_q).count()

    return [r.as_dict() for r in rows], total
