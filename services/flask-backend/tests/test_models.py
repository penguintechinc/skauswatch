"""Tests for penguin-dal database models."""

from typing import Any

import pytest
from quart import Quart

from app.models import (
    create_user,
    delete_user,
    get_user_by_email,
    get_user_by_id,
    list_users,
    update_user,
)


@pytest.mark.asyncio
async def test_get_user_by_email_returns_none_for_missing(app: Quart) -> None:
    """get_user_by_email returns None for missing email."""
    async with app.app_context():
        user = await get_user_by_email("nonexistent@example.com")
        assert user is None


@pytest.mark.asyncio
async def test_get_user_by_email_returns_user(app: Quart) -> None:
    """get_user_by_email returns user dict for existing email."""
    async with app.app_context():
        # Create user
        user = await create_user(
            email="test@example.com",
            password_hash="hash123",
            full_name="Test User",
            role="viewer",
        )

        # Fetch by email
        fetched = await get_user_by_email("test@example.com")
        assert fetched is not None
        assert fetched["email"] == "test@example.com"
        assert fetched["full_name"] == "Test User"
        assert fetched["role"] == "viewer"


@pytest.mark.asyncio
async def test_create_user_creates_and_returns_user(app: Quart) -> None:
    """create_user creates and returns user dict."""
    async with app.app_context():
        user = await create_user(
            email="newuser@example.com",
            password_hash="hash123",
            full_name="New User",
            role="maintainer",
        )

        assert user is not None
        assert user["email"] == "newuser@example.com"
        assert user["full_name"] == "New User"
        assert user["role"] == "maintainer"
        assert user["is_active"] is True
        assert "created_at" in user
        assert user["id"] is not None


@pytest.mark.asyncio
async def test_create_user_default_role_is_viewer(app: Quart) -> None:
    """create_user defaults to viewer role."""
    async with app.app_context():
        user = await create_user(
            email="defaultrole@example.com",
            password_hash="hash123",
            full_name="Default Role User",
        )

        assert user["role"] == "viewer"


@pytest.mark.asyncio
async def test_create_user_default_full_name_is_empty(app: Quart) -> None:
    """create_user defaults full_name to empty string."""
    async with app.app_context():
        user = await create_user(
            email="nofullname@example.com",
            password_hash="hash123",
        )

        assert user["full_name"] == ""


@pytest.mark.asyncio
async def test_get_user_by_id_returns_none_for_missing(app: Quart) -> None:
    """get_user_by_id returns None for missing id."""
    async with app.app_context():
        user = await get_user_by_id(99999)
        assert user is None


@pytest.mark.asyncio
async def test_get_user_by_id_returns_user(app: Quart) -> None:
    """get_user_by_id returns user dict for existing id."""
    async with app.app_context():
        # Create user
        created = await create_user(
            email="byid@example.com",
            password_hash="hash123",
            full_name="By ID User",
            role="admin",
        )

        # Fetch by id
        fetched = await get_user_by_id(created["id"])
        assert fetched is not None
        assert fetched["id"] == created["id"]
        assert fetched["email"] == "byid@example.com"
        assert fetched["role"] == "admin"


@pytest.mark.asyncio
async def test_update_user_updates_single_field(app: Quart) -> None:
    """update_user updates single field."""
    async with app.app_context():
        # Create user
        user = await create_user(
            email="update@example.com",
            password_hash="hash123",
            full_name="Original Name",
            role="viewer",
        )

        # Update full_name only
        updated = await update_user(user["id"], full_name="Updated Name")

        assert updated["full_name"] == "Updated Name"
        assert updated["email"] == "update@example.com"  # unchanged
        assert updated["role"] == "viewer"  # unchanged


@pytest.mark.asyncio
async def test_update_user_updates_multiple_fields(app: Quart) -> None:
    """update_user updates multiple fields."""
    async with app.app_context():
        # Create user
        user = await create_user(
            email="multi@example.com",
            password_hash="hash123",
            full_name="Original",
            role="viewer",
        )

        # Update multiple fields
        updated = await update_user(
            user["id"],
            full_name="Updated",
            role="maintainer",
            is_active=False,
        )

        assert updated["full_name"] == "Updated"
        assert updated["role"] == "maintainer"
        assert updated["is_active"] is False


@pytest.mark.asyncio
async def test_update_user_ignores_invalid_fields(app: Quart) -> None:
    """update_user ignores fields not in allowed list."""
    async with app.app_context():
        # Create user
        user = await create_user(
            email="invalid@example.com",
            password_hash="hash123",
            full_name="Original",
            role="viewer",
        )

        # Try to update invalid field
        updated = await update_user(
            user["id"],
            invalid_field="should-be-ignored",
            full_name="Updated",
        )

        assert updated["full_name"] == "Updated"
        assert not hasattr(updated, "invalid_field")


@pytest.mark.asyncio
async def test_update_user_no_changes_returns_user(app: Quart) -> None:
    """update_user with no changes returns user."""
    async with app.app_context():
        # Create user
        user = await create_user(
            email="nochange@example.com",
            password_hash="hash123",
            full_name="Original",
            role="viewer",
        )

        # Update with no valid fields
        updated = await update_user(user["id"])

        assert updated["id"] == user["id"]
        assert updated["full_name"] == "Original"


@pytest.mark.asyncio
async def test_delete_user_returns_true_on_success(app: Quart) -> None:
    """delete_user returns True on success."""
    async with app.app_context():
        # Create user
        user = await create_user(
            email="delete@example.com",
            password_hash="hash123",
            full_name="Delete Me",
            role="viewer",
        )

        # Delete
        result = await delete_user(user["id"])
        assert result is True

        # Verify deleted
        fetched = await get_user_by_id(user["id"])
        assert fetched is None


@pytest.mark.asyncio
async def test_delete_user_returns_false_for_nonexistent(app: Quart) -> None:
    """delete_user returns False for nonexistent user."""
    async with app.app_context():
        result = await delete_user(99999)
        assert result is False


@pytest.mark.asyncio
async def test_list_users_returns_paginated_results(app: Quart) -> None:
    """list_users returns paginated list of users."""
    async with app.app_context():
        # Create multiple users
        for i in range(5):
            await create_user(
                email=f"user{i}@example.com",
                password_hash="hash123",
                full_name=f"User {i}",
                role="viewer",
            )

        # Get first page
        users, total = await list_users(page=1, per_page=2)

        assert len(users) == 2
        assert total == 5
        assert users[0]["email"].startswith("user")


@pytest.mark.asyncio
async def test_list_users_pagination_offset_works(app: Quart) -> None:
    """list_users pagination offsets correctly."""
    async with app.app_context():
        # Create users
        for i in range(5):
            await create_user(
                email=f"page{i}@example.com",
                password_hash="hash123",
                full_name=f"Page {i}",
                role="viewer",
            )

        # Get second page
        page2_users, total = await list_users(page=2, per_page=2)

        assert len(page2_users) == 2
        assert total == 5


@pytest.mark.asyncio
async def test_list_users_default_pagination(app: Quart) -> None:
    """list_users uses default pagination (page=1, per_page=20)."""
    async with app.app_context():
        users, total = await list_users()

        assert isinstance(users, list)
        assert isinstance(total, int)


@pytest.mark.asyncio
async def test_list_users_returns_user_dicts(app: Quart) -> None:
    """list_users returns list of user dicts with all fields."""
    async with app.app_context():
        # Create user
        created = await create_user(
            email="dicttest@example.com",
            password_hash="hash123",
            full_name="Dict Test",
            role="admin",
        )

        users, total = await list_users(page=1, per_page=10)

        assert len(users) >= 1
        user = users[0]
        assert isinstance(user, dict)
        assert "id" in user
        assert "email" in user
        assert "password_hash" in user
        assert "full_name" in user
        assert "role" in user
        assert "is_active" in user


@pytest.mark.asyncio
async def test_list_users_empty_page_returns_empty_list(app: Quart) -> None:
    """list_users returns empty list for page beyond total."""
    async with app.app_context():
        users, total = await list_users(page=100, per_page=10)

        assert len(users) == 0
        assert total >= 0
