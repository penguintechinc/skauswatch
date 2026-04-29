"""Pytest fixtures for flask-backend tests."""

import os
import tempfile

import pytest
import pytest_asyncio
from quart import Quart
from sqlalchemy import create_engine

from app import create_app
from app.auth import _build_claims, hash_password
from app.config import TestingConfig
from app.models import create_user
from app.schema import Base


def _make_test_config(db_path: str) -> type:
    """Build a per-test Config subclass pointing at a temp SQLite file."""

    class _TestConfig(TestingConfig):
        DB_NAME = db_path
        DB_POOL_SIZE = 1  # SQLite file-lock safety

    return _TestConfig


@pytest_asyncio.fixture
async def app():
    """
    Quart test app with a fresh SQLite file per test.

    Uses a temp file (not :memory:) so that the sync SQLAlchemy engine that
    creates the schema and the async penguin-dal engine both connect to the
    SAME database.  before_serving fires via app.test_app(), which initialises
    penguin-dal + OIDCProvider.
    """
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name

    try:
        # Create schema in the temp file BEFORE before_serving fires.
        sync_engine = create_engine(f"sqlite:///{db_path}")
        Base.metadata.create_all(sync_engine)
        sync_engine.dispose()

        test_config = _make_test_config(db_path)
        quart_app = create_app(test_config)

        async with quart_app.test_app():
            # before_serving has now fired: init_dal + OIDCProvider are ready.
            yield quart_app
    finally:
        os.unlink(db_path)


@pytest_asyncio.fixture
async def client(app: Quart):
    """Quart test client."""
    async with app.test_client() as test_client:
        yield test_client


# ── user data ────────────────────────────────────────────────────────────────


@pytest.fixture
def admin_user_data() -> dict:
    return {"email": "admin@test.com", "password": "AdminPass123!", "full_name": "Admin", "role": "admin"}


@pytest.fixture
def maintainer_user_data() -> dict:
    return {"email": "maintainer@test.com", "password": "MaintPass123!", "full_name": "Maintainer", "role": "maintainer"}


@pytest.fixture
def viewer_user_data() -> dict:
    return {"email": "viewer@test.com", "password": "ViewPass123!", "full_name": "Viewer", "role": "viewer"}


# ── users in DB ──────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def admin_user(app: Quart, admin_user_data: dict) -> dict:
    async with app.app_context():
        return await create_user(
            email=admin_user_data["email"],
            password_hash=hash_password(admin_user_data["password"]),
            full_name=admin_user_data["full_name"],
            role="admin",
        )


@pytest_asyncio.fixture
async def maintainer_user(app: Quart, maintainer_user_data: dict) -> dict:
    async with app.app_context():
        return await create_user(
            email=maintainer_user_data["email"],
            password_hash=hash_password(maintainer_user_data["password"]),
            full_name=maintainer_user_data["full_name"],
            role="maintainer",
        )


@pytest_asyncio.fixture
async def viewer_user(app: Quart, viewer_user_data: dict) -> dict:
    async with app.app_context():
        return await create_user(
            email=viewer_user_data["email"],
            password_hash=hash_password(viewer_user_data["password"]),
            full_name=viewer_user_data["full_name"],
            role="viewer",
        )


# ── tokens ───────────────────────────────────────────────────────────────────


async def _issue_token(app: Quart, user: dict) -> str:
    async with app.app_context():
        provider = app.extensions["oidc_provider"]
        return provider.issue_token_set(_build_claims(user)).access_token


@pytest_asyncio.fixture
async def admin_token(app: Quart, admin_user: dict) -> str:
    return await _issue_token(app, admin_user)


@pytest_asyncio.fixture
async def maintainer_token(app: Quart, maintainer_user: dict) -> str:
    return await _issue_token(app, maintainer_user)


@pytest_asyncio.fixture
async def viewer_token(app: Quart, viewer_user: dict) -> str:
    return await _issue_token(app, viewer_user)


# ── auth headers ─────────────────────────────────────────────────────────────


@pytest_asyncio.fixture
async def admin_headers(admin_token: str) -> dict:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest_asyncio.fixture
async def maintainer_headers(maintainer_token: str) -> dict:
    return {"Authorization": f"Bearer {maintainer_token}"}


@pytest_asyncio.fixture
async def viewer_headers(viewer_token: str) -> dict:
    return {"Authorization": f"Bearer {viewer_token}"}
