"""Shared test fixtures for checkpoint-core."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace
from typing import Any


class _Q(MagicMock):
    """MagicMock subclass that supports PyDAL-style query expressions.

    PyDAL tables use ``tbl.field > value`` to build query objects.
    Plain ``MagicMock`` returns ``NotImplemented`` from ``__gt__`` etc.,
    causing ``TypeError`` when Python falls through to the right-hand
    operand.  This subclass overrides those operators and also overrides
    ``_get_child_mock`` so that *all* attribute access returns ``_Q``
    instances, allowing arbitrarily deep query-expression chaining.

    IMPORTANT: ``MagicMock._mock_set_magics()`` runs during ``__init__``
    and installs per-instance-class magic method stubs that return
    ``NotImplemented`` for comparison operators.  These stubs are placed
    on the dynamic subclass that Python uses for dunder lookup (i.e. on
    ``type(self)``, not on ``_Q`` itself), so class-body definitions of
    ``__gt__`` etc. are silently overridden.  We therefore override
    ``_mock_set_magics`` to re-install the PyDAL-compatible operators on
    that dynamic class *after* the parent has run its setup.
    """

    def _mock_set_magics(self) -> None:  # type: ignore[override]
        super()._mock_set_magics()  # let MagicMock do its thing first
        klass = type(self)          # the per-instance dynamic class
        klass.__gt__ = lambda s, other: _Q()  # type: ignore[assignment]
        klass.__lt__ = lambda s, other: _Q()  # type: ignore[assignment]
        klass.__ge__ = lambda s, other: _Q()  # type: ignore[assignment]
        klass.__le__ = lambda s, other: _Q()  # type: ignore[assignment]
        klass.__and__ = lambda s, other: _Q()  # type: ignore[assignment]
        klass.__or__ = lambda s, other: _Q()  # type: ignore[assignment]
        klass.__iand__ = lambda s, other: s  # type: ignore[assignment]
        klass.__ior__ = lambda s, other: s  # type: ignore[assignment]
        klass.__invert__ = lambda s: _Q()  # type: ignore[assignment]

    def _get_child_mock(self, /, **kw: object) -> "_Q":  # type: ignore[override]
        return _Q(**kw)

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

# Required env vars for CheckpointConfig (no defaults in the model)
_REQUIRED_ENV = {
    "CHECKPOINT_DB_PASS": "testpassword",
    "CHECKPOINT_SIGNING_MEK": "A" * 43 + "=",  # 32-byte base64 placeholder (43 A's + padding = 32 bytes)
    "CHECKPOINT_ISSUER_URL": "https://checkpoint.test",
    "CHECKPOINT_SAML_ENTITY_ID": "https://checkpoint.test/saml",
}


@pytest.fixture
async def app():
    """Create test Quart app with mocked DB and infrastructure."""
    env_vars = {
        "CHECKPOINT_DB_PASS": "test",
        "CHECKPOINT_SIGNING_MEK": "A" * 43 + "=",
        "CHECKPOINT_ISSUER_URL": "https://checkpoint.test",
        "CHECKPOINT_SAML_ENTITY_ID": "https://checkpoint.test/saml",
        "CHECKPOINT_GRPC_PORT": "50051",
        "CHECKPOINT_LDAP_PORT": "389",
        "CHECKPOINT_CORE_GRPC_HOST": "localhost",
        "CHECKPOINT_CORE_GRPC_PORT": "50052",
        "CHECKPOINT_WATCHER_ENABLED": "false",
    }
    mock_db_instance = _Q()

    with (
        patch.dict(os.environ, env_vars),
        patch("main.init_checkpoint_tables", return_value=mock_db_instance),
        patch("main.CoreIdentityClient") as mock_core_cls,
        patch("main.UpstreamSyncLoop") as mock_sync_cls,
        patch("main.LDAPServer") as mock_ldap_cls,
        patch("main.start_grpc_server"),
    ):
        mock_core_cls.return_value = AsyncMock()
        mock_sync_cls.return_value.run_forever = AsyncMock()
        mock_ldap_cls.return_value.start = AsyncMock()

        from main import create_app

        application = create_app()
        async with application.test_app():
            yield application


@pytest.fixture
async def client(app):
    """Quart test client."""
    return app.test_client()


@pytest.fixture
def mock_config():
    """Mock CheckpointConfig."""
    cfg = MagicMock()
    cfg.issuer_url = "https://checkpoint.test"
    cfg.require_pkce = True
    cfg.code_ttl = 600
    cfg.token_ttl = 3600
    cfg.refresh_token_ttl = 86400
    return cfg


@pytest.fixture(autouse=True)
def required_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure required CheckpointConfig env vars are always present."""
    for key, value in _REQUIRED_ENV.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def rsa_key_pair() -> tuple[Any, Any]:
    """Generate a test RSA key pair for JWT/SAML signing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )
    return private_key, private_key.public_key()


@pytest.fixture
def mock_db() -> _Q:
    """Mock penguin-dal DB instance with PyDAL query-expression support.

    Returns a :class:`_Q` instance so that ``db.table.field > value``
    comparisons work without raising ``TypeError``.  All child mocks are
    also ``_Q`` instances (via ``_get_child_mock``), so the chaining is
    arbitrarily deep.

    Default query results:
    * ``db(q).count()``  → ``0``
    * ``db(q).select()`` → ``_Q()`` (iterable as empty; has ``.first()``)
    """
    db = _Q()
    db.return_value.count.return_value = 0
    db.commit = MagicMock()
    return db


@pytest.fixture
def mock_async_db() -> AsyncMock:
    """Mock async penguin-dal DB instance."""
    db = AsyncMock()
    db.checkpoint_oauth_clients = AsyncMock()
    db.checkpoint_tokens = AsyncMock()
    db.checkpoint_auth_codes = AsyncMock()
    db.checkpoint_signing_keys = AsyncMock()
    db.checkpoint_audit_log = AsyncMock()
    db.checkpoint_upstream_idps = AsyncMock()
    db.checkpoint_saml_providers = AsyncMock()
    db.checkpoint_scim_tokens = AsyncMock()
    db.commit = AsyncMock()
    return db


@pytest.fixture
def mock_core_client() -> AsyncMock:
    """Mock gRPC core client."""
    return AsyncMock()


@pytest.fixture
def user_record() -> SimpleNamespace:
    """Mock user record for SCIM tests."""
    return SimpleNamespace(
        uuid="user-123",
        username="jdoe",
        email="jdoe@example.com",
        display_name="John Doe",
        is_active=True,
        groups=["group-1", "group-2"],
        attributes={"department": "engineering", "location": "sf"},
    )


@pytest.fixture
def inactive_user_record() -> SimpleNamespace:
    """Mock inactive user record."""
    return SimpleNamespace(
        uuid="user-456",
        username="jsmith",
        email="jsmith@example.com",
        display_name="Jane Smith",
        is_active=False,
        groups=[],
        attributes={},
    )


@pytest.fixture
def group_record() -> SimpleNamespace:
    """Mock group record for SCIM tests."""
    return SimpleNamespace(
        uuid="group-789",
        name="Engineering Team",
    )


@pytest.fixture
def member_records() -> list[SimpleNamespace]:
    """Mock member records for group SCIM tests."""
    return [
        SimpleNamespace(
            uuid="user-001",
            username="alice",
            email="alice@example.com",
            display_name="Alice",
            is_active=True,
            groups=[],
            attributes={},
        ),
        SimpleNamespace(
            uuid="user-002",
            username="bob",
            email="bob@example.com",
            display_name="Bob Chen",
            is_active=True,
            groups=[],
            attributes={},
        ),
    ]
