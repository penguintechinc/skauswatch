"""
Comprehensive pytest tests for checkpoint-core OAuth2 client management API.

Tests all CRUD endpoints, auth failures, input validation, secret hashing,
and 404 cases. Uses Quart test client with mocked database and JWT validation.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

import bcrypt
import pytest


@pytest.fixture
async def app():
    """Create test Quart app with mocked DB and infrastructure."""
    import os

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
    mock_db_instance = MagicMock()
    mock_db_instance.return_value.select.return_value = []

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
def mock_db() -> MagicMock:
    """Mock PyDAL DB instance."""
    db = MagicMock()
    db.checkpoint_oauth_clients = MagicMock()
    db.commit = MagicMock()
    return db


@pytest.fixture
def mock_config() -> MagicMock:
    """Mock CheckpointConfig."""
    cfg = MagicMock()
    cfg.issuer_url = "https://checkpoint.test"
    cfg.require_pkce = True
    return cfg


@pytest.fixture
def mock_audit() -> AsyncMock:
    """Mock AuditLogger."""
    return AsyncMock()


@pytest.fixture
def valid_token_claims() -> dict:
    """Valid JWT token claims for authorization."""
    return {
        "sub": "user-123",
        "scope": "checkpoint:clients:read checkpoint:clients:write checkpoint:admin",
        "iss": "https://checkpoint.test",
    }


@pytest.fixture
def read_only_token_claims() -> dict:
    """JWT token with read-only scope."""
    return {
        "sub": "user-456",
        "scope": "checkpoint:clients:read",
        "iss": "https://checkpoint.test",
    }


@pytest.fixture
def no_scope_token_claims() -> dict:
    """JWT token with no checkpoint scopes."""
    return {
        "sub": "user-789",
        "scope": "some:other:scope",
        "iss": "https://checkpoint.test",
    }


@pytest.fixture
def mock_client_row() -> SimpleNamespace:
    """Mock PyDAL client row from database."""
    return SimpleNamespace(
        id=1,
        client_id="cp_testclientid123456789",
        client_secret_hash=bcrypt.hashpw(
            b"test_secret_123", bcrypt.gensalt()
        ).decode(),
        name="Test OAuth Client",
        description="A test OAuth2 client",
        redirect_uris=json.dumps(["https://example.com/callback"]),
        allowed_scopes="openid profile email",
        grant_types=json.dumps(["authorization_code", "refresh_token"]),
        require_pkce=True,
        is_active=True,
        created_by_uuid="user-123",
        created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
    )


# ══════════════════════════════════════════════════════════════════════════════
# LIST CLIENTS TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestListClients:
    """Test GET /api/v1/clients endpoint."""

    @pytest.mark.asyncio
    async def test_list_clients_success(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims, mock_client_row
    ):
        """Successfully list clients with valid read scope."""
        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value = [mock_client_row]

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.get(
                "/api/v1/clients",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["client_id"] == "cp_testclientid123456789"
        assert data[0]["name"] == "Test OAuth Client"
        assert "client_secret_hash" not in data[0]  # Secret hash never returned

    @pytest.mark.asyncio
    async def test_list_clients_empty(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """List clients when database is empty."""
        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value = []

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.get(
                "/api/v1/clients",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert isinstance(data, list)
        assert len(data) == 0

    @pytest.mark.asyncio
    async def test_list_clients_missing_auth_header(
        self, client, app, mock_db, mock_config, mock_audit
    ):
        """401 when Authorization header is missing."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch("api.v1.clients.verify_token", return_value=None),
        ):
            response = await client.get("/api/v1/clients")

        assert response.status_code == 401
        data = await response.get_json()
        assert data.get("error") == "unauthorized"

    @pytest.mark.asyncio
    async def test_list_clients_invalid_token(
        self, client, app, mock_db, mock_config, mock_audit
    ):
        """401 when token verification fails."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch("api.v1.clients.verify_token", return_value=None),
        ):
            response = await client.get(
                "/api/v1/clients",
                headers={"Authorization": "Bearer invalid_token"},
            )

        assert response.status_code == 401
        data = await response.get_json()
        assert data.get("error") == "unauthorized"

    @pytest.mark.asyncio
    async def test_list_clients_insufficient_scope(
        self, client, app, mock_db, mock_config, mock_audit, no_scope_token_claims
    ):
        """403 when token lacks required scope."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=no_scope_token_claims,
            ),
        ):
            response = await client.get(
                "/api/v1/clients",
                headers={"Authorization": "Bearer token_without_scope"},
            )

        assert response.status_code == 403
        data = await response.get_json()
        assert data.get("error") == "insufficient_scope"


# ══════════════════════════════════════════════════════════════════════════════
# CREATE CLIENT TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestCreateClient:
    """Test POST /api/v1/clients endpoint."""

    @pytest.mark.asyncio
    async def test_create_client_success(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """Successfully create a new OAuth2 client."""
        mock_db.checkpoint_oauth_clients.insert.return_value = 42
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "New Client",
                    "description": "A new OAuth2 client",
                    "redirect_uris": ["https://example.com/callback"],
                    "allowed_scopes": "openid profile email",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "require_pkce": True,
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 201
        data = await response.get_json()
        assert data["id"] == 42
        assert data["name"] == "New Client"
        assert data["client_id"].startswith("cp_")
        assert "client_secret" in data
        # Verify secret is 40+ chars (url-safe base64)
        assert len(data["client_secret"]) >= 40
        assert data["is_active"] is True
        assert data["require_pkce"] is True

        # Verify DB insert was called with bcrypt-hashed secret
        mock_db.checkpoint_oauth_clients.insert.assert_called_once()
        call_kwargs = mock_db.checkpoint_oauth_clients.insert.call_args[1]
        assert "client_secret_hash" in call_kwargs
        # Verify hash is bcrypt (starts with $2b$)
        assert call_kwargs["client_secret_hash"].startswith("$2b$")

    @pytest.mark.asyncio
    async def test_create_client_defaults(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """Create client with defaults for optional fields."""
        mock_db.checkpoint_oauth_clients.insert.return_value = 99
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "Minimal Client",
                    "redirect_uris": ["https://example.com/cb"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 201
        data = await response.get_json()
        assert data["allowed_scopes"] == "openid profile email"
        assert data["grant_types"] == ["authorization_code"]
        assert data["require_pkce"] is True
        assert data["description"] == ""

    @pytest.mark.asyncio
    async def test_create_client_missing_name(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """400 when name is missing."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "redirect_uris": ["https://example.com/cb"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 400
        data = await response.get_json()
        assert "name is required" in data.get("error", "")

    @pytest.mark.asyncio
    async def test_create_client_empty_name(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """400 when name is empty string."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "   ",
                    "redirect_uris": ["https://example.com/cb"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 400
        data = await response.get_json()
        assert "name is required" in data.get("error", "")

    @pytest.mark.asyncio
    async def test_create_client_missing_redirect_uris(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """400 when redirect_uris is missing."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={"name": "Test Client"},
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 400
        data = await response.get_json()
        assert "redirect_uris is required" in data.get("error", "")

    @pytest.mark.asyncio
    async def test_create_client_empty_redirect_uris(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """400 when redirect_uris is empty list."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "Test Client",
                    "redirect_uris": [],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 400
        data = await response.get_json()
        assert "redirect_uris is required" in data.get("error", "")

    @pytest.mark.asyncio
    async def test_create_client_invalid_redirect_uri_scheme(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """400 when redirect_uri has invalid scheme."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "Test Client",
                    "redirect_uris": ["ftp://example.com/cb"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 400
        data = await response.get_json()
        assert "invalid redirect_uri" in data.get("error", "")

    @pytest.mark.asyncio
    async def test_create_client_invalid_redirect_uri_no_netloc(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """400 when redirect_uri has no netloc."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "Test Client",
                    "redirect_uris": ["https://"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 400
        data = await response.get_json()
        assert "invalid redirect_uri" in data.get("error", "")

    @pytest.mark.asyncio
    async def test_create_client_localhost_allowed(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """HTTP localhost URIs are allowed for development."""
        mock_db.checkpoint_oauth_clients.insert.return_value = 55
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "Dev Client",
                    "redirect_uris": ["http://localhost:3000/callback"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 201
        data = await response.get_json()
        assert data["redirect_uris"] == ["http://localhost:3000/callback"]

    @pytest.mark.asyncio
    async def test_create_client_missing_write_scope(
        self, client, app, mock_db, mock_config, mock_audit, read_only_token_claims
    ):
        """403 when token lacks write scope."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=read_only_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "Test Client",
                    "redirect_uris": ["https://example.com/cb"],
                },
                headers={"Authorization": "Bearer read_only_token"},
            )

        assert response.status_code == 403
        data = await response.get_json()
        assert data.get("error") == "insufficient_scope"

    @pytest.mark.asyncio
    async def test_create_client_audit_logged(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """Client creation is audit logged."""
        mock_db.checkpoint_oauth_clients.insert.return_value = 77
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "Audited Client",
                    "redirect_uris": ["https://example.com/cb"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 201
        # Verify audit.log was called
        mock_audit.log.assert_called_once()
        call_args = mock_audit.log.call_args
        assert call_args[0][0] == "oauth2.client_created"
        assert call_args[1]["actor_uuid"] == "user-123"


# ══════════════════════════════════════════════════════════════════════════════
# GET CLIENT TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestGetClient:
    """Test GET /api/v1/clients/{id} endpoint."""

    @pytest.mark.asyncio
    async def test_get_client_success(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims, mock_client_row
    ):
        """Successfully get a single client."""
        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.return_value = (
            mock_client_row
        )

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.get(
                "/api/v1/clients/1",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["id"] == 1
        assert data["client_id"] == "cp_testclientid123456789"
        assert data["name"] == "Test OAuth Client"
        assert "client_secret_hash" not in data

    @pytest.mark.asyncio
    async def test_get_client_not_found(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """404 when client does not exist."""
        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.return_value = None

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.get(
                "/api/v1/clients/999",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 404
        data = await response.get_json()
        assert data.get("error") == "not found"

    @pytest.mark.asyncio
    async def test_get_client_missing_auth(
        self, client, app, mock_db, mock_config, mock_audit
    ):
        """401 when missing authorization."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch("api.v1.clients.verify_token", return_value=None),
        ):
            response = await client.get("/api/v1/clients/1")

        assert response.status_code == 401
        data = await response.get_json()
        assert data.get("error") == "unauthorized"


# ══════════════════════════════════════════════════════════════════════════════
# UPDATE CLIENT TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestUpdateClient:
    """Test PUT /api/v1/clients/{id} endpoint."""

    @pytest.mark.asyncio
    async def test_update_client_name(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims, mock_client_row
    ):
        """Successfully update client name."""
        updated_row = SimpleNamespace(**vars(mock_client_row))
        updated_row.name = "Updated Client Name"

        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.side_effect = [
            mock_client_row,  # First call: check if exists
            updated_row,  # Second call: fetch updated row
        ]
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.put(
                "/api/v1/clients/1",
                json={"name": "Updated Client Name"},
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["name"] == "Updated Client Name"

    @pytest.mark.asyncio
    async def test_update_client_multiple_fields(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims, mock_client_row
    ):
        """Update multiple client fields at once."""
        updated_row = SimpleNamespace(**vars(mock_client_row))
        updated_row.name = "New Name"
        updated_row.description = "New description"
        updated_row.redirect_uris = json.dumps(["https://newexample.com/cb"])

        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.side_effect = [
            mock_client_row,
            updated_row,
        ]
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.put(
                "/api/v1/clients/1",
                json={
                    "name": "New Name",
                    "description": "New description",
                    "redirect_uris": ["https://newexample.com/cb"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["name"] == "New Name"
        assert data["description"] == "New description"
        assert data["redirect_uris"] == ["https://newexample.com/cb"]

    @pytest.mark.asyncio
    async def test_update_client_toggle_active(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims, mock_client_row
    ):
        """Toggle is_active flag."""
        updated_row = SimpleNamespace(**vars(mock_client_row))
        updated_row.is_active = False

        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.side_effect = [
            mock_client_row,
            updated_row,
        ]
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.put(
                "/api/v1/clients/1",
                json={"is_active": False},
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data["is_active"] is False

    @pytest.mark.asyncio
    async def test_update_client_not_found(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """404 when updating non-existent client."""
        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.return_value = None

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.put(
                "/api/v1/clients/999",
                json={"name": "New Name"},
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 404
        data = await response.get_json()
        assert data.get("error") == "not found"

    @pytest.mark.asyncio
    async def test_update_client_missing_write_scope(
        self, client, app, mock_db, mock_config, mock_audit, read_only_token_claims
    ):
        """403 when token lacks write scope."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=read_only_token_claims,
            ),
        ):
            response = await client.put(
                "/api/v1/clients/1",
                json={"name": "New Name"},
                headers={"Authorization": "Bearer read_only_token"},
            )

        assert response.status_code == 403
        data = await response.get_json()
        assert data.get("error") == "insufficient_scope"

    @pytest.mark.asyncio
    async def test_update_client_audit_logged(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims, mock_client_row
    ):
        """Client update is audit logged."""
        updated_row = SimpleNamespace(**vars(mock_client_row))
        updated_row.name = "Updated Name"

        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.side_effect = [
            mock_client_row,
            updated_row,
        ]
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.put(
                "/api/v1/clients/1",
                json={"name": "Updated Name"},
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        mock_audit.log.assert_called_once()
        call_args = mock_audit.log.call_args
        assert call_args[0][0] == "oauth2.client_updated"
        assert call_args[1]["actor_uuid"] == "user-123"


# ══════════════════════════════════════════════════════════════════════════════
# DELETE CLIENT TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestDeleteClient:
    """Test DELETE /api/v1/clients/{id} endpoint."""

    @pytest.mark.asyncio
    async def test_delete_client_success(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims, mock_client_row
    ):
        """Successfully delete (soft-delete) a client."""
        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.return_value = (
            mock_client_row
        )
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.delete(
                "/api/v1/clients/1",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        data = await response.get_json()
        assert data.get("status") == "deleted"

        # Verify soft-delete by checking is_active=False was set
        mock_db.return_value.update.assert_called_once()
        update_kwargs = mock_db.return_value.update.call_args[1]
        assert update_kwargs.get("is_active") is False

    @pytest.mark.asyncio
    async def test_delete_client_not_found(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """404 when deleting non-existent client."""
        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.return_value = None

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.delete(
                "/api/v1/clients/999",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 404
        data = await response.get_json()
        assert data.get("error") == "not found"

    @pytest.mark.asyncio
    async def test_delete_client_missing_write_scope(
        self, client, app, mock_db, mock_config, mock_audit, read_only_token_claims
    ):
        """403 when token lacks write scope."""
        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=read_only_token_claims,
            ),
        ):
            response = await client.delete(
                "/api/v1/clients/1",
                headers={"Authorization": "Bearer read_only_token"},
            )

        assert response.status_code == 403
        data = await response.get_json()
        assert data.get("error") == "insufficient_scope"

    @pytest.mark.asyncio
    async def test_delete_client_audit_logged(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims, mock_client_row
    ):
        """Client deletion is audit logged."""
        mock_db.checkpoint_oauth_clients.return_value = mock_db
        mock_db.return_value.select.return_value.first.return_value = (
            mock_client_row
        )
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.delete(
                "/api/v1/clients/1",
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 200
        mock_audit.log.assert_called_once()
        call_args = mock_audit.log.call_args
        assert call_args[0][0] == "oauth2.client_deleted"
        assert call_args[1]["target_type"] == "oauth_client"


# ══════════════════════════════════════════════════════════════════════════════
# SECRET HASHING TESTS
# ══════════════════════════════════════════════════════════════════════════════


class TestSecretHashing:
    """Test that client secrets are properly bcrypt-hashed."""

    @pytest.mark.asyncio
    async def test_secret_is_bcrypt_hashed_on_creation(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """Verify secret is bcrypt-hashed when creating a client."""
        captured_hash = None

        def capture_insert(*args, **kwargs):
            nonlocal captured_hash
            captured_hash = kwargs.get("client_secret_hash")
            return 88

        mock_db.checkpoint_oauth_clients.insert.side_effect = capture_insert
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "Hashing Test Client",
                    "redirect_uris": ["https://example.com/cb"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 201
        data = await response.get_json()
        raw_secret = data["client_secret"]

        # Verify hash is bcrypt format ($2b$)
        assert captured_hash is not None
        assert captured_hash.startswith("$2b$")

        # Verify raw secret can be verified against hash
        assert bcrypt.checkpw(raw_secret.encode(), captured_hash.encode())

    @pytest.mark.asyncio
    async def test_raw_secret_not_stored(
        self, client, app, mock_db, mock_config, mock_audit, valid_token_claims
    ):
        """Verify raw secret is not stored in database."""
        captured_kwargs = None

        def capture_insert(*args, **kwargs):
            nonlocal captured_kwargs
            captured_kwargs = kwargs
            return 99

        mock_db.checkpoint_oauth_clients.insert.side_effect = capture_insert
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch(
                "api.v1.clients.verify_token",
                return_value=valid_token_claims,
            ),
        ):
            response = await client.post(
                "/api/v1/clients",
                json={
                    "name": "Secret Storage Test",
                    "redirect_uris": ["https://example.com/cb"],
                },
                headers={"Authorization": "Bearer valid_token"},
            )

        assert response.status_code == 201
        data = await response.get_json()
        raw_secret = data["client_secret"]

        # Verify raw secret is NOT in the database kwargs
        assert raw_secret not in str(captured_kwargs)
        # Verify only hash is present
        assert "client_secret_hash" in captured_kwargs


# ══════════════════════════════════════════════════════════════════════════════
# MISSING LINE COVERAGE TESTS
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
class TestClientsCoverageMissing:
    """Test missing lines in api/v1/clients.py."""

    async def test_serialise_client_json_parsing(self, app, mock_db):
        """Test _serialise_client parses JSON fields correctly."""
        from api.v1.clients import _serialise_client

        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.client_id = "cp_test"
        mock_row.name = "Test"
        mock_row.description = "Desc"
        mock_row.redirect_uris = '["https://example.com/cb", "https://example.com/cb2"]'
        mock_row.allowed_scopes = "openid profile"
        mock_row.grant_types = '["authorization_code", "refresh_token"]'
        mock_row.require_pkce = False
        mock_row.is_active = True
        mock_row.created_by_uuid = "user-abc"
        mock_row.created_at = datetime(2025, 1, 22, 10, 0, 0, tzinfo=timezone.utc)
        mock_row.updated_at = datetime(2025, 1, 22, 11, 0, 0, tzinfo=timezone.utc)

        result = _serialise_client(mock_row)
        # Verify JSON was parsed
        assert isinstance(result["redirect_uris"], list)
        assert len(result["redirect_uris"]) == 2
        assert isinstance(result["grant_types"], list)
        assert len(result["grant_types"]) == 2

    async def test_serialise_client_includes_all_fields(self, app, mock_db):
        """Test _serialise_client includes all expected fields."""
        from api.v1.clients import _serialise_client

        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.client_id = "cp_test"
        mock_row.name = "Test Client"
        mock_row.description = "Test description"
        mock_row.redirect_uris = '["https://example.com/cb"]'
        mock_row.allowed_scopes = "openid profile email"
        mock_row.grant_types = '["authorization_code"]'
        mock_row.require_pkce = True
        mock_row.is_active = True
        mock_row.created_by_uuid = "user-123"
        mock_row.created_at = datetime(2025, 1, 22, 10, 0, 0, tzinfo=timezone.utc)
        mock_row.updated_at = datetime(2025, 1, 22, 11, 0, 0, tzinfo=timezone.utc)

        result = _serialise_client(mock_row)
        assert result["id"] == 1
        assert result["client_id"] == "cp_test"
        assert result["name"] == "Test Client"
        assert isinstance(result["redirect_uris"], list)

    async def test_update_client_updates_allowed_scopes(self, client, mock_db, mock_config, mock_audit, valid_token_claims):
        """Test PUT /api/v1/clients/<id> updates allowed_scopes."""
        row = MagicMock()
        row.id = 1
        row.client_id = "cp_test"
        row.name = "Test"
        row.description = ""
        row.redirect_uris = '["https://example.com/cb"]'
        row.allowed_scopes = "openid"
        row.grant_types = '["authorization_code"]'
        row.require_pkce = True
        row.is_active = True
        row.created_by_uuid = "user-1"
        row.created_at = None
        row.updated_at = None

        mock_db.return_value.select.return_value.first.return_value = row
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch("api.v1.clients.verify_token", return_value=valid_token_claims),
        ):
            response = await client.put(
                "/api/v1/clients/1",
                json={"allowed_scopes": "openid profile email"},
                headers={"Authorization": "Bearer valid_token"},
            )
        assert response.status_code == 200

    async def test_update_client_updates_grant_types(self, client, mock_db, mock_config, mock_audit, valid_token_claims):
        """Test PUT /api/v1/clients/<id> updates grant_types."""
        row = MagicMock()
        row.id = 1
        row.client_id = "cp_test"
        row.name = "Test"
        row.description = ""
        row.redirect_uris = '["https://example.com/cb"]'
        row.allowed_scopes = "openid"
        row.grant_types = '["authorization_code"]'
        row.require_pkce = True
        row.is_active = True
        row.created_by_uuid = "user-1"
        row.created_at = None
        row.updated_at = None

        mock_db.return_value.select.return_value.first.return_value = row
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch("api.v1.clients.verify_token", return_value=valid_token_claims),
        ):
            response = await client.put(
                "/api/v1/clients/1",
                json={"grant_types": ["authorization_code", "refresh_token"]},
                headers={"Authorization": "Bearer valid_token"},
            )
        assert response.status_code == 200

    async def test_update_client_updates_require_pkce(self, client, mock_db, mock_config, mock_audit, valid_token_claims):
        """Test PUT /api/v1/clients/<id> updates require_pkce."""
        row = MagicMock()
        row.id = 1
        row.client_id = "cp_test"
        row.name = "Test"
        row.description = ""
        row.redirect_uris = '["https://example.com/cb"]'
        row.allowed_scopes = "openid"
        row.grant_types = '["authorization_code"]'
        row.require_pkce = True
        row.is_active = True
        row.created_by_uuid = "user-1"
        row.created_at = None
        row.updated_at = None

        mock_db.return_value.select.return_value.first.return_value = row
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch("api.v1.clients.verify_token", return_value=valid_token_claims),
        ):
            response = await client.put(
                "/api/v1/clients/1",
                json={"require_pkce": False},
                headers={"Authorization": "Bearer valid_token"},
            )
        assert response.status_code == 200

    async def test_update_client_updates_is_active(self, client, mock_db, mock_config, mock_audit, valid_token_claims):
        """Test PUT /api/v1/clients/<id> updates is_active."""
        row = MagicMock()
        row.id = 1
        row.client_id = "cp_test"
        row.name = "Test"
        row.description = ""
        row.redirect_uris = '["https://example.com/cb"]'
        row.allowed_scopes = "openid"
        row.grant_types = '["authorization_code"]'
        row.require_pkce = True
        row.is_active = True
        row.created_by_uuid = "user-1"
        row.created_at = None
        row.updated_at = None

        mock_db.return_value.select.return_value.first.return_value = row
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch("api.v1.clients.verify_token", return_value=valid_token_claims),
        ):
            response = await client.put(
                "/api/v1/clients/1",
                json={"is_active": False},
                headers={"Authorization": "Bearer valid_token"},
            )
        assert response.status_code == 200

    async def test_delete_client_audits_deletion(self, client, mock_db, mock_config, mock_audit, valid_token_claims):
        """Test DELETE /api/v1/clients/<id> audits the deletion."""
        row = MagicMock()
        row.id = 1
        row.client_id = "cp_test"

        mock_db.return_value.select.return_value.first.return_value = row
        mock_db.commit = MagicMock()

        with (
            patch("api.v1.clients._get_db", return_value=mock_db),
            patch("api.v1.clients._get_config", return_value=mock_config),
            patch("api.v1.clients._get_audit", return_value=mock_audit),
            patch("api.v1.clients.verify_token", return_value=valid_token_claims),
        ):
            response = await client.delete(
                "/api/v1/clients/1",
                headers={"Authorization": "Bearer valid_token"},
            )
        assert response.status_code == 200
        # Verify audit was called with client_id in details
        mock_audit.log.assert_called_once()
        call_kwargs = mock_audit.log.call_args[1]
        assert call_kwargs["details"]["client_id"] == "cp_test"
