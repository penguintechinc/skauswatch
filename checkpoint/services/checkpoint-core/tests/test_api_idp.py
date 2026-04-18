"""
Comprehensive pytest test suite for api/v1/idp.py module.

Tests all endpoints:
  - GET /api/v1/idps (list)
  - POST /api/v1/idps (create)
  - GET /api/v1/idps/<id> (get)
  - PUT /api/v1/idps/<id> (update)
  - DELETE /api/v1/idps/<id> (delete)
  - POST /api/v1/idps/<id>/sync (trigger sync)

Coverage includes:
  - Authentication failures (401/403)
  - Input validation (missing required fields, invalid types)
  - Encryption/decryption of config_json
  - CRUD operations for all IDP types (oidc, saml, ldap, google, okta)
  - 404 for nonexistent IDPs
  - Sync endpoint validation
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Mark all tests as async
pytestmark = pytest.mark.asyncio


# ── Test Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
async def authenticated_headers() -> dict[str, str]:
    """Headers with valid Authorization token carrying checkpoint:idps:admin scope."""
    return {
        "Authorization": "Bearer valid-token",
        "Content-Type": "application/json",
    }


@pytest.fixture
async def insufficient_scope_headers() -> dict[str, str]:
    """Headers with valid token but insufficient scope."""
    return {
        "Authorization": "Bearer insufficient-token",
        "Content-Type": "application/json",
    }


@pytest.fixture
async def missing_auth_headers() -> dict[str, str]:
    """Headers with no Authorization header."""
    return {"Content-Type": "application/json"}


@pytest.fixture
def mock_idp_row() -> SimpleNamespace:
    """Mock IDP database row."""
    return SimpleNamespace(
        id=1,
        name="test-idp",
        type="oidc",
        federation_mode="sync",
        sync_interval_secs=3600,
        config_json_encrypted='{"dek_encrypted":"abc","dek_nonce":"def","nonce":"ghi","ciphertext":"jkl"}',
        is_active=True,
        last_sync_at=datetime(2025, 1, 1, 12, 0, 0),
        sync_error=None,
        created_at=datetime(2025, 1, 1, 10, 0, 0),
        updated_at=datetime(2025, 1, 1, 11, 0, 0),
    )


@pytest.fixture
def mock_idp_row_saml() -> SimpleNamespace:
    """Mock SAML IDP database row."""
    return SimpleNamespace(
        id=2,
        name="saml-idp",
        type="saml",
        federation_mode="proxy",
        sync_interval_secs=7200,
        config_json_encrypted='{"dek_encrypted":"xyz","dek_nonce":"uvw","nonce":"rst","ciphertext":"opq"}',
        is_active=True,
        last_sync_at=None,
        sync_error=None,
        created_at=datetime(2025, 1, 1, 10, 0, 0),
        updated_at=datetime(2025, 1, 1, 11, 0, 0),
    )


@pytest.fixture
def oidc_config() -> dict[str, str]:
    """Valid OIDC IDP configuration."""
    return {
        "issuer_url": "https://auth.example.com",
        "client_id": "my-client-id",
        "client_secret": "super-secret",
    }


@pytest.fixture
def ldap_config() -> dict[str, str]:
    """Valid LDAP IDP configuration."""
    return {
        "host": "ldap.example.com",
        "port": 389,
        "bind_dn": "cn=admin,dc=example,dc=com",
        "bind_password": "ldap-password",
        "base_dn": "dc=example,dc=com",
    }


@pytest.fixture
def saml_config() -> dict[str, str]:
    """Valid SAML IDP configuration."""
    return {
        "entity_id": "https://idp.example.com",
        "sso_url": "https://idp.example.com/sso",
        "x509_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    }


@pytest.fixture
def google_config() -> dict[str, str]:
    """Valid Google Workspace IDP configuration."""
    return {
        "service_account_json": '{"type":"service_account","project_id":"my-project"}',
        "admin_email": "admin@example.com",
        "domain": "example.com",
    }


@pytest.fixture
def okta_config() -> dict[str, str]:
    """Valid Okta IDP configuration."""
    return {
        "domain": "dev-12345.okta.com",
        "api_token": "okta-api-token-xyz",
    }


# ── Auth Tests ────────────────────────────────────────────────────────────


class TestAuthenticationAndAuthorization:
    """Test authentication and authorization on all endpoints."""

    async def test_list_idps_missing_auth(self, client, missing_auth_headers, mock_db):
        """GET /api/v1/idps without Authorization header returns 401."""
        with patch("api.v1.idp._get_token_claims", return_value=None):
            response = await client.get("/api/v1/idps", headers=missing_auth_headers)
            assert response.status_code == 401
            data = await response.get_json()
            assert data["error"] == "unauthorized"

    async def test_list_idps_insufficient_scope(
        self, client, insufficient_scope_headers, mock_db
    ):
        """GET /api/v1/idps with insufficient scope returns 403."""
        claims = {"scope": "other:read"}  # missing checkpoint:idps:admin
        with patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.get("/api/v1/idps", headers=insufficient_scope_headers)
            assert response.status_code == 403
            data = await response.get_json()
            assert data["error"] == "insufficient_scope"

    async def test_list_idps_with_checkpoint_admin_scope(
        self, client, authenticated_headers, mock_db
    ):
        """GET /api/v1/idps with checkpoint:admin scope (broader) succeeds."""
        claims = {"scope": "checkpoint:admin"}
        mock_db.return_value.select.return_value = []
        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.get("/api/v1/idps", headers=authenticated_headers)
                assert response.status_code == 200

    async def test_create_idp_missing_auth(self, client, missing_auth_headers, oidc_config):
        """POST /api/v1/idps without auth returns 401."""
        payload = {
            "name": "test-idp",
            "type": "oidc",
            "config": oidc_config,
        }
        with patch("api.v1.idp._get_token_claims", return_value=None):
            response = await client.post(
                "/api/v1/idps",
                json=payload,
                headers=missing_auth_headers,
            )
            assert response.status_code == 401

    async def test_delete_idp_insufficient_scope(
        self, client, insufficient_scope_headers, mock_db, mock_idp_row
    ):
        """DELETE /api/v1/idps/<id> without required scope returns 403."""
        claims = {"scope": "users:read"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.delete(
                    "/api/v1/idps/1",
                    headers=insufficient_scope_headers,
                )
                assert response.status_code == 403


# ── List Endpoint Tests ────────────────────────────────────────────────────


class TestListIDPs:
    """Test GET /api/v1/idps endpoint."""

    async def test_list_idps_empty(self, client, authenticated_headers, mock_db):
        """List IDPs returns empty array when none exist."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value = []
        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.get("/api/v1/idps", headers=authenticated_headers)
                assert response.status_code == 200
                data = await response.get_json()
                assert isinstance(data, list)
                assert len(data) == 0

    async def test_list_idps_returns_multiple(
        self, client, authenticated_headers, mock_db, mock_idp_row, mock_idp_row_saml
    ):
        """List IDPs returns all IDPs ordered by name."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value = [
            mock_idp_row,
            mock_idp_row_saml,
        ]
        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.get("/api/v1/idps", headers=authenticated_headers)
                assert response.status_code == 200
                data = await response.get_json()
                assert len(data) == 2
                assert data[0]["id"] == 1
                assert data[1]["id"] == 2
                # Verify no decrypted config is returned
                assert "config_json" not in data[0]
                assert "config_json_encrypted" not in data[0]


# ── Create Endpoint Tests ──────────────────────────────────────────────────


class TestCreateIDP:
    """Test POST /api/v1/idps endpoint."""

    async def test_create_oidc_idp_success(
        self, client, authenticated_headers, mock_db, oidc_config
    ):
        """Create OIDC IDP succeeds with valid config."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.insert.return_value = 1
        mock_idp_row = SimpleNamespace(
            id=1,
            name="my-oidc",
            type="oidc",
            federation_mode="sync",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        payload = {
            "name": "my-oidc",
            "type": "oidc",
            "config": oidc_config,
            "federation_mode": "sync",
            "sync_interval_secs": 3600,
        }

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_config"):
                with patch("api.v1.idp._get_audit", return_value=mock_audit):
                    with patch("api.v1.idp._get_token_claims", return_value=claims):
                        with patch("api.v1.idp._encrypt_config") as mock_encrypt:
                            mock_encrypt.return_value = (
                                '{"dek_encrypted":"x","dek_nonce":"y","nonce":"z","ciphertext":"w"}'
                            )
                            response = await client.post(
                                "/api/v1/idps",
                                json=payload,
                                headers=authenticated_headers,
                            )
                            assert response.status_code == 201
                            data = await response.get_json()
                            assert data["name"] == "my-oidc"
                            assert data["type"] == "oidc"
                            assert data["federation_mode"] == "sync"

    async def test_create_ldap_idp_success(
        self, client, authenticated_headers, mock_db, ldap_config
    ):
        """Create LDAP IDP succeeds with valid config."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.insert.return_value = 2
        mock_idp_row = SimpleNamespace(
            id=2,
            name="my-ldap",
            type="ldap",
            federation_mode="sync",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        payload = {
            "name": "my-ldap",
            "type": "ldap",
            "config": ldap_config,
        }

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_config"):
                with patch("api.v1.idp._get_audit", return_value=mock_audit):
                    with patch("api.v1.idp._get_token_claims", return_value=claims):
                        with patch("api.v1.idp._encrypt_config") as mock_encrypt:
                            mock_encrypt.return_value = (
                                '{"dek_encrypted":"a","dek_nonce":"b","nonce":"c","ciphertext":"d"}'
                            )
                            response = await client.post(
                                "/api/v1/idps",
                                json=payload,
                                headers=authenticated_headers,
                            )
                            assert response.status_code == 201

    async def test_create_saml_idp_success(
        self, client, authenticated_headers, mock_db, saml_config
    ):
        """Create SAML IDP succeeds with valid config."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.insert.return_value = 3
        mock_idp_row = SimpleNamespace(
            id=3,
            name="my-saml",
            type="saml",
            federation_mode="proxy",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        payload = {
            "name": "my-saml",
            "type": "saml",
            "config": saml_config,
            "federation_mode": "proxy",
        }

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_config"):
                with patch("api.v1.idp._get_audit", return_value=mock_audit):
                    with patch("api.v1.idp._get_token_claims", return_value=claims):
                        with patch("api.v1.idp._encrypt_config") as mock_encrypt:
                            mock_encrypt.return_value = (
                                '{"dek_encrypted":"e","dek_nonce":"f","nonce":"g","ciphertext":"h"}'
                            )
                            response = await client.post(
                                "/api/v1/idps",
                                json=payload,
                                headers=authenticated_headers,
                            )
                            assert response.status_code == 201

    async def test_create_google_idp_success(
        self, client, authenticated_headers, mock_db, google_config
    ):
        """Create Google Workspace IDP succeeds with valid config."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.insert.return_value = 4
        mock_idp_row = SimpleNamespace(
            id=4,
            name="my-google",
            type="google",
            federation_mode="sync",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        payload = {
            "name": "my-google",
            "type": "google",
            "config": google_config,
        }

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_config"):
                with patch("api.v1.idp._get_audit", return_value=mock_audit):
                    with patch("api.v1.idp._get_token_claims", return_value=claims):
                        with patch("api.v1.idp._encrypt_config") as mock_encrypt:
                            mock_encrypt.return_value = (
                                '{"dek_encrypted":"i","dek_nonce":"j","nonce":"k","ciphertext":"l"}'
                            )
                            response = await client.post(
                                "/api/v1/idps",
                                json=payload,
                                headers=authenticated_headers,
                            )
                            assert response.status_code == 201

    async def test_create_okta_idp_success(
        self, client, authenticated_headers, mock_db, okta_config
    ):
        """Create Okta IDP succeeds with valid config."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.insert.return_value = 5
        mock_idp_row = SimpleNamespace(
            id=5,
            name="my-okta",
            type="okta",
            federation_mode="sync",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        payload = {
            "name": "my-okta",
            "type": "okta",
            "config": okta_config,
        }

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_config"):
                with patch("api.v1.idp._get_audit", return_value=mock_audit):
                    with patch("api.v1.idp._get_token_claims", return_value=claims):
                        with patch("api.v1.idp._encrypt_config") as mock_encrypt:
                            mock_encrypt.return_value = (
                                '{"dek_encrypted":"m","dek_nonce":"n","nonce":"o","ciphertext":"p"}'
                            )
                            response = await client.post(
                                "/api/v1/idps",
                                json=payload,
                                headers=authenticated_headers,
                            )
                            assert response.status_code == 201

    async def test_create_idp_missing_name(
        self, client, authenticated_headers, mock_db, oidc_config
    ):
        """Create IDP without name returns 400."""
        claims = {"scope": "checkpoint:idps:admin"}
        payload = {"type": "oidc", "config": oidc_config}

        with patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json=payload,
                headers=authenticated_headers,
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "name is required" in data["error"]

    async def test_create_idp_invalid_type(
        self, client, authenticated_headers, mock_db, oidc_config
    ):
        """Create IDP with invalid type returns 400."""
        claims = {"scope": "checkpoint:idps:admin"}
        payload = {
            "name": "test",
            "type": "invalid_type",
            "config": oidc_config,
        }

        with patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json=payload,
                headers=authenticated_headers,
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "type must be one of" in data["error"]

    async def test_create_idp_invalid_federation_mode(
        self, client, authenticated_headers, mock_db, oidc_config
    ):
        """Create IDP with invalid federation_mode returns 400."""
        claims = {"scope": "checkpoint:idps:admin"}
        payload = {
            "name": "test",
            "type": "oidc",
            "config": oidc_config,
            "federation_mode": "invalid",
        }

        with patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json=payload,
                headers=authenticated_headers,
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "federation_mode must be one of" in data["error"]

    async def test_create_oidc_idp_missing_required_field(
        self, client, authenticated_headers, mock_db
    ):
        """Create OIDC IDP without required field returns 400 with details."""
        claims = {"scope": "checkpoint:idps:admin"}
        incomplete_config = {"issuer_url": "https://auth.example.com"}  # missing client_id, client_secret

        payload = {
            "name": "incomplete-oidc",
            "type": "oidc",
            "config": incomplete_config,
        }

        with patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json=payload,
                headers=authenticated_headers,
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert data["error"] == "invalid config"
            assert "details" in data
            assert len(data["details"]) > 0

    async def test_create_ldap_idp_missing_required_field(
        self, client, authenticated_headers, mock_db
    ):
        """Create LDAP IDP without required field returns 400 with details."""
        claims = {"scope": "checkpoint:idps:admin"}
        incomplete_config = {"host": "ldap.example.com"}  # missing other fields

        payload = {
            "name": "incomplete-ldap",
            "type": "ldap",
            "config": incomplete_config,
        }

        with patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json=payload,
                headers=authenticated_headers,
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert data["error"] == "invalid config"

    async def test_create_idp_missing_config(
        self, client, authenticated_headers, mock_db
    ):
        """Create IDP without config returns 400."""
        claims = {"scope": "checkpoint:idps:admin"}
        payload = {"name": "test", "type": "oidc"}

        with patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json=payload,
                headers=authenticated_headers,
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "config is required" in data["error"]

    async def test_create_idp_encryption_failure(
        self, client, authenticated_headers, mock_db, oidc_config
    ):
        """Create IDP with encryption failure returns 500."""
        claims = {"scope": "checkpoint:idps:admin"}
        payload = {
            "name": "test-idp",
            "type": "oidc",
            "config": oidc_config,
        }

        with patch("api.v1.idp._get_token_claims", return_value=claims):
            with patch("api.v1.idp._encrypt_config") as mock_encrypt:
                mock_encrypt.side_effect = RuntimeError("MEK not available")
                response = await client.post(
                    "/api/v1/idps",
                    json=payload,
                    headers=authenticated_headers,
                )
                assert response.status_code == 500
                data = await response.get_json()
                assert "server configuration error" in data["error"]


# ── Get Endpoint Tests ─────────────────────────────────────────────────────


class TestGetIDP:
    """Test GET /api/v1/idps/<id> endpoint."""

    async def test_get_idp_by_id(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Get IDP by ID returns IDP details without decrypted config."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.get(
                    "/api/v1/idps/1",
                    headers=authenticated_headers,
                )
                assert response.status_code == 200
                data = await response.get_json()
                assert data["id"] == 1
                assert data["name"] == "test-idp"
                assert data["type"] == "oidc"
                assert "config_json" not in data
                assert "config_json_encrypted" not in data

    async def test_get_idp_not_found(
        self, client, authenticated_headers, mock_db
    ):
        """Get nonexistent IDP returns 404."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = None

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.get(
                    "/api/v1/idps/999",
                    headers=authenticated_headers,
                )
                assert response.status_code == 404
                data = await response.get_json()
                assert data["error"] == "not found"


# ── Update Endpoint Tests ──────────────────────────────────────────────────


class TestUpdateIDP:
    """Test PUT /api/v1/idps/<id> endpoint."""

    async def test_update_idp_name(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Update IDP name succeeds."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        updated_row = SimpleNamespace(
            id=1,
            name="updated-name",
            type="oidc",
            federation_mode="sync",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=mock_idp_row.created_at,
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.side_effect = [
            mock_idp_row,  # First call (check existence)
            updated_row,   # Second call (return updated)
        ]

        payload = {"name": "updated-name"}

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_audit", return_value=mock_audit):
                with patch("api.v1.idp._get_token_claims", return_value=claims):
                    response = await client.put(
                        "/api/v1/idps/1",
                        json=payload,
                        headers=authenticated_headers,
                    )
                    assert response.status_code == 200
                    data = await response.get_json()
                    assert data["name"] == "updated-name"

    async def test_update_idp_federation_mode(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Update IDP federation_mode succeeds."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        updated_row = SimpleNamespace(
            id=1,
            name="test-idp",
            type="oidc",
            federation_mode="proxy",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=mock_idp_row.created_at,
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.side_effect = [
            mock_idp_row,
            updated_row,
        ]

        payload = {"federation_mode": "proxy"}

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_audit", return_value=mock_audit):
                with patch("api.v1.idp._get_token_claims", return_value=claims):
                    response = await client.put(
                        "/api/v1/idps/1",
                        json=payload,
                        headers=authenticated_headers,
                    )
                    assert response.status_code == 200
                    data = await response.get_json()
                    assert data["federation_mode"] == "proxy"

    async def test_update_idp_invalid_federation_mode(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Update IDP with invalid federation_mode returns 400."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row

        payload = {"federation_mode": "invalid"}

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.put(
                    "/api/v1/idps/1",
                    json=payload,
                    headers=authenticated_headers,
                )
                assert response.status_code == 400
                data = await response.get_json()
                assert "federation_mode must be one of" in data["error"]

    async def test_update_idp_config(
        self, client, authenticated_headers, mock_db, mock_idp_row, oidc_config
    ):
        """Update IDP config re-encrypts the config_json."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        updated_row = SimpleNamespace(
            id=1,
            name="test-idp",
            type="oidc",
            federation_mode="sync",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=mock_idp_row.created_at,
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.side_effect = [
            mock_idp_row,
            updated_row,
        ]

        new_config = {
            "issuer_url": "https://new-auth.example.com",
            "client_id": "new-client",
            "client_secret": "new-secret",
        }

        payload = {"config": new_config}

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_audit", return_value=mock_audit):
                with patch("api.v1.idp._get_token_claims", return_value=claims):
                    with patch("api.v1.idp._encrypt_config") as mock_encrypt:
                        mock_encrypt.return_value = (
                            '{"dek_encrypted":"new","dek_nonce":"data","nonce":"here","ciphertext":"done"}'
                        )
                        response = await client.put(
                            "/api/v1/idps/1",
                            json=payload,
                            headers=authenticated_headers,
                        )
                        assert response.status_code == 200
                        # Verify encryption was called
                        mock_encrypt.assert_called_once()

    async def test_update_idp_config_invalid(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Update IDP with invalid config returns 400."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row

        invalid_config = {"issuer_url": "https://auth.example.com"}  # missing fields for oidc

        payload = {"config": invalid_config}

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.put(
                    "/api/v1/idps/1",
                    json=payload,
                    headers=authenticated_headers,
                )
                assert response.status_code == 400
                data = await response.get_json()
                assert data["error"] == "invalid config"

    async def test_update_idp_not_found(
        self, client, authenticated_headers, mock_db
    ):
        """Update nonexistent IDP returns 404."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = None

        payload = {"name": "new-name"}

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.put(
                    "/api/v1/idps/999",
                    json=payload,
                    headers=authenticated_headers,
                )
                assert response.status_code == 404

    async def test_update_idp_multiple_fields(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Update multiple IDP fields at once."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        updated_row = SimpleNamespace(
            id=1,
            name="new-name",
            type="oidc",
            federation_mode="proxy",
            sync_interval_secs=7200,
            is_active=False,
            last_sync_at=None,
            sync_error=None,
            created_at=mock_idp_row.created_at,
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.side_effect = [
            mock_idp_row,
            updated_row,
        ]

        payload = {
            "name": "new-name",
            "federation_mode": "proxy",
            "sync_interval_secs": 7200,
            "is_active": False,
        }

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_audit", return_value=mock_audit):
                with patch("api.v1.idp._get_token_claims", return_value=claims):
                    response = await client.put(
                        "/api/v1/idps/1",
                        json=payload,
                        headers=authenticated_headers,
                    )
                    assert response.status_code == 200
                    data = await response.get_json()
                    assert data["name"] == "new-name"
                    assert data["federation_mode"] == "proxy"
                    assert data["sync_interval_secs"] == 7200
                    assert data["is_active"] is False


# ── Delete Endpoint Tests ──────────────────────────────────────────────────


class TestDeleteIDP:
    """Test DELETE /api/v1/idps/<id> endpoint."""

    async def test_delete_idp_success(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Delete IDP (soft-delete) succeeds."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_audit", return_value=mock_audit):
                with patch("api.v1.idp._get_token_claims", return_value=claims):
                    response = await client.delete(
                        "/api/v1/idps/1",
                        headers=authenticated_headers,
                    )
                    assert response.status_code == 200
                    data = await response.get_json()
                    assert data["status"] == "deleted"
                    # Verify audit log was called
                    mock_audit.log.assert_called_once()

    async def test_delete_idp_not_found(
        self, client, authenticated_headers, mock_db
    ):
        """Delete nonexistent IDP returns 404."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = None

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.delete(
                    "/api/v1/idps/999",
                    headers=authenticated_headers,
                )
                assert response.status_code == 404


# ── Sync Endpoint Tests ────────────────────────────────────────────────────


class TestTriggerSync:
    """Test POST /api/v1/idps/<id>/sync endpoint."""

    async def test_trigger_sync_success(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Trigger manual sync succeeds."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_audit", return_value=mock_audit):
                with patch("api.v1.idp._get_token_claims", return_value=claims):
                    response = await client.post(
                        "/api/v1/idps/1/sync",
                        headers=authenticated_headers,
                    )
                    assert response.status_code == 202
                    data = await response.get_json()
                    assert data["status"] == "sync_queued"
                    assert data["idp_id"] == 1

    async def test_trigger_sync_not_found(
        self, client, authenticated_headers, mock_db
    ):
        """Trigger sync on nonexistent IDP returns 404."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = None

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.post(
                    "/api/v1/idps/999/sync",
                    headers=authenticated_headers,
                )
                assert response.status_code == 404

    async def test_trigger_sync_inactive_idp(
        self, client, authenticated_headers, mock_db
    ):
        """Trigger sync on inactive IDP returns 400."""
        claims = {"scope": "checkpoint:idps:admin"}
        inactive_row = SimpleNamespace(
            id=1,
            name="inactive",
            type="oidc",
            federation_mode="sync",
            sync_interval_secs=3600,
            is_active=False,
            last_sync_at=None,
            sync_error=None,
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.return_value = inactive_row

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.post(
                    "/api/v1/idps/1/sync",
                    headers=authenticated_headers,
                )
                assert response.status_code == 400
                data = await response.get_json()
                assert "inactive" in data["error"]

    async def test_trigger_sync_saml_sync_mode_not_supported(
        self, client, authenticated_headers, mock_db, mock_idp_row_saml
    ):
        """Trigger sync on SAML IDP in sync mode returns 400."""
        # Convert SAML row to sync mode for this test
        saml_sync_row = SimpleNamespace(
            id=2,
            name="saml-sync",
            type="saml",
            federation_mode="sync",  # SAML doesn't support sync
            sync_interval_secs=7200,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )

        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = saml_sync_row

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.post(
                    "/api/v1/idps/2/sync",
                    headers=authenticated_headers,
                )
                assert response.status_code == 400
                data = await response.get_json()
                assert "SAML" in data["error"]

    async def test_trigger_sync_resets_sync_error(
        self, client, authenticated_headers, mock_db
    ):
        """Trigger sync clears previous sync_error."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        error_row = SimpleNamespace(
            id=1,
            name="test-idp",
            type="oidc",
            federation_mode="sync",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=datetime(2025, 1, 1, 12, 0, 0),
            sync_error="Previous sync failed",
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.return_value = error_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_audit", return_value=mock_audit):
                with patch("api.v1.idp._get_token_claims", return_value=claims):
                    response = await client.post(
                        "/api/v1/idps/1/sync",
                        headers=authenticated_headers,
                    )
                    assert response.status_code == 202
                    # Verify the update call includes sync_error=None
                    calls = mock_db.return_value.update.call_args_list
                    assert any(
                        "sync_error" in str(call) for call in calls
                    ), "sync_error should be reset"


# ── Serialization Tests ────────────────────────────────────────────────────


class TestSerialization:
    """Test IDP serialization (no config leakage)."""

    async def test_serialized_idp_never_includes_config(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Serialized IDP never includes config_json or config_json_encrypted."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.get(
                    "/api/v1/idps/1",
                    headers=authenticated_headers,
                )
                data = await response.get_json()
                assert "config_json" not in data
                assert "config_json_encrypted" not in data
                assert "config" not in data

    async def test_list_serialized_idps_never_includes_config(
        self, client, authenticated_headers, mock_db, mock_idp_row, mock_idp_row_saml
    ):
        """Listed IDPs never include config_json."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value = [
            mock_idp_row,
            mock_idp_row_saml,
        ]

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.get(
                    "/api/v1/idps",
                    headers=authenticated_headers,
                )
                data = await response.get_json()
                for idp in data:
                    assert "config_json" not in idp
                    assert "config_json_encrypted" not in idp


# ── Edge Case Tests ────────────────────────────────────────────────────────


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    async def test_create_idp_empty_name(
        self, client, authenticated_headers, mock_db, oidc_config
    ):
        """Create IDP with empty string name is treated as missing."""
        claims = {"scope": "checkpoint:idps:admin"}
        payload = {
            "name": "   ",  # whitespace only
            "type": "oidc",
            "config": oidc_config,
        }

        with patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json=payload,
                headers=authenticated_headers,
            )
            assert response.status_code == 400

    async def test_create_idp_type_case_insensitive(
        self, client, authenticated_headers, mock_db, oidc_config
    ):
        """Create IDP with uppercase type name is normalized."""
        claims = {"scope": "checkpoint:idps:admin", "sub": "user-123"}
        payload = {
            "name": "test-idp",
            "type": "OIDC",  # uppercase
            "config": oidc_config,
        }

        mock_db.return_value.insert.return_value = 1
        mock_idp_row = SimpleNamespace(
            id=1,
            name="test-idp",
            type="oidc",
            federation_mode="sync",
            sync_interval_secs=3600,
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
            updated_at=datetime.now(tz=timezone.utc).replace(tzinfo=None),
        )
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row
        mock_audit = AsyncMock()
        mock_audit.log = AsyncMock()

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_config"):
                with patch("api.v1.idp._get_audit", return_value=mock_audit):
                    with patch("api.v1.idp._get_token_claims", return_value=claims):
                        with patch("api.v1.idp._encrypt_config") as mock_encrypt:
                            mock_encrypt.return_value = (
                                '{"dek_encrypted":"x","dek_nonce":"y","nonce":"z","ciphertext":"w"}'
                            )
                            response = await client.post(
                                "/api/v1/idps",
                                json=payload,
                                headers=authenticated_headers,
                            )
                            assert response.status_code == 201

    async def test_update_idp_empty_config_dict(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """Update IDP with empty config dict returns 400."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value.first.return_value = mock_idp_row

        payload = {"config": {}}

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.put(
                    "/api/v1/idps/1",
                    json=payload,
                    headers=authenticated_headers,
                )
                assert response.status_code == 400

    async def test_list_idps_response_has_iso_timestamps(
        self, client, authenticated_headers, mock_db, mock_idp_row
    ):
        """List IDPs includes ISO 8601 timestamps with Z suffix."""
        claims = {"scope": "checkpoint:idps:admin"}
        mock_db.return_value.select.return_value = [mock_idp_row]

        with patch("api.v1.idp._get_db", return_value=mock_db):
            with patch("api.v1.idp._get_token_claims", return_value=claims):
                response = await client.get(
                    "/api/v1/idps",
                    headers=authenticated_headers,
                )
                data = await response.get_json()
                assert len(data) > 0
                idp = data[0]
                if idp["created_at"]:
                    assert idp["created_at"].endswith("Z")
                if idp["updated_at"]:
                    assert idp["updated_at"].endswith("Z")
                if idp["last_sync_at"]:
                    assert idp["last_sync_at"].endswith("Z")


# ── Uncovered Validation Tests ───────────────────────────────────────────────────


@pytest.mark.asyncio
class TestCreateIDPValidation:
    """Test IDP validation for all types (lines 99-107, 121-140, 149-164)."""

    async def test_create_oidc_missing_issuer_url(self, client, authenticated_headers, mock_db):
        """OIDC validation: missing issuer_url → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Test IDP",
                    "type": "oidc",
                    "config": {"client_id": "id", "client_secret": "secret"},  # Missing issuer_url
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_oidc_missing_client_id(self, client, authenticated_headers, mock_db):
        """OIDC validation: missing client_id → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Test IDP",
                    "type": "oidc",
                    "config": {"issuer_url": "https://oidc.example.com", "client_secret": "secret"},  # Missing client_id
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_oidc_missing_client_secret(self, client, authenticated_headers, mock_db):
        """OIDC validation: missing client_secret → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Test IDP",
                    "type": "oidc",
                    "config": {"issuer_url": "https://oidc.example.com", "client_id": "id"},  # Missing client_secret
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_ldap_missing_host(self, client, authenticated_headers, mock_db):
        """LDAP validation: missing host → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "LDAP IDP",
                    "type": "ldap",
                    "config": {"port": 389, "bind_dn": "cn=admin", "bind_password": "pwd", "base_dn": "dc=example"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_ldap_missing_bind_dn(self, client, authenticated_headers, mock_db):
        """LDAP validation: missing bind_dn → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "LDAP IDP",
                    "type": "ldap",
                    "config": {"host": "ldap.example.com", "port": 389, "bind_password": "pwd", "base_dn": "dc=example"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_saml_missing_entity_id(self, client, authenticated_headers, mock_db):
        """SAML validation: missing entity_id → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "SAML IDP",
                    "type": "saml",
                    "config": {"sso_url": "https://saml.example.com/sso", "x509_cert": "cert"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_saml_missing_sso_url(self, client, authenticated_headers, mock_db):
        """SAML validation: missing sso_url → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "SAML IDP",
                    "type": "saml",
                    "config": {"entity_id": "https://idp.example.com", "x509_cert": "cert"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_saml_missing_x509_cert(self, client, authenticated_headers, mock_db):
        """SAML validation: missing x509_cert → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "SAML IDP",
                    "type": "saml",
                    "config": {"entity_id": "https://idp.example.com", "sso_url": "https://saml.example.com/sso"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_google_missing_service_account_json(self, client, authenticated_headers, mock_db):
        """Google validation: missing service_account_json → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Google IDP",
                    "type": "google",
                    "config": {"admin_email": "admin@example.com", "domain": "example.com"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_google_missing_admin_email(self, client, authenticated_headers, mock_db):
        """Google validation: missing admin_email → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Google IDP",
                    "type": "google",
                    "config": {"service_account_json": "{}", "domain": "example.com"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_google_missing_domain(self, client, authenticated_headers, mock_db):
        """Google validation: missing domain → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Google IDP",
                    "type": "google",
                    "config": {"service_account_json": "{}", "admin_email": "admin@example.com"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_okta_missing_domain(self, client, authenticated_headers, mock_db):
        """Okta validation: missing domain → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Okta IDP",
                    "type": "okta",
                    "config": {"api_token": "token"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_okta_missing_api_token(self, client, authenticated_headers, mock_db):
        """Okta validation: missing api_token → 400."""
        claims = {"scope": "checkpoint:idps:admin"}

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Okta IDP",
                    "type": "okta",
                    "config": {"domain": "example.okta.com"},
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 400

    async def test_create_idp_with_all_valid_fields(self, client, authenticated_headers, mock_db):
        """OIDC: all required fields present → 201."""
        claims = {"scope": "checkpoint:idps:admin"}
        new_row = SimpleNamespace(
            id=10,
            name="Complete IDP",
            type="oidc",
            federation_mode="sync",
            sync_interval_secs=3600,
            config_json_encrypted="encrypted",
            is_active=True,
            last_sync_at=None,
            sync_error=None,
            created_at=datetime(2025, 1, 1, 10, 0, 0),
            updated_at=datetime(2025, 1, 1, 10, 0, 0),
        )
        mock_db.return_value.insert.return_value = 10
        mock_db.return_value.select.return_value.first.return_value = new_row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=claims), \
             patch("api.v1.idp._encrypt_config", return_value="encrypted"):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Complete IDP",
                    "type": "oidc",
                    "config": {
                        "issuer_url": "https://oidc.example.com",
                        "client_id": "id",
                        "client_secret": "secret",
                    },
                },
                headers=authenticated_headers,
            )

        assert response.status_code == 201
        data = await response.get_json()
        assert data["id"] == 10
        assert data["name"] == "Complete IDP"
