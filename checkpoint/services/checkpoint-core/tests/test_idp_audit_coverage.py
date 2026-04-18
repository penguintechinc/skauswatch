"""Coverage tests for api/v1/idp.py and api/v1/audit.py endpoints."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


@pytest.mark.asyncio
class TestIDPCreateValidation:
    """Test POST /api/v1/idps validation and error cases."""

    async def test_create_idp_missing_name(self, client, mock_db):
        """POST /api/v1/idps without name field returns 400."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.post(
                "/api/v1/idps",
                json={"type": "oidc", "config": {}},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 400

    async def test_create_idp_missing_type(self, client, mock_db):
        """POST /api/v1/idps without type field returns 400."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.post(
                "/api/v1/idps",
                json={"name": "Test IDP", "config": {}},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 400

    async def test_create_idp_invalid_type(self, client, mock_db):
        """POST /api/v1/idps with invalid type returns 400."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.post(
                "/api/v1/idps",
                json={"name": "Test", "type": "invalid_type", "config": {}},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 400

    async def test_create_idp_oidc_missing_client_id(self, client, mock_db):
        """POST /api/v1/idps OIDC without client_id in config returns 400."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.post(
                "/api/v1/idps",
                json={"name": "OIDC IDP", "type": "oidc", "config": {"discovery_url": "https://oidc.test"}},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 400

    async def test_create_idp_ldap_missing_bind_dn(self, client, mock_db):
        """POST /api/v1/idps LDAP without bind_dn in config returns 400."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.post(
                "/api/v1/idps",
                json={"name": "LDAP IDP", "type": "ldap", "config": {"server": "ldap.test"}},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 400

    async def test_create_idp_unauthorized(self, client, mock_db):
        """POST /api/v1/idps without checkpoint:idps:admin scope returns 403."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:viewer"}):
            response = await client.post(
                "/api/v1/idps",
                json={"name": "Test", "type": "oidc", "config": {"client_id": "x"}},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 403

    async def test_create_idp_unauthenticated(self, client, mock_db):
        """POST /api/v1/idps without Authorization header returns 401."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value=None):
            response = await client.post(
                "/api/v1/idps",
                json={"name": "Test", "type": "oidc", "config": {}}
            )
        assert response.status_code == 401


@pytest.mark.asyncio
class TestIDPGetNotFound:
    """Test GET /api/v1/idps/<id> when IDP not found."""

    async def test_get_idp_not_found(self, client, mock_db):
        """GET /api/v1/idps/<id> with non-existent ID returns 404."""
        mock_db.return_value.select.return_value.first.return_value = None
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.get(
                "/api/v1/idps/nonexistent",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestIDPUpdateNotFound:
    """Test PUT /api/v1/idps/<id> when IDP not found."""

    async def test_update_idp_not_found(self, client, mock_db):
        """PUT /api/v1/idps/<id> with non-existent ID returns 404."""
        mock_db.return_value.select.return_value.first.return_value = None
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.put(
                "/api/v1/idps/nonexistent",
                json={"name": "Updated"},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestIDPDeleteNotFound:
    """Test DELETE /api/v1/idps/<id> when IDP not found."""

    async def test_delete_idp_not_found(self, client, mock_db):
        """DELETE /api/v1/idps/<id> with non-existent ID returns 404."""
        mock_db.return_value.select.return_value.first.return_value = None
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.delete(
                "/api/v1/idps/nonexistent",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 404


@pytest.mark.asyncio
class TestIDPListEndpoint:
    """Test GET /api/v1/idps list endpoint."""

    async def test_list_idps_empty(self, client, mock_db):
        """GET /api/v1/idps with no IDPs returns 200 with empty list."""
        mock_db.return_value.select.return_value = []
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.get(
                "/api/v1/idps",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_list_idps_unauthorized(self, client, mock_db):
        """GET /api/v1/idps without required scope returns 403."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:viewer"}):
            response = await client.get(
                "/api/v1/idps",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestAuditLogEndpoint:
    """Test GET /api/v1/audit endpoint."""

    async def test_audit_list_empty(self, client, mock_db):
        """GET /api/v1/audit with no logs returns 200."""
        mock_db.return_value.select.return_value = []
        with patch("api.v1.audit._get_db", return_value=mock_db), \
             patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_audit_filter_by_actor_uuid(self, client, mock_db):
        """GET /api/v1/audit?actor_uuid=xxx filters results."""
        mock_db.return_value.select.return_value = []
        with patch("api.v1.audit._get_db", return_value=mock_db), \
             patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}):
            response = await client.get(
                "/api/v1/audit?actor_uuid=user-123",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_audit_filter_by_event_type(self, client, mock_db):
        """GET /api/v1/audit?event_type=auth.success filters results."""
        mock_db.return_value.select.return_value = []
        with patch("api.v1.audit._get_db", return_value=mock_db), \
             patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}):
            response = await client.get(
                "/api/v1/audit?event_type=auth.success",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_audit_filter_by_date_range(self, client, mock_db):
        """GET /api/v1/audit?date_start=xxx&date_end=yyy filters by date."""
        mock_db.return_value.select.return_value = []
        with patch("api.v1.audit._get_db", return_value=mock_db), \
             patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}):
            response = await client.get(
                "/api/v1/audit?date_start=2025-01-01&date_end=2025-01-31",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_audit_pagination_defaults(self, client, mock_db):
        """GET /api/v1/audit uses default pagination values."""
        mock_db.return_value.select.return_value = []
        with patch("api.v1.audit._get_db", return_value=mock_db), \
             patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_audit_pagination_custom(self, client, mock_db):
        """GET /api/v1/audit?page=2&per_page=50 uses custom pagination."""
        mock_db.return_value.select.return_value = []
        with patch("api.v1.audit._get_db", return_value=mock_db), \
             patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}):
            response = await client.get(
                "/api/v1/audit?page=2&per_page=50",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_audit_unauthorized(self, client, mock_db):
        """GET /api/v1/audit without checkpoint:audit:read scope returns 403."""
        with patch("api.v1.audit._get_db", return_value=mock_db), \
             patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:viewer"}):
            response = await client.get(
                "/api/v1/audit",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 403

    async def test_audit_unauthenticated(self, client, mock_db):
        """GET /api/v1/audit without Authorization header returns 401."""
        with patch("api.v1.audit._get_db", return_value=mock_db), \
             patch("api.v1.audit._get_token_claims", return_value=None):
            response = await client.get("/api/v1/audit")
        assert response.status_code == 401

    async def test_audit_multiple_filters_combined(self, client, mock_db):
        """GET /api/v1/audit with multiple query filters combined."""
        mock_db.return_value.select.return_value = []
        with patch("api.v1.audit._get_db", return_value=mock_db), \
             patch("api.v1.audit._get_token_claims", return_value={"scope": "checkpoint:audit:read"}):
            response = await client.get(
                "/api/v1/audit?actor_uuid=user-123&event_type=auth.success&page=1&per_page=20",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200


@pytest.mark.asyncio
class TestIDPCreateSuccess:
    """Test POST /api/v1/idps successful creation with encryption."""

    async def test_create_idp_oidc_success(self, client, mock_db):
        """POST /api/v1/idps with valid OIDC config returns 201 and encrypted IDP."""
        row = MagicMock()
        row.id = 1
        row.name = "Test OIDC"
        row.type = "oidc"
        row.federation_mode = "sync"
        row.sync_interval_secs = 3600
        row.is_active = True
        row.last_sync_at = None
        row.sync_error = None
        row.created_at = None
        row.updated_at = None

        mock_db.return_value.checkpoint_upstream_idps.insert.return_value = 1
        mock_db.return_value.select.return_value.first.return_value = row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}), \
             patch("api.v1.idp._encrypt_config", return_value='{"dek_encrypted":"X","nonce":"Y","ciphertext":"Z"}'):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Test OIDC",
                    "type": "oidc",
                    "config": {"issuer_url": "https://oidc.test", "client_id": "id", "client_secret": "sec"},
                    "federation_mode": "sync",
                    "sync_interval_secs": 3600
                },
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 201

    async def test_create_idp_ldap_success(self, client, mock_db):
        """POST /api/v1/idps with valid LDAP config returns 201."""
        row = MagicMock()
        row.id = 2
        row.name = "Test LDAP"
        row.type = "ldap"
        row.federation_mode = "proxy"
        row.sync_interval_secs = 7200
        row.is_active = True
        row.last_sync_at = None
        row.sync_error = None
        row.created_at = None
        row.updated_at = None

        mock_db.return_value.checkpoint_upstream_idps.insert.return_value = 2
        mock_db.return_value.select.return_value.first.return_value = row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}), \
             patch("api.v1.idp._encrypt_config", return_value='{"dek_encrypted":"X","nonce":"Y","ciphertext":"Z"}'):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Test LDAP",
                    "type": "ldap",
                    "config": {
                        "host": "ldap.test",
                        "port": 389,
                        "bind_dn": "cn=admin",
                        "bind_password": "pass",
                        "base_dn": "dc=test"
                    },
                    "federation_mode": "proxy"
                },
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 201

    async def test_create_idp_saml_success(self, client, mock_db):
        """POST /api/v1/idps with valid SAML config returns 201."""
        row = MagicMock()
        row.id = 3
        row.name = "Test SAML"
        row.type = "saml"
        row.federation_mode = "proxy"
        row.sync_interval_secs = 3600
        row.is_active = True
        row.last_sync_at = None
        row.sync_error = None
        row.created_at = None
        row.updated_at = None

        mock_db.return_value.checkpoint_upstream_idps.insert.return_value = 3
        mock_db.return_value.select.return_value.first.return_value = row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}), \
             patch("api.v1.idp._encrypt_config", return_value='{"dek_encrypted":"X","nonce":"Y","ciphertext":"Z"}'):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Test SAML",
                    "type": "saml",
                    "config": {
                        "entity_id": "https://saml.test",
                        "sso_url": "https://saml.test/sso",
                        "x509_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                    }
                },
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 201

    async def test_create_idp_encryption_failure(self, client, mock_db):
        """POST /api/v1/idps with encryption failure returns 500."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}), \
             patch("api.v1.idp._encrypt_config", side_effect=RuntimeError("MEK not available")):
            response = await client.post(
                "/api/v1/idps",
                json={
                    "name": "Test IDP",
                    "type": "oidc",
                    "config": {"issuer_url": "https://oidc.test", "client_id": "id", "client_secret": "sec"}
                },
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 500


@pytest.mark.asyncio
class TestIDPUpdateSuccess:
    """Test PUT /api/v1/idps/<id> successful updates."""

    async def test_update_idp_name_only(self, client, mock_db):
        """PUT /api/v1/idps/<id> updating only name returns 200."""
        old_row = MagicMock()
        old_row.id = 1
        old_row.name = "Old Name"
        old_row.type = "oidc"
        old_row.federation_mode = "sync"
        old_row.sync_interval_secs = 3600
        old_row.is_active = True
        old_row.last_sync_at = None
        old_row.sync_error = None
        old_row.created_at = None
        old_row.updated_at = None

        new_row = MagicMock()
        new_row.id = 1
        new_row.name = "New Name"
        new_row.type = "oidc"
        new_row.federation_mode = "sync"
        new_row.sync_interval_secs = 3600
        new_row.is_active = True
        new_row.last_sync_at = None
        new_row.sync_error = None
        new_row.created_at = None
        new_row.updated_at = None

        mock_db.return_value.checkpoint_upstream_idps.id == 1
        mock_db.return_value.select.return_value.first.side_effect = [old_row, new_row]

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}):
            response = await client.put(
                "/api/v1/idps/1",
                json={"name": "New Name"},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_update_idp_federation_mode(self, client, mock_db):
        """PUT /api/v1/idps/<id> updating federation_mode returns 200."""
        old_row = MagicMock()
        old_row.id = 1
        old_row.type = "ldap"
        old_row.federation_mode = "sync"

        new_row = MagicMock()
        new_row.id = 1
        new_row.name = "Test LDAP"
        new_row.type = "ldap"
        new_row.federation_mode = "proxy"
        new_row.sync_interval_secs = 3600
        new_row.is_active = True
        new_row.last_sync_at = None
        new_row.sync_error = None
        new_row.created_at = None
        new_row.updated_at = None

        mock_db.return_value.select.return_value.first.side_effect = [old_row, new_row]

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}):
            response = await client.put(
                "/api/v1/idps/1",
                json={"federation_mode": "proxy"},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_update_idp_config_with_encryption(self, client, mock_db):
        """PUT /api/v1/idps/<id> updating config re-encrypts returns 200."""
        old_row = MagicMock()
        old_row.id = 1
        old_row.type = "oidc"

        new_row = MagicMock()
        new_row.id = 1
        new_row.name = "Updated OIDC"
        new_row.type = "oidc"
        new_row.federation_mode = "sync"
        new_row.sync_interval_secs = 3600
        new_row.is_active = True
        new_row.last_sync_at = None
        new_row.sync_error = None
        new_row.created_at = None
        new_row.updated_at = None

        mock_db.return_value.select.return_value.first.side_effect = [old_row, new_row]

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}), \
             patch("api.v1.idp._encrypt_config", return_value='{"dek_encrypted":"X","nonce":"Y","ciphertext":"Z"}'):
            response = await client.put(
                "/api/v1/idps/1",
                json={
                    "config": {"issuer_url": "https://oidc-new.test", "client_id": "newid", "client_secret": "newsec"}
                },
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200

    async def test_update_idp_invalid_federation_mode(self, client, mock_db):
        """PUT /api/v1/idps/<id> with invalid federation_mode returns 400."""
        old_row = MagicMock()
        old_row.id = 1

        mock_db.return_value.select.return_value.first.return_value = old_row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.put(
                "/api/v1/idps/1",
                json={"federation_mode": "invalid_mode"},
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 400

    async def test_update_idp_config_validation_error(self, client, mock_db):
        """PUT /api/v1/idps/<id> with invalid config returns 400."""
        old_row = MagicMock()
        old_row.id = 1
        old_row.type = "oidc"

        mock_db.return_value.select.return_value.first.return_value = old_row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.put(
                "/api/v1/idps/1",
                json={"config": {"issuer_url": "https://oidc.test"}},  # Missing client_id and client_secret
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 400

    async def test_update_idp_config_encryption_failure(self, client, mock_db):
        """PUT /api/v1/idps/<id> with encryption failure returns 500."""
        old_row = MagicMock()
        old_row.id = 1
        old_row.type = "saml"

        mock_db.return_value.select.return_value.first.return_value = old_row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}), \
             patch("api.v1.idp._encrypt_config", side_effect=RuntimeError("MEK not available")):
            response = await client.put(
                "/api/v1/idps/1",
                json={
                    "config": {
                        "entity_id": "https://saml.test",
                        "sso_url": "https://saml.test/sso",
                        "x509_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
                    }
                },
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 500


@pytest.mark.asyncio
class TestIDPSyncEndpoint:
    """Test POST /api/v1/idps/<id>/sync endpoint."""

    async def test_trigger_sync_success(self, client, mock_db):
        """POST /api/v1/idps/<id>/sync queues sync and returns 202."""
        row = MagicMock()
        row.id = 1
        row.name = "Test IDP"
        row.is_active = True
        row.type = "oidc"
        row.federation_mode = "sync"

        mock_db.return_value.select.return_value.first.return_value = row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}):
            response = await client.post(
                "/api/v1/idps/1/sync",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 202

    async def test_trigger_sync_idp_not_found(self, client, mock_db):
        """POST /api/v1/idps/<id>/sync with non-existent IDP returns 404."""
        mock_db.return_value.select.return_value.first.return_value = None

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.post(
                "/api/v1/idps/999/sync",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 404

    async def test_trigger_sync_inactive_idp(self, client, mock_db):
        """POST /api/v1/idps/<id>/sync with inactive IDP returns 400."""
        row = MagicMock()
        row.id = 1
        row.is_active = False

        mock_db.return_value.select.return_value.first.return_value = row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.post(
                "/api/v1/idps/1/sync",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 400

    async def test_trigger_sync_saml_sync_mode_not_supported(self, client, mock_db):
        """POST /api/v1/idps/<id>/sync SAML sync mode returns 400."""
        row = MagicMock()
        row.id = 1
        row.is_active = True
        row.type = "saml"
        row.federation_mode = "sync"
        row.name = "Test SAML"

        mock_db.return_value.select.return_value.first.return_value = row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.post(
                "/api/v1/idps/1/sync",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 400

    async def test_trigger_sync_saml_proxy_success(self, client, mock_db):
        """POST /api/v1/idps/<id>/sync SAML proxy mode returns 202."""
        row = MagicMock()
        row.id = 1
        row.is_active = True
        row.type = "saml"
        row.federation_mode = "proxy"
        row.name = "Test SAML"

        mock_db.return_value.select.return_value.first.return_value = row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}):
            response = await client.post(
                "/api/v1/idps/1/sync",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 202

    async def test_trigger_sync_unauthorized(self, client, mock_db):
        """POST /api/v1/idps/<id>/sync without scope returns 403."""
        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:viewer"}):
            response = await client.post(
                "/api/v1/idps/1/sync",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 403


@pytest.mark.asyncio
class TestIDPGetSuccess:
    """Test GET /api/v1/idps/<id> successful retrieval."""

    async def test_get_idp_success(self, client, mock_db):
        """GET /api/v1/idps/<id> returns IDP details."""
        row = MagicMock()
        row.id = 1
        row.name = "Test IDP"
        row.type = "oidc"
        row.federation_mode = "sync"
        row.sync_interval_secs = 3600
        row.is_active = True
        row.last_sync_at = None
        row.sync_error = None
        row.created_at = None
        row.updated_at = None

        mock_db.return_value.select.return_value.first.return_value = row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin"}):
            response = await client.get(
                "/api/v1/idps/1",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200


@pytest.mark.asyncio
class TestIDPDeleteSuccess:
    """Test DELETE /api/v1/idps/<id> successful deletion."""

    async def test_delete_idp_success(self, client, mock_db):
        """DELETE /api/v1/idps/<id> soft-deletes IDP returns 200."""
        row = MagicMock()
        row.id = 1
        row.name = "Test IDP"

        mock_db.return_value.select.return_value.first.return_value = row

        with patch("api.v1.idp._get_db", return_value=mock_db), \
             patch("api.v1.idp._get_token_claims", return_value={"scope": "checkpoint:idps:admin", "sub": "user-1"}):
            response = await client.delete(
                "/api/v1/idps/1",
                headers={"Authorization": "Bearer test"}
            )
        assert response.status_code == 200
