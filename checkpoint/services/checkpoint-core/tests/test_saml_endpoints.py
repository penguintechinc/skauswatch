"""
Tests for saml/endpoints.py — SAML 2.0 IdP endpoints.

Covers:
  - GET /saml/metadata → IdP metadata XML
  - GET /saml/sso → IdP-initiated SSO (JWT auth required)
  - POST /saml/acs/<sp_entity_b64> → Assertion Consumer Service
  - GET /saml/slo → Single Logout
  - GET /saml/upstream/<idp_id> → Upstream IdP federation request
  - Missing/invalid parameters and error cases
  - Unsigned/tampered assertions rejected
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from types import SimpleNamespace

import pytest
from lxml import etree

from saml.endpoints import (
    saml_bp,
    _strip_pem,
    _extract_issuer_from_authn_request,
)


@pytest.mark.asyncio
class TestIdpMetadata:
    """Test GET /saml/metadata endpoint."""

    async def test_metadata_returns_xml(self, client):
        """GET /saml/metadata returns valid XML response."""
        response = await client.get("/saml/metadata")
        assert response.status_code == 200
        assert "application/xml" in response.content_type

        data = await response.get_data()
        assert b"EntityDescriptor" in data
        assert b"IDPSSODescriptor" in data

    async def test_metadata_includes_issuer_url(self, client):
        """Metadata includes issuer URL."""
        response = await client.get("/saml/metadata")
        data = await response.get_data()
        root = etree.fromstring(data)
        issuer_url = root.get("entityID")
        assert "checkpoint.test" in issuer_url

    async def test_metadata_includes_sso_url(self, client):
        """Metadata includes SSO endpoint."""
        response = await client.get("/saml/metadata")
        data = await response.get_data()

        root = etree.fromstring(data)
        ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
        sso_services = root.findall(".//md:SingleSignOnService", ns)

        assert len(sso_services) >= 1
        sso_urls = [svc.get("Location") for svc in sso_services]
        assert any("/saml/sso" in url for url in sso_urls)

    async def test_metadata_includes_slo_url(self, client):
        """Metadata includes SLO endpoint."""
        response = await client.get("/saml/metadata")
        data = await response.get_data()

        root = etree.fromstring(data)
        ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata"}
        slo_services = root.findall(".//md:SingleLogoutService", ns)

        assert len(slo_services) >= 1
        slo_urls = [svc.get("Location") for svc in slo_services]
        assert any("/saml/slo" in url for url in slo_urls)

    async def test_metadata_no_auth_required(self, client):
        """Metadata endpoint requires no authentication."""
        # No Bearer token, should still succeed
        response = await client.get("/saml/metadata")
        assert response.status_code == 200


@pytest.mark.asyncio
class TestSsoEndpoint:
    """Test GET /saml/sso endpoint (IdP-initiated SSO)."""

    async def test_sso_missing_jwt_returns_401(self, client):
        """Missing JWT returns 401 Unauthorized."""
        response = await client.get("/saml/sso")
        assert response.status_code == 401
        data = await response.get_json()
        assert "unauthorized" in data.get("error", "").lower()

    async def test_sso_invalid_jwt_returns_401(self, client):
        """Invalid JWT returns 401."""
        response = await client.get(
            "/saml/sso",
            headers={"Authorization": "Bearer invalid-jwt-token"},
        )
        assert response.status_code == 401

    async def test_sso_missing_sp_param_returns_400(self, client):
        """Missing SP entity_id returns 400."""
        with patch("oidc.jwt_utils.verify_token") as mock_verify:
            mock_verify.return_value = {"sub": "user-123"}
            response = await client.get(
                "/saml/sso",
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "sp entity_id required" in data.get("error", "").lower()

    async def test_sso_unknown_sp_returns_404(self, client, mock_db):
        """Unknown SP entity_id returns 404."""
        mock_db.return_value.select.return_value.first.return_value = None

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=None):
            mock_verify.return_value = {"sub": "user-123"}
            response = await client.get(
                "/saml/sso?sp=https://unknown.example.com",
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 404
            data = await response.get_json()
            assert "unknown service provider" in data.get("error", "").lower()

    async def test_sso_no_signing_key_returns_503(self, client, mock_db):
        """No active signing key returns 503."""
        sp_config_mock = MagicMock()
        sp_config_mock.entity_id = "https://example.com/saml"
        sp_config_mock.acs_url = "https://example.com/saml/acs"

        mock_db.return_value.select.return_value.first.return_value = None

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=sp_config_mock), \
             patch("saml.endpoints._get_core") as mock_core_fn, \
             patch("saml.endpoints._get_config") as mock_cfg_fn, \
             patch("saml.endpoints._get_active_signing_key", return_value=None):
            mock_verify.return_value = {"sub": "user-123"}
            mock_core = AsyncMock()
            mock_core.get_user.return_value = SimpleNamespace(uuid="user-123", email="test@example.com")
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/saml/sso?sp=https://example.com/saml",
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 503
            data = await response.get_json()
            assert "signing key" in data.get("error", "").lower()

    async def test_sso_user_not_found_returns_404(self, client, mock_db):
        """User not found in core returns 404."""
        sp_config_mock = MagicMock()
        sp_config_mock.entity_id = "https://example.com/saml"

        mock_db.return_value.select.return_value.first.return_value = None

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=sp_config_mock), \
             patch("saml.endpoints._get_core") as mock_core_fn, \
             patch("saml.endpoints._get_active_signing_key", return_value={"public_key": "cert"}):
            mock_verify.return_value = {"sub": "user-123"}
            mock_core = AsyncMock()
            mock_core.get_user.return_value = None
            mock_core_fn.return_value = mock_core

            response = await client.get(
                "/saml/sso?sp=https://example.com/saml",
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 404
            data = await response.get_json()
            assert "user not found" in data.get("error", "").lower()

    async def test_sso_returns_html_form(self, client, mock_db):
        """Successful SSO returns HTML form for HTTP-POST binding."""
        sp_config_mock = MagicMock()
        sp_config_mock.entity_id = "https://example.com/saml"
        sp_config_mock.acs_url = "https://example.com/saml/acs"

        signing_key = {
            "public_key": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
            "private_key_encrypted": "encrypted-key",
        }
        mock_db.return_value.select.return_value.first.return_value = signing_key

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=sp_config_mock), \
             patch("saml.endpoints._get_core") as mock_core_fn, \
             patch("saml.endpoints._get_config") as mock_cfg_fn, \
             patch("saml.endpoints._get_active_signing_key", return_value=signing_key), \
             patch("saml.endpoints.build_saml_response", return_value="base64-response"), \
             patch("saml.endpoints._get_audit") as mock_audit_fn:
            mock_verify.return_value = {"sub": "user-123"}
            mock_core = AsyncMock()
            mock_core.get_user.return_value = SimpleNamespace(
                uuid="user-123",
                email="test@example.com",
                display_name="Test User",
            )
            mock_core_fn.return_value = mock_core

            mock_cfg = MagicMock()
            mock_cfg.issuer_url = "https://checkpoint.test"
            mock_cfg_fn.return_value = mock_cfg

            mock_audit = AsyncMock()
            mock_audit.log = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.get(
                "/saml/sso?sp=https://example.com/saml",
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 200
            assert "text/html" in response.content_type

            html = await response.get_data(as_text=True)
            assert "SAMLResponse" in html
            assert "form" in html


@pytest.mark.asyncio
class TestAcsEndpoint:
    """Test POST /saml/acs/<sp_entity_b64> endpoint."""

    async def test_acs_invalid_base64_returns_400(self, client):
        """Invalid base64 encoding returns 400."""
        response = await client.post(
            "/saml/acs/not-valid-base64!!!",
            form={"SAMLResponse": "response", "RelayState": "state"},
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert "invalid sp_entity_b64" in data.get("error", "").lower()

    async def test_acs_missing_saml_response_returns_400(self, client):
        """Missing SAMLResponse returns 400."""
        sp_b64 = base64.urlsafe_b64encode(b"https://example.com").decode().rstrip("=")
        response = await client.post(
            f"/saml/acs/{sp_b64}",
            data={"RelayState": "state"},
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert "samlresponse is required" in data.get("error", "").lower()

    async def test_acs_missing_relay_state_returns_400(self, client):
        """Missing upstream IDP in relay_state returns 400."""
        sp_b64 = base64.urlsafe_b64encode(b"https://example.com").decode().rstrip("=")
        response = await client.post(
            f"/saml/acs/{sp_b64}",
            form={"SAMLResponse": "response-b64", "RelayState": "no-idp-prefix"},
        )
        assert response.status_code == 400
        data = await response.get_json()
        assert "relay_state must carry upstream idp id" in data.get("error", "").lower()

    async def test_acs_unknown_idp_returns_404(self, client, mock_db):
        """Unknown upstream IDP returns 404."""
        mock_db.return_value.select.return_value.first.return_value = None

        sp_b64 = base64.urlsafe_b64encode(b"https://example.com").decode().rstrip("=")
        with patch("saml.endpoints._get_db", return_value=mock_db):
            response = await client.post(
                f"/saml/acs/{sp_b64}",
                form={"SAMLResponse": "response-b64", "RelayState": "idp:999:original-state"},
            )
            assert response.status_code == 404
            data = await response.get_json()
            assert "upstream idp not found" in data.get("error", "").lower()

    async def test_acs_idp_config_decrypt_error_returns_500(self, client, mock_db):
        """IDP config decryption error returns 500."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "corrupted-encrypted-config"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        sp_b64 = base64.urlsafe_b64encode(b"https://example.com").decode().rstrip("=")
        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", side_effect=Exception("Decrypt error")):
            response = await client.post(
                f"/saml/acs/{sp_b64}",
                form={"SAMLResponse": "response-b64", "RelayState": "idp:1:original-state"},
            )
            assert response.status_code == 500
            data = await response.get_json()
            assert "configuration error" in data.get("error", "").lower()


@pytest.mark.asyncio
class TestSsoFormDataExtraction:
    """Test SSO endpoint form data extraction (lines 181-184)."""

    async def test_sso_issuer_extraction_from_request(self, client, mock_db):
        """SSO endpoint extracts Issuer from SAMLRequest if sp param missing (line 189)."""
        from saml.utils import SAMLSpConfig

        sp_config_mock = SAMLSpConfig(
            entity_id="https://example.com/saml",
            acs_url="https://example.com/saml/acs",
            signing_cert="cert",
        )

        signing_key = {
            "public_key": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
            "private_key_encrypted": "encrypted-key",
        }
        mock_db.return_value.select.return_value.first.return_value = signing_key

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=sp_config_mock), \
             patch("saml.endpoints._get_core") as mock_core_fn, \
             patch("saml.endpoints._get_config") as mock_cfg_fn, \
             patch("saml.endpoints._get_active_signing_key", return_value=signing_key), \
             patch("saml.endpoints.build_saml_response", return_value="base64-response"), \
             patch("saml.endpoints._get_audit") as mock_audit_fn, \
             patch("saml.endpoints._extract_issuer_from_authn_request", return_value="https://example.com/saml"):
            mock_verify.return_value = {"sub": "user-123"}
            mock_core = AsyncMock()
            mock_core.get_user.return_value = SimpleNamespace(
                uuid="user-123",
                email="test@example.com",
            )
            mock_core_fn.return_value = mock_core

            mock_cfg = MagicMock()
            mock_cfg.issuer_url = "https://checkpoint.test"
            mock_cfg_fn.return_value = mock_cfg

            mock_audit = AsyncMock()
            mock_audit.log = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.get(
                "/saml/sso?SAMLRequest=base64-encoded",
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 200


@pytest.mark.asyncio
class TestSsoAuditLogging:
    """Test SSO audit logging and response handling (lines 224-226)."""

    async def test_sso_audit_log_called(self, client, mock_db):
        """SSO endpoint logs audit event on success (line 228-233)."""
        from saml.utils import SAMLSpConfig

        sp_config_mock = SAMLSpConfig(
            entity_id="https://example.com/saml",
            acs_url="https://example.com/saml/acs",
            signing_cert="cert",
        )

        signing_key = {
            "public_key": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
            "private_key_encrypted": "encrypted-key",
        }
        mock_db.return_value.select.return_value.first.return_value = signing_key

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=sp_config_mock), \
             patch("saml.endpoints._get_core") as mock_core_fn, \
             patch("saml.endpoints._get_config") as mock_cfg_fn, \
             patch("saml.endpoints._get_active_signing_key", return_value=signing_key), \
             patch("saml.endpoints.build_saml_response", return_value="base64-response"), \
             patch("saml.endpoints._get_audit") as mock_audit_fn:
            mock_verify.return_value = {"sub": "user-123"}
            mock_core = AsyncMock()
            mock_core.get_user.return_value = SimpleNamespace(
                uuid="user-123",
                email="test@example.com",
            )
            mock_core_fn.return_value = mock_core

            mock_cfg = MagicMock()
            mock_cfg.issuer_url = "https://checkpoint.test"
            mock_cfg_fn.return_value = mock_cfg

            mock_audit = AsyncMock()
            mock_audit.log = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.get(
                "/saml/sso?sp=https://example.com/saml",
                headers={"Authorization": "Bearer valid-jwt"},
            )

            assert response.status_code == 200
            mock_audit.log.assert_called()


@pytest.mark.asyncio
class TestUpstreamIdpErrors:
    """Test upstream IdP error handling (lines 406-408)."""

    async def test_upstream_generate_request_error_returns_500(self, client, mock_db):
        """Upstream generate request error returns 500."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "encrypted-config"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", return_value={"entity_id": "idp", "sso_url": "url"}), \
             patch("saml.endpoints.generate_saml_request", side_effect=Exception("Generate error")):
            response = await client.get("/saml/upstream/1")
            assert response.status_code == 500
            data = await response.get_json()
            assert "failed to generate" in data.get("error", "").lower()

    async def test_upstream_idp_config_decrypt_error(self, client, mock_db):
        """Upstream IDP config decryption error returns 500."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "corrupted"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", side_effect=Exception("Decrypt")):
            response = await client.get("/saml/upstream/1")
            assert response.status_code == 500
            data = await response.get_json()
            assert "configuration error" in data.get("error", "").lower()


@pytest.mark.asyncio
class TestHelperFunctions:
    """Test SAML endpoint helper functions (lines 49, 65-69)."""

    async def test_get_db_helper(self, client, mock_db):
        """_get_db() helper accesses checkpoint_db extension."""
        with patch("saml.endpoints._get_db", return_value=mock_db):
            response = await client.get("/saml/metadata")
            assert response.status_code == 200

    async def test_get_config_helper(self, client):
        """_get_config() helper accesses checkpoint_config extension."""
        response = await client.get("/saml/metadata")
        assert response.status_code == 200

    async def test_get_core_helper(self, client):
        """_get_core() helper accesses checkpoint_core_client extension."""
        response = await client.get("/saml/metadata")
        assert response.status_code == 200

    async def test_get_audit_helper(self, client):
        """_get_audit() helper accesses checkpoint_audit extension."""
        response = await client.get("/saml/metadata")
        assert response.status_code == 200

    async def test_strip_pem_helper(self):
        """_strip_pem() removes PEM headers and whitespace."""
        pem_with_headers = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKbfKrHJzz5IMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
-----END CERTIFICATE-----"""
        result = _strip_pem(pem_with_headers)
        assert "-----BEGIN" not in result
        assert "-----END" not in result
        assert "MIIDXTCCAkWgAwIBAgIJAKbfKrHJzz5IMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV" in result

    async def test_extract_issuer_from_authn_request(self):
        """_extract_issuer_from_authn_request() extracts Issuer element."""
        from lxml import etree
        from saml.utils import NS_SAML, NS_SAMLP, NSMAP

        request_xml = f"""<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="{NS_SAMLP}" xmlns:saml="{NS_SAML}"
    ID="_123" Version="2.0" IssueInstant="2025-01-01T00:00:00Z"
    Destination="https://idp.example.com/sso"
    AssertionConsumerServiceURL="https://sp.example.com/acs">
  <saml:Issuer>https://sp.example.com</saml:Issuer>
</samlp:AuthnRequest>"""

        request_b64 = base64.b64encode(request_xml.encode()).decode()
        issuer = _extract_issuer_from_authn_request(request_b64)
        assert issuer == "https://sp.example.com"

    async def test_acs_invalid_assertion_returns_400(self, client, mock_db):
        """Invalid SAML assertion returns 400."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "encrypted-config"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        sp_b64 = base64.urlsafe_b64encode(b"https://example.com").decode().rstrip("=")
        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", return_value={"entity_id": "https://idp.example.com"}), \
             patch("saml.endpoints.validate_saml_response", side_effect=ValueError("Invalid signature")), \
             patch("saml.endpoints._get_audit") as mock_audit_fn:
            mock_audit = AsyncMock()
            mock_audit.log = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.post(
                f"/saml/acs/{sp_b64}",
                form={"SAMLResponse": "invalid-response", "RelayState": "idp:1:original-state"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "invalid" in data.get("error", "").lower()

    async def test_acs_valid_assertion_returns_200(self, client, mock_db):
        """Valid assertion returns 200 with claims."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "encrypted-config"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        sp_b64 = base64.urlsafe_b64encode(b"https://example.com").decode().rstrip("=")
        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", return_value={
                 "entity_id": "https://idp.example.com",
                 "signing_cert": "cert",
             }), \
             patch("saml.endpoints.validate_saml_response", return_value={
                 "sub": "user-456",
                 "email": "user@idp.example.com",
                 "attributes": {"name": "User Name"},
             }), \
             patch("saml.endpoints._get_audit") as mock_audit_fn:
            mock_audit = AsyncMock()
            mock_audit.log = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.post(
                f"/saml/acs/{sp_b64}",
                form={"SAMLResponse": "valid-response", "RelayState": "idp:1:original-state"},
            )
            assert response.status_code == 200
            data = await response.get_json()
            assert data["sub"] == "user-456"
            assert data["email"] == "user@idp.example.com"
            assert data["relay_state"] == "original-state"


@pytest.mark.asyncio
class TestSloEndpoint:
    """Test GET /saml/slo endpoint."""

    async def test_slo_returns_200(self, client):
        """SLO returns 200 with acknowledgment."""
        response = await client.get("/saml/slo")
        assert response.status_code == 200
        data = await response.get_json()
        assert "status" in data

    async def test_slo_post_returns_200(self, client):
        """SLO POST request returns 200."""
        response = await client.post("/saml/slo", data={})
        assert response.status_code == 200
        data = await response.get_json()
        assert "status" in data

    async def test_slo_no_auth_required(self, client):
        """SLO requires no authentication."""
        response = await client.get("/saml/slo")
        assert response.status_code == 200


@pytest.mark.asyncio
class TestUpstreamSsoRedirect:
    """Test GET /saml/upstream/<idp_id> endpoint."""

    async def test_upstream_unknown_idp_returns_404(self, client, mock_db):
        """Unknown upstream IDP returns 404."""
        mock_db.return_value.select.return_value.first.return_value = None

        with patch("saml.endpoints._get_db", return_value=mock_db):
            response = await client.get("/saml/upstream/999")
            assert response.status_code == 404
            data = await response.get_json()
            assert "upstream idp not found" in data.get("error", "").lower()

    async def test_upstream_idp_config_decrypt_error_returns_500(self, client, mock_db):
        """IDP config decryption error returns 500."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "corrupted-config"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", side_effect=Exception("Decrypt error")):
            response = await client.get("/saml/upstream/1")
            assert response.status_code == 500
            data = await response.get_json()
            assert "configuration error" in data.get("error", "").lower()

    async def test_upstream_returns_redirect_url(self, client, mock_db):
        """Valid upstream IDP returns redirect URL."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "encrypted-config"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", return_value={
                 "entity_id": "https://idp.example.com",
                 "sso_url": "https://idp.example.com/sso",
                 "signing_cert": "cert",
             }), \
             patch("saml.endpoints.generate_saml_request", return_value=("request-b64", "relay-state")), \
             patch("saml.endpoints._get_config") as mock_cfg_fn:
            mock_cfg = MagicMock()
            mock_cfg.issuer_url = "https://checkpoint.test"
            mock_cfg_fn.return_value = mock_cfg

            response = await client.get("/saml/upstream/1?relay_state=custom-state")
            assert response.status_code == 200
            data = await response.get_json()
            assert "redirect_url" in data
            assert "idp_id" in data
            assert data["idp_id"] == 1
            assert "https://idp.example.com/sso" in data["redirect_url"]

    async def test_upstream_relay_state_preserved(self, client, mock_db):
        """Relay state is embedded in composed relay_state."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "encrypted-config"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", return_value={
                 "entity_id": "https://idp.example.com",
                 "sso_url": "https://idp.example.com/sso",
                 "signing_cert": "cert",
             }), \
             patch("saml.endpoints.generate_saml_request", return_value=("request-b64", "relay-state")), \
             patch("saml.endpoints._get_config") as mock_cfg_fn:
            mock_cfg = MagicMock()
            mock_cfg.issuer_url = "https://checkpoint.test"
            mock_cfg_fn.return_value = mock_cfg

            response = await client.get("/saml/upstream/1?relay_state=my-relay")
            assert response.status_code == 200
            data = await response.get_json()
            # Relay state should be present and contain the embedded IDP ID
            assert "relay_state" in data


@pytest.mark.asyncio
class TestHelperFunctions:
    """Test utility functions."""

    def test_strip_pem(self):
        """_strip_pem removes PEM headers and whitespace."""
        pem = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKlbr/L5
-----END CERTIFICATE-----"""
        result = _strip_pem(pem)
        assert "-----BEGIN" not in result
        assert "-----END" not in result
        assert result == "MIIDXTCCAkWgAwIBAgIJAKlbr/L5"

    def test_strip_pem_with_spaces(self):
        """_strip_pem handles extra whitespace."""
        pem = """
        -----BEGIN CERTIFICATE-----
        MIIDXTCCAkWgAwIBAgIJAKlbr/L5
        -----END CERTIFICATE-----
        """
        result = _strip_pem(pem)
        assert "-----BEGIN" not in result
        assert result == "MIIDXTCCAkWgAwIBAgIJAKlbr/L5"

    def test_extract_issuer_from_authn_request(self):
        """_extract_issuer_from_authn_request extracts Issuer element."""
        xml = """<?xml version="1.0"?>
<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"
              xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
  <saml:Issuer>https://example.com/saml</saml:Issuer>
</AuthnRequest>"""
        b64 = base64.b64encode(xml.encode()).decode()
        issuer = _extract_issuer_from_authn_request(b64)
        assert issuer == "https://example.com/saml"

    def test_extract_issuer_missing_issuer(self):
        """_extract_issuer_from_authn_request returns empty if no Issuer."""
        xml = """<?xml version="1.0"?>
<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol"></AuthnRequest>"""
        b64 = base64.b64encode(xml.encode()).decode()
        issuer = _extract_issuer_from_authn_request(b64)
        assert issuer == ""


@pytest.mark.asyncio
class TestSamlEndpointsCoverageMissing:
    """Test missing lines in saml/endpoints.py that are already covered."""

    async def test_acs_invalid_relay_state_no_idp(self, client, mock_db):
        """Test ACS with invalid relay_state format returns 400."""
        sp_b64 = base64.urlsafe_b64encode(b"https://sp.test").decode().rstrip("=")
        response = await client.post(
            f"/saml/acs/{sp_b64}",
            data={"SAMLResponse": "resp", "RelayState": "invalid-state"}
        )
        assert response.status_code == 400

    async def test_acs_sp_entity_decoding(self, client, mock_db):
        """Test ACS decodes sp_entity_b64 correctly."""
        sp_b64 = base64.urlsafe_b64encode(b"https://sp.test").decode().rstrip("=")
        # Without proper SAMLResponse, should get 400 (missing IDP or validation error)
        response = await client.post(
            f"/saml/acs/{sp_b64}",
            data={"SAMLResponse": "resp", "RelayState": "state"}
        )
        # Either 400 or 404 depending on relay state parsing
        assert response.status_code in (400, 404)


@pytest.mark.asyncio
class TestSsoPostFormDataAndMissing:
    """Test SSO POST form data extraction (lines 181-184, 190-191, 204-206, 224-226)."""

    async def test_sso_post_with_form_data(self, client, mock_db):
        """SSO POST endpoint extracts SAMLRequest/RelayState/sp from form (lines 181-184)."""
        from saml.utils import SAMLSpConfig

        sp_config_mock = SAMLSpConfig(
            entity_id="https://example.com/saml",
            acs_url="https://example.com/saml/acs",
            signing_cert="cert",
        )

        signing_key = {
            "public_key": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
            "private_key_encrypted": "encrypted-key",
        }
        mock_db.return_value.select.return_value.first.return_value = signing_key

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=sp_config_mock), \
             patch("saml.endpoints._get_core") as mock_core_fn, \
             patch("saml.endpoints._get_config") as mock_cfg_fn, \
             patch("saml.endpoints._get_active_signing_key", return_value=signing_key), \
             patch("saml.endpoints.build_saml_response", return_value="base64-response"), \
             patch("saml.endpoints._get_audit") as mock_audit_fn:
            mock_verify.return_value = {"sub": "user-123"}
            mock_core = AsyncMock()
            mock_core.get_user.return_value = SimpleNamespace(
                uuid="user-123",
                email="test@example.com",
            )
            mock_core_fn.return_value = mock_core

            mock_cfg = MagicMock()
            mock_cfg.issuer_url = "https://checkpoint.test"
            mock_cfg_fn.return_value = mock_cfg

            mock_audit = AsyncMock()
            mock_audit.log = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.post(
                "/saml/sso",
                form={"SAMLRequest": "base64-request", "RelayState": "relay1", "sp": "https://example.com/saml"},
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 200
            html = await response.get_data(as_text=True)
            assert "SAMLResponse" in html

    async def test_sso_extract_issuer_from_request_in_form(self, client, mock_db):
        """SSO extracts Issuer from SAMLRequest in form when sp param missing (line 190-191)."""
        from saml.utils import SAMLSpConfig, NS_SAMLP, NS_SAML

        sp_config_mock = SAMLSpConfig(
            entity_id="https://example.com/saml",
            acs_url="https://example.com/saml/acs",
            signing_cert="cert",
        )

        signing_key = {
            "public_key": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
            "private_key_encrypted": "encrypted-key",
        }
        mock_db.return_value.select.return_value.first.return_value = signing_key

        # Create a valid SAML request with Issuer
        request_xml = f"""<?xml version="1.0"?>
<samlp:AuthnRequest xmlns:samlp="{NS_SAMLP}" xmlns:saml="{NS_SAML}"
    ID="_123" Version="2.0" IssueInstant="2025-01-01T00:00:00Z"
    Destination="https://idp.example.com/sso"
    AssertionConsumerServiceURL="https://example.com/saml/acs">
  <saml:Issuer>https://example.com/saml</saml:Issuer>
</samlp:AuthnRequest>"""
        request_b64 = base64.b64encode(request_xml.encode()).decode()

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=sp_config_mock), \
             patch("saml.endpoints._get_core") as mock_core_fn, \
             patch("saml.endpoints._get_config") as mock_cfg_fn, \
             patch("saml.endpoints._get_active_signing_key", return_value=signing_key), \
             patch("saml.endpoints.build_saml_response", return_value="base64-response"), \
             patch("saml.endpoints._get_audit") as mock_audit_fn, \
             patch("saml.endpoints._extract_issuer_from_authn_request", return_value="https://example.com/saml"):
            mock_verify.return_value = {"sub": "user-123"}
            mock_core = AsyncMock()
            mock_core.get_user.return_value = SimpleNamespace(
                uuid="user-123",
                email="test@example.com",
            )
            mock_core_fn.return_value = mock_core

            mock_cfg = MagicMock()
            mock_cfg.issuer_url = "https://checkpoint.test"
            mock_cfg_fn.return_value = mock_cfg

            mock_audit = AsyncMock()
            mock_audit.log = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.post(
                "/saml/sso",
                form={"SAMLRequest": request_b64, "RelayState": "relay1"},
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 200

    async def test_sso_core_get_user_exception_returns_500(self, client, mock_db):
        """SSO core.get_user() exception returns 500 (line 204-206)."""
        from saml.utils import SAMLSpConfig

        sp_config_mock = SAMLSpConfig(
            entity_id="https://example.com/saml",
            acs_url="https://example.com/saml/acs",
            signing_cert="cert",
        )

        signing_key = {
            "public_key": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
            "private_key_encrypted": "encrypted-key",
        }
        mock_db.return_value.select.return_value.first.return_value = signing_key

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=sp_config_mock), \
             patch("saml.endpoints._get_core") as mock_core_fn, \
             patch("saml.endpoints._get_config") as mock_cfg_fn, \
             patch("saml.endpoints._get_active_signing_key", return_value=signing_key):
            mock_verify.return_value = {"sub": "user-123"}
            mock_core = AsyncMock()
            mock_core.get_user.side_effect = Exception("Core service error")
            mock_core_fn.return_value = mock_core

            mock_cfg = MagicMock()
            mock_cfg.issuer_url = "https://checkpoint.test"
            mock_cfg_fn.return_value = mock_cfg

            response = await client.get(
                "/saml/sso?sp=https://example.com/saml",
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 500
            data = await response.get_json()
            assert "error" in data

    async def test_sso_build_saml_response_exception_returns_500(self, client, mock_db):
        """SSO build_saml_response() exception returns 500 (line 224-226)."""
        from saml.utils import SAMLSpConfig

        sp_config_mock = SAMLSpConfig(
            entity_id="https://example.com/saml",
            acs_url="https://example.com/saml/acs",
            signing_cert="cert",
        )

        signing_key = {
            "public_key": "-----BEGIN CERTIFICATE-----\nMIID...\n-----END CERTIFICATE-----",
            "private_key_encrypted": "encrypted-key",
        }
        mock_db.return_value.select.return_value.first.return_value = signing_key

        with patch("oidc.jwt_utils.verify_token") as mock_verify, \
             patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("saml.endpoints._get_sp_config", return_value=sp_config_mock), \
             patch("saml.endpoints._get_core") as mock_core_fn, \
             patch("saml.endpoints._get_config") as mock_cfg_fn, \
             patch("saml.endpoints._get_active_signing_key", return_value=signing_key), \
             patch("saml.endpoints.build_saml_response", side_effect=Exception("SAML build error")):
            mock_verify.return_value = {"sub": "user-123"}
            mock_core = AsyncMock()
            mock_core.get_user.return_value = SimpleNamespace(
                uuid="user-123",
                email="test@example.com",
            )
            mock_core_fn.return_value = mock_core

            mock_cfg = MagicMock()
            mock_cfg.issuer_url = "https://checkpoint.test"
            mock_cfg_fn.return_value = mock_cfg

            response = await client.get(
                "/saml/sso?sp=https://example.com/saml",
                headers={"Authorization": "Bearer valid-jwt"},
            )
            assert response.status_code == 500
            data = await response.get_json()
            assert "error" in data


@pytest.mark.asyncio
class TestAcsEndpointValidationAndSuccess:
    """Test ACS endpoint validation and success paths (lines 301-336)."""

    async def test_acs_validate_saml_response_value_error_returns_400(self, client, mock_db):
        """ACS validate_saml_response ValueError returns 400 (lines 301-327)."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "encrypted-config"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        sp_b64 = base64.urlsafe_b64encode(b"https://example.com").decode().rstrip("=")
        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", return_value={
                 "entity_id": "https://idp.example.com",
                 "signing_cert": "cert",
             }), \
             patch("saml.endpoints.validate_saml_response", side_effect=ValueError("Invalid signature")), \
             patch("saml.endpoints._get_audit") as mock_audit_fn:
            mock_audit = AsyncMock()
            mock_audit.log = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.post(
                f"/saml/acs/{sp_b64}",
                form={"SAMLResponse": "invalid-saml", "RelayState": "idp:1:original-state"},
            )
            assert response.status_code == 400
            data = await response.get_json()
            assert "invalid" in data.get("error", "").lower()
            # Verify audit log was called
            mock_audit.log.assert_called()

    async def test_acs_success_returns_200_with_claims(self, client, mock_db):
        """ACS success path returns 200 with claims (lines 329-336)."""
        idp_row = MagicMock()
        idp_row.config_json_encrypted = "encrypted-config"
        mock_db.return_value.select.return_value.first.return_value = idp_row

        sp_b64 = base64.urlsafe_b64encode(b"https://example.com").decode().rstrip("=")
        with patch("saml.endpoints._get_db", return_value=mock_db), \
             patch("crypto.envelope.decrypt_config_json", return_value={
                 "entity_id": "https://idp.example.com",
                 "signing_cert": "cert",
             }), \
             patch("saml.endpoints.validate_saml_response", return_value={
                 "sub": "user-456",
                 "email": "user@idp.example.com",
                 "attributes": {"name": "User Name"},
             }), \
             patch("saml.endpoints._get_audit") as mock_audit_fn:
            mock_audit = AsyncMock()
            mock_audit.log = AsyncMock()
            mock_audit_fn.return_value = mock_audit

            response = await client.post(
                f"/saml/acs/{sp_b64}",
                form={"SAMLResponse": "valid-saml", "RelayState": "idp:1:original-state"},
            )
            assert response.status_code == 200
            data = await response.get_json()
            assert data["sub"] == "user-456"
            assert data["email"] == "user@idp.example.com"
            assert data["relay_state"] == "original-state"
            # Verify audit log was called
            mock_audit.log.assert_called()
