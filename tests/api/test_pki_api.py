"""PKI Server API tests. Tests X.509 and SSH certificate endpoints.

Uses an isolated Quart test client with a mocked CertificateManager so no
real CA keys or database connection is required.  All certificate operations
are handled by AsyncMock instances injected into app.config["cert_manager"].

URL layout (from the source):
    /healthz                              – liveness
    /readyz                               – readiness
    /version                              – version info
    /api/v1/certificates                  – X.509 CRUD & search
    /api/v1/certificates/crl              – CRL
    /api/v1/certificates/ocsp             – OCSP
    /api/v1/certificates/ca               – CA info
    /api/v1/certificates/ca/certificate   – CA cert download
    /api/v1/ssh/certificates              – SSH CRUD
    /api/v1/ssh/krl                       – SSH KRL
    /api/v1/ssh/ca                        – SSH CA info
    /api/v1/ssh/ca/public-key             – SSH CA public key
    /api/v1/ssh/config/known-hosts        – known_hosts generation
    /api/v1/ssh/config/authorized-keys    – authorized_keys generation
    /api/v1/ssh/verify                    – certificate verification
"""

import importlib.util
import os
import sys
from datetime import datetime, timedelta
from typing import Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = [pytest.mark.api, pytest.mark.asyncio]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PKI_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "services", "pki-server-new"
)


def _load_pki_main():
    """Import pki-server-new.main via importlib (directory name has hyphens)."""
    if _PKI_DIR not in sys.path:
        sys.path.insert(0, _PKI_DIR)

    spec = importlib.util.spec_from_file_location(
        "pki_server_new.main",
        os.path.join(_PKI_DIR, "main.py"),
    )
    main_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(main_module)
    return main_module


def _make_x509_cert(serial="AABBCC112233"):
    """Return a minimal X.509 certificate dict as the mock would return."""
    now = datetime.utcnow()
    return {
        "id": "cert-uuid-001",
        "serial_number": serial,
        "subject": "CN=test.example.com",
        "status": "active",
        "not_before": now,
        "not_after": now + timedelta(days=365),
        "revoked_at": None,
        "revocation_reason": None,
        "private_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nFAKE\n-----END RSA PRIVATE KEY-----",
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----",
    }


def _make_ssh_cert(serial=1001):
    """Return a minimal SSH certificate dict as the mock would return."""
    now = datetime.utcnow()
    return {
        "id": "ssh-cert-uuid-001",
        "serial_number": serial,
        "key_id": "user@host",
        "certificate_type": "user",
        "status": "active",
        "valid_after": now,
        "valid_before": now + timedelta(hours=24),
        "revoked_at": None,
        "revocation_reason": None,
        "certificate": "ssh-rsa-cert-v01@openssh.com AAAA...",
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def pki_app():
    """Create PKI test application with mocked CertificateManager.

    Returns a tuple of (app, mock_cert_manager) so individual tests can
    configure return values on the mock before making requests.
    """
    os.environ.setdefault("PKI_DB_TYPE", "sqlite")
    os.environ.setdefault("PKI_DB_NAME", ":memory:")
    os.environ.setdefault("PKI_X509_CA_CERT_PATH", "/tmp/test-ca.pem")
    os.environ.setdefault("PKI_X509_CA_KEY_PATH", "/tmp/test-ca-key.pem")

    with (
        patch("main.startup", new=AsyncMock()),
        patch("main.shutdown", new=AsyncMock()),
    ):
        main_module = _load_pki_main()

        with patch.object(main_module, "startup", new=AsyncMock()), patch.object(
            main_module, "shutdown", new=AsyncMock()
        ):
            app = main_module.create_app()

    app.config["TESTING"] = True

    # Build a comprehensive AsyncMock for cert_manager
    mock_cm = AsyncMock()

    # X.509 CA sub-object (accessed synchronously in the route)
    mock_x509_ca = MagicMock()
    mock_x509_ca.get_ca_info.return_value = {
        "subject": "CN=Test CA",
        "serial_number": "00",
        "not_before": datetime.utcnow().isoformat(),
        "not_after": (datetime.utcnow() + timedelta(days=3650)).isoformat(),
    }
    mock_x509_ca.get_ca_certificate_pem.return_value = (
        "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----"
    )
    mock_cm.x509_ca = mock_x509_ca

    # SSH CA sub-object (accessed synchronously in the route)
    mock_ssh_ca = MagicMock()
    mock_ssh_ca.get_ca_info.return_value = {
        "public_key": "ssh-ed25519 AAAA...",
        "key_type": "ed25519",
    }
    mock_ssh_ca.get_ca_public_key.return_value = "ssh-ed25519 AAAA... comment"
    mock_ssh_ca.generate_known_hosts_entry.return_value = (
        "@cert-authority *.example.com ssh-ed25519 AAAA..."
    )
    mock_ssh_ca.generate_authorized_keys_entry.return_value = (
        'cert-authority,principals="alice,bob" ssh-ed25519 AAAA...'
    )
    mock_ssh_ca.generate_ssh_config.return_value = (
        "Host example.com\n  CertificateFile ~/.ssh/id_ed25519-cert.pub\n"
    )
    mock_ssh_ca.check_certificate = AsyncMock(
        return_value={
            "serial": 1001,
            "key_id": "user@host",
            "valid": True,
            "status": "active",
        }
    )
    mock_cm.ssh_ca = mock_ssh_ca

    # Default return values for async cert operations
    mock_cm.issue_x509_certificate.return_value = _make_x509_cert()
    mock_cm.get_x509_certificate.return_value = _make_x509_cert()
    mock_cm.list_x509_certificates.return_value = ([_make_x509_cert()], 1)
    mock_cm.revoke_x509_certificate.return_value = True
    mock_cm.generate_x509_crl.return_value = {
        "crl_pem": "-----BEGIN X509 CRL-----\nFAKE\n-----END X509 CRL-----",
        "revoked_count": 0,
        "this_update": datetime.utcnow().isoformat(),
        "next_update": (datetime.utcnow() + timedelta(days=7)).isoformat(),
    }

    mock_cm.issue_ssh_certificate.return_value = _make_ssh_cert()
    mock_cm.get_ssh_certificate.return_value = _make_ssh_cert()
    mock_cm.list_ssh_certificates.return_value = ([_make_ssh_cert()], 1)
    mock_cm.revoke_ssh_certificate.return_value = True
    mock_cm.generate_ssh_krl.return_value = {
        "krl_binary": "AAAA",
        "revoked_count": 0,
        "updated_at": datetime.utcnow().isoformat(),
    }

    app.config["cert_manager"] = mock_cm
    return app, mock_cm


@pytest.fixture
def pki_client(pki_app):
    """Quart test client connected to the PKI app."""
    app, mock_cm = pki_app
    return app.test_client(), mock_cm


# ---------------------------------------------------------------------------
# TestPKIHealth
# ---------------------------------------------------------------------------


@pytest.mark.api
class TestPKIHealth:
    """Health and metadata endpoints (no authentication required)."""

    async def test_healthz_returns_200(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/healthz")
        assert resp.status_code == 200

    async def test_healthz_response_format(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/healthz")
        data = await resp.get_json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    async def test_version_returns_200(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/version")
        assert resp.status_code == 200

    async def test_version_response_format(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/version")
        data = await resp.get_json()
        assert "version" in data
        assert "app_name" in data
        assert "environment" in data

    async def test_readyz_returns_status(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/readyz")
        # May be 200 or 503 depending on global state – just check it responds
        assert resp.status_code in (200, 503)
        data = await resp.get_json()
        assert "status" in data
        assert "checks" in data

    async def test_health_detail_endpoint(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "status" in data
        assert "components" in data


# ---------------------------------------------------------------------------
# TestX509API
# ---------------------------------------------------------------------------


@pytest.mark.api
class TestX509API:
    """X.509 certificate management endpoints."""

    # --- Issue certificate ---

    async def test_issue_certificate_success(self, pki_client):
        client, mock_cm = pki_client
        payload = {
            "subject": "CN=server.example.com,O=Example Inc",
            "key_algorithm": "RSA",
            "key_size": 4096,
            "validity_days": 365,
            "san_dns": ["server.example.com"],
            "san_ip": [],
            "san_email": [],
            "key_usage": ["digital_signature", "key_encipherment"],
            "extended_key_usage": ["server_auth"],
            "is_ca": False,
        }
        mock_cm.issue_x509_certificate.return_value = _make_x509_cert("FFEE112233")
        resp = await client.post(
            "/api/v1/certificates",
            json=payload,
        )
        assert resp.status_code == 201
        data = await resp.get_json()
        assert "serial_number" in data

    async def test_issue_certificate_no_cert_manager(self, pki_app):
        app, _ = pki_app
        app.config["cert_manager"] = None
        async with app.test_client() as client:
            payload = {
                "subject": "CN=test",
                "key_algorithm": "RSA",
                "key_size": 2048,
                "validity_days": 90,
                "san_dns": [],
                "san_ip": [],
                "san_email": [],
                "key_usage": ["digital_signature"],
                "extended_key_usage": [],
                "is_ca": False,
            }
            resp = await client.post("/api/v1/certificates", json=payload)
            assert resp.status_code == 503

    async def test_issue_certificate_invalid_payload(self, pki_client):
        client, _ = pki_client
        # Missing required fields
        resp = await client.post("/api/v1/certificates", json={"subject": "CN=bad"})
        assert resp.status_code == 400

    # --- List certificates ---

    async def test_list_certificates_returns_200(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.list_x509_certificates.return_value = ([_make_x509_cert()], 1)
        resp = await client.get("/api/v1/certificates")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "certificates" in data
        assert "total" in data
        assert "page" in data
        assert "page_size" in data

    async def test_list_certificates_pagination(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.list_x509_certificates.return_value = ([], 0)
        resp = await client.get("/api/v1/certificates?page=2&page_size=10")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["page"] == 2
        assert data["page_size"] == 10

    async def test_list_certificates_status_filter(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.list_x509_certificates.return_value = ([], 0)
        resp = await client.get("/api/v1/certificates?status=revoked")
        assert resp.status_code == 200
        # Confirm the mock was called with the status filter
        call_kwargs = mock_cm.list_x509_certificates.call_args.kwargs
        assert call_kwargs.get("status") == "revoked"

    # --- Get certificate by serial ---

    async def test_get_cert_by_serial_found(self, pki_client):
        client, mock_cm = pki_client
        cert = _make_x509_cert("DEADBEEF")
        mock_cm.get_x509_certificate.return_value = cert
        resp = await client.get("/api/v1/certificates/serial/DEADBEEF")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["serial_number"] == "DEADBEEF"
        # Private key must be stripped from the response
        assert "private_key_pem" not in data

    async def test_get_cert_by_serial_not_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_x509_certificate.return_value = None
        resp = await client.get("/api/v1/certificates/serial/NOTEXIST")
        assert resp.status_code == 404

    # --- Get certificate by ID ---

    async def test_get_cert_by_id_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_x509_certificate.return_value = _make_x509_cert()
        resp = await client.get("/api/v1/certificates/cert-uuid-001")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "serial_number" in data

    async def test_get_cert_private_key_excluded_by_default(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_x509_certificate.return_value = _make_x509_cert()
        resp = await client.get("/api/v1/certificates/cert-uuid-001")
        data = await resp.get_json()
        assert "private_key_pem" not in data

    async def test_get_cert_private_key_included_when_requested(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_x509_certificate.return_value = _make_x509_cert()
        resp = await client.get(
            "/api/v1/certificates/cert-uuid-001?include_private_key=true"
        )
        data = await resp.get_json()
        assert "private_key_pem" in data

    async def test_get_cert_by_id_not_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_x509_certificate.return_value = None
        resp = await client.get("/api/v1/certificates/nonexistent-id")
        assert resp.status_code == 404

    # --- Revoke certificate ---

    async def test_revoke_certificate_success(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.revoke_x509_certificate.return_value = True
        resp = await client.post(
            "/api/v1/certificates/cert-uuid-001/revoke",
            json={"reason": "key_compromise"},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "message" in data
        assert "certificate_id" in data

    async def test_revoke_certificate_not_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.revoke_x509_certificate.return_value = False
        resp = await client.post(
            "/api/v1/certificates/cert-uuid-999/revoke",
            json={"reason": "unspecified"},
        )
        assert resp.status_code == 404

    async def test_revoke_certificate_invalid_reason(self, pki_client):
        client, _ = pki_client
        resp = await client.post(
            "/api/v1/certificates/cert-uuid-001/revoke",
            json={"reason": "not_a_valid_reason"},
        )
        assert resp.status_code == 400

    # --- CRL ---

    async def test_get_crl_json_format(self, pki_client):
        client, mock_cm = pki_client
        resp = await client.get("/api/v1/certificates/crl")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "crl_pem" in data

    async def test_get_crl_pem_format(self, pki_client):
        client, mock_cm = pki_client
        resp = await client.get(
            "/api/v1/certificates/crl",
            headers={"Accept": "application/pkix-crl"},
        )
        assert resp.status_code == 200
        assert resp.content_type == "application/pkix-crl"

    async def test_get_crl_no_cert_manager(self, pki_app):
        app, _ = pki_app
        app.config["cert_manager"] = None
        async with app.test_client() as client:
            resp = await client.get("/api/v1/certificates/crl")
            assert resp.status_code == 503

    # --- OCSP ---

    async def test_ocsp_good_certificate(self, pki_client):
        client, mock_cm = pki_client
        cert = _make_x509_cert("AABB0011")
        cert["status"] = "active"
        mock_cm.get_x509_certificate.return_value = cert
        resp = await client.post(
            "/api/v1/certificates/ocsp",
            json={"serial_number": "AABB0011"},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["status"] == "good"
        assert data["serial_number"] == "AABB0011"

    async def test_ocsp_revoked_certificate(self, pki_client):
        client, mock_cm = pki_client
        cert = _make_x509_cert("AABB0022")
        cert["status"] = "revoked"
        cert["revoked_at"] = datetime.utcnow()
        cert["revocation_reason"] = "key_compromise"
        mock_cm.get_x509_certificate.return_value = cert
        resp = await client.post(
            "/api/v1/certificates/ocsp",
            json={"serial_number": "AABB0022"},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["status"] == "revoked"

    async def test_ocsp_unknown_certificate(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_x509_certificate.return_value = None
        resp = await client.post(
            "/api/v1/certificates/ocsp",
            json={"serial_number": "UNKNOWN"},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["status"] == "unknown"

    async def test_ocsp_missing_serial_number(self, pki_client):
        client, _ = pki_client
        resp = await client.post("/api/v1/certificates/ocsp", json={})
        assert resp.status_code == 400

    # --- CA info ---

    async def test_get_ca_info_returns_200(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/api/v1/certificates/ca")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "subject" in data

    async def test_get_ca_certificate_download(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/api/v1/certificates/ca/certificate")
        assert resp.status_code == 200
        assert resp.content_type == "application/x-pem-file"

    async def test_get_ca_info_no_cert_manager(self, pki_app):
        app, _ = pki_app
        app.config["cert_manager"] = None
        async with app.test_client() as client:
            resp = await client.get("/api/v1/certificates/ca")
            assert resp.status_code == 503


# ---------------------------------------------------------------------------
# TestSSHAPI
# ---------------------------------------------------------------------------


@pytest.mark.api
class TestSSHAPI:
    """SSH certificate management endpoints."""

    # --- Issue SSH certificate ---

    async def test_issue_ssh_certificate_success(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.issue_ssh_certificate.return_value = _make_ssh_cert(2001)
        payload = {
            "public_key": "ssh-ed25519 AAAA... user@host",
            "certificate_type": "user",
            "key_id": "alice@jumphost",
            "principals": ["alice", "devs"],
            "validity_seconds": 86400,
            "extensions": {"permit-pty": ""},
            "critical_options": {},
        }
        resp = await client.post("/api/v1/ssh/certificates", json=payload)
        assert resp.status_code == 201
        data = await resp.get_json()
        assert "serial_number" in data

    async def test_issue_ssh_certificate_no_cert_manager(self, pki_app):
        app, _ = pki_app
        app.config["cert_manager"] = None
        async with app.test_client() as client:
            payload = {
                "public_key": "ssh-ed25519 AAAA...",
                "certificate_type": "user",
                "key_id": "test",
                "principals": ["test"],
                "validity_seconds": 3600,
                "extensions": {},
                "critical_options": {},
            }
            resp = await client.post("/api/v1/ssh/certificates", json=payload)
            assert resp.status_code == 503

    async def test_issue_ssh_certificate_invalid_payload(self, pki_client):
        client, _ = pki_client
        # Missing required fields
        resp = await client.post(
            "/api/v1/ssh/certificates",
            json={"public_key": "ssh-ed25519 AAAA..."},
        )
        assert resp.status_code == 400

    # --- List SSH certificates ---

    async def test_list_ssh_certificates_returns_200(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.list_ssh_certificates.return_value = ([_make_ssh_cert()], 1)
        resp = await client.get("/api/v1/ssh/certificates")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "certificates" in data
        assert "total" in data

    async def test_list_ssh_certificates_type_filter(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.list_ssh_certificates.return_value = ([], 0)
        resp = await client.get("/api/v1/ssh/certificates?type=host")
        assert resp.status_code == 200
        call_kwargs = mock_cm.list_ssh_certificates.call_args.kwargs
        assert call_kwargs.get("certificate_type") == "host"

    async def test_list_ssh_certificates_principal_filter(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.list_ssh_certificates.return_value = ([], 0)
        resp = await client.get("/api/v1/ssh/certificates?principal=alice")
        assert resp.status_code == 200

    # --- Get SSH certificate by serial ---

    async def test_get_ssh_cert_by_serial_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_ssh_certificate.return_value = _make_ssh_cert(3001)
        resp = await client.get("/api/v1/ssh/certificates/serial/3001")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["serial_number"] == 3001

    async def test_get_ssh_cert_by_serial_not_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_ssh_certificate.return_value = None
        resp = await client.get("/api/v1/ssh/certificates/serial/9999")
        assert resp.status_code == 404

    # --- Get SSH certificate by ID ---

    async def test_get_ssh_cert_by_id_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_ssh_certificate.return_value = _make_ssh_cert()
        resp = await client.get("/api/v1/ssh/certificates/ssh-cert-uuid-001")
        assert resp.status_code == 200

    async def test_get_ssh_cert_by_id_not_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_ssh_certificate.return_value = None
        resp = await client.get("/api/v1/ssh/certificates/no-such-id")
        assert resp.status_code == 404

    # --- Revoke SSH certificate ---

    async def test_revoke_ssh_certificate_success(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.revoke_ssh_certificate.return_value = True
        resp = await client.post(
            "/api/v1/ssh/certificates/ssh-cert-uuid-001/revoke",
            json={"reason": "key_compromise"},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "message" in data

    async def test_revoke_ssh_certificate_not_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.revoke_ssh_certificate.return_value = False
        resp = await client.post(
            "/api/v1/ssh/certificates/nonexistent-uuid/revoke",
            json={"reason": "unspecified"},
        )
        assert resp.status_code == 404

    # --- KRL ---

    async def test_get_krl_json_format(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/api/v1/ssh/krl")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "krl_binary" in data

    async def test_get_krl_no_cert_manager(self, pki_app):
        app, _ = pki_app
        app.config["cert_manager"] = None
        async with app.test_client() as client:
            resp = await client.get("/api/v1/ssh/krl")
            assert resp.status_code == 503

    # --- SSH CA public key ---

    async def test_get_ssh_ca_public_key_json(self, pki_client):
        client, _ = pki_client
        resp = await client.get("/api/v1/ssh/ca/public-key")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "ca_public_key" in data

    async def test_get_ssh_ca_public_key_text_plain(self, pki_client):
        client, _ = pki_client
        resp = await client.get(
            "/api/v1/ssh/ca/public-key",
            headers={"Accept": "text/plain"},
        )
        assert resp.status_code == 200
        assert "text/plain" in resp.content_type

    # --- known-hosts generation ---

    async def test_generate_known_hosts(self, pki_client):
        client, mock_cm = pki_client
        resp = await client.post(
            "/api/v1/ssh/config/known-hosts",
            json={"hostnames": ["*.example.com", "bastion.example.com"]},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "known_hosts" in data
        assert "hostnames" in data

    async def test_generate_known_hosts_missing_hostnames(self, pki_client):
        client, _ = pki_client
        resp = await client.post(
            "/api/v1/ssh/config/known-hosts",
            json={"hostnames": []},
        )
        assert resp.status_code == 400

    # --- authorized-keys generation ---

    async def test_generate_authorized_keys(self, pki_client):
        client, _ = pki_client
        resp = await client.post(
            "/api/v1/ssh/config/authorized-keys",
            json={"principals": ["alice", "bob"], "options": ""},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "authorized_keys" in data
        assert "trustedUserCAKeys" in data

    # --- SSH certificate status ---

    async def test_get_ssh_cert_status_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_ssh_certificate.return_value = _make_ssh_cert()
        resp = await client.get(
            "/api/v1/ssh/certificates/ssh-cert-uuid-001/status"
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "status" in data
        assert "serial_number" in data
        assert "is_expired" in data

    async def test_get_ssh_cert_status_not_found(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_ssh_certificate.return_value = None
        resp = await client.get(
            "/api/v1/ssh/certificates/nonexistent-id/status"
        )
        assert resp.status_code == 404

    # --- SSH certificate verification ---

    async def test_verify_ssh_certificate_valid(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.get_ssh_certificate.return_value = _make_ssh_cert()
        resp = await client.post(
            "/api/v1/ssh/verify",
            json={"certificate": "ssh-rsa-cert-v01@openssh.com AAAA..."},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "valid" in data or "status" in data

    async def test_verify_ssh_certificate_missing_cert(self, pki_client):
        client, _ = pki_client
        resp = await client.post("/api/v1/ssh/verify", json={})
        assert resp.status_code == 400

    async def test_verify_ssh_certificate_invalid(self, pki_client):
        client, mock_cm = pki_client
        mock_cm.ssh_ca.check_certificate = AsyncMock(
            side_effect=ValueError("Invalid certificate format")
        )
        resp = await client.post(
            "/api/v1/ssh/verify",
            json={"certificate": "garbage-data"},
        )
        assert resp.status_code == 400
        data = await resp.get_json()
        assert "error" in data

    async def test_verify_ssh_certificate_no_cert_manager(self, pki_app):
        app, _ = pki_app
        app.config["cert_manager"] = None
        async with app.test_client() as client:
            resp = await client.post(
                "/api/v1/ssh/verify",
                json={"certificate": "ssh-rsa-cert-v01@openssh.com AAAA..."},
            )
            assert resp.status_code == 503
