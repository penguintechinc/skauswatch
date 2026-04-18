"""Unit tests for X.509 certificate API endpoints."""

from datetime import datetime, timedelta, timezone

import pytest


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cert_dict(cert_id="cert-001", serial="ABC123", status="active", revoked=False):
    now = _now()
    future = now + timedelta(days=365)
    d = {
        "id": cert_id,
        "serial_number": serial,
        "subject": "CN=test.example.com",
        "issuer": "CN=SkausWatch CA",
        "not_before": now,
        "not_after": future,
        "key_algorithm": "RSA",
        "key_size": 4096,
        "fingerprint_sha256": "sha256:aabbcc",
        "certificate_pem": "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
        "private_key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
        "san_dns": ["test.example.com"],
        "san_ip": [],
        "status": status,
        "revoked_at": now if revoked else None,
        "revocation_reason": "unspecified" if revoked else None,
        "created_at": now,
    }
    return d


_VALID_ISSUE_PAYLOAD = {
    "subject": "CN=test.example.com",
    "san_dns": ["test.example.com"],
}

_REVOKE_PAYLOAD = {"reason": "unspecified"}


# ===========================================================================
# Issue Certificate
# ===========================================================================
@pytest.mark.unit
class TestIssueCertificate:
    """POST /api/v1/certificates"""

    async def test_issue_certificate_success(self, client, mock_cert_manager):
        """201 response with certificate data on valid request."""
        resp = await client.post(
            "/api/v1/certificates",
            json=_VALID_ISSUE_PAYLOAD,
        )
        assert resp.status_code == 201
        data = await resp.get_json()
        assert data["id"] == "cert-001"
        assert data["serial_number"] == "ABC123"
        assert data["status"] == "active"
        mock_cert_manager.issue_x509_certificate.assert_awaited_once()

    async def test_issue_certificate_calls_manager_with_subject(
        self, client, mock_cert_manager
    ):
        """Verify subject is forwarded to cert_manager."""
        await client.post(
            "/api/v1/certificates",
            json={"subject": "CN=myhost.example.org"},
        )
        call_kwargs = mock_cert_manager.issue_x509_certificate.call_args
        assert call_kwargs.kwargs["subject"] == "CN=myhost.example.org"

    async def test_issue_certificate_missing_subject_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when mandatory 'subject' field is absent."""
        resp = await client.post(
            "/api/v1/certificates",
            json={"san_dns": ["example.com"]},
        )
        assert resp.status_code == 400

    async def test_issue_certificate_invalid_key_algorithm_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when key_algorithm is not a known enum value."""
        resp = await client.post(
            "/api/v1/certificates",
            json={"subject": "CN=test", "key_algorithm": "INVALID"},
        )
        assert resp.status_code == 400

    async def test_issue_certificate_no_cert_manager_returns_503(
        self, client, app
    ):
        """503 when cert_manager is not initialised."""
        app.config["cert_manager"] = None
        resp = await client.post(
            "/api/v1/certificates",
            json=_VALID_ISSUE_PAYLOAD,
        )
        assert resp.status_code == 503
        data = await resp.get_json()
        assert "not initialized" in data["error"]
        # Restore for other tests
        app.config["cert_manager"] = None

    async def test_issue_certificate_manager_exception_returns_500(
        self, client, mock_cert_manager
    ):
        """500 when the cert_manager raises an unexpected exception."""
        mock_cert_manager.issue_x509_certificate.side_effect = RuntimeError("DB down")
        resp = await client.post(
            "/api/v1/certificates",
            json=_VALID_ISSUE_PAYLOAD,
        )
        assert resp.status_code == 500
        # Reset
        mock_cert_manager.issue_x509_certificate.side_effect = None
        mock_cert_manager.issue_x509_certificate.return_value = _cert_dict()


# ===========================================================================
# Get Certificate by ID
# ===========================================================================
@pytest.mark.unit
class TestGetCertificate:
    """GET /api/v1/certificates/{cert_id}"""

    async def test_get_certificate_found(self, client, mock_cert_manager):
        """200 and certificate body when cert exists."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict()
        resp = await client.get("/api/v1/certificates/cert-001")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["id"] == "cert-001"
        assert data["serial_number"] == "ABC123"

    async def test_get_certificate_not_found(self, client, mock_cert_manager):
        """404 when cert_manager returns None."""
        mock_cert_manager.get_x509_certificate.return_value = None
        resp = await client.get("/api/v1/certificates/nonexistent")
        assert resp.status_code == 404
        data = await resp.get_json()
        assert "not found" in data["error"].lower()

    async def test_get_certificate_excludes_private_key_by_default(
        self, client, mock_cert_manager
    ):
        """Private key is stripped unless include_private_key=true query param."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict()
        resp = await client.get("/api/v1/certificates/cert-001")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "private_key_pem" not in data

    async def test_get_certificate_includes_private_key_when_requested(
        self, client, mock_cert_manager
    ):
        """Private key is included when include_private_key=true."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict()
        resp = await client.get(
            "/api/v1/certificates/cert-001?include_private_key=true"
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "private_key_pem" in data

    async def test_get_certificate_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager is absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/certificates/cert-001")
        assert resp.status_code == 503


# ===========================================================================
# Get Certificate by Serial
# ===========================================================================
@pytest.mark.unit
class TestGetCertificateBySerial:
    """GET /api/v1/certificates/serial/{serial_number}"""

    async def test_get_by_serial_found(self, client, mock_cert_manager):
        """200 and cert body when found by serial."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict(
            serial="DEAD01"
        )
        resp = await client.get("/api/v1/certificates/serial/DEAD01")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["serial_number"] == "DEAD01"

    async def test_get_by_serial_not_found(self, client, mock_cert_manager):
        """404 when serial not in database."""
        mock_cert_manager.get_x509_certificate.return_value = None
        resp = await client.get("/api/v1/certificates/serial/NOSUCH")
        assert resp.status_code == 404

    async def test_get_by_serial_private_key_stripped(
        self, client, mock_cert_manager
    ):
        """Private key is always stripped from serial-number lookups."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict()
        resp = await client.get("/api/v1/certificates/serial/ABC123")
        data = await resp.get_json()
        assert "private_key_pem" not in data

    async def test_get_by_serial_calls_manager_with_serial(
        self, client, mock_cert_manager
    ):
        """Verify the serial_number kwarg is passed to cert_manager."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict()
        await client.get("/api/v1/certificates/serial/XYZ999")
        call_kwargs = mock_cert_manager.get_x509_certificate.call_args
        assert call_kwargs.kwargs.get("serial_number") == "XYZ999"


# ===========================================================================
# List Certificates
# ===========================================================================
@pytest.mark.unit
class TestListCertificates:
    """GET /api/v1/certificates"""

    async def test_list_empty(self, client, mock_cert_manager):
        """Returns empty list with pagination envelope."""
        mock_cert_manager.list_x509_certificates.return_value = ([], 0)
        resp = await client.get("/api/v1/certificates")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["certificates"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    async def test_list_with_pagination_params(self, client, mock_cert_manager):
        """page and page_size query params forwarded to manager."""
        mock_cert_manager.list_x509_certificates.return_value = ([], 0)
        resp = await client.get("/api/v1/certificates?page=2&page_size=10")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["page"] == 2
        assert data["page_size"] == 10
        call_kwargs = mock_cert_manager.list_x509_certificates.call_args
        assert call_kwargs.kwargs.get("page") == 2
        assert call_kwargs.kwargs.get("page_size") == 10

    async def test_list_with_status_filter(self, client, mock_cert_manager):
        """status query param forwarded to manager."""
        mock_cert_manager.list_x509_certificates.return_value = ([], 0)
        await client.get("/api/v1/certificates?status=active")
        call_kwargs = mock_cert_manager.list_x509_certificates.call_args
        assert call_kwargs.kwargs.get("status") == "active"

    async def test_list_returns_certificates(self, client, mock_cert_manager):
        """Non-empty list is correctly wrapped in pagination envelope."""
        certs = [_cert_dict("cert-001"), _cert_dict("cert-002")]
        mock_cert_manager.list_x509_certificates.return_value = (certs, 2)
        resp = await client.get("/api/v1/certificates")
        data = await resp.get_json()
        assert data["total"] == 2
        assert len(data["certificates"]) == 2

    async def test_list_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/certificates")
        assert resp.status_code == 503


# ===========================================================================
# Revoke Certificate
# ===========================================================================
@pytest.mark.unit
class TestRevokeCertificate:
    """POST /api/v1/certificates/{cert_id}/revoke"""

    async def test_revoke_success(self, client, mock_cert_manager):
        """200 with revoked message when cert exists."""
        mock_cert_manager.revoke_x509_certificate.return_value = True
        resp = await client.post(
            "/api/v1/certificates/cert-001/revoke",
            json=_REVOKE_PAYLOAD,
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "revoked" in data["message"].lower()
        assert data["certificate_id"] == "cert-001"

    async def test_revoke_not_found_returns_404(self, client, mock_cert_manager):
        """404 when cert_manager returns False (cert not found)."""
        mock_cert_manager.revoke_x509_certificate.return_value = False
        resp = await client.post(
            "/api/v1/certificates/nonexistent/revoke",
            json=_REVOKE_PAYLOAD,
        )
        assert resp.status_code == 404

    async def test_revoke_invalid_reason_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when revocation reason is not a valid enum value."""
        resp = await client.post(
            "/api/v1/certificates/cert-001/revoke",
            json={"reason": "MADE_UP_REASON"},
        )
        assert resp.status_code == 400

    async def test_revoke_passes_reason_to_manager(
        self, client, mock_cert_manager
    ):
        """reason enum value is forwarded to cert_manager."""
        mock_cert_manager.revoke_x509_certificate.return_value = True
        await client.post(
            "/api/v1/certificates/cert-001/revoke",
            json={"reason": "key_compromise"},
        )
        call_kwargs = mock_cert_manager.revoke_x509_certificate.call_args
        assert call_kwargs.kwargs.get("reason") == "key_compromise"

    async def test_revoke_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.post(
            "/api/v1/certificates/cert-001/revoke",
            json=_REVOKE_PAYLOAD,
        )
        assert resp.status_code == 503


# ===========================================================================
# CRL
# ===========================================================================
@pytest.mark.unit
class TestGetCRL:
    """GET /api/v1/certificates/crl"""

    async def test_get_crl_json(self, client, mock_cert_manager):
        """200 JSON response with CRL data."""
        resp = await client.get("/api/v1/certificates/crl")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "crl_pem" in data
        assert "revoked_count" in data

    async def test_get_crl_pem_accept_header(self, client, mock_cert_manager):
        """application/pkix-crl Accept header returns raw PEM."""
        resp = await client.get(
            "/api/v1/certificates/crl",
            headers={"Accept": "application/pkix-crl"},
        )
        assert resp.status_code == 200
        assert resp.content_type == "application/pkix-crl"

    async def test_get_crl_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/certificates/crl")
        assert resp.status_code == 503


# ===========================================================================
# OCSP
# ===========================================================================
@pytest.mark.unit
class TestOCSPResponse:
    """POST /api/v1/certificates/ocsp"""

    async def test_ocsp_known_active_cert_returns_good(
        self, client, mock_cert_manager
    ):
        """OCSP returns 'good' for an active certificate."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict(
            status="active"
        )
        resp = await client.post(
            "/api/v1/certificates/ocsp",
            json={"serial_number": "ABC123"},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["serial_number"] == "ABC123"
        assert data["status"] == "good"

    async def test_ocsp_revoked_cert_returns_revoked(
        self, client, mock_cert_manager
    ):
        """OCSP returns 'revoked' for a revoked certificate."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict(
            status="revoked", revoked=True
        )
        resp = await client.post(
            "/api/v1/certificates/ocsp",
            json={"serial_number": "ABC123"},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["status"] == "revoked"

    async def test_ocsp_unknown_serial_returns_unknown(
        self, client, mock_cert_manager
    ):
        """OCSP returns 'unknown' when cert not in database."""
        mock_cert_manager.get_x509_certificate.return_value = None
        resp = await client.post(
            "/api/v1/certificates/ocsp",
            json={"serial_number": "NOSUCH"},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["status"] == "unknown"

    async def test_ocsp_missing_serial_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when serial_number is absent from request body."""
        resp = await client.post(
            "/api/v1/certificates/ocsp",
            json={},
        )
        assert resp.status_code == 400

    async def test_ocsp_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.post(
            "/api/v1/certificates/ocsp",
            json={"serial_number": "ABC123"},
        )
        assert resp.status_code == 503


# ===========================================================================
# CA Info
# ===========================================================================
@pytest.mark.unit
class TestCAInfo:
    """GET /api/v1/certificates/ca"""

    async def test_get_ca_info(self, client, mock_cert_manager):
        """200 with CA info including PEM certificate."""
        resp = await client.get("/api/v1/certificates/ca")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "subject" in data
        assert "ca_certificate_pem" in data

    async def test_get_ca_info_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/certificates/ca")
        assert resp.status_code == 503

    async def test_download_ca_certificate(self, client, mock_cert_manager):
        """GET /ca/certificate returns PEM with correct content-type."""
        resp = await client.get("/api/v1/certificates/ca/certificate")
        assert resp.status_code == 200
        assert resp.content_type == "application/x-pem-file"


# ===========================================================================
# Certificate Status
# ===========================================================================
@pytest.mark.unit
class TestCertificateStatus:
    """GET /api/v1/certificates/{cert_id}/status"""

    async def test_get_status_found(self, client, mock_cert_manager):
        """200 with status information for existing cert."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict()
        resp = await client.get("/api/v1/certificates/cert-001/status")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["certificate_id"] == "cert-001"
        assert data["status"] == "active"
        assert "is_expired" in data
        assert "not_before" in data
        assert "not_after" in data

    async def test_get_status_not_found(self, client, mock_cert_manager):
        """404 when cert does not exist."""
        mock_cert_manager.get_x509_certificate.return_value = None
        resp = await client.get("/api/v1/certificates/nosuch/status")
        assert resp.status_code == 404

    async def test_get_status_active_cert_not_expired(
        self, client, mock_cert_manager
    ):
        """is_expired is False for a cert with future expiry."""
        mock_cert_manager.get_x509_certificate.return_value = _cert_dict()
        resp = await client.get("/api/v1/certificates/cert-001/status")
        data = await resp.get_json()
        assert data["is_expired"] is False

    async def test_get_status_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/certificates/cert-001/status")
        assert resp.status_code == 503
