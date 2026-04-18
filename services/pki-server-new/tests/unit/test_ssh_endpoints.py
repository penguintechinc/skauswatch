"""Unit tests for SSH certificate API endpoints."""

from datetime import datetime, timedelta, timezone

import pytest


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Minimal valid SSH public key prefix accepted by SSHCertificateRequest
_PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb test-key"


def _ssh_cert_dict(
    cert_id="ssh-cert-001",
    serial="1000001",
    status="active",
    revoked=False,
):
    now = _now()
    future = now + timedelta(hours=24)
    return {
        "id": cert_id,
        "serial_number": serial,
        "key_id": "user-test",
        "certificate_type": "user",
        "principals": ["testuser"],
        "valid_after": now,
        "valid_before": future,
        "key_type": "ssh-ed25519",
        "signed_certificate": "ssh-rsa-cert-v01@openssh.com AAAA...",
        "ca_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
        "status": status,
        "revoked_at": now if revoked else None,
        "revocation_reason": "unspecified" if revoked else None,
        "created_at": now,
    }


_VALID_SSH_ISSUE_PAYLOAD = {
    "public_key": _PUBKEY,
    "key_id": "user-test",
    "principals": ["testuser"],
    "certificate_type": "user",
}

_REVOKE_PAYLOAD = {"reason": "unspecified"}


# ===========================================================================
# Issue SSH Certificate
# ===========================================================================
@pytest.mark.unit
class TestIssueSSHCertificate:
    """POST /api/v1/ssh/certificates"""

    async def test_issue_ssh_certificate_success(self, client, mock_cert_manager):
        """201 response with certificate data on valid request."""
        resp = await client.post(
            "/api/v1/ssh/certificates",
            json=_VALID_SSH_ISSUE_PAYLOAD,
        )
        assert resp.status_code == 201
        data = await resp.get_json()
        assert data["id"] == "ssh-cert-001"
        assert data["serial_number"] == "1000001"
        assert data["status"] == "active"
        mock_cert_manager.issue_ssh_certificate.assert_awaited_once()

    async def test_issue_ssh_certificate_missing_public_key_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when mandatory 'public_key' field is absent."""
        resp = await client.post(
            "/api/v1/ssh/certificates",
            json={"key_id": "x", "principals": ["user"]},
        )
        assert resp.status_code == 400

    async def test_issue_ssh_certificate_missing_key_id_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when mandatory 'key_id' field is absent."""
        resp = await client.post(
            "/api/v1/ssh/certificates",
            json={"public_key": _PUBKEY, "principals": ["user"]},
        )
        assert resp.status_code == 400

    async def test_issue_ssh_certificate_missing_principals_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when 'principals' list is absent."""
        resp = await client.post(
            "/api/v1/ssh/certificates",
            json={"public_key": _PUBKEY, "key_id": "x"},
        )
        assert resp.status_code == 400

    async def test_issue_ssh_certificate_invalid_public_key_format_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when public_key does not start with a known SSH key type prefix."""
        resp = await client.post(
            "/api/v1/ssh/certificates",
            json={
                "public_key": "not-a-real-key AAAA...",
                "key_id": "x",
                "principals": ["user"],
            },
        )
        assert resp.status_code == 400

    async def test_issue_ssh_certificate_no_cert_manager_returns_503(
        self, client, app
    ):
        """503 when cert_manager is not initialised."""
        app.config["cert_manager"] = None
        resp = await client.post(
            "/api/v1/ssh/certificates",
            json=_VALID_SSH_ISSUE_PAYLOAD,
        )
        assert resp.status_code == 503

    async def test_issue_ssh_certificate_manager_exception_returns_500(
        self, client, mock_cert_manager
    ):
        """500 when the cert_manager raises an unexpected exception."""
        mock_cert_manager.issue_ssh_certificate.side_effect = RuntimeError("CA error")
        resp = await client.post(
            "/api/v1/ssh/certificates",
            json=_VALID_SSH_ISSUE_PAYLOAD,
        )
        assert resp.status_code == 500
        # Reset side effect
        mock_cert_manager.issue_ssh_certificate.side_effect = None
        mock_cert_manager.issue_ssh_certificate.return_value = _ssh_cert_dict()

    async def test_issue_ssh_certificate_host_type_requires_hostname(
        self, client, mock_cert_manager
    ):
        """400 when certificate_type='host' but hostname is not provided."""
        resp = await client.post(
            "/api/v1/ssh/certificates",
            json={
                "public_key": _PUBKEY,
                "key_id": "host-myserver",
                "principals": ["myserver"],
                "certificate_type": "host",
                # hostname intentionally omitted
            },
        )
        assert resp.status_code == 400


# ===========================================================================
# Get SSH Certificate by ID
# ===========================================================================
@pytest.mark.unit
class TestGetSSHCertificate:
    """GET /api/v1/ssh/certificates/{cert_id}"""

    async def test_get_found(self, client, mock_cert_manager):
        """200 and certificate body when cert exists."""
        mock_cert_manager.get_ssh_certificate.return_value = _ssh_cert_dict()
        resp = await client.get("/api/v1/ssh/certificates/ssh-cert-001")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["id"] == "ssh-cert-001"
        assert data["key_id"] == "user-test"

    async def test_get_not_found(self, client, mock_cert_manager):
        """404 when cert_manager returns None."""
        mock_cert_manager.get_ssh_certificate.return_value = None
        resp = await client.get("/api/v1/ssh/certificates/nosuch")
        assert resp.status_code == 404
        data = await resp.get_json()
        assert "not found" in data["error"].lower()

    async def test_get_calls_manager_with_cert_id(
        self, client, mock_cert_manager
    ):
        """cert_id URL segment is forwarded to cert_manager."""
        mock_cert_manager.get_ssh_certificate.return_value = _ssh_cert_dict()
        await client.get("/api/v1/ssh/certificates/specific-id")
        call_kwargs = mock_cert_manager.get_ssh_certificate.call_args
        assert call_kwargs.kwargs.get("cert_id") == "specific-id"

    async def test_get_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/ssh/certificates/cert-001")
        assert resp.status_code == 503


# ===========================================================================
# List SSH Certificates
# ===========================================================================
@pytest.mark.unit
class TestListSSHCertificates:
    """GET /api/v1/ssh/certificates"""

    async def test_list_empty(self, client, mock_cert_manager):
        """Returns empty list with pagination envelope."""
        mock_cert_manager.list_ssh_certificates.return_value = ([], 0)
        resp = await client.get("/api/v1/ssh/certificates")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["certificates"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    async def test_list_with_pagination_params(self, client, mock_cert_manager):
        """page and page_size forwarded to manager."""
        mock_cert_manager.list_ssh_certificates.return_value = ([], 0)
        resp = await client.get("/api/v1/ssh/certificates?page=3&page_size=5")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["page"] == 3
        assert data["page_size"] == 5

    async def test_list_with_type_filter(self, client, mock_cert_manager):
        """type query param forwarded to manager."""
        mock_cert_manager.list_ssh_certificates.return_value = ([], 0)
        await client.get("/api/v1/ssh/certificates?type=user")
        call_kwargs = mock_cert_manager.list_ssh_certificates.call_args
        assert call_kwargs.kwargs.get("certificate_type") == "user"

    async def test_list_returns_certs(self, client, mock_cert_manager):
        """Non-empty list is correctly wrapped in pagination envelope."""
        certs = [_ssh_cert_dict("ssh-cert-001"), _ssh_cert_dict("ssh-cert-002")]
        mock_cert_manager.list_ssh_certificates.return_value = (certs, 2)
        resp = await client.get("/api/v1/ssh/certificates")
        data = await resp.get_json()
        assert data["total"] == 2
        assert len(data["certificates"]) == 2

    async def test_list_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/ssh/certificates")
        assert resp.status_code == 503


# ===========================================================================
# Revoke SSH Certificate
# ===========================================================================
@pytest.mark.unit
class TestRevokeSSHCertificate:
    """POST /api/v1/ssh/certificates/{cert_id}/revoke"""

    async def test_revoke_success(self, client, mock_cert_manager):
        """200 with revoked message when cert exists."""
        mock_cert_manager.revoke_ssh_certificate.return_value = True
        resp = await client.post(
            "/api/v1/ssh/certificates/ssh-cert-001/revoke",
            json=_REVOKE_PAYLOAD,
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "revoked" in data["message"].lower()
        assert data["certificate_id"] == "ssh-cert-001"

    async def test_revoke_not_found_returns_404(self, client, mock_cert_manager):
        """404 when cert_manager returns False."""
        mock_cert_manager.revoke_ssh_certificate.return_value = False
        resp = await client.post(
            "/api/v1/ssh/certificates/nosuch/revoke",
            json=_REVOKE_PAYLOAD,
        )
        assert resp.status_code == 404

    async def test_revoke_invalid_reason_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when revocation reason is not a valid enum value."""
        resp = await client.post(
            "/api/v1/ssh/certificates/ssh-cert-001/revoke",
            json={"reason": "INVENTED_REASON"},
        )
        assert resp.status_code == 400

    async def test_revoke_passes_reason_to_manager(
        self, client, mock_cert_manager
    ):
        """reason is forwarded to cert_manager."""
        mock_cert_manager.revoke_ssh_certificate.return_value = True
        await client.post(
            "/api/v1/ssh/certificates/ssh-cert-001/revoke",
            json={"reason": "key_compromise"},
        )
        call_kwargs = mock_cert_manager.revoke_ssh_certificate.call_args
        assert call_kwargs.kwargs.get("reason") == "key_compromise"

    async def test_revoke_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.post(
            "/api/v1/ssh/certificates/ssh-cert-001/revoke",
            json=_REVOKE_PAYLOAD,
        )
        assert resp.status_code == 503


# ===========================================================================
# KRL
# ===========================================================================
@pytest.mark.unit
class TestGetKRL:
    """GET /api/v1/ssh/krl"""

    async def test_get_krl_json(self, client, mock_cert_manager):
        """200 JSON response with KRL data."""
        resp = await client.get("/api/v1/ssh/krl")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "krl_binary" in data
        assert "revoked_count" in data

    async def test_get_krl_binary_accept_header(self, client, mock_cert_manager):
        """application/octet-stream Accept header returns binary data."""
        resp = await client.get(
            "/api/v1/ssh/krl",
            headers={"Accept": "application/octet-stream"},
        )
        assert resp.status_code == 200
        assert resp.content_type == "application/octet-stream"

    async def test_get_krl_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/ssh/krl")
        assert resp.status_code == 503


# ===========================================================================
# SSH CA Info
# ===========================================================================
@pytest.mark.unit
class TestSSHCAInfo:
    """GET /api/v1/ssh/ca"""

    async def test_get_ca_info(self, client, mock_cert_manager):
        """200 with SSH CA information."""
        resp = await client.get("/api/v1/ssh/ca")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "key_type" in data
        assert "fingerprint" in data

    async def test_get_ca_info_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/ssh/ca")
        assert resp.status_code == 503


# ===========================================================================
# SSH CA Public Key
# ===========================================================================
@pytest.mark.unit
class TestSSHCAPublicKey:
    """GET /api/v1/ssh/ca/public-key"""

    async def test_get_ca_public_key_json(self, client, mock_cert_manager):
        """200 JSON response with ca_public_key field."""
        resp = await client.get("/api/v1/ssh/ca/public-key")
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "ca_public_key" in data
        assert data["ca_public_key"].startswith("ssh-ed25519")

    async def test_get_ca_public_key_text_plain(self, client, mock_cert_manager):
        """text/plain Accept header returns raw public key string."""
        resp = await client.get(
            "/api/v1/ssh/ca/public-key",
            headers={"Accept": "text/plain"},
        )
        assert resp.status_code == 200
        assert "text/plain" in resp.content_type

    async def test_get_ca_public_key_no_cert_manager_returns_503(
        self, client, app
    ):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.get("/api/v1/ssh/ca/public-key")
        assert resp.status_code == 503


# ===========================================================================
# Verify SSH Certificate
# ===========================================================================
@pytest.mark.unit
class TestVerifySSHCertificate:
    """POST /api/v1/ssh/verify"""

    async def test_verify_valid_cert(self, client, mock_cert_manager):
        """200 with valid=True for a good certificate."""
        mock_cert_manager.get_ssh_certificate.return_value = _ssh_cert_dict(
            status="active"
        )
        resp = await client.post(
            "/api/v1/ssh/verify",
            json={"certificate": "ssh-rsa-cert-v01@openssh.com AAAA..."},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data["valid"] is True

    async def test_verify_missing_certificate_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when certificate field is absent from request body."""
        resp = await client.post(
            "/api/v1/ssh/verify",
            json={},
        )
        assert resp.status_code == 400
        data = await resp.get_json()
        assert "certificate" in data["error"].lower()

    async def test_verify_revoked_cert_shows_revoked_status(
        self, client, mock_cert_manager
    ):
        """Verification result shows 'revoked' status for a revoked cert."""
        mock_cert_manager.get_ssh_certificate.return_value = _ssh_cert_dict(
            status="revoked", revoked=True
        )
        resp = await client.post(
            "/api/v1/ssh/verify",
            json={"certificate": "ssh-rsa-cert-v01@openssh.com AAAA..."},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert data.get("status") == "revoked"

    async def test_verify_check_certificate_raises_value_error_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when ssh_ca.check_certificate raises ValueError."""
        mock_cert_manager.ssh_ca.check_certificate.side_effect = ValueError(
            "malformed cert"
        )
        resp = await client.post(
            "/api/v1/ssh/verify",
            json={"certificate": "garbage"},
        )
        assert resp.status_code == 400
        data = await resp.get_json()
        assert data["valid"] is False
        # Reset
        mock_cert_manager.ssh_ca.check_certificate.side_effect = None
        mock_cert_manager.ssh_ca.check_certificate.return_value = {
            "valid": True,
            "serial": "1000001",
            "key_id": "user-test",
        }

    async def test_verify_no_cert_manager_returns_503(self, client, app):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.post(
            "/api/v1/ssh/verify",
            json={"certificate": "ssh-rsa-cert-v01@openssh.com AAAA..."},
        )
        assert resp.status_code == 503


# ===========================================================================
# SSH Config Generation
# ===========================================================================
@pytest.mark.unit
class TestSSHConfigGeneration:
    """Config generation endpoints."""

    async def test_generate_known_hosts(self, client, mock_cert_manager):
        """POST /config/known-hosts returns known_hosts entry."""
        resp = await client.post(
            "/api/v1/ssh/config/known-hosts",
            json={"hostnames": ["myserver.example.com"]},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "known_hosts" in data
        assert "hostnames" in data
        assert data["hostnames"] == ["myserver.example.com"]

    async def test_generate_known_hosts_missing_hostnames_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when 'hostnames' list is absent."""
        resp = await client.post(
            "/api/v1/ssh/config/known-hosts",
            json={},
        )
        assert resp.status_code == 400

    async def test_generate_known_hosts_empty_list_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when 'hostnames' list is empty."""
        resp = await client.post(
            "/api/v1/ssh/config/known-hosts",
            json={"hostnames": []},
        )
        assert resp.status_code == 400

    async def test_generate_authorized_keys(self, client, mock_cert_manager):
        """POST /config/authorized-keys returns authorized_keys entry."""
        resp = await client.post(
            "/api/v1/ssh/config/authorized-keys",
            json={"principals": ["alice", "bob"]},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "authorized_keys" in data
        assert "trustedUserCAKeys" in data

    async def test_generate_authorized_keys_missing_principals_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when 'principals' field is absent."""
        resp = await client.post(
            "/api/v1/ssh/config/authorized-keys",
            json={},
        )
        assert resp.status_code == 400

    async def test_generate_ssh_config(self, client, mock_cert_manager):
        """POST /config/ssh-config returns ssh_config and known_hosts_entry."""
        resp = await client.post(
            "/api/v1/ssh/config/ssh-config",
            json={"hostname": "myserver.example.com"},
        )
        assert resp.status_code == 200
        data = await resp.get_json()
        assert "ssh_config" in data
        assert "known_hosts_entry" in data
        assert "ca_public_key" in data

    async def test_generate_ssh_config_missing_hostname_returns_400(
        self, client, mock_cert_manager
    ):
        """400 when 'hostname' field is absent."""
        resp = await client.post(
            "/api/v1/ssh/config/ssh-config",
            json={},
        )
        assert resp.status_code == 400

    async def test_generate_known_hosts_no_cert_manager_returns_503(
        self, client, app
    ):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.post(
            "/api/v1/ssh/config/known-hosts",
            json={"hostnames": ["host.example.com"]},
        )
        assert resp.status_code == 503

    async def test_generate_authorized_keys_no_cert_manager_returns_503(
        self, client, app
    ):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.post(
            "/api/v1/ssh/config/authorized-keys",
            json={"principals": ["alice"]},
        )
        assert resp.status_code == 503

    async def test_generate_ssh_config_no_cert_manager_returns_503(
        self, client, app
    ):
        """503 when cert_manager absent."""
        app.config["cert_manager"] = None
        resp = await client.post(
            "/api/v1/ssh/config/ssh-config",
            json={"hostname": "myserver.example.com"},
        )
        assert resp.status_code == 503
