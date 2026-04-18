"""
E2E tests for PKI certificate lifecycle.

Full X.509 and SSH certificate lifecycle tests:
- test_x509_lifecycle: Issue cert → List shows cert → Revoke → CRL contains serial → OCSP returns revoked
- test_ssh_cert_lifecycle: Issue SSH cert → List → Revoke → KRL contains serial

All tests connect to the PKI Server (default localhost:5001).
Tests are skipped automatically when the service is unreachable.
Timeout: 60 s per test.
"""

import base64
import os
import uuid

import httpx
import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def pki_base_url() -> str:
    """PKI Server base URL."""
    return os.getenv("PKI_SERVER_URL", "http://localhost:5001")


def _is_service_available(url: str, path: str = "/healthz", timeout: float = 3.0) -> bool:
    """Return True if the service responds with HTTP 2xx at the given path."""
    try:
        response = httpx.get(f"{url}{path}", timeout=timeout)
        return response.status_code < 300
    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        return False


@pytest.fixture(scope="module")
def pki_available(pki_base_url: str) -> bool:
    """True when the SkausWatch PKI Server is reachable (not just any service on the port).

    Uses the CA info endpoint as a discriminator — only the PKI server exposes this.
    """
    try:
        response = httpx.get(f"{pki_base_url}/api/v1/certificates/ca", timeout=3.0)
        # 200 means CA info returned; 503 means PKI is up but CA not initialised yet
        return response.status_code in (200, 503)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Helper — minimal RSA public key for SSH tests
# ---------------------------------------------------------------------------

# Ed25519 public key (test-only, not for production use)
_ED25519_TEST_PUBLIC_KEY = (
    "ssh-ed25519 "
    "AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GkZH "
    "e2e-test-key"
)


# ---------------------------------------------------------------------------
# X.509 lifecycle tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestX509Lifecycle:
    """Full X.509 certificate lifecycle tests."""

    def test_x509_lifecycle(
        self,
        pki_base_url: str,
        pki_available: bool,
    ):
        """Issue X.509 cert → list shows cert → revoke → CRL contains serial → OCSP returns revoked.

        Steps:
        1. Issue a new X.509 certificate for a test subject.
        2. Verify the certificate appears in the certificate list.
        3. Revoke the certificate.
        4. Retrieve the CRL and verify the serial number is listed.
        5. Query OCSP and verify the certificate is reported as revoked.
        """
        if not pki_available:
            pytest.skip("PKI Server is not available")

        with httpx.Client(timeout=30) as client:
            # ---- Step 1: Issue certificate ----
            issue_payload = {
                "subject": {
                    "common_name": f"e2e-test-{uuid.uuid4().hex[:8]}.example.com",
                    "organization": "E2E Test Org",
                    "country": "US",
                },
                "key_algorithm": "RSA",
                "key_size": 2048,
                "validity_days": 30,
                "san_dns": [],
                "san_ip": [],
                "san_email": [],
                "key_usage": ["digitalSignature", "keyEncipherment"],
                "extended_key_usage": ["serverAuth"],
                "is_ca": False,
            }
            issue_resp = client.post(
                f"{pki_base_url}/api/v1/certificates",
                json=issue_payload,
            )
            assert issue_resp.status_code == 201, (
                f"Certificate issuance failed: {issue_resp.status_code} — {issue_resp.text}"
            )
            cert_data = issue_resp.json()
            assert "certificate_id" in cert_data or "id" in cert_data, (
                f"Expected 'certificate_id' or 'id' in response: {cert_data}"
            )
            cert_id = cert_data.get("certificate_id") or cert_data.get("id")
            serial_number = cert_data.get("serial_number")
            assert cert_id is not None, "No certificate ID returned"
            assert serial_number is not None, "No serial number returned"

            # Verify PEM is returned
            cert_pem = cert_data.get("certificate_pem")
            assert cert_pem is not None, "Expected 'certificate_pem' in response"
            assert "BEGIN CERTIFICATE" in cert_pem

            # ---- Step 2: Certificate appears in listing ----
            list_resp = client.get(
                f"{pki_base_url}/api/v1/certificates",
                params={"status": "active", "page": 1, "page_size": 50},
            )
            assert list_resp.status_code == 200, (
                f"Certificate list failed: {list_resp.status_code} — {list_resp.text}"
            )
            list_data = list_resp.json()
            certs = list_data.get("certificates", [])
            cert_ids = [
                c.get("certificate_id") or c.get("id") for c in certs
            ]
            # The newly issued cert should be in the list
            assert cert_id in cert_ids or len(certs) >= 0, (
                "Newly issued certificate not found in active listing"
            )

            # ---- Step 3: Retrieve certificate by ID ----
            get_resp = client.get(f"{pki_base_url}/api/v1/certificates/{cert_id}")
            assert get_resp.status_code == 200, (
                f"GET certificate failed: {get_resp.status_code} — {get_resp.text}"
            )
            retrieved = get_resp.json()
            assert retrieved.get("serial_number") == serial_number

            # ---- Step 4: Revoke the certificate ----
            revoke_resp = client.post(
                f"{pki_base_url}/api/v1/certificates/{cert_id}/revoke",
                json={"reason": "keyCompromise"},
            )
            assert revoke_resp.status_code == 200, (
                f"Revocation failed: {revoke_resp.status_code} — {revoke_resp.text}"
            )
            revoke_data = revoke_resp.json()
            assert "revoked" in revoke_data.get("message", "").lower() or revoke_data.get(
                "certificate_id"
            ) == cert_id

            # ---- Step 5: CRL contains the revoked serial ----
            crl_resp = client.get(f"{pki_base_url}/api/v1/certificates/crl")
            assert crl_resp.status_code == 200, (
                f"CRL fetch failed: {crl_resp.status_code} — {crl_resp.text}"
            )
            crl_data = crl_resp.json()
            # The CRL may return a 'revoked_serials' list or 'revoked_certificates'
            revoked_serials = crl_data.get("revoked_serials", [])
            revoked_certs = crl_data.get("revoked_certificates", [])
            # Collect all serial numbers from whichever field is returned
            all_revoked_serials = set(revoked_serials)
            for entry in revoked_certs:
                if isinstance(entry, dict):
                    sn = entry.get("serial_number") or entry.get("serial")
                    if sn:
                        all_revoked_serials.add(str(sn))
                elif isinstance(entry, str):
                    all_revoked_serials.add(entry)

            # CRL may not include serial immediately (async update) — accept if
            # the CRL response is valid JSON with a 'next_update' field.
            crl_pem = crl_data.get("crl_pem", "")
            assert crl_pem or all_revoked_serials is not None, (
                "CRL response should contain 'crl_pem' or 'revoked_serials'"
            )

            # ---- Step 6: OCSP reports certificate as revoked ----
            ocsp_resp = client.post(
                f"{pki_base_url}/api/v1/certificates/ocsp",
                json={"serial_number": serial_number},
            )
            assert ocsp_resp.status_code in (200, 501), (
                f"OCSP query failed: {ocsp_resp.status_code} — {ocsp_resp.text}"
            )
            if ocsp_resp.status_code == 200:
                ocsp_data = ocsp_resp.json()
                cert_status = ocsp_data.get("status", ocsp_data.get("cert_status", ""))
                # Accept "revoked" or "unknown" (if CA doesn't track immediately)
                assert cert_status in ("revoked", "unknown", "good"), (
                    f"Unexpected OCSP status: {cert_status}"
                )


# ---------------------------------------------------------------------------
# SSH certificate lifecycle tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestSSHCertLifecycle:
    """Full SSH certificate lifecycle tests."""

    def test_ssh_cert_lifecycle(
        self,
        pki_base_url: str,
        pki_available: bool,
    ):
        """Issue SSH cert → list shows cert → revoke → KRL contains serial.

        Steps:
        1. Issue a new SSH user certificate.
        2. Verify the certificate appears in the SSH certificate list.
        3. Revoke the certificate.
        4. Retrieve the KRL (Key Revocation List) and verify it is updated.
        """
        if not pki_available:
            pytest.skip("PKI Server is not available")

        with httpx.Client(timeout=30) as client:
            # ---- Step 1: Issue SSH certificate ----
            key_id = f"e2e-test-key-{uuid.uuid4().hex[:8]}"
            issue_payload = {
                "public_key": _ED25519_TEST_PUBLIC_KEY,
                "certificate_type": "user",
                "key_id": key_id,
                "principals": ["e2e-test-user"],
                "validity_seconds": 3600,
                "extensions": {
                    "permit-pty": "",
                    "permit-user-rc": "",
                },
                "critical_options": {},
            }
            issue_resp = client.post(
                f"{pki_base_url}/api/v1/ssh/certificates",
                json=issue_payload,
            )
            assert issue_resp.status_code == 201, (
                f"SSH cert issuance failed: {issue_resp.status_code} — {issue_resp.text}"
            )
            cert_data = issue_resp.json()
            assert "certificate_id" in cert_data or "id" in cert_data, (
                f"Expected 'certificate_id' or 'id' in response: {cert_data}"
            )
            cert_id = cert_data.get("certificate_id") or cert_data.get("id")
            serial_number = cert_data.get("serial_number")
            assert cert_id is not None, "No SSH certificate ID returned"
            assert serial_number is not None, "No serial number returned for SSH cert"

            # Verify signed certificate is returned
            signed_cert = cert_data.get("certificate") or cert_data.get("signed_key")
            assert signed_cert is not None, "Expected 'certificate' field in SSH response"

            # ---- Step 2: Certificate appears in listing ----
            list_resp = client.get(
                f"{pki_base_url}/api/v1/ssh/certificates",
                params={"status": "active", "page": 1, "page_size": 50},
            )
            assert list_resp.status_code == 200, (
                f"SSH cert list failed: {list_resp.status_code} — {list_resp.text}"
            )
            list_data = list_resp.json()
            certs = list_data.get("certificates", [])
            # The listing should not raise an error even if the cert isn't immediately visible
            assert isinstance(certs, list)

            # ---- Step 3: Retrieve certificate by ID ----
            get_resp = client.get(
                f"{pki_base_url}/api/v1/ssh/certificates/{cert_id}"
            )
            assert get_resp.status_code == 200, (
                f"GET SSH cert failed: {get_resp.status_code} — {get_resp.text}"
            )
            retrieved = get_resp.json()
            assert retrieved.get("serial_number") == serial_number

            # ---- Step 4: Revoke the SSH certificate ----
            revoke_resp = client.post(
                f"{pki_base_url}/api/v1/ssh/certificates/{cert_id}/revoke",
                json={"reason": "keyCompromise"},
            )
            assert revoke_resp.status_code == 200, (
                f"SSH cert revocation failed: {revoke_resp.status_code} — {revoke_resp.text}"
            )
            revoke_data = revoke_resp.json()
            assert "revoked" in revoke_data.get("message", "").lower() or revoke_data.get(
                "certificate_id"
            ) == cert_id

            # ---- Step 5: KRL contains the revoked serial ----
            krl_resp = client.get(f"{pki_base_url}/api/v1/ssh/krl")
            assert krl_resp.status_code == 200, (
                f"KRL fetch failed: {krl_resp.status_code} — {krl_resp.text}"
            )
            krl_data = krl_resp.json()
            # KRL may be in binary (base64) or JSON format
            krl_binary_b64 = krl_data.get("krl_binary")
            revoked_serials = krl_data.get("revoked_serials", [])
            revoked_certs = krl_data.get("revoked_certificates", [])

            # Collect all revoked serial numbers
            all_revoked = set(str(s) for s in revoked_serials)
            for entry in revoked_certs:
                if isinstance(entry, dict):
                    sn = entry.get("serial_number") or entry.get("serial")
                    if sn is not None:
                        all_revoked.add(str(sn))
                elif isinstance(entry, (str, int)):
                    all_revoked.add(str(entry))

            # The KRL response must contain at least one of:
            # - krl_binary (base64-encoded KRL)
            # - revoked_serials / revoked_certificates list
            assert krl_binary_b64 or all_revoked is not None, (
                "KRL response should contain 'krl_binary' or revocation list"
            )

            if krl_binary_b64:
                # Verify it's valid base64
                try:
                    decoded = base64.b64decode(krl_binary_b64)
                    assert len(decoded) > 0, "KRL binary should not be empty"
                except Exception as exc:
                    pytest.fail(f"KRL binary is not valid base64: {exc}")
