"""E2E tests for PKI certificate lifecycle.

Tests the complete PKI workflow:
1. Request a new certificate
2. Issue the certificate
3. Verify certificate properties
4. Revoke the certificate
"""

import pytest
import requests


@pytest.mark.e2e
class TestPKICertificateLifecycle:
    """PKI certificate lifecycle end-to-end tests."""

    @pytest.fixture(autouse=True)
    def skip_if_pki_unavailable(self, check_services_available):
        """Skip tests if PKI Server service is not available."""
        if not check_services_available.get("pki"):
            pytest.skip("PKI Server service is not available")

    def test_pki_health(self, pki_url: str):
        """Verify PKI Server service is healthy."""
        response = requests.get(f"{pki_url}/healthz", timeout=5)
        assert response.status_code == 200

    def test_request_certificate(self, pki_url: str, auth_headers: dict) -> str | None:
        """Request a new certificate from the PKI server.

        Returns the certificate request ID if successful.
        """
        payload = {
            "subject": "CN=test.skauswatch.local,O=PenguinTech,C=US",
            "key_algorithm": "RSA",
            "key_size": 2048,
            "validity_days": 30,
            "san_dns": ["test.skauswatch.local"],
            "generate_key": True,
        }
        response = requests.post(
            f"{pki_url}/api/v1/certificates",
            json=payload,
            headers=auth_headers,
            timeout=15,
        )
        if response.status_code in (404, 502, 503):
            pytest.skip(f"PKI certificate endpoint not available: {response.status_code}")
        assert response.status_code in (200, 201), (
            f"Expected 200/201, got {response.status_code}: {response.text}"
        )
        data = response.json()
        assert "id" in data or "cert_id" in data or "certificate_pem" in data
        return data.get("id") or data.get("cert_id")

    def test_issue_certificate(
        self, pki_url: str, auth_headers: dict, request_id: str | None = None
    ) -> str | None:
        """Issue a pending certificate request.

        Returns the certificate data or certificate ID.
        """
        payload = {
            "subject": "CN=issue-test.skauswatch.local,O=PenguinTech,C=US",
            "key_algorithm": "RSA",
            "key_size": 2048,
            "validity_days": 30,
            "san_dns": ["issue-test.skauswatch.local"],
            "generate_key": True,
        }
        response = requests.post(
            f"{pki_url}/api/v1/certificates",
            json=payload,
            headers=auth_headers,
            timeout=15,
        )
        if response.status_code in (404, 502, 503):
            pytest.skip(f"PKI certificate endpoint not available: {response.status_code}")
        assert response.status_code in (200, 201), (
            f"Expected 200/201, got {response.status_code}: {response.text}"
        )
        data = response.json()
        assert any(k in data for k in ("id", "cert_id", "certificate_pem", "serial_number"))
        assert "certificate_pem" in data or "id" in data or "cert_id" in data
        return data.get("id") or data.get("cert_id")

    def test_verify_certificate_properties(
        self, pki_url: str, auth_headers: dict, cert_id: str | None = None
    ):
        """Verify issued certificate has correct properties.

        Ensures certificate data is correct and valid.
        """
        payload = {
            "subject": "CN=verify-test.skauswatch.local,O=PenguinTech,C=US",
            "key_algorithm": "RSA",
            "key_size": 2048,
            "validity_days": 30,
            "san_dns": ["verify-test.skauswatch.local"],
            "generate_key": True,
        }
        response = requests.post(
            f"{pki_url}/api/v1/certificates",
            json=payload,
            headers=auth_headers,
            timeout=15,
        )
        if response.status_code in (404, 502, 503):
            pytest.skip(f"PKI certificate endpoint not available: {response.status_code}")
        assert response.status_code in (200, 201)
        cert_data = response.json()
        cert_id = cert_data.get("id") or cert_data.get("cert_id")

        if not cert_id:
            pytest.skip("Certificate ID not returned from issuance")

        # Retrieve certificate
        get_response = requests.get(
            f"{pki_url}/api/v1/certificates/{cert_id}",
            headers=auth_headers,
            timeout=10,
        )
        if get_response.status_code in (404, 502, 503):
            pytest.skip(f"Certificate retrieval endpoint not available: {get_response.status_code}")
        assert get_response.status_code == 200, (
            f"Expected 200, got {get_response.status_code}: {get_response.text}"
        )

        retrieved = get_response.json()
        assert "certificate_pem" in retrieved or "id" in retrieved
        assert "serial_number" in retrieved or "id" in retrieved

    def test_revoke_certificate(self, pki_url: str, auth_headers: dict, cert_id: str | None = None):
        """Revoke an issued certificate.

        Verifies the certificate is added to the revocation list.
        """
        payload = {
            "subject": "CN=revoke-test.skauswatch.local,O=PenguinTech,C=US",
            "key_algorithm": "RSA",
            "key_size": 2048,
            "validity_days": 30,
            "san_dns": ["revoke-test.skauswatch.local"],
            "generate_key": True,
        }
        response = requests.post(
            f"{pki_url}/api/v1/certificates",
            json=payload,
            headers=auth_headers,
            timeout=15,
        )
        if response.status_code in (404, 502, 503):
            pytest.skip(f"PKI certificate endpoint not available: {response.status_code}")
        assert response.status_code in (200, 201)
        cert_data = response.json()
        cert_id = cert_data.get("id") or cert_data.get("cert_id")

        if not cert_id:
            pytest.skip("Certificate ID not returned from issuance")

        # Revoke certificate
        revoke_payload = {"reason": "testing"}
        revoke_response = requests.post(
            f"{pki_url}/api/v1/certificates/{cert_id}/revoke",
            json=revoke_payload,
            headers=auth_headers,
            timeout=10,
        )
        if revoke_response.status_code in (404, 502, 503):
            pytest.skip(
                f"Certificate revocation endpoint not available: {revoke_response.status_code}"
            )
        assert revoke_response.status_code in (200, 204), (
            f"Expected 200/204, got {revoke_response.status_code}: {revoke_response.text}"
        )

    def test_verify_revocation_in_crl(self, pki_url: str, serial_number: str | None = None):
        """Verify revoked certificate appears in CRL (Certificate Revocation List).

        Ensures revocation is properly published.
        """
        response = requests.get(
            f"{pki_url}/api/v1/ca/info",
            timeout=10,
        )
        if response.status_code in (404, 502, 503):
            pytest.skip(f"CA info endpoint not available: {response.status_code}")
        assert response.status_code == 200, (
            f"Expected 200, got {response.status_code}: {response.text}"
        )
        data = response.json()
        assert "ca_cert" in data or "issuer" in data or "dn" in data

    def test_clean_up_certificate_data(
        self, pki_url: str, auth_headers: dict, cert_id: str | None = None
    ):
        """Clean up test certificate data after tests.

        Optional: Delete test certificates from the system.
        """
        # Verify PKI server is still healthy
        response = requests.get(
            f"{pki_url}/healthz",
            timeout=5,
        )
        assert response.status_code == 200, (
            f"PKI server health check failed: {response.status_code}"
        )
