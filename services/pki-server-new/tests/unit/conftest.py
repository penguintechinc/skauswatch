"""Pytest configuration and fixtures for PKI Server unit tests."""

import sys
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# The pki-server-new directory is a Python package whose folder name contains
# hyphens, so it can't be imported directly.  Add the services/ parent to the
# path and create an alias so Python can resolve the relative-import chain.
_SERVICES_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..")
_PKI_DIR = os.path.join(os.path.dirname(__file__), "..", "..")

if _SERVICES_DIR not in sys.path:
    sys.path.insert(0, _SERVICES_DIR)
if _PKI_DIR not in sys.path:
    sys.path.insert(0, _PKI_DIR)

# The directory on disk is "pki-server-new" but Python needs a valid identifier.
# Register the package under the name Python will encounter with relative imports
# coming from `main.py` (which lives inside the package itself).
import importlib.util

_PKI_PACKAGE_DIR = os.path.normpath(_PKI_DIR)
_PKI_PACKAGE_NAME = "pki_server_new"

if _PKI_PACKAGE_NAME not in sys.modules:
    # Load the package __init__ manually and register it
    spec = importlib.util.spec_from_file_location(
        _PKI_PACKAGE_NAME,
        os.path.join(_PKI_PACKAGE_DIR, "__init__.py"),
        submodule_search_locations=[_PKI_PACKAGE_DIR],
    )
    pkg = importlib.util.module_from_spec(spec)
    pkg.__path__ = [_PKI_PACKAGE_DIR]
    pkg.__package__ = _PKI_PACKAGE_NAME
    sys.modules[_PKI_PACKAGE_NAME] = pkg
    spec.loader.exec_module(pkg)


def _make_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


@pytest.fixture
def mock_cert_manager():
    """Create a mock CertificateManager with all expected methods."""
    cm = MagicMock()

    now = _make_now()
    future = now + timedelta(days=365)

    # -------------------------------------------------------------------
    # X.509 methods
    # -------------------------------------------------------------------
    cm.issue_x509_certificate = AsyncMock(
        return_value={
            "id": "cert-001",
            "serial_number": "ABC123",
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
            "status": "active",
            "created_at": now,
        }
    )

    cm.get_x509_certificate = AsyncMock(return_value=None)  # Default: not found

    cm.list_x509_certificates = AsyncMock(return_value=([], 0))

    cm.revoke_x509_certificate = AsyncMock(return_value=True)

    cm.generate_x509_crl = AsyncMock(
        return_value={
            "crl_pem": "-----BEGIN X509 CRL-----\n...\n-----END X509 CRL-----",
            "revoked_count": 0,
            "generated_at": now.isoformat(),
        }
    )

    cm.get_statistics = AsyncMock(
        return_value={
            "x509": {"total": 0, "active": 0, "revoked": 0, "expired": 0},
            "ssh": {"total": 0, "active": 0, "revoked": 0, "expired": 0},
        }
    )

    # -------------------------------------------------------------------
    # X.509 CA sub-object
    # -------------------------------------------------------------------
    x509_ca = MagicMock()
    x509_ca.get_ca_info.return_value = {
        "subject": "CN=SkausWatch CA",
        "issuer": "CN=SkausWatch Root CA",
        "serial_number": "ROOT001",
        "not_before": now.isoformat(),
        "not_after": future.isoformat(),
    }
    x509_ca.get_ca_certificate_pem.return_value = (
        "-----BEGIN CERTIFICATE-----\nCA...\n-----END CERTIFICATE-----"
    )
    cm.x509_ca = x509_ca

    # -------------------------------------------------------------------
    # SSH methods
    # -------------------------------------------------------------------
    ssh_future = now + timedelta(hours=24)

    cm.issue_ssh_certificate = AsyncMock(
        return_value={
            "id": "ssh-cert-001",
            "serial_number": "1000001",
            "key_id": "user-test",
            "certificate_type": "user",
            "principals": ["testuser"],
            "valid_after": now,
            "valid_before": ssh_future,
            "key_type": "ssh-ed25519",
            "signed_certificate": "ssh-rsa-cert-v01@openssh.com AAAA...",
            "ca_public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
            "status": "active",
            "created_at": now,
        }
    )

    cm.get_ssh_certificate = AsyncMock(return_value=None)  # Default: not found

    cm.list_ssh_certificates = AsyncMock(return_value=([], 0))

    cm.revoke_ssh_certificate = AsyncMock(return_value=True)

    cm.generate_ssh_krl = AsyncMock(
        return_value={
            "krl_binary": "base64encodedkrl==",
            "revoked_count": 0,
            "generated_at": now.isoformat(),
        }
    )

    # -------------------------------------------------------------------
    # SSH CA sub-object
    # -------------------------------------------------------------------
    ssh_ca = MagicMock()
    ssh_ca.get_ca_info.return_value = {
        "key_type": "ssh-ed25519",
        "fingerprint": "SHA256:abc123...",
        "serial_counter": 1000000,
    }
    ssh_ca.get_ca_public_key.return_value = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... CA Key"
    )
    ssh_ca.generate_known_hosts_entry.return_value = (
        "@cert-authority * ssh-ed25519 AAAAC3..."
    )
    ssh_ca.generate_authorized_keys_entry.return_value = (
        'cert-authority,principals="user1" ssh-ed25519 AAAAC3...'
    )
    ssh_ca.generate_ssh_config.return_value = (
        "Host test.example.com\n    CertificateFile ~/.ssh/cert.pub"
    )
    ssh_ca.check_certificate = AsyncMock(
        return_value={"valid": True, "serial": "1000001", "key_id": "user-test"}
    )
    cm.ssh_ca = ssh_ca

    return cm


@pytest.fixture
def app(mock_cert_manager):
    """Create the PKI Server Quart app with mocked startup/shutdown."""
    # Patch the heavy infrastructure so create_app() succeeds without real
    # CA keys, a database, or gRPC.  startup() is registered as a
    # before_serving hook; in test_client() context it does NOT run
    # automatically, so we only need to ensure app.config["cert_manager"]
    # is populated before any request is made.
    with (
        patch(f"{_PKI_PACKAGE_NAME}.main.startup", new_callable=AsyncMock),
        patch(f"{_PKI_PACKAGE_NAME}.main.shutdown", new_callable=AsyncMock),
        patch(f"{_PKI_PACKAGE_NAME}.main.get_settings") as mock_get_settings,
    ):
        # Provide a minimal Settings-like object so create_app() doesn't try
        # to read real environment variables or fail validators.
        from pki_server_new.config import Settings

        mock_get_settings.return_value = Settings()

        from pki_server_new.main import create_app

        test_app = create_app()
        test_app.config["TESTING"] = True
        # Inject the mock cert_manager so API handlers can retrieve it via
        # current_app.config["cert_manager"]
        test_app.config["cert_manager"] = mock_cert_manager

        yield test_app


@pytest.fixture
def client(app):
    """Return a Quart test client."""
    return app.test_client()
