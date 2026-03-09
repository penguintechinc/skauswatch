"""TLS certificate inspector for ASM.

Connects to TLS services and extracts certificate metadata including
subject, issuer, expiry, SANs, and SHA-256 fingerprint.
Uses stdlib ssl + socket + cryptography library.
"""

import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


def inspect_cert(
    host: str,
    port: int,
    timeout: float = 5.0,
) -> Optional[dict[str, Any]]:
    """Inspect TLS certificate at host:port.

    Args:
        host: Target hostname or IP address.
        port: Target TLS port.
        timeout: Connection timeout in seconds.

    Returns:
        Dict with certificate metadata, or None on failure.
        Keys: subject, issuer, not_before, not_after, is_expired,
              days_until_expiry, sans, fingerprint_sha256, error.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                if not cert_der:
                    return None

                return _parse_cert_der(cert_der)

    except ssl.SSLError as e:
        logger.debug(f"SSL error inspecting {host}:{port}: {e}")
        return {"error": str(e), "host": host, "port": port}
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug(f"Connection error inspecting {host}:{port}: {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error inspecting {host}:{port}: {e}")
        return None


def _parse_cert_der(cert_der: bytes) -> dict[str, Any]:
    """Parse DER-encoded certificate into metadata dict.

    Args:
        cert_der: DER-encoded certificate bytes.

    Returns:
        Dict with parsed certificate fields.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import ExtensionOID, NameOID
    except ImportError:
        logger.error("cryptography library not installed")
        return {"error": "cryptography library not available"}

    try:
        cert = x509.load_der_x509_certificate(cert_der)
    except Exception as e:
        return {"error": f"Failed to parse certificate: {e}"}

    now = datetime.now(timezone.utc)

    # Subject and issuer
    subject = _format_name(cert.subject)
    issuer = _format_name(cert.issuer)

    # Validity dates (ensure timezone-aware)
    not_before = (
        cert.not_valid_before_utc
        if hasattr(cert, "not_valid_before_utc")
        else cert.not_valid_before.replace(tzinfo=timezone.utc)
    )
    not_after = (
        cert.not_valid_after_utc
        if hasattr(cert, "not_valid_after_utc")
        else cert.not_valid_after.replace(tzinfo=timezone.utc)
    )

    # Expiry
    is_expired = not_after < now
    days_until_expiry = (not_after - now).days

    # SANs (Subject Alternative Names)
    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        for name in san_ext.value:
            if hasattr(name, "value"):
                sans.append(str(name.value))
    except x509.ExtensionNotFound:
        pass
    except Exception as e:
        logger.debug(f"SAN extraction error: {e}")

    # SHA-256 fingerprint
    try:
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        fingerprint = ""

    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "is_expired": is_expired,
        "days_until_expiry": days_until_expiry,
        "sans": sans,
        "fingerprint_sha256": fingerprint,
    }


def _format_name(name) -> str:
    """Format an x509 Name object as a string."""
    try:
        from cryptography.x509.oid import NameOID

        parts = []
        for attr in name:
            try:
                oid_name = (
                    attr.oid._name if hasattr(attr.oid, "_name") else str(attr.oid)
                )
                parts.append(f"{oid_name}={attr.value}")
            except Exception:
                continue
        return ", ".join(parts) if parts else str(name)
    except Exception:
        return str(name)


def inspect_certs_batch(
    services: list[dict[str, Any]],
    timeout: float = 5.0,
) -> list[dict[str, Any]]:
    """Inspect TLS certs for a batch of services.

    Args:
        services: List of dicts with 'ip' and 'port' keys.
        timeout: Per-connection timeout.

    Returns:
        List of cert result dicts with 'ip' and 'port' added.
    """
    results = []
    for svc in services:
        ip = svc.get("ip", "")
        port = svc.get("port", 443)
        cert_data = inspect_cert(ip, port, timeout=timeout)
        if cert_data:
            cert_data["ip"] = ip
            cert_data["port"] = port
            results.append(cert_data)
    return results
