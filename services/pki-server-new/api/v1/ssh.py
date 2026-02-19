"""SSH Certificate REST API endpoints."""

from datetime import datetime
from functools import wraps
from typing import Callable

from pydantic import ValidationError
from quart import Blueprint, request, jsonify, g, current_app
import structlog

from ...validators.pydantic_models import (
    SSHCertificateRequest,
    RevokeRequest,
    SSHConfigRequest,
    AuthorizedKeysRequest,
)

logger = structlog.get_logger()

ssh_bp = Blueprint("ssh", __name__, url_prefix="/ssh")


def validate_request(model_class):
    """Decorator to validate request body with Pydantic model."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        async def wrapper(*args, **kwargs):
            try:
                data = await request.get_json()
                validated = model_class(**data)
                g.validated_data = validated
                return await f(*args, **kwargs)
            except ValidationError as e:
                return (
                    jsonify({"error": "Validation error", "details": e.errors()}),
                    400,
                )
            except Exception as e:
                logger.error("Request validation failed", error=str(e))
                return jsonify({"error": "Invalid request"}), 400

        return wrapper

    return decorator


def get_cert_manager():
    """Get certificate manager from app context."""
    return current_app.config.get("cert_manager")


# =============================================================================
# Certificate Issuance
# =============================================================================
@ssh_bp.route("/certificates", methods=["POST"])
@validate_request(SSHCertificateRequest)
async def issue_certificate():
    """Issue a new SSH certificate."""
    data = g.validated_data
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    try:
        result = await cert_manager.issue_ssh_certificate(
            public_key=data.public_key,
            certificate_type=data.certificate_type.value,
            key_id=data.key_id,
            principals=data.principals,
            validity_seconds=data.validity_seconds,
            extensions=data.extensions,
            critical_options=data.critical_options,
            source_addresses=data.source_addresses,
            force_command=data.force_command,
            hostname=data.hostname,
            requester_id=request.headers.get("X-User-ID"),
        )

        logger.info(
            "SSH certificate issued",
            serial=result["serial_number"],
            key_id=data.key_id,
            type=data.certificate_type.value,
        )

        return jsonify(result), 201

    except Exception as e:
        logger.error("Failed to issue SSH certificate", error=str(e))
        return jsonify({"error": str(e)}), 500


@ssh_bp.route("/certificates/<cert_id>", methods=["GET"])
async def get_certificate(cert_id: str):
    """Get SSH certificate by ID."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    cert = await cert_manager.get_ssh_certificate(cert_id=cert_id)

    if not cert:
        return jsonify({"error": "Certificate not found"}), 404

    return jsonify(cert)


@ssh_bp.route("/certificates/serial/<serial_number>", methods=["GET"])
async def get_certificate_by_serial(serial_number: str):
    """Get SSH certificate by serial number."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    cert = await cert_manager.get_ssh_certificate(serial_number=serial_number)

    if not cert:
        return jsonify({"error": "Certificate not found"}), 404

    return jsonify(cert)


# =============================================================================
# Certificate Revocation
# =============================================================================
@ssh_bp.route("/certificates/<cert_id>/revoke", methods=["POST"])
@validate_request(RevokeRequest)
async def revoke_certificate(cert_id: str):
    """Revoke an SSH certificate."""
    data = g.validated_data
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    success = await cert_manager.revoke_ssh_certificate(
        cert_id=cert_id,
        reason=data.reason.value,
        actor_id=request.headers.get("X-User-ID"),
    )

    if not success:
        return jsonify({"error": "Certificate not found"}), 404

    logger.info("SSH certificate revoked", cert_id=cert_id, reason=data.reason.value)

    return jsonify({"message": "Certificate revoked", "certificate_id": cert_id})


# =============================================================================
# Certificate Listing
# =============================================================================
@ssh_bp.route("/certificates", methods=["GET"])
async def list_certificates():
    """List SSH certificates with filtering."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    status = request.args.get("status")
    certificate_type = request.args.get("type")
    principal = request.args.get("principal")
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 50))

    certificates, total = await cert_manager.list_ssh_certificates(
        status=status,
        certificate_type=certificate_type,
        principal=principal,
        page=page,
        page_size=page_size,
    )

    return jsonify(
        {
            "certificates": certificates,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,
        }
    )


# =============================================================================
# KRL (Key Revocation List)
# =============================================================================
@ssh_bp.route("/krl", methods=["GET"])
async def get_krl():
    """Get current Key Revocation List."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    krl = await cert_manager.generate_ssh_krl()

    # Return as binary if requested
    if request.headers.get("Accept") == "application/octet-stream":
        import base64

        krl_binary = base64.b64decode(krl["krl_binary"])
        return (
            krl_binary,
            200,
            {
                "Content-Type": "application/octet-stream",
                "Content-Disposition": "attachment; filename=revoked_keys",
            },
        )

    return jsonify(krl)


# =============================================================================
# CA Information
# =============================================================================
@ssh_bp.route("/ca", methods=["GET"])
async def get_ca_info():
    """Get SSH CA information."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    ca_info = cert_manager.ssh_ca.get_ca_info()
    return jsonify(ca_info)


@ssh_bp.route("/ca/public-key", methods=["GET"])
async def get_ca_public_key():
    """Get SSH CA public key."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    ca_public_key = cert_manager.ssh_ca.get_ca_public_key()

    # Return as plain text if requested
    if request.headers.get("Accept") == "text/plain":
        return ca_public_key, 200, {"Content-Type": "text/plain"}

    return jsonify({"ca_public_key": ca_public_key})


# =============================================================================
# Configuration Generation
# =============================================================================
@ssh_bp.route("/config/known-hosts", methods=["POST"])
async def generate_known_hosts():
    """Generate known_hosts entry for host certificate verification."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    data = await request.get_json()
    hostnames = data.get("hostnames", [])

    if not hostnames:
        return jsonify({"error": "hostnames required"}), 400

    known_hosts_entry = cert_manager.ssh_ca.generate_known_hosts_entry(
        hostnames=hostnames, cert_authority=True
    )

    return jsonify(
        {
            "known_hosts": known_hosts_entry,
            "hostnames": hostnames,
        }
    )


@ssh_bp.route("/config/authorized-keys", methods=["POST"])
@validate_request(AuthorizedKeysRequest)
async def generate_authorized_keys():
    """Generate authorized_keys entry for user certificate verification."""
    data = g.validated_data
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    authorized_keys_entry = cert_manager.ssh_ca.generate_authorized_keys_entry(
        principals=data.principals, options=data.options
    )

    ca_public_key = cert_manager.ssh_ca.get_ca_public_key()

    return jsonify(
        {
            "authorized_keys": authorized_keys_entry,
            "trustedUserCAKeys": ca_public_key,
            "principals": data.principals,
        }
    )


@ssh_bp.route("/config/ssh-config", methods=["POST"])
@validate_request(SSHConfigRequest)
async def generate_ssh_config():
    """Generate SSH config snippet for a host."""
    data = g.validated_data
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    ssh_config = cert_manager.ssh_ca.generate_ssh_config(
        hostname=data.hostname,
        port=data.port,
        user=data.user,
        identity_file=data.identity_file,
    )

    known_hosts_entry = cert_manager.ssh_ca.generate_known_hosts_entry(
        hostnames=[data.hostname], cert_authority=True
    )

    return jsonify(
        {
            "ssh_config": ssh_config,
            "known_hosts_entry": known_hosts_entry,
            "ca_public_key": cert_manager.ssh_ca.get_ca_public_key(),
        }
    )


# =============================================================================
# Certificate Status
# =============================================================================
@ssh_bp.route("/certificates/<cert_id>/status", methods=["GET"])
async def get_certificate_status(cert_id: str):
    """Get SSH certificate status."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    cert = await cert_manager.get_ssh_certificate(cert_id=cert_id)

    if not cert:
        return jsonify({"error": "Certificate not found"}), 404

    now = datetime.utcnow()
    is_expired = cert["valid_before"] < now

    return jsonify(
        {
            "certificate_id": cert_id,
            "serial_number": cert["serial_number"],
            "key_id": cert["key_id"],
            "status": cert["status"],
            "is_expired": is_expired,
            "valid_after": cert["valid_after"].isoformat(),
            "valid_before": cert["valid_before"].isoformat(),
            "revoked_at": (
                cert["revoked_at"].isoformat() if cert["revoked_at"] else None
            ),
            "revocation_reason": cert.get("revocation_reason"),
        }
    )


# =============================================================================
# Certificate Verification
# =============================================================================
@ssh_bp.route("/verify", methods=["POST"])
async def verify_certificate():
    """Verify an SSH certificate."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    data = await request.get_json()
    certificate = data.get("certificate")

    if not certificate:
        return jsonify({"error": "certificate required"}), 400

    try:
        cert_info = await cert_manager.ssh_ca.check_certificate(certificate)

        # Check if revoked
        if cert_info.get("serial"):
            cert = await cert_manager.get_ssh_certificate(
                serial_number=cert_info["serial"]
            )
            if cert and cert["status"] == "revoked":
                cert_info["status"] = "revoked"
                cert_info["revoked_at"] = cert["revoked_at"].isoformat()

        return jsonify(cert_info)

    except ValueError as e:
        return jsonify({"error": str(e), "valid": False}), 400
    except Exception as e:
        logger.error("Certificate verification failed", error=str(e))
        return jsonify({"error": str(e)}), 500
