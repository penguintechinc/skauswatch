"""X.509 Certificate REST API endpoints."""

from datetime import datetime
from functools import wraps
from typing import Callable

from pydantic import ValidationError
from quart import Blueprint, request, jsonify, g, current_app
import structlog

from ...validators.pydantic_models import (
    X509CertificateRequest,
    RevokeRequest,
    CertificateSearchRequest,
    OCSPRequest,
)

logger = structlog.get_logger()

x509_bp = Blueprint("x509", __name__, url_prefix="/certificates")


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
@x509_bp.route("", methods=["POST"])
@validate_request(X509CertificateRequest)
async def issue_certificate():
    """Issue a new X.509 certificate."""
    data = g.validated_data
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    try:
        result = await cert_manager.issue_x509_certificate(
            subject=data.subject,
            key_algorithm=data.key_algorithm.value,
            key_size=data.key_size,
            validity_days=data.validity_days,
            san_dns=data.san_dns,
            san_ip=data.san_ip,
            san_email=data.san_email,
            key_usage=[ku.value for ku in data.key_usage],
            extended_key_usage=[eku.value for eku in data.extended_key_usage],
            is_ca=data.is_ca,
            path_length=data.path_length,
            csr_pem=data.csr_pem,
            requester_id=request.headers.get("X-User-ID"),
        )

        logger.info(
            "X.509 certificate issued",
            serial=result["serial_number"],
            subject=data.subject,
        )

        return jsonify(result), 201

    except Exception as e:
        logger.error("Failed to issue certificate", error=str(e))
        return jsonify({"error": str(e)}), 500


@x509_bp.route("/<cert_id>", methods=["GET"])
async def get_certificate(cert_id: str):
    """Get X.509 certificate by ID."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    cert = await cert_manager.get_x509_certificate(cert_id=cert_id)

    if not cert:
        return jsonify({"error": "Certificate not found"}), 404

    # Don't return private key unless explicitly requested
    include_private_key = (
        request.args.get("include_private_key", "false").lower() == "true"
    )
    if not include_private_key:
        cert.pop("private_key_pem", None)

    return jsonify(cert)


@x509_bp.route("/serial/<serial_number>", methods=["GET"])
async def get_certificate_by_serial(serial_number: str):
    """Get X.509 certificate by serial number."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    cert = await cert_manager.get_x509_certificate(serial_number=serial_number)

    if not cert:
        return jsonify({"error": "Certificate not found"}), 404

    cert.pop("private_key_pem", None)
    return jsonify(cert)


# =============================================================================
# Certificate Revocation
# =============================================================================
@x509_bp.route("/<cert_id>/revoke", methods=["POST"])
@validate_request(RevokeRequest)
async def revoke_certificate(cert_id: str):
    """Revoke an X.509 certificate."""
    data = g.validated_data
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    success = await cert_manager.revoke_x509_certificate(
        cert_id=cert_id,
        reason=data.reason.value,
        actor_id=request.headers.get("X-User-ID"),
    )

    if not success:
        return jsonify({"error": "Certificate not found"}), 404

    logger.info("X.509 certificate revoked", cert_id=cert_id, reason=data.reason.value)

    return jsonify({"message": "Certificate revoked", "certificate_id": cert_id})


@x509_bp.route("/serial/<serial_number>/revoke", methods=["POST"])
@validate_request(RevokeRequest)
async def revoke_certificate_by_serial(serial_number: str):
    """Revoke an X.509 certificate by serial number."""
    data = g.validated_data
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    success = await cert_manager.revoke_x509_certificate(
        serial_number=serial_number,
        reason=data.reason.value,
        actor_id=request.headers.get("X-User-ID"),
    )

    if not success:
        return jsonify({"error": "Certificate not found"}), 404

    return jsonify({"message": "Certificate revoked", "serial_number": serial_number})


# =============================================================================
# Certificate Listing and Search
# =============================================================================
@x509_bp.route("", methods=["GET"])
async def list_certificates():
    """List X.509 certificates with filtering."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    status = request.args.get("status")
    subject = request.args.get("subject")
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 50))

    expires_before = None
    if request.args.get("expires_before"):
        expires_before = datetime.fromisoformat(request.args.get("expires_before"))

    certificates, total = await cert_manager.list_x509_certificates(
        status=status,
        subject=subject,
        expires_before=expires_before,
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


@x509_bp.route("/search", methods=["POST"])
@validate_request(CertificateSearchRequest)
async def search_certificates():
    """Search X.509 certificates."""
    data = g.validated_data
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    certificates, total = await cert_manager.list_x509_certificates(
        status=data.status.value if data.status else None,
        subject=data.subject,
        expires_before=data.expires_before,
        page=data.page,
        page_size=data.page_size,
    )

    return jsonify(
        {
            "certificates": certificates,
            "total": total,
            "page": data.page,
            "page_size": data.page_size,
            "pages": (total + data.page_size - 1) // data.page_size,
        }
    )


# =============================================================================
# CRL and OCSP
# =============================================================================
@x509_bp.route("/crl", methods=["GET"])
async def get_crl():
    """Get current Certificate Revocation List."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    crl = await cert_manager.generate_x509_crl()

    # Return as PEM if requested
    if request.headers.get("Accept") == "application/pkix-crl":
        return (
            crl["crl_pem"],
            200,
            {
                "Content-Type": "application/pkix-crl",
                "Content-Disposition": "attachment; filename=crl.pem",
            },
        )

    return jsonify(crl)


@x509_bp.route("/ocsp", methods=["POST"])
async def ocsp_response():
    """OCSP responder endpoint."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    try:
        # Handle both JSON and DER-encoded OCSP requests
        content_type = request.content_type

        if content_type == "application/ocsp-request":
            # Handle binary OCSP request
            return jsonify({"error": "Binary OCSP not yet implemented"}), 501

        # JSON request
        data = await request.get_json()
        serial_number = data.get("serial_number")

        if not serial_number:
            return jsonify({"error": "serial_number required"}), 400

        cert = await cert_manager.get_x509_certificate(serial_number=serial_number)

        if not cert:
            return jsonify(
                {
                    "serial_number": serial_number,
                    "status": "unknown",
                    "this_update": datetime.utcnow().isoformat(),
                    "next_update": datetime.utcnow().isoformat(),
                }
            )

        status = "good"
        revocation_time = None
        revocation_reason = None

        if cert["status"] == "revoked":
            status = "revoked"
            revocation_time = (
                cert["revoked_at"].isoformat() if cert["revoked_at"] else None
            )
            revocation_reason = cert.get("revocation_reason")

        return jsonify(
            {
                "serial_number": serial_number,
                "status": status,
                "this_update": datetime.utcnow().isoformat(),
                "next_update": datetime.utcnow().isoformat(),
                "revocation_time": revocation_time,
                "revocation_reason": revocation_reason,
            }
        )

    except Exception as e:
        logger.error("OCSP request failed", error=str(e))
        return jsonify({"error": str(e)}), 500


# =============================================================================
# CA Information
# =============================================================================
@x509_bp.route("/ca", methods=["GET"])
async def get_ca_info():
    """Get X.509 CA information."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    ca_info = cert_manager.x509_ca.get_ca_info()
    ca_info["ca_certificate_pem"] = cert_manager.x509_ca.get_ca_certificate_pem()

    return jsonify(ca_info)


@x509_bp.route("/ca/certificate", methods=["GET"])
async def download_ca_certificate():
    """Download CA certificate in PEM format."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    ca_pem = cert_manager.x509_ca.get_ca_certificate_pem()

    return (
        ca_pem,
        200,
        {
            "Content-Type": "application/x-pem-file",
            "Content-Disposition": "attachment; filename=ca.crt",
        },
    )


# =============================================================================
# Certificate Status
# =============================================================================
@x509_bp.route("/<cert_id>/status", methods=["GET"])
async def get_certificate_status(cert_id: str):
    """Get certificate status."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    cert = await cert_manager.get_x509_certificate(cert_id=cert_id)

    if not cert:
        return jsonify({"error": "Certificate not found"}), 404

    now = datetime.utcnow()
    is_expired = cert["not_after"] < now

    return jsonify(
        {
            "certificate_id": cert_id,
            "serial_number": cert["serial_number"],
            "status": cert["status"],
            "is_expired": is_expired,
            "not_before": cert["not_before"].isoformat(),
            "not_after": cert["not_after"].isoformat(),
            "revoked_at": (
                cert["revoked_at"].isoformat() if cert["revoked_at"] else None
            ),
            "revocation_reason": cert.get("revocation_reason"),
        }
    )
