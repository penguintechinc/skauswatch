"""Common REST API endpoints for PKI Server."""

from datetime import datetime, timedelta

import structlog
from quart import Blueprint, current_app, jsonify

logger = structlog.get_logger()

common_bp = Blueprint("common", __name__)


def get_cert_manager():
    """Get certificate manager from app context."""
    return current_app.config.get("cert_manager")


@common_bp.route("/statistics", methods=["GET"])
async def get_statistics():
    """Get PKI statistics for both X.509 and SSH certificates."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    stats = await cert_manager.get_statistics()
    return jsonify(stats)


@common_bp.route("/ca/info", methods=["GET"])
async def get_all_ca_info():
    """Get information about all Certificate Authorities."""
    cert_manager = get_cert_manager()

    if not cert_manager:
        return jsonify({"error": "Certificate manager not initialized"}), 503

    x509_info = cert_manager.x509_ca.get_ca_info()
    ssh_info = cert_manager.ssh_ca.get_ca_info()

    return jsonify(
        {
            "x509": x509_info,
            "ssh": ssh_info,
        }
    )


@common_bp.route("/audit", methods=["GET"])
async def get_audit_log():
    """Get PKI audit log."""
    from ...models.db import db_session

    page = int(current_app.request.args.get("page", 1))
    page_size = int(current_app.request.args.get("page_size", 50))
    event_type = current_app.request.args.get("event_type")
    cert_type = current_app.request.args.get("certificate_type")

    with db_session() as db:
        query = db.pki_audit_log

        if event_type:
            query = query(db.pki_audit_log.event_type == event_type)
        if cert_type:
            query = query(db.pki_audit_log.certificate_type == cert_type)

        total = query.count()
        offset = (page - 1) * page_size

        entries = query.select(
            orderby=~db.pki_audit_log.timestamp, limitby=(offset, offset + page_size)
        )

        audit_log = [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "certificate_type": e.certificate_type,
                "certificate_id": e.certificate_id,
                "serial_number": e.serial_number,
                "subject": e.subject,
                "actor_id": e.actor_id,
                "action": e.action,
                "status": e.status,
                "error_message": e.error_message,
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            }
            for e in entries
        ]

    return jsonify(
        {
            "audit_log": audit_log,
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,
        }
    )


@common_bp.route("/expiring", methods=["GET"])
async def get_expiring_certificates():
    """Get certificates expiring within specified days."""
    from ...models.db import db_session

    days = int(current_app.request.args.get("days", 30))
    cert_type = current_app.request.args.get("type", "all")  # x509, ssh, all

    now = datetime.utcnow()
    expiring_before = now + timedelta(days=days)

    result = {
        "expiring_within_days": days,
        "x509": [],
        "ssh": [],
    }

    with db_session() as db:
        if cert_type in ("x509", "all"):
            x509_certs = db(
                (db.x509_certificates.status == "active")
                & (db.x509_certificates.not_after < expiring_before)
                & (db.x509_certificates.not_after > now)
            ).select(orderby=db.x509_certificates.not_after)

            result["x509"] = [
                {
                    "id": str(c.id),
                    "serial_number": c.serial_number,
                    "subject": c.subject,
                    "not_after": c.not_after.isoformat(),
                    "days_until_expiry": (c.not_after - now).days,
                }
                for c in x509_certs
            ]

        if cert_type in ("ssh", "all"):
            ssh_certs = db(
                (db.ssh_certificates.status == "active")
                & (db.ssh_certificates.valid_before < expiring_before)
                & (db.ssh_certificates.valid_before > now)
            ).select(orderby=db.ssh_certificates.valid_before)

            result["ssh"] = [
                {
                    "id": str(c.id),
                    "serial_number": c.serial_number,
                    "key_id": c.key_id,
                    "valid_before": c.valid_before.isoformat(),
                    "days_until_expiry": (c.valid_before - now).days,
                }
                for c in ssh_certs
            ]

    return jsonify(result)


@common_bp.route("/cleanup", methods=["POST"])
async def cleanup_expired():
    """Mark expired certificates as expired status."""
    from ...models.db import db_session

    now = datetime.utcnow()
    updated_count = 0

    with db_session() as db:
        # Update expired X.509 certificates
        x509_updated = db(
            (db.x509_certificates.status == "active")
            & (db.x509_certificates.not_after < now)
        ).update(status="expired", updated_at=now)
        updated_count += x509_updated

        # Update expired SSH certificates
        ssh_updated = db(
            (db.ssh_certificates.status == "active")
            & (db.ssh_certificates.valid_before < now)
        ).update(status="expired", updated_at=now)
        updated_count += ssh_updated

    logger.info("Expired certificates cleanup", updated_count=updated_count)

    return jsonify(
        {
            "message": "Cleanup completed",
            "updated_count": updated_count,
        }
    )
