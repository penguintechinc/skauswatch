"""ASM (Attack Surface Management) API routes for worker-scanner service.

Provides endpoints for:
- Triggering and monitoring ASM scans
- Viewing discovered hosts, services, screenshots, certs
- Diffing consecutive scans for new/removed exposure
- Managing extra port settings
"""

import os
from datetime import datetime
from typing import Any

from api.middleware.auth import jwt_required
from api.schemas.asm import AsmScanCreateSchema, PortsConfigSchema
from database.models import get_configured_db
from flask import Blueprint, jsonify, request
from marshmallow import ValidationError
from utils.logger import get_logger

logger = get_logger(__name__)

asm_bp = Blueprint("asm", __name__)

_create_schema = AsmScanCreateSchema()
_ports_schema = PortsConfigSchema()


@asm_bp.route("/scans", methods=["POST"])
@jwt_required
def create_asm_scan():
    """Trigger a new ASM scan.

    Request body:
        target_id (int): ID of scan target
        mode (str): 'internal', 'external', or 'both'
        extra_ports (list[int]): Additional ports beyond defaults
        rate (int): Masscan packets per second

    Returns:
        201: Created scan record
        400: Validation error
        404: Target not found
    """
    try:
        data = _create_schema.load(request.get_json() or {})
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.messages}), 400

    db = get_configured_db()

    # Verify target exists
    target = db.scan_targets[data["target_id"]]
    if not target:
        return (
            jsonify({"error": "Target not found", "target_id": data["target_id"]}),
            404,
        )

    # Load extra ports from DB settings (merged with request extra_ports)
    db_extra_ports = _get_setting(db, "extra_ports", [])
    all_extra_ports = list(set(data.get("extra_ports", []) + db_extra_ports))

    ports_config = {
        "extra_ports": all_extra_ports,
        "rate": data.get("rate", int(os.environ.get("ASM_MASSCAN_RATE", "1000"))),
    }

    # Create scan record
    from flask import g

    scan_id = db.asm_scans.insert(
        target_id=data["target_id"],
        mode=data.get("mode", "external"),
        status="pending",
        ports_config=ports_config,
        created_at=datetime.utcnow(),
        created_by=getattr(g, "current_user", {}).get("sub", "api"),
    )
    db.commit()

    # Trigger Celery task
    try:
        from workers.scan_worker import execute_asm_scan

        execute_asm_scan.delay(scan_id)
        logger.info(f"ASM scan {scan_id} queued for target {data['target_id']}")
    except Exception as e:
        logger.error(f"Failed to queue ASM scan {scan_id}: {e}")
        db(db.asm_scans.id == scan_id).update(status="failed")
        db.commit()
        return jsonify({"error": "Failed to queue scan", "details": str(e)}), 500

    scan = db.asm_scans[scan_id]
    return (
        jsonify(
            {
                "id": scan.id,
                "target_id": scan.target_id,
                "mode": scan.mode,
                "status": scan.status,
                "ports_config": scan.ports_config,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
            }
        ),
        201,
    )


@asm_bp.route("/scans", methods=["GET"])
@jwt_required
def list_asm_scans():
    """List ASM scans with pagination.

    Query params:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 20, max: 100)
        target_id (int): Filter by target

    Returns:
        200: Paginated list of scans
    """
    db = get_configured_db()
    page = max(1, int(request.args.get("page", 1)))
    per_page = min(100, max(1, int(request.args.get("per_page", 20))))
    target_id = request.args.get("target_id", type=int)

    if target_id:
        rows = db(db.asm_scans.target_id == target_id).select(
            orderby=~db.asm_scans.created_at,
            limitby=((page - 1) * per_page, page * per_page),
        )
        total = db(db.asm_scans.target_id == target_id).count()
    else:
        rows = db(db.asm_scans.id > 0).select(
            orderby=~db.asm_scans.created_at,
            limitby=((page - 1) * per_page, page * per_page),
        )
        total = db(db.asm_scans.id > 0).count()

    return (
        jsonify(
            {
                "scans": [_serialize_scan(r) for r in rows],
                "total": total,
                "page": page,
                "per_page": per_page,
            }
        ),
        200,
    )


@asm_bp.route("/scans/<int:scan_id>", methods=["GET"])
@jwt_required
def get_asm_scan(scan_id: int):
    """Get ASM scan detail."""
    db = get_configured_db()
    scan = db.asm_scans[scan_id]
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(_serialize_scan(scan)), 200


@asm_bp.route("/scans/<int:scan_id>/hosts", methods=["GET"])
@jwt_required
def get_asm_scan_hosts(scan_id: int):
    """Get discovered hosts and services for a scan."""
    db = get_configured_db()
    if not db.asm_scans[scan_id]:
        return jsonify({"error": "Scan not found"}), 404

    hosts = db(db.asm_hosts.scan_id == scan_id).select(orderby=db.asm_hosts.ip_address)
    result = []
    for host in hosts:
        services = db(db.asm_services.host_id == host.id).select(
            orderby=db.asm_services.port
        )
        result.append(
            {
                "id": host.id,
                "ip_address": host.ip_address,
                "hostname": host.hostname,
                "is_alive": host.is_alive,
                "latency_ms": host.latency_ms,
                "os_guess": host.os_guess,
                "services": [
                    {
                        "id": s.id,
                        "port": s.port,
                        "protocol": s.protocol,
                        "state": s.state,
                        "service_name": s.service_name,
                        "banner": s.banner,
                        "version": s.version,
                    }
                    for s in services
                ],
            }
        )
    return jsonify({"hosts": result, "total": len(result)}), 200


@asm_bp.route("/scans/<int:scan_id>/screenshots", methods=["GET"])
@jwt_required
def get_asm_scan_screenshots(scan_id: int):
    """Get screenshots with presigned S3 URLs."""
    db = get_configured_db()
    if not db.asm_scans[scan_id]:
        return jsonify({"error": "Scan not found"}), 404

    # Get all screenshots for this scan via join
    screenshots = db(
        (db.asm_screenshots.service_id == db.asm_services.id)
        & (db.asm_services.host_id == db.asm_hosts.id)
        & (db.asm_hosts.scan_id == scan_id)
    ).select(db.asm_screenshots.ALL, db.asm_services.port, db.asm_hosts.ip_address)

    result = []
    for row in screenshots:
        s = row.asm_screenshots
        presigned_url = _generate_presigned_url(s.s3_key)
        result.append(
            {
                "id": s.id,
                "service_id": s.service_id,
                "s3_key": s.s3_key,
                "presigned_url": presigned_url,
                "url": s.url,
                "tool": s.tool,
                "file_size_bytes": s.file_size_bytes,
                "captured_at": s.captured_at.isoformat() if s.captured_at else None,
                "host": row.asm_hosts.ip_address,
                "port": row.asm_services.port,
            }
        )
    return jsonify({"screenshots": result, "total": len(result)}), 200


@asm_bp.route("/scans/<int:scan_id>/certs", methods=["GET"])
@jwt_required
def get_asm_scan_certs(scan_id: int):
    """Get TLS certificate findings for a scan."""
    db = get_configured_db()
    if not db.asm_scans[scan_id]:
        return jsonify({"error": "Scan not found"}), 404

    certs = db(
        (db.asm_certs.service_id == db.asm_services.id)
        & (db.asm_services.host_id == db.asm_hosts.id)
        & (db.asm_hosts.scan_id == scan_id)
    ).select(db.asm_certs.ALL, db.asm_services.port, db.asm_hosts.ip_address)

    result = []
    for row in certs:
        c = row.asm_certs
        result.append(
            {
                "id": c.id,
                "subject": c.subject,
                "issuer": c.issuer,
                "not_before": c.not_before.isoformat() if c.not_before else None,
                "not_after": c.not_after.isoformat() if c.not_after else None,
                "is_expired": c.is_expired,
                "days_until_expiry": c.days_until_expiry,
                "sans": c.sans,
                "fingerprint_sha256": c.fingerprint_sha256,
                "host": row.asm_hosts.ip_address,
                "port": row.asm_services.port,
            }
        )
    return jsonify({"certs": result, "total": len(result)}), 200


@asm_bp.route("/scans/<int:scan_id>/diff", methods=["GET"])
@jwt_required
def get_asm_scan_diff(scan_id: int):
    """Get diff between this scan and previous scan."""
    db = get_configured_db()
    if not db.asm_scans[scan_id]:
        return jsonify({"error": "Scan not found"}), 404

    diff = (
        db(db.asm_diffs.scan_id == scan_id)
        .select(orderby=~db.asm_diffs.created_at, limitby=(0, 1))
        .first()
    )

    if not diff:
        return (
            jsonify({"message": "No diff available for this scan", "scan_id": scan_id}),
            200,
        )

    return (
        jsonify(
            {
                "id": diff.id,
                "scan_id": diff.scan_id,
                "prev_scan_id": diff.prev_scan_id,
                "new_services": diff.new_services or [],
                "removed_services": diff.removed_services or [],
                "new_certs": diff.new_certs or [],
                "expired_certs": diff.expired_certs or [],
                "created_at": diff.created_at.isoformat() if diff.created_at else None,
            }
        ),
        200,
    )


@asm_bp.route("/scans/<int:scan_id>/report", methods=["GET"])
@jwt_required
def get_asm_scan_report(scan_id: int):
    """Get presigned S3 URL for full scan JSON report."""
    scan = get_configured_db().asm_scans[scan_id]
    if not scan:
        return jsonify({"error": "Scan not found"}), 404

    s3_key = f"reports/{scan_id}/report.json"
    presigned_url = _generate_presigned_url(s3_key, expires_in=3600)

    return (
        jsonify(
            {
                "scan_id": scan_id,
                "s3_key": s3_key,
                "presigned_url": presigned_url,
            }
        ),
        200,
    )


@asm_bp.route("/settings/ports", methods=["GET"])
@jwt_required
def get_port_settings():
    """Get current port configuration (default + extra)."""
    import yaml

    config_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "config", "scanner_defaults.yaml"
    )
    try:
        with open(config_path) as f:
            defaults = yaml.safe_load(f)
        default_ports = defaults.get("asm", {}).get("default_ports", [])
    except Exception:
        default_ports = []

    db = get_configured_db()
    extra_ports = _get_setting(db, "extra_ports", [])
    masscan_rate = _get_setting(db, "masscan_rate", 1000)

    return (
        jsonify(
            {
                "default_ports": default_ports,
                "extra_ports": extra_ports,
                "masscan_rate": masscan_rate,
                "effective_ports": sorted(set(default_ports) | set(extra_ports)),
            }
        ),
        200,
    )


@asm_bp.route("/settings/ports", methods=["PUT"])
@jwt_required
def update_port_settings():
    """Update extra ports and masscan rate (admin only).

    Request body:
        extra_ports (list[int]): Additional ports to scan
        masscan_rate (int): Masscan packets per second
    """
    try:
        data = _ports_schema.load(request.get_json() or {})
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.messages}), 400

    db = get_configured_db()
    _set_setting(db, "extra_ports", data["extra_ports"])
    _set_setting(db, "masscan_rate", data["masscan_rate"])
    db.commit()

    return (
        jsonify(
            {
                "extra_ports": data["extra_ports"],
                "masscan_rate": data["masscan_rate"],
                "message": "Port settings updated",
            }
        ),
        200,
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _serialize_scan(scan) -> dict[str, Any]:
    """Serialize an asm_scans PyDAL row to a dictionary."""
    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "mode": scan.mode,
        "status": scan.status,
        "ports_config": scan.ports_config,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "created_by": scan.created_by,
    }


def _get_setting(db, key: str, default: Any) -> Any:
    """Get a setting value from asm_settings table."""
    try:
        row = db(db.asm_settings.key == key).select().first()
        if row:
            return row.value
    except Exception:
        pass
    return default


def _set_setting(db, key: str, value: Any) -> None:
    """Upsert a setting in asm_settings table."""
    existing = db(db.asm_settings.key == key).select().first()
    if existing:
        db(db.asm_settings.key == key).update(
            value=value,
            updated_at=datetime.utcnow(),
        )
    else:
        db.asm_settings.insert(
            key=key,
            value=value,
            updated_at=datetime.utcnow(),
        )


def _generate_presigned_url(s3_key: str, expires_in: int = 3600) -> str | None:
    """Generate a presigned URL for an S3 key."""
    try:
        import asyncio

        from scanners.screenshot import ScreenshotScanner

        scanner = ScreenshotScanner(config={})
        loop = asyncio.new_event_loop()
        url = loop.run_until_complete(
            scanner.generate_presigned_url(s3_key, expires_in)
        )
        loop.close()
        return url
    except Exception as e:
        logger.warning(f"Could not generate presigned URL for {s3_key}: {e}")
        return None
