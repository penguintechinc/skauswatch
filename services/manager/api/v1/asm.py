"""
ASM (Attack Surface Management) API proxy endpoints.

Proxies all ASM requests to the worker-scanner service with authentication.
"""

import os

import httpx
from api.v1.auth import auth_required, role_required
from quart import Blueprint, jsonify, request

bp = Blueprint("asm", __name__)

WORKER_SCANNER_URL = os.environ.get("WORKER_SCANNER_URL", "http://worker-scanner:5001")
ASM_BASE = f"{WORKER_SCANNER_URL}/api/v1/asm"


async def _proxy(method: str, path: str, **kwargs) -> tuple:
    """Forward a request to worker-scanner's ASM API.

    Args:
        method: HTTP method (GET, POST, PUT)
        path: Path suffix after /api/v1/asm
        **kwargs: Additional httpx request arguments

    Returns:
        Tuple of (response dict, status code)
    """
    url = f"{ASM_BASE}{path}"
    # Forward auth header
    headers = {}
    auth_header = request.headers.get("Authorization")
    if auth_header:
        headers["Authorization"] = auth_header

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.request(method, url, headers=headers, **kwargs)
            try:
                data = resp.json()
            except Exception:
                data = {"raw": resp.text}
            return jsonify(data), resp.status_code
    except httpx.TimeoutException:
        return jsonify({"error": "Worker scanner timeout"}), 504
    except httpx.ConnectError:
        return jsonify({"error": "Cannot connect to worker-scanner"}), 503
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Scan endpoints ──────────────────────────────────────────────────────────


@bp.route("/scans", methods=["POST"])
@auth_required
async def create_asm_scan():
    """Trigger a new ASM scan."""
    body = await request.get_json()
    return await _proxy("POST", "/scans", json=body or {})


@bp.route("/scans", methods=["GET"])
@auth_required
async def list_asm_scans():
    """List ASM scans."""
    params = dict(request.args)
    return await _proxy("GET", "/scans", params=params)


@bp.route("/scans/<int:scan_id>", methods=["GET"])
@auth_required
async def get_asm_scan(scan_id: int):
    """Get ASM scan detail."""
    return await _proxy("GET", f"/scans/{scan_id}")


@bp.route("/scans/<int:scan_id>/hosts", methods=["GET"])
@auth_required
async def get_asm_scan_hosts(scan_id: int):
    """Get discovered hosts and services."""
    return await _proxy("GET", f"/scans/{scan_id}/hosts")


@bp.route("/scans/<int:scan_id>/screenshots", methods=["GET"])
@auth_required
async def get_asm_scan_screenshots(scan_id: int):
    """Get screenshots with presigned URLs."""
    return await _proxy("GET", f"/scans/{scan_id}/screenshots")


@bp.route("/scans/<int:scan_id>/certs", methods=["GET"])
@auth_required
async def get_asm_scan_certs(scan_id: int):
    """Get TLS certificate findings."""
    return await _proxy("GET", f"/scans/{scan_id}/certs")


@bp.route("/scans/<int:scan_id>/diff", methods=["GET"])
@auth_required
async def get_asm_scan_diff(scan_id: int):
    """Get diff vs previous scan."""
    return await _proxy("GET", f"/scans/{scan_id}/diff")


@bp.route("/scans/<int:scan_id>/report", methods=["GET"])
@auth_required
async def get_asm_scan_report(scan_id: int):
    """Get presigned URL for full scan report."""
    return await _proxy("GET", f"/scans/{scan_id}/report")


# ── Settings endpoints ────────────────────────────────────────────────────────


@bp.route("/settings/ports", methods=["GET"])
@auth_required
async def get_port_settings():
    """Get port configuration."""
    return await _proxy("GET", "/settings/ports")


@bp.route("/settings/ports", methods=["PUT"])
@auth_required
@role_required("admin")
async def update_port_settings():
    """Update port settings (admin only)."""
    body = await request.get_json()
    return await _proxy("PUT", "/settings/ports", json=body or {})
