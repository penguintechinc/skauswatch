"""Darwin AI Code Review proxy endpoints.

Proxies all Darwin requests to the worker-darwin service with authentication
and license gating (Point A — manager-level license check).

Architecture:
    WebUI → /api/v1/darwin/* (Manager, Quart)
                     ↓ httpx proxy (timeout=120s)
          worker-darwin:5005 (Flask + Celery)
"""

import os

import httpx
from api.v1.auth import auth_required, role_required
from quart import Blueprint, jsonify, request

bp = Blueprint("darwin", __name__)

WORKER_DARWIN_URL = os.environ.get("WORKER_DARWIN_URL", "http://worker-darwin:5005")
DARWIN_BASE = f"{WORKER_DARWIN_URL}/api/v1/darwin"


def _check_darwin_license() -> tuple[bool, object]:
    """Check if the darwin feature is licensed.

    Returns:
        Tuple of (allowed: bool, error_response or None)
    """
    try:
        from penguin_licensing import get_license_client

        lc = get_license_client()
        if not lc.has_feature("darwin"):
            return False, (
                jsonify({"error": "Darwin AI review requires a Darwin license."}),
                403,
            )
    except Exception:
        pass  # dev mode / license server unreachable → allow through
    return True, None


async def _proxy(method: str, path: str, **kwargs) -> tuple:
    """Forward a request to worker-darwin's Darwin API.

    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        path: Path suffix after /api/v1/darwin
        **kwargs: Additional httpx request arguments

    Returns:
        Tuple of (response, status_code)
    """
    url = f"{DARWIN_BASE}{path}"

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
        return jsonify({"error": "worker-darwin timeout"}), 504
    except httpx.ConnectError:
        return jsonify({"error": "Cannot connect to worker-darwin"}), 503
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


# ── Status ───────────────────────────────────────────────────────────────────


@bp.route("/status", methods=["GET"])
@auth_required
async def darwin_status():
    """Get Darwin service status."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    return await _proxy("GET", "/status")


# ── Repositories ─────────────────────────────────────────────────────────────


@bp.route("/repos", methods=["GET"])
@auth_required
async def list_repos():
    """List repository configurations."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    params = dict(request.args)
    return await _proxy("GET", "/repos", params=params)


@bp.route("/repos", methods=["POST"])
@auth_required
@role_required("admin")
async def create_repo():
    """Add a repository configuration (admin only)."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    body = await request.get_json()
    return await _proxy("POST", "/repos", json=body or {})


@bp.route("/repos/<int:repo_id>", methods=["GET"])
@auth_required
async def get_repo(repo_id: int):
    """Get a repository configuration."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    return await _proxy("GET", f"/repos/{repo_id}")


@bp.route("/repos/<int:repo_id>", methods=["PUT"])
@auth_required
@role_required("admin")
async def update_repo(repo_id: int):
    """Update a repository configuration (admin only)."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    body = await request.get_json()
    return await _proxy("PUT", f"/repos/{repo_id}", json=body or {})


@bp.route("/repos/<int:repo_id>", methods=["DELETE"])
@auth_required
@role_required("admin")
async def delete_repo(repo_id: int):
    """Delete a repository configuration (admin only)."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    return await _proxy("DELETE", f"/repos/{repo_id}")


# ── Reviews ───────────────────────────────────────────────────────────────────


@bp.route("/reviews", methods=["GET"])
@auth_required
async def list_reviews():
    """List code reviews."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    params = dict(request.args)
    return await _proxy("GET", "/reviews", params=params)


@bp.route("/reviews", methods=["POST"])
@auth_required
@role_required("maintainer")
async def create_review():
    """Queue a new code review (maintainer+)."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    body = await request.get_json()
    return await _proxy("POST", "/reviews", json=body or {})


@bp.route("/reviews/<int:review_id>", methods=["GET"])
@auth_required
async def get_review(review_id: int):
    """Get a code review with comments."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    return await _proxy("GET", f"/reviews/{review_id}")


# ── Issue Plans ───────────────────────────────────────────────────────────────


@bp.route("/plans", methods=["GET"])
@auth_required
async def list_plans():
    """List issue plans."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    params = dict(request.args)
    return await _proxy("GET", "/plans", params=params)


@bp.route("/plans", methods=["POST"])
@auth_required
async def create_plan():
    """Queue a new issue plan generation."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    body = await request.get_json()
    return await _proxy("POST", "/plans", json=body or {})


@bp.route("/plans/<int:plan_id>", methods=["GET"])
@auth_required
async def get_plan(plan_id: int):
    """Get an issue plan."""
    allowed, err = _check_darwin_license()
    if not allowed:
        return err
    return await _proxy("GET", f"/plans/{plan_id}")
