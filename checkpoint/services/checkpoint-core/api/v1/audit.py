"""
checkpoint-core — Audit log read API.

Blueprint: audit_bp, prefix /api/v1/audit

Endpoints:
  GET /api/v1/audit  — list audit log entries (requires checkpoint:audit:read)

Query params:
  event_type   — filter by exact event_type string
  actor_uuid   — filter by actor UUID
  target_uuid  — filter by target UUID
  client_id    — filter by OAuth2 client_id
  from_ts      — ISO-8601 timestamp lower bound (inclusive)
  to_ts        — ISO-8601 timestamp upper bound (inclusive)
  page         — zero-based page index (default 0)
  per_page     — items per page (default 50, max 500)
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from quart import Blueprint, current_app, jsonify, request

from oidc.jwt_utils import verify_token

logger = logging.getLogger(__name__)

audit_bp = Blueprint("audit", __name__, url_prefix="/api/v1/audit")


# ── App extension helpers ──────────────────────────────────────────────────────


def _get_db() -> Any:
    return current_app.extensions["checkpoint_db"]


def _get_config() -> Any:
    return current_app.extensions["checkpoint_config"]


async def _get_token_claims() -> dict[str, Any] | None:
    db = _get_db()
    cfg = _get_config()
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        return verify_token(db, cfg.issuer_url, auth[7:])
    except Exception:  # noqa: BLE001
        return None


def _require_audit_read(fn):  # type: ignore[return]
    """Decorator enforcing checkpoint:audit:read scope."""
    import functools

    @functools.wraps(fn)
    async def wrapper(*args: Any, **kwargs: Any) -> Any:
        claims = await _get_token_claims()
        if claims is None:
            return jsonify({"error": "unauthorized"}), 401
        scopes = set((claims.get("scope") or "").split())
        if "checkpoint:audit:read" not in scopes and "checkpoint:admin" not in scopes:
            return jsonify({"error": "insufficient_scope"}), 403
        return await fn(*args, **kwargs)

    return wrapper


# ── Serialiser ────────────────────────────────────────────────────────────────


def _serialise_entry(row: Any) -> dict[str, Any]:
    """Convert a PyDAL audit log row to a response dict."""
    return {
        "id": row.id,
        "event_type": row.event_type,
        "actor_uuid": row.actor_uuid or None,
        "actor_ip": row.actor_ip or None,
        "target_uuid": row.target_uuid or None,
        "target_type": row.target_type or None,
        "client_id": row.client_id or None,
        "scopes": row.scopes or None,
        "details": row.details_json or "{}",
        "created_at": row.created_at.isoformat() + "Z" if row.created_at else None,
    }


def _parse_ts(value: str) -> datetime | None:
    """
    Parse an ISO-8601 timestamp string to a naive UTC datetime.

    Returns None on parse failure (permissive — don't crash on bad filter).
    """
    if not value:
        return None
    try:
        # Accept both "2025-01-01T00:00:00Z" and "2025-01-01T00:00:00+00:00"
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    except (ValueError, OverflowError):
        return None


# ── Endpoints ─────────────────────────────────────────────────────────────────


@audit_bp.route("", methods=["GET"])
@_require_audit_read
async def list_audit_entries() -> Any:
    """
    Return a paginated, filtered list of audit log entries.

    All filter parameters are optional. Multiple filters are AND-ed together.
    """
    db = _get_db()

    try:
        page = max(0, int(request.args.get("page", 0)))
    except (ValueError, TypeError):
        page = 0
    try:
        per_page = min(500, max(1, int(request.args.get("per_page", 50))))
    except (ValueError, TypeError):
        per_page = 50
    offset = page * per_page

    event_type = request.args.get("event_type", "").strip()
    actor_uuid = request.args.get("actor_uuid", "").strip()
    target_uuid = request.args.get("target_uuid", "").strip()
    client_id = request.args.get("client_id", "").strip()
    from_ts_str = request.args.get("from_ts", "").strip()
    to_ts_str = request.args.get("to_ts", "").strip()

    # Build the PyDAL query expression
    tbl = db.checkpoint_audit_log
    query = tbl.id > 0  # base condition — always true

    if event_type:
        query &= tbl.event_type == event_type
    if actor_uuid:
        query &= tbl.actor_uuid == actor_uuid
    if target_uuid:
        query &= tbl.target_uuid == target_uuid
    if client_id:
        query &= tbl.client_id == client_id

    from_dt = _parse_ts(from_ts_str)
    if from_dt is not None:
        query &= tbl.created_at >= from_dt

    to_dt = _parse_ts(to_ts_str)
    if to_dt is not None:
        query &= tbl.created_at <= to_dt

    total = db(query).count()
    rows = db(query).select(
        orderby=~tbl.created_at,  # newest first
        limitby=(offset, offset + per_page),
    )

    return jsonify({
        "entries": [_serialise_entry(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    })
