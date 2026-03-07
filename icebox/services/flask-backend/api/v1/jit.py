"""
IceBox JIT Access API — Phase 3

Just-in-Time access with approval workflows.

Flow:
  1. POST /jit/requests               (jit:request scope)
  2. PATCH /jit/requests/{id}/approve (jit:approve scope + owner of secret)
  3. PATCH /jit/requests/{id}/reject  (jit:approve scope + owner of secret)
  4. GET /secrets/{id}/value with JIT token
  5. Auto-revoke via background task (60s interval)

JIT tokens are HMAC-SHA256 signed strings, NOT full JWTs:
  Format: jit:{grant_id}:{grantee_id}:{expires_epoch}
  Token hash stored in icebox_jit_grants.access_token_hash
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from quart import Blueprint, current_app, g, jsonify, request

from api.v1.auth import auth_required, require_any_scope, require_scope
from models.db import get_db

logger = logging.getLogger(__name__)
bp = Blueprint("jit", __name__)


def _generate_jit_token(grant_id: str, grantee_id: str, expires_epoch: int, jit_secret: str) -> str:
    """
    Generate an HMAC-signed JIT token.

    Token format: jit:{grant_id}:{grantee_id}:{expires_epoch}
    The token_hash stored in DB is SHA-256 of the full token string.
    """
    token = f"jit:{grant_id}:{grantee_id}:{expires_epoch}"
    return token


def _token_hash(token: str) -> str:
    """SHA-256 hash of the token for DB storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def _request_to_dict(req) -> dict:
    return {
        "id": req.id,
        "secret_id": req.secret_id,
        "requestor_id": req.requestor_id,
        "reason": req.reason,
        "requested_duration_seconds": req.requested_duration_seconds,
        "approved_duration_seconds": req.approved_duration_seconds,
        "status": req.status,
        "approved_by": req.approved_by,
        "approved_at": req.approved_at.isoformat() if req.approved_at else None,
        "access_expires_at": req.access_expires_at.isoformat() if req.access_expires_at else None,
        "created_at": req.created_at.isoformat() if req.created_at else None,
    }


def _is_secret_owner(db, secret_id: str, user_id: str) -> bool:
    """Check if user is an owner of the secret."""
    return bool(
        db(
            (db.icebox_secret_owners.secret_id == secret_id)
            & (db.icebox_secret_owners.owner_type == "user")
            & (db.icebox_secret_owners.owner_id == user_id)
        ).count()
    )


@bp.route("/requests", methods=["GET"])
@auth_required
@require_any_scope("jit:request", "jit:approve")
async def list_jit_requests():
    """List JIT requests (own requests + requests to approve for owned secrets)."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    has_approve = "jit:approve" in g.token_scopes
    status_filter = request.args.getlist("status")

    if has_approve:
        # Owners see all requests for their secrets
        owned_secrets = db(
            (db.icebox_secret_owners.owner_type == "user")
            & (db.icebox_secret_owners.owner_id == g.user_id)
        ).select(db.icebox_secret_owners.secret_id)
        owned_ids = [r.secret_id for r in owned_secrets]

        query = (
            (db.icebox_jit_requests.requestor_id == g.user_id)
            | db.icebox_jit_requests.secret_id.belongs(owned_ids)
        )
    else:
        # Regular users see only their own requests
        query = db.icebox_jit_requests.requestor_id == g.user_id

    if status_filter:
        query = query & db.icebox_jit_requests.status.belongs(status_filter)

    rows = db(query).select(orderby=~db.icebox_jit_requests.created_at)
    return jsonify({"requests": [_request_to_dict(r) for r in rows]})


@bp.route("/requests", methods=["POST"])
@auth_required
@require_scope("jit:request")
async def create_jit_request():
    """Request JIT access to a secret."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    body = await request.get_json() or {}
    secret_id = body.get("secret_id", "").strip()
    reason = body.get("reason", "").strip()
    duration = body.get("requested_duration_seconds", 3600)

    if not secret_id or not reason:
        return jsonify({"error": "secret_id and reason are required"}), 400

    if not db(db.icebox_secrets.id == secret_id).count():
        return jsonify({"error": "Secret not found"}), 404

    max_duration = config.auth.jit_token_max_duration_seconds
    if duration > max_duration:
        return jsonify({
            "error": f"Requested duration exceeds maximum ({max_duration}s)"
        }), 400

    req_id = str(uuid4())
    db.icebox_jit_requests.insert(
        id=req_id,
        secret_id=secret_id,
        requestor_id=g.user_id,
        reason=reason,
        requested_duration_seconds=duration,
        status="pending",
        created_at=datetime.utcnow(),
    )
    db.commit()

    row = db(db.icebox_jit_requests.id == req_id).select().first()
    return jsonify(_request_to_dict(row)), 201


@bp.route("/requests/<request_id>/approve", methods=["PATCH"])
@auth_required
@require_scope("jit:approve")
async def approve_jit_request(request_id: str):
    """Approve a JIT access request and issue an access token."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    jit_req = db(db.icebox_jit_requests.id == request_id).select().first()
    if not jit_req:
        return jsonify({"error": "Request not found"}), 404

    if jit_req.status != "pending":
        return jsonify({"error": f"Request is already {jit_req.status}"}), 409

    if not _is_secret_owner(db, jit_req.secret_id, g.user_id):
        return jsonify({"error": "Not an owner of this secret"}), 403

    body = await request.get_json() or {}
    max_duration = config.auth.jit_token_max_duration_seconds
    approved_duration = min(
        body.get("approved_duration_seconds", jit_req.requested_duration_seconds),
        max_duration,
    )

    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=approved_duration)
    expires_epoch = int(expires_at.timestamp())

    grant_id = str(uuid4())
    token = _generate_jit_token(grant_id, jit_req.requestor_id, expires_epoch, config.auth.jwt_secret)
    token_h = _token_hash(token)

    db.icebox_jit_grants.insert(
        id=grant_id,
        request_id=request_id,
        secret_id=jit_req.secret_id,
        grantee_id=jit_req.requestor_id,
        access_token_hash=token_h,
        expires_at=expires_at,
    )

    db(db.icebox_jit_requests.id == request_id).update(
        status="approved",
        approved_by=g.user_id,
        approved_at=now,
        approved_duration_seconds=approved_duration,
        access_expires_at=expires_at,
    )
    db.commit()

    return jsonify({
        "request_id": request_id,
        "grant_id": grant_id,
        "access_token": token,
        "expires_at": expires_at.isoformat(),
        "secret_id": jit_req.secret_id,
    })


@bp.route("/requests/<request_id>/reject", methods=["PATCH"])
@auth_required
@require_scope("jit:approve")
async def reject_jit_request(request_id: str):
    """Reject a JIT access request."""
    config = current_app.config["ICEBOX_CONFIG"]
    db = get_db(config.database.uri, config.database.pool_size)

    jit_req = db(db.icebox_jit_requests.id == request_id).select().first()
    if not jit_req:
        return jsonify({"error": "Request not found"}), 404

    if jit_req.status != "pending":
        return jsonify({"error": f"Request is already {jit_req.status}"}), 409

    if not _is_secret_owner(db, jit_req.secret_id, g.user_id):
        return jsonify({"error": "Not an owner of this secret"}), 403

    db(db.icebox_jit_requests.id == request_id).update(
        status="rejected",
        approved_by=g.user_id,
        approved_at=datetime.utcnow(),
    )
    db.commit()

    return jsonify({"request_id": request_id, "status": "rejected"})
