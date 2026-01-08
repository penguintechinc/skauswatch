"""
Approval workflow API endpoints.

Provides:
- Create approval requests
- List pending approvals
- Approve/reject requests
- Approval history
"""

from datetime import datetime, timedelta
from typing import List, Optional

from pydantic import ValidationError
from quart import Blueprint, current_app, g, jsonify, request

from ...models.db import get_db
from ...validators.pydantic_models import (
    ApprovalCreateRequest,
    ApprovalDecisionRequest,
    ApprovalResponse,
    ApprovalStatus,
    ApprovalType,
)
from .auth import auth_required, role_required

bp = Blueprint("approvals", __name__)


@bp.route("", methods=["GET"])
@auth_required
async def list_approvals():
    """List approval requests with pagination and filtering."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Get pagination params
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    per_page = min(per_page, 100)

    # Get filter params
    status = request.args.getlist("status")
    request_type = request.args.getlist("type")
    requester_id = request.args.get("requester_id", type=int)

    offset = (page - 1) * per_page

    # Build query
    query = db.approval_requests

    if status:
        query = query & (db.approval_requests.status.belongs(status))
    if request_type:
        query = query & (db.approval_requests.request_type.belongs(request_type))
    if requester_id:
        query = query & (db.approval_requests.requester_id == requester_id)

    # Execute query
    approvals = db(query).select(
        orderby=~db.approval_requests.created_at,
        limitby=(offset, offset + per_page),
    )
    total = db(query).count()

    # Convert to response format
    approval_list = []
    for approval in approvals:
        approval_list.append({
            "id": approval.id,
            "request_type": approval.request_type,
            "resource_id": approval.resource_id,
            "resource_type": approval.resource_type,
            "requester_id": approval.requester_id,
            "status": approval.status,
            "required_approvals": approval.required_approvals,
            "current_approvals": approval.current_approvals,
            "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
            "created_at": approval.created_at.isoformat() if approval.created_at else None,
        })

    return jsonify({
        "items": approval_list,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": (total + per_page - 1) // per_page,
    }), 200


@bp.route("/pending", methods=["GET"])
@auth_required
@role_required("admin", "maintainer")
async def list_pending_approvals():
    """List pending approvals for the current user to review."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Get pending approvals that haven't expired
    approvals = db(
        (db.approval_requests.status == "pending") &
        (
            (db.approval_requests.expires_at == None) |
            (db.approval_requests.expires_at > datetime.utcnow())
        )
    ).select(orderby=~db.approval_requests.created_at)

    approval_list = []
    for approval in approvals:
        # Check if current user hasn't already approved
        approval_history = approval.approval_history or []
        already_approved = any(
            h.get("user_id") == g.current_user_id
            for h in approval_history
        )

        if not already_approved:
            approval_list.append({
                "id": approval.id,
                "request_type": approval.request_type,
                "resource_id": approval.resource_id,
                "resource_type": approval.resource_type,
                "requester_id": approval.requester_id,
                "status": approval.status,
                "required_approvals": approval.required_approvals,
                "current_approvals": approval.current_approvals,
                "metadata": approval.metadata or {},
                "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
                "created_at": approval.created_at.isoformat() if approval.created_at else None,
            })

    return jsonify({"items": approval_list, "count": len(approval_list)}), 200


@bp.route("/<int:approval_id>", methods=["GET"])
@auth_required
async def get_approval(approval_id: int):
    """Get approval request by ID."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    approval = db(db.approval_requests.id == approval_id).select().first()
    if not approval:
        return jsonify({"error": "Approval request not found"}), 404

    return jsonify({
        "id": approval.id,
        "request_type": approval.request_type,
        "resource_id": approval.resource_id,
        "resource_type": approval.resource_type,
        "requester_id": approval.requester_id,
        "status": approval.status,
        "required_approvals": approval.required_approvals,
        "current_approvals": approval.current_approvals,
        "approvers": approval.approvers or [],
        "approval_history": approval.approval_history or [],
        "metadata": approval.metadata or {},
        "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
        "completed_at": approval.completed_at.isoformat() if approval.completed_at else None,
        "created_at": approval.created_at.isoformat() if approval.created_at else None,
        "updated_at": approval.updated_at.isoformat() if approval.updated_at else None,
    }), 200


@bp.route("", methods=["POST"])
@auth_required
async def create_approval():
    """Create a new approval request."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        create_data = ApprovalCreateRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    # Calculate expiration
    expires_at = datetime.utcnow() + timedelta(hours=create_data.expires_hours)

    # Create approval request
    approval_id = db.approval_requests.insert(
        request_type=create_data.request_type.value,
        resource_id=create_data.resource_id,
        resource_type=create_data.resource_type,
        requester_id=g.current_user_id,
        status="pending",
        required_approvals=create_data.required_approvals,
        current_approvals=0,
        approvers=[],
        approval_history=[],
        metadata=create_data.metadata,
        expires_at=expires_at,
    )
    db.commit()

    approval = db(db.approval_requests.id == approval_id).select().first()

    return jsonify({
        "message": "Approval request created",
        "approval": {
            "id": approval.id,
            "request_type": approval.request_type,
            "resource_id": approval.resource_id,
            "status": approval.status,
            "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
            "created_at": approval.created_at.isoformat() if approval.created_at else None,
        },
    }), 201


@bp.route("/<int:approval_id>/decide", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
async def decide_approval(approval_id: int):
    """Approve or reject an approval request."""
    config = current_app.config["MANAGER_CONFIG"]

    try:
        data = await request.get_json()
        decision_data = ApprovalDecisionRequest(**data)
    except ValidationError as e:
        return jsonify({"error": "Validation error", "details": e.errors()}), 400

    db = get_db(config.database.uri)

    approval = db(db.approval_requests.id == approval_id).select().first()
    if not approval:
        return jsonify({"error": "Approval request not found"}), 404

    # Check if already completed
    if approval.status != "pending":
        return jsonify({"error": f"Approval request already {approval.status}"}), 400

    # Check if expired
    if approval.expires_at and approval.expires_at <= datetime.utcnow():
        db(db.approval_requests.id == approval_id).update(status="expired")
        db.commit()
        return jsonify({"error": "Approval request has expired"}), 400

    # Check if user is the requester
    if approval.requester_id == g.current_user_id:
        return jsonify({"error": "Cannot approve your own request"}), 403

    # Check if user already decided
    approval_history = approval.approval_history or []
    if any(h.get("user_id") == g.current_user_id for h in approval_history):
        return jsonify({"error": "You have already made a decision on this request"}), 400

    # Add decision to history
    decision_record = {
        "user_id": g.current_user_id,
        "user_email": g.current_user["email"],
        "approved": decision_data.approved,
        "reason": decision_data.reason,
        "timestamp": datetime.utcnow().isoformat(),
    }
    approval_history.append(decision_record)

    if decision_data.approved:
        # Increment approval count
        new_approval_count = approval.current_approvals + 1
        approvers = approval.approvers or []
        approvers.append(g.current_user_id)

        updates = {
            "current_approvals": new_approval_count,
            "approvers": approvers,
            "approval_history": approval_history,
        }

        # Check if fully approved
        if new_approval_count >= approval.required_approvals:
            updates["status"] = "approved"
            updates["completed_at"] = datetime.utcnow()
    else:
        # Rejection
        updates = {
            "status": "rejected",
            "approval_history": approval_history,
            "completed_at": datetime.utcnow(),
        }

    db(db.approval_requests.id == approval_id).update(**updates)
    db.commit()

    # Fetch updated approval
    approval = db(db.approval_requests.id == approval_id).select().first()

    return jsonify({
        "message": "Decision recorded",
        "approval": {
            "id": approval.id,
            "status": approval.status,
            "current_approvals": approval.current_approvals,
            "required_approvals": approval.required_approvals,
            "completed_at": approval.completed_at.isoformat() if approval.completed_at else None,
        },
    }), 200


@bp.route("/<int:approval_id>/cancel", methods=["POST"])
@auth_required
async def cancel_approval(approval_id: int):
    """Cancel an approval request (by requester or admin)."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    approval = db(db.approval_requests.id == approval_id).select().first()
    if not approval:
        return jsonify({"error": "Approval request not found"}), 404

    # Check permissions
    is_requester = approval.requester_id == g.current_user_id
    is_admin = g.current_user["role"] == "admin"

    if not is_requester and not is_admin:
        return jsonify({"error": "Forbidden"}), 403

    # Check if already completed
    if approval.status != "pending":
        return jsonify({"error": f"Cannot cancel {approval.status} request"}), 400

    # Cancel the request
    db(db.approval_requests.id == approval_id).update(
        status="rejected",
        completed_at=datetime.utcnow(),
    )
    db.commit()

    return jsonify({"message": "Approval request cancelled"}), 200


@bp.route("/statistics", methods=["GET"])
@auth_required
@role_required("admin", "maintainer")
async def get_statistics():
    """Get approval statistics."""
    config = current_app.config["MANAGER_CONFIG"]
    db = get_db(config.database.uri)

    # Count by status
    status_counts = {}
    for status in ApprovalStatus:
        count = db(db.approval_requests.status == status.value).count()
        status_counts[status.value] = count

    # Count by type
    type_counts = {}
    for req_type in ApprovalType:
        count = db(db.approval_requests.request_type == req_type.value).count()
        type_counts[req_type.value] = count

    # Count expired (pending but past expiration)
    expired_count = db(
        (db.approval_requests.status == "pending") &
        (db.approval_requests.expires_at != None) &
        (db.approval_requests.expires_at <= datetime.utcnow())
    ).count()

    # Recent activity (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_count = db(db.approval_requests.created_at >= week_ago).count()

    return jsonify({
        "total": db(db.approval_requests).count(),
        "by_status": status_counts,
        "by_type": type_counts,
        "expired_pending": expired_count,
        "last_7_days": recent_count,
    }), 200
