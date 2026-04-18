"""
checkpoint-core — Users and Groups REST API.

Blueprint: users_groups_bp, prefix /api/v1

Proxies identity operations to skauswatch-core via CoreIdentityClient.
checkpoint-core never owns identity data — it always delegates.

Scopes:
  checkpoint:users:read    — list/get users
  checkpoint:users:write   — create/update users
  checkpoint:users:delete  — delete users
  checkpoint:groups:read   — list/get groups
  checkpoint:groups:write  — create/update/delete groups, manage membership
"""
from __future__ import annotations

import logging
from typing import Any

from quart import Blueprint, current_app, jsonify, request

from audit.logger import AuditLogger
from checkpoint_grpc.core_client import CheckpointCoreError, CoreIdentityClient
from oidc.jwt_utils import verify_token

logger = logging.getLogger(__name__)

users_groups_bp = Blueprint("users_groups", __name__, url_prefix="/api/v1")


# ── App extension helpers ──────────────────────────────────────────────────────


def _get_db() -> Any:
    return current_app.extensions["checkpoint_db"]


def _get_config() -> Any:
    return current_app.extensions["checkpoint_config"]


def _get_audit() -> AuditLogger:
    return current_app.extensions["checkpoint_audit"]


def _get_core() -> CoreIdentityClient:
    return current_app.extensions["checkpoint_core_client"]


def _client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "")


# ── Auth helper ────────────────────────────────────────────────────────────────


async def _get_token_claims() -> dict[str, Any] | None:
    """Extract and verify Bearer token from Authorization header."""
    db = _get_db()
    cfg = _get_config()
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    raw_token = auth[7:]
    try:
        return verify_token(db, cfg.issuer_url, raw_token)
    except Exception:  # noqa: BLE001
        return None


def require_checkpoint_scope(*required_scopes: str):  # type: ignore[return]
    """
    Decorator that enforces one of the required scopes on the request token.

    At least one of *required_scopes* must be present in the token's scope claim.
    Also accepts checkpoint:admin as a super-scope.
    """
    import functools

    def decorator(fn):  # type: ignore[return]
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            claims = await _get_token_claims()
            if claims is None:
                return jsonify({"error": "unauthorized"}), 401
            token_scopes = set((claims.get("scope") or "").split())
            allowed = set(required_scopes) | {"checkpoint:admin"}
            if not (token_scopes & allowed):
                return jsonify({"error": "insufficient_scope"}), 403
            return await fn(*args, **kwargs)

        return wrapper

    return decorator


# ── User serialiser ────────────────────────────────────────────────────────────


def _serialise_user(user: Any) -> dict[str, Any]:
    """Convert a UserRecord (or proto user) to a safe response dict."""
    return {
        "uuid": user.uuid,
        "username": user.username,
        "email": user.email,
        "display_name": user.display_name,
        "is_active": user.is_active,
        "groups": list(getattr(user, "groups", [])),
        "attributes": dict(getattr(user, "attributes", {})),
    }


def _serialise_group(group: Any) -> dict[str, Any]:
    """Convert a GroupRecord to a safe response dict."""
    return {
        "uuid": group.uuid,
        "name": group.name,
        "description": getattr(group, "description", ""),
        "member_count": getattr(group, "member_count", 0),
    }


# ── User endpoints ─────────────────────────────────────────────────────────────


@users_groups_bp.route("/users", methods=["GET"])
@require_checkpoint_scope("checkpoint:users:read")
async def list_users() -> Any:
    """
    List users from skauswatch-core.

    Query params:
      page      — zero-based page index (default 0)
      per_page  — items per page (default 100, max 500)
      status    — "active" | "inactive" | "all" (default "all")
    """
    core = _get_core()
    page = max(0, int(request.args.get("page", 0)))
    per_page = min(500, max(1, int(request.args.get("per_page", 100))))
    status = request.args.get("status", "all").lower()

    filter_active: bool | None = None
    if status == "active":
        filter_active = True
    elif status == "inactive":
        filter_active = False

    try:
        users = await core.list_users(page=page, page_size=per_page, filter_active=filter_active)
    except CheckpointCoreError as exc:
        logger.error("list_users.rpc_error error=%r", exc)
        return jsonify({"error": "upstream identity service error"}), 502

    return jsonify({
        "users": [_serialise_user(u) for u in users],
        "page": page,
        "per_page": per_page,
    })


@users_groups_bp.route("/users/<string:user_uuid>", methods=["GET"])
@require_checkpoint_scope("checkpoint:users:read")
async def get_user(user_uuid: str) -> Any:
    """Get a single user by UUID."""
    core = _get_core()
    try:
        user = await core.get_user(uuid=user_uuid)
    except CheckpointCoreError as exc:
        logger.error("get_user.rpc_error uuid=%s error=%r", user_uuid, exc)
        return jsonify({"error": "upstream identity service error"}), 502

    if user is None:
        return jsonify({"error": "not found"}), 404

    return jsonify(_serialise_user(user))


@users_groups_bp.route("/users", methods=["POST"])
@require_checkpoint_scope("checkpoint:users:write")
async def create_user() -> Any:
    """
    Create a new user via skauswatch-core.

    Required body fields: username, email, display_name
    Optional: password, attributes (dict), group_uuids (list)
    """
    core = _get_core()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    data = await request.get_json() or {}

    username: str = (data.get("username") or "").strip()
    email: str = (data.get("email") or "").strip()
    display_name: str = (data.get("display_name") or "").strip()

    if not username:
        return jsonify({"error": "username is required"}), 400
    if not email:
        return jsonify({"error": "email is required"}), 400
    if not display_name:
        return jsonify({"error": "display_name is required"}), 400

    # Basic email format check
    if "@" not in email or "." not in email.split("@")[-1]:
        return jsonify({"error": "invalid email format"}), 400

    try:
        user = await core.create_user(
            username=username,
            email=email,
            display_name=display_name,
            password=data.get("password"),
            attributes=data.get("attributes") or {},
            group_uuids=data.get("group_uuids") or [],
        )
    except CheckpointCoreError as exc:
        logger.error("create_user.rpc_error error=%r", exc)
        return jsonify({"error": "upstream identity service error"}), 502

    await audit.log(
        "identity.user_created",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_uuid=user.uuid,
        target_type="user",
        details={"username": username},
    )

    return jsonify(_serialise_user(user)), 201


@users_groups_bp.route("/users/<string:user_uuid>", methods=["PUT"])
@require_checkpoint_scope("checkpoint:users:write")
async def update_user(user_uuid: str) -> Any:
    """Update user fields via skauswatch-core."""
    core = _get_core()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    data = await request.get_json() or {}
    if not data:
        return jsonify({"error": "no fields to update"}), 400

    try:
        user = await core.update_user(uuid=user_uuid, fields=data)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return jsonify({"error": "not found"}), 404
        logger.error("update_user.rpc_error uuid=%s error=%r", user_uuid, exc)
        return jsonify({"error": "upstream identity service error"}), 502

    await audit.log(
        "identity.user_updated",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_uuid=user_uuid,
        target_type="user",
        details={"fields_updated": list(data.keys())},
    )

    return jsonify(_serialise_user(user))


@users_groups_bp.route("/users/<string:user_uuid>", methods=["DELETE"])
@require_checkpoint_scope("checkpoint:users:delete")
async def delete_user(user_uuid: str) -> Any:
    """Delete (deprovision) a user via skauswatch-core."""
    core = _get_core()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    try:
        await core.delete_user(uuid=user_uuid)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return jsonify({"error": "not found"}), 404
        logger.error("delete_user.rpc_error uuid=%s error=%r", user_uuid, exc)
        return jsonify({"error": "upstream identity service error"}), 502

    await audit.log(
        "identity.user_deleted",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_uuid=user_uuid,
        target_type="user",
        details={},
    )

    return jsonify({"status": "deleted"}), 200


# ── Group endpoints ────────────────────────────────────────────────────────────


@users_groups_bp.route("/groups", methods=["GET"])
@require_checkpoint_scope("checkpoint:groups:read")
async def list_groups() -> Any:
    """List groups from skauswatch-core."""
    core = _get_core()
    page = max(0, int(request.args.get("page", 0)))
    per_page = min(500, max(1, int(request.args.get("per_page", 100))))

    try:
        groups = await core.list_groups(page=page, page_size=per_page)
    except CheckpointCoreError as exc:
        logger.error("list_groups.rpc_error error=%r", exc)
        return jsonify({"error": "upstream identity service error"}), 502

    return jsonify({
        "groups": [_serialise_group(g) for g in groups],
        "page": page,
        "per_page": per_page,
    })


@users_groups_bp.route("/groups/<string:group_uuid>", methods=["GET"])
@require_checkpoint_scope("checkpoint:groups:read")
async def get_group(group_uuid: str) -> Any:
    """Get a single group by UUID."""
    core = _get_core()
    try:
        group = await core.get_group(uuid=group_uuid)
    except CheckpointCoreError as exc:
        logger.error("get_group.rpc_error uuid=%s error=%r", group_uuid, exc)
        return jsonify({"error": "upstream identity service error"}), 502

    if group is None:
        return jsonify({"error": "not found"}), 404

    return jsonify(_serialise_group(group))


@users_groups_bp.route("/groups", methods=["POST"])
@require_checkpoint_scope("checkpoint:groups:write")
async def create_group() -> Any:
    """Create a new group via skauswatch-core."""
    core = _get_core()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    data = await request.get_json() or {}
    name: str = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    try:
        group = await core.create_group(
            name=name,
            description=data.get("description") or "",
        )
    except CheckpointCoreError as exc:
        logger.error("create_group.rpc_error error=%r", exc)
        return jsonify({"error": "upstream identity service error"}), 502

    await audit.log(
        "identity.group_created",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_uuid=group.uuid,
        target_type="group",
        details={"name": name},
    )

    return jsonify(_serialise_group(group)), 201


@users_groups_bp.route("/groups/<string:group_uuid>", methods=["PUT"])
@require_checkpoint_scope("checkpoint:groups:write")
async def update_group(group_uuid: str) -> Any:
    """Update a group via skauswatch-core."""
    core = _get_core()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    data = await request.get_json() or {}
    if not data:
        return jsonify({"error": "no fields to update"}), 400

    try:
        group = await core.update_group(uuid=group_uuid, fields=data)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return jsonify({"error": "not found"}), 404
        logger.error("update_group.rpc_error uuid=%s error=%r", group_uuid, exc)
        return jsonify({"error": "upstream identity service error"}), 502

    await audit.log(
        "identity.group_updated",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_uuid=group_uuid,
        target_type="group",
        details={"fields_updated": list(data.keys())},
    )

    return jsonify(_serialise_group(group))


@users_groups_bp.route("/groups/<string:group_uuid>", methods=["DELETE"])
@require_checkpoint_scope("checkpoint:groups:write")
async def delete_group(group_uuid: str) -> Any:
    """Delete a group via skauswatch-core."""
    core = _get_core()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    try:
        await core.delete_group(uuid=group_uuid)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return jsonify({"error": "not found"}), 404
        logger.error("delete_group.rpc_error uuid=%s error=%r", group_uuid, exc)
        return jsonify({"error": "upstream identity service error"}), 502

    await audit.log(
        "identity.group_deleted",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_uuid=group_uuid,
        target_type="group",
        details={},
    )

    return jsonify({"status": "deleted"}), 200


@users_groups_bp.route("/groups/<string:group_uuid>/members", methods=["GET"])
@require_checkpoint_scope("checkpoint:groups:read")
async def list_group_members(group_uuid: str) -> Any:
    """List members of a group."""
    core = _get_core()
    try:
        members = await core.list_group_members(group_uuid=group_uuid)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return jsonify({"error": "not found"}), 404
        logger.error("list_group_members.rpc_error group=%s error=%r", group_uuid, exc)
        return jsonify({"error": "upstream identity service error"}), 502

    return jsonify({
        "group_uuid": group_uuid,
        "members": [_serialise_user(u) for u in members],
    })


@users_groups_bp.route("/groups/<string:group_uuid>/members", methods=["POST"])
@require_checkpoint_scope("checkpoint:groups:write")
async def add_group_member(group_uuid: str) -> Any:
    """Add a user to a group."""
    core = _get_core()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    data = await request.get_json() or {}
    user_uuid: str = (data.get("user_uuid") or "").strip()
    if not user_uuid:
        return jsonify({"error": "user_uuid is required"}), 400

    try:
        await core.add_membership(group_uuid=group_uuid, user_uuid=user_uuid)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return jsonify({"error": "not found"}), 404
        logger.error(
            "add_group_member.rpc_error group=%s user=%s error=%r",
            group_uuid, user_uuid, exc,
        )
        return jsonify({"error": "upstream identity service error"}), 502

    await audit.log(
        "identity.member_added",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_uuid=group_uuid,
        target_type="group",
        details={"user_uuid": user_uuid},
    )

    return jsonify({"status": "added", "group_uuid": group_uuid, "user_uuid": user_uuid}), 201


@users_groups_bp.route("/groups/<string:group_uuid>/members/<string:user_uuid>", methods=["DELETE"])
@require_checkpoint_scope("checkpoint:groups:write")
async def remove_group_member(group_uuid: str, user_uuid: str) -> Any:
    """Remove a user from a group."""
    core = _get_core()
    audit = _get_audit()
    claims = await _get_token_claims()
    actor_uuid = claims.get("sub") if claims else None

    try:
        await core.remove_membership(group_uuid=group_uuid, user_uuid=user_uuid)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return jsonify({"error": "not found"}), 404
        logger.error(
            "remove_group_member.rpc_error group=%s user=%s error=%r",
            group_uuid, user_uuid, exc,
        )
        return jsonify({"error": "upstream identity service error"}), 502

    await audit.log(
        "identity.member_removed",
        actor_uuid=actor_uuid,
        actor_ip=_client_ip(),
        target_uuid=group_uuid,
        target_type="group",
        details={"user_uuid": user_uuid},
    )

    return jsonify({"status": "removed"}), 200
