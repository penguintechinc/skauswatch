"""
checkpoint-core — SCIM 2.0 provisioning endpoints.

Blueprint: scim_bp, prefix /scim/v2

Authentication: Bearer token checked against checkpoint_scim_tokens table
(SHA-256 of the raw token compared against token_hash).

References:
  RFC 7643 — SCIM Core Schema
  RFC 7644 — SCIM Protocol
"""
from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from quart import Blueprint, current_app, jsonify, request

from audit.logger import AuditLogger
from checkpoint_grpc.core_client import CheckpointCoreError, CoreIdentityClient
from scim.mappers import (
    SCIM_USER_SCHEMA,
    group_to_scim,
    scim_error,
    scim_list_response,
    scim_to_user_fields,
    user_to_scim,
)

logger = logging.getLogger(__name__)

scim_bp = Blueprint("scim", __name__, url_prefix="/scim/v2")

# Max filter results per request
_MAX_RESULTS = 200


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


def _scim_base_url() -> str:
    """Build the SCIM base URL from the request host."""
    cfg = _get_config()
    issuer = cfg.issuer_url.rstrip("/")
    return f"{issuer}/scim/v2"


# ── SCIM token authentication ─────────────────────────────────────────────────


def _verify_scim_token() -> dict[str, Any] | None:
    """
    Verify the Bearer token against checkpoint_scim_tokens.

    Returns the token row on success, None if missing or invalid.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    raw_token = auth[7:]
    if not raw_token:
        return None

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    db = _get_db()
    now = datetime.now(tz=timezone.utc).replace(tzinfo=None)

    row = db(
        (db.checkpoint_scim_tokens.token_hash == token_hash)
        & (db.checkpoint_scim_tokens.revoked_at == None)  # noqa: E711
    ).select().first()

    if row is None:
        return None

    # Check revoked (defense-in-depth: DB filter may not apply in all paths)
    if row.revoked_at is not None:
        return None

    # Check expiry
    if row.expires_at is not None and row.expires_at < now:
        return None

    return dict(row)


def _require_scim_auth():  # type: ignore[return]
    """
    Decorator: enforce SCIM Bearer token authentication.

    Returns 401 if token is missing or invalid.
    """
    import functools

    def decorator(fn):  # type: ignore[return]
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            token_row = _verify_scim_token()
            if token_row is None:
                return (
                    jsonify(scim_error(401, "SCIM bearer token required or invalid")),
                    401,
                    {"Content-Type": "application/scim+json"},
                )
            return await fn(*args, **kwargs)

        return wrapper

    return decorator


# ── SCIM filter parser (minimal: userName eq / emails.value eq) ───────────────


def _parse_scim_filter(filter_str: str) -> tuple[str, str] | None:
    """
    Parse a simple SCIM filter expression.

    Supports:
      userName eq "value"
      emails.value eq "value"

    Returns (attribute, value) or None if not parseable.
    """
    if not filter_str:
        return None
    # Reject overly long filters
    if len(filter_str) > 512:
        return None
    parts = filter_str.strip().split(None, 2)
    if len(parts) != 3 or parts[1].lower() != "eq":
        return None
    attr = parts[0].lower()
    value = parts[2].strip('"').strip("'")
    if attr in ("username", "emails.value"):
        return (attr, value)
    return None


# ── ServiceProviderConfig (no auth required) ──────────────────────────────────


@scim_bp.route("/ServiceProviderConfig", methods=["GET"])
async def service_provider_config() -> Any:
    """Return SCIM ServiceProviderConfig — no authentication required."""
    cfg = {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": _MAX_RESULTS},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using the OAuth Bearer Token Standard",
                "specUri": "http://www.rfc-editor.org/info/rfc6750",
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": f"{_scim_base_url()}/ServiceProviderConfig",
        },
    }
    return jsonify(cfg), 200, {"Content-Type": "application/scim+json"}


# ── Users ─────────────────────────────────────────────────────────────────────


@scim_bp.route("/Users", methods=["GET"])
@_require_scim_auth()
async def scim_list_users() -> Any:
    """
    List or filter users (SCIM 2.0 ListResponse).

    Supports ?filter=userName eq "..." and ?filter=emails.value eq "..."
    """
    core = _get_core()
    base = _scim_base_url()
    filter_str = request.args.get("filter", "").strip()

    try:
        if filter_str:
            parsed = _parse_scim_filter(filter_str)
            if parsed is None:
                return (
                    jsonify(scim_error(400, "Invalid filter syntax", "invalidFilter")),
                    400,
                    {"Content-Type": "application/scim+json"},
                )
            _attr, value = parsed
            users = await core.search_users(query=value)
        else:
            users = await core.list_users(page=0, page_size=_MAX_RESULTS)
    except CheckpointCoreError as exc:
        logger.error("scim.list_users.error error=%r", exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    # Fetch groups for each user (best-effort)
    scim_users = []
    for u in users:
        try:
            groups = await core.get_user_groups(u.uuid)
            u.groups = groups  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            pass
        scim_users.append(user_to_scim(u, base))

    return (
        jsonify(scim_list_response(scim_users, len(scim_users))),
        200,
        {"Content-Type": "application/scim+json"},
    )


@scim_bp.route("/Users", methods=["POST"])
@_require_scim_auth()
async def scim_create_user() -> Any:
    """Provision a new user via SCIM POST /Users."""
    core = _get_core()
    audit = _get_audit()
    base = _scim_base_url()
    body = await request.get_json() or {}

    fields = scim_to_user_fields(body)
    username: str = fields.get("username") or ""
    email: str = fields.get("email") or ""
    display_name: str = fields.get("display_name") or username

    if not username:
        return (
            jsonify(scim_error(400, "userName is required", "invalidValue")),
            400,
            {"Content-Type": "application/scim+json"},
        )
    if not email:
        return (
            jsonify(scim_error(400, "emails[primary] is required", "invalidValue")),
            400,
            {"Content-Type": "application/scim+json"},
        )

    try:
        user = await core.create_user(
            username=username,
            email=email,
            display_name=display_name,
            password=fields.get("password"),
            attributes={},
            group_uuids=[],
        )
    except CheckpointCoreError as exc:
        logger.error("scim.create_user.error error=%r", exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    await audit.log(
        "scim.user_provisioned",
        actor_ip=_client_ip(),
        target_uuid=user.uuid,
        target_type="user",
        details={"username": username, "source": "scim"},
    )

    return (
        jsonify(user_to_scim(user, base)),
        201,
        {
            "Content-Type": "application/scim+json",
            "Location": f"{base}/Users/{user.uuid}",
        },
    )


@scim_bp.route("/Users/<string:user_id>", methods=["GET"])
@_require_scim_auth()
async def scim_get_user(user_id: str) -> Any:
    """Get a SCIM User by ID (UUID)."""
    core = _get_core()
    base = _scim_base_url()

    try:
        user = await core.get_user(uuid=user_id)
    except CheckpointCoreError as exc:
        logger.error("scim.get_user.error user_id=%s error=%r", user_id, exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    if user is None:
        return (
            jsonify(scim_error(404, f"User {user_id} not found")),
            404,
            {"Content-Type": "application/scim+json"},
        )

    try:
        user.groups = await core.get_user_groups(user.uuid)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        pass

    return jsonify(user_to_scim(user, base)), 200, {"Content-Type": "application/scim+json"}


@scim_bp.route("/Users/<string:user_id>", methods=["PUT"])
@_require_scim_auth()
async def scim_replace_user(user_id: str) -> Any:
    """Replace all user attributes (SCIM PUT)."""
    core = _get_core()
    audit = _get_audit()
    base = _scim_base_url()
    body = await request.get_json() or {}
    fields = scim_to_user_fields(body)

    if not fields:
        return (
            jsonify(scim_error(400, "No fields to update", "invalidValue")),
            400,
            {"Content-Type": "application/scim+json"},
        )

    try:
        user = await core.update_user(uuid=user_id, fields=fields)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return (
                jsonify(scim_error(404, f"User {user_id} not found")),
                404,
                {"Content-Type": "application/scim+json"},
            )
        logger.error("scim.replace_user.error user_id=%s error=%r", user_id, exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    await audit.log(
        "scim.user_replaced",
        actor_ip=_client_ip(),
        target_uuid=user_id,
        target_type="user",
        details={"fields_updated": list(fields.keys())},
    )

    return jsonify(user_to_scim(user, base)), 200, {"Content-Type": "application/scim+json"}


@scim_bp.route("/Users/<string:user_id>", methods=["PATCH"])
@_require_scim_auth()
async def scim_patch_user(user_id: str) -> Any:
    """
    Partial update via SCIM PATCH.

    Supports Operations array with op: add | replace | remove.
    """
    core = _get_core()
    audit = _get_audit()
    base = _scim_base_url()
    body = await request.get_json() or {}
    operations = body.get("Operations") or []

    if not isinstance(operations, list):
        return (
            jsonify(scim_error(400, "Operations array is required", "invalidValue")),
            400,
            {"Content-Type": "application/scim+json"},
        )

    # Build a merged fields dict from all operations
    fields: dict[str, Any] = {}
    for op in operations:
        op_type = (op.get("op") or "").lower()
        path = (op.get("path") or "").lower()
        value = op.get("value")

        if op_type in ("add", "replace"):
            if path in ("username", "username"):
                fields["username"] = str(value)
            elif path in ("displayname",):
                fields["display_name"] = str(value)
            elif path in ("active",):
                fields["is_active"] = bool(value)
            elif path in ("emails", "emails[type eq \"work\"].value"):
                if isinstance(value, list) and value:
                    fields["email"] = value[0].get("value", "")
                elif isinstance(value, str):
                    fields["email"] = value
            elif not path and isinstance(value, dict):
                # No path — treat value dict as SCIM user body
                merged = scim_to_user_fields(value)
                fields.update(merged)
        elif op_type == "remove":
            # Remove active = deactivate
            if path == "active":
                fields["is_active"] = False

    if not fields:
        # No actionable operations — return current state
        user = await core.get_user(uuid=user_id)
        if user is None:
            return (
                jsonify(scim_error(404, f"User {user_id} not found")),
                404,
                {"Content-Type": "application/scim+json"},
            )
        return jsonify(user_to_scim(user, base)), 200, {"Content-Type": "application/scim+json"}

    try:
        user = await core.update_user(uuid=user_id, fields=fields)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return (
                jsonify(scim_error(404, f"User {user_id} not found")),
                404,
                {"Content-Type": "application/scim+json"},
            )
        logger.error("scim.patch_user.error user_id=%s error=%r", user_id, exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    await audit.log(
        "scim.user_patched",
        actor_ip=_client_ip(),
        target_uuid=user_id,
        target_type="user",
        details={"fields_updated": list(fields.keys())},
    )

    return jsonify(user_to_scim(user, base)), 200, {"Content-Type": "application/scim+json"}


@scim_bp.route("/Users/<string:user_id>", methods=["DELETE"])
@_require_scim_auth()
async def scim_delete_user(user_id: str) -> Any:
    """Deprovision a user (SCIM DELETE)."""
    core = _get_core()
    audit = _get_audit()

    try:
        await core.delete_user(uuid=user_id)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return (
                jsonify(scim_error(404, f"User {user_id} not found")),
                404,
                {"Content-Type": "application/scim+json"},
            )
        logger.error("scim.delete_user.error user_id=%s error=%r", user_id, exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    await audit.log(
        "scim.user_deprovisioned",
        actor_ip=_client_ip(),
        target_uuid=user_id,
        target_type="user",
        details={"source": "scim"},
    )

    return "", 204


# ── Groups ────────────────────────────────────────────────────────────────────


@scim_bp.route("/Groups", methods=["GET"])
@_require_scim_auth()
async def scim_list_groups() -> Any:
    """List groups (SCIM 2.0 ListResponse)."""
    core = _get_core()
    base = _scim_base_url()

    try:
        groups = await core.list_groups(page=0, page_size=_MAX_RESULTS)
    except CheckpointCoreError as exc:
        logger.error("scim.list_groups.error error=%r", exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    scim_groups = [group_to_scim(g, base_url=base) for g in groups]
    return (
        jsonify(scim_list_response(scim_groups, len(scim_groups))),
        200,
        {"Content-Type": "application/scim+json"},
    )


@scim_bp.route("/Groups", methods=["POST"])
@_require_scim_auth()
async def scim_create_group() -> Any:
    """Create a group via SCIM POST /Groups."""
    core = _get_core()
    audit = _get_audit()
    base = _scim_base_url()
    body = await request.get_json() or {}

    display_name: str = (body.get("displayName") or "").strip()
    if not display_name:
        return (
            jsonify(scim_error(400, "displayName is required", "invalidValue")),
            400,
            {"Content-Type": "application/scim+json"},
        )

    try:
        group = await core.create_group(name=display_name, description="")
    except CheckpointCoreError as exc:
        logger.error("scim.create_group.error error=%r", exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    await audit.log(
        "scim.group_created",
        actor_ip=_client_ip(),
        target_uuid=group.uuid,
        target_type="group",
        details={"name": display_name, "source": "scim"},
    )

    return (
        jsonify(group_to_scim(group, base_url=base)),
        201,
        {
            "Content-Type": "application/scim+json",
            "Location": f"{base}/Groups/{group.uuid}",
        },
    )


@scim_bp.route("/Groups/<string:group_id>", methods=["GET"])
@_require_scim_auth()
async def scim_get_group(group_id: str) -> Any:
    """Get a SCIM Group by ID."""
    core = _get_core()
    base = _scim_base_url()

    try:
        group = await core.get_group(uuid=group_id)
    except CheckpointCoreError as exc:
        logger.error("scim.get_group.error group_id=%s error=%r", group_id, exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    if group is None:
        return (
            jsonify(scim_error(404, f"Group {group_id} not found")),
            404,
            {"Content-Type": "application/scim+json"},
        )

    try:
        members = await core.list_group_members(group_uuid=group_id)
    except Exception:  # noqa: BLE001
        members = []

    return (
        jsonify(group_to_scim(group, members=members, base_url=base)),
        200,
        {"Content-Type": "application/scim+json"},
    )


@scim_bp.route("/Groups/<string:group_id>", methods=["PUT"])
@_require_scim_auth()
async def scim_replace_group(group_id: str) -> Any:
    """Replace group (SCIM PUT)."""
    core = _get_core()
    audit = _get_audit()
    base = _scim_base_url()
    body = await request.get_json() or {}

    display_name: str = (body.get("displayName") or "").strip()
    if not display_name:
        return (
            jsonify(scim_error(400, "displayName is required", "invalidValue")),
            400,
            {"Content-Type": "application/scim+json"},
        )

    try:
        group = await core.update_group(uuid=group_id, fields={"name": display_name})
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return (
                jsonify(scim_error(404, f"Group {group_id} not found")),
                404,
                {"Content-Type": "application/scim+json"},
            )
        logger.error("scim.replace_group.error group_id=%s error=%r", group_id, exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    await audit.log(
        "scim.group_replaced",
        actor_ip=_client_ip(),
        target_uuid=group_id,
        target_type="group",
        details={"name": display_name},
    )

    return jsonify(group_to_scim(group, base_url=base)), 200, {"Content-Type": "application/scim+json"}


@scim_bp.route("/Groups/<string:group_id>", methods=["PATCH"])
@_require_scim_auth()
async def scim_patch_group(group_id: str) -> Any:
    """
    Partial group update via SCIM PATCH.

    Supports add/remove members via Operations array.
    """
    core = _get_core()
    audit = _get_audit()
    base = _scim_base_url()
    body = await request.get_json() or {}
    operations = body.get("Operations") or []

    if not isinstance(operations, list):
        return (
            jsonify(scim_error(400, "Operations must be an array", "invalidValue")),
            400,
            {"Content-Type": "application/scim+json"},
        )

    for op in operations:
        op_type = (op.get("op") or "").lower()
        path = (op.get("path") or "").lower()
        value = op.get("value")

        if op_type in ("add", "replace") and path == "members":
            # value is a list of {value: user_uuid} objects
            if isinstance(value, list):
                for member in value:
                    user_uuid = member.get("value") if isinstance(member, dict) else str(member)
                    if user_uuid:
                        try:
                            await core.add_membership(group_uuid=group_id, user_uuid=user_uuid)
                        except CheckpointCoreError as exc:
                            logger.warning(
                                "scim.patch_group.add_member_failed group=%s user=%s error=%r",
                                group_id, user_uuid, exc,
                            )
        elif op_type == "remove":
            if path.startswith("members[value eq"):
                # Extract UUID from: members[value eq "uuid"]
                start = path.find('"')
                end = path.rfind('"')
                if 0 <= start < end:
                    user_uuid = path[start + 1:end]
                    try:
                        await core.remove_membership(group_uuid=group_id, user_uuid=user_uuid)
                    except CheckpointCoreError as exc:
                        logger.warning(
                            "scim.patch_group.remove_member_failed group=%s user=%s error=%r",
                            group_id, user_uuid, exc,
                        )
            elif path == "members" and isinstance(value, list):
                for member in value:
                    user_uuid = member.get("value") if isinstance(member, dict) else str(member)
                    if user_uuid:
                        try:
                            await core.remove_membership(group_uuid=group_id, user_uuid=user_uuid)
                        except CheckpointCoreError as exc:
                            logger.warning(
                                "scim.patch_group.remove_member_failed group=%s user=%s error=%r",
                                group_id, user_uuid, exc,
                            )
        elif op_type in ("add", "replace") and path == "displayname":
            if isinstance(value, str):
                try:
                    await core.update_group(uuid=group_id, fields={"name": value})
                except CheckpointCoreError as exc:
                    logger.error("scim.patch_group.update_name_failed group=%s error=%r", group_id, exc)

    await audit.log(
        "scim.group_patched",
        actor_ip=_client_ip(),
        target_uuid=group_id,
        target_type="group",
        details={"op_count": len(operations)},
    )

    # Return updated group
    try:
        group = await core.get_group(uuid=group_id)
        members = await core.list_group_members(group_uuid=group_id)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return (
                jsonify(scim_error(404, f"Group {group_id} not found")),
                404,
                {"Content-Type": "application/scim+json"},
            )
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    return (
        jsonify(group_to_scim(group, members=members, base_url=base)),
        200,
        {"Content-Type": "application/scim+json"},
    )


@scim_bp.route("/Groups/<string:group_id>", methods=["DELETE"])
@_require_scim_auth()
async def scim_delete_group(group_id: str) -> Any:
    """Delete a group via SCIM DELETE."""
    core = _get_core()
    audit = _get_audit()

    try:
        await core.delete_group(uuid=group_id)
    except CheckpointCoreError as exc:
        import grpc as _grpc

        if getattr(exc, "grpc_code", None) == _grpc.StatusCode.NOT_FOUND:
            return (
                jsonify(scim_error(404, f"Group {group_id} not found")),
                404,
                {"Content-Type": "application/scim+json"},
            )
        logger.error("scim.delete_group.error group_id=%s error=%r", group_id, exc)
        return (
            jsonify(scim_error(503, "Upstream identity service unavailable")),
            503,
            {"Content-Type": "application/scim+json"},
        )

    await audit.log(
        "scim.group_deleted",
        actor_ip=_client_ip(),
        target_uuid=group_id,
        target_type="group",
        details={"source": "scim"},
    )

    return "", 204
