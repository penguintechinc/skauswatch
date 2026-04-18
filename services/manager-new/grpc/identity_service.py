"""
IdentityService gRPC servicer implementation.

Implements all IdentityService RPCs defined in proto/identity.proto.
Called by Checkpoint sub-module (checkpoint-core and checkpoint-ldap-agent)
to authenticate users and read/write identity data.

Design notes:
- Each method creates its own DB query; no shared cursors across calls.
- Password verification uses bcrypt.checkpw against the stored hash.
- User scopes are computed from group memberships at query time:
    owner  → *:read *:write *:admin
    admin  → *:read *:write
    member → *:read
- Input validation: UUID format, email format, pagination caps.
- Logs authentication events at INFO/WARNING; never logs PII values.
"""

import logging
import re
from typing import List, Optional
from uuid import uuid4

import bcrypt
import grpc

from grpc.generated.identity_pb2 import (
    AttributeRecord,
    AttributeResponse,
    AttributesResponse,
    AuthenticateResponse,
    DeleteResponse,
    GroupRecord,
    GroupResponse,
    ListGroupsResponse,
    ListUsersResponse,
    MembershipResponse,
    UserRecord,
    UserResponse,
    VerifyTokenResponse,
)
from grpc.generated.identity_pb2_grpc import IdentityServiceServicer
from models.db import get_db

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_VALID_USER_STATUSES = {"active", "suspended", "pending"}
_VALID_MEMBERSHIP_ROLES = {"member", "owner", "admin"}
_VALID_MEMBERSHIP_SOURCES = {"local", "synced"}
_VALID_SUBJECT_TYPES = {"user", "group"}
_VALID_ATTRIBUTE_SOURCES = {"local", "synced", "computed"}

_MAX_PER_PAGE = 100
_DEFAULT_PER_PAGE = 50
_DEFAULT_SEARCH_LIMIT = 25
_MAX_SEARCH_LIMIT = 100

# Scope bundles keyed by membership role
_ROLE_SCOPES: dict[str, list[str]] = {
    "owner": ["*:read", "*:write", "*:admin"],
    "admin": ["*:read", "*:write"],
    "member": ["*:read"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_valid_uuid(value: str) -> bool:
    """Return True if value matches UUID4 format."""
    return bool(value and _UUID_RE.match(value))


def _is_valid_email(value: str) -> bool:
    """Return True if value looks like an email address."""
    return bool(value and _EMAIL_RE.match(value))


def _new_uuid() -> str:
    """Generate a new UUID4 string."""
    return str(uuid4())


def _dt_to_epoch(dt) -> int:
    """Convert a datetime (or None) to a Unix epoch int."""
    if dt is None:
        return 0
    try:
        return int(dt.timestamp())
    except Exception:
        return 0


def _compute_scopes(db, user_uuid: str) -> List[str]:
    """
    Compute the union of scopes from all group memberships for a user.

    Higher-privileged roles subsume lower ones, so we take the broadest
    set across all memberships.
    """
    memberships = db(
        db.identity_memberships.user_uuid == user_uuid
    ).select(db.identity_memberships.role)

    scope_set: set[str] = set()
    for m in memberships:
        scope_set.update(_ROLE_SCOPES.get(m.role, []))

    return sorted(scope_set)


def _row_to_user_record(db, row) -> UserRecord:
    """Convert a PyDAL identity_users row to a UserRecord dataclass."""
    scopes = _compute_scopes(db, row.uuid)
    return UserRecord(
        uuid=row.uuid or "",
        email=row.email or "",
        display_name=row.display_name or "",
        given_name=row.given_name or "",
        family_name=row.family_name or "",
        phone=row.phone or "",
        status=row.status or "",
        mfa_enabled=bool(row.mfa_enabled),
        locale=row.locale or "en",
        timezone=row.timezone or "UTC",
        avatar_url=row.avatar_url or "",
        external_id=row.external_id or "",
        external_provider=row.external_provider or "",
        created_at=_dt_to_epoch(row.created_at),
        updated_at=_dt_to_epoch(row.updated_at),
        last_login_at=_dt_to_epoch(row.last_login_at),
        scopes=scopes,
    )


def _row_to_group_record(db, row) -> GroupRecord:
    """Convert a PyDAL identity_groups row to a GroupRecord dataclass."""
    member_count = db(
        db.identity_memberships.group_uuid == row.uuid
    ).count()
    return GroupRecord(
        uuid=row.uuid or "",
        name=row.name or "",
        display_name=row.display_name or "",
        description=row.description or "",
        type=row.type or "local",
        external_id=row.external_id or "",
        external_provider=row.external_provider or "",
        created_at=_dt_to_epoch(row.created_at),
        member_count=member_count,
    )


def _row_to_attribute_record(row) -> AttributeRecord:
    """Convert a PyDAL identity_attributes row to an AttributeRecord."""
    return AttributeRecord(
        uuid=row.uuid or "",
        key=row.key or "",
        value=row.value or "",
        source=row.source or "local",
    )


# ---------------------------------------------------------------------------
# Servicer
# ---------------------------------------------------------------------------


class IdentityServiceServicerImpl(IdentityServiceServicer):
    """
    Concrete implementation of IdentityService.

    Receives a PyDAL DAL factory callable so each method creates its own
    DB connection — thread-safe, no shared cursor state.

    Args:
        db_uri: Database connection URI forwarded to get_db().
    """

    def __init__(self, db_uri: str) -> None:
        self._db_uri = db_uri

    def _db(self):
        """Return a per-call DAL instance (migrate=False, pool_size=1)."""
        return get_db(self._db_uri)

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def AuthenticateUser(self, request, context):
        """
        Authenticate a user by email + password.

        Verifies the bcrypt hash stored in identity_users.password_hash.
        Updates last_login_at on success.
        Logs auth events without recording PII values.
        """
        if not _is_valid_email(request.email):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Invalid email format")
            return AuthenticateResponse(
                success=False, error="Invalid email format"
            )

        db = self._db()
        try:
            user = db(
                db.identity_users.email == request.email
            ).select().first()

            if not user:
                logger.warning(
                    "AuthenticateUser: unknown email domain=%s",
                    request.email.split("@")[-1] if "@" in request.email else "[invalid]",
                )
                return AuthenticateResponse(
                    success=False, error="Invalid credentials"
                )

            if not user.password_hash:
                logger.warning(
                    "AuthenticateUser: no password hash for user uuid=%s",
                    user.uuid,
                )
                return AuthenticateResponse(
                    success=False, error="Invalid credentials"
                )

            if user.status != "active":
                logger.info(
                    "AuthenticateUser: rejected non-active user uuid=%s status=%s",
                    user.uuid,
                    user.status,
                )
                return AuthenticateResponse(
                    success=False,
                    error=f"Account is {user.status}",
                )

            password_bytes = request.password.encode("utf-8")
            hash_bytes = user.password_hash.encode("utf-8")

            if not bcrypt.checkpw(password_bytes, hash_bytes):
                logger.warning(
                    "AuthenticateUser: bad password for user uuid=%s ip=%s",
                    user.uuid,
                    request.client_ip,
                )
                return AuthenticateResponse(
                    success=False, error="Invalid credentials"
                )

            # Update last_login_at
            from datetime import datetime

            db(db.identity_users.uuid == user.uuid).update(
                last_login_at=datetime.utcnow()
            )
            db.commit()

            logger.info(
                "AuthenticateUser: success uuid=%s ip=%s",
                user.uuid,
                request.client_ip,
            )
            return AuthenticateResponse(
                success=True,
                user_uuid=user.uuid,
                user=_row_to_user_record(db, user),
            )

        except Exception as exc:
            logger.exception("AuthenticateUser: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return AuthenticateResponse(success=False, error="Internal error")

    def VerifyToken(self, request, context):
        """
        Verify a JWT session token is still valid (not revoked, not expired).
        """
        if not request.token_hash or len(request.token_hash) != 64:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("token_hash must be a 64-character SHA-256 hex string")
            return VerifyTokenResponse(valid=False)

        db = self._db()
        try:
            from datetime import datetime

            session = db(
                (db.identity_sessions.token_hash == request.token_hash)
                & (db.identity_sessions.revoked_at == None)  # noqa: E711
                & (db.identity_sessions.expires_at > datetime.utcnow())
            ).select().first()

            if not session:
                return VerifyTokenResponse(valid=False)

            return VerifyTokenResponse(
                valid=True,
                user_uuid=session.user_uuid,
                scopes=session.scopes or "",
                expires_at=_dt_to_epoch(session.expires_at),
            )

        except Exception as exc:
            logger.exception("VerifyToken: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return VerifyTokenResponse(valid=False)

    def RevokeToken(self, request, context):
        """Revoke a JWT by setting revoked_at on the session record."""
        if not request.token_hash or len(request.token_hash) != 64:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("token_hash must be a 64-character SHA-256 hex string")
            return DeleteResponse(success=False, error="Invalid token_hash")

        db = self._db()
        try:
            from datetime import datetime

            rows = db(
                db.identity_sessions.token_hash == request.token_hash
            ).update(revoked_at=datetime.utcnow())
            db.commit()

            if not rows:
                return DeleteResponse(success=False, error="Token not found")

            return DeleteResponse(success=True)

        except Exception as exc:
            logger.exception("RevokeToken: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return DeleteResponse(success=False, error="Internal error")

    # ------------------------------------------------------------------
    # Users (read)
    # ------------------------------------------------------------------

    def GetUser(self, request, context):
        """Fetch a single user by UUID."""
        if not _is_valid_uuid(request.uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("uuid must be a valid UUID")
            return UserResponse(error="Invalid UUID")

        db = self._db()
        try:
            user = db(
                db.identity_users.uuid == request.uuid
            ).select().first()

            if not user:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("User not found")
                return UserResponse(error="User not found")

            return UserResponse(user=_row_to_user_record(db, user))

        except Exception as exc:
            logger.exception("GetUser: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return UserResponse(error="Internal error")

    def ListUsers(self, request, context):
        """Return a paginated list of users with optional status filter."""
        page = max(1, request.page)
        per_page = min(max(1, request.per_page or _DEFAULT_PER_PAGE), _MAX_PER_PAGE)
        offset = (page - 1) * per_page

        db = self._db()
        try:
            query = db.identity_users
            if request.status and request.status in _VALID_USER_STATUSES:
                query = db(db.identity_users.status == request.status)
            else:
                query = db(db.identity_users.id > 0)

            total = query.count()
            rows = query.select(
                limitby=(offset, offset + per_page),
                orderby=db.identity_users.created_at,
            )

            users = [_row_to_user_record(db, r) for r in rows]
            return ListUsersResponse(users=users, total=total)

        except Exception as exc:
            logger.exception("ListUsers: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return ListUsersResponse(error="Internal error")

    def SearchUsers(self, request, context):
        """Full-text search across email, display_name, external_id."""
        if not request.query or len(request.query.strip()) < 2:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("query must be at least 2 characters")
            return ListUsersResponse(error="query too short")

        limit = min(max(1, request.limit or _DEFAULT_SEARCH_LIMIT), _MAX_SEARCH_LIMIT)
        pattern = f"%{request.query.strip()}%"

        db = self._db()
        try:
            rows = db(
                (db.identity_users.email.like(pattern))
                | (db.identity_users.display_name.like(pattern))
                | (db.identity_users.external_id.like(pattern))
            ).select(
                limitby=(0, limit),
                orderby=db.identity_users.email,
            )

            users = [_row_to_user_record(db, r) for r in rows]
            return ListUsersResponse(users=users, total=len(users))

        except Exception as exc:
            logger.exception("SearchUsers: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return ListUsersResponse(error="Internal error")

    # ------------------------------------------------------------------
    # Users (write)
    # ------------------------------------------------------------------

    def CreateUser(self, request, context):
        """Create a new local user (SCIM provisioning path)."""
        if not _is_valid_email(request.email):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Invalid email format")
            return UserResponse(error="Invalid email format")

        if not request.password:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("password is required")
            return UserResponse(error="password is required")

        db = self._db()
        try:
            # Check for duplicate email
            existing = db(
                db.identity_users.email == request.email
            ).select().first()
            if existing:
                context.set_code(grpc.StatusCode.ALREADY_EXISTS)
                context.set_details("Email already registered")
                return UserResponse(error="Email already registered")

            password_hash = bcrypt.hashpw(
                request.password.encode("utf-8"),
                bcrypt.gensalt(),
            ).decode("utf-8")

            user_uuid = _new_uuid()
            db.identity_users.insert(
                uuid=user_uuid,
                email=request.email,
                password_hash=password_hash,
                display_name=request.display_name or "",
                given_name=request.given_name or "",
                family_name=request.family_name or "",
                phone=request.phone or "",
                locale=request.locale or "en",
                timezone=request.timezone or "UTC",
                external_id=request.external_id or "",
                external_provider=request.external_provider or "",
                status="active",
            )
            db.commit()

            user = db(db.identity_users.uuid == user_uuid).select().first()
            logger.info("CreateUser: created uuid=%s", user_uuid)
            return UserResponse(user=_row_to_user_record(db, user))

        except Exception as exc:
            logger.exception("CreateUser: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return UserResponse(error="Internal error")

    def UpdateUser(self, request, context):
        """Update mutable fields on a user (excludes email and password)."""
        if not _is_valid_uuid(request.uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("uuid must be a valid UUID")
            return UserResponse(error="Invalid UUID")

        if request.status and request.status not in _VALID_USER_STATUSES:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(
                f"status must be one of: {', '.join(sorted(_VALID_USER_STATUSES))}"
            )
            return UserResponse(error="Invalid status")

        db = self._db()
        try:
            user = db(
                db.identity_users.uuid == request.uuid
            ).select().first()
            if not user:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("User not found")
                return UserResponse(error="User not found")

            updates: dict = {}
            if request.display_name:
                updates["display_name"] = request.display_name
            if request.given_name:
                updates["given_name"] = request.given_name
            if request.family_name:
                updates["family_name"] = request.family_name
            if request.phone:
                updates["phone"] = request.phone
            if request.status:
                updates["status"] = request.status
            if request.locale:
                updates["locale"] = request.locale
            if request.timezone:
                updates["timezone"] = request.timezone
            if request.avatar_url:
                updates["avatar_url"] = request.avatar_url

            if updates:
                db(db.identity_users.uuid == request.uuid).update(**updates)
                db.commit()

            user = db(db.identity_users.uuid == request.uuid).select().first()
            return UserResponse(user=_row_to_user_record(db, user))

        except Exception as exc:
            logger.exception("UpdateUser: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return UserResponse(error="Internal error")

    def DeleteUser(self, request, context):
        """Delete a user and all associated memberships and attributes."""
        if not _is_valid_uuid(request.uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("uuid must be a valid UUID")
            return DeleteResponse(success=False, error="Invalid UUID")

        db = self._db()
        try:
            user = db(
                db.identity_users.uuid == request.uuid
            ).select().first()
            if not user:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("User not found")
                return DeleteResponse(success=False, error="User not found")

            # Cascade: remove memberships, attributes, sessions
            db(db.identity_memberships.user_uuid == request.uuid).delete()
            db(
                (db.identity_attributes.subject_uuid == request.uuid)
                & (db.identity_attributes.subject_type == "user")
            ).delete()
            db(db.identity_sessions.user_uuid == request.uuid).delete()
            db(db.identity_users.uuid == request.uuid).delete()
            db.commit()

            logger.info("DeleteUser: deleted uuid=%s", request.uuid)
            return DeleteResponse(success=True)

        except Exception as exc:
            logger.exception("DeleteUser: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return DeleteResponse(success=False, error="Internal error")

    # ------------------------------------------------------------------
    # Groups (read)
    # ------------------------------------------------------------------

    def GetGroup(self, request, context):
        """Fetch a single group by UUID."""
        if not _is_valid_uuid(request.uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("uuid must be a valid UUID")
            return GroupResponse(error="Invalid UUID")

        db = self._db()
        try:
            group = db(
                db.identity_groups.uuid == request.uuid
            ).select().first()
            if not group:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Group not found")
                return GroupResponse(error="Group not found")

            return GroupResponse(group=_row_to_group_record(db, group))

        except Exception as exc:
            logger.exception("GetGroup: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return GroupResponse(error="Internal error")

    def ListGroups(self, request, context):
        """Return a paginated list of groups."""
        page = max(1, request.page)
        per_page = min(max(1, request.per_page or _DEFAULT_PER_PAGE), _MAX_PER_PAGE)
        offset = (page - 1) * per_page

        db = self._db()
        try:
            total = db(db.identity_groups.id > 0).count()
            rows = db(db.identity_groups.id > 0).select(
                limitby=(offset, offset + per_page),
                orderby=db.identity_groups.name,
            )
            groups = [_row_to_group_record(db, r) for r in rows]
            return ListGroupsResponse(groups=groups, total=total)

        except Exception as exc:
            logger.exception("ListGroups: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return ListGroupsResponse(error="Internal error")

    def GetUserGroups(self, request, context):
        """Return all groups a user belongs to."""
        if not _is_valid_uuid(request.uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("uuid must be a valid UUID")
            return ListGroupsResponse(error="Invalid UUID")

        db = self._db()
        try:
            memberships = db(
                db.identity_memberships.user_uuid == request.uuid
            ).select(db.identity_memberships.group_uuid)

            group_uuids = [m.group_uuid for m in memberships]
            if not group_uuids:
                return ListGroupsResponse(groups=[], total=0)

            rows = db(
                db.identity_groups.uuid.belongs(group_uuids)
            ).select(orderby=db.identity_groups.name)

            groups = [_row_to_group_record(db, r) for r in rows]
            return ListGroupsResponse(groups=groups, total=len(groups))

        except Exception as exc:
            logger.exception("GetUserGroups: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return ListGroupsResponse(error="Internal error")

    # ------------------------------------------------------------------
    # Groups (write)
    # ------------------------------------------------------------------

    def CreateGroup(self, request, context):
        """Create a new group."""
        if not request.name or not request.name.strip():
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("name is required")
            return GroupResponse(error="name is required")

        db = self._db()
        try:
            existing = db(
                db.identity_groups.name == request.name
            ).select().first()
            if existing:
                context.set_code(grpc.StatusCode.ALREADY_EXISTS)
                context.set_details("Group name already in use")
                return GroupResponse(error="Group name already in use")

            group_uuid = _new_uuid()
            db.identity_groups.insert(
                uuid=group_uuid,
                name=request.name,
                display_name=request.display_name or "",
                description=request.description or "",
                type=request.type or "local",
                external_id=request.external_id or "",
                external_provider=request.external_provider or "",
            )
            db.commit()

            group = db(db.identity_groups.uuid == group_uuid).select().first()
            logger.info("CreateGroup: created uuid=%s name=%s", group_uuid, request.name)
            return GroupResponse(group=_row_to_group_record(db, group))

        except Exception as exc:
            logger.exception("CreateGroup: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return GroupResponse(error="Internal error")

    def UpdateGroup(self, request, context):
        """Update mutable fields on a group."""
        if not _is_valid_uuid(request.uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("uuid must be a valid UUID")
            return GroupResponse(error="Invalid UUID")

        db = self._db()
        try:
            group = db(
                db.identity_groups.uuid == request.uuid
            ).select().first()
            if not group:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Group not found")
                return GroupResponse(error="Group not found")

            updates: dict = {}
            if request.display_name:
                updates["display_name"] = request.display_name
            if request.description:
                updates["description"] = request.description

            if updates:
                db(db.identity_groups.uuid == request.uuid).update(**updates)
                db.commit()

            group = db(db.identity_groups.uuid == request.uuid).select().first()
            return GroupResponse(group=_row_to_group_record(db, group))

        except Exception as exc:
            logger.exception("UpdateGroup: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return GroupResponse(error="Internal error")

    def DeleteGroup(self, request, context):
        """Delete a group and all its memberships and attributes."""
        if not _is_valid_uuid(request.uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("uuid must be a valid UUID")
            return DeleteResponse(success=False, error="Invalid UUID")

        db = self._db()
        try:
            group = db(
                db.identity_groups.uuid == request.uuid
            ).select().first()
            if not group:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Group not found")
                return DeleteResponse(success=False, error="Group not found")

            db(db.identity_memberships.group_uuid == request.uuid).delete()
            db(
                (db.identity_attributes.subject_uuid == request.uuid)
                & (db.identity_attributes.subject_type == "group")
            ).delete()
            db(db.identity_groups.uuid == request.uuid).delete()
            db.commit()

            logger.info("DeleteGroup: deleted uuid=%s", request.uuid)
            return DeleteResponse(success=True)

        except Exception as exc:
            logger.exception("DeleteGroup: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return DeleteResponse(success=False, error="Internal error")

    # ------------------------------------------------------------------
    # Memberships
    # ------------------------------------------------------------------

    def AddMembership(self, request, context):
        """Add a user to a group with a specified role."""
        if not _is_valid_uuid(request.user_uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("user_uuid must be a valid UUID")
            return MembershipResponse(error="Invalid user_uuid")

        if not _is_valid_uuid(request.group_uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("group_uuid must be a valid UUID")
            return MembershipResponse(error="Invalid group_uuid")

        role = request.role or "member"
        if role not in _VALID_MEMBERSHIP_ROLES:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(
                f"role must be one of: {', '.join(sorted(_VALID_MEMBERSHIP_ROLES))}"
            )
            return MembershipResponse(error="Invalid role")

        source = request.source or "local"
        if source not in _VALID_MEMBERSHIP_SOURCES:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(
                f"source must be one of: {', '.join(sorted(_VALID_MEMBERSHIP_SOURCES))}"
            )
            return MembershipResponse(error="Invalid source")

        db = self._db()
        try:
            # Verify user and group exist
            user = db(
                db.identity_users.uuid == request.user_uuid
            ).select().first()
            if not user:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("User not found")
                return MembershipResponse(error="User not found")

            group = db(
                db.identity_groups.uuid == request.group_uuid
            ).select().first()
            if not group:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Group not found")
                return MembershipResponse(error="Group not found")

            # Check for existing membership
            existing = db(
                (db.identity_memberships.user_uuid == request.user_uuid)
                & (db.identity_memberships.group_uuid == request.group_uuid)
            ).select().first()
            if existing:
                context.set_code(grpc.StatusCode.ALREADY_EXISTS)
                context.set_details("Membership already exists")
                return MembershipResponse(error="Membership already exists")

            membership_uuid = _new_uuid()
            db.identity_memberships.insert(
                uuid=membership_uuid,
                user_uuid=request.user_uuid,
                group_uuid=request.group_uuid,
                role=role,
                added_by_uuid=request.added_by_uuid or "",
                source=source,
            )
            db.commit()

            logger.info(
                "AddMembership: user=%s group=%s role=%s",
                request.user_uuid,
                request.group_uuid,
                role,
            )
            return MembershipResponse(uuid=membership_uuid)

        except Exception as exc:
            logger.exception("AddMembership: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return MembershipResponse(error="Internal error")

    def RemoveMembership(self, request, context):
        """Remove a user from a group."""
        if not _is_valid_uuid(request.user_uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("user_uuid must be a valid UUID")
            return DeleteResponse(success=False, error="Invalid user_uuid")

        if not _is_valid_uuid(request.group_uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("group_uuid must be a valid UUID")
            return DeleteResponse(success=False, error="Invalid group_uuid")

        db = self._db()
        try:
            rows = db(
                (db.identity_memberships.user_uuid == request.user_uuid)
                & (db.identity_memberships.group_uuid == request.group_uuid)
            ).delete()
            db.commit()

            if not rows:
                context.set_code(grpc.StatusCode.NOT_FOUND)
                context.set_details("Membership not found")
                return DeleteResponse(success=False, error="Membership not found")

            logger.info(
                "RemoveMembership: user=%s group=%s",
                request.user_uuid,
                request.group_uuid,
            )
            return DeleteResponse(success=True)

        except Exception as exc:
            logger.exception("RemoveMembership: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return DeleteResponse(success=False, error="Internal error")

    # ------------------------------------------------------------------
    # Attributes
    # ------------------------------------------------------------------

    def GetAttributes(self, request, context):
        """Fetch all key-value attributes for a user or group."""
        if not _is_valid_uuid(request.subject_uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("subject_uuid must be a valid UUID")
            return AttributesResponse(error="Invalid subject_uuid")

        if request.subject_type not in _VALID_SUBJECT_TYPES:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(
                f"subject_type must be one of: {', '.join(sorted(_VALID_SUBJECT_TYPES))}"
            )
            return AttributesResponse(error="Invalid subject_type")

        db = self._db()
        try:
            rows = db(
                (db.identity_attributes.subject_uuid == request.subject_uuid)
                & (db.identity_attributes.subject_type == request.subject_type)
            ).select(orderby=db.identity_attributes.key)

            attributes = [_row_to_attribute_record(r) for r in rows]
            return AttributesResponse(attributes=attributes)

        except Exception as exc:
            logger.exception("GetAttributes: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return AttributesResponse(error="Internal error")

    def SetAttribute(self, request, context):
        """Upsert a key-value attribute on a user or group."""
        if not _is_valid_uuid(request.subject_uuid):
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("subject_uuid must be a valid UUID")
            return AttributeResponse(error="Invalid subject_uuid")

        if request.subject_type not in _VALID_SUBJECT_TYPES:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(
                f"subject_type must be one of: {', '.join(sorted(_VALID_SUBJECT_TYPES))}"
            )
            return AttributeResponse(error="Invalid subject_type")

        if not request.key or not request.key.strip():
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("key is required")
            return AttributeResponse(error="key is required")

        source = request.source or "local"
        if source not in _VALID_ATTRIBUTE_SOURCES:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details(
                f"source must be one of: {', '.join(sorted(_VALID_ATTRIBUTE_SOURCES))}"
            )
            return AttributeResponse(error="Invalid source")

        db = self._db()
        try:
            existing = db(
                (db.identity_attributes.subject_uuid == request.subject_uuid)
                & (db.identity_attributes.subject_type == request.subject_type)
                & (db.identity_attributes.key == request.key)
            ).select().first()

            if existing:
                db(
                    (db.identity_attributes.subject_uuid == request.subject_uuid)
                    & (db.identity_attributes.subject_type == request.subject_type)
                    & (db.identity_attributes.key == request.key)
                ).update(value=request.value, source=source)
                db.commit()
                attr_uuid = existing.uuid
            else:
                attr_uuid = _new_uuid()
                db.identity_attributes.insert(
                    uuid=attr_uuid,
                    subject_uuid=request.subject_uuid,
                    subject_type=request.subject_type,
                    key=request.key,
                    value=request.value or "",
                    source=source,
                )
                db.commit()

            attr = db(
                db.identity_attributes.uuid == attr_uuid
            ).select().first()
            return AttributeResponse(attribute=_row_to_attribute_record(attr))

        except Exception as exc:
            logger.exception("SetAttribute: internal error: %s", exc)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details("Internal error")
            return AttributeResponse(error="Internal error")
