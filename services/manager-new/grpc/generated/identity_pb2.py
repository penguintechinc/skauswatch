"""
Auto-generated protobuf message stubs for identity.proto.

Replace with real protoc output:
    python -m grpc_tools.protoc \
        -I./grpc/protos \
        --python_out=./grpc/generated \
        --grpc_python_out=./grpc/generated \
        ./grpc/protos/identity.proto
"""

from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Auth messages
# ---------------------------------------------------------------------------


@dataclass
class AuthenticateRequest:
    """Authenticate a user with email + password over mTLS gRPC."""

    email: str = ""
    password: str = ""       # plaintext — transport security is mTLS
    client_ip: str = ""
    user_agent: str = ""


@dataclass
class AuthenticateResponse:
    """Result of an authentication attempt."""

    success: bool = False
    user_uuid: str = ""
    error: str = ""          # empty on success
    user: Optional["UserRecord"] = None


@dataclass
class VerifyTokenRequest:
    """Verify a JWT by its SHA-256 token hash."""

    token_hash: str = ""     # SHA-256 hex of JWT jti claim


@dataclass
class VerifyTokenResponse:
    """Token verification result."""

    valid: bool = False
    user_uuid: str = ""
    scopes: str = ""         # space-separated scope list
    expires_at: int = 0      # Unix epoch


@dataclass
class RevokeTokenRequest:
    """Revoke a JWT by its SHA-256 token hash."""

    token_hash: str = ""


@dataclass
class DeleteResponse:
    """Generic deletion result."""

    success: bool = False
    error: str = ""


# ---------------------------------------------------------------------------
# User messages
# ---------------------------------------------------------------------------


@dataclass
class GetUserRequest:
    """Fetch a single user by UUID."""

    uuid: str = ""


@dataclass
class ListUsersRequest:
    """Paginated user list request."""

    page: int = 1
    per_page: int = 50       # max 100
    status: str = ""         # filter: active, suspended, pending, "" = all


@dataclass
class SearchUsersRequest:
    """Full-text search across email, display_name, external_id."""

    query: str = ""
    limit: int = 25


@dataclass
class UserRecord:
    """Canonical user identity record — PII present, handle with care."""

    uuid: str = ""
    email: str = ""
    display_name: str = ""
    given_name: str = ""
    family_name: str = ""
    phone: str = ""
    status: str = ""
    mfa_enabled: bool = False
    locale: str = "en"
    timezone: str = "UTC"
    avatar_url: str = ""
    external_id: str = ""
    external_provider: str = ""
    created_at: int = 0      # Unix epoch
    updated_at: int = 0      # Unix epoch
    last_login_at: int = 0   # Unix epoch
    scopes: List[str] = field(default_factory=list)   # computed from groups


@dataclass
class UserResponse:
    """Single user result."""

    user: Optional[UserRecord] = None
    error: str = ""


@dataclass
class ListUsersResponse:
    """Paginated list of users."""

    users: List[UserRecord] = field(default_factory=list)
    total: int = 0
    error: str = ""


@dataclass
class CreateUserRequest:
    """Create a new local user."""

    email: str = ""
    password: str = ""
    display_name: str = ""
    given_name: str = ""
    family_name: str = ""
    phone: str = ""
    locale: str = "en"
    timezone: str = "UTC"
    external_id: str = ""
    external_provider: str = ""


@dataclass
class UpdateUserRequest:
    """Update mutable fields on a user; email and password changed separately."""

    uuid: str = ""
    display_name: str = ""
    given_name: str = ""
    family_name: str = ""
    phone: str = ""
    status: str = ""
    locale: str = ""
    timezone: str = ""
    avatar_url: str = ""


# ---------------------------------------------------------------------------
# Group messages
# ---------------------------------------------------------------------------


@dataclass
class GetGroupRequest:
    """Fetch a single group by UUID."""

    uuid: str = ""


@dataclass
class ListGroupsRequest:
    """Paginated group list request."""

    page: int = 1
    per_page: int = 50       # max 100


@dataclass
class GroupRecord:
    """Group record — no PII stored here."""

    uuid: str = ""
    name: str = ""
    display_name: str = ""
    description: str = ""
    type: str = "local"      # local | external
    external_id: str = ""
    external_provider: str = ""
    created_at: int = 0      # Unix epoch
    member_count: int = 0


@dataclass
class GroupResponse:
    """Single group result."""

    group: Optional[GroupRecord] = None
    error: str = ""


@dataclass
class ListGroupsResponse:
    """Paginated list of groups."""

    groups: List[GroupRecord] = field(default_factory=list)
    total: int = 0
    error: str = ""


@dataclass
class CreateGroupRequest:
    """Create a new group."""

    name: str = ""
    display_name: str = ""
    description: str = ""
    type: str = "local"
    external_id: str = ""
    external_provider: str = ""


@dataclass
class UpdateGroupRequest:
    """Update mutable group fields."""

    uuid: str = ""
    display_name: str = ""
    description: str = ""


# ---------------------------------------------------------------------------
# Membership messages
# ---------------------------------------------------------------------------


@dataclass
class AddMembershipRequest:
    """Add a user to a group with a specific role."""

    user_uuid: str = ""
    group_uuid: str = ""
    role: str = "member"     # member | owner | admin
    added_by_uuid: str = ""
    source: str = "local"    # local | synced


@dataclass
class RemoveMembershipRequest:
    """Remove a user from a group."""

    user_uuid: str = ""
    group_uuid: str = ""


@dataclass
class MembershipResponse:
    """Membership creation result."""

    uuid: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Attribute messages
# ---------------------------------------------------------------------------


@dataclass
class GetAttributesRequest:
    """Fetch all attributes for a user or group."""

    subject_uuid: str = ""
    subject_type: str = ""   # user | group


@dataclass
class AttributeRecord:
    """Single key-value attribute."""

    uuid: str = ""
    key: str = ""
    value: str = ""
    source: str = "local"    # local | synced | computed


@dataclass
class AttributesResponse:
    """All attributes for a subject."""

    attributes: List[AttributeRecord] = field(default_factory=list)
    error: str = ""


@dataclass
class SetAttributeRequest:
    """Upsert a single attribute on a user or group."""

    subject_uuid: str = ""
    subject_type: str = ""
    key: str = ""
    value: str = ""
    source: str = "local"


@dataclass
class AttributeResponse:
    """Single attribute result."""

    attribute: Optional[AttributeRecord] = None
    error: str = ""
