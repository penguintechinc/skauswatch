"""
checkpoint-core — gRPC client for skauswatch-core (CoreIdentityService).

Wraps the gRPC channel and provides async methods that map to the identity
proto RPCs exposed by skauswatch-core (manager-new).

All methods raise CheckpointCoreError on transport or application-level
gRPC errors so callers can handle them uniformly.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

import grpc

logger = logging.getLogger(__name__)

# ── Custom exception ──────────────────────────────────────────────────────────


class CheckpointCoreError(Exception):
    """Raised when a call to skauswatch-core fails."""

    def __init__(self, message: str, code: grpc.StatusCode | None = None) -> None:
        super().__init__(message)
        self.grpc_code = code


# ── Data transfer objects returned by this client ─────────────────────────────


@dataclass(slots=True)
class UserRecord:
    """Minimal user record returned from skauswatch-core."""

    uuid: str
    username: str
    email: str
    display_name: str
    is_active: bool
    groups: list[str] = field(default_factory=list)
    attributes: dict[str, str] = field(default_factory=dict)


# ── Client ────────────────────────────────────────────────────────────────────


class CoreIdentityClient:
    """
    Async gRPC client that calls skauswatch-core for identity data.

    Checkpoint never owns user/group data — it always delegates to this client.

    Usage::

        client = CoreIdentityClient(host="skauswatch-core", port=50051)
        await client.connect()
        user = await client.get_user(uuid="...")
        await client.close()
    """

    def __init__(self, host: str, port: int) -> None:
        self._target = f"{host}:{port}"
        self._channel: grpc.aio.Channel | None = None
        # NOTE: Stub classes are generated from identity.proto by skauswatch-core.
        # Import them lazily so this module does not hard-fail if proto stubs are
        # not yet generated at import time (e.g. during unit tests).
        self._stub: Any = None

    async def connect(self) -> None:
        """Open the async gRPC channel to skauswatch-core."""
        self._channel = grpc.aio.insecure_channel(self._target)
        try:
            # Lazy import — generated stubs live alongside the identity.proto
            from grpc_generated import identity_pb2_grpc  # type: ignore[import]

            self._stub = identity_pb2_grpc.IdentityServiceStub(self._channel)
            logger.info("core_client.connected target=%s", self._target)
        except ImportError:
            logger.warning(
                "core_client.stubs_missing — run 'make proto' to generate gRPC stubs. "
                "Calls will fail until stubs are available."
            )

    async def close(self) -> None:
        """Close the gRPC channel."""
        if self._channel is not None:
            await self._channel.close()
            logger.info("core_client.disconnected target=%s", self._target)

    # ── Helper ────────────────────────────────────────────────────────────────

    def _require_stub(self) -> Any:
        if self._stub is None:
            raise CheckpointCoreError(
                "CoreIdentityClient is not connected or gRPC stubs are missing. "
                "Call connect() first and ensure proto stubs are generated."
            )
        return self._stub

    @staticmethod
    def _handle_grpc_error(exc: grpc.RpcError, method: str) -> None:
        code: grpc.StatusCode = exc.code()  # type: ignore[attr-defined]
        details: str = exc.details()  # type: ignore[attr-defined]
        logger.error("core_client.rpc_error method=%s code=%s details=%s", method, code, details)
        raise CheckpointCoreError(
            f"skauswatch-core RPC '{method}' failed: {details}", code=code
        ) from exc

    # ── Identity RPCs ─────────────────────────────────────────────────────────

    async def authenticate_user(self, username: str, password: str) -> UserRecord | None:
        """
        Verify credentials against skauswatch-core.

        Returns a UserRecord on success, None if credentials are invalid.
        Raises CheckpointCoreError on transport errors.
        """
        stub = self._require_stub()
        try:
            from grpc_generated import identity_pb2  # type: ignore[import]

            req = identity_pb2.AuthenticateRequest(username=username, password=password)
            resp = await stub.AuthenticateUser(req)
            if not resp.success:
                return None
            return UserRecord(
                uuid=resp.user.uuid,
                username=resp.user.username,
                email=resp.user.email,
                display_name=resp.user.display_name,
                is_active=resp.user.is_active,
            )
        except grpc.RpcError as exc:
            self._handle_grpc_error(exc, "AuthenticateUser")

    async def get_user(self, uuid: str) -> UserRecord | None:
        """Fetch a single user by UUID. Returns None if not found."""
        stub = self._require_stub()
        try:
            from grpc_generated import identity_pb2  # type: ignore[import]

            req = identity_pb2.GetUserRequest(uuid=uuid)
            resp = await stub.GetUser(req)
            if not resp.found:
                return None
            return UserRecord(
                uuid=resp.user.uuid,
                username=resp.user.username,
                email=resp.user.email,
                display_name=resp.user.display_name,
                is_active=resp.user.is_active,
            )
        except grpc.RpcError as exc:
            self._handle_grpc_error(exc, "GetUser")

    async def list_users(
        self, page: int = 0, page_size: int = 100, filter_active: bool | None = None
    ) -> list[UserRecord]:
        """Return a page of users from skauswatch-core."""
        stub = self._require_stub()
        try:
            from grpc_generated import identity_pb2  # type: ignore[import]

            req = identity_pb2.ListUsersRequest(page=page, page_size=page_size)
            if filter_active is not None:
                req.filter_active = filter_active
            resp = await stub.ListUsers(req)
            return [
                UserRecord(
                    uuid=u.uuid,
                    username=u.username,
                    email=u.email,
                    display_name=u.display_name,
                    is_active=u.is_active,
                )
                for u in resp.users
            ]
        except grpc.RpcError as exc:
            self._handle_grpc_error(exc, "ListUsers")
            return []

    async def search_users(self, query: str) -> list[UserRecord]:
        """
        Search users by username, email, or display name.

        Returns a list (possibly empty) of matching UserRecords.
        """
        stub = self._require_stub()
        try:
            from grpc_generated import identity_pb2  # type: ignore[import]

            req = identity_pb2.SearchUsersRequest(query=query)
            resp = await stub.SearchUsers(req)
            return [
                UserRecord(
                    uuid=u.uuid,
                    username=u.username,
                    email=u.email,
                    display_name=u.display_name,
                    is_active=u.is_active,
                )
                for u in resp.users
            ]
        except grpc.RpcError as exc:
            self._handle_grpc_error(exc, "SearchUsers")
            return []

    async def get_user_groups(self, user_uuid: str) -> list[str]:
        """Return a list of group names (or DNs) for the given user UUID."""
        stub = self._require_stub()
        try:
            from grpc_generated import identity_pb2  # type: ignore[import]

            req = identity_pb2.GetUserGroupsRequest(user_uuid=user_uuid)
            resp = await stub.GetUserGroups(req)
            return list(resp.group_names)
        except grpc.RpcError as exc:
            self._handle_grpc_error(exc, "GetUserGroups")
            return []

    async def get_attributes(self, user_uuid: str) -> dict[str, str]:
        """
        Return extended attribute map for a user.

        Keys are LDAP attribute names or OIDC claim names.
        """
        stub = self._require_stub()
        try:
            from grpc_generated import identity_pb2  # type: ignore[import]

            req = identity_pb2.GetAttributesRequest(user_uuid=user_uuid)
            resp = await stub.GetAttributes(req)
            return dict(resp.attributes)
        except grpc.RpcError as exc:
            self._handle_grpc_error(exc, "GetAttributes")
            return {}
