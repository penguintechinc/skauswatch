"""
Auto-generated gRPC servicer base stubs for identity.proto.

Replace with real protoc output:
    python -m grpc_tools.protoc \
        -I./grpc/protos \
        --python_out=./grpc/generated \
        --grpc_python_out=./grpc/generated \
        ./grpc/protos/identity.proto

The concrete implementation lives in grpc/identity_service.py.
"""

import grpc


class IdentityServiceServicer:
    """
    Base servicer for IdentityService — override all methods.

    All unimplemented methods return gRPC UNIMPLEMENTED status.
    The concrete implementation in identity_service.py overrides every method.
    """

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def AuthenticateUser(self, request, context):
        """Authenticate a user by email + password over mTLS gRPC."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def VerifyToken(self, request, context):
        """Verify a JWT session token by its SHA-256 hash."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def RevokeToken(self, request, context):
        """Revoke a JWT session token by its SHA-256 hash."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    # ------------------------------------------------------------------
    # Users (read)
    # ------------------------------------------------------------------

    def GetUser(self, request, context):
        """Fetch a single user by UUID."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def ListUsers(self, request, context):
        """Return a paginated list of users with optional status filter."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def SearchUsers(self, request, context):
        """Full-text search across email, display_name, external_id."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    # ------------------------------------------------------------------
    # Users (write)
    # ------------------------------------------------------------------

    def CreateUser(self, request, context):
        """Create a new local user (SCIM provisioning)."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def UpdateUser(self, request, context):
        """Update mutable fields on an existing user."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def DeleteUser(self, request, context):
        """Delete a user by UUID."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    # ------------------------------------------------------------------
    # Groups (read)
    # ------------------------------------------------------------------

    def GetGroup(self, request, context):
        """Fetch a single group by UUID."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def ListGroups(self, request, context):
        """Return a paginated list of groups."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def GetUserGroups(self, request, context):
        """Return all groups a user belongs to."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    # ------------------------------------------------------------------
    # Groups (write)
    # ------------------------------------------------------------------

    def CreateGroup(self, request, context):
        """Create a new group."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def UpdateGroup(self, request, context):
        """Update mutable fields on a group."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def DeleteGroup(self, request, context):
        """Delete a group by UUID."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    # ------------------------------------------------------------------
    # Memberships
    # ------------------------------------------------------------------

    def AddMembership(self, request, context):
        """Add a user to a group with a specified role."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def RemoveMembership(self, request, context):
        """Remove a user from a group."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    # ------------------------------------------------------------------
    # Attributes
    # ------------------------------------------------------------------

    def GetAttributes(self, request, context):
        """Fetch all key-value attributes for a user or group."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None

    def SetAttribute(self, request, context):
        """Upsert a key-value attribute on a user or group."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details("Method not implemented!")
        return None


def add_IdentityServiceServicer_to_server(
    servicer: IdentityServiceServicer,
    server: grpc.Server,
) -> None:
    """
    Register an IdentityServiceServicer with a gRPC server.

    This is a stub implementation that registers the servicer's methods
    as generic RPC handlers.  When real protoc stubs are generated,
    this function is replaced by the auto-generated version which uses
    proper protobuf serialization descriptors.

    Args:
        servicer: Concrete IdentityServiceServicer implementation.
        server: The grpc.Server instance to register with.
    """
    # Stub: registration is a no-op until protoc stubs replace this file.
    # The real generated version maps method names to request/response
    # serializers via pb2 descriptors.
    pass
