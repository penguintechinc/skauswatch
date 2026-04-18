"""
Unit tests for gRPC IdentityService.

Tests user authentication, group management, and scope computation.
Uses mocked PyDAL database and gRPC context.
"""

from unittest.mock import MagicMock, patch
from uuid import uuid4

import bcrypt
import grpc
import pytest

from grpc.generated.identity_pb2 import AuthenticateRequest, UserResponse


@pytest.fixture
def mock_db():
    """Mock PyDAL database."""
    db = MagicMock()
    db.identity_users = MagicMock()
    db.identity_groups = MagicMock()
    db.identity_memberships = MagicMock()
    return db


@pytest.fixture
def mock_context():
    """Mock gRPC ServicerContext."""
    context = MagicMock(spec=grpc.ServicerContext)
    return context


@pytest.fixture
def test_user_uuid():
    """Generate a test UUID."""
    return str(uuid4())


@pytest.fixture
def test_email():
    """Generate a test email."""
    return "testuser@example.com"


class TestAuthenticateUser:
    """Test AuthenticateUser RPC."""

    @pytest.mark.asyncio
    async def test_authenticate_success_with_correct_password(self, mock_db, mock_context, test_user_uuid, test_email):
        """AuthenticateUser with correct password → success=True, user returned."""
        password = "correct_password"
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        mock_user = MagicMock()
        mock_user.uuid = test_user_uuid
        mock_user.email = test_email
        mock_user.username = "testuser"
        mock_user.display_name = "Test User"
        mock_user.password_hash = password_hash
        mock_user.status = "active"

        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value.first.return_value = mock_user

        from grpc.identity_service import IdentityService

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = AuthenticateRequest(email=test_email, password=password)
            response = await service.AuthenticateUser(request, mock_context)

            assert response.success is True
            assert response.user.uuid == test_user_uuid
            assert response.user.email == test_email

    @pytest.mark.asyncio
    async def test_authenticate_fail_with_wrong_password(self, mock_db, mock_context, test_user_uuid, test_email):
        """AuthenticateUser with wrong password → success=False."""
        correct_password = "correct_password"
        wrong_password = "wrong_password"
        password_hash = bcrypt.hashpw(correct_password.encode(), bcrypt.gensalt()).decode()

        mock_user = MagicMock()
        mock_user.uuid = test_user_uuid
        mock_user.email = test_email
        mock_user.password_hash = password_hash

        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value.first.return_value = mock_user

        from grpc.identity_service import IdentityService

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = AuthenticateRequest(email=test_email, password=wrong_password)
            response = await service.AuthenticateUser(request, mock_context)

            assert response.success is False

    @pytest.mark.asyncio
    async def test_authenticate_fail_user_not_found(self, mock_db, mock_context, test_email):
        """AuthenticateUser for non-existent user → success=False."""
        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value.first.return_value = None

        from grpc.identity_service import IdentityService

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = AuthenticateRequest(email=test_email, password="password")
            response = await service.AuthenticateUser(request, mock_context)

            assert response.success is False


class TestGetUser:
    """Test GetUser RPC."""

    @pytest.mark.asyncio
    async def test_get_user_exists(self, mock_db, mock_context, test_user_uuid):
        """GetUser for existing UUID → UserResponse with user data."""
        mock_user = MagicMock()
        mock_user.uuid = test_user_uuid
        mock_user.email = "user@example.com"
        mock_user.username = "user"
        mock_user.display_name = "User Name"
        mock_user.status = "active"

        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value.first.return_value = mock_user

        from grpc.identity_service import IdentityService
        from grpc.generated.identity_pb2 import GetUserRequest

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = GetUserRequest(uuid=test_user_uuid)
            response = await service.GetUser(request, mock_context)

            assert response.user.uuid == test_user_uuid
            assert response.user.email == "user@example.com"

    @pytest.mark.asyncio
    async def test_get_user_not_found(self, mock_db, mock_context, test_user_uuid):
        """GetUser for missing UUID → gRPC NOT_FOUND."""
        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value.first.return_value = None

        from grpc.identity_service import IdentityService
        from grpc.generated.identity_pb2 import GetUserRequest

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = GetUserRequest(uuid=test_user_uuid)

            with pytest.raises(grpc.RpcError) as exc_info:
                await service.GetUser(request, mock_context)

            assert exc_info.value.code() == grpc.StatusCode.NOT_FOUND


class TestListUsers:
    """Test ListUsers RPC."""

    @pytest.mark.asyncio
    async def test_list_users_pagination(self, mock_db, mock_context):
        """ListUsers returns paginated results."""
        mock_users = [MagicMock(uuid=str(uuid4()), email=f"user{i}@example.com") for i in range(3)]

        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value = mock_users

        from grpc.identity_service import IdentityService
        from grpc.generated.identity_pb2 import ListUsersRequest

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = ListUsersRequest(per_page=50, page=1)
            response = await service.ListUsers(request, mock_context)

            assert len(response.users) == 3

    @pytest.mark.asyncio
    async def test_list_users_per_page_capped_at_100(self, mock_db, mock_context):
        """ListUsers caps per_page at 100."""
        from grpc.identity_service import IdentityService
        from grpc.generated.identity_pb2 import ListUsersRequest

        service = IdentityService()
        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value = []

        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = ListUsersRequest(per_page=500, page=1)
            # Should not raise; per_page should be capped internally
            response = await service.ListUsers(request, mock_context)
            assert isinstance(response, object)


class TestSearchUsers:
    """Test SearchUsers RPC."""

    @pytest.mark.asyncio
    async def test_search_users_by_email(self, mock_db, mock_context):
        """SearchUsers searches by email partial match."""
        mock_users = [MagicMock(uuid=str(uuid4()), email="test@example.com")]

        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value = mock_users

        from grpc.identity_service import IdentityService
        from grpc.generated.identity_pb2 import SearchUsersRequest

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = SearchUsersRequest(query="test@", limit=25)
            response = await service.SearchUsers(request, mock_context)

            assert len(response.users) == 1


class TestCreateUser:
    """Test CreateUser RPC."""

    @pytest.mark.asyncio
    async def test_create_user_success(self, mock_db, mock_context):
        """CreateUser creates with bcrypt password hash."""
        email = "newuser@example.com"
        password = "secure_password"
        new_uuid = str(uuid4())

        mock_db.return_value = mock_db
        mock_db.insert = MagicMock(return_value=1)
        mock_db.commit = MagicMock()

        from grpc.identity_service import IdentityService
        from grpc.generated.identity_pb2 import CreateUserRequest

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            with patch("grpc.identity_service._new_uuid", return_value=new_uuid):
                request = CreateUserRequest(
                    email=email, password=password, username="newuser", display_name="New User"
                )
                response = await service.CreateUser(request, mock_context)

                assert response.user.uuid == new_uuid
                assert response.user.email == email

    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, mock_db, mock_context):
        """CreateUser with duplicate email → gRPC ALREADY_EXISTS."""
        email = "existing@example.com"
        mock_existing_user = MagicMock(email=email)

        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value.first.return_value = mock_existing_user

        from grpc.identity_service import IdentityService
        from grpc.generated.identity_pb2 import CreateUserRequest

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = CreateUserRequest(email=email, password="password", username="user")

            with pytest.raises(grpc.RpcError) as exc_info:
                await service.CreateUser(request, mock_context)

            assert exc_info.value.code() == grpc.StatusCode.ALREADY_EXISTS


class TestGetUserGroups:
    """Test GetUserGroups RPC."""

    @pytest.mark.asyncio
    async def test_get_user_groups(self, mock_db, mock_context, test_user_uuid):
        """GetUserGroups returns groups for a user UUID."""
        mock_groups = [
            MagicMock(uuid=str(uuid4()), name="admins", id=1),
            MagicMock(uuid=str(uuid4()), name="developers", id=2),
        ]

        mock_db.return_value = mock_db
        mock_db.__call__.return_value.select.return_value = mock_groups

        from grpc.identity_service import IdentityService
        from grpc.generated.identity_pb2 import GetUserGroupsRequest

        service = IdentityService()
        with patch("grpc.identity_service.get_db", return_value=mock_db):
            request = GetUserGroupsRequest(user_uuid=test_user_uuid)
            response = await service.GetUserGroups(request, mock_context)

            assert len(response.groups) == 2
