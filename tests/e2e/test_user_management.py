"""
E2E test: Admin login → Create user → New user logs in →
Views profile → Admin deletes user → Deleted user can't login.

All tests connect to the SkausWatch Manager service (default localhost:5004).
Tests are skipped automatically when the service is unreachable.
Timeout: 60 s per test.
"""

import os
import uuid

import httpx
import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def manager_base_url() -> str:
    """Manager service base URL."""
    return os.getenv("MANAGER_URL", "http://localhost:5004")


@pytest.fixture(scope="module")
def admin_credentials() -> dict:
    """Admin user credentials for E2E tests."""
    return {
        "email": os.getenv("E2E_ADMIN_EMAIL", "admin@skauswatch.local"),
        "password": os.getenv("E2E_ADMIN_PASSWORD", "AdminPassword1!"),
    }


def _is_service_available(url: str, path: str = "/healthz", timeout: float = 3.0) -> bool:
    """Return True if the service responds with HTTP 2xx at the given path."""
    try:
        response = httpx.get(f"{url}{path}", timeout=timeout)
        return response.status_code < 300
    except (httpx.ConnectError, httpx.TimeoutException, OSError):
        return False


@pytest.fixture(scope="module")
def manager_available(manager_base_url: str) -> bool:
    """True when the Manager service is reachable."""
    return _is_service_available(manager_base_url)


@pytest.fixture(scope="module")
def admin_token(
    manager_base_url: str,
    admin_credentials: dict,
    manager_available: bool,
) -> str:
    """Obtain an admin Bearer token; skip the test session if login fails."""
    if not manager_available:
        pytest.skip("Manager service is not available")

    response = httpx.post(
        f"{manager_base_url}/api/v1/auth/login",
        json=admin_credentials,
        timeout=10,
    )
    if response.status_code != 200:
        pytest.skip(
            f"Admin login failed (HTTP {response.status_code}). "
            "Ensure admin credentials are correct."
        )
    return response.json()["access_token"]


@pytest.fixture
def admin_headers(admin_token: str) -> dict:
    """Authorization headers for the admin user."""
    return {"Authorization": f"Bearer {admin_token}"}


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _unique_email(prefix: str = "e2e") -> str:
    """Generate a unique email address for test users."""
    return f"{prefix}-{uuid.uuid4().hex[:8]}@e2e.skauswatch.test"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.e2e
class TestUserLifecycle:
    """Full user lifecycle: create → login → profile → delete → verify."""

    def test_user_lifecycle(
        self,
        manager_base_url: str,
        admin_headers: dict,
        manager_available: bool,
    ):
        """Admin creates user → user logs in → views own profile → admin deletes user →
        deleted user cannot login.
        """
        if not manager_available:
            pytest.skip("Manager service is not available")

        test_email = _unique_email("lifecycle")
        test_password = "E2eTestPass1!"

        with httpx.Client(timeout=30) as client:
            # ---- Step 1: Admin creates a new viewer user ----
            create_resp = client.post(
                f"{manager_base_url}/api/v1/users",
                json={
                    "email": test_email,
                    "password": test_password,
                    "full_name": "E2E Lifecycle User",
                    "role": "viewer",
                    "is_active": True,
                },
                headers=admin_headers,
            )
            assert create_resp.status_code == 201, (
                f"User creation failed: {create_resp.status_code} — {create_resp.text}"
            )
            created_user = create_resp.json()
            user_data = created_user.get("user", created_user)
            user_id = user_data["id"]
            assert user_data["email"] == test_email
            assert user_data["role"] == "viewer"

            # ---- Step 2: New user logs in ----
            login_resp = client.post(
                f"{manager_base_url}/api/v1/auth/login",
                json={"email": test_email, "password": test_password},
            )
            assert login_resp.status_code == 200, (
                f"New user login failed: {login_resp.status_code} — {login_resp.text}"
            )
            user_token = login_resp.json()["access_token"]
            assert user_token
            user_headers = {"Authorization": f"Bearer {user_token}"}

            # ---- Step 3: New user views own profile ----
            profile_resp = client.get(
                f"{manager_base_url}/api/v1/auth/me",
                headers=user_headers,
            )
            assert profile_resp.status_code == 200, (
                f"Profile fetch failed: {profile_resp.status_code} — {profile_resp.text}"
            )
            profile = profile_resp.json()
            assert profile["email"] == test_email
            assert profile["role"] == "viewer"

            # ---- Step 4: New user views own user record by ID ----
            get_user_resp = client.get(
                f"{manager_base_url}/api/v1/users/{user_id}",
                headers=user_headers,
            )
            assert get_user_resp.status_code == 200, (
                f"User GET failed: {get_user_resp.status_code} — {get_user_resp.text}"
            )
            assert get_user_resp.json()["id"] == user_id

            # ---- Step 5: Admin deletes the user ----
            delete_resp = client.delete(
                f"{manager_base_url}/api/v1/users/{user_id}",
                headers=admin_headers,
            )
            assert delete_resp.status_code in (200, 204), (
                f"User deletion failed: {delete_resp.status_code} — {delete_resp.text}"
            )

            # ---- Step 6: Deleted user cannot log in ----
            post_delete_login = client.post(
                f"{manager_base_url}/api/v1/auth/login",
                json={"email": test_email, "password": test_password},
            )
            assert post_delete_login.status_code in (401, 404), (
                f"Expected 401/404 after deletion, got {post_delete_login.status_code}"
            )


@pytest.mark.e2e
class TestRoleBasedAccess:
    """Role-based access control: viewer cannot access admin endpoints."""

    def test_role_based_access(
        self,
        manager_base_url: str,
        admin_headers: dict,
        manager_available: bool,
    ):
        """Admin creates viewer user → viewer cannot create users (admin-only endpoint).

        Verifies that the viewer role is enforced on privileged endpoints.
        """
        if not manager_available:
            pytest.skip("Manager service is not available")

        viewer_email = _unique_email("viewer-rbac")
        viewer_password = "E2eViewerPass1!"

        with httpx.Client(timeout=30) as client:
            # ---- Step 1: Admin creates a viewer user ----
            create_resp = client.post(
                f"{manager_base_url}/api/v1/users",
                json={
                    "email": viewer_email,
                    "password": viewer_password,
                    "full_name": "E2E RBAC Viewer",
                    "role": "viewer",
                    "is_active": True,
                },
                headers=admin_headers,
            )
            assert create_resp.status_code == 201, (
                f"Viewer creation failed: {create_resp.status_code} — {create_resp.text}"
            )
            viewer_data = create_resp.json().get("user", create_resp.json())
            viewer_id = viewer_data["id"]

            # ---- Step 2: Viewer logs in ----
            viewer_login = client.post(
                f"{manager_base_url}/api/v1/auth/login",
                json={"email": viewer_email, "password": viewer_password},
            )
            assert viewer_login.status_code == 200, (
                f"Viewer login failed: {viewer_login.status_code} — {viewer_login.text}"
            )
            viewer_token = viewer_login.json()["access_token"]
            viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

            # ---- Step 3: Viewer cannot access the user list (admin/maintainer only) ----
            list_users_resp = client.get(
                f"{manager_base_url}/api/v1/users",
                headers=viewer_headers,
            )
            assert list_users_resp.status_code in (403, 401), (
                f"Expected 403/401 for viewer on /api/v1/users, "
                f"got {list_users_resp.status_code}"
            )

            # ---- Step 4: Viewer cannot create a new user (admin-only) ----
            another_email = _unique_email("viewer-created")
            create_by_viewer = client.post(
                f"{manager_base_url}/api/v1/users",
                json={
                    "email": another_email,
                    "password": "SomePassword1!",
                    "full_name": "Should Not Exist",
                    "role": "viewer",
                },
                headers=viewer_headers,
            )
            assert create_by_viewer.status_code in (403, 401), (
                f"Expected 403/401 for viewer on POST /api/v1/users, "
                f"got {create_by_viewer.status_code}"
            )

            # ---- Step 5: Viewer can read own profile ----
            own_profile = client.get(
                f"{manager_base_url}/api/v1/auth/me",
                headers=viewer_headers,
            )
            assert own_profile.status_code == 200

            # ---- Cleanup: Admin deletes the viewer ----
            client.delete(
                f"{manager_base_url}/api/v1/users/{viewer_id}",
                headers=admin_headers,
            )

    def test_unauthenticated_requests_rejected(
        self,
        manager_base_url: str,
        manager_available: bool,
    ):
        """Unauthenticated requests to protected endpoints return 401."""
        if not manager_available:
            pytest.skip("Manager service is not available")

        with httpx.Client(timeout=10) as client:
            protected_paths = [
                "/api/v1/auth/me",
                "/api/v1/users",
                "/api/v1/s3-scan/buckets",
                "/api/v1/threat-intel/iocs",
            ]
            for path in protected_paths:
                resp = client.get(f"{manager_base_url}{path}")
                assert resp.status_code == 401, (
                    f"Expected 401 for unauthenticated GET {path}, got {resp.status_code}"
                )
