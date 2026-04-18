"""JWT token helpers for testing.

Creates tokens matching the exact structure produced by
services/manager-new/api/v1/auth.py.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from jose import jwt

DEFAULT_SECRET = "test-jwt-secret"
DEFAULT_ALGORITHM = "HS256"
DEFAULT_ACCESS_EXPIRES = timedelta(minutes=30)
DEFAULT_REFRESH_EXPIRES = timedelta(days=7)


def create_test_token(
    user_id: int = 1,
    role: str = "viewer",
    token_type: str = "access",
    secret: str = DEFAULT_SECRET,
    algorithm: str = DEFAULT_ALGORITHM,
    expires_delta: Optional[timedelta] = None,
    expired: bool = False,
    extra_claims: Optional[dict] = None,
) -> str:
    """Create a JWT token matching manager-new's format.

    Args:
        user_id: User ID for the 'sub' claim.
        role: User role (admin, maintainer, viewer).
        token_type: Token type ('access' or 'refresh').
        secret: JWT signing secret.
        algorithm: JWT signing algorithm.
        expires_delta: Custom expiration. Defaults to 30min (access) or 7d (refresh).
        expired: If True, creates an already-expired token.
        extra_claims: Additional claims to merge into the payload.
    """
    now = datetime.now(timezone.utc)

    if expired:
        exp = now - timedelta(hours=1)
    elif expires_delta:
        exp = now + expires_delta
    elif token_type == "refresh":
        exp = now + DEFAULT_REFRESH_EXPIRES
    else:
        exp = now + DEFAULT_ACCESS_EXPIRES

    payload = {
        "sub": str(user_id),
        "type": token_type,
        "exp": exp,
        "iat": now,
    }

    # Access tokens include role
    if token_type == "access":
        payload["role"] = role

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, secret, algorithm=algorithm)


def create_admin_token(
    user_id: int = 1, secret: str = DEFAULT_SECRET
) -> str:
    """Create an admin access token."""
    return create_test_token(user_id=user_id, role="admin", secret=secret)


def create_maintainer_token(
    user_id: int = 2, secret: str = DEFAULT_SECRET
) -> str:
    """Create a maintainer access token."""
    return create_test_token(user_id=user_id, role="maintainer", secret=secret)


def create_viewer_token(
    user_id: int = 3, secret: str = DEFAULT_SECRET
) -> str:
    """Create a viewer access token."""
    return create_test_token(user_id=user_id, role="viewer", secret=secret)


def auth_header(token: str) -> dict:
    """Build an Authorization header dict from a token."""
    return {"Authorization": f"Bearer {token}"}
