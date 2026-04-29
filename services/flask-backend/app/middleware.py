"""Authentication and Authorization Middleware."""

from datetime import datetime, timezone
from functools import wraps
from typing import Callable, Optional

import jwt as pyjwt
from penguin_aaa import Claims
from quart import current_app, g, jsonify, request

from .models import get_user_by_id


# Scope required per role group
_ROLE_SCOPE_MAP: dict[str, str] = {
    "admin": "users:admin",
    "maintainer": "*:write",
}


class LocalTokenValidator:
    """Validates RS256 JWTs issued by the local OIDCProvider without HTTP discovery."""

    def __init__(self, provider, issuer: str, audiences: list[str]) -> None:
        self._provider = provider
        self._issuer = issuer
        self._audiences = audiences

    async def verify_token(self, token: str) -> Claims:
        """Verify and decode RS256 JWT token, returning Claims object."""
        signing_key, _kid = self._provider._keystore.get_signing_key()
        public_key = signing_key.public_key()

        payload = pyjwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience=self._audiences,
            issuer=self._issuer,
        )

        return Claims(
            sub=payload["sub"],
            iss=payload["iss"],
            aud=payload["aud"] if isinstance(payload["aud"], list) else [payload["aud"]],
            iat=datetime.fromtimestamp(payload["iat"], tz=timezone.utc),
            exp=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
            scope=payload.get("scope", []),
            roles=payload.get("roles", []),
            tenant=payload.get("tenant", "default"),
            teams=payload.get("teams", []),
            ext=payload.get("ext", {}),
        )


def get_current_user() -> Optional[dict]:
    """Get current authenticated user from request context."""
    return getattr(g, "current_user", None)


def auth_required(f: Callable) -> Callable:
    """Decorator to require authentication and validate JWT token."""

    @wraps(f)
    async def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")

        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing authorization token"}), 401

        token = auth_header[7:]

        try:
            validator = current_app.extensions.get("token_validator")
            if not validator:
                return jsonify({"error": "Token validator not configured"}), 500
            claims = await validator.verify_token(token)
        except pyjwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({"error": "Invalid or malformed token"}), 401
        except Exception as e:
            return jsonify({"error": "Invalid or expired token"}), 401

        # Get user from database
        user_id = claims.sub
        if not user_id:
            return jsonify({"error": "Invalid token payload"}), 401

        user = await get_user_by_id(int(user_id))
        if not user:
            return jsonify({"error": "User not found"}), 401

        if not user.get("is_active"):
            return jsonify({"error": "User account is deactivated"}), 401

        # Store user and claims in request context
        g.current_user = user
        g.claims = claims

        return await f(*args, **kwargs)

    return decorated


def role_required(*allowed_roles: str) -> Callable:
    """Decorator to require specific roles using OIDC scopes."""

    def decorator(f: Callable) -> Callable:
        @wraps(f)
        async def decorated(*args, **kwargs):
            claims = getattr(g, "claims", None)

            if claims is None:
                return jsonify({"error": "Authentication required"}), 401

            # Check if any allowed role's required scope is present
            user_scopes = set(claims.scope)
            has_access = any(
                _ROLE_SCOPE_MAP.get(role, f"{role}:access") in user_scopes
                or "*:admin" in user_scopes  # admin always has access
                for role in allowed_roles
            )

            if not has_access:
                return (
                    jsonify(
                        {
                            "error": "Insufficient permissions",
                            "required_roles": list(allowed_roles),
                        }
                    ),
                    403,
                )

            return await f(*args, **kwargs)

        return decorated

    return decorator


def admin_required(f: Callable) -> Callable:
    """Decorator to require admin role."""
    return role_required("admin")(f)


def maintainer_or_admin_required(f: Callable) -> Callable:
    """Decorator to require maintainer or admin role."""
    return role_required("admin", "maintainer")(f)
