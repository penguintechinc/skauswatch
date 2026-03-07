"""
IceBox RBAC & JWT middleware.

All permission checks use OIDC claims and scopes — never ad-hoc role strings.
Roles are pre-bundled scope sets; this module checks scopes only.

IceBox roles (expanded at token issuance by auth service):
    vault_admin   → secrets:* jit:* audit:read sync:admin pki:* ssh:*
    secret_owner  → secrets:read secrets:write jit:approve pki:read ssh:read
    secret_user   → secrets:read jit:request
    auditor       → audit:read secrets:read

Usage:
    @bp.route("/secrets")
    @auth_required
    @require_scope("secrets:read")
    async def list_secrets():
        user_id = g.token_claims["sub"]
        ...
"""

from __future__ import annotations

import functools
import logging
from typing import Callable, List, Optional

import jwt
from quart import current_app, g, jsonify, request

logger = logging.getLogger(__name__)

# Roles are pre-bundled scope sets — auth service expands these at token issuance.
# Stored here for documentation only; authorization always checks g.token_scopes.
ROLE_SCOPES = {
    "vault_admin": [
        "secrets:read", "secrets:write", "secrets:admin", "secrets:delete",
        "jit:request", "jit:approve",
        "audit:read",
        "sync:admin", "sync:read",
        "pki:read", "pki:write", "pki:admin",
        "ssh:read", "ssh:write", "ssh:admin",
    ],
    "secret_owner": [
        "secrets:read", "secrets:write",
        "jit:approve",
        "pki:read", "ssh:read",
    ],
    "secret_user": ["secrets:read", "jit:request"],
    "auditor": ["audit:read", "secrets:read"],
}


def _decode_jwt(token: str) -> Optional[dict]:
    """Decode and validate JWT. Returns claims dict or None on failure."""
    config = current_app.config["ICEBOX_CONFIG"]
    try:
        return jwt.decode(
            token,
            config.auth.jwt_secret,
            algorithms=[config.auth.jwt_algorithm],
            options={"require": ["sub", "exp", "scope"]},
        )
    except jwt.ExpiredSignatureError:
        logger.warning("JWT expired")
        return None
    except jwt.InvalidTokenError as exc:
        logger.warning("JWT invalid: %s", exc)
        return None


def auth_required(fn: Callable) -> Callable:
    """
    Decorator: validate JWT and inject claims into g.

    Sets:
        g.token_claims  — full decoded JWT payload
        g.user_id       — subject claim (sub)
        g.tenant_id     — tenant claim
        g.token_scopes  — set of scope strings from 'scope' claim
    """
    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        # Support JIT token override (checked in secrets.py value endpoint)
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401

        token = auth_header.removeprefix("Bearer ").strip()
        claims = _decode_jwt(token)
        if claims is None:
            return jsonify({"error": "Invalid or expired token"}), 401

        g.token_claims = claims
        g.user_id = claims.get("sub", "")
        g.tenant_id = claims.get("tenant", "default")
        g.token_scopes = set(claims.get("scope", "").split())
        g.raw_token = token

        return await fn(*args, **kwargs)

    return wrapper


def require_scope(*scopes: str) -> Callable:
    """
    Decorator factory: require ALL listed scopes in g.token_scopes.

    Must be applied after @auth_required.
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            missing = [s for s in scopes if s not in g.token_scopes]
            if missing:
                logger.warning(
                    "Scope check failed for user %s: missing %s",
                    g.user_id,
                    missing,
                )
                return jsonify({
                    "error": "Insufficient scope",
                    "required": list(scopes),
                    "missing": missing,
                }), 403
            return await fn(*args, **kwargs)
        return wrapper
    return decorator


def require_any_scope(*scopes: str) -> Callable:
    """
    Decorator factory: require at least ONE of the listed scopes.

    Used for endpoints accessible by multiple roles (e.g., both
    jit:request and jit:approve can list JIT requests).
    """
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            if not any(s in g.token_scopes for s in scopes):
                return jsonify({
                    "error": "Insufficient scope",
                    "required_any": list(scopes),
                }), 403
            return await fn(*args, **kwargs)
        return wrapper
    return decorator
