"""Role-Based Access Control (RBAC) Middleware with OAuth2-style Scopes.

Implements multi-tier RBAC with scope checking at global, tenant, team, and
resource levels. Enforces strict tenant isolation for multi-tenant deployments.
"""

from functools import wraps
from typing import Callable, List, Optional

from flask import g, jsonify

from .middleware import get_current_user
from .models import get_db


# Default scope mappings for built-in roles
ROLE_SCOPE_MAPPINGS = {
    "global": {
        "admin": [
            "system:read", "system:write", "system:admin",
            "tenants:read", "tenants:write", "tenants:admin",
            "users:read", "users:write", "users:admin",
        ],
        "maintainer": [
            "system:read", "tenants:read", "users:read", "users:write",
        ],
        "viewer": [
            "system:read", "tenants:read", "users:read",
        ],
    },
    "tenant": {
        "admin": [
            "tenant:teams:read", "tenant:teams:write", "tenant:teams:admin",
            "tenant:users:read", "tenant:users:write", "tenant:users:admin",
            "tenant:repos:read", "tenant:repos:write", "tenant:repos:admin",
            "tenant:reviews:read", "tenant:reviews:trigger",
        ],
        "maintainer": [
            "tenant:teams:read", "tenant:users:read",
            "tenant:repos:read", "tenant:repos:write",
            "tenant:reviews:read", "tenant:reviews:trigger",
        ],
        "viewer": [
            "tenant:teams:read", "tenant:users:read",
            "tenant:repos:read", "tenant:reviews:read",
        ],
    },
    "team": {
        "admin": [
            "team:repos:read", "team:repos:write", "team:repos:admin",
            "team:reviews:read", "team:reviews:trigger", "team:reviews:cancel",
            "team:members:read", "team:members:write", "team:members:admin",
            "team:credentials:read", "team:credentials:write", "team:credentials:admin",
        ],
        "maintainer": [
            "team:repos:read", "team:repos:write",
            "team:reviews:read", "team:reviews:trigger",
            "team:members:read", "team:credentials:read", "team:credentials:write",
        ],
        "viewer": [
            "team:repos:read", "team:reviews:read",
            "team:members:read", "team:credentials:read",
        ],
    },
    "resource": {
        "owner": [
            "repo:config:read", "repo:config:write", "repo:config:admin",
            "repo:reviews:read", "repo:reviews:trigger", "repo:reviews:cancel",
            "repo:credentials:read", "repo:credentials:write",
        ],
        "maintainer": [
            "repo:config:read", "repo:config:write",
            "repo:reviews:read", "repo:reviews:trigger",
            "repo:credentials:read", "repo:credentials:write",
        ],
        "viewer": [
            "repo:config:read", "repo:reviews:read",
            "repo:credentials:read",
        ],
    },
}


def get_user_scopes(user_id: int) -> List[str]:
    """Aggregate scopes from all RBAC levels (global, tenant, team, resource).

    Scopes are aggregated from:
    1. Global role (users.global_role)
    2. Tenant membership (tenant_members.role)
    3. Team memberships (team_members.role) - can have multiple
    4. Custom roles and direct scope assignments at each level

    Args:
        user_id: User ID to aggregate scopes for

    Returns:
        List of unique scopes the user has across all levels
    """
    db = get_db()
    scopes = set()

    # Get user and verify they exist
    user = db(db.users.id == user_id).select().first()
    if not user:
        return []

    # 1. Add global role scopes
    global_role = user.get("global_role", "viewer")
    scopes.update(ROLE_SCOPE_MAPPINGS["global"].get(global_role, []))

    # 2. Add tenant-level scopes from default tenant membership
    if user.get("default_tenant_id"):
        tenant_member = db(
            (db.tenant_members.user_id == user_id) &
            (db.tenant_members.is_active == True)
        ).select().first()

        if tenant_member:
            tenant_role = tenant_member.get("role", "viewer")
            if tenant_role == "custom" and tenant_member.get("custom_role_id"):
                # Get scopes from custom role
                custom_role = db(
                    db.custom_roles.id == tenant_member.get("custom_role_id")
                ).select().first()
                if custom_role:
                    scopes.update(custom_role.get("scopes", []))
            else:
                scopes.update(ROLE_SCOPE_MAPPINGS["tenant"].get(tenant_role, []))

            # Add direct scope assignments
            if tenant_member.get("scopes"):
                scopes.update(tenant_member.get("scopes", []))

    # 3. Add team-level scopes (users can be in multiple teams)
    team_members = db(
        (db.team_members.user_id == user_id) &
        (db.team_members.is_active == True)
    ).select()

    for team_member in team_members:
        team_role = team_member.get("role", "viewer")
        if team_role == "custom" and team_member.get("custom_role_id"):
            # Get scopes from custom role
            custom_role = db(
                db.custom_roles.id == team_member.get("custom_role_id")
            ).select().first()
            if custom_role:
                scopes.update(custom_role.get("scopes", []))
        else:
            scopes.update(ROLE_SCOPE_MAPPINGS["team"].get(team_role, []))

        # Add direct scope assignments
        if team_member.get("scopes"):
            scopes.update(team_member.get("scopes", []))

    # 4. Add resource-level scopes (from repository_members)
    repo_members = db(
        db.repository_members.user_id == user_id
    ).select()

    for repo_member in repo_members:
        repo_role = repo_member.get("role", "viewer")
        if repo_role == "custom" and repo_member.get("custom_role_id"):
            # Get scopes from custom role
            custom_role = db(
                db.custom_roles.id == repo_member.get("custom_role_id")
            ).select().first()
            if custom_role:
                scopes.update(custom_role.get("scopes", []))
        else:
            scopes.update(ROLE_SCOPE_MAPPINGS["resource"].get(repo_role, []))

        # Add direct scope assignments
        if repo_member.get("scopes"):
            scopes.update(repo_member.get("scopes", []))

    return list(scopes)


def check_permission(user_id: int, required_scope: str) -> bool:
    """Check if user has a specific scope/permission.

    Args:
        user_id: User ID to check
        required_scope: Scope to check for (e.g., "users:read", "team:repos:admin")

    Returns:
        True if user has the scope, False otherwise
    """
    user_scopes = get_user_scopes(user_id)
    return required_scope in user_scopes


def get_user_tenant_filter(user_id: int) -> Optional[int]:
    """Get tenant ID filter for current user's queries.

    For multi-tenant isolation, this returns the tenant_id that should be used
    to filter queries. Global users (with global admin/maintainer roles) can
    access multiple tenants and get None. Tenant users get their specific
    tenant_id.

    Args:
        user_id: User ID to get tenant filter for

    Returns:
        - None if user is a global user (can access multiple tenants)
        - Integer tenant_id if user is a tenant-level user
    """
    db = get_db()
    user = db(db.users.id == user_id).select().first()

    if not user:
        return None

    # Global users (admin/maintainer) can access multiple tenants
    global_role = user.get("global_role", "viewer")
    if global_role in ("admin", "maintainer"):
        return None

    # Tenant users can only see their default_tenant_id
    return user.get("default_tenant_id")


def require_scope(*required_scopes: str) -> Callable:
    """Decorator to check if user has at least one required scope.

    Usage:
        @require_scope("users:read")
        @require_scope("users:write", "users:admin")  # Requires one of these
        def my_endpoint():
            pass

    Args:
        *required_scopes: One or more scopes, user must have at least one

    Returns:
        Decorated function that checks scopes before execution
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401

            user_id = user.get("id")
            if not user_id:
                return jsonify({"error": "Invalid user context"}), 401

            # Check if user has any of the required scopes
            user_scopes = get_user_scopes(user_id)
            has_scope = any(scope in user_scopes for scope in required_scopes)

            if not has_scope:
                return jsonify({
                    "error": "Insufficient permissions",
                    "required_scopes": list(required_scopes),
                }), 403

            return f(*args, **kwargs)

        return decorated

    return decorator


def require_all_scopes(*required_scopes: str) -> Callable:
    """Decorator to check if user has ALL required scopes.

    Usage:
        @require_all_scopes("users:read", "users:write")
        def my_endpoint():
            pass

    Args:
        *required_scopes: All scopes required for access

    Returns:
        Decorated function that checks scopes before execution
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({"error": "Authentication required"}), 401

            user_id = user.get("id")
            if not user_id:
                return jsonify({"error": "Invalid user context"}), 401

            # Check if user has all required scopes
            user_scopes = set(get_user_scopes(user_id))
            required = set(required_scopes)

            if not required.issubset(user_scopes):
                missing = required - user_scopes
                return jsonify({
                    "error": "Insufficient permissions",
                    "required_scopes": list(required_scopes),
                    "missing_scopes": list(missing),
                }), 403

            return f(*args, **kwargs)

        return decorated

    return decorator


def require_tenant_access(f: Callable) -> Callable:
    """Decorator to enforce tenant isolation for tenant-level users.

    Ensures users can only access data within their assigned tenant.
    Global users (admin/maintainer) can access any tenant.

    Usage:
        @require_tenant_access
        def list_repos():
            tenant_filter = get_user_tenant_filter(user.id)
            # Use tenant_filter in queries to isolate by tenant

    Args:
        f: Function to decorate

    Returns:
        Decorated function with tenant isolation enforcement
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401

        # Store tenant filter in g for use in the endpoint
        user_id = user.get("id")
        tenant_filter = get_user_tenant_filter(user_id)
        g.user_tenant_filter = tenant_filter

        return f(*args, **kwargs)

    return decorated


def require_team_access(f: Callable) -> Callable:
    """Decorator to enforce team isolation for team-level users.

    For team-level operations, users can only access their team's resources.
    Global and tenant-level admins bypass this restriction.

    Usage:
        @require_team_access
        def list_team_repos():
            user_teams = get_user_teams(user.id)
            # Use user_teams in queries to isolate by team

    Args:
        f: Function to decorate

    Returns:
        Decorated function with team isolation enforcement
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({"error": "Authentication required"}), 401

        # Get user's team memberships
        user_id = user.get("id")
        db = get_db()

        team_members = db(
            (db.team_members.user_id == user_id) &
            (db.team_members.is_active == True)
        ).select()

        team_ids = [tm.get("team_id") for tm in team_members]
        g.user_team_ids = team_ids if team_ids else []

        return f(*args, **kwargs)

    return decorated


def enforce_tenant_isolation(query, user_id: int):
    """Apply tenant isolation to a PyDAL query.

    Modifies the query to only return data belonging to the user's tenant.
    Global users get unfiltered results.

    Usage in endpoints:
        repos = db.repo_configs.select()
        repos = enforce_tenant_isolation(repos, user.id)

    Args:
        query: PyDAL query object
        user_id: User ID to enforce isolation for

    Returns:
        Filtered query object
    """
    tenant_filter = get_user_tenant_filter(user_id)
    if tenant_filter is not None:
        # Tenant user - filter by their tenant_id
        return query.where(db.repo_configs.tenant_id == tenant_filter)
    # Global user - return unfiltered
    return query


def get_user_teams(user_id: int) -> List[int]:
    """Get list of team IDs that user is a member of.

    Args:
        user_id: User ID

    Returns:
        List of team IDs the user belongs to
    """
    db = get_db()
    team_members = db(
        (db.team_members.user_id == user_id) &
        (db.team_members.is_active == True)
    ).select()

    return [tm.get("team_id") for tm in team_members]


def get_user_tenant_id(user_id: int) -> Optional[int]:
    """Get user's default tenant ID.

    Args:
        user_id: User ID

    Returns:
        User's default_tenant_id or None if not set
    """
    db = get_db()
    user = db(db.users.id == user_id).select().first()
    return user.get("default_tenant_id") if user else None
