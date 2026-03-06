"""Teams API Endpoints - Team management with tenant isolation."""

from flask import Blueprint, jsonify, request

from ...middleware import auth_required, get_current_user
from ...models import get_db

teams_bp = Blueprint("teams", __name__, url_prefix="/api/v1/teams")


def get_user_tenant_id(user: dict) -> int:
    """Extract tenant ID from current user context."""
    return user.get("default_tenant_id")


def is_tenant_admin(user: dict, tenant_id: int) -> bool:
    """Check if user is admin of the given tenant."""
    db = get_db()
    tenant_member = db(
        (db.tenant_members.user_id == user.get("id")) &
        (db.tenant_members.tenant_id == tenant_id)
    ).select().first()

    if not tenant_member:
        return False

    return tenant_member.role == "admin"


def is_team_admin(user: dict, team_id: int) -> bool:
    """Check if user is admin of the given team."""
    db = get_db()
    team_member = db(
        (db.team_members.user_id == user.get("id")) &
        (db.team_members.team_id == team_id)
    ).select().first()

    if not team_member:
        return False

    return team_member.role == "admin"


def is_team_member(user: dict, team_id: int) -> bool:
    """Check if user is member of the given team."""
    db = get_db()
    team_member = db(
        (db.team_members.user_id == user.get("id")) &
        (db.team_members.team_id == team_id)
    ).select().first()

    return team_member is not None


def serialize_team(team_row) -> dict:
    """Convert team database row to JSON-serializable dict."""
    return {
        "id": team_row.id,
        "tenant_id": team_row.tenant_id,
        "name": team_row.name,
        "slug": team_row.slug,
        "description": team_row.description,
        "is_active": team_row.is_active,
        "is_default": team_row.is_default,
        "settings": team_row.settings or {},
        "created_at": team_row.created_at.isoformat() if team_row.created_at else None,
        "updated_at": team_row.updated_at.isoformat() if team_row.updated_at else None,
    }


def serialize_team_member(member_row) -> dict:
    """Convert team_members database row to JSON-serializable dict."""
    return {
        "user_id": member_row.user_id,
        "role": member_row.role,
        "joined_at": member_row.joined_at.isoformat() if member_row.joined_at else None,
    }


@teams_bp.route("", methods=["GET"])
@auth_required
def list_teams():
    """List teams in user's tenant (tenant member)."""
    user = get_current_user()
    tenant_id = get_user_tenant_id(user)

    if not tenant_id:
        return jsonify({"error": "User has no assigned tenant"}), 400

    db = get_db()

    # Get pagination params
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    # Validate pagination
    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20

    # Query teams in tenant
    rows = db(db.teams.tenant_id == tenant_id).select()
    total = len(rows)

    # Paginate
    start = (page - 1) * per_page
    end = start + per_page
    paginated_rows = rows[start:end]

    # Enrich with member counts
    teams = []
    for row in paginated_rows:
        team_dict = serialize_team(row)
        # Count members
        member_count = db(db.team_members.team_id == row.id).count()
        team_dict["member_count"] = member_count
        teams.append(team_dict)

    return jsonify({
        "teams": teams,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }), 200


@teams_bp.route("", methods=["POST"])
@auth_required
def create_team():
    """Create team in user's tenant (tenant admin)."""
    user = get_current_user()
    tenant_id = get_user_tenant_id(user)

    if not tenant_id:
        return jsonify({"error": "User has no assigned tenant"}), 400

    # Check if user is tenant admin
    if not is_tenant_admin(user, tenant_id):
        return jsonify({"error": "Insufficient permissions"}), 403

    data = request.get_json() or {}

    # Validate required fields
    name = data.get("name", "").strip()
    slug = data.get("slug", "").strip().lower()

    if not name:
        return jsonify({"error": "Team name is required"}), 400

    if not slug:
        return jsonify({"error": "Team slug is required"}), 400

    description = data.get("description", "").strip()
    settings = data.get("settings", {})

    if not isinstance(settings, dict):
        return jsonify({"error": "Settings must be a JSON object"}), 400

    db = get_db()

    # Check if slug is unique within tenant
    existing = db(
        (db.teams.tenant_id == tenant_id) &
        (db.teams.slug == slug)
    ).select().first()

    if existing:
        return jsonify({"error": "Team slug already exists in this tenant"}), 409

    # Create team
    team_id = db.teams.insert(
        tenant_id=tenant_id,
        name=name,
        slug=slug,
        description=description,
        is_active=True,
        is_default=False,
        settings=settings,
    )

    # Add creator as team admin
    db.team_members.insert(
        team_id=team_id,
        user_id=user.get("id"),
        role="admin",
    )

    # Get created team
    team = db.teams(team_id)

    return jsonify({
        "message": "Team created successfully",
        "team": serialize_team(team),
    }), 201


@teams_bp.route("/<int:team_id>", methods=["GET"])
@auth_required
def get_team(team_id: int):
    """Get team details (team member)."""
    user = get_current_user()
    tenant_id = get_user_tenant_id(user)

    if not tenant_id:
        return jsonify({"error": "User has no assigned tenant"}), 400

    db = get_db()

    # Fetch team
    team = db.teams(team_id)

    if not team:
        return jsonify({"error": "Team not found"}), 404

    # Check tenant isolation
    if team.tenant_id != tenant_id:
        return jsonify({"error": "Team not found"}), 404

    # Check if user is team member
    if not is_team_member(user, team_id):
        return jsonify({"error": "Insufficient permissions"}), 403

    return jsonify(serialize_team(team)), 200


@teams_bp.route("/<int:team_id>", methods=["PUT"])
@auth_required
def update_team(team_id: int):
    """Update team (tenant admin or team admin)."""
    user = get_current_user()
    tenant_id = get_user_tenant_id(user)

    if not tenant_id:
        return jsonify({"error": "User has no assigned tenant"}), 400

    db = get_db()

    # Fetch team
    team = db.teams(team_id)

    if not team:
        return jsonify({"error": "Team not found"}), 404

    # Check tenant isolation
    if team.tenant_id != tenant_id:
        return jsonify({"error": "Team not found"}), 404

    # Check permissions (tenant admin or team admin)
    is_tenant_admin_user = is_tenant_admin(user, tenant_id)
    is_team_admin_user = is_team_admin(user, team_id)

    if not (is_tenant_admin_user or is_team_admin_user):
        return jsonify({"error": "Insufficient permissions"}), 403

    data = request.get_json() or {}
    update_data = {}

    # Update name
    if "name" in data:
        name = data.get("name", "").strip()
        if not name:
            return jsonify({"error": "Team name cannot be empty"}), 400
        update_data["name"] = name

    # Update description
    if "description" in data:
        update_data["description"] = data.get("description", "").strip()

    # Update settings
    if "settings" in data:
        settings = data.get("settings", {})
        if not isinstance(settings, dict):
            return jsonify({"error": "Settings must be a JSON object"}), 400
        update_data["settings"] = settings

    # Update active status
    if "is_active" in data:
        update_data["is_active"] = bool(data.get("is_active"))

    if not update_data:
        return jsonify({"error": "No valid fields to update"}), 400

    # Update team
    team.update_record(**update_data)

    return jsonify({
        "message": "Team updated successfully",
        "team": serialize_team(team),
    }), 200


@teams_bp.route("/<int:team_id>", methods=["DELETE"])
@auth_required
def delete_team(team_id: int):
    """Delete team (tenant admin, but prevent deleting default team)."""
    user = get_current_user()
    tenant_id = get_user_tenant_id(user)

    if not tenant_id:
        return jsonify({"error": "User has no assigned tenant"}), 400

    # Check if user is tenant admin
    if not is_tenant_admin(user, tenant_id):
        return jsonify({"error": "Insufficient permissions"}), 403

    db = get_db()

    # Fetch team
    team = db.teams(team_id)

    if not team:
        return jsonify({"error": "Team not found"}), 404

    # Check tenant isolation
    if team.tenant_id != tenant_id:
        return jsonify({"error": "Team not found"}), 404

    # Prevent deletion of default team
    if team.is_default:
        return jsonify({"error": "Cannot delete default team"}), 400

    # Delete team (cascades to team_members)
    db(db.teams.id == team_id).delete()

    return jsonify({"message": "Team deleted successfully"}), 200


@teams_bp.route("/<int:team_id>/members", methods=["GET"])
@auth_required
def list_team_members(team_id: int):
    """List team members (team member)."""
    user = get_current_user()
    tenant_id = get_user_tenant_id(user)

    if not tenant_id:
        return jsonify({"error": "User has no assigned tenant"}), 400

    db = get_db()

    # Fetch team
    team = db.teams(team_id)

    if not team:
        return jsonify({"error": "Team not found"}), 404

    # Check tenant isolation
    if team.tenant_id != tenant_id:
        return jsonify({"error": "Team not found"}), 404

    # Check if user is team member
    if not is_team_member(user, team_id):
        return jsonify({"error": "Insufficient permissions"}), 403

    # Get pagination params
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    # Validate pagination
    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20

    # Query team members
    rows = db(db.team_members.team_id == team_id).select()
    total = len(rows)

    # Paginate
    start = (page - 1) * per_page
    end = start + per_page
    paginated_rows = rows[start:end]

    # Enrich with user data
    members = []
    for row in paginated_rows:
        member_data = serialize_team_member(row)
        member_user = db.users(row.user_id)
        if member_user:
            member_data["user"] = {
                "id": member_user.id,
                "email": member_user.email,
                "full_name": member_user.full_name,
            }
        members.append(member_data)

    return jsonify({
        "data": members,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page,
        },
    }), 200


@teams_bp.route("/<int:team_id>/members", methods=["POST"])
@auth_required
def add_team_member(team_id: int):
    """Add user to team (tenant admin or team admin)."""
    user = get_current_user()
    tenant_id = get_user_tenant_id(user)

    if not tenant_id:
        return jsonify({"error": "User has no assigned tenant"}), 400

    db = get_db()

    # Fetch team
    team = db.teams(team_id)

    if not team:
        return jsonify({"error": "Team not found"}), 404

    # Check tenant isolation
    if team.tenant_id != tenant_id:
        return jsonify({"error": "Team not found"}), 404

    # Check permissions (tenant admin or team admin)
    is_tenant_admin_user = is_tenant_admin(user, tenant_id)
    is_team_admin_user = is_team_admin(user, team_id)

    if not (is_tenant_admin_user or is_team_admin_user):
        return jsonify({"error": "Insufficient permissions"}), 403

    data = request.get_json() or {}

    # Get user ID and role
    target_user_id = data.get("user_id")
    role = data.get("role", "viewer")

    if not target_user_id:
        return jsonify({"error": "user_id is required"}), 400

    if role not in ["admin", "maintainer", "viewer"]:
        return jsonify({
            "error": "Invalid role. Must be one of: admin, maintainer, viewer"
        }), 400

    # Check if user exists and belongs to tenant
    target_user = db.users(target_user_id)
    if not target_user:
        return jsonify({"error": "User not found"}), 404

    # Verify target user is in same tenant
    tenant_member = db(
        (db.tenant_members.user_id == target_user_id) &
        (db.tenant_members.tenant_id == tenant_id)
    ).select().first()

    if not tenant_member:
        return jsonify({"error": "User is not a member of this tenant"}), 400

    # Check if already a member
    existing_member = db(
        (db.team_members.team_id == team_id) &
        (db.team_members.user_id == target_user_id)
    ).select().first()

    if existing_member:
        return jsonify({"error": "User is already a team member"}), 409

    # Add user to team
    db.team_members.insert(
        team_id=team_id,
        user_id=target_user_id,
        role=role,
    )

    return jsonify({
        "message": "User added to team successfully",
        "user_id": target_user_id,
        "role": role,
    }), 201


@teams_bp.route("/<int:team_id>/members/<int:user_id>", methods=["DELETE"])
@auth_required
def remove_team_member(team_id: int, user_id: int):
    """Remove user from team (tenant admin or team admin)."""
    user = get_current_user()
    tenant_id = get_user_tenant_id(user)

    if not tenant_id:
        return jsonify({"error": "User has no assigned tenant"}), 400

    db = get_db()

    # Fetch team
    team = db.teams(team_id)

    if not team:
        return jsonify({"error": "Team not found"}), 404

    # Check tenant isolation
    if team.tenant_id != tenant_id:
        return jsonify({"error": "Team not found"}), 404

    # Check permissions (tenant admin or team admin)
    is_tenant_admin_user = is_tenant_admin(user, tenant_id)
    is_team_admin_user = is_team_admin(user, team_id)

    if not (is_tenant_admin_user or is_team_admin_user):
        return jsonify({"error": "Insufficient permissions"}), 403

    # Prevent self-removal
    if user.get("id") == user_id:
        return jsonify({"error": "Cannot remove yourself from team"}), 400

    # Check if user is team member
    member = db(
        (db.team_members.team_id == team_id) &
        (db.team_members.user_id == user_id)
    ).select().first()

    if not member:
        return jsonify({"error": "User is not a team member"}), 404

    # Remove user from team
    db((db.team_members.team_id == team_id) &
       (db.team_members.user_id == user_id)).delete()

    return jsonify({"message": "User removed from team successfully"}), 200
