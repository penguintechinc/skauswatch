"""Platform Identity API Endpoints - Link external platform accounts to Darwin users."""

from flask import Blueprint, g, jsonify, request

from ...middleware import auth_required, admin_required
from ...models import (
    create_platform_identity,
    get_platform_identities,
    get_platform_identity_by_id,
    delete_platform_identity,
    list_all_platform_identities,
    get_db,
)

platform_identities_bp = Blueprint(
    "platform_identities", __name__,
    url_prefix="/api/v1/platform-identities",
)


@platform_identities_bp.route("", methods=["GET"])
@auth_required
def list_my_identities():
    """List current user's platform identities."""
    user = g.current_user
    identities = get_platform_identities(user.get("id"))
    return jsonify({"data": identities, "total": len(identities)}), 200


@platform_identities_bp.route("", methods=["POST"])
@auth_required
def link_platform_account():
    """Link a platform account to the current user."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    platform = data.get("platform")
    username = data.get("platform_username")

    if not platform or not username:
        return jsonify({"error": "Missing required fields: platform, platform_username"}), 400

    if platform not in ["github", "gitlab"]:
        return jsonify({"error": "Platform must be 'github' or 'gitlab'"}), 400

    # Check if this platform+username is already linked
    db = get_db()
    existing = db(
        (db.platform_identities.platform == platform) &
        (db.platform_identities.platform_username == username)
    ).select().first()

    if existing:
        return jsonify({"error": "This platform account is already linked to a user"}), 409

    user = g.current_user
    identity = create_platform_identity(
        user_id=user.get("id"),
        platform=platform,
        username=username,
        platform_user_id=data.get("platform_user_id"),
        avatar_url=data.get("platform_avatar_url"),
    )

    return jsonify(identity), 201


@platform_identities_bp.route("/<int:identity_id>", methods=["DELETE"])
@auth_required
def unlink_platform_account(identity_id: int):
    """Unlink a platform account from the current user."""
    identity = get_platform_identity_by_id(identity_id)

    if not identity:
        return jsonify({"error": "Platform identity not found"}), 404

    # Ensure the identity belongs to the current user
    user = g.current_user
    if identity.get("user_id") != user.get("id"):
        return jsonify({"error": "Not authorized to delete this identity"}), 403

    delete_platform_identity(identity_id)
    return jsonify({"message": "Platform identity removed"}), 200


@platform_identities_bp.route("/admin", methods=["GET"])
@auth_required
@admin_required
def list_all_identities():
    """Admin: list all platform identities."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    if page < 1:
        page = 1
    if per_page < 1 or per_page > 100:
        per_page = 20

    identities, total = list_all_platform_identities(page=page, per_page=per_page)

    return jsonify({
        "data": identities,
        "pagination": {
            "page": page,
            "per_page": per_page,
            "total": total,
            "pages": (total + per_page - 1) // per_page if total > 0 else 0,
        },
    }), 200
