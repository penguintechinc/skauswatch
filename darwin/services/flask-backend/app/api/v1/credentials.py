"""Git Credential CRUD API Endpoints."""

from flask import Blueprint, jsonify, request

from ...middleware import auth_required, admin_required, get_current_user
from ...models import (
    store_credential,
    get_credentials,
    delete_credential,
    get_db,
)

credentials_bp = Blueprint("credentials", __name__, url_prefix="/api/v1/credentials")


@credentials_bp.route("", methods=["POST"])
@auth_required
@admin_required
def create_credential():
    """Create a new git credential."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    # Validate required fields
    required_fields = ["name", "git_url_pattern", "auth_type"]
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Validate auth type
    auth_type = data.get("auth_type")
    if auth_type not in ["https_token", "ssh_key"]:
        return jsonify({
            "error": "Invalid auth_type",
            "valid_types": ["https_token", "ssh_key"],
        }), 400

    # Validate credential data based on type
    if auth_type == "https_token":
        if not data.get("credential"):
            return jsonify({"error": "Token is required for https_token auth_type"}), 400
        encrypted_credential = data.get("credential").encode()
    elif auth_type == "ssh_key":
        if not data.get("credential"):
            return jsonify({"error": "SSH key is required for ssh_key auth_type"}), 400
        encrypted_credential = data.get("credential").encode()

    # Get current user
    from ...middleware import get_current_user
    user = get_current_user()

    ssh_key_passphrase = None
    if data.get("ssh_key_passphrase"):
        ssh_key_passphrase = data.get("ssh_key_passphrase").encode()

    # Store credential
    credential = store_credential(
        name=data.get("name"),
        git_url_pattern=data.get("git_url_pattern"),
        auth_type=auth_type,
        encrypted_credential=encrypted_credential,
        ssh_key_passphrase=ssh_key_passphrase,
        created_by=user.get("id"),
    )

    return jsonify({
        "message": "Credential created successfully",
        "credential": {
            "id": credential.get("id"),
            "name": credential.get("name"),
            "git_url_pattern": credential.get("git_url_pattern"),
            "auth_type": credential.get("auth_type"),
            "created_at": credential.get("created_at"),
        },
    }), 201


@credentials_bp.route("", methods=["GET"])
@auth_required
@admin_required
def list_all_credentials():
    """List all git credentials (admin only)."""
    git_url_pattern = request.args.get("git_url_pattern")

    credentials = get_credentials(git_url_pattern=git_url_pattern)

    # Remove sensitive data from response
    safe_credentials = []
    for cred in credentials:
        safe_cred = {
            "id": cred.get("id"),
            "name": cred.get("name"),
            "git_url_pattern": cred.get("git_url_pattern"),
            "auth_type": cred.get("auth_type"),
            "created_at": cred.get("created_at"),
            "updated_at": cred.get("updated_at"),
        }
        safe_credentials.append(safe_cred)

    return jsonify({
        "data": safe_credentials,
        "total": len(safe_credentials),
        "filters": {
            "git_url_pattern": git_url_pattern,
        },
    }), 200


@credentials_bp.route("/<int:credential_id>", methods=["GET"])
@auth_required
@admin_required
def get_credential(credential_id: int):
    """Get a specific credential (admin only)."""
    db = get_db()

    credential = db(db.git_credentials.id == credential_id).select().first()
    if not credential:
        return jsonify({"error": "Credential not found"}), 404

    # Return safe version without actual credential data
    return jsonify({
        "id": credential.id,
        "name": credential.name,
        "git_url_pattern": credential.git_url_pattern,
        "auth_type": credential.auth_type,
        "created_at": credential.created_at,
        "updated_at": credential.updated_at,
    }), 200


@credentials_bp.route("/<int:credential_id>", methods=["DELETE"])
@auth_required
@admin_required
def delete_git_credential(credential_id: int):
    """Delete a git credential."""
    db = get_db()

    credential = db(db.git_credentials.id == credential_id).select().first()
    if not credential:
        return jsonify({"error": "Credential not found"}), 404

    # Delete credential
    deleted = delete_credential(credential_id)

    return jsonify({
        "message": "Credential deleted successfully",
        "deleted": deleted,
        "credential_id": credential_id,
    }), 200


@credentials_bp.route("/<int:credential_id>", methods=["PATCH"])
@auth_required
@admin_required
def update_credential(credential_id: int):
    """Update a git credential."""
    db = get_db()

    credential = db(db.git_credentials.id == credential_id).select().first()
    if not credential:
        return jsonify({"error": "Credential not found"}), 404

    data = request.get_json()
    if not data:
        return jsonify({"error": "Request body required"}), 400

    # Prepare update data
    update_data = {}

    if "name" in data:
        update_data["name"] = data.get("name")

    if "git_url_pattern" in data:
        update_data["git_url_pattern"] = data.get("git_url_pattern")

    if "credential" in data:
        update_data["encrypted_credential"] = data.get("credential").encode()

    if "ssh_key_passphrase" in data and data.get("ssh_key_passphrase"):
        update_data["ssh_key_passphrase"] = data.get("ssh_key_passphrase").encode()

    # Update credential
    db(db.git_credentials.id == credential_id).update(**update_data)
    db.commit()

    # Fetch updated credential
    updated = db(db.git_credentials.id == credential_id).select().first()

    return jsonify({
        "message": "Credential updated successfully",
        "credential": {
            "id": updated.id,
            "name": updated.name,
            "git_url_pattern": updated.git_url_pattern,
            "auth_type": updated.auth_type,
            "updated_at": updated.updated_at,
        },
    }), 200


@credentials_bp.route("/test", methods=["POST"])
@auth_required
@admin_required
def test_credential():
    """Test a git credential (validates format, not actual connectivity)."""
    data = request.get_json()

    if not data:
        return jsonify({"error": "Request body required"}), 400

    auth_type = data.get("auth_type")
    credential = data.get("credential")

    # Validate auth type
    if auth_type not in ["https_token", "ssh_key"]:
        return jsonify({
            "error": "Invalid auth_type",
            "valid_types": ["https_token", "ssh_key"],
        }), 400

    if not credential:
        return jsonify({"error": "Credential is required"}), 400

    # Basic validation
    if auth_type == "https_token":
        if len(credential) < 10:
            return jsonify({
                "valid": False,
                "error": "Token appears to be too short",
            }), 400
        return jsonify({
            "valid": True,
            "message": "Token format looks valid",
            "type": "https_token",
        }), 200

    elif auth_type == "ssh_key":
        if not credential.startswith("-----BEGIN"):
            return jsonify({
                "valid": False,
                "error": "SSH key does not appear to be in PEM format",
            }), 400
        return jsonify({
            "valid": True,
            "message": "SSH key format looks valid",
            "type": "ssh_key",
        }), 200


@credentials_bp.route("/by-pattern", methods=["GET"])
@auth_required
@admin_required
def get_credentials_by_pattern():
    """Get credentials matching a git URL pattern."""
    pattern = request.args.get("pattern")

    if not pattern:
        return jsonify({"error": "Pattern parameter is required"}), 400

    credentials = get_credentials(git_url_pattern=pattern)

    # Remove sensitive data
    safe_credentials = []
    for cred in credentials:
        safe_cred = {
            "id": cred.get("id"),
            "name": cred.get("name"),
            "git_url_pattern": cred.get("git_url_pattern"),
            "auth_type": cred.get("auth_type"),
        }
        safe_credentials.append(safe_cred)

    return jsonify({
        "pattern": pattern,
        "data": safe_credentials,
        "total": len(safe_credentials),
    }), 200
