"""License Policy API Endpoints."""

from flask import Blueprint, jsonify, request

from ...middleware import auth_required, role_required
from ...models import (
    create_license_policy,
    get_license_policy,
    list_license_policies,
    delete_license_policy,
    get_review_license_violations,
    update_violation_status,
)

licenses_bp = Blueprint("licenses", __name__, url_prefix="/api/v1/licenses")


@licenses_bp.route("/policies", methods=["GET"])
@auth_required
def list_policies():
    """List all license policies."""
    policies = list_license_policies()
    return jsonify({"policies": policies}), 200


@licenses_bp.route("/policies/<license_name>", methods=["GET"])
@auth_required
def get_policy(license_name: str):
    """Get a specific license policy."""
    policy = get_license_policy(license_name)

    if not policy:
        return jsonify({"error": "Policy not found"}), 404

    return jsonify(policy), 200


@licenses_bp.route("/policies", methods=["POST"])
@auth_required
@role_required("admin", "maintainer")
def create_policy():
    """Create or update a license policy."""
    data = request.get_json() or {}

    license_name = data.get("license_name")
    if not license_name:
        return jsonify({"error": "license_name is required"}), 400

    policy = data.get("policy", "allowed")
    if policy not in ["allowed", "blocked", "review_required"]:
        return jsonify({
            "error": "policy must be 'allowed', 'blocked', or 'review_required'"
        }), 400

    actions = data.get("actions", ["warn"])
    if not isinstance(actions, list):
        return jsonify({"error": "actions must be a list"}), 400

    # Validate actions
    valid_actions = ["block", "warn", "alert"]
    for action in actions:
        if action not in valid_actions:
            return jsonify({
                "error": f"Invalid action '{action}'. Must be one of: {', '.join(valid_actions)}"
            }), 400

    description = data.get("description", "")

    policy_result = create_license_policy(
        license_name=license_name,
        policy=policy,
        actions=actions,
        description=description,
    )

    return jsonify(policy_result), 201


@licenses_bp.route("/policies/<license_name>", methods=["PUT"])
@auth_required
@role_required("admin", "maintainer")
def update_policy(license_name: str):
    """Update a license policy."""
    data = request.get_json() or {}

    policy = data.get("policy")
    if policy and policy not in ["allowed", "blocked", "review_required"]:
        return jsonify({
            "error": "policy must be 'allowed', 'blocked', or 'review_required'"
        }), 400

    actions = data.get("actions")
    if actions and not isinstance(actions, list):
        return jsonify({"error": "actions must be a list"}), 400

    if actions:
        valid_actions = ["block", "warn", "alert"]
        for action in actions:
            if action not in valid_actions:
                return jsonify({
                    "error": f"Invalid action '{action}'. Must be one of: {', '.join(valid_actions)}"
                }), 400

    description = data.get("description", "")

    # Create or update
    policy_result = create_license_policy(
        license_name=license_name,
        policy=policy or "allowed",
        actions=actions or ["warn"],
        description=description,
    )

    return jsonify(policy_result), 200


@licenses_bp.route("/policies/<license_name>", methods=["DELETE"])
@auth_required
@role_required("admin")
def delete_policy_endpoint(license_name: str):
    """Delete a license policy."""
    success = delete_license_policy(license_name)

    if not success:
        return jsonify({"error": "Policy not found"}), 404

    return jsonify({"message": "Policy deleted successfully"}), 200


@licenses_bp.route("/violations/<int:review_id>", methods=["GET"])
@auth_required
def get_violations(review_id: int):
    """Get license violations for a review."""
    violations = get_review_license_violations(review_id)
    return jsonify({"violations": violations}), 200


@licenses_bp.route("/violations/<int:violation_id>", methods=["PATCH"])
@auth_required
@role_required("admin", "maintainer")
def update_violation(violation_id: int):
    """Update license violation status."""
    data = request.get_json() or {}

    status = data.get("status")
    if not status:
        return jsonify({"error": "status is required"}), 400

    if status not in ["open", "acknowledged", "resolved", "suppressed"]:
        return jsonify({
            "error": "status must be 'open', 'acknowledged', 'resolved', or 'suppressed'"
        }), 400

    violation = update_violation_status(violation_id, status)

    if not violation:
        return jsonify({"error": "Violation not found"}), 404

    return jsonify(violation), 200


@licenses_bp.route("/common", methods=["GET"])
@auth_required
def get_common_licenses():
    """Get list of common open-source licenses with recommended policies."""
    common_licenses = [
        {
            "name": "MIT",
            "category": "permissive",
            "recommended_policy": "allowed",
            "description": "Very permissive, allows commercial use"
        },
        {
            "name": "Apache-2.0",
            "category": "permissive",
            "recommended_policy": "allowed",
            "description": "Permissive with patent grant"
        },
        {
            "name": "BSD-3-Clause",
            "category": "permissive",
            "recommended_policy": "allowed",
            "description": "Permissive with attribution requirement"
        },
        {
            "name": "GPL-3.0",
            "category": "copyleft",
            "recommended_policy": "review_required",
            "description": "Strong copyleft, requires source disclosure"
        },
        {
            "name": "LGPL-3.0",
            "category": "weak-copyleft",
            "recommended_policy": "review_required",
            "description": "Weak copyleft, allows dynamic linking"
        },
        {
            "name": "AGPL-3.0",
            "category": "network-copyleft",
            "recommended_policy": "blocked",
            "description": "Network copyleft, requires source for SaaS"
        },
        {
            "name": "MPL-2.0",
            "category": "weak-copyleft",
            "recommended_policy": "allowed",
            "description": "File-level copyleft"
        },
        {
            "name": "ISC",
            "category": "permissive",
            "recommended_policy": "allowed",
            "description": "Similar to MIT and BSD"
        },
        {
            "name": "Unlicense",
            "category": "public-domain",
            "recommended_policy": "allowed",
            "description": "Public domain dedication"
        },
        {
            "name": "SSPL",
            "category": "proprietary",
            "recommended_policy": "blocked",
            "description": "Server Side Public License (controversial)"
        },
        {
            "name": "Commercial",
            "category": "proprietary",
            "recommended_policy": "review_required",
            "description": "Proprietary commercial license"
        },
        {
            "name": "UNKNOWN",
            "category": "unknown",
            "recommended_policy": "review_required",
            "description": "Unknown or undetected license"
        },
    ]

    return jsonify({"licenses": common_licenses}), 200
