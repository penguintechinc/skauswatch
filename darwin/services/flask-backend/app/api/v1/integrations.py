"""Integration APIs for external systems (Elder, SIEM, etc.)."""

import logging
import requests
from flask import Blueprint, jsonify, request
from datetime import datetime

from app.middleware import auth_required, admin_required
from app.models import get_db, get_config_value

logger = logging.getLogger(__name__)

integrations_bp = Blueprint("integrations", __name__)


@integrations_bp.route("/elder", methods=["POST"])
@auth_required
def push_to_elder():
    """
    Push security findings to Elder SIEM/Security platform.

    Request body:
        {
            "findings": [
                {
                    "id": 123,
                    "repository": "owner/repo",
                    "platform": "github",
                    "file_path": "src/auth.py",
                    "line_start": 42,
                    "line_end": 45,
                    "severity": "critical",
                    "category": "security",
                    "title": "SQL Injection Vulnerability",
                    "body": "Direct SQL query construction without parameterization",
                    "suggestion": "Use parameterized queries",
                    "created_at": "2026-01-14T12:00:00Z"
                }
            ],
            "repository_filter": "owner/repo",  # Optional: filter to specific repository
            "severity_filter": "critical",      # Optional: filter to specific severity
            "category_filter": "security"       # Optional: filter to specific category
        }

    Returns:
        200: Findings pushed successfully
        400: Invalid request or Elder not configured
        500: Elder API error
    """
    try:
        # Check if Elder integration is enabled
        elder_enabled = get_config_value("elder_enabled", default="false")
        if elder_enabled.lower() != "true":
            return jsonify({"error": "Elder integration is not enabled"}), 400

        # Get Elder configuration
        elder_url = get_config_value("elder_url", default="")
        elder_api_key = get_config_value("elder_api_key", default="")

        if not elder_url:
            return jsonify({"error": "Elder URL not configured"}), 400

        if not elder_api_key:
            return jsonify({"error": "Elder API key not configured"}), 400

        # Get request data
        data = request.get_json()

        if not data:
            return jsonify({"error": "No data provided"}), 400

        # Extract findings from request or fetch from database
        findings = data.get("findings", [])

        if not findings:
            # No findings provided, fetch from database based on filters
            db = get_db()

            # Build query with optional filters
            query = db.review_comments

            if data.get("repository_filter"):
                # Join with reviews table to filter by repository
                query = query & (db.reviews.repository == data["repository_filter"])

            if data.get("severity_filter"):
                query = query & (db.review_comments.severity == data["severity_filter"])

            if data.get("category_filter"):
                query = query & (db.review_comments.category == data["category_filter"])

            # Fetch findings
            findings_rows = db(query).select(
                db.review_comments.ALL,
                db.reviews.repository,
                db.reviews.platform,
                left=db.reviews.on(db.review_comments.review_id == db.reviews.id),
                orderby=~db.review_comments.created_at,
                limitby=(0, 1000)  # Limit to 1000 findings
            )

            # Convert to list of dicts
            findings = []
            for row in findings_rows:
                findings.append({
                    "id": row.review_comments.id,
                    "repository": row.reviews.repository,
                    "platform": row.reviews.platform,
                    "file_path": row.review_comments.file_path,
                    "line_start": row.review_comments.line_start,
                    "line_end": row.review_comments.line_end,
                    "severity": row.review_comments.severity,
                    "category": row.review_comments.category,
                    "title": row.review_comments.title,
                    "body": row.review_comments.body,
                    "suggestion": row.review_comments.suggestion,
                    "created_at": row.review_comments.created_at.isoformat() if row.review_comments.created_at else None,
                })

        if not findings:
            return jsonify({"message": "No findings to push"}), 200

        # Prepare Elder API payload
        elder_payload = {
            "source": "darwin-pr-reviewer",
            "timestamp": datetime.utcnow().isoformat(),
            "findings": findings,
            "metadata": {
                "total_findings": len(findings),
                "severities": {
                    "critical": sum(1 for f in findings if f.get("severity") == "critical"),
                    "major": sum(1 for f in findings if f.get("severity") == "major"),
                    "minor": sum(1 for f in findings if f.get("severity") == "minor"),
                    "suggestion": sum(1 for f in findings if f.get("severity") == "suggestion"),
                }
            }
        }

        # Send to Elder API
        # Elder endpoint: POST /api/v1/services/darwin/findings
        elder_endpoint = f"{elder_url.rstrip('/')}/api/v1/services/darwin/findings"

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {elder_api_key}",
            "User-Agent": "Darwin-PR-Reviewer/1.0",
        }

        logger.info(f"Pushing {len(findings)} findings to Elder at {elder_endpoint}")

        response = requests.post(
            elder_endpoint,
            json=elder_payload,
            headers=headers,
            timeout=30
        )

        response.raise_for_status()

        elder_response = response.json()

        return jsonify({
            "message": f"Successfully pushed {len(findings)} findings to Elder",
            "findings_pushed": len(findings),
            "elder_response": elder_response,
        }), 200

    except requests.exceptions.RequestException as e:
        logger.error(f"Error pushing to Elder: {e}")
        return jsonify({"error": f"Failed to push to Elder: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Error pushing to Elder: {e}")
        return jsonify({"error": "Failed to push findings to Elder"}), 500


@integrations_bp.route("/elder/test", methods=["POST"])
@admin_required
def test_elder_connection():
    """
    Test Elder integration configuration.

    Returns:
        200: Elder connection successful
        400: Elder not configured
        500: Elder connection failed
    """
    try:
        # Check if Elder integration is enabled
        elder_enabled = get_config_value("elder_enabled", default="false")
        if elder_enabled.lower() != "true":
            return jsonify({"error": "Elder integration is not enabled"}), 400

        # Get Elder configuration
        elder_url = get_config_value("elder_url", default="")
        elder_api_key = get_config_value("elder_api_key", default="")

        if not elder_url:
            return jsonify({"error": "Elder URL not configured"}), 400

        if not elder_api_key:
            return jsonify({"error": "Elder API key not configured"}), 400

        # Test Elder connection via health check
        elder_health_endpoint = f"{elder_url.rstrip('/')}/api/v1/healthz"

        headers = {
            "Authorization": f"Bearer {elder_api_key}",
            "User-Agent": "Darwin-PR-Reviewer/1.0",
        }

        logger.info(f"Testing Elder connection at {elder_health_endpoint}")

        response = requests.get(
            elder_health_endpoint,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()

        return jsonify({
            "message": "Elder connection successful",
            "elder_url": elder_url,
            "status": response.status_code,
        }), 200

    except requests.exceptions.RequestException as e:
        logger.error(f"Elder connection test failed: {e}")
        return jsonify({"error": f"Elder connection failed: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Elder connection test failed: {e}")
        return jsonify({"error": "Failed to test Elder connection"}), 500


@integrations_bp.route("/elder/stats", methods=["GET"])
@admin_required
def get_elder_push_stats():
    """
    Get statistics about Elder push history.

    Returns:
        200: Elder push statistics
        500: Database error
    """
    try:
        # TODO: Implement push history tracking in database
        # For now, return current findings count

        db = get_db()

        total_findings = db(db.review_comments).count()

        critical = db(db.review_comments.severity == "critical").count()
        major = db(db.review_comments.severity == "major").count()
        minor = db(db.review_comments.severity == "minor").count()
        suggestion = db(db.review_comments.severity == "suggestion").count()

        security = db(db.review_comments.category == "security").count()
        best_practices = db(db.review_comments.category == "best_practices").count()
        framework = db(db.review_comments.category == "framework").count()
        iac = db(db.review_comments.category == "iac").count()

        return jsonify({
            "total_findings": total_findings,
            "by_severity": {
                "critical": critical,
                "major": major,
                "minor": minor,
                "suggestion": suggestion,
            },
            "by_category": {
                "security": security,
                "best_practices": best_practices,
                "framework": framework,
                "iac": iac,
            }
        }), 200

    except Exception as e:
        logger.error(f"Error getting Elder push stats: {e}")
        return jsonify({"error": "Failed to get Elder push statistics"}), 500
