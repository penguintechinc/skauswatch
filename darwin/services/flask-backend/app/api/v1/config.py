"""Configuration Management API - GET/PUT configuration values stored in database.

All configuration is stored in the installation_config table and falls back to
environment variables on first run.
"""

import logging
from flask import Blueprint, jsonify, request

from app.middleware import auth_required, admin_required
from app.models import get_config_value, set_config_value, get_db
from app.config import Config

logger = logging.getLogger(__name__)

config_bp = Blueprint("config", __name__)


@config_bp.route("", methods=["GET"])
@auth_required
def get_config():
    """
    Get all configuration values from database with fallback to environment.

    Returns:
        200: Configuration object
        500: Database error
    """
    try:
        # AI Configuration
        ai_enabled = get_config_value("ai_enabled", default="true" if Config.AI_ENABLED else "false")
        default_ai_provider = get_config_value("default_ai_provider", default=Config.DEFAULT_AI_PROVIDER)

        # Ollama Configuration
        ollama_base_url = get_config_value("ollama_base_url", default=Config.OLLAMA_BASE_URL)
        ollama_security_llm = get_config_value("ollama_security_llm", default=Config.OLLAMA_SECURITY_LLM)
        ollama_best_practices_llm = get_config_value("ollama_best_practices_llm", default=Config.OLLAMA_BEST_PRACTICES_LLM)
        ollama_framework_llm = get_config_value("ollama_framework_llm", default=Config.OLLAMA_FRAMEWORK_LLM)
        ollama_iac_llm = get_config_value("ollama_iac_llm", default=Config.OLLAMA_IAC_LLM)
        ollama_fallback_llm = get_config_value("ollama_fallback_llm", default=Config.OLLAMA_FALLBACK_LLM)
        ollama_default_llm = get_config_value("ollama_default_llm", default=Config.OLLAMA_DEFAULT_LLM)

        # Review Category Configuration
        review_security_enabled = get_config_value("review_security_enabled", default="true" if Config.REVIEW_SECURITY_ENABLED else "false")
        review_best_practices_enabled = get_config_value("review_best_practices_enabled", default="true" if Config.REVIEW_BEST_PRACTICES_ENABLED else "false")
        review_framework_enabled = get_config_value("review_framework_enabled", default="true" if Config.REVIEW_FRAMEWORK_ENABLED else "false")
        review_iac_enabled = get_config_value("review_iac_enabled", default="true" if Config.REVIEW_IAC_ENABLED else "false")

        # Review Limits
        max_files_per_review = get_config_value("max_files_per_review", default=str(Config.MAX_FILES_PER_REVIEW))
        max_lines_per_file = get_config_value("max_lines_per_file", default=str(Config.MAX_LINES_PER_FILE))
        review_timeout_seconds = get_config_value("review_timeout_seconds", default=str(Config.REVIEW_TIMEOUT_SECONDS))

        # Elder Integration Configuration
        elder_enabled = get_config_value("elder_enabled", default="false")
        elder_url = get_config_value("elder_url", default="")
        elder_api_key = get_config_value("elder_api_key", default="")

        config_data = {
            "ai": {
                "enabled": ai_enabled.lower() == "true",
                "default_provider": default_ai_provider,
            },
            "providers": {
                "ollama": {
                    "base_url": ollama_base_url,
                    "models": {
                        "security": ollama_security_llm,
                        "best_practices": ollama_best_practices_llm,
                        "framework": ollama_framework_llm,
                        "iac": ollama_iac_llm,
                        "fallback": ollama_fallback_llm,
                        "default": ollama_default_llm,
                    }
                },
                # OpenAI and Anthropic API keys are intentionally not exposed
                # They should be set via environment variables only
            },
            "review_categories": {
                "security_enabled": review_security_enabled.lower() == "true",
                "best_practices_enabled": review_best_practices_enabled.lower() == "true",
                "framework_enabled": review_framework_enabled.lower() == "true",
                "iac_enabled": review_iac_enabled.lower() == "true",
            },
            "review_limits": {
                "max_files_per_review": int(max_files_per_review),
                "max_lines_per_file": int(max_lines_per_file),
                "review_timeout_seconds": int(review_timeout_seconds),
            },
            "integrations": {
                "elder": {
                    "enabled": elder_enabled.lower() == "true",
                    "url": elder_url,
                    # API key is intentionally not exposed in GET requests
                }
            }
        }

        return jsonify(config_data), 200

    except Exception as e:
        logger.error(f"Error getting configuration: {e}")
        return jsonify({"error": "Failed to retrieve configuration"}), 500


@config_bp.route("", methods=["PUT"])
@admin_required
def update_config():
    """
    Update configuration values in database (admin only).

    Request body:
        {
            "ai": {
                "enabled": true,
                "default_provider": "ollama"
            },
            "providers": {
                "ollama": {
                    "base_url": "http://ollama:11434",
                    "models": {
                        "security": "granite-code:34b",
                        "best_practices": "llama3.3:70b",
                        "framework": "codestral:22b",
                        "iac": "granite-code:20b",
                        "fallback": "starcoder2:15b",
                        "default": "granite-code:20b"
                    }
                }
            },
            "review_categories": {
                "security_enabled": true,
                "best_practices_enabled": true,
                "framework_enabled": true,
                "iac_enabled": true
            },
            "review_limits": {
                "max_files_per_review": 50,
                "max_lines_per_file": 1000,
                "review_timeout_seconds": 300
            },
            "integrations": {
                "elder": {
                    "enabled": true,
                    "url": "https://elder.penguintech.io",
                    "api_key": "secret-key"
                }
            }
        }

    Returns:
        200: Configuration updated successfully
        400: Invalid request data
        500: Database error
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No configuration data provided"}), 400

        # Update AI configuration
        if "ai" in data:
            if "enabled" in data["ai"]:
                set_config_value("ai_enabled", "true" if data["ai"]["enabled"] else "false")
            if "default_provider" in data["ai"]:
                set_config_value("default_ai_provider", data["ai"]["default_provider"])

        # Update provider configuration
        if "providers" in data:
            if "ollama" in data["providers"]:
                ollama_config = data["providers"]["ollama"]
                if "base_url" in ollama_config:
                    set_config_value("ollama_base_url", ollama_config["base_url"])
                if "models" in ollama_config:
                    models = ollama_config["models"]
                    if "security" in models:
                        set_config_value("ollama_security_llm", models["security"])
                    if "best_practices" in models:
                        set_config_value("ollama_best_practices_llm", models["best_practices"])
                    if "framework" in models:
                        set_config_value("ollama_framework_llm", models["framework"])
                    if "iac" in models:
                        set_config_value("ollama_iac_llm", models["iac"])
                    if "fallback" in models:
                        set_config_value("ollama_fallback_llm", models["fallback"])
                    if "default" in models:
                        set_config_value("ollama_default_llm", models["default"])

        # Update review category configuration
        if "review_categories" in data:
            categories = data["review_categories"]
            if "security_enabled" in categories:
                set_config_value("review_security_enabled", "true" if categories["security_enabled"] else "false")
            if "best_practices_enabled" in categories:
                set_config_value("review_best_practices_enabled", "true" if categories["best_practices_enabled"] else "false")
            if "framework_enabled" in categories:
                set_config_value("review_framework_enabled", "true" if categories["framework_enabled"] else "false")
            if "iac_enabled" in categories:
                set_config_value("review_iac_enabled", "true" if categories["iac_enabled"] else "false")

        # Update review limits
        if "review_limits" in data:
            limits = data["review_limits"]
            if "max_files_per_review" in limits:
                set_config_value("max_files_per_review", str(limits["max_files_per_review"]))
            if "max_lines_per_file" in limits:
                set_config_value("max_lines_per_file", str(limits["max_lines_per_file"]))
            if "review_timeout_seconds" in limits:
                set_config_value("review_timeout_seconds", str(limits["review_timeout_seconds"]))

        # Update Elder integration configuration
        if "integrations" in data:
            if "elder" in data["integrations"]:
                elder_config = data["integrations"]["elder"]
                if "enabled" in elder_config:
                    set_config_value("elder_enabled", "true" if elder_config["enabled"] else "false")
                if "url" in elder_config:
                    set_config_value("elder_url", elder_config["url"])
                if "api_key" in elder_config:
                    # Store API key securely (consider encryption in production)
                    set_config_value("elder_api_key", elder_config["api_key"])

        return jsonify({"message": "Configuration updated successfully"}), 200

    except Exception as e:
        logger.error(f"Error updating configuration: {e}")
        return jsonify({"error": "Failed to update configuration"}), 500


@config_bp.route("/ai", methods=["GET"])
@auth_required
def get_ai_config():
    """
    Get AI configuration (legacy endpoint for compatibility).

    Returns:
        200: AI configuration
        500: Database error
    """
    try:
        # Call main config endpoint and extract AI section
        response, status = get_config()
        if status == 200:
            full_config = response.get_json()
            return jsonify(full_config["ai"]), 200
        return response, status
    except Exception as e:
        logger.error(f"Error getting AI configuration: {e}")
        return jsonify({"error": "Failed to retrieve AI configuration"}), 500


@config_bp.route("/ai", methods=["PUT"])
@admin_required
def update_ai_config():
    """
    Update AI configuration (legacy endpoint for compatibility).

    Request body:
        {
            "enabled": true,
            "default_provider": "ollama"
        }

    Returns:
        200: Configuration updated successfully
        400: Invalid request data
        500: Database error
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "No AI configuration data provided"}), 400

        # Convert to full config format and call main update endpoint
        full_config = {"ai": data}
        request.json = full_config
        return update_config()

    except Exception as e:
        logger.error(f"Error updating AI configuration: {e}")
        return jsonify({"error": "Failed to update AI configuration"}), 500
