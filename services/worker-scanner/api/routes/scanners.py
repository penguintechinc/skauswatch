"""Flask blueprint for scanner status and health information endpoints.

This module provides REST API endpoints for checking the health and availability
of all configured security scanners (Nuclei, ZAP, OpenVAS). All endpoints require
JWT authentication.

Endpoints:
    GET /scanners - Check status of all enabled scanners
    GET /healthz - Simple health check endpoint
"""

import logging
from typing import Any, Dict, List, Tuple

from api.middleware.auth import jwt_required
from config.settings import settings
from flask import Blueprint, jsonify
from scanners.nuclei import NucleiScanner
from scanners.openvas import OpenvasScanner
from scanners.zap import ZapScanner
from utils.logger import get_logger

scanners_bp = Blueprint("scanners", __name__)

# Get logger for this module
logger = get_logger(__name__)


def _scanner_status_to_dict(status: Any) -> Dict[str, Any]:
    """Convert ScannerStatus dataclass to JSON-serializable dictionary.

    Handles conversion of ScannerStatus dataclass fields including datetime
    objects to ISO format strings for proper JSON serialization.

    Args:
        status: ScannerStatus dataclass instance from scanner.get_status()

    Returns:
        Dictionary with all fields properly serialized for JSON response

    Example:
        >>> from scanners.base import ScannerStatus
        >>> status = ScannerStatus(name="Nuclei", available=True, version="3.0.0")
        >>> result = _scanner_status_to_dict(status)
        >>> print(result)
        {'name': 'Nuclei', 'available': True, 'version': '3.0.0', ...}
    """
    result = {
        "name": status.name,
        "available": status.available,
        "version": status.version,
        "message": status.message,
    }

    # Convert last_checked datetime to ISO format if present
    if status.last_checked:
        result["last_checked"] = status.last_checked.isoformat()
    else:
        result["last_checked"] = None

    return result


def _check_scanner_status(
    scanner_class: type,
    scanner_name: str,
    config: Dict[str, Any],
    is_enabled: bool,
) -> Dict[str, Any]:
    """Check the status of a single scanner instance.

    Instantiates a scanner class, calls get_status(), and returns the status
    information. If the scanner is disabled, returns a disabled status response.
    Catches all exceptions to prevent one failing scanner from breaking the endpoint.

    Args:
        scanner_class: Scanner class to instantiate (e.g., NucleiScanner)
        scanner_name: Human-readable name of the scanner (e.g., "nuclei")
        config: Configuration dictionary for the scanner
        is_enabled: Whether the scanner is enabled via settings

    Returns:
        Dictionary with scanner status information including name, enabled flag,
        available status, version, and status message. Returns disabled status if
        is_enabled is False.

    Example:
        >>> config = {"binary_path": "/usr/local/bin/nuclei"}
        >>> status = _check_scanner_status(NucleiScanner, "nuclei", config, True)
        >>> print(status["available"])
        True
    """
    # If scanner is disabled via settings, return disabled status
    if not is_enabled:
        logger.debug(f"Scanner {scanner_name} is disabled")
        return {
            "name": scanner_name,
            "enabled": False,
            "available": False,
            "version": "",
            "status": "disabled",
            "message": f"{scanner_name} scanner is disabled in configuration",
        }

    # Try to get scanner status
    try:
        logger.debug(f"Checking status for scanner: {scanner_name}")
        scanner = scanner_class(config)
        scanner_status = scanner.get_status()

        # Convert status to dictionary
        status_dict = _scanner_status_to_dict(scanner_status)

        # Add enabled flag and status label
        status_dict["enabled"] = True
        status_dict["status"] = "online" if scanner_status.available else "offline"

        logger.info(
            f"Scanner {scanner_name} status: "
            f"available={scanner_status.available}, version={scanner_status.version}"
        )

        return status_dict

    except Exception as e:
        # Catch any exception and report scanner as unavailable
        error_message = f"Failed to check {scanner_name} status: {str(e)}"
        logger.error(error_message, exc_info=True)

        return {
            "name": scanner_name,
            "enabled": True,
            "available": False,
            "version": "",
            "status": "error",
            "message": error_message,
        }


@scanners_bp.route("/scanners", methods=["GET"])
@jwt_required
def get_scanners_status() -> Tuple[Dict[str, Any], int]:
    """Get status and health information for all configured scanners.

    Checks the availability and version of each scanner (Nuclei, ZAP, OpenVAS)
    by instantiating the scanner class and calling get_status(). Scanners that
    are disabled via settings are reported as disabled. Any exceptions during
    status checking are caught and reported as unavailable.

    Returns:
        JSON response with list of scanner status objects:
        {
            "scanners": [
                {
                    "name": "nuclei",
                    "enabled": true,
                    "available": true,
                    "version": "3.0.0",
                    "status": "online",
                    "message": "Nuclei scanner is operational"
                },
                ...
            ]
        }

        HTTP 200 is always returned even if some scanners are unavailable,
        to allow clients to see the status of all scanners.

    Example:
        GET /api/v1/scanner/scanners
        Authorization: Bearer <jwt_token>

        Response:
        {
            "scanners": [
                {
                    "name": "Nuclei",
                    "enabled": true,
                    "available": true,
                    "version": "3.0.0",
                    "status": "online",
                    "message": "Nuclei scanner is operational"
                },
                {
                    "name": "OWASP ZAP",
                    "enabled": true,
                    "available": true,
                    "version": "2.14.0",
                    "status": "online",
                    "message": "ZAP is available and responding"
                },
                {
                    "name": "OpenVAS",
                    "enabled": false,
                    "available": false,
                    "version": "",
                    "status": "disabled",
                    "message": "OpenVAS scanner is disabled in configuration"
                }
            ]
        }
    """
    logger.info("Received request to check scanner status")

    scanners_list: List[Dict[str, Any]] = []

    # Build Nuclei scanner config from settings
    nuclei_config = {
        "binary_path": settings.nuclei.binary_path,
        "templates_path": settings.nuclei.templates_path,
        "rate_limit": settings.nuclei.rate_limit,
        "concurrency": settings.nuclei.concurrency,
    }

    # Check Nuclei scanner status
    nuclei_status = _check_scanner_status(
        NucleiScanner,
        "nuclei",
        nuclei_config,
        settings.scanner_toggles.nuclei_enabled,
    )
    scanners_list.append(nuclei_status)

    # Build ZAP scanner config from settings
    zap_config = {
        "base_url": settings.scanner.zap_url,
        "api_key": settings.scanner.zap_api_key,
    }

    # Check ZAP scanner status
    zap_status = _check_scanner_status(
        ZapScanner,
        "zap",
        zap_config,
        settings.scanner_toggles.zap_enabled,
    )
    scanners_list.append(zap_status)

    # Build OpenVAS scanner config from settings
    openvas_config = {
        "host": settings.scanner.openvas_host,
        "port": settings.scanner.openvas_port,
        "username": settings.scanner.openvas_user,
        "password": settings.scanner.openvas_password,
    }

    # Check OpenVAS scanner status
    openvas_status = _check_scanner_status(
        OpenvasScanner,
        "openvas",
        openvas_config,
        settings.scanner_toggles.openvas_enabled,
    )
    scanners_list.append(openvas_status)

    logger.info(
        f"Scanner status check completed: {len(scanners_list)} scanners checked"
    )

    return jsonify({"scanners": scanners_list}), 200


# NOTE: The /healthz endpoint is registered directly in app.py (not via blueprint)
# to ensure it is unauthenticated for Docker healthchecks and load balancers.
