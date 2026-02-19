"""Input validation helper functions for worker-scanner service."""

import re
from ipaddress import AddressValueError, IPv4Address, IPv6Address, ip_network
from urllib.parse import urlparse

from croniter import croniter


def validate_target_value(target_type: str, value: str) -> tuple[bool, str]:
    """
    Validate target values based on type.

    Supports domain, ip, url, and cidr target types with appropriate validation rules.

    Args:
        target_type: Type of target ("domain", "ip", "url", "cidr")
        value: Target value to validate

    Returns:
        Tuple of (is_valid, error_message). Returns (True, "") if valid,
        (False, "error message") if invalid.
    """
    target_type = target_type.lower().strip()

    if not value or not isinstance(value, str):
        return False, "Target value must be a non-empty string"

    value = value.strip()

    if target_type == "domain":
        # Domain validation: RFC 1123 compliant domain names
        # Must not contain protocol prefix
        if "://" in value:
            return (
                False,
                "Domain should not include protocol prefix (http://, https://)",
            )

        domain_pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
        if not re.match(domain_pattern, value):
            return False, "Invalid domain format"

        if len(value) > 255:
            return False, "Domain name exceeds maximum length of 255 characters"

        return True, ""

    elif target_type == "ip":
        # IPv4 or IPv6 validation
        try:
            # Try IPv4 first
            IPv4Address(value)
            return True, ""
        except AddressValueError:
            pass

        try:
            # Try IPv6
            IPv6Address(value)
            return True, ""
        except AddressValueError:
            return False, "Invalid IPv4 or IPv6 address format"

    elif target_type == "url":
        # URL validation with http/https scheme requirement
        try:
            parsed = urlparse(value)

            if not parsed.scheme:
                return False, "URL must include a scheme (http:// or https://)"

            if parsed.scheme.lower() not in ("http", "https"):
                return False, "URL scheme must be http or https"

            if not parsed.netloc:
                return False, "URL must include a network location (domain or IP)"

            return True, ""
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}"

    elif target_type == "cidr":
        # CIDR notation validation
        try:
            ip_network(value, strict=False)
            return True, ""
        except AddressValueError as e:
            return False, f"Invalid CIDR notation: {str(e)}"

    else:
        return False, f"Unknown target type: {target_type}"


def validate_severity(severity: str) -> bool:
    """
    Validate severity level.

    Valid severity levels: critical, high, medium, low, info.

    Args:
        severity: Severity level to validate

    Returns:
        True if severity is valid, False otherwise.
    """
    valid_severities = {"critical", "high", "medium", "low", "info"}
    return severity.lower().strip() in valid_severities


def validate_scanner_type(scanner_type: str) -> bool:
    """
    Validate scanner type.

    Valid scanner types: nuclei, zap, openvas.

    Args:
        scanner_type: Scanner type to validate

    Returns:
        True if scanner type is valid, False otherwise.
    """
    valid_types = {"nuclei", "zap", "openvas"}
    return scanner_type.lower().strip() in valid_types


def validate_scan_type(scan_type: str) -> bool:
    """
    Validate scan type.

    Valid scan types: baseline, full, api, custom, discovery, full_and_fast, full_and_deep.

    Args:
        scan_type: Scan type to validate

    Returns:
        True if scan type is valid, False otherwise.
    """
    valid_types = {
        "baseline",
        "full",
        "api",
        "custom",
        "discovery",
        "full_and_fast",
        "full_and_deep",
    }
    return scan_type.lower().strip() in valid_types


def validate_finding_status(status: str) -> bool:
    """
    Validate finding status.

    Valid finding statuses: open, acknowledged, false_positive, fixed.

    Args:
        status: Finding status to validate

    Returns:
        True if status is valid, False otherwise.
    """
    valid_statuses = {"open", "acknowledged", "false_positive", "fixed"}
    return status.lower().strip() in valid_statuses


def validate_cron_expression(expression: str) -> tuple[bool, str]:
    """
    Validate cron expression format.

    Uses croniter to validate cron expressions. Supports standard 5-field
    and extended 6-field cron formats.

    Args:
        expression: Cron expression to validate

    Returns:
        Tuple of (is_valid, error_message). Returns (True, "") if valid,
        (False, "error message") if invalid.
    """
    if not expression or not isinstance(expression, str):
        return False, "Cron expression must be a non-empty string"

    expression = expression.strip()

    try:
        croniter(expression)
        return True, ""
    except (ValueError, KeyError) as e:
        return False, f"Invalid cron expression: {str(e)}"


def validate_job_status(status: str) -> bool:
    """
    Validate job status.

    Valid job statuses: pending, running, completed, failed, cancelled.

    Args:
        status: Job status to validate

    Returns:
        True if status is valid, False otherwise.
    """
    valid_statuses = {"pending", "running", "completed", "failed", "cancelled"}
    return status.lower().strip() in valid_statuses


def validate_priority(priority: int) -> bool:
    """
    Validate priority level.

    Valid priority range: 1-10 (1=highest, 10=lowest).

    Args:
        priority: Priority level to validate

    Returns:
        True if priority is valid (between 1 and 10), False otherwise.
    """
    if not isinstance(priority, int):
        return False

    return 1 <= priority <= 10


def sanitize_string(value: str, max_length: int = 255) -> str:
    """
    Sanitize string input.

    Strips whitespace, truncates to max_length, and removes null bytes
    and control characters.

    Args:
        value: String to sanitize
        max_length: Maximum allowed length (default 255)

    Returns:
        Sanitized string.
    """
    if not isinstance(value, str):
        return ""

    # Strip leading and trailing whitespace
    sanitized = value.strip()

    # Remove null bytes and control characters (0x00-0x1F, 0x7F-0x9F)
    sanitized = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", sanitized)

    # Truncate to max_length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]

    return sanitized


def validate_pagination(page: int, per_page: int) -> tuple[int, int]:
    """
    Validate and sanitize pagination parameters.

    Page must be >= 1 (default 1). Per_page must be 1-100 (default 20).

    Args:
        page: Page number to validate
        per_page: Items per page to validate

    Returns:
        Tuple of sanitized (page, per_page) values.
    """
    # Validate and set default for page
    if not isinstance(page, int) or page < 1:
        page = 1

    # Validate and set default for per_page
    if not isinstance(per_page, int) or per_page < 1 or per_page > 100:
        per_page = 20

    return page, per_page
