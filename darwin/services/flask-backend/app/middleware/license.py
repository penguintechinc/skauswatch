"""License integration middleware for feature gating and review limits.

This module provides decorators and utilities for integrating with the PenguinTech
License Server to gate features and enforce review limits.
"""

import logging
from functools import wraps
from typing import Callable, Optional, Any, Dict

from flask import current_app, g, jsonify

from penguin_licensing.python_client import (
    PenguinTechLicenseClient,
    FeatureNotAvailableError as LicenseFeatureError,
    LicenseValidationError,
)


logger = logging.getLogger(__name__)


# Feature constants
FEATURE_WHOLE_REVIEW = "WHOLE_REVIEW"
FEATURE_GITLAB = "GITLAB"
FEATURE_IAC_REVIEW = "IAC_REVIEW"
FEATURE_OLLAMA = "OLLAMA"
FEATURE_CUSTOM_RULES = "CUSTOM_RULES"
FEATURE_UNLIMITED_REVIEWS = "UNLIMITED_REVIEWS"
FEATURE_UNLIMITED_REPOS = "UNLIMITED_REPOS"
FEATURE_ISSUE_AUTOPILOT = "ISSUE_AUTOPILOT"

# Feature flag for development mode (all features available when disabled)
RELEASE_MODE = False

# Global license client
_license_client: Optional[PenguinTechLicenseClient] = None


class FeatureNotAvailableError(Exception):
    """Raised when a required feature is not available in the current license."""

    def __init__(self, feature: str, message: Optional[str] = None):
        """
        Initialize the exception.

        Args:
            feature: The feature name that is not available
            message: Optional custom error message
        """
        self.feature = feature
        default_msg = f"Feature '{feature}' requires license upgrade"
        super().__init__(message or default_msg)


class ReviewLimitExceededError(Exception):
    """Raised when review limits have been exceeded."""

    def __init__(self, limit: int, current: int, feature: str = "UNLIMITED_REVIEWS"):
        """
        Initialize the exception.

        Args:
            limit: The maximum review limit
            current: The current review count
            feature: The feature that provides unlimited reviews
        """
        self.limit = limit
        self.current = current
        self.feature = feature
        super().__init__(
            f"Review limit exceeded: {current}/{limit}. "
            f"Upgrade to '{feature}' for unlimited reviews"
        )


def get_license_client() -> Optional[PenguinTechLicenseClient]:
    """
    Get the global license client instance.

    The client is lazily initialized from Flask configuration on first access.

    Returns:
        PenguinTechLicenseClient instance or None if not configured
    """
    global _license_client

    if _license_client is not None:
        return _license_client

    # Initialize from Flask config
    try:
        license_key = current_app.config.get("LICENSE_KEY", "")
        product_name = current_app.config.get("PRODUCT_NAME", "ai-pr-reviewer")
        server_url = current_app.config.get(
            "LICENSE_SERVER_URL",
            "https://license.penguintech.io"
        )

        if not license_key:
            logger.warning("LICENSE_KEY not configured in Flask app")
            return None

        _license_client = PenguinTechLicenseClient(
            license_key=license_key,
            product=product_name,
            base_url=server_url,
            timeout=30
        )

        # Validate the license on initialization
        try:
            _license_client.validate()
            logger.info(f"License initialized for product: {product_name}")
        except LicenseValidationError as e:
            logger.error(f"License validation failed: {e}")
            if current_app.config.get("RELEASE_MODE", False):
                raise

        return _license_client

    except Exception as e:
        logger.error(f"Failed to initialize license client: {e}")
        if current_app.config.get("RELEASE_MODE", False):
            raise
        return None


def check_feature_available(feature: str) -> bool:
    """
    Check if a specific feature is available.

    In development mode (RELEASE_MODE=false), all features are available.
    In production mode (RELEASE_MODE=true), license validation is enforced.

    Args:
        feature: The feature name to check

    Returns:
        True if feature is available, False otherwise
    """
    # In development mode, all features are available
    if not current_app.config.get("RELEASE_MODE", False):
        return True

    # In production mode, check with license server
    client = get_license_client()
    if not client:
        logger.warning(f"License client unavailable, feature {feature} denied")
        return False

    return client.check_feature(feature)


def get_review_limit() -> Optional[int]:
    """
    Get the maximum number of reviews allowed.

    If UNLIMITED_REVIEWS feature is available, returns None (unlimited).
    Otherwise, returns the configured limit from app config.

    Returns:
        Maximum review limit or None for unlimited
    """
    if check_feature_available(FEATURE_UNLIMITED_REVIEWS):
        return None

    return current_app.config.get("MAX_REVIEWS_PER_DAY", 10)


def requires_feature(feature_name: str) -> Callable:
    """
    Decorator to gate functionality behind license features.

    Usage:
        @app.route("/api/v1/reviews/gitlab", methods=["POST"])
        @requires_feature(FEATURE_GITLAB)
        def create_gitlab_review():
            # This endpoint is only available with GITLAB feature
            pass

    Args:
        feature_name: Name of the required feature

    Returns:
        Decorator function

    Raises:
        FeatureNotAvailableError: If the feature is not available
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not check_feature_available(feature_name):
                error = FeatureNotAvailableError(feature_name)
                logger.warning(f"Feature {feature_name} not available for endpoint {func.__name__}")

                # Return JSON error response for API endpoints
                return (
                    jsonify({
                        "error": "Feature not available",
                        "feature": feature_name,
                        "message": str(error),
                    }),
                    403
                )

            return func(*args, **kwargs)

        return wrapper

    return decorator


def check_review_limits(
    current_reviews: int,
    max_reviews: Optional[int] = None
) -> bool:
    """
    Check if the review count is within limits.

    If UNLIMITED_REVIEWS feature is available, always returns True.
    Otherwise, compares current_reviews against the configured limit.

    Args:
        current_reviews: The current number of reviews
        max_reviews: Optional override for max review limit

    Returns:
        True if within limits, False otherwise

    Raises:
        ReviewLimitExceededError: If review limit is exceeded
    """
    # Check for unlimited reviews feature
    if check_feature_available(FEATURE_UNLIMITED_REVIEWS):
        return True

    # Get review limit (use provided or configured)
    limit = max_reviews or get_review_limit()
    if limit is None:
        return True

    # Check if exceeding limit
    if current_reviews >= limit:
        raise ReviewLimitExceededError(
            limit=limit,
            current=current_reviews,
            feature=FEATURE_UNLIMITED_REVIEWS
        )

    return True


def check_review_limits_middleware(
    max_reviews: Optional[int] = None
) -> Callable:
    """
    Decorator for checking review limits on endpoints.

    Usage:
        @app.route("/api/v1/reviews", methods=["POST"])
        @auth_required
        @check_review_limits_middleware(max_reviews=50)
        def create_review():
            # Check must happen in the endpoint body
            user_reviews = db.query(Review).filter_by(user_id=user.id).count()
            try:
                check_review_limits(user_reviews)
            except ReviewLimitExceededError as e:
                return jsonify({"error": str(e)}), 429

    Args:
        max_reviews: Optional override for max review limit

    Returns:
        Decorator function
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Store limit in request context for use in endpoint
            g.review_limit = max_reviews or get_review_limit()
            return func(*args, **kwargs)

        return wrapper

    return decorator


def initialize_licensing() -> bool:
    """
    Initialize the licensing system.

    This should be called once during application startup.
    It validates the license and logs available features.

    Returns:
        True if licensing is initialized successfully
    """
    try:
        client = get_license_client()
        if not client:
            logger.warning("License client not available (development mode)")
            return True

        # Get all available features
        all_features = client.get_all_features()
        logger.info(f"License initialized with {len(all_features)} features")

        # Log enabled features
        for feature, enabled in all_features.items():
            if enabled:
                logger.info(f"Feature enabled: {feature}")

        return True

    except Exception as e:
        logger.error(f"License initialization failed: {e}")
        if current_app.config.get("RELEASE_MODE", False):
            return False
        return True


def reset_license_client() -> None:
    """Reset the global license client instance.

    Useful for testing or reconfiguration.
    """
    global _license_client
    _license_client = None


# Feature flag helpers
def is_whole_review_available() -> bool:
    """Check if WHOLE_REVIEW feature is available."""
    return check_feature_available(FEATURE_WHOLE_REVIEW)


def is_gitlab_available() -> bool:
    """Check if GITLAB feature is available."""
    return check_feature_available(FEATURE_GITLAB)


def is_iac_review_available() -> bool:
    """Check if IAC_REVIEW feature is available."""
    return check_feature_available(FEATURE_IAC_REVIEW)


def is_ollama_available() -> bool:
    """Check if OLLAMA feature is available."""
    return check_feature_available(FEATURE_OLLAMA)


def is_custom_rules_available() -> bool:
    """Check if CUSTOM_RULES feature is available."""
    return check_feature_available(FEATURE_CUSTOM_RULES)


def is_unlimited_reviews_available() -> bool:
    """Check if UNLIMITED_REVIEWS feature is available."""
    return check_feature_available(FEATURE_UNLIMITED_REVIEWS)


def is_unlimited_repos_available() -> bool:
    """Check if UNLIMITED_REPOS feature is available."""
    return check_feature_available(FEATURE_UNLIMITED_REPOS)


def is_issue_autopilot_available() -> bool:
    """Check if ISSUE_AUTOPILOT feature is available."""
    return check_feature_available(FEATURE_ISSUE_AUTOPILOT)


def get_repo_limit() -> Optional[int]:
    """
    Get the maximum number of repos allowed.

    If UNLIMITED_REPOS feature is available, returns None (unlimited).
    Otherwise, returns the configured free tier limit from app config.

    Returns:
        Maximum repo limit or None for unlimited
    """
    if check_feature_available(FEATURE_UNLIMITED_REPOS):
        return None

    return current_app.config.get("MAX_REPOS_FREE", 3)


def check_repo_limits(current_repos: int) -> bool:
    """
    Check if the repo count is within limits.

    If UNLIMITED_REPOS feature is available, always returns True.
    Otherwise, compares current_repos against the configured limit.

    Args:
        current_repos: The current number of configured repositories

    Returns:
        True if within limits

    Raises:
        FeatureNotAvailableError: If repo limit is exceeded
    """
    # Check for unlimited repos feature
    if check_feature_available(FEATURE_UNLIMITED_REPOS):
        return True

    # Get repo limit
    limit = get_repo_limit()
    if limit is None:
        return True

    # Check if exceeding limit
    if current_repos >= limit:
        raise FeatureNotAvailableError(
            feature=FEATURE_UNLIMITED_REPOS,
            message=(
                f"Repository limit exceeded: {current_repos}/{limit}. "
                f"Free tier allows maximum {limit} repositories. "
                f"Please upgrade to Professional license for unlimited repositories."
            )
        )

    return True


def requires_repo_limit_check(func: Callable) -> Callable:
    """
    Decorator to check repo limit before adding new repository.

    Usage:
        @app.route("/api/v1/configs", methods=["POST"])
        @auth_required
        @requires_repo_limit_check
        def create_repo_config():
            # This will fail if repo limit is exceeded
            pass

    Args:
        func: The endpoint function to wrap

    Returns:
        Decorated function
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        # Import here to avoid circular dependency
        from ..models import get_repo_count

        current_repos = get_repo_count()

        try:
            check_repo_limits(current_repos)
        except FeatureNotAvailableError as e:
            logger.warning(f"Repo limit check failed: {e}")
            return (
                jsonify({
                    "error": "Repository limit exceeded",
                    "feature": e.feature,
                    "message": str(e),
                    "current_repos": current_repos,
                    "max_repos": get_repo_limit(),
                    "upgrade_url": current_app.config.get(
                        "LICENSE_SERVER_URL",
                        "https://license.penguintech.io"
                    ) + "/pricing",
                }),
                403
            )

        return func(*args, **kwargs)

    return wrapper
