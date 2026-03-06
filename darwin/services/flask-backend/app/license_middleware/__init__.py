"""License middleware module for Flask backend."""

import logging

logger = logging.getLogger(__name__)

# Attempt to import license middleware, provide no-ops if unavailable
try:
    from .license import (
        requires_feature,
        check_review_limits,
        get_license_client,
        FeatureNotAvailableError,
        ReviewLimitExceededError,
    )
except ImportError as e:
    logger.warning(f"License middleware not available: {e}. Using no-op implementations.")

    # No-op implementations when licensing module is not available
    def requires_feature(feature_name: str):
        """No-op decorator that allows all features in development mode."""
        def decorator(func):
            return func
        return decorator

    def check_review_limits(current_reviews: int, max_reviews=None) -> bool:
        """No-op implementation that always allows reviews."""
        return True

    def get_license_client():
        """No-op implementation that returns None."""
        return None

    class FeatureNotAvailableError(Exception):
        """No-op exception for missing features."""
        pass

    class ReviewLimitExceededError(Exception):
        """No-op exception for exceeded review limits."""
        pass

__all__ = [
    "requires_feature",
    "check_review_limits",
    "get_license_client",
    "FeatureNotAvailableError",
    "ReviewLimitExceededError",
]
