"""Pattern detection engine for SkausWatch AAA Monitor service."""

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from .config import PatternDetectionConfig

logger = structlog.get_logger(__name__)


class PatternDetector:
    """Detects patterns in security events."""

    def __init__(self, config: "PatternDetectionConfig"):
        """Initialize pattern detector.

        Args:
            config: Pattern detection configuration
        """
        self.config = config
        logger.info(
            "pattern_detector_initialized",
            time_window=config.time_window,
            min_events=config.min_events,
            confidence_threshold=config.confidence_threshold,
        )
