"""Anomaly detection engine for SkausWatch AAA Monitor service."""

from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    import redis.asyncio as redis

    from .config import AnomalyDetectionConfig

logger = structlog.get_logger(__name__)


class AnomalyDetector:
    """Detects anomalies in security events."""

    def __init__(self, config: "AnomalyDetectionConfig", redis_client: "redis.Redis"):
        """Initialize anomaly detector.

        Args:
            config: Anomaly detection configuration
            redis_client: Redis async client instance
        """
        self.config = config
        self.redis_client = redis_client
        logger.info(
            "anomaly_detector_initialized",
            algorithm=config.algorithm,
            contamination=config.contamination,
        )
