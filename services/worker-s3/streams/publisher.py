"""Async result publisher module for Redis Streams."""

import json
import logging
from typing import Any, Dict, Optional

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class ResultPublisher:
    """Publisher for scan results to Redis Streams."""

    def __init__(self, redis_client: redis.Redis, prefix: str):
        """Initialize result publisher.

        Args:
            redis_client: Redis async client instance
            prefix: Stream key prefix
        """
        self.redis_client = redis_client
        self.prefix = prefix

    async def publish_result(self, result: Dict[str, Any]) -> str:
        """Publish scan result to Redis Stream.

        Args:
            result: Result dictionary containing:
                - job_id: Job identifier
                - object_key: S3 object key
                - status: Job status (completed, failed, etc.)
                - hashes: File hashes
                - threats: Detected threats
                - ti_enrichment: TI enrichment data (optional)
                - error: Error message (if failed)

        Returns:
            Message ID from Redis Stream
        """
        try:
            stream_name = f"{self.prefix}results"

            # Prepare message data
            message = self._prepare_message(result)

            # Publish to Redis Stream
            message_id = await self.redis_client.xadd(stream_name, message)

            logger.info(f"Published result {result.get('job_id')}: {message_id}")
            return message_id

        except Exception as e:
            logger.error(f"Error publishing result: {e}")
            raise

    async def publish_scan_started(self, job_id: str, object_key: str) -> str:
        """Publish scan start notification.

        Args:
            job_id: Job identifier
            object_key: S3 object key

        Returns:
            Message ID from Redis Stream
        """
        try:
            stream_name = f"{self.prefix}events"

            message = {
                "event_type": "scan_started",
                "job_id": job_id,
                "object_key": object_key,
            }

            message_id = await self.redis_client.xadd(stream_name, message)
            logger.info(f"Published scan started event: {message_id}")
            return message_id

        except Exception as e:
            logger.error(f"Error publishing scan started event: {e}")
            raise

    async def publish_threat_detected(
        self, job_id: str, object_key: str, threat_names: list
    ) -> str:
        """Publish threat detection notification.

        Args:
            job_id: Job identifier
            object_key: S3 object key
            threat_names: List of detected threat names

        Returns:
            Message ID from Redis Stream
        """
        try:
            stream_name = f"{self.prefix}events"

            message = {
                "event_type": "threat_detected",
                "job_id": job_id,
                "object_key": object_key,
                "threat_count": len(threat_names),
                "threats": ",".join(threat_names[:5]),  # Limit to 5 for message size
            }

            message_id = await self.redis_client.xadd(stream_name, message)
            logger.info(f"Published threat detected event: {message_id}")
            return message_id

        except Exception as e:
            logger.error(f"Error publishing threat detected event: {e}")
            raise

    @staticmethod
    def _prepare_message(result: Dict[str, Any]) -> Dict[str, str]:
        """Prepare result for Redis Stream storage.

        Args:
            result: Result dictionary

        Returns:
            Dictionary with string keys and values for Redis Stream
        """
        message = {}

        # Required fields
        if "job_id" in result:
            message["job_id"] = str(result["job_id"])

        if "object_key" in result:
            message["object_key"] = str(result["object_key"])

        if "status" in result:
            message["status"] = str(result["status"])

        # Hashes
        if "hashes" in result and isinstance(result["hashes"], dict):
            hashes = result["hashes"]
            if hashes.get("sha256"):
                message["sha256"] = hashes["sha256"]
            if hashes.get("md5"):
                message["md5"] = hashes["md5"]
            if hashes.get("sha1"):
                message["sha1"] = hashes["sha1"]

        # Threats
        if "threats" in result:
            threats = result["threats"]
            if isinstance(threats, list):
                message["threat_count"] = str(len(threats))
                message["threats"] = ",".join(threats[:10])  # Limit to 10
            else:
                message["threats"] = str(threats)

        # TI Enrichment
        if "ti_enrichment" in result:
            enrichment = result["ti_enrichment"]
            if isinstance(enrichment, dict):
                if enrichment.get("vt_score") is not None:
                    message["vt_score"] = str(enrichment["vt_score"])
                if enrichment.get("severity"):
                    message["severity"] = str(enrichment["severity"])
                if enrichment.get("threat_family"):
                    message["threat_family"] = str(enrichment["threat_family"])

        # Timing
        if "elapsed_time" in result:
            message["elapsed_time"] = str(result["elapsed_time"])

        # Error
        if "error" in result:
            message["error"] = str(result["error"])

        # Timestamp
        if "timestamp" in result:
            message["timestamp"] = str(result["timestamp"])

        return message
