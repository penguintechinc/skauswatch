"""Indicator creation request publisher module."""

import json
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class IndicatorPublisher:
    """Publisher for threat indicator creation requests."""

    def __init__(self):
        """Initialize indicator publisher."""
        pass

    async def create_indicator_request(
        self, hashes: Dict, threat_names: List[str], job_id: str, object_key: str
    ) -> Dict:
        """Create indicator request for publishing.

        Args:
            hashes: Dictionary with hash types: {sha256, md5, sha1}
            threat_names: List of threat names from YARA rules
            job_id: Job ID for tracking
            object_key: S3 object key of the file

        Returns:
            Dictionary representing indicator creation request:
                - request_id: Unique request identifier
                - hashes: File hashes
                - threat_names: Associated threat names
                - severity: Calculated severity level
                - source: Source identification (worker-s3)
                - job_id: Related job ID
                - object_key: S3 object key reference
                - timestamp: Request creation timestamp
        """
        try:
            from datetime import datetime, timezone

            request = {
                "request_id": f"ind_{job_id}_{hashes.get('sha256', 'unknown')[:8]}",
                "hashes": {
                    "sha256": hashes.get("sha256"),
                    "md5": hashes.get("md5"),
                    "sha1": hashes.get("sha1"),
                },
                "threat_names": threat_names,
                "severity": self._calculate_severity_from_names(threat_names),
                "source": "worker-s3",
                "job_id": job_id,
                "object_key": object_key,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            logger.info(f"Created indicator request: {request['request_id']}")
            return request

        except Exception as e:
            logger.error(f"Error creating indicator request: {e}")
            raise

    @staticmethod
    def _calculate_severity_from_names(threat_names: List[str]) -> str:
        """Calculate severity from threat names.

        Args:
            threat_names: List of threat names

        Returns:
            Severity level: critical, high, medium, low
        """
        if not threat_names:
            return "low"

        # Check for critical indicators
        critical_keywords = ["trojan", "ransomware", "worm", "backdoor", "botnet"]
        high_keywords = ["spyware", "adware", "pup", "riskware"]

        threat_str = " ".join(threat_names).lower()

        for keyword in critical_keywords:
            if keyword in threat_str:
                return "critical"

        for keyword in high_keywords:
            if keyword in threat_str:
                return "high"

        return "medium"
