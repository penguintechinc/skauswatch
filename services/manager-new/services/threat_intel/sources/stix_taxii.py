"""STIX/TAXII threat intelligence source."""
from datetime import datetime
from typing import Optional, List, Dict, Any

import httpx
import structlog

logger = structlog.get_logger()


class TAXIISource:
    """
    STIX/TAXII 2.1 threat intelligence feed client.

    TAXII (Trusted Automated eXchange of Intelligence Information) is a standard
    protocol for exchanging threat intelligence. Many free and commercial feeds
    are available via TAXII.

    Free TAXII feeds:
    - MITRE ATT&CK: https://cti-taxii.mitre.org/taxii/
    - Anomali LIMO: https://limo.anomali.com/api/v1/taxii2/
    - AlienVault: https://otx.alienvault.com/taxii/root/
    """

    DEFAULT_HEADERS = {
        "Accept": "application/taxii+json;version=2.1",
        "Content-Type": "application/taxii+json;version=2.1",
    }

    def __init__(
        self,
        server_url: str,
        collection_id: str = None,
        username: str = None,
        password: str = None,
        api_root: str = None,
    ):
        """Initialize TAXII source."""
        self.server_url = server_url.rstrip("/")
        self.collection_id = collection_id
        self.api_root = api_root
        self._auth = None

        if username and password:
            self._auth = (username, password)

        self._client = httpx.AsyncClient(
            headers=self.DEFAULT_HEADERS,
            auth=self._auth,
            timeout=60.0,
        )

    async def discover(self) -> Dict[str, Any]:
        """Discover TAXII server information."""
        try:
            response = await self._client.get(f"{self.server_url}/taxii2/")
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error("TAXII discovery failed", error=str(e))
            return {}

    async def get_api_roots(self) -> List[str]:
        """Get available API roots."""
        discovery = await self.discover()
        return discovery.get("api_roots", [])

    async def get_collections(self, api_root: str = None) -> List[Dict[str, Any]]:
        """Get available collections from an API root."""
        root = api_root or self.api_root or f"{self.server_url}/api/"

        try:
            response = await self._client.get(f"{root}collections/")
            response.raise_for_status()
            return response.json().get("collections", [])
        except Exception as e:
            logger.error("Failed to get collections", error=str(e))
            return []

    async def check_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """
        TAXII is feed-based, not query-based.
        Indicators should be fetched and stored locally.
        """
        return None

    async def fetch_indicators(self) -> List[Dict[str, Any]]:
        """Fetch STIX objects from TAXII collection."""
        if not self.collection_id:
            logger.warning("No collection_id configured for TAXII source")
            return []

        indicators = []
        api_root = self.api_root or f"{self.server_url}/api/"

        try:
            # Get collection objects
            url = f"{api_root}collections/{self.collection_id}/objects/"
            response = await self._client.get(url)
            response.raise_for_status()

            data = response.json()
            objects = data.get("objects", [])

            for obj in objects:
                stix_type = obj.get("type")

                if stix_type == "indicator":
                    # Parse STIX indicator
                    indicator = self._parse_stix_indicator(obj)
                    if indicator:
                        indicators.append(indicator)

                elif stix_type == "malware":
                    # Parse malware object
                    malware = self._parse_stix_malware(obj)
                    if malware:
                        indicators.append(malware)

                elif stix_type == "attack-pattern":
                    # Parse ATT&CK pattern
                    pattern = self._parse_attack_pattern(obj)
                    if pattern:
                        indicators.append(pattern)

            logger.info(
                "TAXII collection fetched",
                collection=self.collection_id,
                objects=len(objects),
                indicators=len(indicators)
            )

        except Exception as e:
            logger.error(
                "TAXII fetch failed",
                collection=self.collection_id,
                error=str(e)
            )

        return indicators

    def _parse_stix_indicator(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse STIX 2.1 indicator object."""
        pattern = obj.get("pattern", "")

        # Extract indicator value from STIX pattern
        # Example: [ipv4-addr:value = '1.2.3.4']
        indicator_type, value = self._parse_stix_pattern(pattern)

        if not indicator_type or not value:
            return None

        return {
            "indicator_type": indicator_type,
            "value": value,
            "source": "taxii",
            "stix_id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "pattern": pattern,
            "created": obj.get("created"),
            "modified": obj.get("modified"),
            "valid_from": obj.get("valid_from"),
            "valid_until": obj.get("valid_until"),
            "kill_chain_phases": obj.get("kill_chain_phases", []),
            "labels": obj.get("labels", []),
            "confidence": obj.get("confidence"),
            "threat_level": self._map_confidence_to_level(obj.get("confidence")),
        }

    def _parse_stix_pattern(self, pattern: str) -> tuple:
        """Parse STIX pattern to extract indicator type and value."""
        import re

        # IPv4 address pattern
        ipv4_match = re.search(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]", pattern)
        if ipv4_match:
            return ("ip", ipv4_match.group(1))

        # Domain pattern
        domain_match = re.search(r"\[domain-name:value\s*=\s*'([^']+)'\]", pattern)
        if domain_match:
            return ("domain", domain_match.group(1))

        # URL pattern
        url_match = re.search(r"\[url:value\s*=\s*'([^']+)'\]", pattern)
        if url_match:
            return ("url", url_match.group(1))

        # File hash patterns
        md5_match = re.search(r"\[file:hashes\.MD5\s*=\s*'([^']+)'\]", pattern, re.I)
        if md5_match:
            return ("hash", md5_match.group(1))

        sha256_match = re.search(r"\[file:hashes\.'SHA-256'\s*=\s*'([^']+)'\]", pattern, re.I)
        if sha256_match:
            return ("hash", sha256_match.group(1))

        # Email pattern
        email_match = re.search(r"\[email-addr:value\s*=\s*'([^']+)'\]", pattern)
        if email_match:
            return ("email", email_match.group(1))

        return (None, None)

    def _parse_stix_malware(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse STIX malware object."""
        return {
            "indicator_type": "malware",
            "value": obj.get("name", ""),
            "source": "taxii",
            "stix_id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "malware_types": obj.get("malware_types", []),
            "is_family": obj.get("is_family", False),
            "aliases": obj.get("aliases", []),
            "first_seen": obj.get("first_seen"),
            "last_seen": obj.get("last_seen"),
            "threat_level": "high",
        }

    def _parse_attack_pattern(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse MITRE ATT&CK pattern."""
        # Extract MITRE ATT&CK ID from external references
        mitre_id = None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                mitre_id = ref.get("external_id")
                break

        return {
            "indicator_type": "attack_pattern",
            "value": mitre_id or obj.get("name", ""),
            "source": "taxii",
            "stix_id": obj.get("id"),
            "name": obj.get("name"),
            "description": obj.get("description"),
            "mitre_id": mitre_id,
            "kill_chain_phases": obj.get("kill_chain_phases", []),
            "external_references": obj.get("external_references", []),
            "threat_level": "info",
        }

    def _map_confidence_to_level(self, confidence: Optional[int]) -> str:
        """Map STIX confidence score to threat level."""
        if confidence is None:
            return "medium"

        if confidence >= 85:
            return "critical"
        elif confidence >= 65:
            return "high"
        elif confidence >= 35:
            return "medium"
        else:
            return "low"

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.aclose()
