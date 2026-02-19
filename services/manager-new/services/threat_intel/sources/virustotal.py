"""VirusTotal threat intelligence source."""

from datetime import datetime
from typing import Optional, List, Dict, Any

import httpx
import structlog

logger = structlog.get_logger()


class VirusTotalSource:
    """
    VirusTotal API integration.

    Free tier limits:
    - 500 lookups per day
    - 4 lookups per minute
    - No file submissions

    Get free API key at: https://www.virustotal.com/
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    INDICATOR_ENDPOINTS = {
        "ip": "/ip_addresses/{value}",
        "domain": "/domains/{value}",
        "url": "/urls/{value}",
        "hash": "/files/{value}",
    }

    def __init__(self, api_key: str):
        """Initialize VirusTotal source."""
        self.api_key = api_key
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            headers={"x-apikey": api_key},
            timeout=30.0,
        )

    async def check_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Check an indicator against VirusTotal."""
        if indicator_type not in self.INDICATOR_ENDPOINTS:
            return None

        # URL needs to be base64 encoded
        if indicator_type == "url":
            import base64

            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

        try:
            endpoint = self.INDICATOR_ENDPOINTS[indicator_type].format(value=value)
            response = await self._client.get(endpoint)

            if response.status_code == 404:
                return None

            if response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                return None

            response.raise_for_status()
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})

            # Get analysis stats
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            if malicious > 0 or suspicious > 0:
                return {
                    "indicator_type": indicator_type,
                    "value": value,
                    "malicious": malicious > 0,
                    "suspicious": suspicious > 0,
                    "stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                        "total": total,
                    },
                    "detection_rate": f"{malicious}/{total}" if total else "0/0",
                    "reputation": attributes.get("reputation", 0),
                    "tags": attributes.get("tags", []),
                    "source": "virustotal",
                    "timestamp": datetime.utcnow().isoformat(),
                }

        except httpx.HTTPStatusError as e:
            logger.error("VirusTotal API error", status=e.response.status_code)
        except Exception as e:
            logger.error("VirusTotal check failed", error=str(e))

        return None

    async def fetch_indicators(self) -> List[Dict[str, Any]]:
        """
        VirusTotal is query-based, not feed-based for free tier.
        Returns empty list.
        """
        return []

    async def enrich_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Get full enrichment data for an indicator."""
        if indicator_type not in self.INDICATOR_ENDPOINTS:
            return None

        original_value = value

        # URL needs to be base64 encoded
        if indicator_type == "url":
            import base64

            value = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")

        enrichment = {
            "indicator_type": indicator_type,
            "value": original_value,
            "source": "virustotal",
        }

        try:
            endpoint = self.INDICATOR_ENDPOINTS[indicator_type].format(value=value)
            response = await self._client.get(endpoint)

            if response.status_code == 404:
                enrichment["found"] = False
                return enrichment

            response.raise_for_status()
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})

            # Analysis stats
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values()) if stats else 0

            enrichment.update(
                {
                    "found": True,
                    "malicious": malicious > 0,
                    "stats": stats,
                    "detection_rate": f"{malicious}/{total}" if total else "0/0",
                    "reputation": attributes.get("reputation", 0),
                    "tags": attributes.get("tags", []),
                }
            )

            # Type-specific enrichment
            if indicator_type == "ip":
                enrichment.update(
                    {
                        "asn": attributes.get("asn"),
                        "as_owner": attributes.get("as_owner"),
                        "country": attributes.get("country"),
                        "network": attributes.get("network"),
                    }
                )

            elif indicator_type == "domain":
                enrichment.update(
                    {
                        "registrar": attributes.get("registrar"),
                        "creation_date": attributes.get("creation_date"),
                        "last_dns_records": attributes.get("last_dns_records", [])[:5],
                        "popularity_ranks": attributes.get("popularity_ranks"),
                    }
                )

            elif indicator_type == "hash":
                enrichment.update(
                    {
                        "meaningful_name": attributes.get("meaningful_name"),
                        "type_description": attributes.get("type_description"),
                        "size": attributes.get("size"),
                        "names": attributes.get("names", [])[:5],
                        "sandbox_verdicts": attributes.get("sandbox_verdicts"),
                    }
                )

            # Calculate risk score
            enrichment["risk_score"] = self._calculate_risk_score(
                malicious, suspicious, total
            )

        except Exception as e:
            logger.error("VirusTotal enrichment failed", error=str(e))
            enrichment["error"] = str(e)

        return enrichment

    async def check_file_hash(self, file_hash: str) -> Optional[Dict[str, Any]]:
        """Check a file hash (MD5, SHA1, or SHA256)."""
        return await self.check_indicator("hash", file_hash)

    async def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Check a URL."""
        return await self.check_indicator("url", url)

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check an IP address."""
        return await self.check_indicator("ip", ip)

    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check a domain."""
        return await self.check_indicator("domain", domain)

    def _calculate_risk_score(
        self, malicious: int, suspicious: int, total: int
    ) -> float:
        """Calculate risk score from VT stats."""
        if total == 0:
            return 0.0

        # Weight malicious more heavily than suspicious
        weighted_bad = malicious + (suspicious * 0.5)
        ratio = weighted_bad / total

        # Scale to 0-1 with thresholds
        if ratio > 0.3:
            return 0.9
        elif ratio > 0.1:
            return 0.7
        elif malicious > 0:
            return 0.5
        elif suspicious > 0:
            return 0.3
        return 0.0

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.aclose()
