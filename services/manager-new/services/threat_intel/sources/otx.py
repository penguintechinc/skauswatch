"""AlienVault OTX threat intelligence source."""
from datetime import datetime
from typing import Optional, List, Dict, Any

import httpx
import structlog

logger = structlog.get_logger()


class OTXSource:
    """
    AlienVault Open Threat Exchange (OTX) integration.

    Free API with generous rate limits:
    - 1000 API calls per hour
    - Pulses (threat reports) with IOCs
    - Indicator lookups
    - Threat intel enrichment

    Get free API key at: https://otx.alienvault.com/
    """

    INDICATOR_TYPES = {
        "ip": "IPv4",
        "ipv6": "IPv6",
        "domain": "domain",
        "hostname": "hostname",
        "url": "URL",
        "hash": "FileHash-MD5",
        "hash_sha1": "FileHash-SHA1",
        "hash_sha256": "FileHash-SHA256",
        "email": "email",
        "cve": "CVE",
    }

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://otx.alienvault.com/api/v1"
    ):
        """Initialize OTX source."""
        self.api_key = api_key
        self.base_url = base_url
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers={"X-OTX-API-KEY": api_key},
            timeout=30.0,
        )

    async def check_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Check an indicator against OTX."""
        otx_type = self._map_indicator_type(indicator_type)
        if not otx_type:
            return None

        try:
            endpoint = f"/indicators/{otx_type}/{value}/general"
            response = await self._client.get(endpoint)

            if response.status_code == 404:
                return None

            response.raise_for_status()
            data = response.json()

            # Check if indicator has any pulses (threat reports)
            pulse_count = data.get("pulse_info", {}).get("count", 0)

            if pulse_count > 0:
                return {
                    "indicator_type": indicator_type,
                    "value": value,
                    "malicious": True,
                    "pulse_count": pulse_count,
                    "pulses": data.get("pulse_info", {}).get("pulses", [])[:5],
                    "validation": data.get("validation", []),
                    "asn": data.get("asn"),
                    "country_code": data.get("country_code"),
                    "source": "otx",
                    "timestamp": datetime.utcnow().isoformat(),
                }

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                logger.warning("OTX rate limit exceeded")
            else:
                logger.error("OTX API error", status=e.response.status_code)
        except Exception as e:
            logger.error("OTX check failed", error=str(e))

        return None

    async def fetch_indicators(self) -> List[Dict[str, Any]]:
        """Fetch subscribed pulse indicators."""
        indicators = []

        try:
            # Get subscribed pulses
            response = await self._client.get(
                "/pulses/subscribed",
                params={"limit": 50, "page": 1}
            )
            response.raise_for_status()

            data = response.json()
            pulses = data.get("results", [])

            for pulse in pulses:
                pulse_indicators = pulse.get("indicators", [])

                for ind in pulse_indicators:
                    indicators.append({
                        "indicator_type": self._reverse_map_type(ind.get("type")),
                        "value": ind.get("indicator"),
                        "source": "otx",
                        "pulse_id": pulse.get("id"),
                        "pulse_name": pulse.get("name"),
                        "description": ind.get("description"),
                        "created": ind.get("created"),
                        "threat_level": self._map_threat_level(pulse),
                        "tags": pulse.get("tags", []),
                    })

            logger.info(
                "OTX pulses fetched",
                pulse_count=len(pulses),
                indicator_count=len(indicators)
            )

        except Exception as e:
            logger.error("OTX fetch failed", error=str(e))

        return indicators

    async def enrich_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Get full enrichment data for an indicator."""
        otx_type = self._map_indicator_type(indicator_type)
        if not otx_type:
            return None

        enrichment = {
            "indicator_type": indicator_type,
            "value": value,
            "source": "otx",
        }

        try:
            # Get general info
            general = await self._get_section(otx_type, value, "general")
            if general:
                enrichment["general"] = general
                enrichment["pulse_count"] = general.get("pulse_info", {}).get("count", 0)
                enrichment["malicious"] = enrichment["pulse_count"] > 0

            # Get geo info for IPs
            if indicator_type in ("ip", "ipv6"):
                geo = await self._get_section(otx_type, value, "geo")
                if geo:
                    enrichment["geo"] = {
                        "country": geo.get("country_name"),
                        "country_code": geo.get("country_code"),
                        "city": geo.get("city"),
                        "asn": geo.get("asn"),
                        "isp": geo.get("isp"),
                    }

                # Get passive DNS
                pdns = await self._get_section(otx_type, value, "passive_dns")
                if pdns:
                    enrichment["passive_dns"] = pdns.get("passive_dns", [])[:10]

            # Get URL info for domains
            elif indicator_type == "domain":
                url_list = await self._get_section(otx_type, value, "url_list")
                if url_list:
                    enrichment["related_urls"] = url_list.get("url_list", [])[:10]

            # Calculate risk score
            enrichment["risk_score"] = self._calculate_risk_score(enrichment)

        except Exception as e:
            logger.error("OTX enrichment failed", error=str(e))

        return enrichment

    async def _get_section(
        self, otx_type: str, value: str, section: str
    ) -> Optional[Dict[str, Any]]:
        """Get a specific section of indicator data."""
        try:
            endpoint = f"/indicators/{otx_type}/{value}/{section}"
            response = await self._client.get(endpoint)

            if response.status_code == 404:
                return None

            response.raise_for_status()
            return response.json()

        except Exception:
            return None

    async def get_pulses(
        self, modified_since: str = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get threat pulses."""
        params = {"limit": limit, "page": 1}
        if modified_since:
            params["modified_since"] = modified_since

        try:
            response = await self._client.get(
                "/pulses/subscribed", params=params
            )
            response.raise_for_status()
            return response.json().get("results", [])
        except Exception as e:
            logger.error("Failed to get pulses", error=str(e))
            return []

    def _map_indicator_type(self, indicator_type: str) -> Optional[str]:
        """Map internal indicator type to OTX type."""
        return self.INDICATOR_TYPES.get(indicator_type)

    def _reverse_map_type(self, otx_type: str) -> str:
        """Map OTX type back to internal type."""
        reverse_map = {v: k for k, v in self.INDICATOR_TYPES.items()}
        return reverse_map.get(otx_type, "unknown")

    def _map_threat_level(self, pulse: Dict[str, Any]) -> str:
        """Determine threat level from pulse data."""
        adversary = pulse.get("adversary")
        targeted = pulse.get("targeted_countries", [])
        malware = pulse.get("malware_families", [])

        if adversary or malware:
            return "high"
        elif targeted:
            return "medium"
        return "low"

    def _calculate_risk_score(self, enrichment: Dict[str, Any]) -> float:
        """Calculate risk score from enrichment data."""
        score = 0.0

        pulse_count = enrichment.get("pulse_count", 0)
        if pulse_count > 10:
            score = 0.9
        elif pulse_count > 5:
            score = 0.7
        elif pulse_count > 0:
            score = 0.5

        return score

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.aclose()
