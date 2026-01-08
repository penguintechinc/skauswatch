"""IP Blacklist threat intelligence source."""
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any, Set

import httpx
import structlog

logger = structlog.get_logger()


class IPBlacklistSource:
    """
    IP blacklist source using free threat feeds.

    Sources:
    - Abuse.ch Feodo Tracker (banking trojans)
    - Abuse.ch SSL Blacklist
    - Blocklist.de (fail2ban aggregated)
    - Emerging Threats compromised IPs
    - FireHOL Level 1 (aggregated)
    """

    FEEDS = {
        "feodo": {
            "url": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
            "description": "Feodo Tracker - Banking Trojans",
            "format": "plain",
        },
        "sslbl": {
            "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
            "description": "SSL Blacklist - Malicious SSL IPs",
            "format": "plain",
        },
        "blocklist_de": {
            "url": "https://lists.blocklist.de/lists/all.txt",
            "description": "Blocklist.de - Aggregated fail2ban",
            "format": "plain",
        },
        "emerging_threats": {
            "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
            "description": "Emerging Threats - Compromised IPs",
            "format": "plain",
        },
    }

    def __init__(self):
        """Initialize IP blacklist source."""
        self._ip_cache: Set[str] = set()
        self._ip_sources: Dict[str, str] = {}  # ip -> source
        self._last_fetch: Optional[datetime] = None
        self._client = httpx.AsyncClient(timeout=30.0)

    async def check_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Check if indicator is in IP blacklists."""
        if indicator_type != "ip":
            return None

        # Ensure cache is populated
        if not self._ip_cache:
            await self.fetch_indicators()

        if value in self._ip_cache:
            source = self._ip_sources.get(value, "unknown")
            return {
                "indicator_type": "ip",
                "value": value,
                "malicious": True,
                "source": source,
                "feed_source": "ip_blacklist",
                "timestamp": datetime.utcnow().isoformat(),
            }

        return None

    async def fetch_indicators(self) -> List[Dict[str, Any]]:
        """Fetch all IP blacklist feeds."""
        indicators = []

        for feed_name, feed_config in self.FEEDS.items():
            try:
                feed_indicators = await self._fetch_feed(feed_name, feed_config)
                indicators.extend(feed_indicators)
            except Exception as e:
                logger.error(
                    "Failed to fetch feed",
                    feed=feed_name,
                    error=str(e)
                )

        self._last_fetch = datetime.utcnow()

        logger.info(
            "IP blacklist feeds updated",
            total_ips=len(self._ip_cache),
            feeds_fetched=len(self.FEEDS)
        )

        return indicators

    async def _fetch_feed(
        self, feed_name: str, config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Fetch a single IP blacklist feed."""
        indicators = []

        try:
            response = await self._client.get(config["url"])
            response.raise_for_status()

            content = response.text

            for line in content.split("\n"):
                line = line.strip()

                # Skip comments and empty lines
                if not line or line.startswith("#") or line.startswith(";"):
                    continue

                # Extract IP (some lists have additional data)
                ip = line.split()[0] if " " in line else line

                # Basic IP validation
                if self._is_valid_ip(ip):
                    self._ip_cache.add(ip)
                    self._ip_sources[ip] = feed_name

                    indicators.append({
                        "indicator_type": "ip",
                        "value": ip,
                        "source": feed_name,
                        "description": config["description"],
                        "threat_level": "high",
                        "confidence": 0.8,
                    })

        except httpx.HTTPError as e:
            logger.error(
                "HTTP error fetching feed",
                feed=feed_name,
                error=str(e)
            )
            raise

        return indicators

    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except (ValueError, AttributeError):
            return False

    async def enrich_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Enrich indicator with IP blacklist data."""
        result = await self.check_indicator(indicator_type, value)

        if result:
            # Add additional context
            feed_name = result.get("source")
            if feed_name in self.FEEDS:
                result["feed_description"] = self.FEEDS[feed_name]["description"]

            result["risk_score"] = 0.7  # High confidence malicious

        return result

    def get_statistics(self) -> Dict[str, Any]:
        """Get IP blacklist statistics."""
        return {
            "total_ips": len(self._ip_cache),
            "last_fetch": self._last_fetch.isoformat() if self._last_fetch else None,
            "feeds": list(self.FEEDS.keys()),
        }

    async def close(self) -> None:
        """Close HTTP client."""
        await self._client.aclose()
