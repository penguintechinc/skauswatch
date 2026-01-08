"""DNS Blacklist threat intelligence source."""
import asyncio
from datetime import datetime
from typing import Optional, List, Dict, Any

import structlog

logger = structlog.get_logger()


class DNSBlacklistSource:
    """
    DNS-based blacklist checker for IP addresses and domains.

    Checks against multiple free DNS blacklists:
    - SpamHaus ZEN (XBL, SBL, PBL combined)
    - SpamCop
    - SORBS
    - Barracuda
    - UCEPROTECT
    """

    # DNS blacklist zones for IP checking
    IP_BLACKLISTS = [
        ("zen.spamhaus.org", "SpamHaus ZEN"),
        ("bl.spamcop.net", "SpamCop"),
        ("dnsbl.sorbs.net", "SORBS"),
        ("b.barracudacentral.org", "Barracuda"),
        ("dnsbl-1.uceprotect.net", "UCEPROTECT Level 1"),
    ]

    # DNS blacklist zones for domain checking
    DOMAIN_BLACKLISTS = [
        ("dbl.spamhaus.org", "SpamHaus DBL"),
        ("multi.surbl.org", "SURBL"),
        ("black.uribl.com", "URIBL Black"),
    ]

    def __init__(self):
        """Initialize DNS blacklist source."""
        self._resolver = None

    async def _get_resolver(self):
        """Get or create DNS resolver."""
        if self._resolver is None:
            try:
                import dns.asyncresolver
                self._resolver = dns.asyncresolver.Resolver()
                self._resolver.timeout = 5.0
                self._resolver.lifetime = 10.0
            except ImportError:
                logger.warning("dnspython not installed, DNS blacklist checks unavailable")
                return None
        return self._resolver

    async def check_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Check if indicator is on any DNS blacklist."""
        if indicator_type == "ip":
            return await self.check_ip(value)
        elif indicator_type == "domain":
            return await self.check_domain(value)
        return None

    async def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check if IP is on any DNS blacklist."""
        resolver = await self._get_resolver()
        if not resolver:
            return None

        # Reverse the IP for DNSBL lookup
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return None
            reversed_ip = ".".join(reversed(parts))
        except Exception:
            return None

        listed_on = []

        for zone, name in self.IP_BLACKLISTS:
            query = f"{reversed_ip}.{zone}"
            try:
                await resolver.resolve(query, "A")
                listed_on.append({
                    "blacklist": name,
                    "zone": zone,
                })
            except Exception:
                # Not listed or query failed
                pass

        if listed_on:
            return {
                "indicator_type": "ip",
                "value": ip,
                "malicious": True,
                "listed_on": listed_on,
                "list_count": len(listed_on),
                "checked_lists": len(self.IP_BLACKLISTS),
                "source": "dns_blacklist",
                "timestamp": datetime.utcnow().isoformat(),
            }

        return None

    async def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check if domain is on any DNS blacklist."""
        resolver = await self._get_resolver()
        if not resolver:
            return None

        # Clean domain
        domain = domain.lower().strip()
        if domain.startswith("www."):
            domain = domain[4:]

        listed_on = []

        for zone, name in self.DOMAIN_BLACKLISTS:
            query = f"{domain}.{zone}"
            try:
                await resolver.resolve(query, "A")
                listed_on.append({
                    "blacklist": name,
                    "zone": zone,
                })
            except Exception:
                pass

        if listed_on:
            return {
                "indicator_type": "domain",
                "value": domain,
                "malicious": True,
                "listed_on": listed_on,
                "list_count": len(listed_on),
                "checked_lists": len(self.DOMAIN_BLACKLISTS),
                "source": "dns_blacklist",
                "timestamp": datetime.utcnow().isoformat(),
            }

        return None

    async def fetch_indicators(self) -> List[Dict[str, Any]]:
        """
        DNS blacklists are query-based, not feed-based.
        Returns empty list as indicators are checked on-demand.
        """
        return []

    async def enrich_indicator(
        self, indicator_type: str, value: str
    ) -> Optional[Dict[str, Any]]:
        """Enrich indicator with DNS blacklist data."""
        result = await self.check_indicator(indicator_type, value)

        if result:
            # Add risk scoring based on number of lists
            list_count = result.get("list_count", 0)
            if list_count >= 3:
                risk_score = 0.9
            elif list_count >= 2:
                risk_score = 0.7
            else:
                risk_score = 0.5

            result["risk_score"] = risk_score

        return result

    async def bulk_check_ips(self, ips: List[str]) -> List[Dict[str, Any]]:
        """Check multiple IPs against DNS blacklists."""
        tasks = [self.check_ip(ip) for ip in ips]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        matches = []
        for ip, result in zip(ips, results):
            if isinstance(result, Exception):
                logger.error("IP check failed", ip=ip, error=str(result))
                continue
            if result:
                matches.append(result)

        return matches
