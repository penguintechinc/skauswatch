"""Shodan API client for threat intelligence lookups."""

from typing import Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


class ShodanClient:
    """Optional Shodan integration for IP and domain intelligence."""

    def __init__(self, api_key: Optional[str] = None, enabled: bool = False):
        """Initialize Shodan client.

        Args:
            api_key: Shodan API key (optional)
            enabled: Whether integration is enabled
        """
        self.api_key = api_key
        self.enabled = enabled and api_key is not None
        self.base_url = "https://api.shodan.io"
        self.timeout = httpx.Timeout(30.0)

    async def lookup_ip(self, ip: str) -> dict:
        """Look up IP address information.

        Args:
            ip: IP address to lookup

        Returns:
            Dict with ports, services, vulns, banners, ssl_cert, last_update
            Empty dict if not enabled or API key missing
        """
        if not self.enabled:
            logger.debug("shodan_lookup_ip_disabled", ip=ip)
            return {}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/shodan/host/{ip}",
                    params={"key": self.api_key},
                )
                response.raise_for_status()
                data = response.json()

                logger.info("shodan_lookup_ip_success", ip=ip)
                return {
                    "ports": data.get("ports", []),
                    "services": data.get("data", []),
                    "vulns": data.get("vulns", []),
                    "banners": data.get("data", []),
                    "ssl_cert": data.get("ssl", {}),
                    "last_update": data.get("last_update"),
                }
        except httpx.HTTPError as e:
            logger.error("shodan_lookup_ip_error", ip=ip, error=str(e))
            return {}
        except Exception as e:
            logger.error("shodan_lookup_ip_exception", ip=ip, error=str(e))
            return {}

    async def lookup_domain(self, domain: str) -> dict:
        """Look up domain and resolve to IP then lookup.

        Args:
            domain: Domain name to lookup

        Returns:
            Dict with IP information
            Empty dict if not enabled or API key missing
        """
        if not self.enabled:
            logger.debug("shodan_lookup_domain_disabled", domain=domain)
            return {}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # First resolve domain to IP
                dns_response = await client.get(
                    f"{self.base_url}/dns/resolve",
                    params={"hostnames": domain, "key": self.api_key},
                )
                dns_response.raise_for_status()
                dns_data = dns_response.json()

                if domain not in dns_data:
                    logger.warning("shodan_domain_not_resolved", domain=domain)
                    return {}

                ip = dns_data[domain]

                # Then lookup the IP
                return await self.lookup_ip(ip)
        except httpx.HTTPError as e:
            logger.error("shodan_lookup_domain_error", domain=domain, error=str(e))
            return {}
        except Exception as e:
            logger.error("shodan_lookup_domain_exception", domain=domain, error=str(e))
            return {}

    async def search(self, query: str) -> list:
        """Execute Shodan search query.

        Args:
            query: Shodan search query string

        Returns:
            List of search results
            Empty list if not enabled or API key missing
        """
        if not self.enabled:
            logger.debug("shodan_search_disabled", query=query)
            return []

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.base_url}/shodan/host/search",
                    params={"query": query, "key": self.api_key},
                )
                response.raise_for_status()
                data = response.json()

                logger.info("shodan_search_success", query=query)
                return data.get("matches", [])
        except httpx.HTTPError as e:
            logger.error("shodan_search_error", query=query, error=str(e))
            return []
        except Exception as e:
            logger.error("shodan_search_exception", query=query, error=str(e))
            return []
