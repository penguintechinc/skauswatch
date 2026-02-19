"""Maltego API client for open source intelligence transforms."""

from typing import Optional

import httpx
import structlog

logger = structlog.get_logger(__name__)


class MaltegoClient:
    """Optional Maltego integration using transforms or public APIs."""

    def __init__(self, trx_server: Optional[str] = None, enabled: bool = False):
        """Initialize Maltego client.

        Args:
            trx_server: Maltego TRX server URL (optional)
            enabled: Whether integration is enabled
        """
        self.trx_server = trx_server
        self.enabled = enabled
        self.timeout = httpx.Timeout(30.0)
        self.hackertarget_base = "https://api.hackertarget.com"

    async def domain_transforms(self, domain: str) -> dict:
        """Get domain transformation data.

        Uses Maltego TRX if available, otherwise uses public APIs.

        Args:
            domain: Domain name to analyze

        Returns:
            Dict with related_domains, emails, social_profiles, shared_hosting
            Empty dict if not enabled
        """
        if not self.enabled:
            logger.debug("maltego_domain_transforms_disabled", domain=domain)
            return {}

        if self.trx_server:
            return await self._domain_transforms_trx(domain)
        else:
            return await self._domain_transforms_public(domain)

    async def _domain_transforms_trx(self, domain: str) -> dict:
        """Domain transforms using Maltego TRX server."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    f"{self.trx_server}/transform/whois/{domain}"
                )
                response.raise_for_status()
                data = response.json()

                logger.info("maltego_domain_transforms_trx_success", domain=domain)
                return {
                    "related_domains": data.get("related_domains", []),
                    "emails": data.get("emails", []),
                    "social_profiles": data.get("social_profiles", []),
                    "shared_hosting": data.get("shared_hosting", []),
                }
        except httpx.HTTPError as e:
            logger.error(
                "maltego_domain_transforms_trx_error", domain=domain, error=str(e)
            )
            return {}
        except Exception as e:
            logger.error(
                "maltego_domain_transforms_trx_exception",
                domain=domain,
                error=str(e),
            )
            return {}

    async def _domain_transforms_public(self, domain: str) -> dict:
        """Domain transforms using free public APIs."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Get reverse DNS and subdomains
                response = await client.get(
                    f"{self.hackertarget_base}/reverseiplookup.php",
                    params={"host": domain},
                )
                response.raise_for_status()
                data = response.text

                logger.info("maltego_domain_transforms_public_success", domain=domain)
                return {
                    "related_domains": data.split("\n") if data else [],
                    "emails": [],
                    "social_profiles": [],
                    "shared_hosting": [],
                }
        except httpx.HTTPError as e:
            logger.error(
                "maltego_domain_transforms_public_error", domain=domain, error=str(e)
            )
            return {}
        except Exception as e:
            logger.error(
                "maltego_domain_transforms_public_exception",
                domain=domain,
                error=str(e),
            )
            return {}

    async def ip_transforms(self, ip: str) -> dict:
        """Get IP transformation data.

        Uses Maltego TRX if available, otherwise uses public APIs.

        Args:
            ip: IP address to analyze

        Returns:
            Dict with reverse_dns, geolocation, hosting_info
            Empty dict if not enabled
        """
        if not self.enabled:
            logger.debug("maltego_ip_transforms_disabled", ip=ip)
            return {}

        if self.trx_server:
            return await self._ip_transforms_trx(ip)
        else:
            return await self._ip_transforms_public(ip)

    async def _ip_transforms_trx(self, ip: str) -> dict:
        """IP transforms using Maltego TRX server."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(f"{self.trx_server}/transform/ip/{ip}")
                response.raise_for_status()
                data = response.json()

                logger.info("maltego_ip_transforms_trx_success", ip=ip)
                return {
                    "reverse_dns": data.get("reverse_dns", []),
                    "geolocation": data.get("geolocation", {}),
                    "hosting_info": data.get("hosting_info", {}),
                }
        except httpx.HTTPError as e:
            logger.error("maltego_ip_transforms_trx_error", ip=ip, error=str(e))
            return {}
        except Exception as e:
            logger.error("maltego_ip_transforms_trx_exception", ip=ip, error=str(e))
            return {}

    async def _ip_transforms_public(self, ip: str) -> dict:
        """IP transforms using free public APIs."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Get reverse DNS lookup
                response = await client.get(
                    f"{self.hackertarget_base}/reversednslookup.php",
                    params={"ip": ip},
                )
                response.raise_for_status()
                data = response.text

                logger.info("maltego_ip_transforms_public_success", ip=ip)
                return {
                    "reverse_dns": data.split("\n") if data else [],
                    "geolocation": {},
                    "hosting_info": {},
                }
        except httpx.HTTPError as e:
            logger.error("maltego_ip_transforms_public_error", ip=ip, error=str(e))
            return {}
        except Exception as e:
            logger.error("maltego_ip_transforms_public_exception", ip=ip, error=str(e))
            return {}
