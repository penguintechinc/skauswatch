import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional

import structlog
import whois
from ipwhois import IPWhois

logger = structlog.get_logger(__name__)


@dataclass
class WhoisResult:
    """Result of WHOIS lookup."""

    success: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


class WhoisClient:
    """Async WHOIS client for domain and IP lookups."""

    def __init__(self, timeout: int = 10) -> None:
        """Initialize WhoisClient.

        Args:
            timeout: Request timeout in seconds (default: 10).
        """
        self.timeout = timeout
        self.logger = structlog.get_logger(__name__)

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        """Look up domain WHOIS information.

        Args:
            domain: Domain name to look up.

        Returns:
            Dictionary with registrar, dates, nameservers, and registrant info.
        """
        try:
            self.logger.debug("domain_lookup_start", domain=domain)

            result = await asyncio.to_thread(
                self._blocking_domain_lookup, domain
            )

            self.logger.debug("domain_lookup_success", domain=domain)
            return result

        except Exception as e:
            self.logger.error(
                "domain_lookup_error",
                domain=domain,
                error=str(e),
            )
            return {
                "success": False,
                "domain": domain,
                "error": str(e),
            }

    def _blocking_domain_lookup(self, domain: str) -> dict[str, Any]:
        """Blocking domain WHOIS lookup.

        Args:
            domain: Domain name to look up.

        Returns:
            Dictionary with domain WHOIS information.
        """
        try:
            whois_info = whois.whois(domain, timeout=self.timeout)

            return {
                "success": True,
                "domain": domain,
                "registrar": whois_info.registrar,
                "creation_date": (
                    whois_info.creation_date.isoformat()
                    if whois_info.creation_date
                    else None
                ),
                "expiration_date": (
                    whois_info.expiration_date.isoformat()
                    if whois_info.expiration_date
                    else None
                ),
                "updated_date": (
                    whois_info.updated_date.isoformat()
                    if whois_info.updated_date
                    else None
                ),
                "nameservers": whois_info.name_servers or [],
                "registrant_name": whois_info.registrant_name,
                "registrant_org": whois_info.registrant_organization,
                "registrant_country": whois_info.registrant_country,
                "registrant_email": whois_info.registrant_email,
            }

        except Exception as e:
            self.logger.error(
                "blocking_domain_lookup_error",
                domain=domain,
                error=str(e),
            )
            return {
                "success": False,
                "domain": domain,
                "error": str(e),
            }

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        """Look up IP WHOIS information.

        Args:
            ip: IP address to look up.

        Returns:
            Dictionary with ASN, network, organization, and country info.
        """
        try:
            self.logger.debug("ip_lookup_start", ip=ip)

            result = await asyncio.to_thread(
                self._blocking_ip_lookup, ip
            )

            self.logger.debug("ip_lookup_success", ip=ip)
            return result

        except Exception as e:
            self.logger.error(
                "ip_lookup_error",
                ip=ip,
                error=str(e),
            )
            return {
                "success": False,
                "ip": ip,
                "error": str(e),
            }

    def _blocking_ip_lookup(self, ip: str) -> dict[str, Any]:
        """Blocking IP WHOIS lookup.

        Args:
            ip: IP address to look up.

        Returns:
            Dictionary with IP WHOIS information.
        """
        try:
            ipwhois_obj = IPWhois(ip, timeout=self.timeout)
            result = ipwhois_obj.lookup()

            return {
                "success": True,
                "ip": ip,
                "asn": result.get("asn"),
                "asn_registry": result.get("asn_registry"),
                "network": result.get("network", {}).get("cidr"),
                "organization": result.get("asn_organization"),
                "country": result.get("asn_country_code"),
                "description": result.get("network", {}).get("description"),
                "type": result.get("network", {}).get("type"),
            }

        except Exception as e:
            self.logger.error(
                "blocking_ip_lookup_error",
                ip=ip,
                error=str(e),
            )
            return {
                "success": False,
                "ip": ip,
                "error": str(e),
            }
