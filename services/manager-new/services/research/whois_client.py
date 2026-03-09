import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional, Union

import structlog
import whois
from ipwhois import IPWhois

logger = structlog.get_logger(__name__)


def _extract_date(date_value: Union[datetime, list, None]) -> Optional[str]:
    """Extract ISO format date string from WHOIS date field.

    python-whois sometimes returns dates as lists (multiple registrar entries).
    This helper extracts the first date and converts to ISO format.

    Args:
        date_value: Date value from WHOIS lookup (datetime, list, or None).

    Returns:
        ISO format date string or None.
    """
    if date_value is None:
        return None

    if isinstance(date_value, list):
        # Take the first date from the list
        if len(date_value) > 0 and date_value[0] is not None:
            first_date = date_value[0]
            if isinstance(first_date, datetime):
                return first_date.isoformat()
            elif isinstance(first_date, str):
                return first_date
        return None

    if isinstance(date_value, datetime):
        return date_value.isoformat()

    if isinstance(date_value, str):
        return date_value

    return None


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

            result = await asyncio.to_thread(self._blocking_domain_lookup, domain)

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

            # Handle nameservers which can also be a list or None
            nameservers = whois_info.name_servers
            if nameservers is None:
                nameservers = []
            elif isinstance(nameservers, str):
                nameservers = [nameservers]

            return {
                "success": True,
                "domain": domain,
                "registrar": whois_info.registrar,
                "creation_date": _extract_date(whois_info.creation_date),
                "expiration_date": _extract_date(whois_info.expiration_date),
                "updated_date": _extract_date(whois_info.updated_date),
                "nameservers": list(nameservers),
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

            result = await asyncio.to_thread(self._blocking_ip_lookup, ip)

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
            # Use lookup_rdap for modern RDAP protocol, fallback to lookup_whois
            try:
                result = ipwhois_obj.lookup_rdap(depth=1)
            except Exception:
                result = ipwhois_obj.lookup_whois()

            # RDAP returns slightly different structure
            network = result.get("network", {}) or {}
            asn_info = result.get("asn", result.get("asn_cidr", ""))

            return {
                "success": True,
                "ip": ip,
                "asn": result.get("asn"),
                "asn_registry": result.get("asn_registry"),
                "network": network.get("cidr") or result.get("asn_cidr"),
                "organization": (
                    network.get("name")
                    or result.get("asn_description")
                    or result.get("network", {}).get("name")
                ),
                "country": (network.get("country") or result.get("asn_country_code")),
                "description": network.get("remarks") or result.get("asn_description"),
                "type": network.get("type"),
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
