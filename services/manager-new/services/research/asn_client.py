"""
Team Cymru DNS-based ASN lookup client.

Uses origin.asn.cymru.com and asn.cymru.com for ASN information lookups.
"""

import asyncio
import dns.asyncresolver
import structlog
from typing import Optional

logger = structlog.get_logger(__name__)


class ASNClient:
    """DNS-based ASN lookup client using Team Cymru services."""

    def __init__(self, timeout: int = 5) -> None:
        """
        Initialize ASN client.

        Args:
            timeout: DNS query timeout in seconds.
        """
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    async def lookup_ip(self, ip: str) -> dict:
        """
        Lookup ASN information for an IP address.

        Args:
            ip: IPv4 or IPv6 address.

        Returns:
            Dictionary containing:
                - asn: Autonomous System Number
                - asn_cidr: CIDR block assigned to the ASN
                - asn_country: Country code
                - asn_registry: Registry (arin, apnic, etc)
                - asn_description: Description of the ASN
        """
        try:
            logger.debug("lookup_ip_start", ip=ip)

            # Reverse IP for DNS query format
            reversed_ip = self._reverse_ip(ip)
            query = f"{reversed_ip}.origin.asn.cymru.com"

            # Query TXT record
            answers = await self.resolver.resolve(query, "TXT")

            if not answers:
                logger.warning("lookup_ip_no_result", ip=ip)
                return {
                    "asn": None,
                    "asn_cidr": None,
                    "asn_country": None,
                    "asn_registry": None,
                    "asn_description": None,
                }

            # Parse response format: "ASN | CIDR | Country | Registry | Description"
            response = str(answers[0]).strip('"')
            parts = [p.strip() for p in response.split("|")]

            if len(parts) < 5:
                logger.warning(
                    "lookup_ip_invalid_response",
                    ip=ip,
                    response=response,
                    parts_count=len(parts),
                )
                return {
                    "asn": None,
                    "asn_cidr": None,
                    "asn_country": None,
                    "asn_registry": None,
                    "asn_description": None,
                }

            result = {
                "asn": parts[0],
                "asn_cidr": parts[1],
                "asn_country": parts[2],
                "asn_registry": parts[3],
                "asn_description": parts[4],
            }

            logger.debug("lookup_ip_success", ip=ip, asn=parts[0])
            return result

        except dns.asyncresolver.NXDOMAIN:
            logger.info("lookup_ip_not_found", ip=ip)
            return {
                "asn": None,
                "asn_cidr": None,
                "asn_country": None,
                "asn_registry": None,
                "asn_description": None,
            }
        except (dns.asyncresolver.Timeout, dns.asyncresolver.LifetimeTimeout):
            logger.warning("lookup_ip_timeout", ip=ip)
            return {
                "asn": None,
                "asn_cidr": None,
                "asn_country": None,
                "asn_registry": None,
                "asn_description": None,
            }
        except Exception as e:
            logger.exception("lookup_ip_error", ip=ip, error=str(e))
            return {
                "asn": None,
                "asn_cidr": None,
                "asn_country": None,
                "asn_registry": None,
                "asn_description": None,
            }

    async def lookup_asn(self, asn: str) -> dict:
        """
        Lookup detailed information for an ASN.

        Args:
            asn: Autonomous System Number (e.g., "AS15169" or "15169").

        Returns:
            Dictionary containing:
                - asn: Autonomous System Number
                - country: Country code
                - registry: Registry (arin, apnic, etc)
                - description: Description of the ASN
                - date_allocated: Date when ASN was allocated
        """
        try:
            # Normalize ASN format
            asn_number = asn.upper().replace("AS", "")

            logger.debug("lookup_asn_start", asn=asn_number)

            query = f"AS{asn_number}.asn.cymru.com"

            # Query TXT record
            answers = await self.resolver.resolve(query, "TXT")

            if not answers:
                logger.warning("lookup_asn_no_result", asn=asn_number)
                return {
                    "asn": None,
                    "country": None,
                    "registry": None,
                    "description": None,
                    "date_allocated": None,
                }

            # Parse response format:
            # "ASN | Country | Registry | Allocated | Description"
            response = str(answers[0]).strip('"')
            parts = [p.strip() for p in response.split("|")]

            if len(parts) < 5:
                logger.warning(
                    "lookup_asn_invalid_response",
                    asn=asn_number,
                    response=response,
                    parts_count=len(parts),
                )
                return {
                    "asn": None,
                    "country": None,
                    "registry": None,
                    "description": None,
                    "date_allocated": None,
                }

            result = {
                "asn": parts[0],
                "country": parts[1],
                "registry": parts[2],
                "date_allocated": parts[3],
                "description": parts[4],
            }

            logger.debug("lookup_asn_success", asn=asn_number)
            return result

        except dns.asyncresolver.NXDOMAIN:
            logger.info("lookup_asn_not_found", asn=asn)
            return {
                "asn": None,
                "country": None,
                "registry": None,
                "description": None,
                "date_allocated": None,
            }
        except (dns.asyncresolver.Timeout, dns.asyncresolver.LifetimeTimeout):
            logger.warning("lookup_asn_timeout", asn=asn)
            return {
                "asn": None,
                "country": None,
                "registry": None,
                "description": None,
                "date_allocated": None,
            }
        except Exception as e:
            logger.exception("lookup_asn_error", asn=asn, error=str(e))
            return {
                "asn": None,
                "country": None,
                "registry": None,
                "description": None,
                "date_allocated": None,
            }

    async def get_asn_prefixes(self, asn: str) -> list:
        """
        Get list of IP prefixes announced by an ASN.

        Args:
            asn: Autonomous System Number (e.g., "AS15169" or "15169").

        Returns:
            List of CIDR blocks announced by the ASN.
        """
        try:
            # Normalize ASN format
            asn_number = asn.upper().replace("AS", "")

            logger.debug("get_asn_prefixes_start", asn=asn_number)

            query = f"AS{asn_number}.asn.cymru.com"

            # Query TXT record for prefix information
            answers = await self.resolver.resolve(query, "TXT")

            if not answers:
                logger.warning("get_asn_prefixes_no_result", asn=asn_number)
                return []

            prefixes = []
            response = str(answers[0]).strip('"')

            # Parse response - contains CIDR in second position typically
            parts = [p.strip() for p in response.split("|")]

            if len(parts) >= 2:
                cidr_block = parts[1]
                if cidr_block and cidr_block != "NA":
                    prefixes.append(cidr_block)

            logger.debug(
                "get_asn_prefixes_success",
                asn=asn_number,
                prefix_count=len(prefixes),
            )
            return prefixes

        except dns.asyncresolver.NXDOMAIN:
            logger.info("get_asn_prefixes_not_found", asn=asn)
            return []
        except (dns.asyncresolver.Timeout, dns.asyncresolver.LifetimeTimeout):
            logger.warning("get_asn_prefixes_timeout", asn=asn)
            return []
        except Exception as e:
            logger.exception("get_asn_prefixes_error", asn=asn, error=str(e))
            return []

    @staticmethod
    def _reverse_ip(ip: str) -> str:
        """
        Reverse an IP address for DNS query format.

        Args:
            ip: IPv4 address.

        Returns:
            Reversed IP address octets.
        """
        parts = ip.split(".")
        return ".".join(reversed(parts))
