import asyncio
from dataclasses import dataclass
from typing import Dict, List, Optional

import dns.asyncresolver
import dns.resolver
import structlog

logger = structlog.get_logger()


@dataclass
class DnsResult:
    """DNS lookup result containing all record types."""
    a_records: List[str]
    aaaa_records: List[str]
    mx_records: List[str]
    ns_records: List[str]
    txt_records: List[str]
    cname_record: Optional[str]
    soa_record: Optional[str]

    def to_dict(self) -> Dict[str, any]:
        """Convert to dictionary format."""
        return {
            'A': self.a_records,
            'AAAA': self.aaaa_records,
            'MX': self.mx_records,
            'NS': self.ns_records,
            'TXT': self.txt_records,
            'CNAME': self.cname_record,
            'SOA': self.soa_record,
        }


class DNSClient:
    """Async DNS client for querying DNS records."""

    def __init__(self, timeout: int = 5) -> None:
        """Initialize DNS client with timeout.

        Args:
            timeout: Query timeout in seconds.
        """
        self.timeout = timeout
        self.resolver = dns.asyncresolver.Resolver()
        self.resolver.timeout = timeout

    async def lookup(self, domain: str) -> DnsResult:
        """Query multiple DNS record types for a domain.

        Args:
            domain: Domain name to query.

        Returns:
            DnsResult with all queried record types.
        """
        logger.info("dns_lookup_started", domain=domain, timeout=self.timeout)

        result = DnsResult(
            a_records=[],
            aaaa_records=[],
            mx_records=[],
            ns_records=[],
            txt_records=[],
            cname_record=None,
            soa_record=None,
        )

        # Query all record types concurrently
        tasks = [
            self._query_a_records(domain),
            self._query_aaaa_records(domain),
            self._query_mx_records(domain),
            self._query_ns_records(domain),
            self._query_txt_records(domain),
            self._query_cname_record(domain),
            self._query_soa_record(domain),
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        result.a_records = results[0]
        result.aaaa_records = results[1]
        result.mx_records = results[2]
        result.ns_records = results[3]
        result.txt_records = results[4]
        result.cname_record = results[5]
        result.soa_record = results[6]

        logger.info(
            "dns_lookup_completed",
            domain=domain,
            a_count=len(result.a_records),
            aaaa_count=len(result.aaaa_records),
            mx_count=len(result.mx_records),
        )

        return result

    async def _query_a_records(self, domain: str) -> List[str]:
        """Query A records."""
        try:
            response = await self.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in response]
        except Exception as e:
            logger.warning("a_records_query_failed", domain=domain, error=str(e))
            return []

    async def _query_aaaa_records(self, domain: str) -> List[str]:
        """Query AAAA records."""
        try:
            response = await self.resolver.resolve(domain, 'AAAA')
            return [str(rdata) for rdata in response]
        except Exception as e:
            logger.warning("aaaa_records_query_failed", domain=domain, error=str(e))
            return []

    async def _query_mx_records(self, domain: str) -> List[str]:
        """Query MX records."""
        try:
            response = await self.resolver.resolve(domain, 'MX')
            return [str(rdata.exchange) for rdata in response]
        except Exception as e:
            logger.warning("mx_records_query_failed", domain=domain, error=str(e))
            return []

    async def _query_ns_records(self, domain: str) -> List[str]:
        """Query NS records."""
        try:
            response = await self.resolver.resolve(domain, 'NS')
            return [str(rdata) for rdata in response]
        except Exception as e:
            logger.warning("ns_records_query_failed", domain=domain, error=str(e))
            return []

    async def _query_txt_records(self, domain: str) -> List[str]:
        """Query TXT records."""
        try:
            response = await self.resolver.resolve(domain, 'TXT')
            return [str(rdata) for rdata in response]
        except Exception as e:
            logger.warning("txt_records_query_failed", domain=domain, error=str(e))
            return []

    async def _query_cname_record(self, domain: str) -> Optional[str]:
        """Query CNAME record."""
        try:
            response = await self.resolver.resolve(domain, 'CNAME')
            return str(response[0])
        except Exception as e:
            logger.warning("cname_record_query_failed", domain=domain, error=str(e))
            return None

    async def _query_soa_record(self, domain: str) -> Optional[str]:
        """Query SOA record."""
        try:
            response = await self.resolver.resolve(domain, 'SOA')
            return str(response[0])
        except Exception as e:
            logger.warning("soa_record_query_failed", domain=domain, error=str(e))
            return None

    async def reverse_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup (PTR record) for IP address.

        Args:
            ip: IP address to reverse lookup.

        Returns:
            Hostname or empty string if lookup fails.
        """
        logger.info("reverse_lookup_started", ip=ip, timeout=self.timeout)

        try:
            response = await self.resolver.resolve_address(ip, raise_on_no_answer=False)
            hostname = str(response[0]).rstrip('.')
            logger.info("reverse_lookup_completed", ip=ip, hostname=hostname)
            return hostname
        except Exception as e:
            logger.warning("reverse_lookup_failed", ip=ip, error=str(e))
            return ""
