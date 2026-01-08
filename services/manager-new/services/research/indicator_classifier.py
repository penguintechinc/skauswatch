import re
from dataclasses import dataclass


@dataclass(slots=True)
class IndicatorClassifier:
    """Classify and validate various security indicator types."""

    # Regex patterns for indicator types
    IPV4_PATTERN = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
        r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    IPV6_PATTERN = re.compile(
        r"^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$"
    )
    DOMAIN_PATTERN = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
    )
    URL_PATTERN = re.compile(
        r"^https?://(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:[/?#].*)?$"
    )
    MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
    SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
    SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
    ASN_PATTERN = re.compile(r"^AS\d+$", re.IGNORECASE)
    EMAIL_PATTERN = re.compile(
        r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~\-]+@"
        r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
    )

    def classify(self, query: str) -> tuple[str, str]:
        """
        Classify a query string into an indicator type.

        Args:
            query: The string to classify

        Returns:
            Tuple of (indicator_type, normalized_value)
            indicator_type: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256, ASN, Email, Unknown
        """
        if not query or not isinstance(query, str):
            return ("Unknown", "")

        query = query.strip()

        if self.is_valid_ipv4(query):
            return ("IPv4", query)
        if self.is_valid_ipv6(query):
            return ("IPv6", query)
        if self.is_valid_url(query):
            return ("URL", query)
        if self.is_valid_md5(query):
            return ("MD5", query.lower())
        if self.is_valid_sha1(query):
            return ("SHA1", query.lower())
        if self.is_valid_sha256(query):
            return ("SHA256", query.lower())
        if self.is_valid_asn(query):
            return ("ASN", query.upper())
        if self.is_valid_email(query):
            return ("Email", query.lower())
        if self.is_valid_domain(query):
            return ("Domain", query.lower())

        return ("Unknown", "")

    def is_valid_ip(self, query: str) -> bool:
        """Check if query is valid IPv4 or IPv6."""
        return self.is_valid_ipv4(query) or self.is_valid_ipv6(query)

    def is_valid_ipv4(self, query: str) -> bool:
        """Check if query is valid IPv4 address."""
        if not isinstance(query, str):
            return False
        return bool(self.IPV4_PATTERN.match(query))

    def is_valid_ipv6(self, query: str) -> bool:
        """Check if query is valid IPv6 address."""
        if not isinstance(query, str):
            return False
        return bool(self.IPV6_PATTERN.match(query))

    def is_valid_domain(self, query: str) -> bool:
        """Check if query is valid domain name."""
        if not isinstance(query, str) or len(query) > 253:
            return False
        if query.startswith("http://") or query.startswith("https://"):
            return False
        return bool(self.DOMAIN_PATTERN.match(query))

    def is_valid_url(self, query: str) -> bool:
        """Check if query is valid URL."""
        if not isinstance(query, str):
            return False
        return bool(self.URL_PATTERN.match(query))

    def is_valid_hash(self, query: str) -> bool:
        """Check if query is valid MD5, SHA1, or SHA256 hash."""
        return self.is_valid_md5(query) or self.is_valid_sha1(query) or self.is_valid_sha256(query)

    def is_valid_md5(self, query: str) -> bool:
        """Check if query is valid MD5 hash."""
        if not isinstance(query, str):
            return False
        return bool(self.MD5_PATTERN.match(query))

    def is_valid_sha1(self, query: str) -> bool:
        """Check if query is valid SHA1 hash."""
        if not isinstance(query, str):
            return False
        return bool(self.SHA1_PATTERN.match(query))

    def is_valid_sha256(self, query: str) -> bool:
        """Check if query is valid SHA256 hash."""
        if not isinstance(query, str):
            return False
        return bool(self.SHA256_PATTERN.match(query))

    def is_valid_asn(self, query: str) -> bool:
        """Check if query is valid ASN (AS####)."""
        if not isinstance(query, str):
            return False
        return bool(self.ASN_PATTERN.match(query))

    def is_valid_email(self, query: str) -> bool:
        """Check if query is valid email address."""
        if not isinstance(query, str) or len(query) > 254:
            return False
        return bool(self.EMAIL_PATTERN.match(query))
