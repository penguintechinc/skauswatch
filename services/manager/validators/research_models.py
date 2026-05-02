"""
Pydantic models for research feature.

Defines enums, request models, result models, and response schemas
for threat research and indicator lookup functionality.
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class IndicatorType(str, Enum):
    """Enumeration of supported indicator types."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    ASN = "asn"
    EMAIL = "email"


# Request Models
class ResearchLookupRequest(BaseModel):
    """Request model for research lookup."""

    query: str = Field(..., min_length=1, max_length=500)
    indicator_type: Optional[IndicatorType] = None
    include_threat_intel: bool = True
    include_shodan: bool = False
    include_maltego: bool = False


class WhoisRequest(BaseModel):
    """Request model for WHOIS lookup."""

    query: str = Field(..., min_length=1)
    indicator_type: Optional[IndicatorType] = None


class DnsRequest(BaseModel):
    """Request model for DNS lookup."""

    query: str = Field(..., min_length=1)
    indicator_type: Optional[IndicatorType] = None


class AsnRequest(BaseModel):
    """Request model for ASN lookup."""

    query: str = Field(..., min_length=1)
    indicator_type: Optional[IndicatorType] = None


# Result Models
class WhoisResult(BaseModel):
    """Result model for WHOIS lookup."""

    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    nameservers: list[str] = Field(default_factory=list)
    registrant: Optional[str] = None
    raw_data: dict = Field(default_factory=dict)


class DnsResult(BaseModel):
    """Result model for DNS lookup."""

    a_records: list[str] = Field(default_factory=list)
    aaaa_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)
    cname_records: list[str] = Field(default_factory=list)
    soa_record: Optional[str] = None


class AsnResult(BaseModel):
    """Result model for ASN lookup."""

    asn: Optional[str] = None
    organization: Optional[str] = None
    country: Optional[str] = None
    network: Optional[str] = None
    registry: Optional[str] = None
    description: Optional[str] = None


class ShodanResult(BaseModel):
    """Result model for Shodan lookup."""

    ip: Optional[str] = None
    ports: list[int] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    vulns: list[str] = Field(default_factory=list)
    ssl_cert: dict = Field(default_factory=dict)
    last_update: Optional[datetime] = None


class MaltegoResult(BaseModel):
    """Result model for Maltego lookup."""

    related_domains: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    social_profiles: list[str] = Field(default_factory=list)
    shared_hosting: list[str] = Field(default_factory=list)
    infrastructure: dict = Field(default_factory=dict)


class ThreatIntelResult(BaseModel):
    """Result model for threat intelligence lookup."""

    virustotal_malicious: int = 0
    virustotal_total: int = 0
    otx_pulses: int = 0
    dns_blacklist_hits: list[str] = Field(default_factory=list)
    local_ioc_match: bool = False


class ResearchSummary(BaseModel):
    """Summary model for research results."""

    indicator_type: IndicatorType
    risk_score: int = Field(..., ge=0, le=100)
    key_findings: list[str] = Field(default_factory=list)


class ResearchLookupResponse(BaseModel):
    """Response model for research lookup."""

    query: str
    indicator_type: IndicatorType
    timestamp: datetime
    summary: ResearchSummary
    whois: Optional[WhoisResult] = None
    dns: Optional[DnsResult] = None
    asn: Optional[AsnResult] = None
    shodan: Optional[ShodanResult] = None
    maltego: Optional[MaltegoResult] = None
    threat_intel: Optional[ThreatIntelResult] = None
    processing_time_ms: int
