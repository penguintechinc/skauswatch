"""
Pydantic models for request/response validation.

All REST and gRPC inputs are validated using these models.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, validator


# ============================================
# Enums
# ============================================


class UserRole(str, Enum):
    ADMIN = "admin"
    MAINTAINER = "maintainer"
    VIEWER = "viewer"


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AlertStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    ESCALATED = "escalated"


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    FILE = "file"
    REGISTRY = "registry"


class ThreatLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class ApprovalType(str, Enum):
    CERTIFICATE = "certificate"
    USER = "user"
    SERVICE = "service"
    CONFIGURATION = "configuration"


class EDRAgentStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISCONNECTED = "disconnected"


# ============================================
# Authentication Models
# ============================================


class LoginRequest(BaseModel):
    """Login request model."""

    email: EmailStr
    password: str = Field(..., min_length=1)

    @validator("password")
    def password_not_empty(cls, v):
        if not v.strip():
            raise ValueError("Password cannot be empty")
        return v


class RegisterRequest(BaseModel):
    """User registration request model."""

    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: str = Field(default="", max_length=255)

    @validator("password")
    def password_complexity(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        return v


class TokenResponse(BaseModel):
    """Token response model."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int


class RefreshTokenRequest(BaseModel):
    """Refresh token request model."""

    refresh_token: str = Field(..., min_length=1)


class UserResponse(BaseModel):
    """User response model."""

    id: int
    email: str
    full_name: Optional[str]
    role: UserRole
    is_active: bool
    mfa_enabled: bool = False
    created_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================
# Alert Models
# ============================================


class AlertCreateRequest(BaseModel):
    """Alert creation request model."""

    title: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., max_length=4000)
    severity: AlertSeverity
    source: str = Field(..., min_length=1, max_length=100)
    indicators: List[str] = Field(default_factory=list, max_items=100)

    @validator("indicators", each_item=True)
    def validate_indicator(cls, v):
        if len(v) > 500:
            raise ValueError("Indicator too long")
        return v.strip()


class AlertUpdateRequest(BaseModel):
    """Alert update request model."""

    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=4000)
    severity: Optional[AlertSeverity] = None
    status: Optional[AlertStatus] = None
    assigned_to: Optional[int] = None
    resolution_notes: Optional[str] = Field(None, max_length=2000)


class AlertResponse(BaseModel):
    """Alert response model."""

    id: int
    title: str
    description: Optional[str]
    severity: AlertSeverity
    status: AlertStatus
    source: Optional[str]
    indicators: List[str] = []
    ai_review: Optional[Dict[str, Any]] = None
    assigned_to: Optional[int]
    resolved_at: Optional[datetime]
    resolution_notes: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class AlertSearchRequest(BaseModel):
    """Alert search request model."""

    query: Optional[str] = Field(None, max_length=500)
    severity: Optional[List[AlertSeverity]] = None
    status: Optional[List[AlertStatus]] = None
    source: Optional[str] = None
    assigned_to: Optional[int] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)


# ============================================
# IOC (Indicator of Compromise) Models
# ============================================


class IOCCreateRequest(BaseModel):
    """IOC creation request model."""

    indicator_type: IndicatorType
    value: str = Field(..., min_length=1, max_length=1000)
    threat_level: ThreatLevel = Field(default=ThreatLevel.MEDIUM)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = Field(..., max_length=100)
    tags: List[str] = Field(default_factory=list, max_items=20)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    expires_at: Optional[datetime] = None

    @validator("value")
    def validate_value(cls, v, values):
        v = v.strip()
        indicator_type = values.get("indicator_type")

        if indicator_type == IndicatorType.IP:
            # Basic IP validation
            parts = v.split(".")
            if len(parts) == 4:
                try:
                    if all(0 <= int(p) <= 255 for p in parts):
                        return v
                except ValueError:
                    pass
            # Could be IPv6 - allow it through
            if ":" in v:
                return v
            raise ValueError("Invalid IP address format")

        if indicator_type == IndicatorType.EMAIL:
            if "@" not in v or "." not in v:
                raise ValueError("Invalid email format")

        return v

    @validator("tags", each_item=True)
    def validate_tags(cls, v):
        if len(v) > 50:
            raise ValueError("Tag too long (max 50 chars)")
        return v.strip().lower()


class IOCResponse(BaseModel):
    """IOC response model."""

    id: int
    indicator_type: IndicatorType
    value: str
    threat_level: ThreatLevel
    confidence: float
    source: str
    tags: List[str] = []
    metadata: Dict[str, Any] = {}
    expires_at: Optional[datetime]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class IOCSearchRequest(BaseModel):
    """IOC search request model."""

    query: Optional[str] = Field(None, max_length=500)
    indicator_type: Optional[List[IndicatorType]] = None
    threat_level: Optional[List[ThreatLevel]] = None
    source: Optional[str] = None
    tags: Optional[List[str]] = None
    confidence_min: Optional[float] = Field(None, ge=0.0, le=1.0)
    include_expired: bool = False
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=50, ge=1, le=500)


class IOCBulkCreateRequest(BaseModel):
    """Bulk IOC creation request model."""

    indicators: List[IOCCreateRequest] = Field(..., max_items=1000)


# ============================================
# Approval Models
# ============================================


class ApprovalCreateRequest(BaseModel):
    """Approval request creation model."""

    request_type: ApprovalType
    resource_id: str = Field(..., max_length=128)
    resource_type: str = Field(..., max_length=50)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    required_approvals: int = Field(default=1, ge=1, le=10)
    expires_hours: int = Field(default=24, ge=1, le=168)


class ApprovalDecisionRequest(BaseModel):
    """Approval decision request model."""

    approved: bool
    reason: Optional[str] = Field(None, max_length=1000)


class ApprovalResponse(BaseModel):
    """Approval response model."""

    id: int
    request_type: ApprovalType
    resource_id: str
    resource_type: str
    requester_id: int
    status: ApprovalStatus
    required_approvals: int
    current_approvals: int
    approvers: List[Dict[str, Any]] = []
    approval_history: List[Dict[str, Any]] = []
    expires_at: Optional[datetime]
    completed_at: Optional[datetime]
    metadata: Dict[str, Any] = {}
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


# ============================================
# EDR Models
# ============================================


class EDRAgentRegisterRequest(BaseModel):
    """EDR agent registration request model."""

    agent_id: str = Field(..., min_length=1, max_length=128)
    hostname: str = Field(..., max_length=255)
    ip_address: str = Field(..., max_length=45)
    os_type: str = Field(..., max_length=50)
    os_version: str = Field(default="", max_length=100)
    agent_version: str = Field(..., max_length=32)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EDRHeartbeatRequest(BaseModel):
    """EDR agent heartbeat request model."""

    agent_id: str = Field(..., min_length=1, max_length=128)
    status: EDRAgentStatus = Field(default=EDRAgentStatus.ACTIVE)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EDREventRequest(BaseModel):
    """EDR event report request model."""

    agent_id: str = Field(..., min_length=1, max_length=128)
    event_type: str = Field(..., min_length=1, max_length=64)
    severity: Optional[ThreatLevel] = None
    process_name: Optional[str] = Field(None, max_length=255)
    process_path: Optional[str] = None
    process_hash: Optional[str] = Field(None, max_length=128)
    parent_process: Optional[str] = Field(None, max_length=255)
    command_line: Optional[str] = None
    network_connections: Optional[List[Dict[str, Any]]] = None
    file_operations: Optional[List[Dict[str, Any]]] = None
    registry_operations: Optional[List[Dict[str, Any]]] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class EDRAgentResponse(BaseModel):
    """EDR agent response model."""

    id: int
    agent_id: str
    hostname: Optional[str]
    ip_address: Optional[str]
    os_type: Optional[str]
    os_version: Optional[str]
    agent_version: Optional[str]
    status: EDRAgentStatus
    last_heartbeat: Optional[datetime]
    metadata: Dict[str, Any] = {}
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True


class EDREventResponse(BaseModel):
    """EDR event response model."""

    id: int
    agent_id: str
    event_type: str
    severity: Optional[ThreatLevel]
    process_name: Optional[str]
    process_path: Optional[str]
    process_hash: Optional[str]
    parent_process: Optional[str]
    command_line: Optional[str]
    details: Dict[str, Any] = {}
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================
# AI Analysis Models
# ============================================


class AIAnalysisRequest(BaseModel):
    """AI analysis request model."""

    alert_id: Optional[int] = None
    events: Optional[List[Dict[str, Any]]] = Field(None, max_items=50)
    text: Optional[str] = Field(None, max_length=10000)
    analysis_type: str = Field(default="alert_review")
    priority: int = Field(default=1, ge=1, le=5)
    provider: Optional[str] = None

    @validator("events", "text", pre=True)
    def at_least_one_input(cls, v, values):
        return v


class AIAnalysisResponse(BaseModel):
    """AI analysis response model."""

    job_id: str
    status: str
    analysis_type: str
    submitted_at: datetime


class AIAnalysisResult(BaseModel):
    """AI analysis result model."""

    job_id: str
    status: str
    analysis_type: str
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    threat_level: Optional[ThreatLevel] = None
    recommendations: List[str] = []
    iocs_found: List[Dict[str, Any]] = []
    key_findings: List[str] = []
    processing_time: Optional[float] = None
    provider_used: Optional[str] = None
    timestamp: datetime


# ============================================
# Common Models
# ============================================


class PaginatedResponse(BaseModel):
    """Generic paginated response model."""

    items: List[Any]
    total: int
    page: int
    per_page: int
    pages: int


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str
    version: str
    database: str
    redis: str
    grpc: str
    timestamp: datetime


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str
    detail: Optional[str] = None
    status_code: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============================================
# Research Models
# ============================================


class ResearchIndicatorType(str, Enum):
    """Research indicator types."""

    IP = "ip"
    DOMAIN = "domain"
    ASN = "asn"
    EMAIL = "email"
    HASH = "hash"
    URL = "url"


class ResearchLookupRequest(BaseModel):
    """Research lookup request model."""

    query: str = Field(..., min_length=1, max_length=500)
    indicator_type: Optional[ResearchIndicatorType] = None
    include_whois: bool = True
    include_dns: bool = True
    include_asn: bool = True
    include_shodan: bool = False
    include_maltego: bool = False
    timeout: int = Field(default=30, ge=5, le=120)


class ResearchLookupResponse(BaseModel):
    """Research lookup response model."""

    query: str
    indicator_type: Optional[str]
    whois: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    asn: Optional[Dict[str, Any]] = None
    shodan: Optional[Dict[str, Any]] = None
    maltego: Optional[Dict[str, Any]] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class WhoisLookupRequest(BaseModel):
    """WHOIS lookup request model."""

    query: str = Field(..., min_length=1, max_length=500)
    indicator_type: ResearchIndicatorType = Field(..., description="domain or ip")


class WhoisResultModel(BaseModel):
    """WHOIS result model."""

    success: bool
    data: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class DnsLookupRequest(BaseModel):
    """DNS lookup request model."""

    query: str = Field(..., min_length=1, max_length=500)
    indicator_type: ResearchIndicatorType = Field(
        default=ResearchIndicatorType.DOMAIN,
        description="domain only"
    )


class DnsResultModel(BaseModel):
    """DNS result model."""

    a_records: List[str] = Field(default_factory=list)
    aaaa_records: List[str] = Field(default_factory=list)
    mx_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    txt_records: List[str] = Field(default_factory=list)
    cname_record: Optional[str] = None
    soa_record: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class AsnLookupRequest(BaseModel):
    """ASN lookup request model."""

    query: str = Field(..., min_length=1, max_length=500)
    indicator_type: ResearchIndicatorType = Field(..., description="ip or asn")


class AsnResultModel(BaseModel):
    """ASN result model."""

    asn: Optional[str] = None
    asn_cidr: Optional[str] = None
    asn_country: Optional[str] = None
    asn_registry: Optional[str] = None
    asn_description: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ShodanResultModel(BaseModel):
    """Shodan result model."""

    success: bool = False
    ports: List[int] = Field(default_factory=list)
    services: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    ssl_cert: Optional[Dict[str, Any]] = None
    last_update: Optional[str] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class MaltegoResultModel(BaseModel):
    """Maltego result model."""

    success: bool = False
    related_domains: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    social_profiles: List[Dict[str, Any]] = Field(default_factory=list)
    shared_hosting: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ResearchConfigResponse(BaseModel):
    """Research configuration response model."""

    research_enabled: bool
    whois_enabled: bool
    dns_enabled: bool
    asn_enabled: bool
    shodan_enabled: bool
    maltego_enabled: bool
    default_timeout: int
    whois_timeout: int
    dns_timeout: int
    asn_timeout: int
    shodan_timeout: int
    maltego_timeout: int
