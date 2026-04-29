"""Shared data models for SkausWatch AAA Monitor Service."""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class AlertStatus(str, Enum):
    """Alert lifecycle status."""

    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class AIProvider(str, Enum):
    """Supported AI provider types."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"


class Severity(str, Enum):
    """Event severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatLevel(str, Enum):
    """Threat intelligence threat levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class EventType(str, Enum):
    """Types of security events."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SYSTEM_CALL = "system_call"
    NETWORK = "network"
    NETWORK_EVENT = "network_event"
    FILE_ACCESS = "file_access"
    PROCESS = "process"
    ACCOUNTING = "accounting"
    ACCESS = "access"
    SECURITY_VIOLATION = "security_violation"
    SYSTEM_EVENT = "system_event"
    CONTAINER_EVENT = "container_event"
    APPLICATION_EVENT = "application_event"


class LogSource(str, Enum):
    """Log source types."""

    AUDITD = "auditd"
    FILE = "file"
    KUBERNETES = "kubernetes"
    LXC_LXD = "lxc_lxd"
    SYSTEM = "system"


@dataclass
class BaseEvent:
    """Base class for all security events."""

    source: LogSource
    event_type: EventType
    severity: Severity
    message: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    host: str = ""
    user: Optional[str] = None
    process: Optional[str] = None
    pid: Optional[int] = None
    enrichments: Dict[str, Any] = field(default_factory=dict)
    threat_matches: List[Any] = field(default_factory=list)
    ai_analysis: Optional[Dict[str, Any]] = None


@dataclass
class IOC:
    """Indicator of Compromise."""

    type: str
    value: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    description: str = ""
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: float = 0.0
    tags: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    kill_chain_phases: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    expiration: Optional[datetime] = None
    source_feed: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatMatch:
    """Result of matching an event against threat intelligence."""

    event_id: str
    ioc_id: str
    matched_value: str
    field_name: str
    confidence: float
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    matched_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatFeed:
    """Threat intelligence feed configuration."""

    name: str
    url: str
    feed_type: str = "taxii"
    enabled: bool = True
    update_frequency: int = 3600
    credentials: Optional[Dict[str, str]] = None
    headers: Optional[Dict[str, str]] = None
    certificate_verification: bool = True
    proxy_url: Optional[str] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    last_updated: Optional[datetime] = None
    ioc_count: int = 0
    status: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuthenticationEvent(BaseEvent):
    """Authentication event (login, logout, credential check)."""

    username: Optional[str] = None
    source_ip: Optional[str] = None
    success: bool = True
    method: Optional[str] = None


@dataclass
class AuthorizationEvent(BaseEvent):
    """Authorization event (access control decision)."""

    username: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    namespace: Optional[str] = None


@dataclass
class SystemCallEvent(BaseEvent):
    """System call event."""

    syscall: str = ""
    result: Optional[str] = None
    arguments: List[str] = field(default_factory=list)
    return_code: Optional[int] = None


@dataclass
class NetworkEvent(BaseEvent):
    """Network connection/activity event."""

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None


@dataclass
class FileAccessEvent(BaseEvent):
    """File access event."""

    path: Optional[str] = None
    operation: Optional[str] = None
    result: Optional[str] = None


@dataclass
class ProcessEvent(BaseEvent):
    """Process creation/termination event."""

    command: Optional[str] = None
    parent_pid: Optional[int] = None
    executable: Optional[str] = None


@dataclass
class ContainerEvent(BaseEvent):
    """Container lifecycle event."""

    container_name: Optional[str] = None
    container_id: Optional[str] = None
    action: Optional[str] = None
    exit_code: Optional[int] = None


# Pydantic API response models


class Alert(BaseModel):
    """Alert model for API responses."""

    id: str
    title: str
    severity: str
    status: str
    created_at: datetime


class AlertSearchRequest(BaseModel):
    """Request model for alert search."""

    query: str = ""
    severity: Optional[str] = None
    limit: int = 50
    offset: int = 0


class AlertSearchResponse(BaseModel):
    """Response model for alert search results."""

    alerts: List[Alert] = []
    total: int = 0
    limit: int = 50
    offset: int = 0


class DashboardMetrics(BaseModel):
    """Dashboard metrics model for API responses."""

    total_events: int = 0
    events_per_hour: float = 0.0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    threats_detected: int = 0
    ai_analyses: int = 0


class EventSearchRequest(BaseModel):
    """Request model for event search."""

    query: str = ""
    event_type: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    limit: int = 50
    offset: int = 0


class EventSearchResponse(BaseModel):
    """Response model for event search results."""

    events: List[Dict[str, Any]] = []
    total: int = 0
    limit: int = 50
    offset: int = 0
