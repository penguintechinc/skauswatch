"""
SkausWatch Manager Service Configuration

Quart-based configuration with Pydantic validation.
Supports environment variables and YAML configuration files.
"""

import os
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, validator


class DatabaseConfig(BaseModel):
    """Database configuration with PyDAL-compatible URI."""

    type: str = Field(default="postgres", description="Database type")
    host: str = Field(default="postgres", description="Database host")
    port: int = Field(default=5432, description="Database port")
    name: str = Field(default="skauswatch", description="Database name")
    user: str = Field(default="skauswatch", description="Database user")
    password: str = Field(default="", description="Database password")
    pool_size: int = Field(default=10, ge=1, le=100)
    migrate: bool = Field(default=True)

    @property
    def uri(self) -> str:
        """Build PyDAL-compatible database URI."""
        type_map = {"postgresql": "postgres", "mysql": "mysql", "sqlite": "sqlite"}
        db_type = type_map.get(self.type, self.type)

        if db_type == "sqlite":
            return f"sqlite://{self.name}.db"

        return f"{db_type}://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class RedisConfig(BaseModel):
    """Redis configuration with Streams and ACL support."""

    url: str = Field(default="redis://redis:6379/0")
    password: Optional[str] = None
    key_prefix: str = Field(
        default="skauswatch", description="Key prefix for namespacing"
    )
    max_connections: int = Field(default=20, ge=1, le=100)

    # Redis Streams configuration
    streams_enabled: bool = Field(default=True)
    consumer_group_prefix: str = Field(default="manager")

    @property
    def full_url(self) -> str:
        """Build Redis URL with password if provided."""
        if self.password and "://:@" not in self.url:
            # Insert password into URL
            if "://" in self.url:
                protocol, rest = self.url.split("://", 1)
                return f"{protocol}://:{self.password}@{rest}"
        return self.url


class AuthConfig(BaseModel):
    """Authentication configuration."""

    secret_key: str = Field(default="change-me-in-production")
    jwt_secret: str = Field(default="change-me-jwt-secret")
    jwt_algorithm: str = Field(default="HS256")
    access_token_expires_minutes: int = Field(default=30, ge=1)
    refresh_token_expires_days: int = Field(default=7, ge=1)
    password_min_length: int = Field(default=8, ge=4)
    max_login_attempts: int = Field(default=5, ge=1)
    lockout_duration_minutes: int = Field(default=15, ge=1)
    mfa_enabled: bool = Field(default=False)

    @property
    def access_token_expires(self) -> timedelta:
        return timedelta(minutes=self.access_token_expires_minutes)

    @property
    def refresh_token_expires(self) -> timedelta:
        return timedelta(days=self.refresh_token_expires_days)


class GRPCConfig(BaseModel):
    """gRPC server configuration."""

    enabled: bool = Field(default=True)
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=50051)
    max_workers: int = Field(default=10, ge=1)
    max_message_length: int = Field(default=4 * 1024 * 1024)  # 4MB

    # PKI Server gRPC client
    pki_server_address: str = Field(default="pki-server:50052")


class AIConfig(BaseModel):
    """AI provider configuration for alert review."""

    enabled: bool = Field(default=True)
    default_provider: str = Field(default="ollama")

    # Ollama configuration (supports remote)
    ollama_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3")
    ollama_timeout: int = Field(default=120, ge=10)

    # Anthropic (Claude) configuration
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = Field(default="claude-3-sonnet-20240229")

    # OpenAI configuration
    openai_api_key: Optional[str] = None
    openai_model: str = Field(default="gpt-4-turbo")

    # Analysis settings
    max_events_per_analysis: int = Field(default=50, ge=1, le=200)
    analysis_timeout: int = Field(default=60, ge=10)


class ThreatIntelConfig(BaseModel):
    """Threat intelligence configuration."""

    enabled: bool = Field(default=True)

    # Free sources
    dns_blacklist_enabled: bool = Field(default=True)
    ip_blacklist_enabled: bool = Field(default=True)

    # AlienVault OTX
    otx_enabled: bool = Field(default=False)
    otx_api_key: Optional[str] = None

    # VirusTotal
    virustotal_enabled: bool = Field(default=False)
    virustotal_api_key: Optional[str] = None

    # STIX/TAXII
    taxii_enabled: bool = Field(default=False)
    taxii_servers: List[Dict[str, Any]] = Field(default_factory=list)

    # Cache settings
    ioc_cache_ttl_hours: int = Field(default=1, ge=1)
    feed_update_interval_minutes: int = Field(default=30, ge=5)

    # Research feature settings
    research_enabled: bool = Field(default=True)
    whois_timeout: int = Field(default=10, ge=1)
    dns_timeout: int = Field(default=5, ge=1)
    asn_timeout: int = Field(default=5, ge=1)
    shodan_enabled: bool = Field(default=False)
    shodan_api_key: Optional[str] = None
    maltego_enabled: bool = Field(default=False)
    maltego_trx_server: Optional[str] = None


class OpenSearchConfig(BaseModel):
    """OpenSearch/KillKrill configuration."""

    # If KILLKRILL_SERVER_API_URL is set, use KillKrill's cluster
    killkrill_url: Optional[str] = None

    # Embedded OpenSearch (used when killkrill_url is empty)
    opensearch_url: str = Field(default="http://opensearch:9200")
    opensearch_user: Optional[str] = None
    opensearch_password: Optional[str] = None

    index_prefix: str = Field(default="skauswatch")

    @property
    def is_killkrill_mode(self) -> bool:
        """Check if using KillKrill's OpenSearch cluster."""
        return bool(self.killkrill_url)

    @property
    def effective_url(self) -> str:
        """Get the effective OpenSearch URL."""
        return self.killkrill_url or self.opensearch_url


class APIConfig(BaseModel):
    """REST API configuration."""

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=5000)
    debug: bool = Field(default=False)
    cors_enabled: bool = Field(default=True)
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])
    docs_enabled: bool = Field(default=True)
    rate_limit_enabled: bool = Field(default=True)
    rate_limit_per_minute: int = Field(default=60, ge=1)


class S3ScanConfig(BaseModel):
    """S3 bucket scanning configuration."""

    enabled: bool = Field(default=True, description="Enable S3 scanning")
    max_file_size_mb: int = Field(
        default=100, ge=1, le=500, description="Maximum file size in MB"
    )
    max_concurrent_jobs: int = Field(
        default=5, ge=1, le=20, description="Maximum concurrent scan jobs"
    )
    scannable_types: List[str] = Field(
        default_factory=lambda: [
            "application/pdf",
            "application/msword",
            "application/vnd.openxmlformats-officedocument.*",
            "application/vnd.ms-*",
            "application/x-executable",
            "application/x-dosexec",
            "application/x-msdos-program",
            "application/zip",
            "application/x-rar-compressed",
            "application/x-7z-compressed",
        ],
        description="Scannable MIME types",
    )
    skip_large_files: bool = Field(
        default=True, description="Skip files exceeding max_file_size_mb"
    )
    rescan_after_hours: int = Field(
        default=24, ge=1, description="Hours before rescanning files"
    )
    credential_encryption_key: str = Field(
        default="change-me", description="Encryption key for S3 credentials"
    )
    yara_rules_path: Optional[str] = Field(
        default=None, description="Path to YARA rules file"
    )
    auto_create_ti_indicators: bool = Field(
        default=True, description="Auto-create threat intelligence indicators"
    )
    sandbox_enabled: bool = Field(default=False, description="Enable sandbox analysis")
    sandbox_api_url: Optional[str] = Field(default=None, description="Sandbox API URL")
    sandbox_api_key: Optional[str] = Field(default=None, description="Sandbox API key")
    sandbox_risk_threshold: float = Field(
        default=0.7, ge=0.0, le=1.0, description="Risk threshold for sandbox results"
    )


class SIEMConfig(BaseModel):
    """SIEM / log pipeline configuration."""

    enabled: bool = Field(default=True, description="Enable SIEM log pipeline")
    opensearch_url: str = Field(
        default="http://opensearch:9200", description="OpenSearch endpoint for SIEM logs"
    )
    log_receiver_url: str = Field(
        default="http://log-receiver:5010", description="Log receiver service URL"
    )
    retention_days: int = Field(
        default=90, ge=1, le=400, description="Log retention in days (1–400)"
    )
    free_tier_user_cap: int = Field(
        default=5, ge=1, description="Maximum users on free tier"
    )
    exempt_domains: List[str] = Field(
        default_factory=lambda: ["skauswatch.penguintech.cloud", "skauswatch.app"],
        description="Domains exempt from free-tier user cap and SSO license requirement",
    )


class ManagerConfig(BaseModel):
    """Main Manager service configuration."""

    # Service info
    service_name: str = Field(default="skauswatch-manager")
    environment: str = Field(default="production")
    log_level: str = Field(default="INFO")

    # Sub-configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    grpc: GRPCConfig = Field(default_factory=GRPCConfig)
    ai: AIConfig = Field(default_factory=AIConfig)
    threat_intel: ThreatIntelConfig = Field(default_factory=ThreatIntelConfig)
    opensearch: OpenSearchConfig = Field(default_factory=OpenSearchConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    s3_scan: S3ScanConfig = Field(default_factory=S3ScanConfig)
    siem: SIEMConfig = Field(default_factory=SIEMConfig)

    class Config:
        env_prefix = "SKAUSWATCH_"


def _build_s3_scan_config() -> S3ScanConfig:
    """Build S3ScanConfig, only setting scannable_types if env var is provided."""
    config_kwargs = {
        "enabled": os.getenv("S3_SCAN_ENABLED", "true").lower() == "true",
        "max_file_size_mb": int(os.getenv("S3_SCAN_MAX_FILE_SIZE_MB", "100")),
        "max_concurrent_jobs": int(os.getenv("S3_SCAN_MAX_CONCURRENT_JOBS", "5")),
        "skip_large_files": os.getenv("S3_SCAN_SKIP_LARGE_FILES", "true").lower()
        == "true",
        "rescan_after_hours": int(os.getenv("S3_SCAN_RESCAN_HOURS", "24")),
        "credential_encryption_key": os.getenv("S3_CRED_ENCRYPTION_KEY", "change-me"),
        "yara_rules_path": os.getenv("S3_SCAN_YARA_RULES_PATH"),
        "auto_create_ti_indicators": os.getenv("S3_SCAN_AUTO_TI", "true").lower()
        == "true",
        "sandbox_enabled": os.getenv("S3_SANDBOX_ENABLED", "false").lower() == "true",
        "sandbox_api_url": os.getenv("S3_SANDBOX_API_URL"),
        "sandbox_api_key": os.getenv("S3_SANDBOX_API_KEY"),
        "sandbox_risk_threshold": float(os.getenv("S3_SANDBOX_RISK_THRESHOLD", "0.7")),
    }

    # Only set scannable_types if explicitly provided, otherwise use default
    s3_scan_types = os.getenv("S3_SCAN_TYPES")
    if s3_scan_types:
        config_kwargs["scannable_types"] = [
            t.strip() for t in s3_scan_types.split(",") if t.strip()
        ]

    return S3ScanConfig(**config_kwargs)


def load_config() -> ManagerConfig:
    """Load configuration from environment variables."""
    return ManagerConfig(
        service_name=os.getenv("SERVICE_NAME", "skauswatch-manager"),
        environment=os.getenv("QUART_ENV", "production"),
        log_level=os.getenv("LOG_LEVEL", "INFO"),
        database=DatabaseConfig(
            type=os.getenv("DB_TYPE", "postgres"),
            host=os.getenv("DB_HOST", "postgres"),
            port=int(os.getenv("DB_PORT", "5432")),
            name=os.getenv("DB_NAME", "skauswatch"),
            user=os.getenv("DB_USER", "skauswatch"),
            password=os.getenv("DB_PASS", os.getenv("DB_PASSWORD", "")),
            pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        ),
        redis=RedisConfig(
            url=os.getenv("REDIS_URL", "redis://redis:6379/0"),
            password=os.getenv("REDIS_PASSWORD"),
            key_prefix=os.getenv("REDIS_KEY_PREFIX", "skauswatch"),
        ),
        auth=AuthConfig(
            secret_key=os.getenv("SECRET_KEY", "change-me-in-production"),
            jwt_secret=os.getenv("JWT_SECRET_KEY", "change-me-jwt-secret"),
        ),
        grpc=GRPCConfig(
            enabled=os.getenv("GRPC_ENABLED", "true").lower() == "true",
            port=int(os.getenv("GRPC_PORT", "50051")),
            pki_server_address=os.getenv("PKI_GRPC_ADDR", "pki-server:50052"),
        ),
        ai=AIConfig(
            enabled=os.getenv("AI_ENABLED", "true").lower() == "true",
            ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434"),
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY"),
            openai_api_key=os.getenv("OPENAI_API_KEY"),
        ),
        threat_intel=ThreatIntelConfig(
            otx_api_key=os.getenv("OTX_API_KEY"),
            virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
            research_enabled=os.getenv("RESEARCH_ENABLED", "true").lower() == "true",
            whois_timeout=int(os.getenv("WHOIS_TIMEOUT", "10")),
            dns_timeout=int(os.getenv("DNS_TIMEOUT", "5")),
            asn_timeout=int(os.getenv("ASN_TIMEOUT", "5")),
            shodan_enabled=os.getenv("SHODAN_ENABLED", "false").lower() == "true",
            shodan_api_key=os.getenv("SHODAN_API_KEY"),
            maltego_enabled=os.getenv("MALTEGO_ENABLED", "false").lower() == "true",
            maltego_trx_server=os.getenv("MALTEGO_TRX_SERVER"),
        ),
        opensearch=OpenSearchConfig(
            killkrill_url=os.getenv("KILLKRILL_SERVER_API_URL"),
            opensearch_url=os.getenv("OPENSEARCH_URL", "http://opensearch:9200"),
        ),
        api=APIConfig(
            debug=os.getenv("QUART_DEBUG", "false").lower() == "true",
            port=int(os.getenv("API_PORT", "5000")),
        ),
        s3_scan=_build_s3_scan_config(),
        siem=SIEMConfig(
            enabled=os.getenv("SIEM_ENABLED", "true").lower() == "true",
            opensearch_url=os.getenv("OPENSEARCH_URL", "http://opensearch:9200"),
            log_receiver_url=os.getenv("LOG_RECEIVER_URL", "http://log-receiver:5010"),
            retention_days=int(os.getenv("LOG_RETENTION_DAYS", "90")),
        ),
    )
