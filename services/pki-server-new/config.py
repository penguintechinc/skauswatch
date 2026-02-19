"""PKI Server configuration using Pydantic."""

import os
from typing import Optional, List
from pydantic import BaseModel, Field, field_validator


class DatabaseConfig(BaseModel):
    """Database configuration."""

    url: str = Field(
        default_factory=lambda: os.getenv(
            "DATABASE_URL", "postgresql://skauswatch:password@localhost:5432/skauswatch"
        )
    )
    pool_size: int = Field(default=10)
    pool_recycle: int = Field(default=3600)


class RedisConfig(BaseModel):
    """Redis configuration."""

    url: str = Field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379/0")
    )
    key_prefix: str = Field(
        default_factory=lambda: os.getenv("REDIS_KEY_PREFIX", "skauswatch")
    )


class X509CAConfig(BaseModel):
    """X.509 Certificate Authority configuration."""

    ca_key_path: str = Field(
        default_factory=lambda: os.getenv("CA_KEY_PATH", "/etc/pki/ca.key")
    )
    ca_cert_path: str = Field(
        default_factory=lambda: os.getenv("CA_CERT_PATH", "/etc/pki/ca.crt")
    )
    ca_key_password: Optional[str] = Field(
        default_factory=lambda: os.getenv("CA_KEY_PASSWORD")
    )
    default_validity_days: int = Field(
        default_factory=lambda: int(os.getenv("DEFAULT_VALIDITY_DAYS", "365"))
    )
    max_validity_days: int = Field(
        default_factory=lambda: int(os.getenv("MAX_VALIDITY_DAYS", "825"))
    )
    default_key_algorithm: str = Field(
        default_factory=lambda: os.getenv("DEFAULT_KEY_ALGORITHM", "RSA")
    )
    default_key_size: int = Field(
        default_factory=lambda: int(os.getenv("DEFAULT_KEY_SIZE", "4096"))
    )
    crl_validity_days: int = Field(
        default_factory=lambda: int(os.getenv("CRL_VALIDITY_DAYS", "7"))
    )
    ocsp_responder_url: Optional[str] = Field(
        default_factory=lambda: os.getenv("OCSP_RESPONDER_URL")
    )
    crl_distribution_points: List[str] = Field(default_factory=list)

    @field_validator("default_key_algorithm")
    @classmethod
    def validate_key_algorithm(cls, v: str) -> str:
        allowed = ["RSA", "ECDSA", "ED25519"]
        if v.upper() not in allowed:
            raise ValueError(f"Key algorithm must be one of: {allowed}")
        return v.upper()


class SSHCAConfig(BaseModel):
    """SSH Certificate Authority configuration."""

    ca_key_path: str = Field(
        default_factory=lambda: os.getenv("SSH_CA_KEY_PATH", "/etc/pki/ssh_ca")
    )
    ca_public_key_path: str = Field(
        default_factory=lambda: os.getenv(
            "SSH_CA_PUBLIC_KEY_PATH", "/etc/pki/ssh_ca.pub"
        )
    )
    ca_key_password: Optional[str] = Field(
        default_factory=lambda: os.getenv("SSH_CA_KEY_PASSWORD")
    )
    default_validity_seconds: int = Field(
        default_factory=lambda: int(os.getenv("SSH_DEFAULT_VALIDITY_SECONDS", "86400"))
    )
    max_validity_seconds: int = Field(
        default_factory=lambda: int(os.getenv("SSH_MAX_VALIDITY_SECONDS", "604800"))
    )
    default_key_type: str = Field(
        default_factory=lambda: os.getenv("SSH_DEFAULT_KEY_TYPE", "ed25519")
    )
    allowed_principals: List[str] = Field(default_factory=list)
    krl_path: str = Field(
        default_factory=lambda: os.getenv("KRL_PATH", "/etc/pki/revoked_keys")
    )

    @field_validator("default_key_type")
    @classmethod
    def validate_key_type(cls, v: str) -> str:
        allowed = ["rsa", "ecdsa", "ed25519"]
        if v.lower() not in allowed:
            raise ValueError(f"Key type must be one of: {allowed}")
        return v.lower()


class GRPCConfig(BaseModel):
    """gRPC server configuration."""

    port: int = Field(default_factory=lambda: int(os.getenv("GRPC_PORT", "50052")))
    max_workers: int = Field(
        default_factory=lambda: int(os.getenv("GRPC_MAX_WORKERS", "10"))
    )
    max_message_length: int = Field(
        default_factory=lambda: int(os.getenv("GRPC_MAX_MESSAGE_LENGTH", "4194304"))
    )


class APIConfig(BaseModel):
    """REST API configuration."""

    host: str = Field(default_factory=lambda: os.getenv("API_HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.getenv("API_PORT", "8001")))
    debug: bool = Field(
        default_factory=lambda: os.getenv("QUART_DEBUG", "false").lower() == "true"
    )


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""

    enabled: bool = Field(
        default_factory=lambda: os.getenv("RATE_LIMIT_ENABLED", "true").lower()
        == "true"
    )
    requests_per_minute: int = Field(
        default_factory=lambda: int(os.getenv("RATE_LIMIT_REQUESTS_PER_MINUTE", "60"))
    )
    burst_size: int = Field(
        default_factory=lambda: int(os.getenv("RATE_LIMIT_BURST_SIZE", "10"))
    )


class AuditConfig(BaseModel):
    """Audit logging configuration."""

    enabled: bool = Field(
        default_factory=lambda: os.getenv("AUDIT_ENABLED", "true").lower() == "true"
    )
    log_to_file: bool = Field(
        default_factory=lambda: os.getenv("AUDIT_LOG_TO_FILE", "false").lower()
        == "true"
    )
    log_path: str = Field(
        default_factory=lambda: os.getenv("AUDIT_LOG_PATH", "/var/log/pki/audit.log")
    )


class ManagerConfig(BaseModel):
    """Manager service connection configuration."""

    grpc_address: str = Field(
        default_factory=lambda: os.getenv("MANAGER_GRPC_ADDR", "manager:50051")
    )
    api_url: str = Field(
        default_factory=lambda: os.getenv("MANAGER_API_URL", "http://manager:5000")
    )


class Settings(BaseModel):
    """Application settings container."""

    app_name: str = "SkausWatch PKI Server"
    version: str = "1.0.0"
    environment: str = Field(
        default_factory=lambda: os.getenv("QUART_ENV", "production")
    )
    secret_key: str = Field(
        default_factory=lambda: os.getenv("SECRET_KEY", "change-me-in-production")
    )

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    x509_ca: X509CAConfig = Field(default_factory=X509CAConfig)
    ssh_ca: SSHCAConfig = Field(default_factory=SSHCAConfig)
    grpc: GRPCConfig = Field(default_factory=GRPCConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    manager: ManagerConfig = Field(default_factory=ManagerConfig)


def get_settings() -> Settings:
    """Get application settings singleton."""
    return Settings()
