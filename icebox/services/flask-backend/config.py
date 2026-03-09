"""
IceBox Flask Backend Configuration

Quart-based configuration with Pydantic v2 validation.
Supports environment variables for all settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional

from pydantic import BaseModel, Field


class DatabaseConfig(BaseModel):
    """Database configuration with PyDAL-compatible URI."""

    type: str = Field(default_factory=lambda: os.getenv("DB_TYPE", "postgresql"))
    host: str = Field(default_factory=lambda: os.getenv("DB_HOST", "postgres"))
    port: int = Field(default_factory=lambda: int(os.getenv("DB_PORT", "5432")))
    name: str = Field(default_factory=lambda: os.getenv("DB_NAME", "skauswatch"))
    user: str = Field(default_factory=lambda: os.getenv("DB_USER", "icebox"))
    password: str = Field(default_factory=lambda: os.getenv("DB_PASS", ""))
    pool_size: int = Field(
        default_factory=lambda: int(os.getenv("DB_POOL_SIZE", "10"))
    )

    @property
    def uri(self) -> str:
        """Build PyDAL-compatible database URI."""
        type_map = {
            "postgresql": "postgres",
            "postgres": "postgres",
            "mysql": "mysql",
            "sqlite": "sqlite",
        }
        db_type = type_map.get(self.type, self.type)
        if db_type == "sqlite":
            return f"sqlite://{self.name}.db"
        return f"{db_type}://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

    @property
    def alembic_url(self) -> str:
        """Build SQLAlchemy-compatible URL for Alembic migrations."""
        type_map = {
            "postgresql": "postgresql+psycopg2",
            "postgres": "postgresql+psycopg2",
            "mysql": "mysql+pymysql",
            "sqlite": "sqlite",
        }
        db_type = type_map.get(self.type, self.type)
        if db_type == "sqlite":
            return f"sqlite:///{self.name}.db"
        return f"{db_type}://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class RedisConfig(BaseModel):
    """Redis configuration for Streams and caching."""

    url: str = Field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://redis:6379/0")
    )
    password: Optional[str] = Field(
        default_factory=lambda: os.getenv("REDIS_PASSWORD")
    )
    key_prefix: str = Field(default="icebox")
    max_connections: int = Field(default=20)

    @property
    def full_url(self) -> str:
        """Build Redis URL with password if provided."""
        if self.password and "://:@" not in self.url and "://" in self.url:
            protocol, rest = self.url.split("://", 1)
            return f"{protocol}://:{self.password}@{rest}"
        return self.url


class AuthConfig(BaseModel):
    """Authentication and JWT configuration."""

    secret_key: str = Field(
        default_factory=lambda: os.getenv(
            "SECRET_KEY", "change-me-icebox-secret-key"
        )
    )
    jwt_secret: str = Field(
        default_factory=lambda: os.getenv(
            "JWT_SECRET", "change-me-icebox-jwt-secret"
        )
    )
    jwt_algorithm: str = Field(default="HS256")
    access_token_expires_minutes: int = Field(default=60)
    jit_token_max_duration_seconds: int = Field(
        default_factory=lambda: int(
            os.getenv("JIT_TOKEN_MAX_DURATION_SECONDS", "3600")
        )
    )
    jit_revocation_check_interval_seconds: int = Field(default=60)


class EncryptionConfig(BaseModel):
    """Envelope encryption configuration."""

    # Master Encryption Key — base64-encoded 32 bytes
    mek: str = Field(
        default_factory=lambda: os.getenv("ICEBOX_MEK", "")
    )
    # Optional cloud KMS reference for MEK wrapping
    aws_kms_key_id: Optional[str] = Field(
        default_factory=lambda: os.getenv("ICEBOX_AWS_KMS_KEY_ID")
    )
    azure_kv_key_id: Optional[str] = Field(
        default_factory=lambda: os.getenv("ICEBOX_AZURE_KV_KEY_ID")
    )
    gcp_kms_key_name: Optional[str] = Field(
        default_factory=lambda: os.getenv("ICEBOX_GCP_KMS_KEY_NAME")
    )


class LicensingConfig(BaseModel):
    """IceBox licensing configuration."""

    license_server_url: str = Field(
        default_factory=lambda: os.getenv(
            "LICENSE_SERVER_URL", "https://license.penguintech.io"
        )
    )
    # Auto-bypass domains — no license key required
    auto_bypass_domains: List[str] = Field(
        default=[
            "*.nest.localhost.local",
            "*.nest.penguintech.cloud",
            "*.nestdata.app",
        ]
    )
    validation_interval_seconds: int = Field(default=21600)  # 6 hours


class IceBoxConfig(BaseModel):
    """Root configuration for IceBox flask-backend."""

    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    redis: RedisConfig = Field(default_factory=RedisConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    encryption: EncryptionConfig = Field(default_factory=EncryptionConfig)
    licensing: LicensingConfig = Field(default_factory=LicensingConfig)

    # Internal service URLs (used by shim proxies in SkausWatch core)
    pki_server_url: str = Field(
        default_factory=lambda: os.getenv(
            "ICEBOX_PKI_URL", "http://icebox-pki:8081"
        )
    )
    ssh_ca_url: str = Field(
        default_factory=lambda: os.getenv(
            "ICEBOX_SSH_CA_URL", "http://icebox-ssh-ca:8082"
        )
    )

    log_level: str = Field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "info").upper()
    )
    host: str = Field(default_factory=lambda: os.getenv("HOST", "0.0.0.0"))
    port: int = Field(default_factory=lambda: int(os.getenv("PORT", "8080")))
    debug: bool = Field(
        default_factory=lambda: os.getenv("DEBUG", "false").lower() == "true"
    )


_config: Optional[IceBoxConfig] = None


def get_config() -> IceBoxConfig:
    """Return singleton config instance."""
    global _config
    if _config is None:
        _config = IceBoxConfig()
    return _config
