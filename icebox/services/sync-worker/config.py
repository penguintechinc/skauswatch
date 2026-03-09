"""Sync-worker configuration — loaded from environment variables."""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass(slots=True)
class RedisConfig:
    """Redis connection and Streams configuration."""

    host: str = field(default_factory=lambda: os.getenv("REDIS_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(os.getenv("REDIS_PORT", "6379")))
    password: str | None = field(default_factory=lambda: os.getenv("REDIS_PASSWORD"))
    db: int = field(default_factory=lambda: int(os.getenv("REDIS_DB", "0")))
    stream_prefix: str = "icebox:sync"
    consumer_group: str = "sync-worker"
    consumer_name: str = field(
        default_factory=lambda: os.getenv("WORKER_ID", "worker-1")
    )
    # xreadgroup BLOCK timeout in milliseconds
    block_ms: int = 5000
    # max messages per xreadgroup call
    batch_size: int = 10

    @property
    def url(self) -> str:
        """Redis URL for aioredis."""
        if self.password:
            return f"redis://:{self.password}@{self.host}:{self.port}/{self.db}"
        return f"redis://{self.host}:{self.port}/{self.db}"

    def stream_name(self, provider: str) -> str:
        """Return the Redis stream key for a given provider."""
        return f"{self.stream_prefix}:{provider}"


@dataclass(slots=True)
class DatabaseConfig:
    """PyDAL database connection configuration."""

    db_type: str = field(
        default_factory=lambda: os.getenv("DB_TYPE", "postgresql")
    )
    host: str = field(default_factory=lambda: os.getenv("DB_HOST", "localhost"))
    port: int = field(
        default_factory=lambda: int(os.getenv("DB_PORT", "5432"))
    )
    name: str = field(default_factory=lambda: os.getenv("DB_NAME", "icebox"))
    user: str = field(default_factory=lambda: os.getenv("DB_USER", "icebox"))
    password: str = field(default_factory=lambda: os.getenv("DB_PASS", ""))
    pool_size: int = field(
        default_factory=lambda: int(os.getenv("DB_POOL_SIZE", "2"))
    )
    max_retries: int = field(
        default_factory=lambda: int(os.getenv("DB_MAX_RETRIES", "10"))
    )
    retry_delay: float = field(
        default_factory=lambda: float(os.getenv("DB_RETRY_DELAY", "5"))
    )

    @property
    def uri(self) -> str:
        """PyDAL connection URI."""
        return (
            f"{self.db_type}://{self.user}:{self.password}"
            f"@{self.host}:{self.port}/{self.name}"
        )


@dataclass(slots=True)
class EncryptionConfig:
    """MEK (Master Encryption Key) version map."""

    mek_versions: dict[int, str] = field(default_factory=dict)
    current_version: int = 1

    def __post_init__(self) -> None:
        """Load all ICEBOX_MEK_V{N} variables from the environment."""
        v = 1
        while True:
            mek = os.getenv(f"ICEBOX_MEK_V{v}")
            if not mek:
                break
            self.mek_versions[v] = mek
            self.current_version = v
            v += 1


@dataclass(slots=True)
class SyncWorkerConfig:
    """Top-level sync-worker configuration."""

    redis: RedisConfig = field(default_factory=RedisConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    encryption: EncryptionConfig = field(default_factory=EncryptionConfig)
    log_level: str = field(
        default_factory=lambda: os.getenv("LOG_LEVEL", "INFO").upper()
    )
    # Providers whose streams this worker consumes
    providers: list[str] = field(
        default_factory=lambda: [
            "aws", "azure", "gcp", "oracle", "kubernetes"
        ]
    )
    # Seconds between full pull-sync polls for cloud→icebox direction
    pull_poll_interval: int = field(
        default_factory=lambda: int(os.getenv("PULL_POLL_INTERVAL", "300"))
    )


def load_config() -> SyncWorkerConfig:
    """Load and return sync-worker configuration from environment."""
    return SyncWorkerConfig()
