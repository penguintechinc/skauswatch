import os
from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class LogReceiverConfig:
    opensearch_url: str = field(
        default_factory=lambda: os.getenv("OPENSEARCH_URL", "http://localhost:9200")
    )
    # S3-compatible storage — empty endpoint = AWS S3, set for MinIO/GCS S3 interop/Cloudflare R2/etc.
    s3_endpoint_url: str | None = field(
        default_factory=lambda: os.getenv("S3_ENDPOINT_URL") or None
    )
    s3_region: str = field(
        default_factory=lambda: os.getenv("S3_REGION", "us-east-1")
    )
    s3_access_key: str = field(
        default_factory=lambda: os.getenv("S3_ACCESS_KEY", "")
    )
    s3_secret_key: str = field(
        default_factory=lambda: os.getenv("S3_SECRET_KEY", "")
    )
    s3_siem_bucket: str = field(
        default_factory=lambda: os.getenv("S3_SIEM_BUCKET", "skauswatch-siem-logs")
    )
    redis_url: str = field(
        default_factory=lambda: os.getenv("REDIS_URL", "redis://localhost:6379")
    )
    log_retention_days: int = field(
        default_factory=lambda: int(os.getenv("LOG_RETENTION_DAYS", "90"))
    )
    http_port: int = field(
        default_factory=lambda: int(os.getenv("HTTP_PORT", "5010"))
    )
    syslog_udp_port: int = field(
        default_factory=lambda: int(os.getenv("SYSLOG_UDP_PORT", "514"))
    )

    def __post_init__(self) -> None:
        if not 1 <= self.log_retention_days <= 400:
            raise ValueError(
                f"log_retention_days must be 1–400, got {self.log_retention_days}"
            )
