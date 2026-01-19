"""
Worker configuration using Pydantic BaseModel pattern.

This module defines the configuration schema for S3 scan workers,
including Redis connections, database settings, and scanner parameters.
"""

from typing import Optional

from pydantic import BaseModel, Field


class WorkerConfig(BaseModel):
    """Configuration for S3 scan worker instances.

    Attributes:
        redis_url: Redis connection URL for message queue
        redis_prefix: Prefix for Redis keys
        consumer_group: Redis stream consumer group name
        consumer_name: Unique identifier for this worker instance
        db_type: Database type (postgres, mysql, mariadb, sqlite)
        db_host: Database host address
        db_port: Database port
        db_name: Database name
        db_user: Database username
        db_pass: Database password
        thread_pool_size: Number of worker threads (1-16)
        max_concurrent_tasks: Maximum concurrent scan tasks (1-50)
        max_file_size_mb: Maximum file size for scanning (1-500 MB)
        scan_timeout_sec: Scan operation timeout (30-600 seconds)
        clamd_socket: Path to ClamAV daemon socket
        clamd_timeout: ClamAV operation timeout (seconds)
        yara_enabled: Enable YARA rule scanning
        yara_rules_path: Path to YARA rules directory
        ti_enabled: Enable threat intelligence enrichment
        virustotal_api_key: VirusTotal API key (optional)
        otx_api_key: Alien Vault OTX API key (optional)
        sandbox_enabled: Enable dynamic analysis sandbox
        sandbox_api_url: Sandbox API endpoint URL (optional)
        sandbox_api_key: Sandbox API key (optional)
    """

    # Redis configuration
    redis_url: str = Field(default="redis://redis:6379/0")
    redis_prefix: str = Field(default="skauswatch")
    consumer_group: str = Field(default="s3scan-workers")
    consumer_name: str = Field(
        ..., description="Unique identifier for this worker instance"
    )

    # Database configuration
    db_type: str = Field(default="postgres")
    db_host: str = Field(default="postgres")
    db_port: int = Field(default=5432)
    db_name: str = Field(default="skauswatch")
    db_user: str = Field(default="skauswatch")
    db_pass: str = Field(default="")

    # Worker tuning
    thread_pool_size: int = Field(default=4, ge=1, le=16)
    max_concurrent_tasks: int = Field(default=10, ge=1, le=50)
    max_file_size_mb: int = Field(default=100, ge=1, le=500)
    scan_timeout_sec: int = Field(default=120, ge=30, le=600)

    # ClamAV configuration
    clamd_socket: str = Field(default="/var/run/clamav/clamd.sock")
    clamd_timeout: int = Field(default=60, ge=10)

    # YARA configuration
    yara_enabled: bool = Field(default=False)
    yara_rules_path: str = Field(default="/yara_rules")

    # Threat intelligence configuration
    ti_enabled: bool = Field(default=True)
    virustotal_api_key: Optional[str] = None
    otx_api_key: Optional[str] = None

    # Sandbox configuration
    sandbox_enabled: bool = Field(default=False)
    sandbox_api_url: Optional[str] = None
    sandbox_api_key: Optional[str] = None

    class Config:
        """Pydantic configuration."""

        case_sensitive = False
        env_file = ".env"

    @property
    def db_uri(self) -> str:
        """Generate database connection URI from configuration.

        Returns:
            Database connection URI string formatted for PyDAL.

        Examples:
            postgres://user:pass@localhost:5432/skauswatch
            mysql://user:pass@localhost:3306/skauswatch
        """
        if self.db_pass:
            return (
                f"{self.db_type}://{self.db_user}:{self.db_pass}@"
                f"{self.db_host}:{self.db_port}/{self.db_name}"
            )
        return (
            f"{self.db_type}://{self.db_user}@"
            f"{self.db_host}:{self.db_port}/{self.db_name}"
        )


def load_worker_config() -> WorkerConfig:
    """Load worker configuration from environment variables.

    Configuration is loaded from environment variables with fallback to defaults
    defined in the WorkerConfig class. All environment variables should be
    uppercase with optional SKAUSWATCH_ prefix.

    Environment variables:
        CONSUMER_NAME: Required unique worker identifier
        REDIS_URL: Redis connection URL
        REDIS_PREFIX: Redis key prefix
        CONSUMER_GROUP: Redis consumer group name
        DB_TYPE: Database type (postgres, mysql, mariadb, sqlite)
        DB_HOST: Database hostname
        DB_PORT: Database port
        DB_NAME: Database name
        DB_USER: Database username
        DB_PASS: Database password
        THREAD_POOL_SIZE: Number of worker threads
        MAX_CONCURRENT_TASKS: Maximum concurrent tasks
        MAX_FILE_SIZE_MB: Maximum file size for scanning
        SCAN_TIMEOUT_SEC: Scan operation timeout
        CLAMD_SOCKET: ClamAV daemon socket path
        CLAMD_TIMEOUT: ClamAV operation timeout
        YARA_ENABLED: Enable YARA scanning (true/false)
        YARA_RULES_PATH: Path to YARA rules
        TI_ENABLED: Enable threat intelligence (true/false)
        VIRUSTOTAL_API_KEY: VirusTotal API key
        OTX_API_KEY: Alien Vault OTX API key
        SANDBOX_ENABLED: Enable sandbox analysis (true/false)
        SANDBOX_API_URL: Sandbox API endpoint
        SANDBOX_API_KEY: Sandbox API key

    Returns:
        WorkerConfig: Loaded and validated configuration object.

    Raises:
        ValueError: If required CONSUMER_NAME is not provided.
        pydantic.ValidationError: If configuration values fail validation.

    Examples:
        >>> config = load_worker_config()
        >>> print(config.db_uri)
        >>> print(config.redis_url)
    """
    import os

    return WorkerConfig(
        # Required fields
        consumer_name=os.getenv(
            "CONSUMER_NAME",
            os.getenv("WORKER_NAME", ""),
        ),
        # Redis configuration
        redis_url=os.getenv("REDIS_URL", "redis://redis:6379/0"),
        redis_prefix=os.getenv("REDIS_PREFIX", "skauswatch"),
        consumer_group=os.getenv("CONSUMER_GROUP", "s3scan-workers"),
        # Database configuration
        db_type=os.getenv("DB_TYPE", "postgres"),
        db_host=os.getenv("DB_HOST", "postgres"),
        db_port=int(os.getenv("DB_PORT", "5432")),
        db_name=os.getenv("DB_NAME", "skauswatch"),
        db_user=os.getenv("DB_USER", "skauswatch"),
        db_pass=os.getenv("DB_PASS", ""),
        # Worker tuning
        thread_pool_size=int(os.getenv("THREAD_POOL_SIZE", "4")),
        max_concurrent_tasks=int(os.getenv("MAX_CONCURRENT_TASKS", "10")),
        max_file_size_mb=int(os.getenv("MAX_FILE_SIZE_MB", "100")),
        scan_timeout_sec=int(os.getenv("SCAN_TIMEOUT_SEC", "120")),
        # ClamAV configuration
        clamd_socket=os.getenv("CLAMD_SOCKET", "/var/run/clamav/clamd.sock"),
        clamd_timeout=int(os.getenv("CLAMD_TIMEOUT", "60")),
        # YARA configuration
        yara_enabled=os.getenv("YARA_ENABLED", "false").lower() == "true",
        yara_rules_path=os.getenv("YARA_RULES_PATH", "/yara_rules"),
        # Threat intelligence configuration
        ti_enabled=os.getenv("TI_ENABLED", "true").lower() == "true",
        virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
        otx_api_key=os.getenv("OTX_API_KEY"),
        # Sandbox configuration
        sandbox_enabled=os.getenv("SANDBOX_ENABLED", "false").lower() == "true",
        sandbox_api_url=os.getenv("SANDBOX_API_URL"),
        sandbox_api_key=os.getenv("SANDBOX_API_KEY"),
    )
