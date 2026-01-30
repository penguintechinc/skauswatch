"""Configuration management for worker-scanner service.

This module provides environment-based configuration using dataclasses with performance
optimizations (__slots__). All settings are loaded from environment variables with sensible
defaults, using python-dotenv for .env file support.
"""

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv


def _parse_bool(value: str) -> bool:
    """Parse string value to boolean.

    Args:
        value: String value to parse

    Returns:
        Boolean value
    """
    if not value:
        return False
    return value.lower() not in ("false", "0", "no", "off", "")


@dataclass(slots=True)
class FlaskConfig:
    """Flask configuration settings."""

    env: str
    debug: bool
    secret_key: str
    port: int


@dataclass(slots=True)
class JWTConfig:
    """JWT authentication configuration."""

    secret_key: str
    algorithm: str


@dataclass(slots=True)
class DatabaseConfig:
    """Database configuration settings."""

    type: str
    host: str
    port: int
    name: str
    user: str
    password: str

    def get_pydal_uri(self) -> str:
        """Generate PyDAL connection URI based on DB_TYPE.

        Returns:
            PyDAL connection string in format: driver://user:password@host:port/database

        Raises:
            ValueError: If unsupported database type is specified
        """
        db_type = self.type.lower()

        if db_type == "postgres":
            return (
                f"postgres://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
            )
        elif db_type == "mysql":
            return (
                f"mysql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
            )
        elif db_type == "mariadb":
            return (
                f"mysql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
            )
        elif db_type == "sqlite":
            # SQLite uses file path, not network connection
            return f"sqlite://{self.name}"
        else:
            raise ValueError(
                f"Unsupported database type: {db_type}. "
                f"Supported types: postgres, mysql, mariadb, sqlite"
            )


@dataclass(slots=True)
class RedisConfig:
    """Redis and Celery configuration."""

    url: str
    celery_broker_url: str
    celery_result_backend: str


@dataclass(slots=True)
class ScannerToggleConfig:
    """Scanner enable/disable flags."""

    nuclei_enabled: bool
    zap_enabled: bool
    openvas_enabled: bool


@dataclass(slots=True)
class ScannerConfig:
    """External scanner service configuration."""

    zap_url: str
    zap_api_key: str
    openvas_host: str
    openvas_port: int
    openvas_user: str
    openvas_password: str


@dataclass(slots=True)
class NucleiConfig:
    """Nuclei scanner specific configuration."""

    binary_path: str
    templates_path: str
    rate_limit: int
    concurrency: int


@dataclass(slots=True)
class LoggingConfig:
    """Logging configuration."""

    level: str
    format: str


@dataclass(slots=True)
class Settings:
    """Main settings class containing all configuration groups.

    All values are loaded from environment variables with sensible defaults.
    Dataclass uses __slots__ for performance optimization (30-50% memory reduction).
    """

    flask: FlaskConfig
    jwt: JWTConfig
    database: DatabaseConfig
    redis: RedisConfig
    scanner_toggles: ScannerToggleConfig
    scanner: ScannerConfig
    nuclei: NucleiConfig
    logging: LoggingConfig

    def __init__(self) -> None:
        """Initialize Settings by loading environment variables.

        Loads .env file if it exists, then reads all configuration values from
        os.environ with appropriate defaults and type conversions.
        """
        # Load .env file if it exists
        load_dotenv()

        # Flask Configuration
        self.flask = FlaskConfig(
            env=os.environ.get("FLASK_ENV", "development"),
            debug=_parse_bool(os.environ.get("FLASK_DEBUG", "false")),
            secret_key=os.environ.get("SECRET_KEY", "change-me-in-development"),
            port=int(os.environ.get("WORKER_SCANNER_PORT", "5001")),
        )

        # JWT Configuration
        self.jwt = JWTConfig(
            secret_key=os.environ.get("JWT_SECRET_KEY", "change-me-shared-secret"),
            algorithm=os.environ.get("JWT_ALGORITHM", "HS256"),
        )

        # Database Configuration
        self.database = DatabaseConfig(
            type=os.environ.get("DB_TYPE", "postgres"),
            host=os.environ.get("DB_HOST", "localhost"),
            port=int(os.environ.get("DB_PORT", "5432")),
            name=os.environ.get("DB_NAME", "skauswatch"),
            user=os.environ.get("DB_USER", "skauswatch"),
            password=os.environ.get("DB_PASSWORD", "changeme"),
        )

        # Redis Configuration
        self.redis = RedisConfig(
            url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
            celery_broker_url=os.environ.get(
                "CELERY_BROKER_URL", "redis://localhost:6379/0"
            ),
            celery_result_backend=os.environ.get(
                "CELERY_RESULT_BACKEND", "redis://localhost:6379/1"
            ),
        )

        # Scanner Toggle Configuration
        self.scanner_toggles = ScannerToggleConfig(
            nuclei_enabled=_parse_bool(
                os.environ.get("SCANNER_NUCLEI_ENABLED", "true")
            ),
            zap_enabled=_parse_bool(os.environ.get("SCANNER_ZAP_ENABLED", "true")),
            openvas_enabled=_parse_bool(
                os.environ.get("SCANNER_OPENVAS_ENABLED", "true")
            ),
        )

        # Scanner Configuration
        self.scanner = ScannerConfig(
            zap_url=os.environ.get("SCANNER_ZAP_URL", "http://localhost:8080"),
            zap_api_key=os.environ.get("SCANNER_ZAP_API_KEY", ""),
            openvas_host=os.environ.get("SCANNER_OPENVAS_HOST", "localhost"),
            openvas_port=int(os.environ.get("SCANNER_OPENVAS_PORT", "9390")),
            openvas_user=os.environ.get("SCANNER_OPENVAS_USER", "admin"),
            openvas_password=os.environ.get("SCANNER_OPENVAS_PASSWORD", "changeme"),
        )

        # Nuclei Configuration
        self.nuclei = NucleiConfig(
            binary_path=os.environ.get(
                "NUCLEI_BINARY_PATH", "/usr/local/bin/nuclei"
            ),
            templates_path=os.environ.get(
                "NUCLEI_TEMPLATES_PATH", "/root/nuclei-templates"
            ),
            rate_limit=int(os.environ.get("NUCLEI_RATE_LIMIT", "150")),
            concurrency=int(os.environ.get("NUCLEI_CONCURRENCY", "25")),
        )

        # Logging Configuration
        self.logging = LoggingConfig(
            level=os.environ.get("LOG_LEVEL", "INFO"),
            format=os.environ.get("LOG_FORMAT", "json"),
        )


# Module-level singleton for easy import and usage across the application
settings = Settings()
