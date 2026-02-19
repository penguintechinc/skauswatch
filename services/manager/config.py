"""
Configuration management for SkausWatch Manager Service

This module handles loading and validation of configuration settings
from files, environment variables, and defaults.
"""

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)


@dataclass
class DatabaseConfig:
    """Database configuration"""

    uri: str = "sqlite://storage.db"
    migrate: bool = True
    fake_migrate: bool = False
    init_default_data: bool = True
    pool_size: int = 10
    connection_timeout: int = 30


@dataclass
class AuthConfig:
    """Authentication configuration"""

    session_timeout: int = 3600  # seconds
    remember_me_timeout: int = 86400 * 30  # 30 days
    password_min_length: int = 8
    password_complexity: bool = True
    max_login_attempts: int = 5
    lockout_duration: int = 900  # 15 minutes
    mfa_required: bool = False
    mfa_issuer: str = "SkausWatch"
    backup_codes_count: int = 10
    jwt_secret: Optional[str] = None
    jwt_expiration: int = 3600
    jwt_algorithm: str = "HS256"


@dataclass
class SecurityConfig:
    """Security configuration"""

    secret_key: str = ""
    secure_cookies: bool = True
    csrf_protection: bool = True
    csrf_timeout: int = 3600
    rate_limit_enabled: bool = True
    rate_limit_requests_per_minute: int = 60
    rate_limit_burst: int = 100
    content_security_policy: Dict[str, str] = field(
        default_factory=lambda: {
            "default-src": "'self'",
            "script-src": "'self' 'unsafe-inline'",
            "style-src": "'self' 'unsafe-inline'",
            "img-src": "'self' data:",
            "font-src": "'self'",
            "connect-src": "'self'",
            "frame-ancestors": "'none'",
        }
    )
    trusted_proxies: List[str] = field(default_factory=list)
    audit_log_retention_days: int = 365


@dataclass
class CacheConfig:
    """Cache configuration"""

    default_expiration: int = 300  # 5 minutes
    redis_url: Optional[str] = None
    memory_cache_size: int = 1000


@dataclass
class LoggingConfig:
    """Logging configuration"""

    level: str = "INFO"
    format: str = "json"
    file: Optional[str] = None
    max_size: int = 100 * 1024 * 1024  # 100MB
    backup_count: int = 5
    structured: bool = True


@dataclass
class HealthCheckConfig:
    """Health check configuration"""

    enabled: bool = True
    interval: int = 30  # seconds
    timeout: int = 10  # seconds
    failure_threshold: int = 3
    success_threshold: int = 1
    external_checks: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class UIConfig:
    """UI configuration"""

    theme: str = "light"
    language: str = "en"
    items_per_page: int = 25
    enable_tooltips: bool = True
    enable_animations: bool = True
    accessibility_mode: bool = False


@dataclass
class NotificationConfig:
    """Notification configuration"""

    enabled: bool = True
    email_backend: str = "smtp"
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    from_email: str = "noreply@skauswatch.local"
    webhook_url: Optional[str] = None
    slack_token: Optional[str] = None


@dataclass
class APIConfig:
    """API configuration"""

    enabled: bool = True
    version: str = "v1"
    docs_enabled: bool = True
    cors_enabled: bool = True
    cors_origins: List[str] = field(default_factory=lambda: ["*"])
    cors_methods: List[str] = field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE"]
    )
    cors_headers: List[str] = field(default_factory=lambda: ["*"])


@dataclass
class CertificateConfig:
    """Certificate management configuration"""

    default_validity_days: int = 365
    auto_renewal_threshold_days: int = 30
    max_validity_days: int = 3650  # 10 years
    require_approval: bool = True
    allowed_key_algorithms: List[str] = field(default_factory=lambda: ["rsa", "ec"])
    default_key_algorithm: str = "rsa"
    default_key_size: int = 2048
    ca_cert_path: Optional[str] = None
    ca_key_path: Optional[str] = None


class ManagerConfig:
    """Main configuration class for SkausWatch Manager Service"""

    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration

        Args:
            config_path: Optional path to configuration file
        """
        self.config_path = config_path

        # Initialize with defaults
        self.database = DatabaseConfig()
        self.auth = AuthConfig()
        self.security = SecurityConfig()
        self.cache = CacheConfig()
        self.logging = LoggingConfig()
        self.health_check = HealthCheckConfig()
        self.ui = UIConfig()
        self.notification = NotificationConfig()
        self.api = APIConfig()
        self.certificate = CertificateConfig()

        # Load configuration from file if provided
        if config_path:
            self.load_from_file(config_path)

        # Override with environment variables
        self.load_from_env()

        # Validate configuration
        self.validate()

        # Generate secrets if needed
        self._ensure_secrets()

    def load_from_file(self, config_path: str) -> None:
        """Load configuration from YAML file

        Args:
            config_path: Path to configuration file
        """
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                logger.warning(f"Configuration file not found: {config_path}")
                return

            with open(config_file, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f) or {}

            # Update configuration sections
            self._update_from_dict(config_data)

            logger.info(f"Configuration loaded from: {config_path}")

        except Exception as e:
            logger.error(f"Failed to load configuration from {config_path}: {e}")
            raise

    def load_from_env(self) -> None:
        """Load configuration from environment variables"""
        # Database configuration
        if os.getenv("SKAUSWATCH_DB_URI"):
            self.database.uri = os.getenv("SKAUSWATCH_DB_URI")
        if os.getenv("SKAUSWATCH_DB_MIGRATE"):
            self.database.migrate = os.getenv("SKAUSWATCH_DB_MIGRATE").lower() == "true"

        # Security configuration
        if os.getenv("SKAUSWATCH_SECRET_KEY"):
            self.security.secret_key = os.getenv("SKAUSWATCH_SECRET_KEY")
        if os.getenv("SKAUSWATCH_SECURE_COOKIES"):
            self.security.secure_cookies = (
                os.getenv("SKAUSWATCH_SECURE_COOKIES").lower() == "true"
            )

        # Authentication configuration
        if os.getenv("SKAUSWATCH_JWT_SECRET"):
            self.auth.jwt_secret = os.getenv("SKAUSWATCH_JWT_SECRET")
        if os.getenv("SKAUSWATCH_SESSION_TIMEOUT"):
            self.auth.session_timeout = int(os.getenv("SKAUSWATCH_SESSION_TIMEOUT"))

        # Cache configuration
        if os.getenv("SKAUSWATCH_REDIS_URL"):
            self.cache.redis_url = os.getenv("SKAUSWATCH_REDIS_URL")

        # Logging configuration
        if os.getenv("SKAUSWATCH_LOG_LEVEL"):
            self.logging.level = os.getenv("SKAUSWATCH_LOG_LEVEL").upper()
        if os.getenv("SKAUSWATCH_LOG_FILE"):
            self.logging.file = os.getenv("SKAUSWATCH_LOG_FILE")

        # Notification configuration
        if os.getenv("SKAUSWATCH_SMTP_HOST"):
            self.notification.smtp_host = os.getenv("SKAUSWATCH_SMTP_HOST")
        if os.getenv("SKAUSWATCH_SMTP_PORT"):
            self.notification.smtp_port = int(os.getenv("SKAUSWATCH_SMTP_PORT"))
        if os.getenv("SKAUSWATCH_SMTP_USERNAME"):
            self.notification.smtp_username = os.getenv("SKAUSWATCH_SMTP_USERNAME")
        if os.getenv("SKAUSWATCH_SMTP_PASSWORD"):
            self.notification.smtp_password = os.getenv("SKAUSWATCH_SMTP_PASSWORD")

    def _update_from_dict(self, config_data: Dict[str, Any]) -> None:
        """Update configuration from dictionary

        Args:
            config_data: Configuration dictionary
        """
        # Database section
        if "database" in config_data:
            db_config = config_data["database"]
            self.database = DatabaseConfig(**{**self.database.__dict__, **db_config})

        # Auth section
        if "auth" in config_data:
            auth_config = config_data["auth"]
            self.auth = AuthConfig(**{**self.auth.__dict__, **auth_config})

        # Security section
        if "security" in config_data:
            security_config = config_data["security"]
            self.security = SecurityConfig(
                **{**self.security.__dict__, **security_config}
            )

        # Cache section
        if "cache" in config_data:
            cache_config = config_data["cache"]
            self.cache = CacheConfig(**{**self.cache.__dict__, **cache_config})

        # Logging section
        if "logging" in config_data:
            logging_config = config_data["logging"]
            self.logging = LoggingConfig(**{**self.logging.__dict__, **logging_config})

        # Health check section
        if "health_check" in config_data:
            health_config = config_data["health_check"]
            self.health_check = HealthCheckConfig(
                **{**self.health_check.__dict__, **health_config}
            )

        # UI section
        if "ui" in config_data:
            ui_config = config_data["ui"]
            self.ui = UIConfig(**{**self.ui.__dict__, **ui_config})

        # Notification section
        if "notification" in config_data:
            notification_config = config_data["notification"]
            self.notification = NotificationConfig(
                **{**self.notification.__dict__, **notification_config}
            )

        # API section
        if "api" in config_data:
            api_config = config_data["api"]
            self.api = APIConfig(**{**self.api.__dict__, **api_config})

        # Certificate section
        if "certificate" in config_data:
            cert_config = config_data["certificate"]
            self.certificate = CertificateConfig(
                **{**self.certificate.__dict__, **cert_config}
            )

    def validate(self) -> None:
        """Validate configuration settings"""
        errors = []

        # Validate database URI
        if not self.database.uri:
            errors.append("Database URI is required")

        # Validate authentication settings
        if self.auth.password_min_length < 4:
            errors.append("Password minimum length must be at least 4")

        if self.auth.session_timeout < 60:
            errors.append("Session timeout must be at least 60 seconds")

        # Validate security settings
        if not self.security.secret_key:
            logger.warning("No secret key configured, will generate random key")

        # Validate certificate settings
        if self.certificate.default_validity_days < 1:
            errors.append("Certificate default validity must be at least 1 day")

        if self.certificate.max_validity_days < self.certificate.default_validity_days:
            errors.append("Certificate max validity must be >= default validity")

        if errors:
            error_msg = "Configuration validation errors:\n" + "\n".join(
                f"- {error}" for error in errors
            )
            logger.error(error_msg)
            raise ValueError(error_msg)

    def _ensure_secrets(self) -> None:
        """Generate secrets if not provided"""
        import secrets
        import string

        if not self.security.secret_key:
            # Generate 64-character secret key
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
            self.security.secret_key = "".join(
                secrets.choice(alphabet) for _ in range(64)
            )
            logger.info("Generated random secret key")

        if not self.auth.jwt_secret:
            # Generate JWT secret
            self.auth.jwt_secret = secrets.token_urlsafe(64)
            logger.info("Generated random JWT secret")

    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary

        Returns:
            Configuration as dictionary
        """
        return {
            "database": self.database.__dict__,
            "auth": self.auth.__dict__,
            "security": {
                k: v
                for k, v in self.security.__dict__.items()
                if not k.endswith("_key") and not k.endswith("_secret")
            },
            "cache": self.cache.__dict__,
            "logging": self.logging.__dict__,
            "health_check": self.health_check.__dict__,
            "ui": self.ui.__dict__,
            "notification": {
                k: v
                for k, v in self.notification.__dict__.items()
                if not k.endswith("_password") and not k.endswith("_token")
            },
            "api": self.api.__dict__,
            "certificate": self.certificate.__dict__,
        }

    def save_to_file(self, file_path: str) -> None:
        """Save configuration to YAML file (excluding secrets)

        Args:
            file_path: Path to save configuration file
        """
        try:
            config_dict = self.to_dict()

            with open(file_path, "w", encoding="utf-8") as f:
                yaml.dump(config_dict, f, default_flow_style=False, indent=2)

            logger.info(f"Configuration saved to: {file_path}")

        except Exception as e:
            logger.error(f"Failed to save configuration to {file_path}: {e}")
            raise
