"""Configuration management for worker-darwin service.

All settings are loaded from environment variables with sensible defaults.
Dataclass uses __slots__ for performance optimization (30-50% memory reduction).
"""

import os
from dataclasses import dataclass
from typing import Optional

from dotenv import load_dotenv


def _parse_bool(value: str) -> bool:
    """Parse string value to boolean."""
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
class DatabaseConfig:
    """Database configuration settings."""

    type: str
    host: str
    port: int
    name: str
    user: str
    password: str

    def get_pydal_uri(self) -> str:
        """Generate PyDAL connection URI based on DB_TYPE."""
        db_type = self.type.lower()
        if db_type in ("postgres", "postgresql"):
            return f"postgres://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
        elif db_type in ("mysql", "mariadb"):
            return f"mysql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
        elif db_type == "sqlite":
            return f"sqlite://{self.name}"
        else:
            raise ValueError(f"Unsupported database type: {db_type}")


@dataclass(slots=True)
class RedisConfig:
    """Redis and Celery configuration."""

    url: str
    celery_broker_url: str
    celery_result_backend: str


@dataclass(slots=True)
class AIConfig:
    """AI provider configuration."""

    provider: str
    model: str
    anthropic_api_key: Optional[str]
    openai_api_key: Optional[str]
    ollama_url: str
    timeout: int


@dataclass(slots=True)
class LicenseConfig:
    """License server configuration."""

    key: Optional[str]
    server_url: str
    release_mode: bool
    free_tier_user_cap: int
    max_repos_free: int
    max_reviews_per_day: int


@dataclass(slots=True)
class Settings:
    """Main settings class containing all configuration groups.

    All values are loaded from environment variables with sensible defaults.
    Dataclass uses __slots__ for performance optimization.
    """

    flask: FlaskConfig
    database: DatabaseConfig
    redis: RedisConfig
    ai: AIConfig
    license: LicenseConfig

    def __init__(self) -> None:
        """Initialize Settings by loading environment variables."""
        load_dotenv()

        self.flask = FlaskConfig(
            env=os.environ.get("FLASK_ENV", "development"),
            debug=_parse_bool(os.environ.get("FLASK_DEBUG", "false")),
            secret_key=os.environ.get("SECRET_KEY", "change-me-in-development"),
            port=int(os.environ.get("DARWIN_PORT", "5005")),
        )

        self.database = DatabaseConfig(
            type=os.environ.get("DB_TYPE", "postgres"),
            host=os.environ.get("DB_HOST", "localhost"),
            port=int(os.environ.get("DB_PORT", "5432")),
            name=os.environ.get("DB_NAME", "skauswatch"),
            user=os.environ.get("DARWIN_DB_USER", os.environ.get("DB_USER", "darwin")),
            password=os.environ.get(
                "DARWIN_DB_PASS", os.environ.get("DB_PASS", "changeme")
            ),
        )

        # Darwin Celery uses Redis DB 2 to avoid collision with worker-scanner (DB 1)
        celery_broker = os.environ.get(
            "DARWIN_CELERY_BROKER_URL",
            f"redis://{_redis_password_fragment()}redis:6379/2",
        )
        self.redis = RedisConfig(
            url=os.environ.get("REDIS_URL", "redis://redis:6379/0"),
            celery_broker_url=celery_broker,
            celery_result_backend=celery_broker,
        )

        self.ai = AIConfig(
            provider=os.environ.get("DARWIN_AI_PROVIDER", "anthropic"),
            model=os.environ.get("DARWIN_AI_MODEL", "claude-opus-4-5"),
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY"),
            openai_api_key=os.environ.get("OPENAI_API_KEY"),
            ollama_url=os.environ.get("OLLAMA_URL", "http://ollama:11434"),
            timeout=int(os.environ.get("DARWIN_AI_TIMEOUT", "120")),
        )

        self.license = LicenseConfig(
            key=os.environ.get("LICENSE_KEY"),
            server_url=os.environ.get(
                "LICENSE_SERVER_URL", "https://license.penguintech.io"
            ),
            release_mode=_parse_bool(os.environ.get("RELEASE_MODE", "false")),
            free_tier_user_cap=int(os.environ.get("DARWIN_FREE_TIER_USER_CAP", "3")),
            max_repos_free=int(os.environ.get("DARWIN_MAX_REPOS_FREE", "3")),
            max_reviews_per_day=int(os.environ.get("DARWIN_MAX_REVIEWS_PER_DAY", "10")),
        )


def _redis_password_fragment() -> str:
    """Build redis password fragment for URL if password is set."""
    pw = os.environ.get("REDIS_PASSWORD", "")
    return f":{pw}@" if pw else ""


# Module-level singleton
settings = Settings()
