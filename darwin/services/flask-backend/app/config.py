"""Flask Backend Configuration."""

import os
from datetime import timedelta


class Config:
    """Base configuration."""

    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    # JWT
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("JWT_ACCESS_TOKEN_MINUTES", "30"))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        days=int(os.getenv("JWT_REFRESH_TOKEN_DAYS", "7"))
    )

    # Database - PyDAL compatible
    DB_TYPE = os.getenv("DB_TYPE", "postgres")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "app_db")
    DB_USER = os.getenv("DB_USER", "app_user")
    DB_PASS = os.getenv("DB_PASS", "app_pass")
    DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))

    # CORS
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

    # AI Provider Configuration
    ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    DEFAULT_AI_PROVIDER = os.getenv("DEFAULT_AI_PROVIDER", "anthropic")
    OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")

    # GitHub/GitLab Configuration
    GITHUB_APP_ID = os.getenv("GITHUB_APP_ID", "")
    GITHUB_APP_PRIVATE_KEY_PATH = os.getenv(
        "GITHUB_APP_PRIVATE_KEY_PATH", "/etc/secrets/github-app-key.pem"
    )
    GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    GITLAB_TOKEN = os.getenv("GITLAB_TOKEN", "")
    GITLAB_WEBHOOK_SECRET = os.getenv("GITLAB_WEBHOOK_SECRET", "")

    # Review Configuration
    MAX_FILES_PER_REVIEW = int(os.getenv("MAX_FILES_PER_REVIEW", "50"))
    MAX_LINES_PER_FILE = int(os.getenv("MAX_LINES_PER_FILE", "1000"))
    REVIEW_TIMEOUT_SECONDS = int(os.getenv("REVIEW_TIMEOUT_SECONDS", "300"))

    # Ollama Model Configuration (Western/US-based models only)
    # See docs/ai-model-recommendations.md for details
    # See docs/USAGE.md for GPU/hardware recommendations
    OLLAMA_SECURITY_LLM = os.getenv("OLLAMA_SECURITY_LLM", "granite-code:34b")
    OLLAMA_BEST_PRACTICES_LLM = os.getenv(
        "OLLAMA_BEST_PRACTICES_LLM", "llama3.3:70b"
    )
    OLLAMA_FRAMEWORK_LLM = os.getenv("OLLAMA_FRAMEWORK_LLM", "codestral:22b")
    OLLAMA_IAC_LLM = os.getenv("OLLAMA_IAC_LLM", "granite-code:20b")
    OLLAMA_FALLBACK_LLM = os.getenv("OLLAMA_FALLBACK_LLM", "starcoder2:15b")
    OLLAMA_DEFAULT_LLM = os.getenv("OLLAMA_DEFAULT_LLM", "granite-code:20b")

    # Review Category Configuration (Enable/Disable)
    REVIEW_SECURITY_ENABLED = os.getenv("REVIEW_SECURITY_ENABLED", "true").lower() == "true"
    REVIEW_BEST_PRACTICES_ENABLED = os.getenv(
        "REVIEW_BEST_PRACTICES_ENABLED", "true"
    ).lower() == "true"
    REVIEW_FRAMEWORK_ENABLED = os.getenv(
        "REVIEW_FRAMEWORK_ENABLED", "true"
    ).lower() == "true"
    REVIEW_IAC_ENABLED = os.getenv("REVIEW_IAC_ENABLED", "true").lower() == "true"

    # Sandbox Configuration
    SANDBOX_BASE_PATH = os.getenv("SANDBOX_BASE_PATH", "/tmp/pr-reviewer")
    SANDBOX_CLEANUP_TIMEOUT = int(os.getenv("SANDBOX_CLEANUP_TIMEOUT", "3600"))

    # Encryption Configuration
    CREDENTIAL_ENCRYPTION_KEY = os.getenv("CREDENTIAL_ENCRYPTION_KEY", "")

    # License Configuration
    LICENSE_KEY = os.getenv("LICENSE_KEY", "")
    LICENSE_SERVER_URL = os.getenv(
        "LICENSE_SERVER_URL", "https://license.penguintech.io"
    )
    PRODUCT_NAME = os.getenv("PRODUCT_NAME", "ai-pr-reviewer")

    # Free Tier Limitation
    MAX_REPOS_FREE = int(os.getenv("MAX_REPOS_FREE", "3"))
    REQUIRE_LICENSE_FOR_EXTRA_REPOS = os.getenv(
        "REQUIRE_LICENSE_FOR_EXTRA_REPOS", "true"
    ).lower() == "true"

    @classmethod
    def get_db_uri(cls) -> str:
        """Build PyDAL-compatible database URI."""
        db_type = cls.DB_TYPE

        # Map common aliases to PyDAL format
        type_map = {
            "postgresql": "postgres",
            "mysql": "mysql",
            "sqlite": "sqlite",
            "mssql": "mssql",
        }
        db_type = type_map.get(db_type, db_type)

        if db_type == "sqlite":
            return f"sqlite://{cls.DB_NAME}.db"

        return (
            f"{db_type}://{cls.DB_USER}:{cls.DB_PASS}@"
            f"{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"
        )


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False


class TestingConfig(Config):
    """Testing configuration."""

    TESTING = True
    DB_TYPE = "sqlite"
    DB_NAME = ":memory:"
