"""Flask Backend Configuration."""

import os
from datetime import timedelta


class Config:
    """Base configuration."""

    # Flask
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    # Database - SQLAlchemy compatible (penguin-dal)
    DB_TYPE = os.getenv("DB_TYPE", "postgresql")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5432")
    DB_NAME = os.getenv("DB_NAME", "app_db")
    DB_USER = os.getenv("DB_USER", "app_user")
    DB_PASS = os.getenv("DB_PASS", "app_pass")
    DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", "10"))

    # OIDC & JWT (penguin-aaa)
    ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:8080")
    JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "skauswatch")
    JWT_KEY_DIR = os.getenv("JWT_KEY_DIR", "/tmp/skauswatch-keys")
    JWT_KEY_ALGORITHM = "RS256"  # RSA-based; HS256 forbidden by penguin-aaa

    # CORS
    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

    @classmethod
    def get_db_uri(cls) -> str:
        """Build SQLAlchemy-compatible database URI (penguin-dal)."""
        db_type = cls.DB_TYPE.lower()

        if db_type == "sqlite":
            # SQLite: use db name as file path or :memory: for in-memory
            db_path = cls.DB_NAME if cls.DB_NAME != ":memory:" else ":memory:"
            return f"sqlite:///{db_path}"

        if db_type in ("postgresql", "postgres"):
            return (
                f"postgresql://{cls.DB_USER}:{cls.DB_PASS}@"
                f"{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"
            )

        if db_type in ("mysql", "mariadb"):
            return (
                f"mysql+pymysql://{cls.DB_USER}:{cls.DB_PASS}@"
                f"{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"
            )

        # Fallback to PostgreSQL
        return (
            f"postgresql://{cls.DB_USER}:{cls.DB_PASS}@"
            f"{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"
        )

    @property
    def DATABASE_URI(self) -> str:
        """SQLAlchemy database URI alias for penguin-dal."""
        return self.get_db_uri()


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
