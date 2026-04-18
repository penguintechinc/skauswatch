"""Unit tests for manager-new configuration classes.

Tests: ManagerConfig, DatabaseConfig, AuthConfig defaults and env loading.
"""

import os

import pytest


@pytest.mark.unit
class TestManagerConfig:
    """ManagerConfig initialization and defaults."""

    def test_default_values(self):
        """Default config has expected values."""
        from config import ManagerConfig

        config = ManagerConfig()
        assert config.service_name == "skauswatch-manager"
        assert config.environment == "production"
        assert config.log_level == "INFO"

    def test_custom_values(self):
        """Config accepts custom values."""
        from config import ManagerConfig

        config = ManagerConfig(
            environment="testing",
            log_level="DEBUG",
        )
        assert config.environment == "testing"
        assert config.log_level == "DEBUG"


@pytest.mark.unit
class TestDatabaseConfig:
    """DatabaseConfig initialization and URI generation."""

    def test_default_values(self):
        """Default database config uses postgres."""
        from config import DatabaseConfig

        config = DatabaseConfig()
        assert config.type == "postgres"
        assert config.port == 5432

    def test_sqlite_uri(self):
        """SQLite URI is generated correctly."""
        from config import DatabaseConfig

        config = DatabaseConfig(type="sqlite", name=":memory:")
        uri = config.uri
        assert "sqlite" in uri

    def test_postgres_uri(self):
        """PostgreSQL URI includes all connection params."""
        from config import DatabaseConfig

        config = DatabaseConfig(
            type="postgres",
            host="db.example.com",
            port=5433,
            name="testdb",
            user="testuser",
            password="testpass",
        )
        uri = config.uri
        assert "postgres" in uri
        assert "testuser" in uri
        assert "db.example.com" in uri


@pytest.mark.unit
class TestAuthConfig:
    """AuthConfig initialization and derived properties."""

    def test_default_values(self):
        """Default auth config has sane defaults."""
        from config import AuthConfig

        config = AuthConfig()
        assert config.jwt_algorithm == "HS256"
        assert config.access_token_expires_minutes == 30
        assert config.refresh_token_expires_days == 7
        assert config.max_login_attempts == 5
        assert config.lockout_duration_minutes == 15
        assert config.password_min_length == 8

    def test_access_token_expires_property(self):
        """access_token_expires returns timedelta."""
        from datetime import timedelta

        from config import AuthConfig

        config = AuthConfig(access_token_expires_minutes=60)
        assert config.access_token_expires == timedelta(minutes=60)

    def test_refresh_token_expires_property(self):
        """refresh_token_expires returns timedelta."""
        from datetime import timedelta

        from config import AuthConfig

        config = AuthConfig(refresh_token_expires_days=14)
        assert config.refresh_token_expires == timedelta(days=14)


@pytest.mark.unit
class TestLoadConfig:
    """load_config() environment variable loading."""

    def test_load_config_from_env(self, monkeypatch):
        """load_config reads environment variables."""
        monkeypatch.setenv("DB_TYPE", "sqlite")
        monkeypatch.setenv("DB_NAME", ":memory:")
        monkeypatch.setenv("JWT_SECRET_KEY", "env-secret")
        monkeypatch.setenv("LOG_LEVEL", "DEBUG")

        from config import load_config

        config = load_config()
        assert config.database.type == "sqlite"
        assert config.auth.jwt_secret == "env-secret"
        assert config.log_level == "DEBUG"
