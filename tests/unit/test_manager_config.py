"""Unit tests for SkausWatch Manager configuration loading.

Tests basic config initialization with environment variables and defaults.
"""

import pytest


class TestManagerConfig:
    """Test suite for Manager service configuration."""

    @pytest.mark.unit
    def test_config_loads_with_defaults(self, mock_config):
        """Test that config object initializes with expected default values."""
        assert mock_config.service_name == "test-service"
        assert mock_config.environment == "test"
        assert mock_config.log_level == "DEBUG"

    @pytest.mark.unit
    def test_database_config_defaults(self, mock_config):
        """Test database configuration has correct default settings."""
        assert mock_config.database.type == "sqlite"
        assert mock_config.database.name == ":memory:"
        assert "sqlite" in mock_config.database.uri

    @pytest.mark.unit
    def test_redis_config_defaults(self, mock_config):
        """Test Redis configuration has correct default settings."""
        assert mock_config.redis.url == "redis://localhost:6379/0"
        assert mock_config.redis.key_prefix == "test"
        assert mock_config.redis.streams_enabled is True

    @pytest.mark.unit
    def test_auth_config_defaults(self, mock_config):
        """Test authentication configuration has correct default settings."""
        assert mock_config.auth.secret_key == "test-secret-key"
        assert mock_config.auth.jwt_secret == "test-jwt-secret"
        assert mock_config.auth.jwt_algorithm == "HS256"
