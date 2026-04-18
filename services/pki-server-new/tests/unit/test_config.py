"""Unit tests for PKI Server configuration (config.py)."""

import pytest
from pydantic import ValidationError

# Ensure the pki_server_new package is importable via the sys.path manipulation
# that conftest.py performs.  Import after conftest side-effects have run.
from pki_server_new.config import (
    APIConfig,
    AuditConfig,
    DatabaseConfig,
    GRPCConfig,
    ManagerConfig,
    RateLimitConfig,
    RedisConfig,
    SSHCAConfig,
    Settings,
    X509CAConfig,
    get_settings,
)


# ===========================================================================
# Settings
# ===========================================================================
@pytest.mark.unit
class TestSettings:
    """Tests for the top-level Settings model."""

    def test_defaults_load_correctly(self):
        """Settings can be instantiated with no arguments using built-in defaults."""
        s = Settings()
        assert s.app_name == "SkausWatch PKI Server"
        assert s.version == "1.0.0"

    def test_has_expected_sub_configs(self):
        """All expected sub-configuration objects are present."""
        s = Settings()
        assert isinstance(s.database, DatabaseConfig)
        assert isinstance(s.redis, RedisConfig)
        assert isinstance(s.x509_ca, X509CAConfig)
        assert isinstance(s.ssh_ca, SSHCAConfig)
        assert isinstance(s.grpc, GRPCConfig)
        assert isinstance(s.api, APIConfig)
        assert isinstance(s.rate_limit, RateLimitConfig)
        assert isinstance(s.audit, AuditConfig)
        assert isinstance(s.manager, ManagerConfig)

    def test_environment_defaults_to_production(self, monkeypatch):
        """Without QUART_ENV, environment defaults to 'production'."""
        monkeypatch.delenv("QUART_ENV", raising=False)
        s = Settings()
        assert s.environment == "production"

    def test_environment_overridden_by_env_var(self, monkeypatch):
        """QUART_ENV environment variable overrides the environment field."""
        monkeypatch.setenv("QUART_ENV", "development")
        s = Settings()
        assert s.environment == "development"

    def test_secret_key_overridden_by_env_var(self, monkeypatch):
        """SECRET_KEY environment variable overrides the secret_key field."""
        monkeypatch.setenv("SECRET_KEY", "supersecretvalue")
        s = Settings()
        assert s.secret_key == "supersecretvalue"

    def test_get_settings_returns_settings_instance(self):
        """get_settings() factory returns a valid Settings object."""
        s = get_settings()
        assert isinstance(s, Settings)


# ===========================================================================
# DatabaseConfig
# ===========================================================================
@pytest.mark.unit
class TestDatabaseConfig:
    """Tests for DatabaseConfig."""

    def test_default_url(self, monkeypatch):
        """DATABASE_URL falls back to the PostgreSQL localhost default."""
        monkeypatch.delenv("DATABASE_URL", raising=False)
        db = DatabaseConfig()
        assert "localhost" in db.url
        assert "5432" in db.url

    def test_url_overridden_by_env_var(self, monkeypatch):
        """DATABASE_URL env var is respected."""
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@myhost:5432/mydb")
        db = DatabaseConfig()
        assert db.url == "postgresql://user:pass@myhost:5432/mydb"

    def test_default_pool_size(self):
        """Default pool_size is 10."""
        db = DatabaseConfig()
        assert db.pool_size == 10


# ===========================================================================
# X509CAConfig
# ===========================================================================
@pytest.mark.unit
class TestX509CAConfig:
    """Tests for X509CAConfig validators."""

    def test_default_key_algorithm_is_rsa(self, monkeypatch):
        """DEFAULT_KEY_ALGORITHM defaults to 'RSA'."""
        monkeypatch.delenv("DEFAULT_KEY_ALGORITHM", raising=False)
        cfg = X509CAConfig()
        assert cfg.default_key_algorithm == "RSA"

    def test_valid_algorithm_rsa(self):
        """RSA is an accepted key algorithm."""
        cfg = X509CAConfig(default_key_algorithm="RSA")
        assert cfg.default_key_algorithm == "RSA"

    def test_valid_algorithm_ecdsa(self):
        """ECDSA is an accepted key algorithm."""
        cfg = X509CAConfig(default_key_algorithm="ECDSA")
        assert cfg.default_key_algorithm == "ECDSA"

    def test_valid_algorithm_ed25519(self):
        """ED25519 is an accepted key algorithm."""
        cfg = X509CAConfig(default_key_algorithm="ED25519")
        assert cfg.default_key_algorithm == "ED25519"

    def test_algorithm_normalised_to_uppercase(self):
        """Lowercase algorithm names are uppercased by the validator."""
        cfg = X509CAConfig(default_key_algorithm="rsa")
        assert cfg.default_key_algorithm == "RSA"

    def test_invalid_algorithm_raises_validation_error(self):
        """An unknown key algorithm triggers a ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            X509CAConfig(default_key_algorithm="DSA")
        errors = exc_info.value.errors()
        assert any(
            "default_key_algorithm" in str(e.get("loc", "")) for e in errors
        )

    def test_default_validity_days(self, monkeypatch):
        """DEFAULT_VALIDITY_DAYS defaults to 365."""
        monkeypatch.delenv("DEFAULT_VALIDITY_DAYS", raising=False)
        cfg = X509CAConfig()
        assert cfg.default_validity_days == 365

    def test_default_key_size(self, monkeypatch):
        """DEFAULT_KEY_SIZE defaults to 4096."""
        monkeypatch.delenv("DEFAULT_KEY_SIZE", raising=False)
        cfg = X509CAConfig()
        assert cfg.default_key_size == 4096

    def test_crl_validity_days_default(self, monkeypatch):
        """CRL_VALIDITY_DAYS defaults to 7."""
        monkeypatch.delenv("CRL_VALIDITY_DAYS", raising=False)
        cfg = X509CAConfig()
        assert cfg.crl_validity_days == 7

    def test_crl_distribution_points_default_empty(self):
        """crl_distribution_points defaults to an empty list."""
        cfg = X509CAConfig()
        assert cfg.crl_distribution_points == []

    def test_key_algorithm_overridden_by_env_var(self, monkeypatch):
        """DEFAULT_KEY_ALGORITHM env var is respected."""
        monkeypatch.setenv("DEFAULT_KEY_ALGORITHM", "ECDSA")
        cfg = X509CAConfig()
        assert cfg.default_key_algorithm == "ECDSA"


# ===========================================================================
# SSHCAConfig
# ===========================================================================
@pytest.mark.unit
class TestSSHCAConfig:
    """Tests for SSHCAConfig validators."""

    def test_default_key_type_is_ed25519(self, monkeypatch):
        """SSH_DEFAULT_KEY_TYPE defaults to 'ed25519'."""
        monkeypatch.delenv("SSH_DEFAULT_KEY_TYPE", raising=False)
        cfg = SSHCAConfig()
        assert cfg.default_key_type == "ed25519"

    def test_valid_key_type_rsa(self):
        """'rsa' is an accepted SSH key type."""
        cfg = SSHCAConfig(default_key_type="rsa")
        assert cfg.default_key_type == "rsa"

    def test_valid_key_type_ecdsa(self):
        """'ecdsa' is an accepted SSH key type."""
        cfg = SSHCAConfig(default_key_type="ecdsa")
        assert cfg.default_key_type == "ecdsa"

    def test_valid_key_type_ed25519(self):
        """'ed25519' is an accepted SSH key type."""
        cfg = SSHCAConfig(default_key_type="ed25519")
        assert cfg.default_key_type == "ed25519"

    def test_key_type_normalised_to_lowercase(self):
        """Uppercase key type names are lowercased by the validator."""
        cfg = SSHCAConfig(default_key_type="ED25519")
        assert cfg.default_key_type == "ed25519"

    def test_invalid_key_type_raises_validation_error(self):
        """An unknown SSH key type triggers a ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            SSHCAConfig(default_key_type="dsa")
        errors = exc_info.value.errors()
        assert any(
            "default_key_type" in str(e.get("loc", "")) for e in errors
        )

    def test_default_validity_seconds(self, monkeypatch):
        """SSH_DEFAULT_VALIDITY_SECONDS defaults to 86400 (24 hours)."""
        monkeypatch.delenv("SSH_DEFAULT_VALIDITY_SECONDS", raising=False)
        cfg = SSHCAConfig()
        assert cfg.default_validity_seconds == 86400

    def test_allowed_principals_default_empty(self):
        """allowed_principals defaults to an empty list."""
        cfg = SSHCAConfig()
        assert cfg.allowed_principals == []

    def test_key_type_overridden_by_env_var(self, monkeypatch):
        """SSH_DEFAULT_KEY_TYPE env var is respected."""
        monkeypatch.setenv("SSH_DEFAULT_KEY_TYPE", "rsa")
        cfg = SSHCAConfig()
        assert cfg.default_key_type == "rsa"


# ===========================================================================
# GRPCConfig
# ===========================================================================
@pytest.mark.unit
class TestGRPCConfig:
    """Tests for GRPCConfig defaults."""

    def test_default_port(self, monkeypatch):
        """GRPC_PORT defaults to 50052."""
        monkeypatch.delenv("GRPC_PORT", raising=False)
        cfg = GRPCConfig()
        assert cfg.port == 50052

    def test_default_max_workers(self, monkeypatch):
        """GRPC_MAX_WORKERS defaults to 10."""
        monkeypatch.delenv("GRPC_MAX_WORKERS", raising=False)
        cfg = GRPCConfig()
        assert cfg.max_workers == 10

    def test_port_overridden_by_env_var(self, monkeypatch):
        """GRPC_PORT env var is respected."""
        monkeypatch.setenv("GRPC_PORT", "50099")
        cfg = GRPCConfig()
        assert cfg.port == 50099


# ===========================================================================
# APIConfig
# ===========================================================================
@pytest.mark.unit
class TestAPIConfig:
    """Tests for APIConfig defaults."""

    def test_default_port(self, monkeypatch):
        """API_PORT defaults to 8001."""
        monkeypatch.delenv("API_PORT", raising=False)
        cfg = APIConfig()
        assert cfg.port == 8001

    def test_default_host(self, monkeypatch):
        """API_HOST defaults to 0.0.0.0."""
        monkeypatch.delenv("API_HOST", raising=False)
        cfg = APIConfig()
        assert cfg.host == "0.0.0.0"

    def test_debug_default_false(self, monkeypatch):
        """QUART_DEBUG defaults to False."""
        monkeypatch.delenv("QUART_DEBUG", raising=False)
        cfg = APIConfig()
        assert cfg.debug is False

    def test_debug_overridden_by_env_var(self, monkeypatch):
        """QUART_DEBUG=true enables debug mode."""
        monkeypatch.setenv("QUART_DEBUG", "true")
        cfg = APIConfig()
        assert cfg.debug is True


# ===========================================================================
# RateLimitConfig
# ===========================================================================
@pytest.mark.unit
class TestRateLimitConfig:
    """Tests for RateLimitConfig defaults."""

    def test_enabled_by_default(self, monkeypatch):
        """Rate limiting is enabled by default."""
        monkeypatch.delenv("RATE_LIMIT_ENABLED", raising=False)
        cfg = RateLimitConfig()
        assert cfg.enabled is True

    def test_default_requests_per_minute(self, monkeypatch):
        """RATE_LIMIT_REQUESTS_PER_MINUTE defaults to 60."""
        monkeypatch.delenv("RATE_LIMIT_REQUESTS_PER_MINUTE", raising=False)
        cfg = RateLimitConfig()
        assert cfg.requests_per_minute == 60

    def test_rate_limit_can_be_disabled(self, monkeypatch):
        """RATE_LIMIT_ENABLED=false disables rate limiting."""
        monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
        cfg = RateLimitConfig()
        assert cfg.enabled is False
