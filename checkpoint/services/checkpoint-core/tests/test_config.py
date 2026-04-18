"""pytest tests for config.py — 90%+ coverage of CheckpointConfig."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from config import CheckpointConfig


class TestCheckpointConfigDefaults:
    """Test default values for CheckpointConfig."""

    def test_db_type_default(self, monkeypatch) -> None:
        """Test db_type defaults to postgresql."""
        monkeypatch.delenv("CHECKPOINT_DB_PASS", raising=False)
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")

        cfg = CheckpointConfig()
        assert cfg.db_type == "postgresql"

    def test_db_host_default(self, monkeypatch) -> None:
        """Test db_host defaults to localhost."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.db_host == "localhost"

    def test_db_port_default(self, monkeypatch) -> None:
        """Test db_port defaults to 5432."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.db_port == 5432

    def test_db_name_default(self, monkeypatch) -> None:
        """Test db_name defaults to skauswatch."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.db_name == "skauswatch"

    def test_db_user_default(self, monkeypatch) -> None:
        """Test db_user defaults to checkpoint-rw."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.db_user == "checkpoint-rw"

    def test_db_pool_size_default(self, monkeypatch) -> None:
        """Test db_pool_size defaults to 10."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.db_pool_size == 10

    def test_grpc_port_default(self, monkeypatch) -> None:
        """Test grpc_port defaults to 50051."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.grpc_port == 50051

    def test_core_grpc_host_default(self, monkeypatch) -> None:
        """Test core_grpc_host defaults to skauswatch-core."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.core_grpc_host == "skauswatch-core"

    def test_core_grpc_port_default(self, monkeypatch) -> None:
        """Test core_grpc_port defaults to 50051."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.core_grpc_port == 50051

    def test_port_default(self, monkeypatch) -> None:
        """Test port defaults to 8080."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.port == 8080

    def test_token_ttl_default(self, monkeypatch) -> None:
        """Test token_ttl defaults to 3600 seconds."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.token_ttl == 3600

    def test_refresh_token_ttl_default(self, monkeypatch) -> None:
        """Test refresh_token_ttl defaults to 86400 seconds."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.refresh_token_ttl == 86400

    def test_code_ttl_default(self, monkeypatch) -> None:
        """Test code_ttl defaults to 300 seconds."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.code_ttl == 300

    def test_require_pkce_default(self, monkeypatch) -> None:
        """Test require_pkce defaults to True."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.require_pkce is True

    def test_saml_signing_key_id_default(self, monkeypatch) -> None:
        """Test saml_signing_key_id defaults to empty string."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_ISSUER_URL", "https://example.com")
        monkeypatch.setenv("CHECKPOINT_SAML_ENTITY_ID", "https://example.com/saml")
        monkeypatch.setenv("CHECKPOINT_SIGNING_MEK", "dGVzdA==")
        cfg = CheckpointConfig()
        assert cfg.saml_signing_key_id == ""

    def test_ldap_port_default(self, monkeypatch) -> None:
        """Test ldap_port defaults to 389."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.ldap_port == 389

    def test_ldaps_port_default(self, monkeypatch) -> None:
        """Test ldaps_port defaults to 636."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.ldaps_port == 636

    def test_ldap_base_dn_default(self, monkeypatch) -> None:
        """Test ldap_base_dn defaults to dc=skauswatch,dc=app."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.ldap_base_dn == "dc=skauswatch,dc=app"

    def test_ldap_enabled_default(self, monkeypatch) -> None:
        """Test ldap_enabled defaults to True."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.ldap_enabled is True

    def test_ldap_allow_anonymous_default(self, monkeypatch) -> None:
        """Test ldap_allow_anonymous defaults to False."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.ldap_allow_anonymous is False

    def test_license_server_url_default(self, monkeypatch) -> None:
        """Test license_server_url defaults to https://license.penguintech.io."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.license_server_url == "https://license.penguintech.io"

    def test_license_key_default(self, monkeypatch) -> None:
        """Test license_key defaults to empty string."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.license_key == ""

    def test_checkpoint_license_bypass_domains_default(self, monkeypatch) -> None:
        """Test checkpoint_license_bypass_domains defaults to empty string."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.checkpoint_license_bypass_domains == ""

    def test_watcher_enabled_default(self, monkeypatch) -> None:
        """Test watcher_enabled defaults to False."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.watcher_enabled is False

    def test_watcher_url_default(self, monkeypatch) -> None:
        """Test watcher_url defaults to empty string."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.watcher_url == ""

    def test_auth_rate_limit_per_min_default(self, monkeypatch) -> None:
        """Test auth_rate_limit_per_min defaults to 10."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.auth_rate_limit_per_min == 10

    def test_auth_rate_limit_per_hour_default(self, monkeypatch) -> None:
        """Test auth_rate_limit_per_hour defaults to 100."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        cfg = CheckpointConfig()
        assert cfg.auth_rate_limit_per_hour == 100


class TestCheckpointConfigRequired:
    """Test required fields in CheckpointConfig."""

    def test_db_pass_required(self, monkeypatch) -> None:
        """Test db_pass is required."""
        monkeypatch.delenv("CHECKPOINT_DB_PASS", raising=False)

        with pytest.raises(ValidationError) as exc_info:
            CheckpointConfig()

        assert "db_pass" in str(exc_info.value)

    def test_issuer_url_required(self, monkeypatch) -> None:
        """Test issuer_url is required."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.delenv("CHECKPOINT_ISSUER_URL", raising=False)

        with pytest.raises(ValidationError) as exc_info:
            CheckpointConfig()

        assert "issuer_url" in str(exc_info.value)

    def test_saml_entity_id_required(self, monkeypatch) -> None:
        """Test saml_entity_id is required."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_ISSUER_URL", "https://example.com")
        monkeypatch.delenv("CHECKPOINT_SAML_ENTITY_ID", raising=False)

        with pytest.raises(ValidationError) as exc_info:
            CheckpointConfig()

        assert "saml_entity_id" in str(exc_info.value)

    def test_signing_mek_required(self, monkeypatch) -> None:
        """Test signing_mek is required."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_ISSUER_URL", "https://example.com")
        monkeypatch.setenv("CHECKPOINT_SAML_ENTITY_ID", "https://example.com/saml")
        monkeypatch.delenv("CHECKPOINT_SIGNING_MEK", raising=False)

        with pytest.raises(ValidationError) as exc_info:
            CheckpointConfig()

        assert "signing_mek" in str(exc_info.value)

    def test_all_required_provided(self, monkeypatch) -> None:
        """Test config loads when all required fields are provided."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_ISSUER_URL", "https://example.com")
        monkeypatch.setenv("CHECKPOINT_SAML_ENTITY_ID", "https://example.com/saml")
        monkeypatch.setenv("CHECKPOINT_SIGNING_MEK", "dGVzdA==")

        cfg = CheckpointConfig()
        assert cfg.db_pass == "password"
        assert cfg.issuer_url == "https://example.com"
        assert cfg.saml_entity_id == "https://example.com/saml"
        assert cfg.signing_mek == "dGVzdA=="


class TestCheckpointConfigDbUri:
    """Test db_uri property."""

    def test_db_uri_postgresql(self, monkeypatch) -> None:
        """Test db_uri for PostgreSQL."""
        monkeypatch.setenv("CHECKPOINT_DB_TYPE", "postgresql")
        monkeypatch.setenv("CHECKPOINT_DB_USER", "pguser")
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "pgpass")
        monkeypatch.setenv("CHECKPOINT_DB_HOST", "pghost")
        monkeypatch.setenv("CHECKPOINT_DB_PORT", "5432")
        monkeypatch.setenv("CHECKPOINT_DB_NAME", "pgdb")

        cfg = CheckpointConfig()
        assert cfg.db_uri == "postgresql://pguser:pgpass@pghost:5432/pgdb"

    def test_db_uri_mysql(self, monkeypatch) -> None:
        """Test db_uri for MySQL."""
        monkeypatch.setenv("CHECKPOINT_DB_TYPE", "mysql")
        monkeypatch.setenv("CHECKPOINT_DB_USER", "mysqluser")
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "mysqlpass")
        monkeypatch.setenv("CHECKPOINT_DB_HOST", "mysqlhost")
        monkeypatch.setenv("CHECKPOINT_DB_PORT", "3306")
        monkeypatch.setenv("CHECKPOINT_DB_NAME", "mysqldb")

        cfg = CheckpointConfig()
        assert cfg.db_uri == "mysql://mysqluser:mysqlpass@mysqlhost:3306/mysqldb"

    def test_db_uri_sqlite(self, monkeypatch) -> None:
        """Test db_uri for SQLite."""
        monkeypatch.setenv("CHECKPOINT_DB_TYPE", "sqlite")
        monkeypatch.setenv("CHECKPOINT_DB_USER", "")
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_DB_HOST", "localhost")
        monkeypatch.setenv("CHECKPOINT_DB_PORT", "0")
        monkeypatch.setenv("CHECKPOINT_DB_NAME", "test.db")

        cfg = CheckpointConfig()
        assert cfg.db_uri == "sqlite://:password@localhost:0/test.db"

    def test_db_uri_special_chars_in_password(self, monkeypatch) -> None:
        """Test db_uri with special characters in password."""
        monkeypatch.setenv("CHECKPOINT_DB_TYPE", "postgresql")
        monkeypatch.setenv("CHECKPOINT_DB_USER", "user")
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "p@ss%word!")
        monkeypatch.setenv("CHECKPOINT_DB_HOST", "host")
        monkeypatch.setenv("CHECKPOINT_DB_PORT", "5432")
        monkeypatch.setenv("CHECKPOINT_DB_NAME", "db")

        cfg = CheckpointConfig()
        assert cfg.db_uri == "postgresql://user:p@ss%word!@host:5432/db"

    def test_db_uri_custom_port(self, monkeypatch) -> None:
        """Test db_uri with custom port."""
        monkeypatch.setenv("CHECKPOINT_DB_TYPE", "postgresql")
        monkeypatch.setenv("CHECKPOINT_DB_USER", "user")
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "pass")
        monkeypatch.setenv("CHECKPOINT_DB_HOST", "host")
        monkeypatch.setenv("CHECKPOINT_DB_PORT", "15432")
        monkeypatch.setenv("CHECKPOINT_DB_NAME", "db")

        cfg = CheckpointConfig()
        assert cfg.db_uri == "postgresql://user:pass@host:15432/db"


class TestCheckpointConfigLicenseBypassDomains:
    """Test license_bypass_domains_list property."""

    def test_license_bypass_domains_empty(self, monkeypatch) -> None:
        """Test empty bypass domains returns empty list."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_CHECKPOINT_LICENSE_BYPASS_DOMAINS", "")

        cfg = CheckpointConfig()
        assert cfg.license_bypass_domains_list == []

    def test_license_bypass_domains_single(self, monkeypatch) -> None:
        """Test single bypass domain."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv(
            "CHECKPOINT_CHECKPOINT_LICENSE_BYPASS_DOMAINS", "*.example.com"
        )

        cfg = CheckpointConfig()
        assert cfg.license_bypass_domains_list == ["*.example.com"]

    def test_license_bypass_domains_multiple(self, monkeypatch) -> None:
        """Test multiple bypass domains."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv(
            "CHECKPOINT_CHECKPOINT_LICENSE_BYPASS_DOMAINS",
            "*.example.com, *.test.local, localhost",
        )

        cfg = CheckpointConfig()
        assert cfg.license_bypass_domains_list == [
            "*.example.com",
            "*.test.local",
            "localhost",
        ]

    def test_license_bypass_domains_strips_whitespace(self, monkeypatch) -> None:
        """Test bypass domains are stripped of whitespace."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv(
            "CHECKPOINT_CHECKPOINT_LICENSE_BYPASS_DOMAINS",
            "  *.example.com  ,  *.test.local  ",
        )

        cfg = CheckpointConfig()
        assert cfg.license_bypass_domains_list == ["*.example.com", "*.test.local"]

    def test_license_bypass_domains_filters_empty_strings(self, monkeypatch) -> None:
        """Test empty strings in domain list are filtered out."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv(
            "CHECKPOINT_CHECKPOINT_LICENSE_BYPASS_DOMAINS",
            "*.example.com,  , *.test.local, ,",
        )

        cfg = CheckpointConfig()
        assert cfg.license_bypass_domains_list == ["*.example.com", "*.test.local"]

    def test_license_bypass_domains_not_set(self, monkeypatch) -> None:
        """Test when license bypass domains env var is not set."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.delenv("CHECKPOINT_CHECKPOINT_LICENSE_BYPASS_DOMAINS", raising=False)

        cfg = CheckpointConfig()
        assert cfg.license_bypass_domains_list == []


class TestCheckpointConfigCustomValues:
    """Test custom configuration values."""

    def test_custom_db_values(self, monkeypatch) -> None:
        """Test setting custom database values."""
        monkeypatch.setenv("CHECKPOINT_DB_TYPE", "mysql")
        monkeypatch.setenv("CHECKPOINT_DB_HOST", "db.example.com")
        monkeypatch.setenv("CHECKPOINT_DB_PORT", "3307")
        monkeypatch.setenv("CHECKPOINT_DB_NAME", "checkpoint_prod")
        monkeypatch.setenv("CHECKPOINT_DB_USER", "checkpoint_app")
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "secret123")
        monkeypatch.setenv("CHECKPOINT_DB_POOL_SIZE", "20")

        cfg = CheckpointConfig()
        assert cfg.db_type == "mysql"
        assert cfg.db_host == "db.example.com"
        assert cfg.db_port == 3307
        assert cfg.db_name == "checkpoint_prod"
        assert cfg.db_user == "checkpoint_app"
        assert cfg.db_pass == "secret123"
        assert cfg.db_pool_size == 20

    def test_custom_grpc_values(self, monkeypatch) -> None:
        """Test setting custom gRPC values."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_GRPC_PORT", "50052")
        monkeypatch.setenv("CHECKPOINT_CORE_GRPC_HOST", "skauswatch-core.svc.cluster.local")
        monkeypatch.setenv("CHECKPOINT_CORE_GRPC_PORT", "50053")

        cfg = CheckpointConfig()
        assert cfg.grpc_port == 50052
        assert cfg.core_grpc_host == "skauswatch-core.svc.cluster.local"
        assert cfg.core_grpc_port == 50053

    def test_custom_oauth2_values(self, monkeypatch) -> None:
        """Test setting custom OAuth2 values."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_ISSUER_URL", "https://auth.example.com")
        monkeypatch.setenv("CHECKPOINT_TOKEN_TTL", "7200")
        monkeypatch.setenv("CHECKPOINT_REFRESH_TOKEN_TTL", "604800")
        monkeypatch.setenv("CHECKPOINT_CODE_TTL", "600")
        monkeypatch.setenv("CHECKPOINT_REQUIRE_PKCE", "false")
        monkeypatch.setenv("CHECKPOINT_SAML_ENTITY_ID", "https://auth.example.com/saml")
        monkeypatch.setenv("CHECKPOINT_SIGNING_MEK", "dGVzdA==")

        cfg = CheckpointConfig()
        assert cfg.issuer_url == "https://auth.example.com"
        assert cfg.token_ttl == 7200
        assert cfg.refresh_token_ttl == 604800
        assert cfg.code_ttl == 600
        assert cfg.require_pkce is False

    def test_custom_ldap_values(self, monkeypatch) -> None:
        """Test setting custom LDAP values."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_LDAP_PORT", "1389")
        monkeypatch.setenv("CHECKPOINT_LDAPS_PORT", "1636")
        monkeypatch.setenv("CHECKPOINT_LDAP_BASE_DN", "dc=company,dc=com")
        monkeypatch.setenv("CHECKPOINT_LDAP_ENABLED", "false")
        monkeypatch.setenv("CHECKPOINT_LDAP_ALLOW_ANONYMOUS", "true")

        cfg = CheckpointConfig()
        assert cfg.ldap_port == 1389
        assert cfg.ldaps_port == 1636
        assert cfg.ldap_base_dn == "dc=company,dc=com"
        assert cfg.ldap_enabled is False
        assert cfg.ldap_allow_anonymous is True

    def test_custom_watcher_values(self, monkeypatch) -> None:
        """Test setting custom Watcher values."""
        monkeypatch.setenv("CHECKPOINT_DB_PASS", "password")
        monkeypatch.setenv("CHECKPOINT_WATCHER_ENABLED", "true")
        monkeypatch.setenv("CHECKPOINT_WATCHER_URL", "https://watcher.example.com")

        cfg = CheckpointConfig()
        assert cfg.watcher_enabled is True
        assert cfg.watcher_url == "https://watcher.example.com"
