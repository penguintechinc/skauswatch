"""
checkpoint-core — Configuration via Pydantic v2 Settings.

All settings are loaded from environment variables with the CHECKPOINT_ prefix.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class CheckpointConfig(BaseSettings):
    """Top-level configuration for checkpoint-core service."""

    # ── Database ──────────────────────────────────────────────────────────────
    db_type: str = "postgresql"
    db_host: str = "localhost"
    db_port: int = 5432
    db_name: str = "skauswatch"
    db_user: str = "checkpoint-rw"
    db_pass: str
    db_pool_size: int = 10

    # ── gRPC server (inbound — called by checkpoint-ldap-agent) ───────────────
    grpc_port: int = 50051

    # ── gRPC client (outbound — calls skauswatch-core) ────────────────────────
    core_grpc_host: str = "skauswatch-core"
    core_grpc_port: int = 50051

    # ── Web ───────────────────────────────────────────────────────────────────
    port: int = 8080

    # ── OIDC / OAuth2 ─────────────────────────────────────────────────────────
    issuer_url: str  # e.g. https://checkpoint.skauswatch.app
    token_ttl: int = 3600          # access token TTL in seconds
    refresh_token_ttl: int = 86400
    code_ttl: int = 300            # authorisation code TTL
    require_pkce: bool = True

    # ── SAML ──────────────────────────────────────────────────────────────────
    saml_entity_id: str            # e.g. https://checkpoint.skauswatch.app/saml
    saml_signing_key_id: str = ""  # kid of active signing key (from DB)

    # ── LDAP ──────────────────────────────────────────────────────────────────
    ldap_port: int = 389
    ldaps_port: int = 636
    ldap_base_dn: str = "dc=skauswatch,dc=app"
    ldap_enabled: bool = True
    ldap_allow_anonymous: bool = False  # Permit anonymous (unauthenticated) LDAP binds

    # ── Signing keys (MEK encrypts private keys at rest) ──────────────────────
    signing_mek: str  # AES-256 master encryption key for signing-key private keys (base64)

    # ── Rate limiting ─────────────────────────────────────────────────────────
    auth_rate_limit_per_min: int = 10
    auth_rate_limit_per_hour: int = 100

    # ── Licensing ─────────────────────────────────────────────────────────────
    license_key: str = ""
    license_server_url: str = "https://license.penguintech.io"
    checkpoint_license_bypass_domains: str = ""  # comma-separated

    # ── Watcher / OpenSearch integration ──────────────────────────────────────
    watcher_enabled: bool = False
    watcher_url: str = ""

    model_config = SettingsConfigDict(
        env_prefix="CHECKPOINT_",
        env_file=".env",
        env_file_encoding="utf-8",
    )

    @property
    def db_uri(self) -> str:
        """Build a PyDAL-compatible connection URI from individual DB settings."""
        return (
            f"{self.db_type}://{self.db_user}:{self.db_pass}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def license_bypass_domains_list(self) -> list[str]:
        """Return bypass domains as a list (empty strings filtered out)."""
        if not self.checkpoint_license_bypass_domains:
            return []
        return [
            d.strip()
            for d in self.checkpoint_license_bypass_domains.split(",")
            if d.strip()
        ]
