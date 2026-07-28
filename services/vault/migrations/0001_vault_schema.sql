-- Vault secrets-manager schema (v2 Rust port).
--
-- Table names are `vault_*`-prefixed to match the v1 schema (zero schema
-- changes intended for v2.0.0 — see services/vault/src/state.rs). Column
-- shapes are dictated by the existing route handlers in
-- services/vault/src/routes/*.rs (sqlx::FromRow structs using
-- `chrono::NaiveDateTime`, hence `TIMESTAMP` without a time zone rather than
-- `TIMESTAMPTZ`).
--
-- No local `vault_users`/`vault_tenants` identity tables: authentication is
-- centralized at the manager service. This service validates the same JWT
-- and trusts its `sub`/`scope`/`tenant` claims directly; actor/owner id
-- columns below are plain TEXT (no FK) referencing that external identity
-- space.

CREATE TABLE IF NOT EXISTS vault_secrets (
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    description         TEXT,
    secret_type         TEXT NOT NULL,
    encrypted_value     TEXT NOT NULL,
    encrypted_dek       TEXT NOT NULL,
    dek_version         INTEGER NOT NULL,
    tags                JSONB,
    secret_metadata     JSONB,
    expires_at          TIMESTAMP,
    created_at          TIMESTAMP NOT NULL DEFAULT now(),
    updated_at          TIMESTAMP NOT NULL DEFAULT now(),
    created_by          TEXT
);

CREATE INDEX IF NOT EXISTS idx_vault_secrets_secret_type ON vault_secrets (secret_type);

CREATE TABLE IF NOT EXISTS vault_secret_versions (
    id                  TEXT PRIMARY KEY,
    secret_id           TEXT NOT NULL REFERENCES vault_secrets (id) ON DELETE CASCADE,
    version_number      INTEGER NOT NULL,
    encrypted_value     TEXT NOT NULL,
    encrypted_dek       TEXT NOT NULL,
    dek_version         INTEGER NOT NULL,
    created_by          TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT now(),
    deprecated_at       TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vault_secret_versions_secret_id ON vault_secret_versions (secret_id);

CREATE TABLE IF NOT EXISTS vault_secret_owners (
    secret_id           TEXT NOT NULL REFERENCES vault_secrets (id) ON DELETE CASCADE,
    owner_type          TEXT NOT NULL,
    owner_id            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vault_secret_owners_secret_id ON vault_secret_owners (secret_id);
CREATE INDEX IF NOT EXISTS idx_vault_secret_owners_owner ON vault_secret_owners (owner_type, owner_id);

CREATE TABLE IF NOT EXISTS vault_jit_requests (
    id                              TEXT PRIMARY KEY,
    secret_id                       TEXT NOT NULL REFERENCES vault_secrets (id) ON DELETE CASCADE,
    requestor_id                    TEXT NOT NULL,
    reason                          TEXT NOT NULL,
    requested_duration_seconds      INTEGER NOT NULL,
    approved_duration_seconds       INTEGER,
    status                          TEXT NOT NULL DEFAULT 'pending',
    approved_by                     TEXT,
    approved_at                     TIMESTAMP,
    access_expires_at               TIMESTAMP,
    created_at                      TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vault_jit_requests_secret_id ON vault_jit_requests (secret_id);
CREATE INDEX IF NOT EXISTS idx_vault_jit_requests_requestor_id ON vault_jit_requests (requestor_id);

CREATE TABLE IF NOT EXISTS vault_jit_grants (
    id                      TEXT PRIMARY KEY,
    request_id              TEXT NOT NULL REFERENCES vault_jit_requests (id) ON DELETE CASCADE,
    secret_id               TEXT NOT NULL,
    grantee_id              TEXT NOT NULL,
    access_token_hash       TEXT NOT NULL,
    expires_at               TIMESTAMP NOT NULL,
    revoked_at               TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vault_jit_grants_secret_id ON vault_jit_grants (secret_id);

CREATE TABLE IF NOT EXISTS vault_one_time_secrets (
    id                  TEXT PRIMARY KEY,
    token_hash          TEXT NOT NULL UNIQUE,
    encrypted_value     TEXT NOT NULL,
    encrypted_dek       TEXT NOT NULL,
    dek_version         INTEGER NOT NULL,
    expires_at          TIMESTAMP NOT NULL,
    viewed_at           TIMESTAMP,
    created_by          TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vault_cloud_integrations (
    id                      TEXT PRIMARY KEY,
    provider                TEXT NOT NULL,
    name                    TEXT NOT NULL,
    description             TEXT,
    sync_direction          TEXT NOT NULL,
    sync_scopes             JSONB,
    encrypted_credentials   TEXT,
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    config                  JSONB,
    last_sync_at            TIMESTAMP,
    created_at              TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS vault_audit_log (
    id                  TEXT PRIMARY KEY,
    actor_id            TEXT NOT NULL,
    action              TEXT NOT NULL,
    resource_type       TEXT NOT NULL,
    resource_id         TEXT,
    ip_address          TEXT,
    user_agent          TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vault_audit_log_actor_id ON vault_audit_log (actor_id);
CREATE INDEX IF NOT EXISTS idx_vault_audit_log_resource ON vault_audit_log (resource_type, resource_id);
