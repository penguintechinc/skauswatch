-- PKI service schema (v2 Rust port). The v2 platform never shipped to prod,
-- so this is a fresh schema derived directly from the current Rust code's
-- query/bind shapes — not a port of a legacy v1 table layout.
--
-- Column types are dictated by the exact `sqlx::query(...).bind(...)` calls
-- and `row.try_get::<T, _>(...)` reads in services/pki/src/manager.rs and
-- services/pki/src/routes/{x509,ssh,common}.rs:
--   * `id`/`certificate_id`/`requester_id`/`approval_request_id`/`actor_id`
--     bind/read as `uuid::Uuid` (the `uuid` sqlx feature) -> UUID.
--   * every timestamp field in this service is `chrono::NaiveDateTime`
--     (never `DateTime<Utc>` — confirmed via `grep -rn NaiveDateTime|DateTime<Utc>`
--     across manager.rs/routes/*.rs/ca/*.rs) -> TIMESTAMP, NOT TIMESTAMPTZ.
--     Binding/reading a NaiveDateTime against a TIMESTAMPTZ column is a
--     sqlx type-mismatch error at query time, not just a semantic wart —
--     this mirrors services/vault/migrations/0001_vault_schema.sql, which
--     documents the same NaiveDateTime -> TIMESTAMP mapping for the same
--     reason. (The org's TIMESTAMPTZ-not-TIMESTAMP rule applies when the
--     Rust side actually uses `DateTime<Utc>`, which this service does not.)
--   * `Vec<String>` binds (san_dns/san_ip/san_email/key_usage/
--     extended_key_usage/principals/source_addresses) -> TEXT[]. Always
--     bound (never `Option<Vec<_>>`), so NOT NULL with an empty-array
--     default.
--   * `Json(serde_json::Value)` binds (metadata/critical_options/
--     extensions/request_data/response_data) -> JSONB. Always bound -> NOT
--     NULL with an empty-object default.
--   * `bool`/`i64 as i32`/`&str` bind shapes -> BOOLEAN/INTEGER/TEXT,
--     NOT NULL unless the Rust side binds `Option<_>`.
--
-- No local identity table: auth is centralized at the manager service (this
-- service verifies the shared JWT signature only — see
-- skauswatch_auth::AuthenticatedCaller) — requester_id/actor_id are opaque
-- UUIDs from that external identity space, no FK.

CREATE TABLE IF NOT EXISTS x509_certificates (
    id                      UUID PRIMARY KEY,
    serial_number           TEXT NOT NULL UNIQUE,
    subject                 TEXT NOT NULL,
    issuer                  TEXT NOT NULL,
    not_before               TIMESTAMP NOT NULL,
    not_after                TIMESTAMP NOT NULL,
    key_algorithm            TEXT NOT NULL,
    key_size                 INTEGER,
    signature_algorithm      TEXT NOT NULL,
    fingerprint_sha256        TEXT NOT NULL,
    certificate_pem          TEXT NOT NULL,
    private_key_pem          TEXT,
    csr_pem                  TEXT,
    san_dns                  TEXT[] NOT NULL DEFAULT '{}',
    san_ip                   TEXT[] NOT NULL DEFAULT '{}',
    san_email                TEXT[] NOT NULL DEFAULT '{}',
    key_usage                 TEXT[] NOT NULL DEFAULT '{}',
    extended_key_usage        TEXT[] NOT NULL DEFAULT '{}',
    is_ca                    BOOLEAN NOT NULL DEFAULT false,
    path_length               INTEGER,
    status                   TEXT NOT NULL DEFAULT 'active',
    revoked_at                TIMESTAMP,
    revocation_reason         TEXT,
    requester_id              UUID,
    approval_request_id       UUID,
    metadata                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at                TIMESTAMP NOT NULL DEFAULT now(),
    updated_at                TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_x509_certificates_status ON x509_certificates (status);
CREATE INDEX IF NOT EXISTS idx_x509_certificates_not_after ON x509_certificates (not_after);
CREATE INDEX IF NOT EXISTS idx_x509_certificates_subject ON x509_certificates (subject);

CREATE TABLE IF NOT EXISTS ssh_certificates (
    id                      UUID PRIMARY KEY,
    serial_number            TEXT NOT NULL UNIQUE,
    key_id                   TEXT NOT NULL,
    certificate_type          TEXT NOT NULL CHECK (certificate_type IN ('user', 'host')),
    principals                TEXT[] NOT NULL DEFAULT '{}',
    valid_after               TIMESTAMP NOT NULL,
    valid_before              TIMESTAMP NOT NULL,
    key_type                  TEXT NOT NULL,
    public_key                TEXT NOT NULL,
    certificate               TEXT NOT NULL,
    critical_options          JSONB NOT NULL DEFAULT '{}'::jsonb,
    extensions                JSONB NOT NULL DEFAULT '{}'::jsonb,
    source_address            TEXT[] NOT NULL DEFAULT '{}',
    force_command             TEXT,
    status                   TEXT NOT NULL DEFAULT 'active',
    hostname                  TEXT,
    revoked_at                TIMESTAMP,
    revocation_reason         TEXT,
    requester_id              UUID,
    approval_request_id       UUID,
    metadata                 JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at                TIMESTAMP NOT NULL DEFAULT now(),
    updated_at                TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ssh_certificates_status ON ssh_certificates (status);
CREATE INDEX IF NOT EXISTS idx_ssh_certificates_valid_before ON ssh_certificates (valid_before);
CREATE INDEX IF NOT EXISTS idx_ssh_certificates_principals ON ssh_certificates USING GIN (principals);

-- Polymorphic revocation ledger shared by both CAs (`certificate_type`
-- discriminates which certificates table `certificate_id` points into) —
-- no FK, matching the two possible parents.
CREATE TABLE IF NOT EXISTS crl_entries (
    id                      UUID PRIMARY KEY,
    certificate_id            UUID NOT NULL,
    serial_number             TEXT NOT NULL,
    certificate_type          TEXT NOT NULL CHECK (certificate_type IN ('x509', 'ssh')),
    revoked_at                TIMESTAMP NOT NULL,
    revocation_reason         TEXT NOT NULL,
    created_at                TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_crl_entries_certificate_type ON crl_entries (certificate_type);
CREATE INDEX IF NOT EXISTS idx_crl_entries_certificate_id ON crl_entries (certificate_id);

CREATE TABLE IF NOT EXISTS pki_audit_log (
    id                      UUID PRIMARY KEY,
    event_type                TEXT NOT NULL,
    certificate_type          TEXT,
    certificate_id            UUID,
    serial_number             TEXT,
    subject                  TEXT,
    actor_id                  UUID,
    action                   TEXT NOT NULL,
    status                   TEXT NOT NULL,
    -- Never populated by the current CertManager::audit() (no call site
    -- passes a failure message through it yet), but routes/common.rs's
    -- GET /api/v1/audit handler already selects it — column must exist.
    error_message             TEXT,
    request_data              JSONB NOT NULL DEFAULT '{}'::jsonb,
    response_data             JSONB NOT NULL DEFAULT '{}'::jsonb,
    timestamp                 TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_pki_audit_log_timestamp ON pki_audit_log (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_pki_audit_log_event_type ON pki_audit_log (event_type);
CREATE INDEX IF NOT EXISTS idx_pki_audit_log_certificate_type ON pki_audit_log (certificate_type);
