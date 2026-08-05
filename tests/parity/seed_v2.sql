-- Golden parity harness seed for the v2 side (skauswatch_v2 database).
-- Row-for-row identical to seed_v1.sql except the endpoint-agent tables use
-- the post-rename names (`endpoint_agents`/`endpoint_events`) that the v2
-- Rust manager's sqlx queries expect, PLUS the tenancy/ASM/enrollment
-- schema from services/manager/migrations/0002-0006 that v1 (frozen
-- pre-tenancy) never had. See docs/MIGRATION.md for the full module
-- rename map and docs/v2-port/tenancy-model.md for the tenancy retrofit.
--
-- Base schema is derived from release/v1.0.x:services/manager/models/db.py
-- (SQLAlchemy section — the contract's authoritative 13-table schema);
-- services/manager/migrations/0001_manager_schema.sql documents this file
-- as ITS OWN schema authority for the 9 tables it mirrors, so the tenancy
-- columns/tables below are kept in lockstep with 0002_tenancy.sql,
-- 0003_tenancy_drop_defaults.sql, 0004_svid_ttl_settings.sql,
-- 0005_endpoint_enrollment_tokens.sql, and 0006_asm_schema.sql exactly
-- (column-for-column) rather than re-deriving them independently. v1's
-- startup create_all() is idempotent by table name, so pre-created tables
-- are left untouched.
--
-- All seeded users share the password  Password123!  (bcrypt below). All
-- rows use the fixed bootstrap tenant ('00000000-0000-0000-0000-000000000001',
-- matching skauswatch_manager::auth::DEFAULT_TENANT_ID) — the harness has
-- exactly one tenant, so every FK'd row explicitly stamps it (no reliance on
-- a column DEFAULT: 0003 drops the transitional default 0002 shipped with,
-- and users/refresh_tokens never had one). All timestamps are fixed
-- literals so both sides render identical strings.

BEGIN;

-- ── tenants (0002_tenancy.sql) ──────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        VARCHAR(63) UNIQUE NOT NULL,
    name        VARCHAR(255) NOT NULL,
    status      VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    created_at  TIMESTAMP NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP
);

INSERT INTO tenants (id, slug, name, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default Tenant', 'active');

-- ── users ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255),
    role VARCHAR(20) NOT NULL DEFAULT 'viewer',
    is_active BOOLEAN DEFAULT true,
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret VARCHAR(32),
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP,
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users (tenant_id, id);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_hash VARCHAR(255) UNIQUE,
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT now(),
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_id ON refresh_tokens (tenant_id, id);

CREATE TABLE IF NOT EXISTS threat_indicators (
    id SERIAL PRIMARY KEY,
    indicator_type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    threat_level VARCHAR(20),
    confidence DOUBLE PRECISION,
    source VARCHAR(100),
    tags JSONB,
    metadata JSONB,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP,
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_tenant_id ON threat_indicators (tenant_id, id);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    source VARCHAR(100),
    indicators JSONB,
    ai_review JSONB,
    assigned_to INTEGER,
    resolved_at TIMESTAMP,
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP,
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status ON alerts (tenant_id, status);

CREATE TABLE IF NOT EXISTS approval_requests (
    id SERIAL PRIMARY KEY,
    request_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(128),
    resource_type VARCHAR(50),
    requester_id INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    required_approvals INTEGER DEFAULT 1,
    current_approvals INTEGER DEFAULT 0,
    approvers JSONB,
    approval_history JSONB,
    expires_at TIMESTAMP,
    completed_at TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP,
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_approval_requests_tenant_status ON approval_requests (tenant_id, status);

CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64),
    resource_id VARCHAR(128),
    user_id INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    details JSONB,
    severity VARCHAR(16) DEFAULT 'info',
    created_at TIMESTAMP DEFAULT now(),
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs (tenant_id, created_at);

CREATE TABLE IF NOT EXISTS endpoint_agents (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(128) UNIQUE NOT NULL,
    hostname VARCHAR(255),
    ip_address VARCHAR(45),
    os_type VARCHAR(50),
    os_version VARCHAR(100),
    agent_version VARCHAR(32),
    status VARCHAR(20) DEFAULT 'active',
    last_heartbeat TIMESTAMP,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP,
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_agents_tenant_agent ON endpoint_agents (tenant_id, agent_id);

CREATE TABLE IF NOT EXISTS endpoint_events (
    id SERIAL PRIMARY KEY,
    agent_id VARCHAR(128) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(20),
    process_name VARCHAR(255),
    process_path TEXT,
    process_hash VARCHAR(128),
    parent_process VARCHAR(255),
    command_line TEXT,
    network_connections JSONB,
    file_operations JSONB,
    registry_operations JSONB,
    details JSONB,
    created_at TIMESTAMP DEFAULT now(),
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_endpoint_events_tenant_agent ON endpoint_events (tenant_id, agent_id);

-- s3scan-owned; schema authority is services/s3scan/migrations/0001_s3scan_schema.sql
-- + 0002_s3scan_tenancy.sql (hybrid credential model, security finding #2:
-- plaintext access_key_id/secret_access_key columns are GONE, replaced by
-- credential_mode ('static'|'assume_role') + credential_enc (envelope-
-- encrypted JSON blob, static mode only) + role_arn/external_id (assume_role
-- mode only) — see crates/skauswatch-vault/src/crypto.rs::encrypt_json).
CREATE TABLE IF NOT EXISTS s3_bucket_configs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    endpoint_url VARCHAR(255) NOT NULL,
    bucket_name VARCHAR(255) NOT NULL,
    credential_mode VARCHAR(20) NOT NULL DEFAULT 'static',
    credential_enc TEXT,
    role_arn VARCHAR(2048),
    external_id VARCHAR(1224),
    region VARCHAR(50),
    use_ssl BOOLEAN DEFAULT true,
    path_style BOOLEAN DEFAULT false,
    prefix_filter VARCHAR(255),
    file_types_filter JSONB,
    max_file_size_mb INTEGER DEFAULT 100,
    scan_enabled BOOLEAN DEFAULT true,
    yara_enabled BOOLEAN DEFAULT false,
    created_by INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP,
    tenant_id UUID NOT NULL,
    CONSTRAINT s3_bucket_configs_credential_mode_check
        CHECK (credential_mode IN ('assume_role', 'static')),
    CONSTRAINT s3_bucket_configs_credential_shape_check CHECK (
        (credential_mode = 'assume_role' AND role_arn IS NOT NULL)
        OR
        (credential_mode = 'static' AND credential_enc IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS idx_s3_bucket_configs_tenant_id ON s3_bucket_configs (tenant_id, id);

CREATE TABLE IF NOT EXISTS s3_scan_jobs (
    id SERIAL PRIMARY KEY,
    job_id VARCHAR(36) UNIQUE NOT NULL,
    bucket_config_id INTEGER NOT NULL,
    job_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    total_objects INTEGER DEFAULT 0,
    scanned_objects INTEGER DEFAULT 0,
    infected_objects INTEGER DEFAULT 0,
    pup_objects INTEGER DEFAULT 0,
    skipped_objects INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    triggered_by INTEGER NOT NULL,
    error_message TEXT,
    metadata JSONB,
    created_at TIMESTAMP DEFAULT now(),
    tenant_id UUID NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_s3_scan_jobs_tenant_job ON s3_scan_jobs (tenant_id, job_id);
CREATE INDEX IF NOT EXISTS idx_s3_scan_jobs_tenant_id ON s3_scan_jobs (tenant_id, id);

CREATE TABLE IF NOT EXISTS s3_scan_results (
    id SERIAL PRIMARY KEY,
    job_id INTEGER NOT NULL,
    bucket_config_id INTEGER NOT NULL,
    object_key TEXT NOT NULL,
    object_size INTEGER,
    object_etag VARCHAR(128),
    content_type VARCHAR(128),
    detected_file_type VARCHAR(64),
    scan_status VARCHAR(20),
    is_malware BOOLEAN DEFAULT false,
    is_pup BOOLEAN DEFAULT false,
    is_threat BOOLEAN DEFAULT false,
    threat_names JSONB,
    clamav_result JSONB,
    yara_matches JSONB,
    file_md5 VARCHAR(32),
    file_sha1 VARCHAR(40),
    file_sha256 VARCHAR(64),
    ti_enrichment JSONB,
    ti_indicator_created BOOLEAN DEFAULT false,
    ti_indicator_id INTEGER,
    sandbox_submitted BOOLEAN DEFAULT false,
    sandbox_task_id VARCHAR(128),
    sandbox_status VARCHAR(20),
    sandbox_result JSONB,
    sandbox_completed_at TIMESTAMP,
    scan_duration_ms INTEGER,
    tags_applied JSONB,
    scanned_at TIMESTAMP,
    tenant_id UUID NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_s3_scan_results_tenant_job ON s3_scan_results (tenant_id, job_id);

CREATE TABLE IF NOT EXISTS adhoc_scan_results (
    id SERIAL PRIMARY KEY,
    scan_id VARCHAR(36) UNIQUE NOT NULL,
    uploaded_by INTEGER NOT NULL,
    original_filename VARCHAR(255) NOT NULL,
    file_size INTEGER,
    content_type VARCHAR(128),
    detected_file_type VARCHAR(64),
    scan_status VARCHAR(20),
    is_malware BOOLEAN DEFAULT false,
    is_pup BOOLEAN DEFAULT false,
    is_threat BOOLEAN DEFAULT false,
    threat_names JSONB,
    file_md5 VARCHAR(32),
    file_sha1 VARCHAR(40),
    file_sha256 VARCHAR(64),
    clamav_result JSONB,
    yara_matches JSONB,
    ti_enrichment JSONB,
    sandbox_submitted BOOLEAN DEFAULT false,
    sandbox_result JSONB,
    scan_duration_ms INTEGER,
    uploaded_at TIMESTAMP DEFAULT now(),
    scanned_at TIMESTAMP,
    expires_at TIMESTAMP,
    tenant_id UUID NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_adhoc_scan_results_tenant_scan ON adhoc_scan_results (tenant_id, scan_id);

CREATE TABLE IF NOT EXISTS s3_scan_schedules (
    id SERIAL PRIMARY KEY,
    bucket_config_id INTEGER UNIQUE NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    timezone VARCHAR(50) DEFAULT 'UTC',
    enabled BOOLEAN DEFAULT true,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP,
    tenant_id UUID NOT NULL REFERENCES tenants(id)
);
CREATE INDEX IF NOT EXISTS idx_s3_scan_schedules_tenant_id ON s3_scan_schedules (tenant_id, id);

-- ── svid_ttl_settings (0004_svid_ttl_settings.sql) — no seed row; a
-- missing row means "never configured" and the admin.rs handler (not
-- exercised by this corpus) falls back to its documented defaults. -------
CREATE TABLE IF NOT EXISTS svid_ttl_settings (
    id               SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    x509_ttl_seconds INTEGER NOT NULL DEFAULT 300 CHECK (x509_ttl_seconds BETWEEN 60 AND 86400),
    jwt_ttl_seconds  INTEGER NOT NULL DEFAULT 300 CHECK (jwt_ttl_seconds BETWEEN 60 AND 86400),
    updated_by       INTEGER REFERENCES users(id),
    updated_at       TIMESTAMP NOT NULL DEFAULT now()
);

-- ── endpoint_enrollment_tokens (0005_endpoint_enrollment_tokens.sql) —
-- seeds ONE single-use token scoped to the bootstrap tenant so
-- `edr.register.new-agent` can exercise the real v2 `register_agent` new-
-- agent path (routes/endpoint.rs §resolve_enrollment_token) instead of
-- being allowlisted around it. Raw token
-- "parity-fixed-enrollment-token-0001"; token_hash below is its SHA-256 hex
-- digest (`skauswatch_manager::auth::token_hash`) — the raw value is never
-- itself stored, matching how the real mint endpoint works. Re-registration
-- of already-seeded agents (alpha/beta/gamma) never consults this table.
CREATE TABLE IF NOT EXISTS endpoint_enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    max_uses    INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    use_count   INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    expires_at  TIMESTAMP NOT NULL,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TIMESTAMP NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON endpoint_enrollment_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_tenant ON endpoint_enrollment_tokens (tenant_id);

-- ── ASM (0006_asm_schema.sql) — no seed rows; the corpus's asm.scans.get/
-- hosts/screenshots/certs/diff/report cases target a nonexistent scan id
-- (404 on both sides) and asm.scans.create writes its own row at runtime
-- with tenant_id from the caller's JWT. Tables only need to exist. --------
CREATE TABLE IF NOT EXISTS asm_scans (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    target          TEXT NOT NULL,
    mode            TEXT NOT NULL DEFAULT 'external' CHECK (mode IN ('internal', 'external', 'both')),
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    ports_config    JSONB,
    error_message   TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT now(),
    started_at      TIMESTAMP,
    completed_at    TIMESTAMP,
    created_by      INTEGER REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_asm_scans_tenant_id ON asm_scans (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_asm_scans_tenant_target ON asm_scans (tenant_id, target, status);

CREATE TABLE IF NOT EXISTS asm_hosts (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         BIGINT NOT NULL REFERENCES asm_scans(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL,
    ip_address      TEXT NOT NULL,
    hostname        TEXT,
    is_alive        BOOLEAN NOT NULL DEFAULT TRUE,
    latency_ms      DOUBLE PRECISION,
    os_guess        TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_asm_hosts_tenant_scan ON asm_hosts (tenant_id, scan_id);

CREATE TABLE IF NOT EXISTS asm_services (
    id              BIGSERIAL PRIMARY KEY,
    host_id         BIGINT NOT NULL REFERENCES asm_hosts(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT NOT NULL DEFAULT 'tcp',
    state           TEXT NOT NULL DEFAULT 'open',
    service_name    TEXT,
    banner          TEXT,
    version         TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_asm_services_tenant_host ON asm_services (tenant_id, host_id);

CREATE TABLE IF NOT EXISTS asm_screenshots (
    id                  BIGSERIAL PRIMARY KEY,
    service_id          BIGINT NOT NULL REFERENCES asm_services(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    s3_key              TEXT NOT NULL,
    url                 TEXT,
    tool                TEXT NOT NULL,
    width               INTEGER,
    height              INTEGER,
    file_size_bytes     INTEGER,
    captured_at         TIMESTAMP,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_asm_screenshots_tenant_service ON asm_screenshots (tenant_id, service_id);

CREATE TABLE IF NOT EXISTS asm_certs (
    id                  BIGSERIAL PRIMARY KEY,
    service_id          BIGINT NOT NULL REFERENCES asm_services(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    subject             TEXT,
    issuer              TEXT,
    not_before          TIMESTAMP,
    not_after           TIMESTAMP,
    is_expired          BOOLEAN NOT NULL DEFAULT FALSE,
    days_until_expiry   INTEGER,
    sans                JSONB,
    fingerprint_sha256  TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_asm_certs_tenant_service ON asm_certs (tenant_id, service_id);

CREATE TABLE IF NOT EXISTS asm_diffs (
    id                  BIGSERIAL PRIMARY KEY,
    scan_id             BIGINT NOT NULL REFERENCES asm_scans(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    prev_scan_id        BIGINT REFERENCES asm_scans(id),
    new_services        JSONB,
    removed_services    JSONB,
    new_certs           JSONB,
    expired_certs       JSONB,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_asm_diffs_tenant_scan ON asm_diffs (tenant_id, scan_id);

CREATE TABLE IF NOT EXISTS asm_settings (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    key             TEXT NOT NULL,
    value           JSONB,
    updated_at      TIMESTAMP NOT NULL DEFAULT now(),
    updated_by      INTEGER REFERENCES users(id),
    UNIQUE (tenant_id, key)
);

-- ── data ─────────────────────────────────────────────────────────────────
-- bcrypt("Password123!")
-- 1 admin / 2 maintainer / 3 viewer / 4 deactivated viewer
INSERT INTO users (id, email, password_hash, full_name, role, is_active, mfa_enabled, failed_login_attempts, created_at, updated_at, tenant_id) VALUES
 (1, 'admin@skauswatch.dev',    '$2b$12$4Xs5MxSBP02SnKBjfjM0/eJKuppYZ9o9Y0olIlFUmV24UsnigVZrO', 'Ada Admin',        'admin',      true,  false, 0, '2026-06-01 08:00:00',        NULL, '00000000-0000-0000-0000-000000000001'),
 (2, 'maint@skauswatch.dev',    '$2b$12$4Xs5MxSBP02SnKBjfjM0/eJKuppYZ9o9Y0olIlFUmV24UsnigVZrO', 'Mick Maintainer',  'maintainer', true,  false, 0, '2026-06-01 08:05:00.123456', NULL, '00000000-0000-0000-0000-000000000001'),
 (3, 'viewer@skauswatch.dev',   '$2b$12$4Xs5MxSBP02SnKBjfjM0/eJKuppYZ9o9Y0olIlFUmV24UsnigVZrO', 'Vera Viewer',      'viewer',     true,  false, 0, '2026-06-01 08:10:00',        NULL, '00000000-0000-0000-0000-000000000001'),
 (4, 'inactive@skauswatch.dev', '$2b$12$4Xs5MxSBP02SnKBjfjM0/eJKuppYZ9o9Y0olIlFUmV24UsnigVZrO', 'Ivan Inactive',    'viewer',     false, false, 0, '2026-06-01 08:15:00',        '2026-06-02 09:00:00', '00000000-0000-0000-0000-000000000001');
SELECT setval('users_id_seq', 4);

-- 4 valid IOCs + 1 expired. Hash value uppercase (HashLookupRequest upcases).
INSERT INTO threat_indicators (id, indicator_type, value, threat_level, confidence, source, tags, metadata, expires_at, created_at, updated_at, tenant_id) VALUES
 (1, 'ip',     '203.0.113.7',                                                       'high',     0.9,  'otx',        '["botnet","c2"]',  '{"asn": 64500}',            NULL,                  '2026-06-10 12:00:00',        NULL, '00000000-0000-0000-0000-000000000001'),
 (2, 'domain', 'evil.example.com',                                                  'critical', 0.95, 'virustotal', '["phishing"]',     '{}',                        NULL,                  '2026-06-10 12:05:00.500000', NULL, '00000000-0000-0000-0000-000000000001'),
 (3, 'hash',   'A94A8FE5CCB19BA61C4C0873D391E987982FBBD3B5D4E9C7A3F1E2D4C5B6A798', 'medium',   0.5,  'manual',     '[]',               '{"note": "sample sha256"}', NULL,                  '2026-06-10 12:10:00',        NULL, '00000000-0000-0000-0000-000000000001'),
 (4, 'url',    'http://bad.example/malware.bin',                                    'low',      0.3,  'otx',        '["dropper"]',      '{}',                        NULL,                  '2026-06-10 12:15:00',        NULL, '00000000-0000-0000-0000-000000000001'),
 (5, 'ip',     '192.0.2.66',                                                        'high',     0.8,  'otx',        '["expired"]',      '{}',                        '2020-01-01 00:00:00', '2019-12-01 00:00:00',        NULL, '00000000-0000-0000-0000-000000000001');
SELECT setval('threat_indicators_id_seq', 5);

INSERT INTO alerts (id, title, description, severity, status, source, indicators, ai_review, assigned_to, resolved_at, resolution_notes, created_at, updated_at, tenant_id) VALUES
 (1, 'C2 beacon detected',        'Endpoint beaconing to a known C2 host.',  'critical', 'pending',        'endpoint',    '["203.0.113.7"]',        NULL, NULL, NULL,                  NULL,             '2026-06-15 09:00:00',        NULL, '00000000-0000-0000-0000-000000000001'),
 (2, 'Suspicious login pattern',  'Multiple failed logins then success.',    'high',     'in_progress',    'siem',   '[]',                     NULL, 2,    NULL,                  NULL,             '2026-06-15 09:30:00.250000', NULL, '00000000-0000-0000-0000-000000000001'),
 (3, 'Malware quarantined',       'ClamAV quarantined an infected upload.',  'medium',   'resolved',       'manual', '["evil.example.com"]',   NULL, 1,    '2026-06-16 10:00:00', 'Cleaned by AV.', '2026-06-15 10:00:00',        '2026-06-16 10:00:00', '00000000-0000-0000-0000-000000000001'),
 (4, 'Port scan (benign)',        'Internal scanner traffic.',               'info',     'false_positive', 'endpoint',    '[]',                     NULL, NULL, NULL,                  NULL,             '2026-06-15 11:00:00',        NULL, '00000000-0000-0000-0000-000000000001');
SELECT setval('alerts_id_seq', 4);

-- A1 pending cert (requester maintainer, needs 2); A2 pending user (requester
-- admin, needs 1); A3 approved configuration (completed); A4 expired-pending.
INSERT INTO approval_requests (id, request_type, resource_id, resource_type, requester_id, status, required_approvals, current_approvals, approvers, approval_history, expires_at, completed_at, metadata, created_at, updated_at, tenant_id) VALUES
 (1, 'certificate',   'cert-42',  'tls_certificate', 2, 'pending',  2, 0, '[]',  '[]', '2030-01-01 00:00:00', NULL,                  '{"cn": "svc.example.com"}', '2026-06-20 08:00:00', NULL, '00000000-0000-0000-0000-000000000001'),
 (2, 'user',          'user-9',   'user_account',    1, 'pending',  1, 0, '[]',  '[]', '2030-01-01 00:00:00', NULL,                  '{}',                        '2026-06-20 08:10:00', NULL, '00000000-0000-0000-0000-000000000001'),
 (3, 'configuration', 'cfg-7',    'siem_config',     2, 'approved', 1, 1, '[1]', '[{"user_id": 1, "user_email": "admin@skauswatch.dev", "approved": true, "reason": "ok", "timestamp": "2026-06-21T09:00:00"}]', '2030-01-01 00:00:00', '2026-06-21 09:00:00', '{}', '2026-06-20 08:20:00', '2026-06-21 09:00:00', '00000000-0000-0000-0000-000000000001'),
 (4, 'service',       'svc-3',    'service_account', 3, 'pending',  1, 0, '[]',  '[]', '2020-01-01 00:00:00', NULL,                  '{}',                        '2019-12-20 08:30:00', NULL, '00000000-0000-0000-0000-000000000001');
SELECT setval('approval_requests_id_seq', 4);

INSERT INTO endpoint_agents (id, agent_id, hostname, ip_address, os_type, os_version, agent_version, status, last_heartbeat, metadata, created_at, updated_at, tenant_id) VALUES
 (1, 'agent-alpha', 'web-01.corp',  '10.0.0.11', 'linux',   'Ubuntu 24.04',  '1.4.2', 'active',   '2026-07-01 06:00:00', '{"site": "dal2"}',                     '2026-05-01 07:00:00', NULL, '00000000-0000-0000-0000-000000000001'),
 (2, 'agent-beta',  'win-02.corp',  '10.0.0.12', 'windows', 'Windows 11',    '1.4.2', 'active',   '2026-07-01 06:05:00', '{"reporting_interval": 120}',          '2026-05-01 07:05:00', NULL, '00000000-0000-0000-0000-000000000001'),
 (3, 'agent-gamma', 'mac-03.corp',  '10.0.0.13', 'macos',   'macOS 15.1',    '1.3.9', 'inactive', '2026-06-01 06:10:00', '{}',                                   '2026-05-01 07:10:00', NULL, '00000000-0000-0000-0000-000000000001');
SELECT setval('endpoint_agents_id_seq', 3);

-- Single-use enrollment token for `edr.register.new-agent` (agent-delta) —
-- raw token "parity-fixed-enrollment-token-0001", hash below is its SHA-256
-- hex digest. See the CREATE TABLE comment above for why this is seeded.
INSERT INTO endpoint_enrollment_tokens (tenant_id, token_hash, max_uses, expires_at, created_by) VALUES
 ('00000000-0000-0000-0000-000000000001', 'c0e2d4551410b80451d45c8d28a9bfbb674e95381e38d7c7e95931f550f4d025', 1, '2030-01-01 00:00:00', 1);

INSERT INTO endpoint_events (id, agent_id, event_type, severity, process_name, process_path, process_hash, parent_process, command_line, network_connections, file_operations, registry_operations, details, created_at, tenant_id) VALUES
 (1, 'agent-alpha', 'process_start',      'low',      'bash',   '/usr/bin/bash',   NULL,       'sshd',    'bash -c id',                 NULL,                                        NULL, NULL, '{}',                       '2026-07-01 05:00:00', '00000000-0000-0000-0000-000000000001'),
 (2, 'agent-alpha', 'network_connection', 'high',     'curl',   '/usr/bin/curl',   'abc123',   'bash',    'curl http://203.0.113.7/x',  '[{"dst": "203.0.113.7", "port": 80}]',      NULL, NULL, '{"direction": "outbound"}', '2026-07-01 05:10:00', '00000000-0000-0000-0000-000000000001'),
 (3, 'agent-alpha', 'file_write',         'medium',   'python', '/usr/bin/python', NULL,       'bash',    'python drop.py',             NULL, '[{"path": "/tmp/drop.bin", "op": "write"}]', NULL, '{}',                  '2026-07-01 05:20:00.750000', '00000000-0000-0000-0000-000000000001');
SELECT setval('endpoint_events_id_seq', 3);

-- Buckets point at the shared stub upstream; path_style so no virtual-host DNS.
-- credential_enc blobs are real skauswatch_vault::EnvelopeEncryption::
-- encrypt_json output (AES-256-GCM, random nonce) under this harness's fixed
-- VAULT_MEK (see run.sh), wrapping {"access_key_id","secret_access_key"} —
-- generated out-of-band with the same construction the crate implements;
-- plaintext keys are never stored, matching the schema's whole point.
INSERT INTO s3_bucket_configs (id, name, endpoint_url, bucket_name, credential_mode, credential_enc, region, use_ssl, path_style, prefix_filter, file_types_filter, max_file_size_mb, scan_enabled, yara_enabled, created_by, created_at, updated_at, tenant_id) VALUES
 (1, 'prod-artifacts', 'http://parity-stub:9999', 'artifacts',  'static', '{"ciphertext":"t/r+zgcAel/f4ysMMsjSpNecu+YVDchChIATOpZ9eBC6mMffDBiJEM2+C1KoDzmxqY/tR9DlRCXrFDiu09+i09q2XOnnO8oB4utWHpwi2/2w/XxlSNXFQDPTcarnTiJ1xWYKqWjTqj5WMjMa","dek":"vF3EbkEfN+M/tUygWOu6X2ALzNP3x4L1m0fajeKb0lZuYRvtyhAbiilKCUVzjNwUXAHOOFAlGXSqaWYR","version":1}', 'us-east-1', false, true, NULL,        '[".exe", ".zip"]', 100, true,  false, 1, '2026-06-25 07:00:00', NULL, '00000000-0000-0000-0000-000000000001'),
 (2, 'backup-cold',    'http://parity-stub:9999', 'backups',    'static', '{"ciphertext":"C3iQRiPumVFlMJi3zOQKP1GRJ5yuJlSMwB4QsznMwBL9c33BgFDpsctH7A62suxP36uBJpgxeUM+sPtK+4S+4oZ08k9yHShXFfhOL3eA8mTqyP8+pXHFNcMp6al6J1Gc7jvV5eBIeo88OTVKuw==","dek":"KOShNnIjTeBYAvRD0V1/3K3H1+qUrUfIQk+qsMs+IFWh4yiiK4uegjfoYxxoPxcs0o+H1PEsCxmUAwFj","version":1}', 'us-east-1', false, true, 'cold/',     '[]',               250, false, false, 1, '2026-06-25 07:05:00', NULL, '00000000-0000-0000-0000-000000000001'),
 (3, 'uploads-hot',    'http://parity-stub:9999', 'uploads',    'static', '{"ciphertext":"Nptd2U1kScuEVupgPhcg2ZvJEewg/pIdRsmYQco21ftmdbSqWa+L8htGPZF0SVo0JVTYvF8sl60wLbDBxnnCPYchYkoDRxNlcSy7/mrltK9Vggvaq9FhoSAEK74g5KOeo3leJA75Sm2HszIUOg==","dek":"H477ALtli4D2YeFSgR3G37CjA0+SwpbnWo1Hb9SkPBdLiiDOFhoRXoG2LcEs3LR4RCGXa6G/RZTOkILM","version":1}', 'us-west-2', false, true, NULL,        '[]',               100, true,  true,  2, '2026-06-25 07:10:00', NULL, '00000000-0000-0000-0000-000000000001');
SELECT setval('s3_bucket_configs_id_seq', 3);

INSERT INTO s3_scan_jobs (id, job_id, bucket_config_id, job_type, status, total_objects, scanned_objects, infected_objects, pup_objects, skipped_objects, error_count, started_at, completed_at, triggered_by, error_message, metadata, created_at, tenant_id) VALUES
 (1, '11111111-1111-4111-8111-111111111111', 1, 'full_scan',        'completed', 10, 8, 1, 0, 1, 0, '2026-06-26 01:00:00', '2026-06-26 01:30:00', 1, NULL,           '{}', '2026-06-26 00:59:00', '00000000-0000-0000-0000-000000000001'),
 (2, '22222222-2222-4222-8222-222222222222', 1, 'incremental_scan', 'running',    5, 2, 0, 0, 0, 0, '2026-06-27 01:00:00', NULL,                  2, NULL,           '{}', '2026-06-27 00:59:00', '00000000-0000-0000-0000-000000000001'),
 (3, '33333333-3333-4333-8333-333333333333', 1, 'prefix_scan',      'cancelled',  0, 0, 0, 0, 0, 0, NULL,                  '2026-06-28 02:00:00', 1, 'cancelled',    '{}', '2026-06-28 01:59:00', '00000000-0000-0000-0000-000000000001');
SELECT setval('s3_scan_jobs_id_seq', 3);

INSERT INTO s3_scan_results (id, job_id, bucket_config_id, object_key, object_size, object_etag, content_type, detected_file_type, scan_status, is_malware, is_pup, is_threat, threat_names, clamav_result, yara_matches, file_md5, file_sha1, file_sha256, ti_enrichment, ti_indicator_created, ti_indicator_id, sandbox_submitted, sandbox_task_id, sandbox_status, sandbox_result, sandbox_completed_at, scan_duration_ms, tags_applied, scanned_at, tenant_id) VALUES
 (1, 1, 1, 'docs/report.pdf',  20480,  'etag-1', 'application/pdf',      'pdf', 'completed', false, false, false, '[]',                    '{"clean": true}',                  '[]',              'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', NULL, 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', NULL, false, NULL, false, NULL, NULL, NULL, NULL, 152,  '[]', '2026-06-26 01:05:00', '00000000-0000-0000-0000-000000000001'),
 (2, 1, 1, 'bin/dropper.exe',  512000, 'etag-2', 'application/x-dosexec','exe', 'completed', true,  false, true,  '["Win.Trojan.Agent"]',  '{"clean": false, "virus": "Win.Trojan.Agent"}', '["rule_pe_packed"]', 'cccccccccccccccccccccccccccccccc', NULL, 'A94A8FE5CCB19BA61C4C0873D391E987982FBBD3B5D4E9C7A3F1E2D4C5B6A798', NULL, false, NULL, false, NULL, NULL, NULL, NULL, 890,  '[]', '2026-06-26 01:10:00', '00000000-0000-0000-0000-000000000001'),
 (3, 2, 1, 'incoming/new.zip', 1024,   'etag-3', 'application/zip',      NULL,  'pending',   false, false, false, '[]',                    NULL,                               NULL,              NULL,                               NULL, NULL,                                                                NULL, false, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL, '2026-06-27 01:05:00', '00000000-0000-0000-0000-000000000001');
SELECT setval('s3_scan_results_id_seq', 3);

INSERT INTO adhoc_scan_results (id, scan_id, uploaded_by, original_filename, file_size, content_type, detected_file_type, scan_status, is_malware, is_pup, is_threat, threat_names, file_md5, file_sha1, file_sha256, clamav_result, yara_matches, ti_enrichment, sandbox_submitted, sandbox_result, scan_duration_ms, uploaded_at, scanned_at, expires_at, tenant_id) VALUES
 (1, '44444444-4444-4444-8444-444444444444', 1, 'sample.pdf', 1000, 'application/pdf', 'pdf', 'completed', false, false, false, '[]', 'dddddddddddddddddddddddddddddddd', NULL, 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE', '{"clean": true}', '[]', NULL, false, NULL, 42, '2026-06-29 09:00:00', '2026-06-29 09:00:05', NULL, '00000000-0000-0000-0000-000000000001'),
 (2, '55555555-5555-4555-8555-555555555555', 3, 'notes.zip',  2000, 'application/zip', 'zip', 'completed', false, false, false, '[]', 'ffffffffffffffffffffffffffffffff', NULL, '9999999999999999999999999999999999999999999999999999999999999999', '{"clean": true}', '[]', NULL, false, NULL, 77, '2026-06-29 09:10:00', '2026-06-29 09:10:04', NULL, '00000000-0000-0000-0000-000000000001');
SELECT setval('adhoc_scan_results_id_seq', 2);

INSERT INTO s3_scan_schedules (id, bucket_config_id, cron_expression, timezone, enabled, last_run_at, next_run_at, created_at, updated_at, tenant_id) VALUES
 (1, 1, '0 2 * * *', 'UTC', true, '2026-06-30 02:00:00', '2026-07-01 02:00:00', '2026-06-25 08:00:00', NULL, '00000000-0000-0000-0000-000000000001');
SELECT setval('s3_scan_schedules_id_seq', 1);

COMMIT;
