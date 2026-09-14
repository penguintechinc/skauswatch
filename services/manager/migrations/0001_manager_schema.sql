-- Manager service schema (v2 Rust port).
--
-- Table shapes are derived from the live schema authority
-- (`tests/parity/seed_v2.sql`), restricted to the tables this service's
-- sqlx queries actually read/write: `users`, `refresh_tokens`,
-- `threat_indicators`, `alerts`, `approval_requests`, `audit_logs`,
-- `endpoint_agents`, `endpoint_events`. Column types match the
-- `sqlx::FromRow`/`query_as` bindings across `src/` exactly — every
-- `created_at`/`updated_at`/... binding here is a plain `chrono::NaiveDateTime`
-- (never `DateTime<Utc>`), so `TIMESTAMP` (no time zone) is correct, matching
-- the seed authority with no type-parity risk.
--
-- `s3_scan_schedules` is ALSO included here even though its name suggests
-- the s3scan family: only manager's `routes/s3_scan.rs` (get/set/delete
-- schedule) ever queries it — `services/s3scan/migrations/0001_s3scan_schema.sql`
-- explicitly documents it as "manager-owned" and omits it from the worker's
-- schema. `s3_bucket_configs`/`s3_scan_jobs`/`s3_scan_results`/
-- `adhoc_scan_results` remain s3scan-owned and are NOT duplicated here —
-- manager-side tests that need them layer this migration together with
-- s3scan's via `skauswatch_testkit::db::test_pool_multi`.

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
    updated_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token_hash VARCHAR(255) UNIQUE,
    expires_at TIMESTAMP,
    revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT now()
);

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
    updated_at TIMESTAMP
);

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
    updated_at TIMESTAMP
);

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
    updated_at TIMESTAMP
);

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
    created_at TIMESTAMP DEFAULT now()
);

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
    updated_at TIMESTAMP
);

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
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE IF NOT EXISTS s3_scan_schedules (
    id SERIAL PRIMARY KEY,
    bucket_config_id INTEGER UNIQUE NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    timezone VARCHAR(50) DEFAULT 'UTC',
    enabled BOOLEAN DEFAULT true,
    last_run_at TIMESTAMP,
    next_run_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP
);
