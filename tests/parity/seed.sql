-- Golden parity harness seed — applied identically to skauswatch_v1 and
-- skauswatch_v2 so both managers see byte-identical state.
--
-- Schema is derived from services/manager/models/db.py (SQLAlchemy section —
-- the contract's authoritative 13-table schema). v1's startup create_all()
-- is idempotent by table name, so pre-created tables are left untouched.
--
-- All seeded users share the password  Password123!  (bcrypt below).
-- All timestamps are fixed literals so both sides render identical strings.

BEGIN;

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

CREATE TABLE IF NOT EXISTS edr_agents (
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

CREATE TABLE IF NOT EXISTS edr_events (
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

CREATE TABLE IF NOT EXISTS s3_bucket_configs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL,
    endpoint_url VARCHAR(255) NOT NULL,
    bucket_name VARCHAR(255) NOT NULL,
    access_key_id VARCHAR(255) NOT NULL,
    secret_access_key VARCHAR(255) NOT NULL,
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
    updated_at TIMESTAMP
);

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
    created_at TIMESTAMP DEFAULT now()
);

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
    scanned_at TIMESTAMP
);

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
    expires_at TIMESTAMP
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

-- ── data ─────────────────────────────────────────────────────────────────
-- bcrypt("Password123!")
-- 1 admin / 2 maintainer / 3 viewer / 4 deactivated viewer
INSERT INTO users (id, email, password_hash, full_name, role, is_active, mfa_enabled, failed_login_attempts, created_at, updated_at) VALUES
 (1, 'admin@skauswatch.dev',    '$2b$12$4Xs5MxSBP02SnKBjfjM0/eJKuppYZ9o9Y0olIlFUmV24UsnigVZrO', 'Ada Admin',        'admin',      true,  false, 0, '2026-06-01 08:00:00',        NULL),
 (2, 'maint@skauswatch.dev',    '$2b$12$4Xs5MxSBP02SnKBjfjM0/eJKuppYZ9o9Y0olIlFUmV24UsnigVZrO', 'Mick Maintainer',  'maintainer', true,  false, 0, '2026-06-01 08:05:00.123456', NULL),
 (3, 'viewer@skauswatch.dev',   '$2b$12$4Xs5MxSBP02SnKBjfjM0/eJKuppYZ9o9Y0olIlFUmV24UsnigVZrO', 'Vera Viewer',      'viewer',     true,  false, 0, '2026-06-01 08:10:00',        NULL),
 (4, 'inactive@skauswatch.dev', '$2b$12$4Xs5MxSBP02SnKBjfjM0/eJKuppYZ9o9Y0olIlFUmV24UsnigVZrO', 'Ivan Inactive',    'viewer',     false, false, 0, '2026-06-01 08:15:00',        '2026-06-02 09:00:00');
SELECT setval('users_id_seq', 4);

-- 4 valid IOCs + 1 expired. Hash value uppercase (HashLookupRequest upcases).
INSERT INTO threat_indicators (id, indicator_type, value, threat_level, confidence, source, tags, metadata, expires_at, created_at, updated_at) VALUES
 (1, 'ip',     '203.0.113.7',                                                       'high',     0.9,  'otx',        '["botnet","c2"]',  '{"asn": 64500}',            NULL,                  '2026-06-10 12:00:00',        NULL),
 (2, 'domain', 'evil.example.com',                                                  'critical', 0.95, 'virustotal', '["phishing"]',     '{}',                        NULL,                  '2026-06-10 12:05:00.500000', NULL),
 (3, 'hash',   'A94A8FE5CCB19BA61C4C0873D391E987982FBBD3B5D4E9C7A3F1E2D4C5B6A798', 'medium',   0.5,  'manual',     '[]',               '{"note": "sample sha256"}', NULL,                  '2026-06-10 12:10:00',        NULL),
 (4, 'url',    'http://bad.example/malware.bin',                                    'low',      0.3,  'otx',        '["dropper"]',      '{}',                        NULL,                  '2026-06-10 12:15:00',        NULL),
 (5, 'ip',     '192.0.2.66',                                                        'high',     0.8,  'otx',        '["expired"]',      '{}',                        '2020-01-01 00:00:00', '2019-12-01 00:00:00',        NULL);
SELECT setval('threat_indicators_id_seq', 5);

INSERT INTO alerts (id, title, description, severity, status, source, indicators, ai_review, assigned_to, resolved_at, resolution_notes, created_at, updated_at) VALUES
 (1, 'C2 beacon detected',        'Endpoint beaconing to a known C2 host.',  'critical', 'pending',        'edr',    '["203.0.113.7"]',        NULL, NULL, NULL,                  NULL,             '2026-06-15 09:00:00',        NULL),
 (2, 'Suspicious login pattern',  'Multiple failed logins then success.',    'high',     'in_progress',    'siem',   '[]',                     NULL, 2,    NULL,                  NULL,             '2026-06-15 09:30:00.250000', NULL),
 (3, 'Malware quarantined',       'ClamAV quarantined an infected upload.',  'medium',   'resolved',       'manual', '["evil.example.com"]',   NULL, 1,    '2026-06-16 10:00:00', 'Cleaned by AV.', '2026-06-15 10:00:00',        '2026-06-16 10:00:00'),
 (4, 'Port scan (benign)',        'Internal scanner traffic.',               'info',     'false_positive', 'edr',    '[]',                     NULL, NULL, NULL,                  NULL,             '2026-06-15 11:00:00',        NULL);
SELECT setval('alerts_id_seq', 4);

-- A1 pending cert (requester maintainer, needs 2); A2 pending user (requester
-- admin, needs 1); A3 approved configuration (completed); A4 expired-pending.
INSERT INTO approval_requests (id, request_type, resource_id, resource_type, requester_id, status, required_approvals, current_approvals, approvers, approval_history, expires_at, completed_at, metadata, created_at, updated_at) VALUES
 (1, 'certificate',   'cert-42',  'tls_certificate', 2, 'pending',  2, 0, '[]',  '[]', '2030-01-01 00:00:00', NULL,                  '{"cn": "svc.example.com"}', '2026-06-20 08:00:00', NULL),
 (2, 'user',          'user-9',   'user_account',    1, 'pending',  1, 0, '[]',  '[]', '2030-01-01 00:00:00', NULL,                  '{}',                        '2026-06-20 08:10:00', NULL),
 (3, 'configuration', 'cfg-7',    'siem_config',     2, 'approved', 1, 1, '[1]', '[{"user_id": 1, "user_email": "admin@skauswatch.dev", "approved": true, "reason": "ok", "timestamp": "2026-06-21T09:00:00"}]', '2030-01-01 00:00:00', '2026-06-21 09:00:00', '{}', '2026-06-20 08:20:00', '2026-06-21 09:00:00'),
 (4, 'service',       'svc-3',    'service_account', 3, 'pending',  1, 0, '[]',  '[]', '2020-01-01 00:00:00', NULL,                  '{}',                        '2019-12-20 08:30:00', NULL);
SELECT setval('approval_requests_id_seq', 4);

INSERT INTO edr_agents (id, agent_id, hostname, ip_address, os_type, os_version, agent_version, status, last_heartbeat, metadata, created_at, updated_at) VALUES
 (1, 'agent-alpha', 'web-01.corp',  '10.0.0.11', 'linux',   'Ubuntu 24.04',  '1.4.2', 'active',   '2026-07-01 06:00:00', '{"site": "dal2"}',                     '2026-05-01 07:00:00', NULL),
 (2, 'agent-beta',  'win-02.corp',  '10.0.0.12', 'windows', 'Windows 11',    '1.4.2', 'active',   '2026-07-01 06:05:00', '{"reporting_interval": 120}',          '2026-05-01 07:05:00', NULL),
 (3, 'agent-gamma', 'mac-03.corp',  '10.0.0.13', 'macos',   'macOS 15.1',    '1.3.9', 'inactive', '2026-06-01 06:10:00', '{}',                                   '2026-05-01 07:10:00', NULL);
SELECT setval('edr_agents_id_seq', 3);

INSERT INTO edr_events (id, agent_id, event_type, severity, process_name, process_path, process_hash, parent_process, command_line, network_connections, file_operations, registry_operations, details, created_at) VALUES
 (1, 'agent-alpha', 'process_start',      'low',      'bash',   '/usr/bin/bash',   NULL,       'sshd',    'bash -c id',                 NULL,                                        NULL, NULL, '{}',                       '2026-07-01 05:00:00'),
 (2, 'agent-alpha', 'network_connection', 'high',     'curl',   '/usr/bin/curl',   'abc123',   'bash',    'curl http://203.0.113.7/x',  '[{"dst": "203.0.113.7", "port": 80}]',      NULL, NULL, '{"direction": "outbound"}', '2026-07-01 05:10:00'),
 (3, 'agent-alpha', 'file_write',         'medium',   'python', '/usr/bin/python', NULL,       'bash',    'python drop.py',             NULL, '[{"path": "/tmp/drop.bin", "op": "write"}]', NULL, '{}',                  '2026-07-01 05:20:00.750000');
SELECT setval('edr_events_id_seq', 3);

-- Buckets point at the shared stub upstream; path_style so no virtual-host DNS.
INSERT INTO s3_bucket_configs (id, name, endpoint_url, bucket_name, access_key_id, secret_access_key, region, use_ssl, path_style, prefix_filter, file_types_filter, max_file_size_mb, scan_enabled, yara_enabled, created_by, created_at, updated_at) VALUES
 (1, 'prod-artifacts', 'http://parity-stub:9999', 'artifacts',  'AKIATESTKEY123456',  'supersecretvalue1234',  'us-east-1', false, true, NULL,        '[".exe", ".zip"]', 100, true,  false, 1, '2026-06-25 07:00:00', NULL),
 (2, 'backup-cold',    'http://parity-stub:9999', 'backups',    'AKIABACKUPKEY7890',  'anothersecretvalue567', 'us-east-1', false, true, 'cold/',     '[]',               250, false, false, 1, '2026-06-25 07:05:00', NULL),
 (3, 'uploads-hot',    'http://parity-stub:9999', 'uploads',    'AKIAUPLOADKEY4567',  'thirdsecretvalue89012', 'us-west-2', false, true, NULL,        '[]',               100, true,  true,  2, '2026-06-25 07:10:00', NULL);
SELECT setval('s3_bucket_configs_id_seq', 3);

INSERT INTO s3_scan_jobs (id, job_id, bucket_config_id, job_type, status, total_objects, scanned_objects, infected_objects, pup_objects, skipped_objects, error_count, started_at, completed_at, triggered_by, error_message, metadata, created_at) VALUES
 (1, '11111111-1111-4111-8111-111111111111', 1, 'full_scan',        'completed', 10, 8, 1, 0, 1, 0, '2026-06-26 01:00:00', '2026-06-26 01:30:00', 1, NULL,           '{}', '2026-06-26 00:59:00'),
 (2, '22222222-2222-4222-8222-222222222222', 1, 'incremental_scan', 'running',    5, 2, 0, 0, 0, 0, '2026-06-27 01:00:00', NULL,                  2, NULL,           '{}', '2026-06-27 00:59:00'),
 (3, '33333333-3333-4333-8333-333333333333', 1, 'prefix_scan',      'cancelled',  0, 0, 0, 0, 0, 0, NULL,                  '2026-06-28 02:00:00', 1, 'cancelled',    '{}', '2026-06-28 01:59:00');
SELECT setval('s3_scan_jobs_id_seq', 3);

INSERT INTO s3_scan_results (id, job_id, bucket_config_id, object_key, object_size, object_etag, content_type, detected_file_type, scan_status, is_malware, is_pup, is_threat, threat_names, clamav_result, yara_matches, file_md5, file_sha1, file_sha256, ti_enrichment, ti_indicator_created, ti_indicator_id, sandbox_submitted, sandbox_task_id, sandbox_status, sandbox_result, sandbox_completed_at, scan_duration_ms, tags_applied, scanned_at) VALUES
 (1, 1, 1, 'docs/report.pdf',  20480,  'etag-1', 'application/pdf',      'pdf', 'completed', false, false, false, '[]',                    '{"clean": true}',                  '[]',              'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', NULL, 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB', NULL, false, NULL, false, NULL, NULL, NULL, NULL, 152,  '[]', '2026-06-26 01:05:00'),
 (2, 1, 1, 'bin/dropper.exe',  512000, 'etag-2', 'application/x-dosexec','exe', 'completed', true,  false, true,  '["Win.Trojan.Agent"]',  '{"clean": false, "virus": "Win.Trojan.Agent"}', '["rule_pe_packed"]', 'cccccccccccccccccccccccccccccccc', NULL, 'A94A8FE5CCB19BA61C4C0873D391E987982FBBD3B5D4E9C7A3F1E2D4C5B6A798', NULL, false, NULL, false, NULL, NULL, NULL, NULL, 890,  '[]', '2026-06-26 01:10:00'),
 (3, 2, 1, 'incoming/new.zip', 1024,   'etag-3', 'application/zip',      NULL,  'pending',   false, false, false, '[]',                    NULL,                               NULL,              NULL,                               NULL, NULL,                                                                NULL, false, NULL, false, NULL, NULL, NULL, NULL, NULL, NULL, '2026-06-27 01:05:00');
SELECT setval('s3_scan_results_id_seq', 3);

INSERT INTO adhoc_scan_results (id, scan_id, uploaded_by, original_filename, file_size, content_type, detected_file_type, scan_status, is_malware, is_pup, is_threat, threat_names, file_md5, file_sha1, file_sha256, clamav_result, yara_matches, ti_enrichment, sandbox_submitted, sandbox_result, scan_duration_ms, uploaded_at, scanned_at, expires_at) VALUES
 (1, '44444444-4444-4444-8444-444444444444', 1, 'sample.pdf', 1000, 'application/pdf', 'pdf', 'completed', false, false, false, '[]', 'dddddddddddddddddddddddddddddddd', NULL, 'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE', '{"clean": true}', '[]', NULL, false, NULL, 42, '2026-06-29 09:00:00', '2026-06-29 09:00:05', NULL),
 (2, '55555555-5555-4555-8555-555555555555', 3, 'notes.zip',  2000, 'application/zip', 'zip', 'completed', false, false, false, '[]', 'ffffffffffffffffffffffffffffffff', NULL, '9999999999999999999999999999999999999999999999999999999999999999', '{"clean": true}', '[]', NULL, false, NULL, 77, '2026-06-29 09:10:00', '2026-06-29 09:10:04', NULL);
SELECT setval('adhoc_scan_results_id_seq', 2);

INSERT INTO s3_scan_schedules (id, bucket_config_id, cron_expression, timezone, enabled, last_run_at, next_run_at, created_at, updated_at) VALUES
 (1, 1, '0 2 * * *', 'UTC', true, '2026-06-30 02:00:00', '2026-07-01 02:00:00', '2026-06-25 08:00:00', NULL);
SELECT setval('s3_scan_schedules_id_seq', 1);

COMMIT;
