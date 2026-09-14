-- S3 scan worker schema (v2 Rust port).
--
-- Table shapes are derived from the live schema authority
-- (`tests/parity/seed_v2.sql`) restricted to the four tables `src/db.rs`
-- actually reads/writes: `s3_bucket_configs`, `s3_scan_jobs`,
-- `s3_scan_results`, `adhoc_scan_results`. Column types match the
-- `sqlx::FromRow`/`query_as` bindings in `db.rs` exactly — none of this
-- worker's queries bind a `chrono` timestamp value directly (all
-- `created_at`/`started_at`/`scanned_at`/... columns are written via SQL
-- `now()` or left untouched), so plain `TIMESTAMP` (no time zone) matches
-- the seed authority with no type-parity risk either way.
--
-- `s3_scan_schedules` and other manager-owned tables are intentionally
-- omitted — this worker never queries them.

-- Hybrid credential model (security finding #2 — plaintext customer AWS
-- keys): `credential_mode` selects how a bucket's S3 client is authorized.
--   - 'assume_role' (preferred, real AWS only): `role_arn` (+ optional
--     `external_id`) is exchanged for short-lived creds via sts:AssumeRole —
--     no customer secret is ever stored.
--   - 'static' (fallback, required for S3-compatible endpoints with no STS —
--     MinIO/Wasabi/etc.): `credential_enc` holds an envelope-encrypted JSON
--     blob (`{"ciphertext","dek","version"}`, see
--     `skauswatch_vault::EnvelopeEncryption::encrypt_json`) wrapping
--     `{"access_key_id","secret_access_key"}`. Plaintext keys are never
--     persisted; the plaintext columns this replaces (`access_key_id`,
--     `secret_access_key`) are gone, not just renamed.
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
    CONSTRAINT s3_bucket_configs_credential_mode_check
        CHECK (credential_mode IN ('assume_role', 'static')),
    CONSTRAINT s3_bucket_configs_credential_shape_check CHECK (
        (credential_mode = 'assume_role' AND role_arn IS NOT NULL)
        OR
        (credential_mode = 'static' AND credential_enc IS NOT NULL)
    )
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
