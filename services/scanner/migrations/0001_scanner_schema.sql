-- Scanner worker schema (v2 Rust port).
--
-- `scanner_scan_results` persists the outcome of every stream-driven scan
-- task consumed from `scanner:tasks` (YARA / ClamAV / ASM), keyed by the
-- producer-supplied `job_id`. Column shapes are dictated by
-- `services/scanner/src/db.rs::insert_scan_result` /
-- `update_scan_result_status` (`sqlx::query` binds, no `FromRow` struct —
-- this worker never reads its own rows back).
--
-- NOTE: this table is intentionally NOT named `adhoc_scan_results`. That
-- name is already owned by the s3scan/manager "ad-hoc file upload scan"
-- feature (see `tests/parity/seed_v1.sql` / `seed_v2.sql`), with a
-- completely different column set (`scan_id`, `uploaded_by`,
-- `original_filename`, ...). All services share one Postgres database in
-- production (see `services/scanner/src/main.rs` — "shared v1 schema"), so
-- reusing that name here would either fail every insert (missing NOT NULL
-- columns) or silently collide with an unrelated feature's table. Fixed as
-- part of the coverage pass — see PR/report.
--
-- No local `scanner_users`/`scanner_tenants` identity tables: this is a
-- backend worker with no caller-facing auth; `job_id` is an opaque
-- producer-assigned string, not a foreign key into any identity space.

CREATE TABLE IF NOT EXISTS scanner_scan_results (
    id                  BIGSERIAL PRIMARY KEY,
    job_id              TEXT NOT NULL,
    scan_type           TEXT NOT NULL,
    target              TEXT NOT NULL,
    findings_count      INTEGER NOT NULL,
    findings            JSONB NOT NULL,
    duration_sec        DOUBLE PRECISION NOT NULL,
    status              TEXT NOT NULL,
    error_message       TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scanner_scan_results_job_id ON scanner_scan_results (job_id);
CREATE INDEX IF NOT EXISTS idx_scanner_scan_results_scan_type ON scanner_scan_results (scan_type);
