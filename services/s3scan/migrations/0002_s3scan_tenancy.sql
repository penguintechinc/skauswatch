-- Tenant isolation retrofit — see docs/v2-port/tenancy-model.md (s3scan row).
--
-- Adds `tenant_id UUID NOT NULL` to every s3scan-owned table and backfills
-- existing rows to the fixed bootstrap tenant
-- (00000000-0000-0000-0000-000000000001), matching manager's
-- `0002_tenancy.sql` seed. s3scan has no FK to a `tenants` table: it lives
-- in a separate database from manager, so no real cross-database FK is
-- possible — tenant identity arrives on the `s3scan:tasks` Redis Stream
-- (a `tenant_id` field stamped by the manager from the dispatching caller's
-- JWT/gRPC metadata; see `src/message.rs::Task::parse`) and is enforced at
-- the application/query layer only (every function in `src/db.rs`).
--
-- Column type is UUID (not the service's native SERIAL id type) per the
-- tenancy spec: tenant identity is manager-issued and global, not local to
-- s3scan's own id space.
--
-- `s3_scan_schedules` (manager-owned, per docs/v2-port/tenancy-model.md §5)
-- is intentionally NOT touched here — this worker never queries it (see
-- 0001's header note).

ALTER TABLE s3_bucket_configs ADD COLUMN tenant_id UUID;
UPDATE s3_bucket_configs SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE s3_bucket_configs ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE s3_scan_jobs ADD COLUMN tenant_id UUID;
UPDATE s3_scan_jobs SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE s3_scan_jobs ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE s3_scan_results ADD COLUMN tenant_id UUID;
UPDATE s3_scan_results SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE s3_scan_results ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE adhoc_scan_results ADD COLUMN tenant_id UUID;
UPDATE adhoc_scan_results SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE adhoc_scan_results ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_s3_bucket_configs_tenant_id ON s3_bucket_configs (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_s3_scan_jobs_tenant_job ON s3_scan_jobs (tenant_id, job_id);
CREATE INDEX IF NOT EXISTS idx_s3_scan_jobs_tenant_id ON s3_scan_jobs (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_s3_scan_results_tenant_job ON s3_scan_results (tenant_id, job_id);
CREATE INDEX IF NOT EXISTS idx_adhoc_scan_results_tenant_scan ON adhoc_scan_results (tenant_id, scan_id);
