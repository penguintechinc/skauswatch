-- Tenant isolation retrofit — see docs/v2-port/tenancy-model.md (scanner row).
--
-- Adds `tenant_id UUID NOT NULL` to `scanner_scan_results` and backfills
-- existing rows to the fixed bootstrap tenant
-- (00000000-0000-0000-0000-000000000001), matching the bootstrap tenant
-- manager's `0002_tenancy.sql` seeds. Scanner has no FK to a `tenants`
-- table: it shares the v1 Postgres database but is a stream-driven worker
-- with no local identity schema, so tenant identity is a manager-issued,
-- stream-field-carried value enforced at the application layer only (every
-- query in db.rs filters on it explicitly).
--
-- Column type is UUID (not the service's native BIGSERIAL id type) per the
-- tenancy spec: tenant identity is manager-issued and global, not local to
-- scanner's own id space.

ALTER TABLE scanner_scan_results ADD COLUMN tenant_id UUID;
UPDATE scanner_scan_results SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE scanner_scan_results ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_scanner_scan_results_tenant_id ON scanner_scan_results (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_scanner_scan_results_tenant_job_id ON scanner_scan_results (tenant_id, job_id);
