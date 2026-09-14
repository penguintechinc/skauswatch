-- Tenant isolation retrofit — see docs/v2-port/tenancy-model.md (vault row).
--
-- Adds `tenant_id UUID NOT NULL` to every vault-owned table and backfills
-- existing rows to the fixed bootstrap tenant
-- (00000000-0000-0000-0000-000000000001), matching the bootstrap tenant
-- manager's `0002_tenancy.sql` seeds. Vault has no FK to a `tenants` table:
-- it lives in a separate database from manager, so no real cross-database
-- FK is possible — tenant identity is a manager-issued, JWT-carried value
-- enforced at the application layer only (every query in routes/*.rs filters
-- on it explicitly).
--
-- Column type is UUID (not the service's native TEXT id type) per the
-- tenancy spec: tenant identity is manager-issued and global, not local to
-- vault's own id space.

ALTER TABLE vault_secrets ADD COLUMN tenant_id UUID;
UPDATE vault_secrets SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE vault_secrets ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE vault_secret_versions ADD COLUMN tenant_id UUID;
UPDATE vault_secret_versions SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE vault_secret_versions ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE vault_secret_owners ADD COLUMN tenant_id UUID;
UPDATE vault_secret_owners SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE vault_secret_owners ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE vault_jit_requests ADD COLUMN tenant_id UUID;
UPDATE vault_jit_requests SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE vault_jit_requests ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE vault_jit_grants ADD COLUMN tenant_id UUID;
UPDATE vault_jit_grants SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE vault_jit_grants ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE vault_one_time_secrets ADD COLUMN tenant_id UUID;
UPDATE vault_one_time_secrets SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE vault_one_time_secrets ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE vault_cloud_integrations ADD COLUMN tenant_id UUID;
UPDATE vault_cloud_integrations SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE vault_cloud_integrations ALTER COLUMN tenant_id SET NOT NULL;

ALTER TABLE vault_audit_log ADD COLUMN tenant_id UUID;
UPDATE vault_audit_log SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE vault_audit_log ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_vault_secrets_tenant_id ON vault_secrets (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_vault_secrets_tenant_type ON vault_secrets (tenant_id, secret_type);
CREATE INDEX IF NOT EXISTS idx_vault_secret_versions_tenant_secret ON vault_secret_versions (tenant_id, secret_id);
CREATE INDEX IF NOT EXISTS idx_vault_secret_owners_tenant_secret ON vault_secret_owners (tenant_id, secret_id);
CREATE INDEX IF NOT EXISTS idx_vault_secret_owners_tenant_owner ON vault_secret_owners (tenant_id, owner_id);
CREATE INDEX IF NOT EXISTS idx_vault_jit_requests_tenant_id ON vault_jit_requests (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_vault_jit_requests_tenant_requestor ON vault_jit_requests (tenant_id, requestor_id);
CREATE INDEX IF NOT EXISTS idx_vault_jit_grants_tenant_id ON vault_jit_grants (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_vault_jit_grants_tenant_secret ON vault_jit_grants (tenant_id, secret_id);
CREATE INDEX IF NOT EXISTS idx_vault_one_time_secrets_tenant_id ON vault_one_time_secrets (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_vault_cloud_integrations_tenant_id ON vault_cloud_integrations (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_vault_audit_log_tenant_created ON vault_audit_log (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_vault_audit_log_tenant_actor ON vault_audit_log (tenant_id, actor_id);
