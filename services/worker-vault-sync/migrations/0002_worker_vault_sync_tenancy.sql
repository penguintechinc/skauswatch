-- Tenant isolation retrofit — see docs/v2-port/tenancy-model.md
-- (worker-vault-sync row).
--
-- Adds `tenant_id UUID NOT NULL` to `vault_cloud_sync_state`, the one table
-- this worker owns. Unlike most stream-consuming workers in this fan-out
-- (s3scan/scanner/worker-codescan), the tenant value here is NOT taken from
-- a Redis stream field: `handler.rs::load_integration` already reads the
-- owning `vault_cloud_integrations` row (vault-owned, `tenant_id UUID NOT
-- NULL` as of `services/vault/migrations/0002_vault_tenancy.sql`) for every
-- message, so that already-trusted, server-side-resolved value is stamped
-- onto every `vault_cloud_sync_state` row this worker writes for that
-- integration — never re-derived from the stream message itself.
--
-- Column type is UUID, matching every other service's tenancy migration
-- (tenant identity is manager-issued and global, not local to this
-- worker's own id space). Backfilled to the fixed bootstrap tenant
-- (00000000-0000-0000-0000-000000000001) for any pre-existing rows —
-- v2 has never hit prod, so every existing row belongs to the one
-- bootstrap tenant, matching every other service's backfill value.

ALTER TABLE vault_cloud_sync_state ADD COLUMN tenant_id UUID;
UPDATE vault_cloud_sync_state SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE vault_cloud_sync_state ALTER COLUMN tenant_id SET NOT NULL;

CREATE INDEX IF NOT EXISTS idx_vault_cloud_sync_state_tenant_integration
    ON vault_cloud_sync_state (tenant_id, integration_id);
