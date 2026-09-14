-- worker-vault-sync owned schema (v2 Rust port).
--
-- This worker reads `vault_cloud_integrations` (and, transitively, secret
-- payloads carried on the sync stream message itself — it never queries
-- `vault_secrets` directly), both owned by the `vault` service's
-- `services/vault/migrations/0001_vault_schema.sql`. `vault_cloud_sync_state`
-- is NOT part of that schema; it is owned here since only this worker reads
-- and writes it (see `src/handler.rs::update_sync_state`/`remove_sync_state`).
--
-- Column shapes are dictated by the existing `sqlx::query` calls in
-- `src/handler.rs`: `INSERT INTO vault_cloud_sync_state (secret_id,
-- integration_id, external_ref, last_synced_at, sync_status,
-- conflict_resolution) ... ON CONFLICT (secret_id, integration_id) DO
-- UPDATE ...` and `DELETE FROM vault_cloud_sync_state WHERE secret_id = $1
-- AND integration_id = $2`. The `ON CONFLICT (secret_id, integration_id)`
-- target requires a unique constraint on that pair, satisfied here by making
-- it the composite primary key (matches v1: one sync-state row per
-- secret/integration pair).

CREATE TABLE IF NOT EXISTS vault_cloud_sync_state (
    secret_id               TEXT NOT NULL,
    integration_id          TEXT NOT NULL,
    external_ref            TEXT,
    last_synced_at          TIMESTAMP,
    sync_status             TEXT NOT NULL,
    conflict_resolution     TEXT NOT NULL DEFAULT 'vault_wins',
    PRIMARY KEY (secret_id, integration_id)
);

CREATE INDEX IF NOT EXISTS idx_vault_cloud_sync_state_integration_id
    ON vault_cloud_sync_state (integration_id);
