//! Stream message handler — Rust port of
//! `icebox/services/sync-worker/worker.py::SyncWorker._handle_message` (+
//! `_do_push`/`_do_delete`/`_load_integration`/`_update_sync_state`/
//! `_remove_sync_state`).
//!
//! **Preserved v1 gap** (not a v2 regression): the only producer of sync
//! stream events, `vault` service's `POST /sync/integrations/{id}/trigger`,
//! publishes only `{integration_id, event_type, timestamp}` — never
//! `action`/`secret_id`/`encrypted_value`. `_do_push`/`_do_delete` and this
//! handler default a missing `action` to `"push"` and a missing
//! `encrypted_value` to `""`, so a manual trigger logs a decrypt failure and
//! skips rather than syncing anything, exactly like v1. Wiring a real
//! secret payload into the publish path is tracked in
//! `docs/v2-port/v2.1-backlog.md` as a pre-existing v1 functional gap, not
//! new v2.0 scope.

use std::collections::HashMap;

use chrono::Utc;
use serde_json::Value;
use skauswatch_streams::{HandlerError, StreamEntry, StreamHandler};
use skauswatch_vault::EnvelopeEncryption;
use sqlx::PgPool;

use crate::providers::{SyncResult, get_provider};

/// Consumes one provider's sync stream, decrypting/pushing/deleting secrets
/// against that provider's cloud API and updating `vault_cloud_sync_state`.
pub struct SyncHandler {
    provider: String,
    db: PgPool,
    envelope: EnvelopeEncryption,
}

impl SyncHandler {
    /// Builds a handler bound to one provider (`aws`, `azure`, `gcp`,
    /// `oracle`, or `kubernetes`).
    pub fn new(provider: impl Into<String>, db: PgPool, envelope: EnvelopeEncryption) -> Self {
        Self {
            provider: provider.into(),
            db,
            envelope,
        }
    }

    async fn load_integration(&self, integration_id: &str) -> Option<LoadedIntegration> {
        #[derive(sqlx::FromRow)]
        struct Row {
            encrypted_credentials: Option<String>,
            config: Option<sqlx::types::Json<Value>>,
        }
        let row = sqlx::query_as::<_, Row>(
            "SELECT encrypted_credentials, config FROM vault_cloud_integrations \
             WHERE id = $1 AND enabled = true",
        )
        .bind(integration_id)
        .fetch_optional(&self.db)
        .await
        .ok()??;

        let creds_blob = row.encrypted_credentials?;
        let envelope_fields: Value = serde_json::from_str(&creds_blob).ok()?;
        let ciphertext = envelope_fields.get("ciphertext")?.as_str()?;
        let dek = envelope_fields.get("dek")?.as_str()?;
        let version = envelope_fields.get("version")?.as_u64()? as u32;
        let plaintext = self.envelope.decrypt(ciphertext, dek, version).ok()?;
        let credentials: Value = serde_json::from_str(&plaintext).ok()?;
        let config = row
            .config
            .map(|j| j.0)
            .unwrap_or_else(|| serde_json::json!({}));

        Some(LoadedIntegration {
            credentials,
            config,
        })
    }

    async fn do_push(&self, msg: &HashMap<String, String>) {
        let secret_id = msg.get("secret_id").cloned().unwrap_or_default();
        let secret_name = msg.get("secret_name").cloned().unwrap_or_default();
        let encrypted_value = msg.get("encrypted_value").cloned().unwrap_or_default();
        let encrypted_dek = msg.get("encrypted_dek").cloned().unwrap_or_default();
        let dek_version: u32 = msg
            .get("dek_version")
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let integration_id = msg.get("integration_id").cloned().unwrap_or_default();

        let plaintext = match self
            .envelope
            .decrypt(&encrypted_value, &encrypted_dek, dek_version)
        {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(secret_id, error = %e, "failed to decrypt secret — skipping push");
                return;
            }
        };

        let Some(integration) = self.load_integration(&integration_id).await else {
            tracing::warn!(
                integration_id,
                "integration not found or disabled — skipping"
            );
            return;
        };

        let provider = match get_provider(
            &self.provider,
            &integration.credentials,
            &integration.config,
        ) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(provider = %self.provider, error = %e, "failed to build provider client");
                return;
            }
        };

        let result = provider
            .push_secret(&secret_name, &plaintext, &secret_id)
            .await;
        if result.success {
            tracing::info!(
                secret_id = %result.secret_id, action = %result.action,
                external_ref = %result.external_ref, "secret pushed to cloud provider"
            );
        } else {
            tracing::error!(
                secret_id = %result.secret_id, error = result.error.as_deref().unwrap_or("unknown"),
                "push to cloud provider failed"
            );
        }
        self.update_sync_state(&secret_id, &integration_id, &result)
            .await;
    }

    async fn do_delete(&self, msg: &HashMap<String, String>) {
        let secret_id = msg.get("secret_id").cloned().unwrap_or_default();
        let integration_id = msg.get("integration_id").cloned().unwrap_or_default();
        let Some(external_ref) = msg.get("external_ref").filter(|r| !r.is_empty()) else {
            tracing::warn!(secret_id, "delete has no external_ref — skipping");
            return;
        };

        let Some(integration) = self.load_integration(&integration_id).await else {
            return;
        };
        let provider = match get_provider(
            &self.provider,
            &integration.credentials,
            &integration.config,
        ) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(provider = %self.provider, error = %e, "failed to build provider client");
                return;
            }
        };

        match provider.delete_secret(external_ref).await {
            Ok(true) => self.remove_sync_state(&secret_id, &integration_id).await,
            Ok(false) => {
                tracing::info!(secret_id, external_ref, "delete target already absent");
            }
            Err(e) => tracing::error!(secret_id, external_ref, error = %e, "delete failed"),
        }
    }

    async fn update_sync_state(&self, secret_id: &str, integration_id: &str, result: &SyncResult) {
        let status = if result.success { "synced" } else { "error" };
        let now = Utc::now().naive_utc();
        let res = sqlx::query(
            "INSERT INTO vault_cloud_sync_state \
             (secret_id, integration_id, external_ref, last_synced_at, sync_status, conflict_resolution) \
             VALUES ($1,$2,$3,$4,$5,'vault_wins') \
             ON CONFLICT (secret_id, integration_id) DO UPDATE SET \
             external_ref = EXCLUDED.external_ref, last_synced_at = EXCLUDED.last_synced_at, \
             sync_status = EXCLUDED.sync_status",
        )
        .bind(secret_id)
        .bind(integration_id)
        .bind(&result.external_ref)
        .bind(now)
        .bind(status)
        .execute(&self.db)
        .await;
        if let Err(e) = res {
            tracing::error!(secret_id, error = %e, "failed to update sync state");
        }
    }

    async fn remove_sync_state(&self, secret_id: &str, integration_id: &str) {
        let res = sqlx::query(
            "DELETE FROM vault_cloud_sync_state WHERE secret_id = $1 AND integration_id = $2",
        )
        .bind(secret_id)
        .bind(integration_id)
        .execute(&self.db)
        .await;
        if let Err(e) = res {
            tracing::error!(secret_id, error = %e, "failed to remove sync state");
        }
    }
}

struct LoadedIntegration {
    credentials: Value,
    config: Value,
}

#[async_trait::async_trait]
impl StreamHandler for SyncHandler {
    async fn handle(&self, entry: &StreamEntry) -> Result<(), HandlerError> {
        let action = entry.get("action").unwrap_or("push").to_owned();
        let integration_id = entry.get("integration_id").unwrap_or_default();
        let secret_id = entry.get("secret_id").unwrap_or_default();
        tracing::debug!(
            provider = %self.provider, action, integration_id, secret_id,
            "handling sync message"
        );

        let fields: HashMap<String, String> = entry.fields.clone();
        match action.as_str() {
            "push" => self.do_push(&fields).await,
            "delete" => self.do_delete(&fields).await,
            other => tracing::warn!(action = other, "unknown action — skipping"),
        }
        // v1 always ACKs regardless of outcome (errors are logged, not
        // retried) — returning `Ok` here keeps that at-most-once-retry
        // semantics rather than the harness's default retry/DLQ behavior.
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn test_handler() -> SyncHandler {
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .expect("lazy pool");
        SyncHandler::new("aws", db, EnvelopeEncryption::default())
    }

    #[tokio::test]
    async fn push_with_no_encrypted_value_logs_and_returns_without_panicking() {
        let handler = test_handler();
        let entry = StreamEntry {
            id: "1-0".to_owned(),
            fields: HashMap::from([
                ("integration_id".to_owned(), "int-1".to_owned()),
                ("event_type".to_owned(), "manual_trigger".to_owned()),
            ]),
        };
        // No `action` field -> defaults to "push"; no `encrypted_value` ->
        // decrypt fails immediately, before any DB/network call — matches
        // v1's behavior for a bare manual-trigger event.
        let result = handler.handle(&entry).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn delete_without_external_ref_is_skipped_without_panicking() {
        let handler = test_handler();
        let entry = StreamEntry {
            id: "1-0".to_owned(),
            fields: HashMap::from([
                ("action".to_owned(), "delete".to_owned()),
                ("secret_id".to_owned(), "s-1".to_owned()),
            ]),
        };
        assert!(handler.handle(&entry).await.is_ok());
    }

    #[tokio::test]
    async fn unknown_action_is_skipped_without_panicking() {
        let handler = test_handler();
        let entry = StreamEntry {
            id: "1-0".to_owned(),
            fields: HashMap::from([("action".to_owned(), "reticulate".to_owned())]),
        };
        assert!(handler.handle(&entry).await.is_ok());
    }
}
