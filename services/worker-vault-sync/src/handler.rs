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

// ── handler tests ────────────────────────────────────────────────────────
//
// The first three (pre-existing) tests exercise paths that return before
// ever touching the DB, so they use a lazy/disconnected pool. Everything
// below drives `SyncHandler::handle` end-to-end against a real, isolated
// Postgres schema (`skauswatch_testkit::db::test_pool_multi` — this
// service's own `vault_cloud_sync_state` migration plus `vault`'s
// `vault_cloud_integrations` table, since `load_integration` queries a
// table this service does not own) and a `wiremock` AWS Secrets Manager
// endpoint (see `providers/aws.rs` for the wire-protocol details).
#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::Path;

    use serde_json::json;
    use skauswatch_vault::MekVersion;
    use sqlx::types::Json as SqlxJson;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    // ── DB-backed fixtures ───────────────────────────────────────────────

    async fn db_pool() -> PgPool {
        skauswatch_testkit::db::test_pool_multi(&[
            Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")),
            Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../vault/migrations")),
        ])
        .await
    }

    /// Same fixed single-MEK envelope used by `skauswatch-vault`'s own
    /// crypto tests — shared between the handler under test and the
    /// fixture-encryption helpers below so ciphertext round-trips.
    fn test_envelope() -> EnvelopeEncryption {
        EnvelopeEncryption::new(
            HashMap::from([(
                1,
                MekVersion {
                    version: 1,
                    key_bytes: [7u8; 32],
                },
            )]),
            1,
        )
    }

    /// Builds the `encrypted_credentials` TEXT blob `load_integration`
    /// expects: `{"ciphertext", "dek", "version"}` wrapping an
    /// envelope-encrypted JSON credentials document.
    fn encrypt_credentials(envelope: &EnvelopeEncryption, credentials: &Value) -> String {
        let plaintext = serde_json::to_string(credentials).expect("serialize credentials");
        let (ciphertext, dek, version) = envelope.encrypt(&plaintext).expect("encrypt creds");
        json!({"ciphertext": ciphertext, "dek": dek, "version": version}).to_string()
    }

    /// Seeds one `vault_cloud_integrations` row (owned by the `vault`
    /// service, borrowed here per `skauswatch_testkit::db::test_pool_multi`
    /// docs).
    async fn seed_integration(
        pool: &PgPool,
        id: &str,
        enabled: bool,
        encrypted_credentials: Option<&str>,
        config: Value,
    ) {
        sqlx::query(
            "INSERT INTO vault_cloud_integrations \
             (id, provider, name, sync_direction, encrypted_credentials, enabled, config) \
             VALUES ($1, 'aws', 'test-integration', 'vault_to_cloud', $2, $3, $4)",
        )
        .bind(id)
        .bind(encrypted_credentials)
        .bind(enabled)
        .bind(SqlxJson(config))
        .execute(pool)
        .await
        .expect("seed integration");
    }

    async fn seed_sync_state(
        pool: &PgPool,
        secret_id: &str,
        integration_id: &str,
        external_ref: &str,
        sync_status: &str,
    ) {
        sqlx::query(
            "INSERT INTO vault_cloud_sync_state \
             (secret_id, integration_id, external_ref, sync_status, conflict_resolution) \
             VALUES ($1, $2, $3, $4, 'vault_wins')",
        )
        .bind(secret_id)
        .bind(integration_id)
        .bind(external_ref)
        .bind(sync_status)
        .execute(pool)
        .await
        .expect("seed sync state");
    }

    struct SyncStateRow {
        external_ref: Option<String>,
        sync_status: String,
        conflict_resolution: String,
    }

    async fn fetch_sync_state(
        pool: &PgPool,
        secret_id: &str,
        integration_id: &str,
    ) -> Option<SyncStateRow> {
        #[derive(sqlx::FromRow)]
        struct Row {
            external_ref: Option<String>,
            sync_status: String,
            conflict_resolution: String,
        }
        let row = sqlx::query_as::<_, Row>(
            "SELECT external_ref, sync_status, conflict_resolution \
             FROM vault_cloud_sync_state WHERE secret_id = $1 AND integration_id = $2",
        )
        .bind(secret_id)
        .bind(integration_id)
        .fetch_optional(pool)
        .await
        .expect("select sync state");
        row.map(|r| SyncStateRow {
            external_ref: r.external_ref,
            sync_status: r.sync_status,
            conflict_resolution: r.conflict_resolution,
        })
    }

    async fn mount_target(server: &MockServer, target: &str, status: u16, body: Value) {
        Mock::given(method("POST"))
            .and(path("/"))
            .and(header("x-amz-target", format!("secretsmanager.{target}")))
            .respond_with(ResponseTemplate::new(status).set_body_json(body))
            .mount(server)
            .await;
    }

    fn push_entry(
        integration_id: &str,
        secret_id: &str,
        secret_name: &str,
        envelope: &EnvelopeEncryption,
        plaintext: &str,
    ) -> StreamEntry {
        let (encrypted_value, encrypted_dek, dek_version) =
            envelope.encrypt(plaintext).expect("encrypt secret value");
        StreamEntry {
            id: "1-0".to_owned(),
            fields: HashMap::from([
                ("action".to_owned(), "push".to_owned()),
                ("integration_id".to_owned(), integration_id.to_owned()),
                ("secret_id".to_owned(), secret_id.to_owned()),
                ("secret_name".to_owned(), secret_name.to_owned()),
                ("encrypted_value".to_owned(), encrypted_value),
                ("encrypted_dek".to_owned(), encrypted_dek),
                ("dek_version".to_owned(), dek_version.to_string()),
            ]),
        }
    }

    fn delete_entry(integration_id: &str, secret_id: &str, external_ref: &str) -> StreamEntry {
        StreamEntry {
            id: "1-0".to_owned(),
            fields: HashMap::from([
                ("action".to_owned(), "delete".to_owned()),
                ("integration_id".to_owned(), integration_id.to_owned()),
                ("secret_id".to_owned(), secret_id.to_owned()),
                ("external_ref".to_owned(), external_ref.to_owned()),
            ]),
        }
    }

    fn aws_credentials() -> Value {
        json!({"access_key_id": "AKIATEST", "secret_access_key": "test-secret"})
    }

    // ── push (do_push) ───────────────────────────────────────────────────

    #[tokio::test]
    async fn push_success_inserts_synced_sync_state_row() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            200,
            json!({"ARN": "arn:1", "Name": "vault/db-password", "VersionId": "v1"}),
        )
        .await;
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(
            &pool,
            "int-1",
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = push_entry("int-1", "secret-1", "db-password", &envelope, "hunter2");
        let result = handler.handle(&entry).await;
        assert!(result.is_ok());

        let row = fetch_sync_state(&pool, "secret-1", "int-1")
            .await
            .expect("sync state row inserted");
        assert_eq!(row.sync_status, "synced");
        assert_eq!(row.external_ref.as_deref(), Some("vault/db-password"));
        assert_eq!(row.conflict_resolution, "vault_wins");
    }

    #[tokio::test]
    async fn push_creates_new_secret_and_records_arn_as_external_ref() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            400,
            json!({"__type": "ResourceNotFoundException", "message": "no such secret"}),
        )
        .await;
        mount_target(
            &server,
            "CreateSecret",
            200,
            json!({"ARN": "arn:aws:secretsmanager:us-east-1:1:secret:vault/new-Ab12", "Name": "vault/new", "VersionId": "v1"}),
        )
        .await;
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(
            &pool,
            "int-2",
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = push_entry("int-2", "secret-2", "new", &envelope, "s3cr3t");
        assert!(handler.handle(&entry).await.is_ok());

        let row = fetch_sync_state(&pool, "secret-2", "int-2")
            .await
            .expect("sync state row inserted");
        assert_eq!(row.sync_status, "synced");
        assert_eq!(
            row.external_ref.as_deref(),
            Some("arn:aws:secretsmanager:us-east-1:1:secret:vault/new-Ab12")
        );
    }

    #[tokio::test]
    async fn push_provider_failure_records_error_sync_status() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            400,
            json!({"__type": "InvalidParameterException", "message": "bad input"}),
        )
        .await;
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(
            &pool,
            "int-3",
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = push_entry("int-3", "secret-3", "x", &envelope, "v");
        // The handler always ACKs regardless of provider outcome (v1 parity
        // — see the `StreamHandler` impl doc comment).
        assert!(handler.handle(&entry).await.is_ok());

        let row = fetch_sync_state(&pool, "secret-3", "int-3")
            .await
            .expect("sync state row still recorded on failure");
        assert_eq!(row.sync_status, "error");
        // Failure external_ref is the computed secret name, not an ARN.
        assert_eq!(row.external_ref.as_deref(), Some("vault/x"));
    }

    #[tokio::test]
    async fn push_upsert_updates_existing_sync_state_row_in_place() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "PutSecretValue",
            200,
            json!({"ARN": "arn:1", "Name": "vault/db-password", "VersionId": "v2"}),
        )
        .await;
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(
            &pool,
            "int-4",
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        // Pre-existing row from a prior (failed) sync attempt.
        seed_sync_state(&pool, "secret-4", "int-4", "vault/stale-ref", "error").await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = push_entry("int-4", "secret-4", "db-password", &envelope, "hunter2");
        assert!(handler.handle(&entry).await.is_ok());

        let row = fetch_sync_state(&pool, "secret-4", "int-4")
            .await
            .expect("row still present after upsert");
        assert_eq!(row.sync_status, "synced");
        assert_eq!(row.external_ref.as_deref(), Some("vault/db-password"));

        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM vault_cloud_sync_state WHERE secret_id = $1 AND integration_id = $2",
        )
        .bind("secret-4")
        .bind("int-4")
        .fetch_one(&pool)
        .await
        .expect("count");
        assert_eq!(count.0, 1, "ON CONFLICT must update, not duplicate");
    }

    #[tokio::test]
    async fn push_unknown_integration_id_skips_without_db_write() {
        let pool = db_pool().await;
        let envelope = test_envelope();
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = push_entry("no-such-integration", "secret-5", "x", &envelope, "v");
        assert!(handler.handle(&entry).await.is_ok());

        assert!(
            fetch_sync_state(&pool, "secret-5", "no-such-integration")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn push_disabled_integration_skips_without_db_write() {
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(&pool, "int-6", false, Some(&creds_blob), json!({})).await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = push_entry("int-6", "secret-6", "x", &envelope, "v");
        assert!(handler.handle(&entry).await.is_ok());

        assert!(fetch_sync_state(&pool, "secret-6", "int-6").await.is_none());
    }

    #[tokio::test]
    async fn push_unbuildable_provider_skips_without_db_write() {
        // A handler bound to a provider name outside the fixed set main.rs
        // dispatches (`aws`/`azure`/`gcp`/`oracle`/`kubernetes`) exercises
        // `get_provider`'s `Err` arm inside `do_push`.
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(&pool, "int-7", true, Some(&creds_blob), json!({})).await;
        let handler = SyncHandler::new("not-a-real-provider", pool.clone(), envelope.clone());

        let entry = push_entry("int-7", "secret-7", "x", &envelope, "v");
        assert!(handler.handle(&entry).await.is_ok());

        assert!(fetch_sync_state(&pool, "secret-7", "int-7").await.is_none());
    }

    // ── delete (do_delete) ───────────────────────────────────────────────

    #[tokio::test]
    async fn delete_unbuildable_provider_leaves_sync_state_row_untouched() {
        // `do_delete`'s own `get_provider(...)` `Err` arm — distinct from
        // (and, before this test, uncovered relative to) `do_push`'s
        // equivalent branch exercised by
        // `push_unbuildable_provider_skips_without_db_write` above.
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(&pool, "int-12", true, Some(&creds_blob), json!({})).await;
        seed_sync_state(&pool, "secret-12", "int-12", "vault/x", "synced").await;
        let handler = SyncHandler::new("not-a-real-provider", pool.clone(), envelope.clone());

        let entry = delete_entry("int-12", "secret-12", "vault/x");
        assert!(handler.handle(&entry).await.is_ok());

        let row = fetch_sync_state(&pool, "secret-12", "int-12")
            .await
            .expect("row left in place — provider construction failed before delete");
        assert_eq!(row.sync_status, "synced");
    }

    #[tokio::test]
    async fn delete_success_removes_sync_state_row() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "DeleteSecret",
            200,
            json!({"ARN": "vault/db-password", "Name": "vault/db-password"}),
        )
        .await;
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(
            &pool,
            "int-8",
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        seed_sync_state(&pool, "secret-8", "int-8", "vault/db-password", "synced").await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = delete_entry("int-8", "secret-8", "vault/db-password");
        assert!(handler.handle(&entry).await.is_ok());

        assert!(fetch_sync_state(&pool, "secret-8", "int-8").await.is_none());
    }

    #[tokio::test]
    async fn delete_already_absent_leaves_sync_state_row_untouched() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "DeleteSecret",
            400,
            json!({"__type": "ResourceNotFoundException", "message": "already gone"}),
        )
        .await;
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(
            &pool,
            "int-9",
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        seed_sync_state(&pool, "secret-9", "int-9", "vault/gone", "synced").await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = delete_entry("int-9", "secret-9", "vault/gone");
        assert!(handler.handle(&entry).await.is_ok());

        // Current handler behavior: an already-absent remote target does
        // not clear the local row (only `Ok(true)` does) — documented here
        // rather than assumed, so a future behavior change is a deliberate
        // test update, not a silent regression.
        let row = fetch_sync_state(&pool, "secret-9", "int-9")
            .await
            .expect("row left in place");
        assert_eq!(row.sync_status, "synced");
    }

    #[tokio::test]
    async fn delete_provider_error_leaves_sync_state_row_untouched() {
        let server = MockServer::start().await;
        mount_target(
            &server,
            "DeleteSecret",
            400,
            json!({"__type": "InvalidParameterException", "message": "bad ref"}),
        )
        .await;
        let pool = db_pool().await;
        let envelope = test_envelope();
        let creds_blob = encrypt_credentials(&envelope, &aws_credentials());
        seed_integration(
            &pool,
            "int-10",
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        seed_sync_state(&pool, "secret-10", "int-10", "vault/x", "synced").await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = delete_entry("int-10", "secret-10", "vault/x");
        assert!(handler.handle(&entry).await.is_ok());

        assert!(
            fetch_sync_state(&pool, "secret-10", "int-10")
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn delete_unknown_integration_returns_before_any_provider_call() {
        // No integration row seeded and no provider endpoint configured at
        // all — `load_integration` returns `None`, so `do_delete` must
        // return via its `let Some(integration) = ... else { return; }`
        // guard without ever attempting to build a provider client
        // (there is nothing wired up for it to call).
        let pool = db_pool().await;
        let envelope = test_envelope();
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = delete_entry("no-such-integration", "secret-11", "vault/x");
        assert!(handler.handle(&entry).await.is_ok());

        assert!(
            fetch_sync_state(&pool, "secret-11", "no-such-integration")
                .await
                .is_none()
        );
    }
}
