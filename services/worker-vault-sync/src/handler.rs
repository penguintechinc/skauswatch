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
use uuid::Uuid;

use crate::providers::aws::{has_static_credentials, resolve_region};
use crate::providers::{SyncResult, get_provider};

/// This worker's own-AWS JWT-SVID federation config for
/// [`SyncHandler::federated_credentials_for`] — dal2's IRSA equivalent (see
/// `docs/v2-port/aws-identity-runbook.md`). `identity` is a trait object
/// (not the concrete `skauswatch_identity::IdentityProvider`) purely so
/// this module's own tests can substitute a hermetic fake; the real binary
/// always wires the genuine `IdentityProvider`.
#[derive(Clone)]
struct Federation {
    identity: std::sync::Arc<dyn skauswatch_s3::credentials::JwtSvidSource>,
    /// This worker's own service-owned IAM role ARN — never a customer's.
    role_arn: String,
}

/// Consumes one provider's sync stream, decrypting/pushing/deleting secrets
/// against that provider's cloud API and updating `vault_cloud_sync_state`.
pub struct SyncHandler {
    provider: String,
    db: PgPool,
    envelope: EnvelopeEncryption,
    /// Own-AWS federation for `"aws"`-provider integrations that carry no
    /// static credentials. `None` (the only value [`SyncHandler::new`]
    /// ever sets) preserves today's behavior exactly — see
    /// [`SyncHandler::with_federation`].
    federation: Option<Federation>,
}

impl SyncHandler {
    /// Builds a handler bound to one provider (`aws`, `azure`, `gcp`,
    /// `oracle`, or `kubernetes`).
    pub fn new(provider: impl Into<String>, db: PgPool, envelope: EnvelopeEncryption) -> Self {
        Self {
            provider: provider.into(),
            db,
            envelope,
            federation: None,
        }
    }

    /// Enables JWT-SVID-&gt;STS federation for this worker's own-AWS
    /// access — the fallback `AwsProvider` uses when an integration's
    /// `credentials` carry no static access-key/secret pair (see
    /// `docs/v2-port/aws-identity-runbook.md`). A no-op for any provider
    /// other than `"aws"`.
    ///
    /// Fail-safe by construction: [`SyncHandler::federated_credentials_for`]
    /// only *attempts* federation when this has been called, and any
    /// failure there (degraded identity, STS error) is logged and treated
    /// as "no override" — the caller falls back to `AwsProvider`'s
    /// pre-existing default-credential-chain behavior, never fatal.
    #[must_use]
    pub fn with_federation(
        mut self,
        identity: std::sync::Arc<dyn skauswatch_s3::credentials::JwtSvidSource>,
        role_arn: String,
    ) -> Self {
        self.federation = Some(Federation { identity, role_arn });
        self
    }

    /// Resolves this worker's own-AWS federated credentials for one
    /// integration's `credentials`/`config`, if applicable: only for the
    /// `"aws"` provider, only when the integration itself carries no
    /// static access-key/secret pair (a customer's own credentials always
    /// win), and only when federation has been configured via
    /// [`SyncHandler::with_federation`]. Otherwise (or on any federation
    /// failure) returns `None` — the caller falls back to `AwsProvider`'s
    /// pre-existing default-credential-chain behavior.
    async fn federated_credentials_for(
        &self,
        credentials: &Value,
        config: &Value,
    ) -> Option<aws_sdk_secretsmanager::config::Credentials> {
        if self.provider != "aws" || has_static_credentials(credentials) {
            return None;
        }
        let federation = self.federation.as_ref()?;
        let region = resolve_region(credentials, config);
        match skauswatch_s3::credentials::federated_base_credentials(
            federation.identity.as_ref(),
            &federation.role_arn,
            &region,
        )
        .await
        {
            Ok(creds) => Some(creds),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "own-AWS JWT-SVID federation unavailable for vault cloud sync — \
                     falling back to the default AWS credential-provider chain"
                );
                None
            }
        }
    }

    /// Loads an enabled integration by id, including its owning tenant.
    ///
    /// `tenant_id` here is the *only* source of tenant for everything this
    /// handler subsequently writes to `vault_cloud_sync_state` — it is
    /// resolved server-side from the vault-owned `vault_cloud_integrations`
    /// row (never from the Redis stream message, which this worker treats
    /// as producer-trusted but tenant-silent) and stamped, unchanged, onto
    /// every sync-state row this integration's push/delete produces. See
    /// `docs/v2-port/tenancy-model.md` and `migrations/0002_worker_vault_sync_tenancy.sql`.
    async fn load_integration(&self, integration_id: &str) -> Option<LoadedIntegration> {
        #[derive(sqlx::FromRow)]
        struct Row {
            tenant_id: Uuid,
            encrypted_credentials: Option<String>,
            config: Option<sqlx::types::Json<Value>>,
        }
        let row = sqlx::query_as::<_, Row>(
            "SELECT tenant_id, encrypted_credentials, config FROM vault_cloud_integrations \
             WHERE id = $1 AND enabled = true",
        )
        .bind(integration_id)
        .fetch_optional(&self.db)
        .await
        .ok()??;

        let tenant_id = row.tenant_id;
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
            tenant_id,
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

        let federated_credentials = self
            .federated_credentials_for(&integration.credentials, &integration.config)
            .await;
        let provider = match get_provider(
            &self.provider,
            &integration.credentials,
            &integration.config,
            federated_credentials,
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
        self.update_sync_state(&secret_id, &integration_id, integration.tenant_id, &result)
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
        let federated_credentials = self
            .federated_credentials_for(&integration.credentials, &integration.config)
            .await;
        let provider = match get_provider(
            &self.provider,
            &integration.credentials,
            &integration.config,
            federated_credentials,
        ) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(provider = %self.provider, error = %e, "failed to build provider client");
                return;
            }
        };

        match provider.delete_secret(external_ref).await {
            Ok(true) => {
                self.remove_sync_state(&secret_id, &integration_id, integration.tenant_id)
                    .await
            }
            Ok(false) => {
                tracing::info!(secret_id, external_ref, "delete target already absent");
            }
            Err(e) => tracing::error!(secret_id, external_ref, error = %e, "delete failed"),
        }
    }

    /// `tenant_id` is always the caller's already-resolved
    /// `LoadedIntegration::tenant_id` — never re-derived here — so a row is
    /// never written without the tenant of the integration that produced it.
    async fn update_sync_state(
        &self,
        secret_id: &str,
        integration_id: &str,
        tenant_id: Uuid,
        result: &SyncResult,
    ) {
        let status = if result.success { "synced" } else { "error" };
        let now = Utc::now().naive_utc();
        let res = sqlx::query(
            "INSERT INTO vault_cloud_sync_state \
             (secret_id, integration_id, tenant_id, external_ref, last_synced_at, sync_status, conflict_resolution) \
             VALUES ($1,$2,$3,$4,$5,$6,'vault_wins') \
             ON CONFLICT (secret_id, integration_id) DO UPDATE SET \
             external_ref = EXCLUDED.external_ref, last_synced_at = EXCLUDED.last_synced_at, \
             sync_status = EXCLUDED.sync_status \
             WHERE vault_cloud_sync_state.tenant_id = EXCLUDED.tenant_id",
        )
        .bind(secret_id)
        .bind(integration_id)
        .bind(tenant_id)
        .bind(&result.external_ref)
        .bind(now)
        .bind(status)
        .execute(&self.db)
        .await;
        if let Err(e) = res {
            tracing::error!(secret_id, error = %e, "failed to update sync state");
        }
    }

    /// `tenant_id` is bound into the `WHERE` clause alongside the
    /// `(secret_id, integration_id)` key — defense in depth per
    /// `docs/v2-port/tenancy-model.md` §4 ("tenant_id in the WHERE clause is
    /// mandatory even when filtering by primary key"), even though this
    /// composite key is already unique per integration (and therefore per
    /// tenant) by construction.
    async fn remove_sync_state(&self, secret_id: &str, integration_id: &str, tenant_id: Uuid) {
        let res = sqlx::query(
            "DELETE FROM vault_cloud_sync_state \
             WHERE secret_id = $1 AND integration_id = $2 AND tenant_id = $3",
        )
        .bind(secret_id)
        .bind(integration_id)
        .bind(tenant_id)
        .execute(&self.db)
        .await;
        if let Err(e) = res {
            tracing::error!(secret_id, error = %e, "failed to remove sync state");
        }
    }
}

struct LoadedIntegration {
    tenant_id: Uuid,
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

    /// Fixed tenant used by every test that isn't specifically exercising
    /// cross-tenant isolation — deliberately distinct from both the
    /// migration's bootstrap-tenant backfill value and [`other_tenant`], so
    /// a test can't pass by accidentally matching a default.
    fn test_tenant() -> Uuid {
        "11111111-1111-1111-1111-111111111111"
            .parse()
            .expect("valid uuid")
    }

    /// A second, distinct tenant — used only by the cross-tenant isolation
    /// test below.
    fn other_tenant() -> Uuid {
        "22222222-2222-2222-2222-222222222222"
            .parse()
            .expect("valid uuid")
    }

    /// Seeds one `vault_cloud_integrations` row (owned by the `vault`
    /// service, borrowed here per `skauswatch_testkit::db::test_pool_multi`
    /// docs). `tenant_id` is the row's owning tenant — the sole source
    /// `load_integration`/`update_sync_state`/`remove_sync_state` use to
    /// stamp `vault_cloud_sync_state.tenant_id`.
    async fn seed_integration(
        pool: &PgPool,
        id: &str,
        tenant_id: Uuid,
        enabled: bool,
        encrypted_credentials: Option<&str>,
        config: Value,
    ) {
        sqlx::query(
            "INSERT INTO vault_cloud_integrations \
             (id, tenant_id, provider, name, sync_direction, encrypted_credentials, enabled, config) \
             VALUES ($1, $2, 'aws', 'test-integration', 'vault_to_cloud', $3, $4, $5)",
        )
        .bind(id)
        .bind(tenant_id)
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
        tenant_id: Uuid,
        external_ref: &str,
        sync_status: &str,
    ) {
        sqlx::query(
            "INSERT INTO vault_cloud_sync_state \
             (secret_id, integration_id, tenant_id, external_ref, sync_status, conflict_resolution) \
             VALUES ($1, $2, $3, $4, $5, 'vault_wins')",
        )
        .bind(secret_id)
        .bind(integration_id)
        .bind(tenant_id)
        .bind(external_ref)
        .bind(sync_status)
        .execute(pool)
        .await
        .expect("seed sync state");
    }

    struct SyncStateRow {
        tenant_id: Uuid,
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
            tenant_id: Uuid,
            external_ref: Option<String>,
            sync_status: String,
            conflict_resolution: String,
        }
        let row = sqlx::query_as::<_, Row>(
            "SELECT tenant_id, external_ref, sync_status, conflict_resolution \
             FROM vault_cloud_sync_state WHERE secret_id = $1 AND integration_id = $2",
        )
        .bind(secret_id)
        .bind(integration_id)
        .fetch_optional(pool)
        .await
        .expect("select sync state");
        row.map(|r| SyncStateRow {
            tenant_id: r.tenant_id,
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
            test_tenant(),
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
            test_tenant(),
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
            test_tenant(),
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
            test_tenant(),
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        // Pre-existing row from a prior (failed) sync attempt.
        seed_sync_state(
            &pool,
            "secret-4",
            "int-4",
            test_tenant(),
            "vault/stale-ref",
            "error",
        )
        .await;
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
        seed_integration(
            &pool,
            "int-6",
            test_tenant(),
            false,
            Some(&creds_blob),
            json!({}),
        )
        .await;
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
        seed_integration(
            &pool,
            "int-7",
            test_tenant(),
            true,
            Some(&creds_blob),
            json!({}),
        )
        .await;
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
        seed_integration(
            &pool,
            "int-12",
            test_tenant(),
            true,
            Some(&creds_blob),
            json!({}),
        )
        .await;
        seed_sync_state(
            &pool,
            "secret-12",
            "int-12",
            test_tenant(),
            "vault/x",
            "synced",
        )
        .await;
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
            test_tenant(),
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        seed_sync_state(
            &pool,
            "secret-8",
            "int-8",
            test_tenant(),
            "vault/db-password",
            "synced",
        )
        .await;
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
            test_tenant(),
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        seed_sync_state(
            &pool,
            "secret-9",
            "int-9",
            test_tenant(),
            "vault/gone",
            "synced",
        )
        .await;
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
            test_tenant(),
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        seed_sync_state(
            &pool,
            "secret-10",
            "int-10",
            test_tenant(),
            "vault/x",
            "synced",
        )
        .await;
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

    // ── tenant isolation ─────────────────────────────────────────────────

    #[tokio::test]
    async fn push_stamps_tenant_from_owning_integration_with_no_cross_tenant_mixing() {
        // Two integrations owned by two different tenants, synced through
        // the same handler instance (this worker has no per-request tenant
        // context — every tenant boundary comes from the integration row).
        // Each resulting `vault_cloud_sync_state` row must carry its own
        // integration's tenant, never the other's.
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
            "int-tenant-a",
            test_tenant(),
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        seed_integration(
            &pool,
            "int-tenant-b",
            other_tenant(),
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry_a = push_entry(
            "int-tenant-a",
            "secret-tenant-a",
            "db-password",
            &envelope,
            "hunter2",
        );
        assert!(handler.handle(&entry_a).await.is_ok());
        let entry_b = push_entry(
            "int-tenant-b",
            "secret-tenant-b",
            "db-password",
            &envelope,
            "hunter3",
        );
        assert!(handler.handle(&entry_b).await.is_ok());

        let row_a = fetch_sync_state(&pool, "secret-tenant-a", "int-tenant-a")
            .await
            .expect("tenant A sync state row written");
        let row_b = fetch_sync_state(&pool, "secret-tenant-b", "int-tenant-b")
            .await
            .expect("tenant B sync state row written");
        assert_eq!(row_a.tenant_id, test_tenant());
        assert_eq!(row_b.tenant_id, other_tenant());
        assert_ne!(row_a.tenant_id, row_b.tenant_id);
    }

    #[tokio::test]
    async fn delete_removes_only_the_row_matching_secret_integration_and_tenant() {
        // `remove_sync_state` binds `tenant_id` into its `WHERE` clause
        // (defense in depth, tenancy-model.md §4) even though
        // `(secret_id, integration_id)` already uniquely identifies the
        // row. Confirms deleting tenant A's row leaves an unrelated tenant
        // B row (different secret/integration entirely) untouched.
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
            "int-tenant-c",
            test_tenant(),
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        seed_integration(
            &pool,
            "int-tenant-d",
            other_tenant(),
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        seed_sync_state(
            &pool,
            "secret-tenant-c",
            "int-tenant-c",
            test_tenant(),
            "vault/db-password",
            "synced",
        )
        .await;
        seed_sync_state(
            &pool,
            "secret-tenant-d",
            "int-tenant-d",
            other_tenant(),
            "vault/other",
            "synced",
        )
        .await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone());

        let entry = delete_entry("int-tenant-c", "secret-tenant-c", "vault/db-password");
        assert!(handler.handle(&entry).await.is_ok());

        assert!(
            fetch_sync_state(&pool, "secret-tenant-c", "int-tenant-c")
                .await
                .is_none(),
            "tenant C's row must be removed"
        );
        let row_d = fetch_sync_state(&pool, "secret-tenant-d", "int-tenant-d")
            .await
            .expect("tenant D's unrelated row must be untouched");
        assert_eq!(row_d.tenant_id, other_tenant());
    }

    // ── own-AWS federation (federated_credentials_for) ──────────────────
    //
    // `federated_base_credentials`'s success path (JWT flows through to a
    // real `sts:AssumeRoleWithWebIdentity` call) is exhaustively covered in
    // `crates/skauswatch-s3::credentials`'s own tests via its
    // `sts_endpoint_override` seam, which is private to that crate — the
    // public `federated_base_credentials` entry point this worker calls
    // always targets the real STS endpoint, so it can't be hermetically
    // redirected from here. What *is* this worker's own responsibility to
    // prove is the gating/fail-safe wiring below.

    /// A [`skauswatch_s3::credentials::JwtSvidSource`] double that always
    /// reports "no identity held" — mirrors what a degraded/unattested
    /// `IdentityProvider` (no SPIRE agent reachable) would surface.
    struct DegradedJwtSource;

    #[async_trait::async_trait]
    impl skauswatch_s3::credentials::JwtSvidSource for DegradedJwtSource {
        async fn fetch_jwt_svid_token(
            &self,
            _audience: &str,
        ) -> Result<String, skauswatch_s3::credentials::CredentialError> {
            Err(skauswatch_s3::credentials::CredentialError::Identity(
                "no identity held (test double)".to_owned(),
            ))
        }
    }

    fn federation_role_arn() -> String {
        "arn:aws:iam::123456789012:role/skauswatch-base".to_owned()
    }

    #[tokio::test]
    async fn federated_credentials_for_returns_none_for_non_aws_provider() {
        let handler = SyncHandler::new(
            "azure",
            sqlx::postgres::PgPoolOptions::new()
                .connect_lazy("postgres://test:test@127.0.0.1:1/test")
                .expect("lazy pool"),
            EnvelopeEncryption::default(),
        )
        .with_federation(
            std::sync::Arc::new(DegradedJwtSource),
            federation_role_arn(),
        );

        let result = handler
            .federated_credentials_for(&json!({}), &json!({}))
            .await;
        assert!(
            result.is_none(),
            "federation must only ever apply to the aws provider"
        );
    }

    #[tokio::test]
    async fn federated_credentials_for_returns_none_without_federation_configured() {
        let handler = test_handler(); // federation: None (default via SyncHandler::new)
        let result = handler
            .federated_credentials_for(&json!({}), &json!({}))
            .await;
        assert!(
            result.is_none(),
            "no federation configured must never attempt federation"
        );
    }

    #[tokio::test]
    async fn federated_credentials_for_returns_none_when_static_credentials_present() {
        let handler = test_handler().with_federation(
            std::sync::Arc::new(DegradedJwtSource),
            federation_role_arn(),
        );
        let result = handler
            .federated_credentials_for(&aws_credentials(), &json!({}))
            .await;
        assert!(
            result.is_none(),
            "a customer's own static credentials must always win over federation"
        );
    }

    #[tokio::test]
    async fn federated_credentials_for_returns_none_when_identity_degraded() {
        let handler = test_handler().with_federation(
            std::sync::Arc::new(DegradedJwtSource),
            federation_role_arn(),
        );
        let result = handler
            .federated_credentials_for(&json!({}), &json!({}))
            .await;
        assert!(
            result.is_none(),
            "a degraded identity source must fall back to None, never fatal"
        );
    }

    /// Same shape as `push_success_inserts_synced_sync_state_row`, but the
    /// integration carries no static credentials and federation is
    /// configured against a degraded identity source. `AwsProvider`'s
    /// no-static/no-override path builds its client directly via
    /// `Config::builder()` (not `aws-config`'s default chain — see that
    /// builder's own doc comment), so it has never had ambient
    /// env/IMDS/profile credentials to fall back to; a degraded federation
    /// attempt lands on exactly that same pre-existing behavior. What this
    /// test proves is the fail-safe contract this feature adds: the
    /// failed federation attempt is caught, logged, and treated as "no
    /// override" — the sync completes deterministically (a clean `"error"`
    /// sync-state row, matching `push_provider_failure_records_error_sync_status`'s
    /// shape), never a panic, hang, or unhandled `Result::Err` propagating
    /// out of `do_push`.
    #[tokio::test]
    async fn push_falls_back_to_default_chain_when_federation_degraded_and_no_static_creds() {
        // No route mounted — proves no request ever reaches this server at
        // all (request construction fails locally, credential-less, before
        // any network I/O), mirroring
        // `push_secret_without_static_credentials_falls_back_gracefully`'s
        // pattern for the exact same `AwsProvider` no-credentials shape.
        let server = MockServer::start().await;
        let pool = db_pool().await;
        let envelope = test_envelope();
        // No access_key_id/secret_access_key at all — exercises the
        // "no static creds" branch of `federated_credentials_for`.
        let creds_blob = encrypt_credentials(&envelope, &json!({}));
        seed_integration(
            &pool,
            "int-fed-fallback",
            test_tenant(),
            true,
            Some(&creds_blob),
            json!({"endpoint_url": server.uri()}),
        )
        .await;
        let handler = SyncHandler::new("aws", pool.clone(), envelope.clone()).with_federation(
            std::sync::Arc::new(DegradedJwtSource),
            federation_role_arn(),
        );

        let entry = push_entry(
            "int-fed-fallback",
            "secret-fed-fallback",
            "fed-fallback",
            &envelope,
            "hunter2",
        );
        assert!(handler.handle(&entry).await.is_ok());

        let row = fetch_sync_state(&pool, "secret-fed-fallback", "int-fed-fallback")
            .await
            .expect("sync state row inserted (do_push always records an outcome)");
        assert_eq!(
            row.sync_status, "error",
            "degraded federation + no static creds must land on AwsProvider's pre-existing \
             no-credentials outcome deterministically, never panic or hang"
        );
        let requests = server
            .received_requests()
            .await
            .expect("request recording enabled");
        assert!(
            requests.is_empty(),
            "no request should ever reach the mock — credential-less request construction \
             fails locally"
        );
    }
}
