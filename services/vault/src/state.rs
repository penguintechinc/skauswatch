//! Shared application state: Postgres pool, JWT signing secret, the
//! penguin-licensing flag/entitlement client (replaces v1's DB-driven
//! `LicenseValidator`), envelope encryption engine, and the Valkey/Redis
//! Streams producer used to notify `worker-vault-sync`.

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};
use skauswatch_streams::StreamProducer;
use skauswatch_vault::EnvelopeEncryption;
use sqlx::PgPool;
use tokio::sync::RwLock;

/// PostHog module flag gating every Vault route (see
/// `services/manager/src/flags.rs` `MODULE_FLAGS`) — replaces v1's
/// DB-stored license key + `/api/v2/validate` polling with the standard
/// penguin-licensing flag check.
pub const VAULT_FLAG: &str = "skauswatch.vault";

/// Auth settings: HS256 JWT secret shared with the manager and webui.
#[derive(Debug, Clone)]
pub struct AuthSettings {
    /// HS256 signing secret (env `JWT_SECRET_KEY`), matching v1
    /// `AuthConfig.jwt_secret` (env `JWT_SECRET`).
    pub jwt_secret: String,
}

impl AuthSettings {
    fn from_env() -> Self {
        Self {
            jwt_secret: std::env::var("JWT_SECRET_KEY")
                .or_else(|_| std::env::var("JWT_SECRET"))
                .unwrap_or_else(|_| {
                    tracing::warn!("JWT_SECRET_KEY not set — using ephemeral dev secret");
                    format!("dev-{}", std::process::id())
                }),
        }
    }
}

/// Inner state shared across all handlers via `Arc`.
pub struct AppStateInner {
    /// License entitlement + PostHog flag client (fail-safe).
    pub license: Arc<LicenseClient>,
    /// Postgres pool (per-service `vault` DB account, v1 schema —
    /// `vault_*` tables, zero schema changes in v2.0.0).
    pub db: PgPool,
    /// Auth settings.
    pub auth: AuthSettings,
    /// Envelope encryption engine. Wrapped in `RwLock` because `/mek/rotate`
    /// mutates `current_version` in place, matching v1's mutable
    /// `EnvelopeEncryption` instance stored on `app.config`.
    pub envelope: RwLock<EnvelopeEncryption>,
    /// Redis Streams producer, publishing to `vault:sync:{provider}` for
    /// `worker-vault-sync`. `None` only in tests.
    pub streams: Option<StreamProducer>,
}

/// Cheap-to-clone handle used as axum state.
pub type AppState = Arc<AppStateInner>;

impl AppStateInner {
    /// Builds state from environment configuration. DB connects with
    /// retry/backoff; license client degrades to cached/community; envelope
    /// encryption exits the process if `VAULT_MEK` is unset and not in dev
    /// mode (matching v1 `create_app`'s `sys.exit(1)`).
    pub async fn from_env() -> anyhow::Result<AppState> {
        let cfg = LicenseConfig::from_env("skauswatch")
            .map_err(|e| anyhow::anyhow!("license config: {e}"))?
            .with_bypass_domain("skauswatch.app");
        let license =
            LicenseClient::new(cfg).map_err(|e| anyhow::anyhow!("license client: {e}"))?;
        let _ = license.refresh().await;

        let db_cfg =
            skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
        let db = skauswatch_db::connect_postgres(&db_cfg)
            .await
            .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;

        let envelope = match EnvelopeEncryption::from_env() {
            Ok(enc) => enc,
            Err(e) => {
                tracing::error!(error = %e, "encryption init failed — VAULT_MEK not set");
                anyhow::bail!("envelope encryption init failed: {e}");
            }
        };

        // Redis key prefix matches the rest of the v2 fleet (manager
        // default `skauswatch`) — streams live in the shared
        // `skauswatch:vault:sync:{provider}` namespace consumed by
        // `worker-vault-sync` (see routes/sync.rs::sync_stream_name).
        let redis_url =
            std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379/0".to_owned());
        let redis_password = std::env::var("REDIS_PASSWORD").ok();
        let prefix = std::env::var("REDIS_KEY_PREFIX").unwrap_or_else(|_| "skauswatch".to_owned());
        let streams = StreamProducer::connect(&redis_url, redis_password.as_deref(), &prefix)
            .await
            .map_err(|e| anyhow::anyhow!("redis connect: {e}"))?;

        Ok(Arc::new(Self {
            license,
            db,
            auth: AuthSettings::from_env(),
            envelope: RwLock::new(envelope),
            streams: Some(streams),
        }))
    }

    /// Test constructor: caller-supplied license client + envelope engine,
    /// lazy (unconnected) pool — handlers exercised in tests must not touch
    /// the DB before their auth/license/validation guard returns.
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::panic)] // test-only constructor fails loudly by design
    pub fn for_tests(license: Arc<LicenseClient>, envelope: EnvelopeEncryption) -> AppState {
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy test pool: {e}"));
        Self::for_tests_with_db(license, envelope, db)
    }

    /// Test constructor for handler/DB-layer tests: identical fixed test
    /// JWT secret to [`for_tests`], but backed by a real, connected pool —
    /// typically one from `skauswatch_testkit::db::test_pool` — instead of
    /// the lazy/unconnected one, so handlers that issue real queries
    /// (secrets/JIT/one-time/sync/admin/audit CRUD) work under test.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn for_tests_with_db(
        license: Arc<LicenseClient>,
        envelope: EnvelopeEncryption,
        db: PgPool,
    ) -> AppState {
        Arc::new(Self {
            license,
            db,
            auth: AuthSettings {
                jwt_secret: "test-secret".to_owned(),
            },
            envelope: RwLock::new(envelope),
            streams: None,
        })
    }
}
