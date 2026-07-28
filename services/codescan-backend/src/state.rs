//! Shared application state: Postgres pool, JWT auth settings, the
//! license/flag client, the credential cipher, and the Valkey/Redis Streams
//! producer used to enqueue review tasks onto `codescan:tasks`.

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};
use skauswatch_streams::StreamProducer;
use sqlx::PgPool;

use crate::crypto::CredentialCipher;

/// JWT settings — this service only verifies tokens issued by the manager,
/// so only the shared signing secret is needed (no issuance/expiry config).
#[derive(Debug, Clone)]
pub struct AuthSettings {
    /// HS256 signing secret (env `JWT_SECRET_KEY`), shared with the manager.
    pub jwt_secret: String,
}

impl AuthSettings {
    fn from_env() -> Self {
        Self {
            jwt_secret: std::env::var("JWT_SECRET_KEY").unwrap_or_else(|_| {
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
    /// Postgres pool (per-service `codescan` account, `codescan_*` tables only).
    pub db: PgPool,
    /// JWT auth settings.
    pub auth: AuthSettings,
    /// AES-256-GCM cipher for git credential tokens at rest.
    pub crypto: Arc<CredentialCipher>,
    /// Redis Streams producer for `codescan:tasks`. `None` only in tests —
    /// every publish site swallows a missing producer the same way it
    /// swallows a transport error (fire-and-forget enqueue, never fails the
    /// request that triggered it).
    pub streams: Option<StreamProducer>,
}

/// Cheap-to-clone handle used as axum state.
pub type AppState = Arc<AppStateInner>;

impl AppStateInner {
    /// Builds state from environment configuration. DB connects with
    /// retry/backoff; license client degrades to cached/community; the
    /// credential cipher key is mandatory (fails startup if missing/invalid).
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

        let crypto =
            CredentialCipher::from_env().map_err(|e| anyhow::anyhow!("credential cipher: {e}"))?;

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
            crypto: Arc::new(crypto),
            streams: Some(streams),
        }))
    }

    /// Publishes ordered fields to a `skauswatch:*` stream, swallowing every
    /// failure with a warning — enqueue never fails the HTTP request that
    /// triggered it (matches `services/manager/src/state.rs`).
    pub async fn publish_stream(&self, stream: &str, fields: skauswatch_streams::EntryFields) {
        let Some(producer) = &self.streams else {
            tracing::warn!(stream, "stream producer not initialized, dropping publish");
            return;
        };
        if let Err(e) = producer.publish(stream, fields).await {
            tracing::warn!(stream, error = %e, "failed to publish to stream");
        }
    }

    /// Test constructor: caller-supplied license client, lazy (unconnected)
    /// pool, and a fixed test credential key — handlers that don't touch the
    /// DB or credential cipher work without infrastructure.
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::panic)] // test-only constructor fails loudly by design
    pub fn for_tests(license: Arc<LicenseClient>) -> AppState {
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy test pool: {e}"));
        Self::for_tests_with_db(license, db)
    }

    /// Test constructor for handler/DB-layer tests: identical fixed test
    /// JWT secret and credential key to [`for_tests`], but backed by a real,
    /// connected pool — typically one from
    /// `skauswatch_testkit::db::test_pool` — instead of the lazy/unconnected
    /// one, so handlers that issue real queries (list/create/update/delete)
    /// work under test.
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::panic)] // test-only constructor fails loudly by design
    pub fn for_tests_with_db(license: Arc<LicenseClient>, db: PgPool) -> AppState {
        let test_key =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [3u8; 32]);
        let crypto = CredentialCipher::from_base64_key(&test_key)
            .unwrap_or_else(|e| panic!("test credential cipher: {e:?}"));
        Arc::new(Self {
            license,
            db,
            auth: AuthSettings {
                jwt_secret: "test-secret".to_owned(),
            },
            crypto: Arc::new(crypto),
            streams: None,
        })
    }
}
