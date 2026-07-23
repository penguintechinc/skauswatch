//! Shared application state: Postgres pool, auth settings, the license/flag
//! client, and the Valkey/Redis Streams producer. gRPC clients join as their
//! routers are ported.

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};
use skauswatch_streams::StreamProducer;
use sqlx::PgPool;

/// Auth settings mirroring the v1 `AuthConfig` defaults.
#[derive(Debug, Clone)]
pub struct AuthSettings {
    /// HS256 signing secret (env `JWT_SECRET_KEY`).
    pub jwt_secret: String,
    /// Access-token lifetime in minutes (v1 default 30).
    pub access_expires_minutes: i64,
    /// Refresh-token lifetime in days (v1 default 7).
    pub refresh_expires_days: i64,
    /// Failed logins before lockout (v1 default 5).
    pub max_login_attempts: i32,
    /// Lockout duration in minutes (v1 default 15).
    pub lockout_minutes: i64,
}

impl AuthSettings {
    fn from_env() -> Self {
        Self {
            jwt_secret: std::env::var("JWT_SECRET_KEY").unwrap_or_else(|_| {
                tracing::warn!("JWT_SECRET_KEY not set — using ephemeral dev secret");
                uuid_like_fallback()
            }),
            access_expires_minutes: 30,
            refresh_expires_days: 7,
            max_login_attempts: 5,
            lockout_minutes: 15,
        }
    }
}

fn uuid_like_fallback() -> String {
    // Dev-only fallback; production deployments always set JWT_SECRET_KEY.
    format!("dev-{}", std::process::id())
}

/// Inner state shared across all handlers via `Arc`.
pub struct AppStateInner {
    /// License entitlement + PostHog flag client (fail-safe).
    pub license: Arc<LicenseClient>,
    /// Postgres pool (per-service account, v1 schema).
    pub db: PgPool,
    /// Auth settings.
    pub auth: AuthSettings,
    /// Redis Streams producer. `None` only when streams are not initialized
    /// (tests) — v1 guards every publish with `if stream_manager:` and its
    /// healthz reports `not initialized` in the same situation.
    pub streams: Option<StreamProducer>,
}

/// Cheap-to-clone handle used as axum state.
pub type AppState = Arc<AppStateInner>;

impl AppStateInner {
    /// Builds state from environment configuration. DB connects with
    /// retry/backoff; license client degrades to cached/community.
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

        // v1 env semantics: REDIS_URL (default redis://redis:6379/0),
        // optional REDIS_PASSWORD, REDIS_KEY_PREFIX (default skauswatch).
        // v1 raises out of startup when the broker is unreachable — match.
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
            streams: Some(streams),
        }))
    }

    /// Publishes ordered fields to a `skauswatch:*` stream, swallowing every
    /// failure with a warning — v1 wraps each HTTP-request publish site in
    /// try/except so publishing never fails the request; the `None` producer
    /// mirrors v1's `if stream_manager:` silent skip.
    pub async fn publish_stream(&self, stream: &str, fields: skauswatch_streams::EntryFields) {
        let Some(producer) = &self.streams else {
            return;
        };
        if let Err(e) = producer.publish(stream, fields).await {
            tracing::warn!(stream, error = %e, "failed to publish to stream");
        }
    }

    /// Test constructor: caller-supplied license client, lazy (unconnected)
    /// pool — handlers that don't touch the DB work without infrastructure.
    #[cfg_attr(not(test), allow(dead_code))]
    #[allow(clippy::panic)] // test-only constructor fails loudly by design
    pub fn for_tests(license: Arc<LicenseClient>) -> AppState {
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy test pool: {e}"));
        Arc::new(Self {
            license,
            db,
            auth: AuthSettings {
                jwt_secret: "test-secret".to_owned(),
                access_expires_minutes: 30,
                refresh_expires_days: 7,
                max_login_attempts: 5,
                lockout_minutes: 15,
            },
            streams: None,
        })
    }
}
