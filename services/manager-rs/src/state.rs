//! Shared application state: Postgres pool, auth settings, and the
//! license/flag client. Valkey/streams and gRPC clients join as their
//! routers are ported.

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};
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

        Ok(Arc::new(Self {
            license,
            db,
            auth: AuthSettings::from_env(),
        }))
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
        })
    }
}
