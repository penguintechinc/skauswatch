//! Shared application state: Postgres pool, JWT auth settings, the
//! license/flag client, the credential cipher, and the Valkey/Redis Streams
//! producer used to enqueue review tasks onto `codescan:tasks`.

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};
use skauswatch_streams::StreamProducer;
use skauswatch_vault::CredentialCipher;
use sqlx::PgPool;

/// JWT settings — this service only verifies tokens issued by the manager,
/// so only the shared ES256 verify key is needed (no issuance/expiry
/// config; audit finding H1b — was a shared symmetric `JWT_SECRET_KEY`).
#[derive(Debug, Clone)]
pub struct AuthSettings {
    /// ES256 verify key (env `JWT_VERIFY_KEY`, PEM SPKI public key), shared
    /// with the manager (the sole issuer, which also holds the private
    /// `JWT_SIGNING_KEY` half).
    pub jwt_verify_key: jsonwebtoken::DecodingKey,
}

impl AuthSettings {
    /// Loads the shared verify key via the house fail-fast policy
    /// (`skauswatch_auth::load_jwt_verify_key`): a missing/empty value FAILS
    /// STARTUP in production rather than falling back to a
    /// process-id-derived, guessable secret — this service verifies every
    /// non-public request's tenant boundary against this key, so a weak
    /// fallback was a real auth bypass risk, not just a dev convenience.
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            jwt_verify_key: skauswatch_auth::load_jwt_verify_key()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        })
    }
}

impl skauswatch_auth::JwtSecretSource for AppStateInner {
    fn jwt_verify_key(&self) -> &jsonwebtoken::DecodingKey {
        &self.auth.jwt_verify_key
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

/// Bounds the ad hoc `reqwest::Client` `main.rs::healthcheck` builds for its
/// own `/healthz` self-probe — audit finding (issue #149, HIGH): a hung
/// connect must never wedge indefinitely. Mirrors
/// `services/depgate/src/config.rs::HttpClientConfig` exactly.
#[derive(Debug, Clone, Copy)]
pub struct HttpClientConfig {
    /// Whole-request timeout in seconds (`CODESCAN_BACKEND_HTTP_TIMEOUT_SECS`,
    /// default 30) — the call site's own explicit 3s `.timeout()` still
    /// overrides this per call.
    pub timeout_secs: u64,
    /// TCP+TLS connect timeout in seconds
    /// (`CODESCAN_BACKEND_HTTP_CONNECT_TIMEOUT_SECS`, default 10).
    pub connect_timeout_secs: u64,
}

impl HttpClientConfig {
    /// Loads the shared bounds from the environment. Back-compat: unset env
    /// vars preserve prior behavior except now bounded (previously
    /// unbounded — no timeout at all on a bare `reqwest::Client::new()`).
    pub fn from_env() -> Self {
        Self {
            timeout_secs: std::env::var("CODESCAN_BACKEND_HTTP_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            connect_timeout_secs: std::env::var("CODESCAN_BACKEND_HTTP_CONNECT_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        }
    }
}

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
            auth: AuthSettings::from_env()?,
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
                jwt_verify_key: skauswatch_auth::test_fixture_keypair().1.clone(),
            },
            crypto: Arc::new(crypto),
            streams: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_client_config_defaults_are_bounded() {
        // regression: gh-149 — the healthcheck's reqwest::Client must never
        // build with an unbounded (no-timeout) default.
        assert!(std::env::var("CODESCAN_BACKEND_HTTP_TIMEOUT_SECS").is_err());
        assert!(std::env::var("CODESCAN_BACKEND_HTTP_CONNECT_TIMEOUT_SECS").is_err());
        let cfg = HttpClientConfig::from_env();
        assert_eq!(cfg.timeout_secs, 30);
        assert_eq!(cfg.connect_timeout_secs, 10);
    }
}
