//! Shared application state: Postgres pool, auth settings, the license/flag
//! client, and the Valkey/Redis Streams producer. gRPC clients join as their
//! routers are ported.

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};
use skauswatch_streams::StreamProducer;
use skauswatch_vault::EnvelopeEncryption;
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
    /// Loads auth settings, applying the house fail-fast secret policy to
    /// `JWT_SECRET_KEY` (see `skauswatch_auth::load_jwt_secret`): production
    /// refuses to start without a real secret rather than falling back to a
    /// guessable per-process value.
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            jwt_secret: skauswatch_auth::load_jwt_secret().map_err(|e| anyhow::anyhow!("{e}"))?,
            access_expires_minutes: 30,
            refresh_expires_days: 7,
            max_login_attempts: 5,
            lockout_minutes: 15,
        })
    }
}

/// v1 `config.endpoint.api_secret` default — kept only as a value to reject, not
/// as a fallback (see `validate_endpoint_secret_for_production`).
const ENDPOINT_DEFAULT_SECRET: &str = "change-me-endpoint-secret";

/// Pure fail-fast predicate: is `secret` acceptable for production use?
/// Rejects blank values and the well-known v1 default.
fn endpoint_secret_is_valid_for_production(secret: &str) -> bool {
    let trimmed = secret.trim();
    !trimmed.is_empty() && trimmed != ENDPOINT_DEFAULT_SECRET
}

/// FAILS STARTUP in production when `ENDPOINT_API_SECRET` is unset, empty, or
/// still the well-known `change-me-endpoint-secret` default — running with any of
/// those lets anyone forge the ENDPOINT agent HMAC. Non-production is
/// unrestricted (routes/endpoint.rs reads the secret fresh per request and fails
/// closed against an empty value rather than falling back to the default).
fn validate_endpoint_secret_for_production(secret: &str) -> anyhow::Result<()> {
    if skauswatch_auth::is_production() && !endpoint_secret_is_valid_for_production(secret) {
        anyhow::bail!(
            "ENDPOINT_API_SECRET must be set to a real secret (not empty, not the default \
             \"{ENDPOINT_DEFAULT_SECRET}\") in production (RELEASE_MODE != \"false\")"
        );
    }
    Ok(())
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
    /// Envelope-encryption engine for `static`-mode S3 bucket credentials
    /// (security finding #2 — see `routes::s3_scan` and
    /// `skauswatch_s3::credentials`). Same `VAULT_MEK*` env vars as the
    /// `vault`/`worker-vault-sync`/`s3scan` services.
    pub envelope: EnvelopeEncryption,
}

/// Cheap-to-clone handle used as axum state.
pub type AppState = Arc<AppStateInner>;

/// Lets `skauswatch_auth::tenant_middleware`/`AuthenticatedCaller` verify
/// tokens against this service's `JWT_SECRET_KEY` without re-threading the
/// secret through every call site — see `crates/skauswatch-auth`.
impl skauswatch_auth::JwtSecretSource for AppStateInner {
    fn jwt_secret(&self) -> &str {
        &self.auth.jwt_secret
    }
}

impl AppStateInner {
    /// Builds state from environment configuration. DB connects with
    /// retry/backoff; license client degrades to cached/community. Fails
    /// fast (before any network I/O) if `JWT_SECRET_KEY`/`ENDPOINT_API_SECRET`
    /// are missing/default in production — see `AuthSettings::from_env` and
    /// `validate_endpoint_secret_for_production`.
    pub async fn from_env() -> anyhow::Result<AppState> {
        let auth = AuthSettings::from_env()?;
        validate_endpoint_secret_for_production(
            &std::env::var("ENDPOINT_API_SECRET").unwrap_or_default(),
        )?;

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

        // Same fail-fast policy as `vault`/`worker-vault-sync`/`s3scan`: a
        // manager that can never decrypt a static S3 credential must not
        // start silently.
        let envelope = EnvelopeEncryption::from_env()
            .map_err(|e| anyhow::anyhow!("envelope encryption init failed: {e}"))?;

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
            auth,
            streams: Some(streams),
            envelope,
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
        Self::for_tests_with_db(license, db)
    }

    /// Test constructor for handler/DB-layer tests: identical fixed test
    /// config to [`for_tests`], but backed by a real, connected pool —
    /// typically one from `skauswatch_testkit::db::test_pool`/`test_pool_multi`
    /// — instead of the lazy/unconnected one, so handlers that issue real
    /// queries (list/create/update/delete) work under test.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn for_tests_with_db(license: Arc<LicenseClient>, db: PgPool) -> AppState {
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
            envelope: test_envelope(),
        })
    }
}

/// Fixed single-MEK envelope shared by every manager test (mirrors the
/// identical fixture pattern in `skauswatch-vault`/`skauswatch-s3`'s own
/// tests) — good enough since no manager test exercises MEK rotation.
/// Not `#[cfg(test)]`-gated: [`AppStateInner::for_tests_with_db`] (which
/// calls this) is itself only `#[allow(dead_code)]`-suppressed outside
/// tests, not `cfg(test)`-gated, so this must compile in every profile too.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn test_envelope() -> EnvelopeEncryption {
    use std::collections::HashMap;

    use skauswatch_vault::MekVersion;

    EnvelopeEncryption::new(
        HashMap::from([(
            1,
            MekVersion {
                version: 1,
                key_bytes: [3u8; 32],
            },
        )]),
        1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_secret_rejects_blank_and_default() {
        assert!(!endpoint_secret_is_valid_for_production(""));
        assert!(!endpoint_secret_is_valid_for_production("   "));
        assert!(!endpoint_secret_is_valid_for_production(
            ENDPOINT_DEFAULT_SECRET
        ));
        assert!(!endpoint_secret_is_valid_for_production(&format!(
            "  {ENDPOINT_DEFAULT_SECRET}  "
        )));
    }

    #[test]
    fn endpoint_secret_accepts_a_real_value() {
        assert!(endpoint_secret_is_valid_for_production(
            "a-real-random-secret"
        ));
    }

    #[test]
    fn validate_endpoint_secret_only_enforced_when_production() {
        // This test process's ambient RELEASE_MODE is out of our control
        // (see the skauswatch-auth `resolve_required_secret`/
        // `release_mode_is_production` unit tests for the pure logic, which
        // doesn't require mutating global env state); this test only
        // exercises that a valid secret is *always* accepted regardless.
        assert!(validate_endpoint_secret_for_production("a-real-random-secret").is_ok());
    }
}
