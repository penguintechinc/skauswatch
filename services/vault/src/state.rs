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

/// Auth settings: ES256 JWT verify key shared with the manager and webui
/// (audit finding H1b — vault never mints tokens, so it holds only the
/// public verify half, never `JWT_SIGNING_KEY`).
#[derive(Debug, Clone)]
pub struct AuthSettings {
    /// ES256 verify key (env `JWT_VERIFY_KEY`, PEM SPKI public key).
    pub jwt_verify_key: jsonwebtoken::DecodingKey,
}

impl AuthSettings {
    /// Loads the ES256 verify key via the house fail-fast policy
    /// (`skauswatch_auth::load_jwt_verify_key`): a missing/empty
    /// `JWT_VERIFY_KEY` aborts startup in production (`RELEASE_MODE !=
    /// "false"`) rather than falling back to a guessable value — vault's
    /// own former fallback (`dev-{pid}`) was both weak (a small, guessable
    /// process id) and never checked production posture at all. Non-prod
    /// only gets a random ephemeral keypair's verify half, per the shared
    /// policy.
    fn from_env() -> Result<Self, skauswatch_auth::JwtKeyError> {
        Ok(Self {
            jwt_verify_key: skauswatch_auth::load_jwt_verify_key()?,
        })
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

        let auth = AuthSettings::from_env().map_err(|e| anyhow::anyhow!("jwt secret: {e}"))?;

        Ok(Arc::new(Self {
            license,
            db,
            auth,
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
                jwt_verify_key: test_jwt_verify_key(),
            },
            envelope: RwLock::new(envelope),
            streams: None,
        })
    }
}

/// Fixed, throwaway ES256 (P-256) test verify key — identical to
/// `crates/skauswatch-testkit::jwt`'s `VERIFY_PEM` fixture (duplicated, not
/// shared: [`AppStateInner::for_tests`]/[`AppStateInner::for_tests_with_db`]
/// are NOT `#[cfg(test)]`-gated, so this module can't pull in
/// `skauswatch-testkit`, a `[dev-dependencies]`-only crate). Every
/// `#[cfg(test)]` module in this service that mints a token via
/// `skauswatch_testkit::jwt::signing_key()` verifies against a state built
/// from this same PEM — keep the two fixtures byte-identical if either is
/// ever regenerated.
#[cfg_attr(not(test), allow(dead_code))]
const TEST_VERIFY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP0rRGDpY7mvK+4dCItv+ilnNZcl7
6Y6TyB7Co5+J5qL9l1XVMoIf09g3asOdnSp55o5QtwR7qsf8qg3yVPbHRw==
-----END PUBLIC KEY-----
";

/// Parses [`TEST_VERIFY_PEM`]. Panics on parse failure — a broken fixture
/// literal is a test-infra fault, never a case under test.
#[cfg_attr(not(test), allow(dead_code))]
#[allow(clippy::panic)]
fn test_jwt_verify_key() -> jsonwebtoken::DecodingKey {
    jsonwebtoken::DecodingKey::from_ec_pem(TEST_VERIFY_PEM.as_bytes())
        .unwrap_or_else(|e| panic!("test fixture verify key: {e}"))
}
