//! Shared application state: Postgres pool, auth settings, the license/flag
//! client, and the Valkey/Redis Streams producer. gRPC clients join as their
//! routers are ported.

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};
use skauswatch_identity::IdentityProvider;
use skauswatch_streams::StreamProducer;
use skauswatch_vault::EnvelopeEncryption;
use sqlx::PgPool;

/// Reads an env var, falling back to `default` when unset or empty.
fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_owned(),
    }
}

/// Deployment environment segment used both in this workload's own SPIFFE
/// ID and in the peer identities it trusts (`spiffe://penguintech.io/<env>/
/// ...` — `docs/v2-port/service-auth-model.md` §1). Read from `SPIFFE_ENV`,
/// defaulting to `"beta"` — mirrors `skauswatch-pki`'s identical
/// `config::spiffe_env` convention exactly (this crate has no `config.rs`
/// module of its own, so the helper lives here alongside the other
/// `from_env()`-adjacent settings).
pub(crate) fn spiffe_env() -> String {
    env_or("SPIFFE_ENV", "beta")
}

/// Bounds every ad hoc `reqwest::Client` this crate builds for an outbound
/// hop (siem.rs's logs/OpenSearch probes, codescan.rs's worker-codescan
/// proxy, main.rs's own `/healthz` self-probe) — audit finding (issue #149,
/// HIGH): a hung/slow peer must never wedge the caller indefinitely. Mirrors
/// `services/depgate/src/config.rs::HttpClientConfig` exactly.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HttpClientConfig {
    /// Whole-request timeout in seconds (`MANAGER_HTTP_TIMEOUT_SECS`,
    /// default 30). Call sites that already set their own per-request
    /// `.timeout()` (siem.rs, codescan.rs) still override this per call —
    /// this is only the client-level fallback.
    pub(crate) timeout_secs: u64,
    /// TCP+TLS connect timeout in seconds
    /// (`MANAGER_HTTP_CONNECT_TIMEOUT_SECS`, default 10).
    pub(crate) connect_timeout_secs: u64,
}

impl HttpClientConfig {
    /// Loads the shared bounds from the environment. Back-compat: unset env
    /// vars preserve prior behavior except now bounded (previously
    /// unbounded — no timeout at all on a bare `reqwest::Client::new()`).
    pub(crate) fn from_env() -> Self {
        Self {
            timeout_secs: env_or("MANAGER_HTTP_TIMEOUT_SECS", "30")
                .parse()
                .unwrap_or(30),
            connect_timeout_secs: env_or("MANAGER_HTTP_CONNECT_TIMEOUT_SECS", "10")
                .parse()
                .unwrap_or(10),
        }
    }
}

/// Builds a bounded `reqwest::Client` per [`HttpClientConfig`] — replaces a
/// bare `reqwest::Client::new()` at this crate's outbound call sites.
/// `ClientBuilder::build()` only fails on conflicting TLS-backend/proxy
/// config, none of which this call site sets, but the `Result` is still
/// surfaced (never `.unwrap()`/`.expect()`) so a future change to this
/// builder can't silently become a panic — callers fold it into their
/// existing `reqwest::Error` handling via `?`/`map_err`.
pub(crate) fn http_client() -> Result<reqwest::Client, reqwest::Error> {
    let cfg = HttpClientConfig::from_env();
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(cfg.timeout_secs))
        .connect_timeout(std::time::Duration::from_secs(cfg.connect_timeout_secs))
        .build()
}

/// Auth settings mirroring the v1 `AuthConfig` defaults.
#[derive(Debug, Clone)]
pub struct AuthSettings {
    /// Private EC signing key (env `JWT_SIGNING_KEY`, PEM PKCS#8) — this
    /// service is the sole issuer of user access/refresh tokens, so it's
    /// the only one that holds this half of the keypair (audit finding
    /// H1b: replaces the single shared symmetric `JWT_SECRET_KEY`).
    pub jwt_signing_key: jsonwebtoken::EncodingKey,
    /// Public EC verify key (env `JWT_VERIFY_KEY`, PEM SPKI) — used to
    /// verify this service's own minted tokens (`CurrentUser`,
    /// `tenant_middleware`) and any machine `ServiceClaims` token presented
    /// to this service's gRPC surface (`require_jwt`).
    pub jwt_verify_key: jsonwebtoken::DecodingKey,
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
    /// Loads auth settings, applying the house fail-fast key-loading policy
    /// to `JWT_SIGNING_KEY`/`JWT_VERIFY_KEY` (see
    /// `skauswatch_auth::load_jwt_signing_key`/`load_jwt_verify_key`):
    /// production refuses to start without real PEM-encoded EC keys rather
    /// than falling back to a guessable per-process value.
    fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            jwt_signing_key: skauswatch_auth::load_jwt_signing_key()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            jwt_verify_key: skauswatch_auth::load_jwt_verify_key()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            access_expires_minutes: 30,
            refresh_expires_days: 7,
            max_login_attempts: 5,
            lockout_minutes: 15,
        })
    }
}

/// Fixed, throwaway ES256 (P-256) test keypair — draws from
/// `skauswatch_auth::test_fixture_keypair`'s process-lifetime cache, the
/// same single source `crates/skauswatch-testkit::jwt`'s `signing_key()`/
/// `verify_key()` fixture reads from (both crates already depend on
/// `skauswatch-auth` as a regular, non-dev dependency; `skauswatch-testkit`
/// itself can't be pulled into this crate's production dependency graph —
/// see that function's docs). Every `#[cfg(test)]` module in this service
/// that mints a token via `skauswatch_testkit::jwt::signing_key()`/
/// `verify_key()` verifies against a state built from these same keys
/// because both crates draw from the identical cached instance within one
/// test process, not a byte-for-byte-copied literal. [`AuthSettings::for_tests`]
/// and friends below are NOT `#[cfg(test)]`-gated — `routes/test_support.rs`'s
/// integration helpers call them from outside this crate's own test cfg —
/// so these wrappers can't be `#[cfg(test)]`-gated either.
#[cfg_attr(not(test), allow(dead_code))]
fn test_jwt_signing_key() -> jsonwebtoken::EncodingKey {
    skauswatch_auth::test_fixture_keypair().0.clone()
}

/// See [`test_jwt_signing_key`].
#[cfg_attr(not(test), allow(dead_code))]
fn test_jwt_verify_key() -> jsonwebtoken::DecodingKey {
    skauswatch_auth::test_fixture_keypair().1.clone()
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
    /// SPIFFE Workload API identity (`docs/v2-port/service-auth-model.md`
    /// §2) — presents manager's own X.509-SVID for gRPC mTLS (server) and,
    /// once a real caller lands, as a client dialing pki. `None` only in
    /// test constructors that don't exercise mTLS at all (`grpc::serve`
    /// treats that identically to a held-but-degraded provider: fall back
    /// to the pre-mTLS plaintext+ES256 behavior — see that module's docs).
    /// Real `from_env()` startup always populates `Some`; production
    /// hard-fails inside `IdentityProvider::connect` itself before this
    /// field would ever be `None` in prod.
    pub identity: Option<Arc<IdentityProvider>>,
    /// Explicit `awsIdentity.mode` selection (`AWS_IDENTITY_MODE`) —
    /// deterministically selects how manager resolves its own base AWS
    /// identity for `assume_role`-mode S3 bucket credentials (the
    /// `/buckets/{id}/test` connection check); see
    /// `docs/v2-port/aws-identity-runbook.md` §0.
    pub aws_identity_mode: skauswatch_s3::credentials::AwsIdentityModeKind,
    /// This service's own federation IAM role ARN (`AWS_FEDERATION_ROLE_ARN`)
    /// — never a customer's `role_arn`. `None` disables federation
    /// regardless of `aws_identity_mode` (see
    /// `skauswatch_s3::credentials::AwsIdentityMode::from_kind`'s fail-safe
    /// degrade-to-`Irsa` behavior).
    pub aws_federation_role_arn: Option<String>,
}

/// Cheap-to-clone handle used as axum state.
pub type AppState = Arc<AppStateInner>;

/// Lets `skauswatch_auth::tenant_middleware`/`AuthenticatedCaller` verify
/// tokens against this service's `JWT_VERIFY_KEY` without re-threading the
/// key through every call site — see `crates/skauswatch-auth`.
impl skauswatch_auth::JwtSecretSource for AppStateInner {
    fn jwt_verify_key(&self) -> &jsonwebtoken::DecodingKey {
        &self.auth.jwt_verify_key
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

        // SPIFFE Workload API identity for gRPC mTLS
        // (docs/v2-port/service-auth-model.md §2). Fails fast in production
        // if no SPIRE agent is attestable — same fail-safe posture as the
        // JWT secret and license client above. Deliberately `connect()`,
        // not a domain-gated variant — see `skauswatch_identity`'s
        // crate-level docs and `skauswatch-pki`'s identical call site for
        // the full rationale (a deployment-domain bypass is for
        // license/feature-flag gating only, never authentication).
        let identity = Arc::new(
            IdentityProvider::connect()
                .await
                .map_err(|e| anyhow::anyhow!("identity provider: {e}"))?,
        );

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
            identity: Some(identity),
            aws_identity_mode: skauswatch_s3::credentials::AwsIdentityModeKind::from_env(),
            aws_federation_role_arn: std::env::var("AWS_FEDERATION_ROLE_ARN")
                .ok()
                .filter(|v| !v.is_empty()),
        }))
    }

    /// Builds the explicit [`skauswatch_s3::credentials::AwsIdentityMode`]
    /// manager should resolve `assume_role`-mode S3 base credentials with,
    /// from the held `identity`/`aws_identity_mode`/
    /// `aws_federation_role_arn` — see `docs/v2-port/aws-identity-runbook.md`
    /// §0. `Spire` degrades to `Irsa` (never errors) when either the
    /// identity or the role ARN is unavailable — same fail-safe posture as
    /// every other identity-adjacent fallback in this service.
    pub fn aws_identity_mode(&self) -> skauswatch_s3::credentials::AwsIdentityMode<'_> {
        let federation = self
            .identity
            .as_deref()
            .zip(self.aws_federation_role_arn.as_deref())
            .map(|(identity, role_arn)| {
                (
                    identity as &dyn skauswatch_s3::credentials::JwtSvidSource,
                    role_arn,
                )
            });
        skauswatch_s3::credentials::AwsIdentityMode::from_kind(self.aws_identity_mode, federation)
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
                jwt_signing_key: test_jwt_signing_key(),
                jwt_verify_key: test_jwt_verify_key(),
                access_expires_minutes: 30,
                refresh_expires_days: 7,
                max_login_attempts: 5,
                lockout_minutes: 15,
            },
            streams: None,
            envelope: test_envelope(),
            identity: None,
            aws_identity_mode: skauswatch_s3::credentials::AwsIdentityModeKind::Irsa,
            aws_federation_role_arn: None,
        })
    }

    /// Like [`Self::for_tests`], but with a caller-supplied
    /// [`IdentityProvider`] — used by `grpc`/`grpc::pki_client` tests that
    /// need to exercise the SPIFFE-identity-aware code paths (degraded-
    /// provider fallback, matcher wiring, real mTLS handshakes) rather than
    /// the `identity: None` shortcut every other test constructor uses,
    /// which skips the identity check entirely instead of exercising its
    /// degraded branch. Mirrors `skauswatch-pki`'s identical
    /// `for_tests_with_identity` constructor.
    #[cfg(test)]
    #[allow(clippy::panic)] // test-only constructor fails loudly by design
    pub(crate) fn for_tests_with_identity(
        license: Arc<LicenseClient>,
        identity: Arc<IdentityProvider>,
    ) -> AppState {
        let db = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy test pool: {e}"));
        Arc::new(Self {
            license,
            db,
            auth: AuthSettings {
                jwt_signing_key: test_jwt_signing_key(),
                jwt_verify_key: test_jwt_verify_key(),
                access_expires_minutes: 30,
                refresh_expires_days: 7,
                max_login_attempts: 5,
                lockout_minutes: 15,
            },
            streams: None,
            envelope: test_envelope(),
            identity: Some(identity),
            aws_identity_mode: skauswatch_s3::credentials::AwsIdentityModeKind::Irsa,
            aws_federation_role_arn: None,
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

    #[test]
    fn spiffe_env_defaults_to_beta_when_unset() {
        assert!(std::env::var("SPIFFE_ENV").is_err());
        assert_eq!(spiffe_env(), "beta");
    }

    #[test]
    fn http_client_config_defaults_are_bounded() {
        // regression: gh-149 — this crate's ad hoc reqwest::Client sites
        // must never build with an unbounded (no-timeout) default.
        assert!(std::env::var("MANAGER_HTTP_TIMEOUT_SECS").is_err());
        assert!(std::env::var("MANAGER_HTTP_CONNECT_TIMEOUT_SECS").is_err());
        let cfg = HttpClientConfig::from_env();
        assert_eq!(cfg.timeout_secs, 30);
        assert_eq!(cfg.connect_timeout_secs, 10);
    }

    #[test]
    fn http_client_builds_successfully_with_default_bounds() {
        // Asserts `ClientBuilder::build()` actually succeeds for the exact
        // options this crate sets (timeout + connect_timeout only) — the
        // invariant documented on `http_client`'s doc comment.
        assert!(http_client().is_ok());
    }
}
