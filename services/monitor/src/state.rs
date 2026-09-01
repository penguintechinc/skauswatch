//! Shared application state: config, license/flag client, and the event
//! store (Elasticsearch/OpenSearch preferred, MongoDB fallback — v1
//! `LogProcessor` priority: `if self.elasticsearch: ... elif self.mongodb:
//! ...`).

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};

use crate::config::Config;
use crate::es::{ElasticsearchStore, EventStore};
use crate::models::BaseEvent;
use crate::threat_intel::store::ThreatStore;

/// Broadcast capacity for the live event stream — generous enough that a
/// burst doesn't force slow SSE subscribers to miss events under normal
/// load; lagged subscribers simply skip ahead (`tokio::sync::broadcast`
/// semantics), which is an acceptable trade-off for a best-effort live feed.
const EVENT_BUS_CAPACITY: usize = 1024;

/// Inner state shared across all handlers via `Arc`.
pub struct AppStateInner {
    /// Resolved configuration.
    pub config: Config,
    /// License entitlement + PostHog flag client (fail-safe).
    pub license: Arc<LicenseClient>,
    /// The active event store, if either backend is configured and reachable.
    pub event_store: Option<Arc<dyn EventStore>>,
    /// Live-event broadcast bus backing `GET /events/stream`. Fed by
    /// `crate::ingest::IngestPipeline`'s flush loop, itself fed by the log
    /// collectors spawned in `main.rs::serve` — see `src/ingest.rs` module
    /// docs for the producer side this closes.
    pub event_bus: tokio::sync::broadcast::Sender<BaseEvent>,
    /// ES256 verify key for bearer tokens (house `JWT_VERIFY_KEY`,
    /// finding #3; audit finding H1b — was a shared symmetric
    /// `JWT_SECRET_KEY`) — loaded via `skauswatch_auth::load_jwt_verify_key`,
    /// which FAILS STARTUP in production rather than the previous
    /// `MONITOR_SECRET_KEY`-or-random-UUID fallback. That fallback was
    /// worse than refusing to start: a fresh random secret on every
    /// restart silently invalidated every outstanding token, and — because
    /// it was never the *same* secret manager mints access tokens with —
    /// no genuine caller's token could ever validate here in the first
    /// place. Shared with every other JWT-verifying service (manager,
    /// vault, pki, sshca, codescan-backend) via the same env var, as it
    /// must be: they all verify tokens minted by manager's login endpoint
    /// against the same public key; only manager also holds the private
    /// `JWT_SIGNING_KEY` half.
    pub jwt_verify_key: jsonwebtoken::DecodingKey,
    /// The TAXII threat-intel engine's own Postgres-backed store
    /// (`crate::threat_intel`) — `None` when `DB_*` env vars aren't
    /// configured, degrading exactly like `event_store`: the feed poller
    /// simply never starts (see `main.rs::serve`) and
    /// `threat_intel::routes` answers 503 rather than failing startup.
    pub threat_store: Option<Arc<ThreatStore>>,
}

/// Cheap-to-clone handle used as axum state.
pub type AppState = Arc<AppStateInner>;

/// Lets `skauswatch_auth::tenant_middleware`/`AuthenticatedCaller` verify
/// tokens against this service's `JWT_VERIFY_KEY` without re-threading the
/// key through every call site — see `crates/skauswatch-auth`.
impl skauswatch_auth::JwtSecretSource for AppStateInner {
    fn jwt_verify_key(&self) -> &jsonwebtoken::DecodingKey {
        &self.jwt_verify_key
    }
}

impl AppStateInner {
    /// Builds state from environment configuration. The event store
    /// degrades gracefully: a misconfigured/unreachable backend logs a
    /// warning and leaves `event_store` `None` rather than failing startup
    /// (matches v1: ES/Mongo init failures are caught and logged, service
    /// still starts — see `main.py::startup`). Fails fast (before any
    /// network I/O) if `JWT_VERIFY_KEY` is missing in production — see
    /// `skauswatch_auth::load_jwt_verify_key` and the `jwt_verify_key` field
    /// docs.
    pub async fn from_env() -> anyhow::Result<AppState> {
        let jwt_verify_key =
            skauswatch_auth::load_jwt_verify_key().map_err(|e| anyhow::anyhow!("{e}"))?;
        let config = Config::from_env();

        let cfg = LicenseConfig::from_env("skauswatch")
            .map_err(|e| anyhow::anyhow!("license config: {e}"))?
            .with_bypass_domain("skauswatch.app");
        let license =
            LicenseClient::new(cfg).map_err(|e| anyhow::anyhow!("license client: {e}"))?;
        let _ = license.refresh().await;

        let event_store = build_event_store(&config).await;
        let threat_store = build_threat_store().await;
        let (event_bus, _rx) = tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY);

        Ok(Arc::new(Self {
            config,
            license,
            event_store,
            event_bus,
            jwt_verify_key,
            threat_store,
        }))
    }

    /// Test constructor: no event store, dev auth bypass off by default so
    /// auth tests exercise the real path unless a test opts in. Fixed
    /// `jwt_verify_key` (not loaded from env — mutating process env in
    /// tests is `unsafe`, denied workspace-wide) so tests can mint valid
    /// bearer tokens deterministically; see
    /// `routes::test_support::sign_claims`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn for_tests(license: Arc<LicenseClient>) -> AppState {
        let (event_bus, _rx) = tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY);
        Arc::new(Self {
            config: Config::from_env(),
            license,
            event_store: None,
            event_bus,
            jwt_verify_key: test_jwt_verify_key(),
            threat_store: None,
        })
    }

    /// Test constructor for `threat_intel::routes` handler tests: identical
    /// to [`for_tests`] but with a real, connected `threat_store` — typically
    /// backed by `skauswatch_testkit::db::test_pool`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn for_tests_with_threat_store(
        license: Arc<LicenseClient>,
        threat_store: Arc<ThreatStore>,
    ) -> AppState {
        let (event_bus, _rx) = tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY);
        Arc::new(Self {
            config: Config::from_env(),
            license,
            event_store: None,
            event_bus,
            jwt_verify_key: test_jwt_verify_key(),
            threat_store: Some(threat_store),
        })
    }
}

/// Fixed, throwaway ES256 (P-256) test verify key — identical to
/// `crates/skauswatch-testkit::jwt`'s `VERIFY_PEM` fixture (duplicated, not
/// shared: [`AppStateInner::for_tests`]/[`for_tests_with_threat_store`] are
/// NOT `#[cfg(test)]`-gated, so this module can't pull in
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

/// Event store backend: OpenSearch/Elasticsearch (Apache-2.0). Disabled →
/// None, and the search/get routes answer 503. (v1 also had a MongoDB
/// fallback; dropped in v2 — MongoDB's server is SSPL, and OpenSearch was
/// already the preferred backend and covers the same event search/get.)
async fn build_event_store(config: &Config) -> Option<Arc<dyn EventStore>> {
    if config.elasticsearch.enabled {
        let store = ElasticsearchStore::new(
            config.elasticsearch.url.clone(),
            config.elasticsearch.index_pattern.clone(),
            config.elasticsearch.username.clone(),
            config.elasticsearch.password.clone(),
        );
        tracing::info!(url = %config.elasticsearch.url, "elasticsearch event store configured");
        return Some(Arc::new(store));
    }
    None
}

/// Threat-intel store backend: Postgres, per `backend-database.md`.
/// Disabled → `None` whenever `DB_*` env vars aren't set at all (a
/// perfectly normal deployment for a monitor instance that doesn't run the
/// TAXII engine — `skauswatch_db::DbConfig::from_env`'s required fields
/// `name`/`user`/`pass` have no defaults, so their absence is itself the
/// "not configured" signal, same spirit as `elasticsearch.enabled` but
/// without a redundant separate flag). A *misconfigured* (vars present but
/// unreachable) database logs a warning and also degrades to `None` —
/// same graceful-degradation policy as [`build_event_store`], not the
/// fail-fast policy `vault`/`pki` use for their primary database.
async fn build_threat_store() -> Option<Arc<ThreatStore>> {
    let db_cfg = match skauswatch_db::DbConfig::from_env() {
        Ok(cfg) => cfg,
        Err(_) => {
            tracing::info!("threat-intel database not configured (DB_* env vars unset)");
            return None;
        }
    };
    match skauswatch_db::connect_postgres(&db_cfg).await {
        Ok(pool) => {
            tracing::info!("threat-intel database connected");
            Some(Arc::new(ThreatStore::new(pool)))
        }
        Err(e) => {
            tracing::warn!(error = %e, "threat-intel database unreachable — TAXII engine disabled");
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::{ApiConfig, ElasticsearchConfig, SecurityConfig, TenancyConfig};

    fn config_with_es(enabled: bool) -> Config {
        Config {
            api: ApiConfig {
                host: "0.0.0.0".to_owned(),
                port: 8003,
            },
            security: SecurityConfig { auth_enabled: true },
            elasticsearch: ElasticsearchConfig {
                enabled,
                url: "http://localhost:9200".to_owned(),
                index_pattern: "aaa-events-*".to_owned(),
                username: None,
                password: None,
            },
            tenancy: TenancyConfig {
                tenant_id: String::new(),
            },
        }
    }

    #[tokio::test]
    async fn build_event_store_is_none_when_elasticsearch_disabled() {
        assert!(build_event_store(&config_with_es(false)).await.is_none());
    }

    #[tokio::test]
    async fn build_event_store_is_some_when_elasticsearch_enabled() {
        assert!(build_event_store(&config_with_es(true)).await.is_some());
    }

    /// The build container/CI runner sets `DB_HOST`/`DB_USER`/`DB_PASS`/
    /// `DB_NAME` (for `skauswatch-testkit::db::test_pool`) but deliberately
    /// never `DB_TYPE` — this test relies on that to deterministically
    /// exercise the "not configured" branch without needing to unset env
    /// vars (mutating process env is `unsafe`, denied workspace-wide).
    #[tokio::test]
    async fn build_threat_store_is_none_without_db_type_configured() {
        assert!(build_threat_store().await.is_none());
    }

    #[tokio::test]
    async fn for_tests_with_threat_store_wires_the_store_in() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy pool: {e}"));
        let store = Arc::new(ThreatStore::new(pool));
        let state = AppStateInner::for_tests_with_threat_store(
            skauswatch_testkit::license::dev_license("skauswatch"),
            store,
        );
        assert!(state.threat_store.is_some());
        assert!(state.event_store.is_none());
    }
}
