//! Shared application state: config, license/flag client, and the event
//! store (Elasticsearch/OpenSearch preferred, MongoDB fallback — v1
//! `LogProcessor` priority: `if self.elasticsearch: ... elif self.mongodb:
//! ...`).

use std::sync::Arc;

use penguin_licensing::{LicenseClient, LicenseConfig};

use crate::config::Config;
use crate::es::{ElasticsearchStore, EventStore};
use crate::models::BaseEvent;

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
    /// Live-event broadcast bus backing `GET /events/stream`. No producer
    /// publishes to it yet — see `src/routes/events.rs` module docs.
    pub event_bus: tokio::sync::broadcast::Sender<BaseEvent>,
}

/// Cheap-to-clone handle used as axum state.
pub type AppState = Arc<AppStateInner>;

impl AppStateInner {
    /// Builds state from environment configuration. The event store
    /// degrades gracefully: a misconfigured/unreachable backend logs a
    /// warning and leaves `event_store` `None` rather than failing startup
    /// (matches v1: ES/Mongo init failures are caught and logged, service
    /// still starts — see `main.py::startup`).
    pub async fn from_env() -> anyhow::Result<AppState> {
        let config = Config::from_env();

        let cfg = LicenseConfig::from_env("skauswatch")
            .map_err(|e| anyhow::anyhow!("license config: {e}"))?
            .with_bypass_domain("skauswatch.app");
        let license =
            LicenseClient::new(cfg).map_err(|e| anyhow::anyhow!("license client: {e}"))?;
        let _ = license.refresh().await;

        let event_store = build_event_store(&config).await;
        let (event_bus, _rx) = tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY);

        Ok(Arc::new(Self {
            config,
            license,
            event_store,
            event_bus,
        }))
    }

    /// Test constructor: no event store, dev auth bypass off by default so
    /// auth tests exercise the real path unless a test opts in.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn for_tests(license: Arc<LicenseClient>) -> AppState {
        let (event_bus, _rx) = tokio::sync::broadcast::channel(EVENT_BUS_CAPACITY);
        Arc::new(Self {
            config: Config::from_env(),
            license,
            event_store: None,
            event_bus,
        })
    }
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
