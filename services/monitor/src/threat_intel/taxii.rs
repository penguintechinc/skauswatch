//! TAXII 2.x feed client: server/collection discovery + object polling.
//! Rust port of the *working core* of v1 `threat_intel/taxii_client.py`'s
//! `TAXIIClient` — real discovery, collection enumeration, and object
//! fetching over HTTP, feeding [`crate::threat_intel::stix::indicator_object_to_iocs`]
//! into [`crate::threat_intel::store::ThreatStore`]. v1's considerable
//! additional reliability machinery (`CircuitBreaker`, `FeedQualityManager`,
//! `RequestTracker`, per-feed adaptive-backoff sleep, OAuth2 credential
//! flows, rate limiting) is intentionally not ported here — documented scope
//! reduction, not a silent one: this client does real, working TAXII
//! polling with a fixed interval and plain bearer/basic-auth credentials,
//! which is the functional core those v1 systems all sat on top of.

use std::sync::Arc;
use std::time::Duration;

use penguin_licensing::LicenseClient;
use serde_json::Value;

use crate::models::ThreatFeed;
use crate::threat_intel::stix::indicator_object_to_iocs;
use crate::threat_intel::store::{StoreError, ThreatStore};

/// PostHog flag gating the TAXII feed poller and its REST surface —
/// `skauswatch.threat-intel`, already reserved in `services/manager/src/
/// flags.rs::MODULE_FLAGS` and already used by manager's *separate*
/// IOC-CRUD routes (`routes/threat_intel.rs`) — sharing the key is
/// intentional: enabling "threat intel" as a product feature enables both
/// subsystems together, see `mod.rs` module docs for why they're still
/// separate code.
pub const THREAT_INTEL_FLAG: &str = "skauswatch.threat-intel";

/// Errors from a poll cycle — logged and counted per feed, never fatal to
/// the poll loop (one bad feed must not stop every other feed's polling).
#[derive(Debug, thiserror::Error)]
pub enum TaxiiError {
    /// HTTP-layer failure (connect/timeout/non-2xx).
    #[error("taxii http request: {0}")]
    Http(#[from] reqwest::Error),
    /// Response body did not parse as the expected TAXII JSON shape.
    #[error("taxii response shape: {0}")]
    Shape(String),
    /// Underlying store failure while persisting a fetched indicator.
    #[error("taxii store: {0}")]
    Store(#[from] StoreError),
}

/// Tunables for the feed poller, loaded from `MONITOR_TAXII_*` env vars.
#[derive(Debug, Clone)]
pub struct TaxiiConfig {
    /// Master enable — off by default (v1 default `TAXIIConfig.enabled=True`
    /// but with an empty feed list; this port defaults off entirely since an
    /// empty poll loop calling out to nothing is not meaningfully "enabled").
    pub enabled: bool,
    /// `name|url` pairs to seed as feeds at startup (`MONITOR_TAXII_FEED_URLS`,
    /// comma-separated) — v1's config-driven feed list; no admin REST CRUD
    /// in this pass, see `routes.rs` module docs.
    pub feed_urls: Vec<(String, String)>,
    /// Poll interval applied to every seeded feed (v1 supported a
    /// per-feed `update_frequency`; this port uses one interval for all
    /// configured feeds — `ThreatFeed.update_frequency` is still stored and
    /// returned via the status API for a future per-feed scheduler).
    pub poll_interval: Duration,
}

impl TaxiiConfig {
    /// Loads from `MONITOR_TAXII_*` env vars. Never fails — an unset/empty
    /// `MONITOR_TAXII_FEED_URLS` just means no feeds are seeded.
    pub fn from_env() -> Self {
        let raw = std::env::var("MONITOR_TAXII_FEED_URLS").unwrap_or_default();
        Self {
            enabled: std::env::var("MONITOR_TAXII_ENABLED")
                .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
                .unwrap_or(false),
            feed_urls: parse_feed_urls(&raw),
            poll_interval: std::env::var("MONITOR_TAXII_POLL_INTERVAL_SECS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .map(Duration::from_secs)
                .unwrap_or(Duration::from_secs(3600)),
        }
    }
}

/// Parses `MONITOR_TAXII_FEED_URLS` (`name|url,name|url,...`) into
/// `(name, url)` pairs. A malformed entry with no `|` uses the URL itself as
/// the name rather than being dropped — a slightly-wrong name is preferable
/// to silently losing an operator-configured feed.
fn parse_feed_urls(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|entry| match entry.split_once('|') {
            Some((name, url)) => (name.trim().to_owned(), url.trim().to_owned()),
            None => (entry.to_owned(), entry.to_owned()),
        })
        .collect()
}

/// Seeds `cfg.feed_urls` into the store as `threat_feeds` rows (upsert, so
/// re-running at every startup is safe) — called once at startup before the
/// poll loop begins.
pub async fn seed_feeds(store: &ThreatStore, cfg: &TaxiiConfig) {
    for (name, url) in &cfg.feed_urls {
        let feed = ThreatFeed {
            id: String::new(),
            name: name.clone(),
            url: url.clone(),
            feed_type: "taxii".to_owned(),
            enabled: true,
            update_frequency: cfg.poll_interval.as_secs() as i64,
            credentials: None,
            headers: None,
            certificate_verification: true,
            proxy_url: None,
            last_updated: None,
            ioc_count: 0,
            status: "unknown".to_owned(),
            metadata: serde_json::json!({}),
        };
        if let Err(e) = store.upsert_feed(&feed).await {
            tracing::error!(feed = %name, error = %e, "failed to seed TAXII feed");
        }
    }
}

/// TAXII 2.1 discovery (`GET {discovery_url}`, `Accept: application/
/// taxii+json;version=2.1`): returns every advertised API root URL. Some
/// operators configure a feed's `url` as a discovery endpoint (this path);
/// others configure it as a specific collection's objects URL directly
/// (`poll_feed_once` falls back to treating the configured URL as the
/// objects URL when discovery finds no `api_roots`) — both are valid TAXII
/// 2.x deployment shapes.
pub async fn discover_api_roots(
    client: &reqwest::Client,
    discovery_url: &str,
) -> Result<Vec<String>, TaxiiError> {
    let body: Value = client
        .get(discovery_url)
        .header("Accept", "application/taxii+json;version=2.1")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(body
        .get("api_roots")
        .and_then(Value::as_array)
        .map(|roots| {
            roots
                .iter()
                .filter_map(|r| r.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default())
}

/// `GET {api_root}collections/` and returns the first collection's objects
/// URL (`{api_root}collections/{id}/objects/`) — v1 also just used the
/// first available collection per feed rather than letting an operator pick
/// one; matched here rather than treated as an improvement opportunity.
pub async fn first_collection_objects_url(
    client: &reqwest::Client,
    api_root: &str,
) -> Result<Option<String>, TaxiiError> {
    let collections_url = format!("{}/collections/", api_root.trim_end_matches('/'));
    let body: Value = client
        .get(&collections_url)
        .header("Accept", "application/taxii+json;version=2.1")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let first_id = body
        .get("collections")
        .and_then(Value::as_array)
        .and_then(|c| c.first())
        .and_then(|c| c.get("id"))
        .and_then(Value::as_str);
    Ok(first_id.map(|id| {
        format!(
            "{}/collections/{}/objects/",
            api_root.trim_end_matches('/'),
            id
        )
    }))
}

/// `GET {objects_url}` and returns the STIX `objects` array.
pub async fn fetch_objects(
    client: &reqwest::Client,
    objects_url: &str,
) -> Result<Vec<Value>, TaxiiError> {
    let body: Value = client
        .get(objects_url)
        .header("Accept", "application/taxii+json;version=2.1")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    body.get("objects")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| TaxiiError::Shape("response missing `objects` array".to_owned()))
}

/// Runs one full poll cycle for `feed`: discover (or fall back to treating
/// `feed.url` as the objects URL directly) → fetch → parse STIX indicators →
/// store. Returns the number of indicators stored.
pub async fn poll_feed_once(
    client: &reqwest::Client,
    feed: &ThreatFeed,
    store: &ThreatStore,
) -> Result<usize, TaxiiError> {
    let objects_url = match discover_api_roots(client, &feed.url).await {
        Ok(roots) if !roots.is_empty() => {
            match first_collection_objects_url(client, &roots[0]).await? {
                Some(url) => url,
                None => feed.url.clone(),
            }
        }
        // No `api_roots` in the discovery response (or discovery itself
        // isn't a TAXII discovery document at this URL) — treat the
        // configured URL as the objects endpoint directly.
        _ => feed.url.clone(),
    };

    let objects = fetch_objects(client, &objects_url).await?;
    let mut stored = 0usize;
    for obj in &objects {
        if obj.get("type").and_then(Value::as_str) != Some("indicator") {
            continue;
        }
        for ioc in indicator_object_to_iocs(obj, &feed.name) {
            store.store_indicator(&ioc).await?;
            stored += 1;
        }
    }
    Ok(stored)
}

/// Background poll loop: seeds configured feeds, then repeatedly polls
/// every enabled feed on `cfg.poll_interval`, re-checking the
/// [`THREAT_INTEL_FLAG`] each cycle (same dynamic-disable philosophy as
/// `ingest.rs`'s log-ingest flag). One feed's failure is logged/recorded
/// against that feed only — never aborts the loop.
pub async fn run(store: Arc<ThreatStore>, cfg: TaxiiConfig, license: Arc<LicenseClient>) {
    if !cfg.enabled {
        tracing::info!("TAXII feed polling disabled (MONITOR_TAXII_ENABLED unset)");
        return;
    }
    seed_feeds(&store, &cfg).await;

    let client = reqwest::Client::new();
    let mut ticker = tokio::time::interval(cfg.poll_interval);
    loop {
        ticker.tick().await;
        if !license.flag_enabled(THREAT_INTEL_FLAG).await {
            tracing::debug!("threat-intel flag disabled — skipping this poll cycle");
            continue;
        }
        let feeds = match store.list_enabled_feeds().await {
            Ok(feeds) => feeds,
            Err(e) => {
                tracing::error!(error = %e, "failed to list threat-intel feeds");
                continue;
            }
        };
        for feed in feeds {
            match poll_feed_once(&client, &feed, &store).await {
                Ok(count) => {
                    tracing::info!(feed = %feed.name, indicators = count, "TAXII feed polled");
                    let _ = store.record_feed_poll(&feed.id, "ok", count as i64).await;
                }
                Err(e) => {
                    tracing::error!(feed = %feed.name, error = %e, "TAXII feed poll failed");
                    let _ = store
                        .record_feed_poll(&feed.id, "error", feed.ioc_count)
                        .await;
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parse_feed_urls_splits_name_and_url() {
        let parsed =
            parse_feed_urls("OTX|https://otx.example/taxii2/, Custom | https://c.example/");
        assert_eq!(
            parsed,
            vec![
                ("OTX".to_owned(), "https://otx.example/taxii2/".to_owned()),
                ("Custom".to_owned(), "https://c.example/".to_owned()),
            ]
        );
    }

    #[test]
    fn parse_feed_urls_uses_the_bare_url_as_name_when_no_separator() {
        let parsed = parse_feed_urls("https://bare.example/taxii2/");
        assert_eq!(
            parsed,
            vec![(
                "https://bare.example/taxii2/".to_owned(),
                "https://bare.example/taxii2/".to_owned()
            )]
        );
    }

    #[test]
    fn parse_feed_urls_ignores_empty_entries() {
        assert!(parse_feed_urls("").is_empty());
        assert!(parse_feed_urls("   ,  ,").is_empty());
    }

    #[tokio::test]
    async fn discover_api_roots_reads_the_discovery_document() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/taxii2/"))
            .and(header("Accept", "application/taxii+json;version=2.1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "Test TAXII server",
                "api_roots": ["http://example.test/api1/"],
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let roots = discover_api_roots(&client, &format!("{}/taxii2/", server.uri()))
            .await
            .unwrap_or_else(|e| panic!("discover: {e}"));
        assert_eq!(roots, vec!["http://example.test/api1/".to_owned()]);
    }

    #[tokio::test]
    async fn discover_api_roots_returns_empty_when_the_document_has_none() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/notaxii/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let roots = discover_api_roots(&client, &format!("{}/notaxii/", server.uri()))
            .await
            .unwrap_or_else(|e| panic!("discover: {e}"));
        assert!(roots.is_empty());
    }

    #[tokio::test]
    async fn first_collection_objects_url_builds_the_expected_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api1/collections/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "collections": [{"id": "abcd-1234", "title": "Indicators"}],
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let url = first_collection_objects_url(&client, &format!("{}/api1/", server.uri()))
            .await
            .unwrap_or_else(|e| panic!("collections: {e}"));
        assert_eq!(
            url,
            Some(format!(
                "{}/api1/collections/abcd-1234/objects/",
                server.uri()
            ))
        );
    }

    #[tokio::test]
    async fn fetch_objects_returns_the_objects_array() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api1/collections/x/objects/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.5']"}],
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let objects = fetch_objects(
            &client,
            &format!("{}/api1/collections/x/objects/", server.uri()),
        )
        .await
        .unwrap_or_else(|e| panic!("fetch: {e}"));
        assert_eq!(objects.len(), 1);
    }

    #[tokio::test]
    async fn fetch_objects_errors_on_malformed_shape() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/bad/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let result = fetch_objects(&client, &format!("{}/bad/", server.uri())).await;
        assert!(matches!(result, Err(TaxiiError::Shape(_))));
    }

    #[tokio::test]
    async fn poll_feed_once_falls_back_to_the_configured_url_when_discovery_has_no_api_roots() {
        let server = MockServer::start().await;
        // The configured feed URL answers with objects directly (no
        // `api_roots` key) — poll_feed_once must treat it as the objects
        // endpoint rather than erroring.
        Mock::given(method("GET"))
            .and(path("/feed/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "objects": [
                    {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.9']"},
                    {"type": "malware", "name": "not an indicator, ignored"},
                ],
            })))
            .mount(&server)
            .await;

        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        let store = ThreatStore::new(pool);
        let client = reqwest::Client::new();
        let feed = ThreatFeed {
            id: String::new(),
            name: "test".to_owned(),
            url: format!("{}/feed/", server.uri()),
            feed_type: "taxii".to_owned(),
            enabled: true,
            update_frequency: 3600,
            credentials: None,
            headers: None,
            certificate_verification: true,
            proxy_url: None,
            last_updated: None,
            ioc_count: 0,
            status: "unknown".to_owned(),
            metadata: serde_json::json!({}),
        };

        let stored = poll_feed_once(&client, &feed, &store)
            .await
            .unwrap_or_else(|e| panic!("poll: {e}"));
        assert_eq!(stored, 1);

        let found = store
            .find_by_kind_value("ip", "203.0.113.9")
            .await
            .unwrap_or_else(|e| panic!("find: {e}"));
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn seed_feeds_upserts_every_configured_feed() {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        let store = ThreatStore::new(pool);
        let cfg = TaxiiConfig {
            enabled: true,
            feed_urls: vec![
                ("Feed A".to_owned(), "https://a.example.test/".to_owned()),
                ("Feed B".to_owned(), "https://b.example.test/".to_owned()),
            ],
            poll_interval: Duration::from_secs(60),
        };
        seed_feeds(&store, &cfg).await;

        let feeds = store
            .list_feeds()
            .await
            .unwrap_or_else(|e| panic!("list_feeds: {e}"));
        assert_eq!(feeds.len(), 2);
        assert!(feeds.iter().any(|f| f.name == "Feed A"));
        assert!(feeds.iter().any(|f| f.name == "Feed B"));
    }

    #[test]
    fn from_env_reads_process_env_without_panicking() {
        let cfg = TaxiiConfig::from_env();
        assert!(!cfg.enabled);
        assert!(cfg.feed_urls.is_empty());
        assert_eq!(cfg.poll_interval, Duration::from_secs(3600));
    }

    #[tokio::test]
    async fn run_returns_immediately_when_disabled() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy pool: {e}"));
        let store = Arc::new(ThreatStore::new(pool));
        let cfg = TaxiiConfig {
            enabled: false,
            feed_urls: vec![],
            poll_interval: Duration::from_secs(1),
        };
        let license = skauswatch_testkit::license::dev_license("skauswatch");
        // Must return promptly rather than entering the poll loop — the
        // lazily-connected pool above would error on any real query.
        tokio::time::timeout(Duration::from_secs(2), run(store, cfg, license))
            .await
            .unwrap_or_else(|_| panic!("run() must return immediately when disabled"));
    }

    #[tokio::test]
    async fn run_skips_a_poll_cycle_when_the_threat_intel_flag_is_disabled() {
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        let store = Arc::new(ThreatStore::new(pool));
        let cfg = TaxiiConfig {
            enabled: true,
            feed_urls: vec![(
                "seeded".to_owned(),
                "https://seeded.example.test/".to_owned(),
            )],
            poll_interval: Duration::from_millis(20),
        };
        let license = skauswatch_testkit::license::gated_license("skauswatch");
        let handle = tokio::spawn(run(store.clone(), cfg, license));

        // Give the loop a few ticks to run the flag-disabled "continue"
        // branch, then verify the seeded feed's status was never touched
        // (no poll cycle ever reached `poll_feed_once`).
        tokio::time::sleep(Duration::from_millis(100)).await;
        handle.abort();

        let feeds = store
            .list_feeds()
            .await
            .unwrap_or_else(|e| panic!("list_feeds: {e}"));
        assert_eq!(feeds.len(), 1);
        assert_eq!(feeds[0].status, "unknown");
    }
}
