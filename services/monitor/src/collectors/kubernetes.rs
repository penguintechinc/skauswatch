//! Kubernetes collector: polls the in-cluster Events API over HTTPS using
//! the pod's own service account token. Rust port of the working core of
//! v1 `collectors/kubernetes_collector.py`'s event collection
//! (`_collect_events`/`_process_k8s_event`) — v1 used the watch API with a
//! `resourceVersion` cursor for a live stream; this port polls
//! `GET /api/v1/events` on an interval instead. Documented scope reduction:
//! simpler, still real and working, but re-fetches the full recent event
//! list each cycle rather than maintaining a watch cursor (a poll interval
//! shorter than the K8s event TTL — default 1h — does not lose events, just
//! re-observes some; full watch-stream semantics are a follow-up if
//! sub-minute latency is later required).
//!
//! **Deployment requirement, flagged for approval (not silently added):**
//! needs an in-cluster `ServiceAccount` with `list`/`watch` on `events`
//! (core API group) bound via RBAC — not wired into `k8s/helm/monitor` by
//! this change, see `collectors/mod.rs` module docs.

use std::env;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::ingest::IngestHandle;
use crate::models::{BaseEvent, EventType, LogSource, Severity};

/// Default in-cluster paths (`kubernetes.io/docs/tasks/run-application/
/// access-api-from-pod`).
const DEFAULT_TOKEN_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";
const DEFAULT_CA_CERT_PATH: &str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";

/// Config for the Kubernetes collector, loaded from
/// `MONITOR_COLLECTOR_K8S_*` plus the standard in-cluster `KUBERNETES_
/// SERVICE_HOST`/`KUBERNETES_SERVICE_PORT` env vars every pod gets.
#[derive(Debug, Clone)]
pub struct KubernetesConfig {
    /// `MONITOR_COLLECTOR_K8S_ENABLED` — off by default (needs the RBAC
    /// grant above).
    pub enabled: bool,
    /// `https://{KUBERNETES_SERVICE_HOST}:{KUBERNETES_SERVICE_PORT}`.
    pub api_server: String,
    /// Service account token file path.
    pub token_path: String,
    /// Service account CA cert file path.
    pub ca_cert_path: String,
    /// `MONITOR_COLLECTOR_K8S_POLL_INTERVAL_SECS`; default 30s.
    pub poll_interval: Duration,
}

impl KubernetesConfig {
    /// Loads from env. Never fails.
    pub fn from_env() -> Self {
        let enabled = env::var("MONITOR_COLLECTOR_K8S_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let host = env::var("KUBERNETES_SERVICE_HOST").unwrap_or_default();
        let port = env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".to_owned());
        let api_server = env::var("MONITOR_COLLECTOR_K8S_API_SERVER")
            .unwrap_or_else(|_| format!("https://{host}:{port}"));
        let poll_interval = env::var("MONITOR_COLLECTOR_K8S_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));
        Self {
            enabled,
            api_server,
            token_path: env::var("MONITOR_COLLECTOR_K8S_TOKEN_PATH")
                .unwrap_or_else(|_| DEFAULT_TOKEN_PATH.to_owned()),
            ca_cert_path: env::var("MONITOR_COLLECTOR_K8S_CA_CERT_PATH")
                .unwrap_or_else(|_| DEFAULT_CA_CERT_PATH.to_owned()),
            poll_interval,
        }
    }
}

/// Errors from a poll cycle.
#[derive(Debug, thiserror::Error)]
pub enum KubernetesError {
    /// HTTP-layer failure.
    #[error("kubernetes api request: {0}")]
    Http(#[from] reqwest::Error),
    /// Response body missing the expected `items` array.
    #[error("kubernetes api response missing `items`")]
    Shape,
}

/// `GET {api_base}/api/v1/events?limit=500` with the service account bearer
/// token, returning the `items` array (`core/v1.Event` objects).
pub async fn fetch_events(
    client: &reqwest::Client,
    api_base: &str,
    token: &str,
) -> Result<Vec<Value>, KubernetesError> {
    let url = format!("{}/api/v1/events?limit=500", api_base.trim_end_matches('/'));
    let body: Value = client
        .get(&url)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    body.get("items")
        .and_then(Value::as_array)
        .cloned()
        .ok_or(KubernetesError::Shape)
}

/// v1 `_determine_event_severity` + `_process_k8s_event`: `Warning`-type
/// events are at least Medium (High for reasons suggesting outright
/// failure); `Normal` events are Info. Returns `None` for anything that
/// isn't a `core/v1.Event` shape (defensive — a malformed/partial item
/// should never panic the poll loop).
pub fn classify_k8s_event(ev: &Value, tenant_id: &str) -> Option<BaseEvent> {
    let event_type_field = ev.get("type").and_then(Value::as_str).unwrap_or("Normal");
    let reason = ev.get("reason").and_then(Value::as_str).unwrap_or("");
    let message = ev.get("message").and_then(Value::as_str)?;

    let severity = if event_type_field.eq_ignore_ascii_case("warning") {
        if contains_any(
            &reason.to_ascii_lowercase(),
            &["failed", "backoff", "unhealthy", "oom"],
        ) {
            Severity::High
        } else {
            Severity::Medium
        }
    } else {
        Severity::Info
    };

    let involved = ev.get("involvedObject");
    let namespace = involved
        .and_then(|o| o.get("namespace"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = involved
        .and_then(|o| o.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let kind = involved
        .and_then(|o| o.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or_default();

    let timestamp = ev
        .get("lastTimestamp")
        .and_then(Value::as_str)
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);

    Some(BaseEvent {
        id: uuid::Uuid::new_v4().to_string(),
        source: LogSource::Kubernetes,
        event_type: EventType::ContainerEvent,
        severity,
        message: message.to_owned(),
        timestamp,
        raw_data: ev.clone(),
        tags: vec!["kubernetes".to_owned(), kind.to_owned(), reason.to_owned()],
        host: format!("{namespace}/{name}"),
        user: None,
        process: None,
        pid: None,
        enrichments: serde_json::Value::Null,
        threat_matches: vec![],
        ai_analysis: None,
        processed_data: serde_json::Value::Null,
        tenant_id: tenant_id.to_owned(),
        extra: Default::default(),
    })
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// One poll cycle: fetch + classify + ingest every event. Returns the
/// number ingested.
pub async fn poll_once(
    client: &reqwest::Client,
    api_base: &str,
    token: &str,
    tenant_id: &str,
    sink: &IngestHandle,
) -> Result<usize, KubernetesError> {
    let events = fetch_events(client, api_base, token).await?;
    let mut count = 0;
    for ev in &events {
        if let Some(event) = classify_k8s_event(ev, tenant_id) {
            sink.ingest(event).await;
            count += 1;
        }
    }
    Ok(count)
}

/// Builds the HTTPS client trusting the in-cluster CA (falls back to the
/// system trust store if the CA file can't be read — e.g. running outside
/// a real cluster during development).
fn build_client(ca_cert_path: &str) -> reqwest::Client {
    let mut builder = reqwest::Client::builder();
    if let Ok(pem) = std::fs::read(ca_cert_path)
        && let Ok(cert) = reqwest::Certificate::from_pem(&pem)
    {
        builder = builder.add_root_certificate(cert);
    }
    builder.build().unwrap_or_default()
}

/// Poll loop: re-reads the service account token every cycle (tokens are
/// rotated by the kubelet periodically) and polls on `cfg.poll_interval`.
pub async fn run(cfg: KubernetesConfig, tenant_id: String, sink: IngestHandle) {
    let client = build_client(&cfg.ca_cert_path);
    let mut ticker = tokio::time::interval(cfg.poll_interval);
    loop {
        ticker.tick().await;
        let token = match std::fs::read_to_string(&cfg.token_path) {
            Ok(t) => t.trim().to_owned(),
            Err(e) => {
                tracing::error!(path = %cfg.token_path, error = %e, "failed to read service account token");
                continue;
            }
        };
        match poll_once(&client, &cfg.api_server, &token, &tenant_id, &sink).await {
            Ok(count) => tracing::debug!(events = count, "kubernetes events polled"),
            Err(e) => tracing::error!(error = %e, "kubernetes events poll failed"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn warning_event(reason: &str) -> Value {
        serde_json::json!({
            "type": "Warning",
            "reason": reason,
            "message": "container failed to start",
            "involvedObject": {"kind": "Pod", "name": "app-1", "namespace": "default"},
            "lastTimestamp": "2026-07-01T00:00:00Z",
        })
    }

    #[test]
    fn classify_normal_event_is_info() {
        let ev = serde_json::json!({
            "type": "Normal",
            "reason": "Scheduled",
            "message": "pod scheduled",
            "involvedObject": {"kind": "Pod", "name": "app-1", "namespace": "default"},
        });
        let event = classify_k8s_event(&ev, "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.severity, Severity::Info);
        assert_eq!(event.host, "default/app-1");
        assert_eq!(event.tenant_id, "tenant-a");
    }

    #[test]
    fn classify_warning_with_failure_reason_is_high() {
        let ev = warning_event("Failed");
        let event = classify_k8s_event(&ev, "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.event_type, EventType::ContainerEvent);
    }

    #[test]
    fn classify_warning_with_other_reason_is_medium() {
        let ev = warning_event("Unschedulable");
        let event = classify_k8s_event(&ev, "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.severity, Severity::Medium);
    }

    #[test]
    fn classify_missing_message_yields_none() {
        let ev = serde_json::json!({"type": "Normal", "reason": "x"});
        assert!(classify_k8s_event(&ev, "tenant-a").is_none());
    }

    #[tokio::test]
    async fn fetch_events_sends_bearer_token_and_parses_items() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/events"))
            .and(query_param("limit", "500"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [warning_event("Failed")],
            })))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let events = fetch_events(&client, &server.uri(), "test-token")
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));
        assert_eq!(events.len(), 1);
    }

    #[tokio::test]
    async fn poll_once_ingests_every_classifiable_event() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "items": [warning_event("Failed"), warning_event("BackOff")],
            })))
            .mount(&server)
            .await;

        let (bus, _rx) = tokio::sync::broadcast::channel(16);
        let sink = crate::ingest::IngestPipeline::spawn(
            None,
            bus,
            None,
            skauswatch_testkit::license::dev_license("skauswatch"),
            crate::ingest::IngestConfig::default(),
        );

        let client = reqwest::Client::new();
        let count = poll_once(&client, &server.uri(), "tok", "tenant-a", &sink)
            .await
            .unwrap_or_else(|e| panic!("poll: {e}"));
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn fetch_events_errors_on_malformed_shape() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/events"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let result = fetch_events(&client, &server.uri(), "tok").await;
        assert!(matches!(result, Err(KubernetesError::Shape)));
    }

    #[test]
    fn from_env_reads_process_env_without_panicking() {
        let cfg = KubernetesConfig::from_env();
        assert!(!cfg.enabled);
        assert_eq!(cfg.token_path, DEFAULT_TOKEN_PATH);
        assert_eq!(cfg.ca_cert_path, DEFAULT_CA_CERT_PATH);
        assert_eq!(cfg.poll_interval, Duration::from_secs(30));
    }

    #[test]
    fn build_client_falls_back_to_the_system_trust_store_when_the_ca_file_is_missing() {
        // Exercises the "CA file can't be read" branch without needing a
        // real in-cluster service account mount.
        let _client = build_client("/nonexistent/ca.crt");
    }
}
