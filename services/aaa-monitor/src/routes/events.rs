//! `/events/*` — v1 `main.py` event endpoints, backed by the ES/Mongo event
//! store (`crate::es`/`crate::mongo`).
//!
//! No route in v1 (or here) ever *creates* an event over HTTP — events are
//! only ever produced by the log collectors (`kubernetes_collector.py`,
//! `auditd_collector.py`, ...), which are a tracked follow-up (see
//! `src/main.rs`). `GET /events/stream` is therefore real, working
//! infrastructure (a broadcast channel + the same filter logic v1 used)
//! with no producer wired up yet: a client connects and idles until the 30s
//! timeout, exactly like v1's `stream_events` does today with zero
//! collectors calling `process_event`.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::error::{ApiError, ApiJson};
use crate::flags::flag_denied;
use crate::models::{BaseEvent, EventSearchRequest, EventType, LogSource, Severity};
use crate::state::AppState;

/// Router for `/events/*`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/events/search", post(search_events))
        .route("/events/{event_id}", get(get_event))
        .route("/events/stream", get(stream_events))
}

/// v1 `log_processor.search_events`: prefers Elasticsearch, falls back to
/// MongoDB, 503s if neither backend is configured (v1 raised a bare
/// `Exception("No search backend available")`, caught by the generic
/// handler and turned into a 500 — 503 is the correct status for "no
/// backend configured", not a request bug).
async fn search_events(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<EventSearchRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = flag_denied(&state).await {
        return Ok(denied);
    }
    let store = state
        .event_store
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("No search backend available".to_owned()))?;
    let resp = store.search(&req).await?;
    Ok(Json(resp).into_response())
}

/// v1 `log_processor.get_event_by_id`.
async fn get_event(
    State(state): State<AppState>,
    Path(event_id): Path<String>,
) -> Result<Response, ApiError> {
    if let Some(denied) = flag_denied(&state).await {
        return Ok(denied);
    }
    let store = state
        .event_store
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("No search backend available".to_owned()))?;
    match store.get_by_id(&event_id).await? {
        Some(event) => Ok(Json(event).into_response()),
        None => Ok(ApiError::NotFound("Event not found".to_owned()).into_response()),
    }
}

/// Query params for `GET /events/stream` — v1 accepted repeated
/// `sources`/`event_types`/`severities` query params.
#[derive(Debug, Deserialize)]
struct StreamParams {
    #[serde(default)]
    sources: Vec<LogSource>,
    #[serde(default)]
    event_types: Vec<EventType>,
    #[serde(default)]
    severities: Vec<Severity>,
}

/// v1 `LogProcessor._event_matches_filters`: empty filter lists mean "match
/// everything" for that dimension.
fn event_matches(event: &BaseEvent, filters: &StreamParams) -> bool {
    if !filters.sources.is_empty() && !filters.sources.contains(&event.source) {
        return false;
    }
    if !filters.event_types.is_empty() && !filters.event_types.contains(&event.event_type) {
        return false;
    }
    if !filters.severities.is_empty() && !filters.severities.contains(&event.severity) {
        return false;
    }
    true
}

/// GET /events/stream — real SSE infrastructure; see module docs for why it
/// has no producers yet.
async fn stream_events(
    State(state): State<AppState>,
    Query(filters): Query<StreamParams>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, Response> {
    if let Some(denied) = flag_denied(&state).await {
        return Err(denied);
    }
    let rx = state.event_bus.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(event) if event_matches(&event, &filters) => serde_json::to_string(&event)
            .ok()
            .map(|json| Ok(Event::default().data(json))),
        _ => None,
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(30))))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::models::{EventType, LogSource, Severity};
    use axum::http::StatusCode;
    use chrono::Utc;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    fn dev_state() -> AppState {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        crate::state::AppStateInner::for_tests(client)
    }

    fn test_server(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new().merge(router()).with_state(state);
        axum_test::TestServer::new(app)
    }

    #[tokio::test]
    async fn search_without_a_backend_is_service_unavailable() {
        let server = test_server(dev_state());
        let res = server
            .post("/events/search")
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Service Unavailable");
    }

    #[tokio::test]
    async fn get_event_without_a_backend_is_service_unavailable() {
        let server = test_server(dev_state());
        let res = server.get("/events/abc-123").await;
        res.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }

    fn sample_event() -> BaseEvent {
        BaseEvent {
            id: "e1".to_owned(),
            source: LogSource::Kubernetes,
            event_type: EventType::Authentication,
            severity: Severity::High,
            message: "m".to_owned(),
            timestamp: Utc::now(),
            raw_data: serde_json::Value::Null,
            tags: vec![],
            host: String::new(),
            user: None,
            process: None,
            pid: None,
            enrichments: serde_json::Value::Null,
            threat_matches: vec![],
            ai_analysis: None,
            processed_data: serde_json::Value::Null,
            extra: Default::default(),
        }
    }

    #[test]
    fn stream_filters_match_v1_empty_means_any_semantics() {
        let event = sample_event();
        let empty = StreamParams {
            sources: vec![],
            event_types: vec![],
            severities: vec![],
        };
        assert!(event_matches(&event, &empty));

        let matching = StreamParams {
            sources: vec![LogSource::Kubernetes],
            event_types: vec![],
            severities: vec![Severity::High],
        };
        assert!(event_matches(&event, &matching));

        let non_matching = StreamParams {
            sources: vec![LogSource::Auditd],
            event_types: vec![],
            severities: vec![],
        };
        assert!(!event_matches(&event, &non_matching));
    }
}
