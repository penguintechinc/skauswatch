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

use crate::error::{ApiError, ApiJson, ErrorResponse};
use crate::flags::flag_denied;
use crate::models::{
    BaseEvent, EventSearchRequest, EventSearchResponse, EventType, LogSource, Severity,
};
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
#[utoipa::path(
    post,
    path = "/api/v1/events/search",
    tag = "monitor",
    request_body = EventSearchRequest,
    responses(
        (status = 200, description = "Matching events", body = EventSearchResponse),
        (status = 400, description = "Malformed request body", body = ErrorResponse),
        (status = 403, description = "monitor feature not enabled for this deployment", body = ErrorResponse),
        (status = 503, description = "No search backend (Elasticsearch/OpenSearch) configured", body = ErrorResponse),
    ),
)]
pub(crate) async fn search_events(
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
#[utoipa::path(
    get,
    path = "/api/v1/events/{event_id}",
    tag = "monitor",
    params(("event_id" = String, Path, description = "Event id")),
    responses(
        (status = 200, description = "The stored event", body = BaseEvent),
        (status = 403, description = "monitor feature not enabled for this deployment", body = ErrorResponse),
        (status = 404, description = "Event not found", body = ErrorResponse),
        (status = 503, description = "No search backend (Elasticsearch/OpenSearch) configured", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_event(
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
#[derive(Debug, Deserialize, utoipa::IntoParams)]
pub(crate) struct StreamParams {
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
#[utoipa::path(
    get,
    path = "/api/v1/events/stream",
    tag = "monitor",
    params(StreamParams),
    responses(
        (status = 200, description = "Live event stream (Server-Sent Events; no producer wired up yet, see module docs)", body = BaseEvent, content_type = "text/event-stream"),
        (status = 403, description = "monitor feature not enabled for this deployment", body = ErrorResponse),
    ),
)]
pub(crate) async fn stream_events(
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
    use crate::models::EventSearchResponse;
    use crate::routes::test_support::{dev_state, gated_state, state_with_store};
    use axum::http::StatusCode;
    use chrono::Utc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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

    #[tokio::test]
    async fn search_events_flag_denied_is_forbidden() {
        let server = test_server(gated_state());
        let res = server
            .post("/events/search")
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Forbidden");
    }

    #[tokio::test]
    async fn get_event_flag_denied_is_forbidden() {
        let server = test_server(gated_state());
        let res = server.get("/events/abc-123").await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn stream_events_flag_denied_is_forbidden() {
        let server = test_server(gated_state());
        let res = server.get("/events/stream").await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn search_events_returns_hits_from_the_configured_store() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aaa-events-*/_search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hits": {"total": {"value": 1}, "hits": [
                    {"_source": {"id": "e1", "source": "kubernetes", "event_type": "authentication", "severity": "high", "message": "login failed"}}
                ]},
            })))
            .mount(&mock_server)
            .await;
        let store =
            crate::es::ElasticsearchStore::new(mock_server.uri(), "aaa-events-*", None, None);
        let server = test_server(state_with_store(store));

        let res = server
            .post("/events/search")
            .json(&serde_json::json!({}))
            .await;
        res.assert_status_ok();
        let body: EventSearchResponse = res.json();
        assert_eq!(body.total, 1);
        assert_eq!(body.events[0].id, "e1");
    }

    #[tokio::test]
    async fn search_events_backend_error_is_internal_server_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aaa-events-*/_search"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;
        let store =
            crate::es::ElasticsearchStore::new(mock_server.uri(), "aaa-events-*", None, None);
        let server = test_server(state_with_store(store));

        let res = server
            .post("/events/search")
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_event_returns_the_stored_event() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/aaa-events-*/_doc/e1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_source": {"id": "e1", "source": "system", "event_type": "process", "severity": "low", "message": "hi"},
            })))
            .mount(&mock_server)
            .await;
        let store =
            crate::es::ElasticsearchStore::new(mock_server.uri(), "aaa-events-*", None, None);
        let server = test_server(state_with_store(store));

        let res = server.get("/events/e1").await;
        res.assert_status_ok();
        let body: BaseEvent = res.json();
        assert_eq!(body.id, "e1");
    }

    #[tokio::test]
    async fn get_event_with_backend_404_is_not_found() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/aaa-events-*/_doc/missing"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        let store =
            crate::es::ElasticsearchStore::new(mock_server.uri(), "aaa-events-*", None, None);
        let server = test_server(state_with_store(store));

        let res = server.get("/events/missing").await;
        res.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = res.json();
        assert_eq!(body["detail"], "Event not found");
    }

    #[tokio::test]
    async fn get_event_backend_error_is_internal_server_error() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/aaa-events-*/_doc/e1"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;
        let store =
            crate::es::ElasticsearchStore::new(mock_server.uri(), "aaa-events-*", None, None);
        let server = test_server(state_with_store(store));

        let res = server.get("/events/e1").await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn stream_events_skips_non_matching_and_delivers_matching_events() {
        let state = dev_state();
        let filters = StreamParams {
            sources: vec![LogSource::Kubernetes],
            event_types: vec![],
            severities: vec![],
        };
        let resp = match stream_events(State(state.clone()), Query(filters)).await {
            Ok(sse) => sse.into_response(),
            Err(_) => panic!("expected sse ok, flag should be enabled by dev_state"),
        };
        let mut stream = resp.into_body().into_data_stream();

        let mut skipped = sample_event();
        skipped.id = "skip-1".to_owned();
        skipped.source = LogSource::Auditd;
        let mut delivered = sample_event();
        delivered.id = "deliver-1".to_owned();
        delivered.source = LogSource::Kubernetes;

        if state.event_bus.send(skipped).is_err() {
            panic!("expected at least one live subscriber for the skipped event");
        }
        if state.event_bus.send(delivered).is_err() {
            panic!("expected at least one live subscriber for the delivered event");
        }

        let chunk = match tokio::time::timeout(Duration::from_secs(2), stream.next()).await {
            Ok(Some(Ok(bytes))) => bytes,
            other => panic!("expected an SSE data chunk, got {other:?}"),
        };
        let text = String::from_utf8_lossy(&chunk);
        assert!(text.contains("deliver-1"), "chunk: {text}");
        assert!(!text.contains("skip-1"), "chunk: {text}");
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
