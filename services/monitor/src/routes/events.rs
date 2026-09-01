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
//!
//! **AUTH + TENANT ISOLATION (hardened — critical finding):** before this
//! pass, every route in this module (search, get, stream) had zero
//! authentication and the Elasticsearch queries behind search/get carried
//! no tenant filter at all — any unauthenticated caller could read every
//! tenant's security events. All three routes now require a valid
//! `Authorization: Bearer <jwt>` — an ES256 token carrying the house
//! `skauswatch_auth::Claims` shape with a non-empty `tenant` claim —
//! enforced as a single router-wide layer via `skauswatch_auth
//! ::tenant_middleware` (see [`router`]), not the local ad hoc
//! `crate::auth::AuthedUser` extractor `alerts.rs`/`openapi.rs` still use
//! (switching those is a separate, tracked `docs/v2-port/tenancy-model.md`
//! item, not part of this fix). A missing/invalid/expired token is 401; a
//! validly signed token with no usable tenant is 403. Handlers extract the
//! resulting `skauswatch_auth::TenantContext` and thread it into every
//! search/get call (`crate::es::build_search_body`,
//! `EventStore::get_by_id`) and into the live-stream filter
//! ([`event_matches`]) — see `crate::models::BaseEvent::tenant_id` and
//! `crate::es` module docs for the query-side half of this fix.

use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use skauswatch_auth::TenantContext;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use crate::error::{ApiError, ApiJson, ErrorResponse};
use crate::flags::flag_denied;
use crate::models::{
    BaseEvent, EventSearchRequest, EventSearchResponse, EventType, LogSource, Severity,
};
use crate::state::AppState;

/// Router for `/events/*`. `tenant_middleware` is the OUTERMOST layer (per
/// that function's ordering contract: the last `.layer()` call runs first),
/// so an unauthenticated or tenant-less request is rejected before it ever
/// reaches a handler — see module docs.
pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/events/search", post(search_events))
        .route("/events/{event_id}", get(get_event))
        .route("/events/stream", get(stream_events))
        .layer(axum::middleware::from_fn_with_state(
            state,
            skauswatch_auth::tenant_middleware::<AppState>,
        ))
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
    security(("bearer_jwt" = [])),
    request_body = EventSearchRequest,
    responses(
        (status = 200, description = "Matching events, scoped to the caller's tenant", body = EventSearchResponse),
        (status = 400, description = "Malformed request body", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Missing or empty tenant claim, or monitor feature not enabled for this deployment", body = ErrorResponse),
        (status = 503, description = "No search backend (Elasticsearch/OpenSearch) configured", body = ErrorResponse),
    ),
)]
pub(crate) async fn search_events(
    State(state): State<AppState>,
    tenant: TenantContext,
    ApiJson(req): ApiJson<EventSearchRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = flag_denied(&state).await {
        return Ok(denied);
    }
    let store = state
        .event_store
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("No search backend available".to_owned()))?;
    let resp = store.search(&req, tenant.tenant.as_str()).await?;
    Ok(Json(resp).into_response())
}

/// v1 `log_processor.get_event_by_id`.
#[utoipa::path(
    get,
    path = "/api/v1/events/{event_id}",
    tag = "monitor",
    security(("bearer_jwt" = [])),
    params(("event_id" = String, Path, description = "Event id")),
    responses(
        (status = 200, description = "The stored event (only if owned by the caller's tenant)", body = BaseEvent),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Missing or empty tenant claim, or monitor feature not enabled for this deployment", body = ErrorResponse),
        (status = 404, description = "Event not found, or owned by a different tenant", body = ErrorResponse),
        (status = 503, description = "No search backend (Elasticsearch/OpenSearch) configured", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_event(
    State(state): State<AppState>,
    tenant: TenantContext,
    Path(event_id): Path<String>,
) -> Result<Response, ApiError> {
    if let Some(denied) = flag_denied(&state).await {
        return Ok(denied);
    }
    let store = state
        .event_store
        .as_ref()
        .ok_or_else(|| ApiError::ServiceUnavailable("No search backend available".to_owned()))?;
    match store.get_by_id(&event_id, tenant.tenant.as_str()).await? {
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
/// everything" for that dimension. `tenant` is not a v1 concept —
/// `event_bus` is a single process-wide broadcast channel shared by every
/// tenant's subscribers (no per-tenant partitioning), so this is the only
/// place enforcing tenant isolation for the live stream; it is checked
/// first and unconditionally, never optional like the other filters.
fn event_matches(event: &BaseEvent, filters: &StreamParams, tenant: &str) -> bool {
    if event.tenant_id != tenant {
        return false;
    }
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
    security(("bearer_jwt" = [])),
    params(StreamParams),
    responses(
        (status = 200, description = "Live event stream scoped to the caller's tenant (Server-Sent Events; no producer wired up yet, see module docs)", body = BaseEvent, content_type = "text/event-stream"),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Missing or empty tenant claim, or monitor feature not enabled for this deployment", body = ErrorResponse),
    ),
)]
pub(crate) async fn stream_events(
    State(state): State<AppState>,
    tenant: TenantContext,
    Query(filters): Query<StreamParams>,
) -> Result<Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>>, Response> {
    if let Some(denied) = flag_denied(&state).await {
        return Err(denied);
    }
    let rx = state.event_bus.subscribe();
    let caller_tenant = tenant.tenant.as_str().to_owned();
    let stream = BroadcastStream::new(rx).filter_map(move |item| match item {
        Ok(event) if event_matches(&event, &filters, &caller_tenant) => {
            serde_json::to_string(&event)
                .ok()
                .map(|json| Ok(Event::default().data(json)))
        }
        _ => None,
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::new().interval(Duration::from_secs(30))))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::models::EventSearchResponse;
    use crate::routes::test_support::{dev_state, gated_state, sign_token, state_with_store};
    use axum::http::StatusCode;
    use chrono::Utc;
    use skauswatch_auth::Tenant;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TENANT_A: &str = "tenant-a";
    const TENANT_B: &str = "tenant-b";
    const READ_SCOPE: &str = "events:read";

    fn test_server(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .merge(router(state.clone()))
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    // -- finding #1: unauthenticated requests are rejected ------------------

    #[tokio::test]
    async fn search_events_without_auth_is_unauthorized() {
        let server = test_server(dev_state());
        let res = server
            .post("/events/search")
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_event_without_auth_is_unauthorized() {
        let server = test_server(dev_state());
        let res = server.get("/events/abc-123").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn stream_events_without_auth_is_unauthorized() {
        let server = test_server(dev_state());
        let res = server.get("/events/stream").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn search_events_with_a_tenant_less_token_is_forbidden() {
        let state = dev_state();
        let claims = skauswatch_auth::Claims {
            sub: "u1".into(),
            iss: "https://auth.skauswatch.app".into(),
            aud: "skauswatch".into(),
            iat: 0,
            exp: i64::MAX,
            scope: READ_SCOPE.into(),
            tenant: "   ".into(),
            teams: vec![],
            roles: vec![],
        };
        let token = crate::routes::test_support::sign_claims(&state, &claims);
        let server = test_server(state);
        let res = server
            .post("/events/search")
            .authorization_bearer(token)
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    // -- existing behavior, now under auth -----------------------------------

    #[tokio::test]
    async fn search_without_a_backend_is_service_unavailable() {
        let state = dev_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        let res = server
            .post("/events/search")
            .authorization_bearer(token)
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Service Unavailable");
    }

    #[tokio::test]
    async fn get_event_without_a_backend_is_service_unavailable() {
        let state = dev_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        let res = server
            .get("/events/abc-123")
            .authorization_bearer(token)
            .await;
        res.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn search_events_flag_denied_is_forbidden() {
        let state = gated_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        let res = server
            .post("/events/search")
            .authorization_bearer(token)
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Forbidden");
    }

    #[tokio::test]
    async fn get_event_flag_denied_is_forbidden() {
        let state = gated_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        let res = server
            .get("/events/abc-123")
            .authorization_bearer(token)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn stream_events_flag_denied_is_forbidden() {
        let state = gated_state();
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);
        let res = server
            .get("/events/stream")
            .authorization_bearer(token)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn search_events_returns_hits_from_the_configured_store() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/aaa-events-*/_search"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hits": {"total": {"value": 1}, "hits": [
                    {"_source": {"id": "e1", "source": "kubernetes", "event_type": "authentication", "severity": "high", "message": "login failed", "tenant_id": "tenant-a"}}
                ]},
            })))
            .mount(&mock_server)
            .await;
        let store =
            crate::es::ElasticsearchStore::new(mock_server.uri(), "aaa-events-*", None, None);
        let state = state_with_store(store);
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);

        let res = server
            .post("/events/search")
            .authorization_bearer(token)
            .json(&serde_json::json!({}))
            .await;
        res.assert_status_ok();
        let body: EventSearchResponse = res.json();
        assert_eq!(body.total, 1);
        assert_eq!(body.events[0].id, "e1");
    }

    /// End-to-end regression for the missing-tenant-filter finding: the
    /// request this route actually sends to Elasticsearch must carry the
    /// authenticated caller's tenant, not just whatever `build_search_body`
    /// produces in isolation (see `crate::es`'s unit tests for that).
    #[tokio::test]
    async fn search_events_sends_the_authenticated_tenant_to_elasticsearch() {
        let mock_server = MockServer::start().await;
        let expected_body = crate::es::build_search_body(&EventSearchRequest::default(), TENANT_A);
        Mock::given(method("POST"))
            .and(path("/aaa-events-*/_search"))
            .and(body_json(expected_body))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "hits": {"total": {"value": 0}, "hits": []},
            })))
            .mount(&mock_server)
            .await;
        let store =
            crate::es::ElasticsearchStore::new(mock_server.uri(), "aaa-events-*", None, None);
        let state = state_with_store(store);
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);

        // Wiremock has no matching mock (and therefore 404s) if the request
        // body doesn't carry the `tenant-a` filter — a 200 here already
        // proves the wiring; the explicit total==0 rules out a stray match.
        let res = server
            .post("/events/search")
            .authorization_bearer(token)
            .json(&serde_json::json!({}))
            .await;
        res.assert_status_ok();
        let body: EventSearchResponse = res.json();
        assert_eq!(body.total, 0);
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
        let state = state_with_store(store);
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);

        let res = server
            .post("/events/search")
            .authorization_bearer(token)
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
                "_source": {"id": "e1", "source": "system", "event_type": "process", "severity": "low", "message": "hi", "tenant_id": "tenant-a"},
            })))
            .mount(&mock_server)
            .await;
        let store =
            crate::es::ElasticsearchStore::new(mock_server.uri(), "aaa-events-*", None, None);
        let state = state_with_store(store);
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);

        let res = server.get("/events/e1").authorization_bearer(token).await;
        res.assert_status_ok();
        let body: BaseEvent = res.json();
        assert_eq!(body.id, "e1");
    }

    /// Cross-tenant isolation regression (the finding this pass fixes): a
    /// document that exists, but belongs to a different tenant than the
    /// caller, must answer 404 — never 200 with someone else's event.
    #[tokio::test]
    async fn get_event_hides_a_different_tenants_event() {
        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/aaa-events-*/_doc/e1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "_source": {"id": "e1", "source": "system", "event_type": "process", "severity": "low", "message": "hi", "tenant_id": "tenant-b"},
            })))
            .mount(&mock_server)
            .await;
        let store =
            crate::es::ElasticsearchStore::new(mock_server.uri(), "aaa-events-*", None, None);
        let state = state_with_store(store);
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);

        let res = server.get("/events/e1").authorization_bearer(token).await;
        res.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = res.json();
        assert_eq!(body["detail"], "Event not found");
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
        let state = state_with_store(store);
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);

        let res = server
            .get("/events/missing")
            .authorization_bearer(token)
            .await;
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
        let state = state_with_store(store);
        let token = sign_token(&state, TENANT_A, READ_SCOPE);
        let server = test_server(state);

        let res = server.get("/events/e1").authorization_bearer(token).await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn tenant_ctx(tenant: &str) -> TenantContext {
        TenantContext {
            tenant: Tenant(tenant.to_owned()),
        }
    }

    #[tokio::test]
    async fn stream_events_skips_non_matching_and_delivers_matching_events() {
        let state = dev_state();
        let filters = StreamParams {
            sources: vec![LogSource::Kubernetes],
            event_types: vec![],
            severities: vec![],
        };
        let resp =
            match stream_events(State(state.clone()), tenant_ctx(TENANT_A), Query(filters)).await {
                Ok(sse) => sse.into_response(),
                Err(_) => panic!("expected sse ok, flag should be enabled by dev_state"),
            };
        let mut stream = resp.into_body().into_data_stream();

        let mut skipped = sample_event(TENANT_A);
        skipped.id = "skip-1".to_owned();
        skipped.source = LogSource::Auditd;
        let mut delivered = sample_event(TENANT_A);
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

    /// Tenant isolation on the broadcast stream (the same shared
    /// `event_bus` carries every tenant's events — see [`event_matches`]
    /// docs): a subscriber authenticated as tenant A must never see an
    /// event stamped with tenant B, even with filters that would otherwise
    /// match on source/type/severity.
    #[tokio::test]
    async fn stream_events_excludes_a_different_tenants_events() {
        let state = dev_state();
        let filters = StreamParams {
            sources: vec![],
            event_types: vec![],
            severities: vec![],
        };
        let resp =
            match stream_events(State(state.clone()), tenant_ctx(TENANT_A), Query(filters)).await {
                Ok(sse) => sse.into_response(),
                Err(_) => panic!("expected sse ok, flag should be enabled by dev_state"),
            };
        let mut stream = resp.into_body().into_data_stream();

        let mut other_tenant = sample_event(TENANT_B);
        other_tenant.id = "other-tenant-event".to_owned();
        let mut own_tenant = sample_event(TENANT_A);
        own_tenant.id = "own-tenant-event".to_owned();

        if state.event_bus.send(other_tenant).is_err() {
            panic!("expected at least one live subscriber for the other-tenant event");
        }
        if state.event_bus.send(own_tenant).is_err() {
            panic!("expected at least one live subscriber for the own-tenant event");
        }

        let chunk = match tokio::time::timeout(Duration::from_secs(2), stream.next()).await {
            Ok(Some(Ok(bytes))) => bytes,
            other => panic!("expected an SSE data chunk, got {other:?}"),
        };
        let text = String::from_utf8_lossy(&chunk);
        assert!(text.contains("own-tenant-event"), "chunk: {text}");
        assert!(
            !text.contains("other-tenant-event"),
            "tenant A must not see tenant B's event; chunk: {text}"
        );
    }

    fn sample_event(tenant_id: &str) -> BaseEvent {
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
            tenant_id: tenant_id.to_owned(),
            extra: Default::default(),
        }
    }

    #[test]
    fn stream_filters_match_v1_empty_means_any_semantics() {
        let event = sample_event(TENANT_A);
        let empty = StreamParams {
            sources: vec![],
            event_types: vec![],
            severities: vec![],
        };
        assert!(event_matches(&event, &empty, TENANT_A));

        let matching = StreamParams {
            sources: vec![LogSource::Kubernetes],
            event_types: vec![],
            severities: vec![Severity::High],
        };
        assert!(event_matches(&event, &matching, TENANT_A));

        let non_matching = StreamParams {
            sources: vec![LogSource::Auditd],
            event_types: vec![],
            severities: vec![],
        };
        assert!(!event_matches(&event, &non_matching, TENANT_A));
    }

    #[test]
    fn event_matches_rejects_a_different_tenant_regardless_of_other_filters() {
        let event = sample_event(TENANT_A);
        let any_filters = StreamParams {
            sources: vec![],
            event_types: vec![],
            severities: vec![],
        };
        assert!(!event_matches(&event, &any_filters, TENANT_B));
    }
}
