//! HTTP ingest surface — a byte-for-byte port of v1 `ingest/http_handler.py`.
//! Exposes `POST /ingest` (the endpoint the manager's siem router proxies to
//! via `LOGS_URL`) and `GET /healthz` (the manager's liveness probe),
//! both on the v1 `HTTP_PORT` (5010).

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};

use crate::jsonord::{self, JsonVal};
use crate::ocsf::normalize;
use crate::opensearch::{build_bulk_body, daily_index, write_bulk};

/// v1 batch cap: a single `/ingest` request may carry at most 10,000 records.
const MAX_BATCH: usize = 10_000;
/// Default log source when the `X-Log-Source` header is absent (v1 default).
const DEFAULT_SOURCE: &str = "http";

/// Time source for the daily-index date and the timestamp fallback. Production
/// uses [`Clock::System`]; tests inject a fixed instant so the emitted index and
/// documents are deterministic.
#[derive(Clone)]
pub enum Clock {
    /// Wall-clock time (`Utc::now()`).
    System,
    /// A pinned instant, used only in tests.
    #[cfg(test)]
    Fixed(DateTime<Utc>),
}

impl Clock {
    /// Current instant per this clock.
    fn now(&self) -> DateTime<Utc> {
        match self {
            Clock::System => Utc::now(),
            #[cfg(test)]
            Clock::Fixed(t) => *t,
        }
    }
}

/// Shared handler state: the reqwest client, the OpenSearch base URL, and the
/// clock.
#[derive(Clone)]
pub struct AppState {
    /// HTTP client used for OpenSearch `_bulk` writes.
    pub http: reqwest::Client,
    /// OpenSearch base URL (`OPENSEARCH_URL`).
    pub opensearch_url: std::sync::Arc<str>,
    /// Time source.
    pub clock: Clock,
}

/// Builds the ingest router (`POST /ingest`, `GET /healthz`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/ingest", post(handle_ingest))
        .route("/healthz", get(handle_health))
        .with_state(state)
}

/// Serializes an order-preserving value as a compact `application/json`
/// response, matching v1's insertion-ordered `json_response` bodies.
fn ordered_json(status: StatusCode, val: &JsonVal) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        val.to_compact_string(),
    )
        .into_response()
}

/// v1 uncaught-exception 500. (v1 emitted aiohttp's plain-text 500; the manager
/// proxy maps any non-JSON/upstream error to its own 500 either way — this
/// keeps a JSON body per house convention.)
fn internal_error() -> Response {
    ordered_json(
        StatusCode::INTERNAL_SERVER_ERROR,
        &JsonVal::Obj(vec![(
            "error".to_owned(),
            JsonVal::Str("Internal Server Error".to_owned()),
        )]),
    )
}

/// `POST /ingest` — accepts a single JSON object or a JSON array of records,
/// normalizes each to OCSF, bulk-indexes them into the daily OpenSearch index,
/// and answers `202 {"ingested": <count>}`. Ported verbatim from v1
/// `HTTPIngestHandler.handle_ingest` (the S3/Parquet mirror-write is a
/// documented deferral — see the port contract).
async fn handle_ingest(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let parsed = match jsonro_parse(&body) {
        Ok(v) => v,
        // v1: `await request.json()` failure → 400 plain-text "Invalid JSON".
        Err(()) => return (StatusCode::BAD_REQUEST, "Invalid JSON").into_response(),
    };

    // v1: `records = body if isinstance(body, list) else [body]`.
    let records: Vec<JsonVal> = match parsed {
        JsonVal::Arr(items) => items,
        other => vec![other],
    };

    if records.len() > MAX_BATCH {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "Batch too large (max 10,000)",
        )
            .into_response();
    }

    let source = headers
        .get("X-Log-Source")
        .and_then(|v| v.to_str().ok())
        .unwrap_or(DEFAULT_SOURCE);

    let now = state.clock.now();
    let mut docs = Vec::with_capacity(records.len());
    for record in &records {
        match normalize(record, source, now) {
            Ok(doc) => docs.push(doc),
            // v1 raised on non-dict records / bad numeric timestamps → 500.
            Err(_) => return internal_error(),
        }
    }

    // v1 writes the batch to OpenSearch; an empty batch makes no request.
    if !docs.is_empty() {
        let index = daily_index(now);
        let bulk = build_bulk_body(&index, &docs);
        if let Err(e) = write_bulk(&state.http, &state.opensearch_url, bulk).await {
            tracing::error!(error = %e, "opensearch_bulk_failed");
            return internal_error();
        }
    }

    // v1: `json_response({"ingested": len(events)}, status=202)`.
    ordered_json(
        StatusCode::ACCEPTED,
        &JsonVal::Obj(vec![(
            "ingested".to_owned(),
            JsonVal::Num((records.len() as i64).into()),
        )]),
    )
}

/// `GET /healthz` — v1 liveness body `{"status":"ok","service":"logs"}`.
async fn handle_health() -> Response {
    ordered_json(
        StatusCode::OK,
        &JsonVal::Obj(vec![
            ("status".to_owned(), JsonVal::Str("ok".to_owned())),
            ("service".to_owned(), JsonVal::Str("logs".to_owned())),
        ]),
    )
}

/// Parses request bytes into an order-preserving value, collapsing any parse
/// error to `()` (the handler turns it into the v1 400 body).
fn jsonro_parse(body: &[u8]) -> Result<JsonVal, ()> {
    jsonord::from_slice(body).map_err(|_| ())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// The authoritative `_bulk` body captured from v1 source + opensearch-py
    /// 2.7.1 (see tests/fixtures + docs/v2-port/logs-contract.md).
    const BULK_REFERENCE: &[u8] = include_bytes!("../tests/fixtures/bulk_reference.ndjson");
    /// The exact batch bytes fed to v1 to produce `BULK_REFERENCE`.
    const BATCH_JSON: &[u8] = include_bytes!("../tests/fixtures/batch.json");

    /// The pinned "now" the reference fixture was generated under
    /// (index `skauswatch-logs-2026.07.25`).
    fn pinned_now() -> DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 7, 25, 12, 0, 0) {
            chrono::LocalResult::Single(dt) => dt,
            _ => panic!("valid pinned now"),
        }
    }

    fn state_for(opensearch_url: &str, clock: Clock) -> AppState {
        AppState {
            http: reqwest::Client::new(),
            opensearch_url: opensearch_url.into(),
            clock,
        }
    }

    /// Boots a `TestServer` for the ingest router with a pinned clock.
    fn test_server(opensearch_url: &str) -> axum_test::TestServer {
        axum_test::TestServer::new(router(state_for(
            opensearch_url,
            Clock::Fixed(pinned_now()),
        )))
    }

    #[test]
    fn system_clock_reflects_wall_clock_time() {
        let before = Utc::now();
        let now = Clock::System.now();
        let after = Utc::now();
        assert!(now >= before && now <= after);
    }

    #[tokio::test]
    async fn non_object_record_in_batch_returns_internal_error() {
        let server = test_server("http://unused");
        let res = server
            .post("/ingest")
            .content_type("application/json")
            .text("[42]")
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(res.text(), r#"{"error":"Internal Server Error"}"#);
    }

    #[tokio::test]
    async fn opensearch_bulk_failure_returns_internal_error() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let server = test_server(&mock.uri());
        let res = server
            .post("/ingest")
            .content_type("application/json")
            .text(r#"{"message":"x"}"#)
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(res.text(), r#"{"error":"Internal Server Error"}"#);
    }

    #[tokio::test]
    async fn healthz_body_matches_v1_bytes() {
        let server = test_server("http://unused");
        let res = server.get("/healthz").await;
        res.assert_status_ok();
        assert_eq!(res.text(), r#"{"status":"ok","service":"logs"}"#);
    }

    #[tokio::test]
    async fn invalid_json_is_plain_text_400() {
        let server = test_server("http://unused");
        let res = server.post("/ingest").text("{not json").await;
        res.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(res.text(), "Invalid JSON");
    }

    #[tokio::test]
    async fn oversized_batch_is_413() {
        let server = test_server("http://unused");
        let big = format!("[{}]", vec!["{}"; MAX_BATCH + 1].join(","));
        let res = server
            .post("/ingest")
            .content_type("application/json")
            .text(big)
            .await;
        res.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(res.text(), "Batch too large (max 10,000)");
    }

    #[tokio::test]
    async fn single_object_is_wrapped_and_ingested() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"errors": false, "items": []})),
            )
            .mount(&mock)
            .await;

        let server = test_server(&mock.uri());
        let res = server
            .post("/ingest")
            .content_type("application/json")
            .text(r#"{"message":"solo"}"#)
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.text(), r#"{"ingested":1}"#);
    }

    /// End-to-end parity: POST the exact v1 batch and assert both the response
    /// shape AND the outgoing OpenSearch `_bulk` body match v1 byte-for-byte.
    #[tokio::test]
    async fn ingest_bulk_body_matches_v1_reference() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"errors": false, "items": []})),
            )
            .mount(&mock)
            .await;

        let server = test_server(&mock.uri());

        let res = server
            .post("/ingest")
            .content_type("application/json")
            .add_header("X-Log-Source", "ingest-test")
            .bytes(BATCH_JSON.to_vec().into())
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.text(), r#"{"ingested":7}"#);

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "exactly one _bulk POST");
        assert_eq!(
            requests[0].body, BULK_REFERENCE,
            "outgoing _bulk body must match v1 byte-for-byte"
        );
    }

    /// The in-process bulk builder must reproduce the fixture independently of
    /// the HTTP path (guards against any regression in framing/ordering).
    #[test]
    fn build_bulk_body_reproduces_reference_bytes() {
        let batch = jsonord::from_slice(BATCH_JSON).unwrap();
        let JsonVal::Arr(records) = batch else {
            panic!("batch fixture is a JSON array");
        };
        let now = pinned_now();
        let docs: Vec<JsonVal> = records
            .iter()
            .map(|r| normalize(r, "ingest-test", now).unwrap())
            .collect();
        let body = build_bulk_body(&daily_index(now), &docs);
        assert_eq!(body.as_bytes(), BULK_REFERENCE);
    }
}
