//! HTTP ingest surface — a byte-for-byte port of v1 `ingest/http_handler.py`,
//! hardened with the auth/tenancy/licensing this service shipped without
//! (see `docs/v2-port/feature-flags.md`'s `services/logs` gap). Exposes
//! `POST /ingest` (the endpoint the manager's siem router proxies to via
//! `LOGS_URL`) and `GET /healthz` (the manager's liveness probe), both on
//! the v1 `HTTP_PORT` (5010).
//!
//! `POST /ingest` now requires a valid tenant-bearing bearer JWT
//! (`skauswatch_auth::tenant_middleware`) and the `LOG_INGEST_FLAG` PostHog
//! flag (`penguin_licensing::axum::FlagGate`) — see [`router`]. Every
//! normalized document is stamped with the caller's `TenantContext` tenant
//! (never a client-supplied value) before it is bulk-indexed, so downstream
//! tenant-scoped search (e.g. monitor's `tenant_id` term filter) has
//! provenance to filter on. `GET /healthz` stays unauthenticated — it is the
//! manager's liveness probe and carries no tenant-scoped data.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::{DateTime, Utc};
use penguin_licensing::LicenseClient;
use penguin_licensing::axum::{FlagGate, flag_gate};
use skauswatch_auth::TenantContext;

use crate::jsonord::{self, JsonVal};
use crate::ocsf::normalize;
use crate::opensearch::{build_bulk_body, daily_index, write_bulk};

/// v1 batch cap: a single `/ingest` request may carry at most 10,000 records.
const MAX_BATCH: usize = 10_000;
/// Default log source when the `X-Log-Source` header is absent (v1 default).
const DEFAULT_SOURCE: &str = "http";
/// PostHog flag gating the SIEM ingest surface — default OFF until
/// validated (see `general.md` Feature Toggling & License Enforcement).
/// Already declared in `services/manager/src/flags.rs`'s `CORE_FLAGS`
/// registry, but was never enforced anywhere in this crate until this pass.
pub const LOG_INGEST_FLAG: &str = "skauswatch.log-ingest";

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

/// Shared handler state: the reqwest client, the OpenSearch base URL, the
/// clock, the shared JWT signing secret, and the license/flag client.
#[derive(Clone)]
pub struct AppState {
    /// HTTP client used for OpenSearch `_bulk` writes.
    pub http: reqwest::Client,
    /// OpenSearch base URL (`OPENSEARCH_URL`).
    pub opensearch_url: std::sync::Arc<str>,
    /// Time source.
    pub clock: Clock,
    /// Shared HS256 signing secret (`JWT_SECRET_KEY`) — every `/ingest`
    /// request must carry a bearer token verified against this (via
    /// `skauswatch_auth::tenant_middleware`). Before this pass `/ingest` had
    /// no authentication at all.
    pub jwt_secret: Arc<str>,
    /// License entitlement + PostHog flag client (fail-safe) — gates
    /// `/ingest` on [`LOG_INGEST_FLAG`].
    pub license: Arc<LicenseClient>,
}

impl skauswatch_auth::JwtSecretSource for AppState {
    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }
}

/// Builds the ingest router (`POST /ingest`, `GET /healthz`).
///
/// `/ingest` is wrapped in two layers, applied in the house tenant → feature
/// ordering (`skauswatch_auth::tenant_middleware`'s ordering contract):
/// `FlagGate` (added first, so it sits innermost, closest to the handler)
/// then `tenant_middleware` (added last, so it sits outermost and runs
/// first) — a request is tenant-authenticated before the flag is even
/// consulted. `/healthz` is merged in afterward, outside both layers: it is
/// the manager's unauthenticated liveness probe
/// (`docs/v2-port/logs-contract.md`) and carries no tenant-scoped data.
pub fn router(state: AppState) -> Router {
    let ingest = Router::new()
        .route("/ingest", post(handle_ingest))
        .layer(axum::middleware::from_fn_with_state(
            FlagGate::new(state.license.clone(), LOG_INGEST_FLAG),
            flag_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            skauswatch_auth::tenant_middleware::<AppState>,
        ));

    Router::new()
        .merge(ingest)
        .route("/healthz", get(handle_health))
        .with_state(state)
}

/// Stamps the caller's tenant onto a normalized OCSF document as a
/// top-level `tenant_id` field, appended after `raw_data`. The tenant value
/// always comes from the validated [`TenantContext`] (the JWT `tenant`
/// claim, decoded by `tenant_middleware`) — a `tenant_id` key embedded in
/// the caller's raw record survives untouched *inside* `raw_data` as
/// unvalidated payload data, but never overrides this top-level stamp; body
/// content is never a trusted tenant source (see
/// `docs/v2-port/tenancy-model.md`). `normalize` always returns a
/// [`JsonVal::Obj`] (see its own contract), so the non-matching arm is
/// unreachable in practice; it is a no-op rather than a panic if that ever
/// changes.
fn stamp_tenant(doc: &mut JsonVal, tenant: &str) {
    if let JsonVal::Obj(entries) = doc {
        entries.push(("tenant_id".to_owned(), JsonVal::Str(tenant.to_owned())));
    }
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
#[utoipa::path(
    post,
    path = "/ingest",
    tag = "logs",
    security(("bearer_jwt" = [])),
    request_body(
        content = serde_json::Value,
        content_type = "application/json",
        description = "A single JSON log record object, or a JSON array of \
            up to 10,000 record objects. Each record is normalized to OCSF, \
            stamped with the caller's JWT tenant, and bulk-indexed into the \
            daily OpenSearch index."
    ),
    responses(
        (status = 202, description = "Records accepted for indexing", body = crate::openapi::IngestAcceptedResponse),
        (status = 400, description = "Request body is not valid JSON", body = String, content_type = "text/plain"),
        (status = 401, description = "Missing, invalid, or expired bearer token", body = crate::openapi::IngestErrorResponse),
        (status = 403, description = "Token carries no usable tenant claim, or the skauswatch.log-ingest flag is disabled", body = crate::openapi::IngestErrorResponse),
        (status = 413, description = "Batch exceeds the 10,000 record cap", body = String, content_type = "text/plain"),
        (status = 500, description = "OCSF normalization failed or the OpenSearch bulk write errored", body = crate::openapi::IngestErrorResponse),
    ),
)]
pub(crate) async fn handle_ingest(
    State(state): State<AppState>,
    tenant_ctx: TenantContext,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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
            Ok(mut doc) => {
                stamp_tenant(&mut doc, tenant_ctx.tenant.as_str());
                docs.push(doc);
            }
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
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "logs",
    responses(
        (status = 200, description = "Service liveness", body = crate::openapi::HealthResponse),
    ),
)]
pub(crate) async fn handle_health() -> Response {
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
    use std::sync::Arc;

    use chrono::TimeZone as _;
    use penguin_licensing::LicenseClient;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// The authoritative `_bulk` body captured from v1 source + opensearch-py
    /// 2.7.1 (see tests/fixtures + docs/v2-port/logs-contract.md). Predates
    /// tenancy — `stamp_bulk_reference` layers the expected `tenant_id` stamp
    /// on top for tests that exercise the now-authenticated handler.
    const BULK_REFERENCE: &[u8] = include_bytes!("../tests/fixtures/bulk_reference.ndjson");
    /// The exact batch bytes fed to v1 to produce `BULK_REFERENCE`.
    const BATCH_JSON: &[u8] = include_bytes!("../tests/fixtures/batch.json");

    /// Fixed `JWT_SECRET_KEY` every test's tokens are signed/verified against.
    const TEST_JWT_SECRET: &str = "test-secret";
    /// The tenant used by tests that aren't specifically exercising
    /// cross-tenant behavior.
    const TEST_TENANT: &str = "tenant-a";

    /// The pinned "now" the reference fixture was generated under
    /// (index `skauswatch-logs-2026.07.25`).
    fn pinned_now() -> DateTime<Utc> {
        match Utc.with_ymd_and_hms(2026, 7, 25, 12, 0, 0) {
            chrono::LocalResult::Single(dt) => dt,
            _ => panic!("valid pinned now"),
        }
    }

    /// Mints a valid house `Claims` bearer token for `tenant`, signed with
    /// [`TEST_JWT_SECRET`].
    fn bearer_for(tenant: &str) -> String {
        skauswatch_testkit::jwt::mint_claims_token(
            TEST_JWT_SECRET,
            "tester",
            tenant,
            "*:read *:write",
            &["admin"],
        )
    }

    /// Splices `,"tenant_id":"<tenant>"` in before the final `}` of every
    /// document line (odd line index) in a `_bulk` NDJSON reference fixture —
    /// reproducing exactly what [`stamp_tenant`] adds on top of the untouched
    /// v1-parity OCSF document, so byte-for-byte assertions keep working
    /// after the tenancy retrofit.
    fn stamp_bulk_reference(reference: &[u8], tenant: &str) -> Vec<u8> {
        let text = std::str::from_utf8(reference).expect("reference fixture is valid utf-8");
        let mut out = String::new();
        for (i, line) in text.lines().enumerate() {
            if i % 2 == 1 {
                let trimmed = line.strip_suffix('}').expect("document line ends with '}'");
                out.push_str(trimmed);
                out.push_str(&format!(",\"tenant_id\":\"{tenant}\"}}"));
            } else {
                out.push_str(line);
            }
            out.push('\n');
        }
        out.into_bytes()
    }

    fn state_for(opensearch_url: &str, clock: Clock, license: Arc<LicenseClient>) -> AppState {
        AppState {
            http: reqwest::Client::new(),
            opensearch_url: opensearch_url.into(),
            clock,
            jwt_secret: TEST_JWT_SECRET.into(),
            license,
        }
    }

    /// Boots a `TestServer` for the ingest router with a pinned clock and a
    /// dev-mode (flag-enabled) license client — the default posture for
    /// tests exercising the ingest success/error paths, not the flag gate
    /// itself (see [`test_server_with_license`] for that).
    fn test_server(opensearch_url: &str) -> axum_test::TestServer {
        test_server_with_license(
            opensearch_url,
            skauswatch_testkit::license::dev_license("skauswatch"),
        )
    }

    /// Like [`test_server`], but with a caller-supplied license client — used
    /// by the flag-gate-denied test to exercise the `LOG_INGEST_FLAG` 403
    /// path with a release-mode (flags default OFF) client.
    fn test_server_with_license(
        opensearch_url: &str,
        license: Arc<LicenseClient>,
    ) -> axum_test::TestServer {
        axum_test::TestServer::new(router(state_for(
            opensearch_url,
            Clock::Fixed(pinned_now()),
            license,
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
            .authorization_bearer(bearer_for(TEST_TENANT))
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
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(r#"{"message":"x"}"#)
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(res.text(), r#"{"error":"Internal Server Error"}"#);
    }

    /// `/healthz` stays outside both the tenant and flag layers — it is the
    /// manager's unauthenticated liveness probe.
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
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .text("{not json")
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(res.text(), "Invalid JSON");
    }

    #[tokio::test]
    async fn oversized_batch_is_413() {
        let server = test_server("http://unused");
        let big = format!("[{}]", vec!["{}"; MAX_BATCH + 1].join(","));
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
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
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(r#"{"message":"solo"}"#)
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.text(), r#"{"ingested":1}"#);
    }

    /// No `Authorization` header at all — `tenant_middleware` rejects before
    /// the handler (or the flag gate) ever runs.
    #[tokio::test]
    async fn ingest_without_bearer_token_is_401() {
        let server = test_server("http://unused");
        let res = server
            .post("/ingest")
            .content_type("application/json")
            .text(r#"{"message":"x"}"#)
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    /// A validly signed token with no usable `tenant` claim is a 403, not a
    /// 401 — matches `skauswatch_auth::TenantAuthError`'s house contract.
    #[tokio::test]
    async fn ingest_with_no_tenant_claim_is_403() {
        let server = test_server("http://unused");
        let token = skauswatch_testkit::jwt::mint_claims_token(
            TEST_JWT_SECRET,
            "tester",
            "", // no tenant claim
            "*:read *:write",
            &["admin"],
        );
        let res = server
            .post("/ingest")
            .authorization_bearer(token)
            .content_type("application/json")
            .text(r#"{"message":"x"}"#)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    /// `LOG_INGEST_FLAG` disabled (release-mode license, flags default OFF)
    /// denies even an otherwise-valid, tenant-bearing request.
    #[tokio::test]
    async fn ingest_denied_when_flag_disabled_returns_403() {
        let server = test_server_with_license(
            "http://unused",
            skauswatch_testkit::license::gated_license("skauswatch"),
        );
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(r#"{"message":"x"}"#)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    /// Every document bulk-indexed by `/ingest` carries the caller's JWT
    /// tenant as a top-level `tenant_id` field — the ingest-side provenance
    /// downstream tenant-scoped search (e.g. monitor's `tenant_id` term
    /// filter) depends on.
    #[tokio::test]
    async fn ingested_document_is_stamped_with_caller_tenant() {
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
            .authorization_bearer(bearer_for("acme-corp"))
            .content_type("application/json")
            .text(r#"{"message":"solo"}"#)
            .await;
        res.assert_status(StatusCode::ACCEPTED);

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1);
        let body = String::from_utf8(requests[0].body.clone()).unwrap();
        assert!(
            body.contains(r#""tenant_id":"acme-corp""#),
            "bulk body must carry the JWT tenant: {body}"
        );
    }

    /// A `tenant_id` key inside the caller's raw log record is inert as a
    /// tenant source: the stamped top-level `tenant_id` always reflects the
    /// JWT, and the body's own value survives unchanged only inside
    /// `raw_data` as ordinary payload data — the client cannot override the
    /// tenant boundary via request content (`docs/v2-port/tenancy-model.md`).
    #[tokio::test]
    async fn body_supplied_tenant_id_does_not_override_jwt_tenant() {
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
            .authorization_bearer(bearer_for("honest-tenant"))
            .content_type("application/json")
            .text(r#"{"tenant_id":"evil-tenant","message":"spoof attempt"}"#)
            .await;
        res.assert_status(StatusCode::ACCEPTED);

        let requests = mock.received_requests().await.unwrap();
        let body = String::from_utf8(requests[0].body.clone()).unwrap();
        // The document line ends with the stamped top-level `tenant_id` —
        // the JWT tenant, not the body-supplied one — appended after the
        // `raw_data` object that still echoes the caller's original (evil)
        // value verbatim as inert, untrusted payload data.
        let expected_doc_suffix = "\"raw_data\":{\"tenant_id\":\"evil-tenant\",\"message\":\"spoof attempt\"},\"tenant_id\":\"honest-tenant\"}\n";
        assert!(
            body.ends_with(expected_doc_suffix),
            "expected doc to end with {expected_doc_suffix:?}, got: {body}"
        );
    }

    /// End-to-end parity: POST the exact v1 batch (now authenticated) and
    /// assert both the response shape AND the outgoing OpenSearch `_bulk`
    /// body match v1 byte-for-byte, modulo the tenant stamp this pass adds.
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
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .add_header("X-Log-Source", "ingest-test")
            .bytes(BATCH_JSON.to_vec().into())
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.text(), r#"{"ingested":7}"#);

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(requests.len(), 1, "exactly one _bulk POST");
        assert_eq!(
            requests[0].body,
            stamp_bulk_reference(BULK_REFERENCE, TEST_TENANT),
            "outgoing _bulk body must match v1 byte-for-byte, plus the tenant stamp"
        );
    }

    /// The in-process bulk builder must reproduce the fixture independently of
    /// the HTTP path (guards against any regression in framing/ordering).
    /// Deliberately exercises `normalize`/`build_bulk_body` directly, with no
    /// tenant stamping — this is the pure OCSF/bulk pipeline parity guard,
    /// unrelated to the handler-level auth/tenancy this pass adds.
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

    /// Direct unit coverage of the stamping helper, independent of the HTTP
    /// path: a non-object `JsonVal` is left untouched rather than panicking
    /// (the defensive no-op arm `normalize`'s contract makes unreachable in
    /// practice via the handler).
    #[test]
    fn stamp_tenant_is_a_noop_on_non_object_values() {
        let mut not_an_object = JsonVal::Str("x".to_owned());
        stamp_tenant(&mut not_an_object, "tenant-a");
        assert_eq!(not_an_object, JsonVal::Str("x".to_owned()));
    }

    #[test]
    fn stamp_tenant_appends_tenant_id_after_raw_data() {
        let mut doc = JsonVal::Obj(vec![("raw_data".to_owned(), JsonVal::Obj(vec![]))]);
        stamp_tenant(&mut doc, "tenant-a");
        let JsonVal::Obj(entries) = &doc else {
            panic!("expected object");
        };
        assert_eq!(entries.last().map(|(k, _)| k.as_str()), Some("tenant_id"));
        assert_eq!(
            doc.get("tenant_id").and_then(JsonVal::as_str),
            Some("tenant-a")
        );
    }
}
