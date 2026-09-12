//! HTTPS OCSF/JSON ingest listener (`:8443`) — a byte-for-byte port of v1
//! `ingest/http_handler.py`, hardened with the auth/tenancy/licensing this
//! service shipped without (see `docs/v2-port/feature-flags.md`'s
//! `services/logs` gap). Exposes `POST /ingest` (the endpoint the manager's
//! siem router proxies to via `LOGS_URL`) and `GET /healthz` + `/readyz`
//! (the manager's liveness and readiness probes), both on the v1 `HTTP_PORT`
//! (5010).
//!
//! `crate::bootstrap::run_receiver` merges [`router`]'s result onto the
//! same HTTPS server as `crate::admin`'s admin surface (see that module's
//! doc comment).
//!
//! `POST /ingest` now requires a valid tenant-bearing bearer JWT
//! (`skauswatch_auth::tenant_middleware`) and the `LOG_INGEST_FLAG` PostHog
//! flag (`penguin_licensing::axum::FlagGate`) — see [`router`]. Every
//! normalized document is stamped with the caller's `TenantContext` tenant
//! (never a client-supplied value) before it is durably enqueued, so
//! downstream tenant-scoped search (e.g. monitor's `tenant_id` term filter)
//! has provenance to filter on. `GET /healthz` + `/readyz` stay
//! unauthenticated — they are the manager's liveness and readiness probes.
//!
//! Task 3.0b fix: this handler used to write straight to OpenSearch via
//! `opensearch::write_bulk`, bypassing the JetStream-backed
//! [`crate::buffer::EventBuffer`] entirely — so HTTPS-ingested events got
//! none of the durability the buffer→writer architecture exists to
//! provide, unlike syslog/OTLP which already enqueued correctly. Every
//! normalized document is now pushed through the same `EventBuffer` seam
//! (see [`crate::buffer`]'s durability contract); the writer, never this
//! listener, owns all OpenSearch writes.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use penguin_licensing::LicenseClient;
use penguin_licensing::axum::{FlagGate, flag_gate};
use sha2::{Digest, Sha256};
use skauswatch_auth::TenantContext;

use crate::buffer::{BufferError, EventBuffer, NormalizedEvent};
use skauswatch_ocsf::jsonord::{self, JsonVal};
use skauswatch_ocsf::normalize;
use skauswatch_ocsf::schema::{is_native_ocsf, validate_required_fields};

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

/// Shared handler state: the durable event buffer, the clock, the shared
/// JWT signing secret, and the license/flag client.
#[derive(Clone)]
pub struct AppState {
    /// Durable event buffer every normalized document is enqueued to
    /// (Task 3.0b) — the writer, never this listener, owns all OpenSearch
    /// writes. See `crate::buffer`'s module-level durability contract.
    pub buffer: Arc<dyn EventBuffer>,
    /// Time source.
    pub clock: Clock,
    /// Shared ES256 verify key (`JWT_VERIFY_KEY`, PEM SPKI public key —
    /// audit finding H1b, was a shared symmetric `JWT_SECRET_KEY`) — every
    /// `/ingest` request must carry a bearer token verified against this
    /// (via `skauswatch_auth::tenant_middleware`). Before this pass
    /// `/ingest` had no authentication at all.
    pub jwt_verify_key: jsonwebtoken::DecodingKey,
    /// License entitlement + PostHog flag client (fail-safe) — gates
    /// `/ingest` on [`LOG_INGEST_FLAG`].
    pub license: Arc<LicenseClient>,
}

impl skauswatch_auth::JwtSecretSource for AppState {
    fn jwt_verify_key(&self) -> &jsonwebtoken::DecodingKey {
        &self.jwt_verify_key
    }
}

/// Builds the ingest router (`POST /ingest`, `GET /healthz`, `GET /readyz`).
///
/// `/ingest` is wrapped in two layers, applied in the house tenant → feature
/// ordering (`skauswatch_auth::tenant_middleware`'s ordering contract):
/// `FlagGate` (added first, so it sits innermost, closest to the handler)
/// then `tenant_middleware` (added last, so it sits outermost and runs
/// first) — a request is tenant-authenticated before the flag is even
/// consulted. `/healthz` and `/readyz` are merged in afterward, outside both
/// layers: they are the manager's unauthenticated liveness and readiness
/// probes and carry no tenant-scoped data.
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
        .route("/readyz", get(handle_ready))
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

/// Deterministic content-hash `Nats-Msg-Id` dedup key for one normalized,
/// tenant-stamped document — mirrors `listeners::syslog::dedup_key`'s
/// tenant+doc content-hash convention, so a retried publish of the same
/// event is a server-side no-op on the buffer (see `crate::buffer`'s
/// durability contract) rather than a duplicate document.
fn dedup_key_for(tenant: &str, doc: &JsonVal) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant.as_bytes());
    hasher.update(doc.to_compact_string().as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Records [`crate::otel::metric_names::RECEIVER_EVENTS_TOTAL`] on success,
/// or [`crate::otel::metric_names::BUFFER_FULL_REJECTIONS_TOTAL`] on
/// backpressure, both labeled `transport = "http"` — mirrors
/// `listeners::syslog`/`listeners::otlp`'s identically-named helper.
fn record_enqueue_metrics(result: &Result<(), BufferError>, transport: &str) {
    match result {
        Ok(()) => {
            metrics::counter!(
                crate::otel::metric_names::RECEIVER_EVENTS_TOTAL,
                "transport" => transport.to_owned()
            )
            .increment(1);
        }
        Err(BufferError::Full) => {
            metrics::counter!(
                crate::otel::metric_names::BUFFER_FULL_REJECTIONS_TOTAL,
                "transport" => transport.to_owned()
            )
            .increment(1);
        }
        Err(_) => {}
    }
}

/// Maps a buffer-push failure onto the ingest HTTP contract: `Full` is 429
/// Too Many Requests (retryable backpressure — matches the OTLP HTTP
/// listener's same convention, Spec §7c); `Transport`/`Serialize` are a
/// genuine server-side fault, 500.
fn buffer_error_to_response(err: BufferError) -> Response {
    match err {
        BufferError::Full => {
            tracing::warn!(%err, "http ingest push backpressure: event buffer is full");
            ordered_json(
                StatusCode::TOO_MANY_REQUESTS,
                &JsonVal::Obj(vec![("error".to_owned(), JsonVal::Str(err.to_string()))]),
            )
        }
        BufferError::Transport(_) | BufferError::Serialize(_) => {
            tracing::error!(%err, "http ingest push failed");
            internal_error()
        }
    }
}

/// `POST /ingest` — accepts a single JSON object or a JSON array of records,
/// normalizes each to OCSF, bulk-indexes them into the daily OpenSearch index,
/// and answers `202 {"ingested": <count>}`. Ported verbatim from v1
/// `HTTPIngestHandler.handle_ingest` (the S3/Parquet mirror-write is a
/// documented deferral — see the port contract).
#[utoipa::path(
    post,
    path = "/ingest",
    tag = "svc-ingest",
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
        (status = 429, description = "Event buffer is full; retry with backoff", body = crate::openapi::IngestErrorResponse),
        (status = 500, description = "OCSF normalization failed or the event buffer push errored", body = crate::openapi::IngestErrorResponse),
    ),
)]
#[tracing::instrument(name = "receiver_enqueue", skip(state, tenant_ctx, headers, body))]
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
        // Native OCSF documents (with class_uid or metadata field) are strictly
        // validated for all required fields; missing a required field is a 400.
        // Generic JSON is normalized (permissive — normalize fills missing fields).
        if is_native_ocsf(record) {
            if validate_required_fields(record).is_err() {
                return (StatusCode::BAD_REQUEST, "Missing required OCSF field").into_response();
            }
            // Native OCSF is already in the correct structure; just stamp tenant.
            let mut doc = record.clone();
            stamp_tenant(&mut doc, tenant_ctx.tenant.as_str());
            docs.push(doc);
        } else {
            // Generic JSON: normalize to OCSF (permissive, adds missing fields).
            match normalize(record, source, now) {
                Ok(mut doc) => {
                    stamp_tenant(&mut doc, tenant_ctx.tenant.as_str());
                    docs.push(doc);
                }
                // v1 raised on non-dict records / bad numeric timestamps → 500.
                Err(_) => return internal_error(),
            }
        }
    }

    // Durably enqueue each normalized, tenant-stamped document — the
    // writer (never this listener) owns all OpenSearch writes (Task 3.0b;
    // see this module's doc comment).
    for doc in &docs {
        let dedup_key = dedup_key_for(tenant_ctx.tenant.as_str(), doc);
        let push_result = state
            .buffer
            .push(NormalizedEvent {
                tenant: tenant_ctx.tenant.clone(),
                doc: doc.clone(),
                dedup_key,
            })
            .await;
        record_enqueue_metrics(&push_result, "http");
        if let Err(err) = push_result {
            return buffer_error_to_response(err);
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

/// `GET /healthz` — v1 liveness body `{"status":"ok","service":"svc-ingest"}`.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "svc-ingest",
    responses(
        (status = 200, description = "Service liveness", body = crate::openapi::HealthResponse),
    ),
)]
pub(crate) async fn handle_health() -> Response {
    ordered_json(
        StatusCode::OK,
        &JsonVal::Obj(vec![
            ("status".to_owned(), JsonVal::Str("ok".to_owned())),
            ("service".to_owned(), JsonVal::Str("svc-ingest".to_owned())),
        ]),
    )
}

/// `GET /readyz` — readiness probe following the standard convention.
#[utoipa::path(
    get,
    path = "/readyz",
    tag = "svc-ingest",
    responses(
        (status = 200, description = "Service is ready", body = crate::openapi::ReadyResponse),
        (status = 503, description = "Service is not ready", body = crate::openapi::ReadyResponse),
    ),
)]
pub(crate) async fn handle_ready() -> (StatusCode, Response) {
    let status = StatusCode::OK;
    let body = Json(serde_json::json!({ "status": "ready" }));
    (status, body.into_response())
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use chrono::TimeZone as _;
    use penguin_licensing::LicenseClient;

    use super::*;
    use crate::buffer::InMemoryBuffer;
    use crate::opensearch::{build_bulk_body, daily_index};

    /// The authoritative `_bulk` body captured from v1 source + opensearch-py
    /// 2.7.1 (see tests/fixtures + docs/v2-port/logs-contract.md). Predates
    /// tenancy — `stamp_bulk_reference` layers the expected `tenant_id` stamp
    /// on top for tests that exercise the now-authenticated handler.
    const BULK_REFERENCE: &[u8] = include_bytes!("../../tests/fixtures/bulk_reference.ndjson");
    /// The exact batch bytes fed to v1 to produce `BULK_REFERENCE`.
    const BATCH_JSON: &[u8] = include_bytes!("../../tests/fixtures/batch.json");

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
    /// the shared fixture keypair (`skauswatch_testkit::jwt::signing_key`).
    fn bearer_for(tenant: &str) -> String {
        skauswatch_testkit::jwt::mint_claims_token(
            skauswatch_testkit::jwt::signing_key(),
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

    fn state_for(
        buffer: Arc<dyn EventBuffer>,
        clock: Clock,
        license: Arc<LicenseClient>,
    ) -> AppState {
        AppState {
            buffer,
            clock,
            jwt_verify_key: skauswatch_testkit::jwt::verify_key().clone(),
            license,
        }
    }

    /// A bounded in-process [`EventBuffer`] with room for `capacity` events
    /// — the default sink for tests that don't care about buffer behavior
    /// itself, plus the ones that do (e.g. `capacity == 0` always answers
    /// [`BufferError::Full`]).
    fn buffer(capacity: usize) -> Arc<dyn EventBuffer> {
        Arc::new(InMemoryBuffer::new(capacity))
    }

    /// Boots a `TestServer` for the ingest router with a pinned clock and a
    /// dev-mode (flag-enabled) license client — the default posture for
    /// tests exercising the ingest success/error paths, not the flag gate
    /// itself (see [`test_server_with_license`] for that).
    fn test_server(buffer: Arc<dyn EventBuffer>) -> axum_test::TestServer {
        test_server_with_license(
            buffer,
            skauswatch_testkit::license::dev_license("skauswatch"),
        )
    }

    /// Like [`test_server`], but with a caller-supplied license client — used
    /// by the flag-gate-denied test to exercise the `LOG_INGEST_FLAG` 403
    /// path with a release-mode (flags default OFF) client.
    fn test_server_with_license(
        buffer: Arc<dyn EventBuffer>,
        license: Arc<LicenseClient>,
    ) -> axum_test::TestServer {
        axum_test::TestServer::new(router(state_for(
            buffer,
            Clock::Fixed(pinned_now()),
            license,
        )))
    }

    /// `EventBuffer` test double whose `push` always fails with a
    /// `BufferError::Transport` — exercises the handler's 500 branch, since
    /// `InMemoryBuffer` never itself produces anything but `Full` (see
    /// `buffer::inmemory`'s own doc comment).
    struct AlwaysTransportErrorBuffer;

    #[async_trait::async_trait]
    impl EventBuffer for AlwaysTransportErrorBuffer {
        async fn push(&self, _event: NormalizedEvent) -> Result<(), BufferError> {
            Err(BufferError::Transport(
                "simulated transport failure".to_owned(),
            ))
        }
        async fn consume(
            &self,
            _batch_size: usize,
        ) -> Result<Vec<crate::buffer::DeliveredEvent>, BufferError> {
            Ok(Vec::new())
        }
        async fn ack(&self, _handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            Ok(())
        }
        async fn nack(&self, _handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            Ok(())
        }
    }

    /// `EventBuffer` test double that only counts `push` calls — proves
    /// `/ingest` enqueues through the buffer and nothing else: after Task
    /// 3.0b, `AppState` carries no HTTP/OpenSearch client at all, so this
    /// buffer is the only sink the handler can possibly reach.
    #[derive(Clone, Default)]
    struct CountingBuffer {
        count: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl EventBuffer for CountingBuffer {
        async fn push(&self, _event: NormalizedEvent) -> Result<(), BufferError> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        async fn consume(
            &self,
            _batch_size: usize,
        ) -> Result<Vec<crate::buffer::DeliveredEvent>, BufferError> {
            Ok(Vec::new())
        }
        async fn ack(&self, _handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            Ok(())
        }
        async fn nack(&self, _handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            Ok(())
        }
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
        let server = test_server(buffer(10));
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text("[42]")
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(res.text(), r#"{"error":"Internal Server Error"}"#);
    }

    /// A buffer transport failure (never surfaced by `InMemoryBuffer`
    /// itself — see [`AlwaysTransportErrorBuffer`]) maps to the same 500
    /// contract v1's OpenSearch bulk-write failure used to.
    #[tokio::test]
    async fn buffer_push_transport_error_returns_internal_error() {
        let erased: Arc<dyn EventBuffer> = Arc::new(AlwaysTransportErrorBuffer);
        let server = test_server(erased);
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(r#"{"message":"x"}"#)
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(res.text(), r#"{"error":"Internal Server Error"}"#);
    }

    /// A full buffer answers 429 (retryable backpressure), never a 500 —
    /// matches the OTLP HTTP listener's identical convention (Spec §7c).
    #[tokio::test]
    async fn ingest_returns_429_when_buffer_is_full() {
        let server = test_server(buffer(0));
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(r#"{"message":"x"}"#)
            .await;
        res.assert_status(StatusCode::TOO_MANY_REQUESTS);
    }

    /// The architectural bug this task fixes: `/ingest` must durably
    /// enqueue through the shared `EventBuffer` — never bypass it with a
    /// direct OpenSearch write. `AppState` carries no HTTP/OpenSearch
    /// client after this fix, so `CountingBuffer` is provably the only
    /// sink the handler can reach; this test additionally pins the exact
    /// push count against the response's `ingested` count.
    #[tokio::test]
    async fn ingest_pushes_exactly_n_events_to_the_buffer_and_writes_nothing_directly() {
        let counting = CountingBuffer::default();
        let erased: Arc<dyn EventBuffer> = Arc::new(counting.clone());
        let server = test_server(erased);

        let batch = r#"[{"message":"one"},{"message":"two"},{"message":"three"}]"#;
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(batch)
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.text(), r#"{"ingested":3}"#);
        assert_eq!(
            counting.count.load(Ordering::SeqCst),
            3,
            "exactly 3 events must be pushed to the buffer, none written elsewhere"
        );
    }

    /// `/healthz` stays outside both the tenant and flag layers — it is the
    /// manager's unauthenticated liveness probe.
    #[tokio::test]
    async fn healthz_body_matches_v1_bytes() {
        let server = test_server(buffer(10));
        let res = server.get("/healthz").await;
        res.assert_status_ok();
        assert_eq!(res.text(), r#"{"status":"ok","service":"svc-ingest"}"#);
    }

    #[tokio::test]
    async fn invalid_json_is_plain_text_400() {
        let server = test_server(buffer(10));
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
        let server = test_server(buffer(10));
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
        let buf = buffer(10);
        let server = test_server(buf.clone());
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(r#"{"message":"solo"}"#)
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.text(), r#"{"ingested":1}"#);

        let delivered = buf.consume(10).await.unwrap();
        assert_eq!(
            delivered.len(),
            1,
            "the single record must be enqueued to the buffer"
        );
    }

    /// No `Authorization` header at all — `tenant_middleware` rejects before
    /// the handler (or the flag gate) ever runs.
    #[tokio::test]
    async fn ingest_without_bearer_token_is_401() {
        let server = test_server(buffer(10));
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
        let server = test_server(buffer(10));
        let token = skauswatch_testkit::jwt::mint_claims_token(
            skauswatch_testkit::jwt::signing_key(),
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
            buffer(10),
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

    /// Every document enqueued by `/ingest` carries the caller's JWT tenant
    /// as a top-level `tenant_id` field — the ingest-side provenance
    /// downstream tenant-scoped search (e.g. monitor's `tenant_id` term
    /// filter) depends on.
    #[tokio::test]
    async fn ingested_document_is_stamped_with_caller_tenant() {
        let buf = buffer(10);
        let server = test_server(buf.clone());
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for("acme-corp"))
            .content_type("application/json")
            .text(r#"{"message":"solo"}"#)
            .await;
        res.assert_status(StatusCode::ACCEPTED);

        let delivered = buf.consume(10).await.unwrap();
        assert_eq!(delivered.len(), 1);
        let event = &delivered[0].event;
        assert_eq!(event.tenant.as_str(), "acme-corp");
        assert_eq!(
            event.doc.get("tenant_id").and_then(JsonVal::as_str),
            Some("acme-corp"),
            "buffered doc must carry the JWT tenant as a top-level field"
        );
    }

    /// A `tenant_id` key inside the caller's raw log record is inert as a
    /// tenant source: the stamped top-level `tenant_id` always reflects the
    /// JWT, and the body's own value survives unchanged only inside
    /// `raw_data` as ordinary payload data — the client cannot override the
    /// tenant boundary via request content (`docs/v2-port/tenancy-model.md`).
    #[tokio::test]
    async fn body_supplied_tenant_id_does_not_override_jwt_tenant() {
        let buf = buffer(10);
        let server = test_server(buf.clone());
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for("honest-tenant"))
            .content_type("application/json")
            .text(r#"{"tenant_id":"evil-tenant","message":"spoof attempt"}"#)
            .await;
        res.assert_status(StatusCode::ACCEPTED);

        let delivered = buf.consume(10).await.unwrap();
        let doc_str = delivered[0].event.doc.to_compact_string();
        // The document ends with the stamped top-level `tenant_id` — the
        // JWT tenant, not the body-supplied one — appended after the
        // `raw_data` object that still echoes the caller's original (evil)
        // value verbatim as inert, untrusted payload data.
        let expected_doc_suffix = "\"raw_data\":{\"tenant_id\":\"evil-tenant\",\"message\":\"spoof attempt\"},\"tenant_id\":\"honest-tenant\"}";
        assert!(
            doc_str.ends_with(expected_doc_suffix),
            "expected doc to end with {expected_doc_suffix:?}, got: {doc_str}"
        );
    }

    /// End-to-end parity: POST the exact v1 batch (now authenticated) and
    /// assert both the response shape AND the buffered documents —
    /// reassembled into a `_bulk` body — match v1 byte-for-byte, modulo the
    /// tenant stamp this pass adds. Proves the fix without reintroducing a
    /// direct OpenSearch dependency into the handler under test.
    #[tokio::test]
    async fn ingest_buffered_docs_reproduce_v1_bulk_reference_bytes() {
        let buf = buffer(10);
        let server = test_server(buf.clone());

        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .add_header("X-Log-Source", "ingest-test")
            .bytes(BATCH_JSON.to_vec().into())
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.text(), r#"{"ingested":7}"#);

        let delivered = buf.consume(10).await.unwrap();
        assert_eq!(
            delivered.len(),
            7,
            "all 7 records must be enqueued to the buffer"
        );
        let docs: Vec<JsonVal> = delivered.into_iter().map(|d| d.event.doc).collect();
        let body = build_bulk_body(&daily_index(pinned_now()), &docs);
        assert_eq!(
            body.as_bytes(),
            stamp_bulk_reference(BULK_REFERENCE, TEST_TENANT).as_slice(),
            "buffered docs must reconstruct the v1 bulk body byte-for-byte, plus the tenant stamp"
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

    /// Native OCSF documents are identified by presence of class_uid or
    /// metadata field. If any required OCSF field is missing, the request is
    /// rejected with 400 (strict validation). This test verifies a native OCSF
    /// document missing a required field returns 400.
    #[tokio::test]
    async fn native_ocsf_document_with_missing_required_field_is_400() {
        let server = test_server(buffer(10));
        // Send a document that has class_uid (OCSF marker) but is missing
        // other required fields (e.g., time, severity_id, etc.). This should
        // be rejected with 400 because it's identified as native OCSF.
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(r#"{"class_uid":2001,"message":"incomplete ocsf"}"#)
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(res.text(), "Missing required OCSF field");
    }

    /// A complete native OCSF document (with all required fields) should be
    /// accepted and indexed as-is (not re-normalized).
    #[tokio::test]
    async fn complete_native_ocsf_document_is_accepted() {
        let buf = buffer(10);
        let server = test_server(buf.clone());
        // Send a complete native OCSF document with all required fields.
        // It should pass validation and be enqueued.
        let ocsf_doc = r#"{
            "class_uid": 2001,
            "class_name": "security_finding",
            "time": "2026-07-25T12:00:00Z",
            "severity_id": 2,
            "status_id": 1,
            "message": "test event",
            "metadata": {"version": "1.3.0"},
            "raw_data": {}
        }"#;
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(ocsf_doc)
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.text(), r#"{"ingested":1}"#);

        let delivered = buf.consume(10).await.unwrap();
        assert_eq!(
            delivered.len(),
            1,
            "the native OCSF document must be enqueued to the buffer"
        );
    }

    /// JSON arrays can contain a mix of generic JSON (normalized) and complete
    /// native OCSF documents (validated + enqueued as-is). This verifies that
    /// heterogeneous batches work correctly.
    #[tokio::test]
    async fn json_array_of_generic_and_ocsf_documents_are_both_enqueued() {
        let buf = buffer(10);
        let server = test_server(buf.clone());
        // Mix of generic JSON (no OCSF markers) and complete native OCSF
        let batch = r#"[
            {"message": "generic log"},
            {
                "class_uid": 2001,
                "class_name": "security_finding",
                "time": "2026-07-25T12:00:00Z",
                "severity_id": 2,
                "status_id": 1,
                "message": "complete ocsf",
                "metadata": {"version": "1.3.0"},
                "raw_data": {}
            }
        ]"#;
        let res = server
            .post("/ingest")
            .authorization_bearer(bearer_for(TEST_TENANT))
            .content_type("application/json")
            .text(batch)
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        assert_eq!(res.text(), r#"{"ingested":2}"#);

        let delivered = buf.consume(10).await.unwrap();
        assert_eq!(
            delivered.len(),
            2,
            "both documents must be enqueued to the buffer"
        );
    }
}
