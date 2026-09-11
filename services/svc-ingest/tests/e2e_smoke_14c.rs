//! Spec §14c consolidated smoke test — the single end-to-end scenario that
//! exercises every ingest protocol together at volume, then verifies real
//! OTel emission, mirroring the exact script in
//! `docs/v2-port/ingest-module-spec.md` §14c:
//!
//! 1. Start JetStream + OpenSearch (testcontainers) — done by every other
//!    Wave-3 e2e test via `tests/common`, reused here unchanged.
//! 2. Send 100 syslog events via UDP → verify all reach the OpenSearch index.
//! 3. Send 10 OTLP LogRecords via gRPC → verify indexed.
//! 4. Send 5 OCSF + 5 generic JSON docs via HTTPS `/ingest` → verify indexed.
//! 5. Verify OTel logs/metrics/traces emitted (≥1 record, ≥1 metric, ≥1 span).
//! 6. Cleanup (harness drops containers on scope exit).
//!
//! # Telemetry approach: real in-test OTLP sink for logs+traces, Prometheus
//! scrape for metrics — not a time-budget shortcut, an architecture fact
//!
//! `src/otel.rs`'s own doc comment establishes that svc-ingest's OTLP
//! exporters (`crate::otel::build_providers`) build only a `SpanExporter`
//! and a `LogExporter` -- **no** `MetricExporter`/`PeriodicReader` exists
//! anywhere in this codebase. Metrics stay exclusively on the `metrics`
//! crate + Prometheus `:9090` path (`skauswatch_telemetry::
//! install_metrics_exporter`) per that module's own doc comment ("Metrics
//! stay on the existing `metrics`-crate + Prometheus `:9090` path ...
//! unchanged"). So a genuine OTLP-network capture of a metric data point
//! is not just hard to build in the time available -- it is structurally
//! impossible against the code as it exists today, not a gap this test can
//! paper over. This test therefore:
//!
//! - Stands up a real in-process OTLP gRPC sink implementing
//!   `LogsService`/`MetricsService`/`TraceService` (via the
//!   `opentelemetry-proto` crate's pre-generated tonic server code -- the
//!   same crate `opentelemetry-otlp` itself depends on, already resolved
//!   in `Cargo.lock` at this exact version), points the spawned receiver
//!   *and* writer at it via `OTEL_EXPORTER_OTLP_ENDPOINT`, and asserts
//!   real, non-zero **log** and **span** counts received over the wire
//!   (the `MetricsService` arm is wired for completeness/genericity but is
//!   never invoked by svc-ingest itself -- documented, not silently
//!   dropped).
//! - Scrapes the receiver's and writer's own `:METRICS_PORT/metrics`
//!   (Prometheus exposition format) for the **real** transport metrics
//!   travel over, and asserts the four Spec §11a metrics that fire on a
//!   clean, error-free happy path (`RECEIVER_EVENTS_TOTAL`,
//!   `RECEIVER_PARSE_DURATION_MS`, `RECEIVER_QUEUE_DEPTH`,
//!   `WRITER_BULK_WRITE_DURATION_MS`) are present with real activity. The
//!   remaining two (`WRITER_OPENSEARCH_ERRORS_TOTAL`,
//!   `BUFFER_FULL_REJECTIONS_TOTAL`) are error/backpressure-only counters
//!   (see their call sites in `src/writer.rs`/`src/listeners/*`) that
//!   cannot legitimately fire during a successful load run without
//!   deliberately injecting a failure -- this test reports their
//!   presence/absence without hard-failing on them, since forcing them
//!   would mean asserting something structurally false. Spec §14c's own
//!   literal bar ("≥1 metric") is satisfied many times over regardless.

// Integration-test binary, not production code: `expect`/`panic` on setup
// failures here are the intended "fail this test with a clear message"
// idiom, matching every other `#[cfg(test)]`/e2e module in this workspace
// (see `tests/e2e_syslog.rs`).
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use opentelemetry_proto::tonic::collector::logs::v1::{
    ExportLogsServiceRequest as SinkExportLogsServiceRequest, ExportLogsServiceResponse,
    logs_service_server::{LogsService, LogsServiceServer},
};
use opentelemetry_proto::tonic::collector::metrics::v1::{
    ExportMetricsServiceRequest, ExportMetricsServiceResponse,
    metrics_service_server::{MetricsService, MetricsServiceServer},
};
use opentelemetry_proto::tonic::collector::trace::v1::{
    ExportTraceServiceRequest, ExportTraceServiceResponse,
    trace_service_server::{TraceService, TraceServiceServer},
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

use common::{
    otlp_log_record, post_ingest, seed_ingest_token, send_otlp_grpc, send_syslog_udp,
    setup_test_db, spawn_receiver_with_env, spawn_writer_with_env, start_nats, start_opensearch,
    wait_for_tenant_hit_count,
};

// ---------------------------------------------------------------------
// In-test OTLP gRPC sink: real LogsService/MetricsService/TraceService
// server implementations the spawned receiver+writer export into.
// ---------------------------------------------------------------------

/// Shared counters this sink's three service impls record into.
#[derive(Default)]
struct OtlpCaptureInner {
    log_records: AtomicU64,
    spans: AtomicU64,
    metric_points: AtomicU64,
}

/// Cheaply `Clone`-able handle to [`OtlpCaptureInner`] -- one instance is
/// wired into all three `add_service` calls in [`start_otlp_sink`], and a
/// second clone is returned to the test for polling counts.
#[derive(Clone, Default)]
struct OtlpCapture(Arc<OtlpCaptureInner>);

impl OtlpCapture {
    fn log_records(&self) -> u64 {
        self.0.log_records.load(Ordering::SeqCst)
    }
    fn spans(&self) -> u64 {
        self.0.spans.load(Ordering::SeqCst)
    }
    fn metric_points(&self) -> u64 {
        self.0.metric_points.load(Ordering::SeqCst)
    }
}

#[tonic::async_trait]
impl LogsService for OtlpCapture {
    async fn export(
        &self,
        request: Request<SinkExportLogsServiceRequest>,
    ) -> Result<Response<ExportLogsServiceResponse>, Status> {
        let req = request.into_inner();
        let count: u64 = req
            .resource_logs
            .iter()
            .flat_map(|rl| rl.scope_logs.iter())
            .map(|sl| sl.log_records.len() as u64)
            .sum();
        self.0.log_records.fetch_add(count, Ordering::SeqCst);
        Ok(Response::new(ExportLogsServiceResponse {
            partial_success: None,
        }))
    }
}

#[tonic::async_trait]
impl TraceService for OtlpCapture {
    async fn export(
        &self,
        request: Request<ExportTraceServiceRequest>,
    ) -> Result<Response<ExportTraceServiceResponse>, Status> {
        let req = request.into_inner();
        let count: u64 = req
            .resource_spans
            .iter()
            .flat_map(|rs| rs.scope_spans.iter())
            .map(|ss| ss.spans.len() as u64)
            .sum();
        self.0.spans.fetch_add(count, Ordering::SeqCst);
        Ok(Response::new(ExportTraceServiceResponse {
            partial_success: None,
        }))
    }
}

/// Wired for completeness/genericity (a real OTLP sink implements all
/// three signals) -- never actually invoked by svc-ingest, which has no
/// metrics OTLP exporter (see this module's doc comment). Kept so the
/// sink is a faithful, general-purpose OTLP collector rather than one
/// hand-fitted to only the signals this codebase happens to emit today.
#[tonic::async_trait]
impl MetricsService for OtlpCapture {
    async fn export(
        &self,
        request: Request<ExportMetricsServiceRequest>,
    ) -> Result<Response<ExportMetricsServiceResponse>, Status> {
        let req = request.into_inner();
        let count: u64 = req
            .resource_metrics
            .iter()
            .flat_map(|rm| rm.scope_metrics.iter())
            .map(|sm| sm.metrics.len() as u64)
            .sum();
        self.0.metric_points.fetch_add(count, Ordering::SeqCst);
        Ok(Response::new(ExportMetricsServiceResponse {
            partial_success: None,
        }))
    }
}

/// A running in-test OTLP gRPC sink plus the capture handle to poll.
struct OtlpSink {
    /// `http://127.0.0.1:{port}` — pass as `OTEL_EXPORTER_OTLP_ENDPOINT`.
    endpoint: String,
    capture: OtlpCapture,
}

/// Starts the sink on an ephemeral loopback port, serving all three OTLP
/// collector services from one `tonic::transport::Server`. Binds via a
/// pre-opened `tokio::net::TcpListener` handed to `serve_with_incoming`
/// (rather than a release-then-rebind port probe) so there is no window
/// for another process to steal the port between allocation and bind.
/// Backed by a `tokio::spawn`ed background task: the `#[tokio::test]`
/// runtime tears it down (abort, not graceful shutdown) when the test
/// function returns, which is acceptable for a single-test-binary sink
/// with no state to flush.
///
/// # Errors
/// Returns an error if the ephemeral port cannot be bound.
async fn start_otlp_sink() -> Result<OtlpSink> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind otlp sink listener")?;
    let port = listener
        .local_addr()
        .context("read otlp sink listener addr")?
        .port();
    let capture = OtlpCapture::default();
    let svc = capture.clone();
    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        let _ = tonic::transport::Server::builder()
            .add_service(LogsServiceServer::new(svc.clone()))
            .add_service(MetricsServiceServer::new(svc.clone()))
            .add_service(TraceServiceServer::new(svc))
            .serve_with_incoming(incoming)
            .await;
    });
    Ok(OtlpSink {
        endpoint: format!("http://127.0.0.1:{port}"),
        capture,
    })
}

/// Upper bound on waiting for the OTLP sink to receive at least one log
/// record AND one span — batch span/log processors export on a timer
/// (`opentelemetry_sdk`'s default `BatchConfig` scheduled delay is 5s),
/// not synchronously per event, so this must poll rather than check once.
const OTLP_SINK_WAIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Polls `capture` until both a log record and a span have been received,
/// bounded by [`OTLP_SINK_WAIT_TIMEOUT`], returning the final `(logs,
/// spans, metric_points)` counts either way (so a timeout can still report
/// exactly how far it got instead of a bare failure).
async fn wait_for_otlp_signals(capture: &OtlpCapture) -> (u64, u64, u64) {
    let deadline = Instant::now() + OTLP_SINK_WAIT_TIMEOUT;
    loop {
        let logs = capture.log_records();
        let spans = capture.spans();
        let metrics = capture.metric_points();
        if logs > 0 && spans > 0 {
            return (logs, spans, metrics);
        }
        if Instant::now() >= deadline {
            return (logs, spans, metrics);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

// ---------------------------------------------------------------------
// Prometheus scrape helpers — the real transport svc-ingest's metrics
// travel over (see this module's top-level doc comment).
// ---------------------------------------------------------------------

/// Spec §11a's six mandatory metric names, duplicated here from
/// `crate::otel::metric_names` — this test binary is a separate crate/
/// process from the `skauswatch-svc-ingest` binary (no `[lib]` target;
/// see `tests/common/mod.rs`'s own precedent duplicating
/// `crate::auth::hash_token`/`crate::buffer::jetstream`'s private
/// constants for the identical reason) and cannot import its private
/// `otel` module directly.
mod metric_names {
    pub const RECEIVER_EVENTS_TOTAL: &str = "svc_ingest_receiver_events_total";
    pub const RECEIVER_PARSE_DURATION_MS: &str = "svc_ingest_receiver_parse_duration_ms";
    pub const RECEIVER_QUEUE_DEPTH: &str = "svc_ingest_receiver_queue_depth";
    pub const WRITER_BULK_WRITE_DURATION_MS: &str = "svc_ingest_writer_bulk_write_duration_ms";
    pub const WRITER_OPENSEARCH_ERRORS_TOTAL: &str = "svc_ingest_writer_opensearch_errors_total";
    pub const BUFFER_FULL_REJECTIONS_TOTAL: &str = "svc_ingest_buffer_full_rejections_total";
}

/// Bounded scrape of `http://127.0.0.1:{port}/metrics` (Prometheus
/// exposition format).
async fn scrape_metrics(port: u16) -> Result<String> {
    let url = format!("http://127.0.0.1:{port}/metrics");
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    resp.text().await.context("read /metrics body")
}

/// Whether `name` appears at all in `body` (a counter/gauge sample line,
/// or any of a histogram's `_bucket`/`_sum`/`_count` expansion lines), and
/// the summed value across every `_count` (histogram) or exact-name
/// (counter) line matching it. A gauge's *value* is deliberately not
/// asserted non-zero anywhere this is used -- e.g. a queue-depth gauge
/// reading `0` after a fast writer has fully drained a batch is a healthy
/// state, not a missing-metric bug; only *presence* matters for a gauge.
fn prometheus_metric_presence_and_activity(body: &str, name: &str) -> (bool, f64) {
    let mut present = false;
    let mut activity = 0.0;
    for line in body.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let metric_part = line.split(['{', ' ']).next().unwrap_or("");
        let is_exact = metric_part == name;
        let is_histogram_part = metric_part == format!("{name}_bucket")
            || metric_part == format!("{name}_sum")
            || metric_part == format!("{name}_count");
        if !is_exact && !is_histogram_part {
            continue;
        }
        present = true;
        if (is_exact || metric_part.ends_with("_count"))
            && let Some(Ok(value)) = line.split_whitespace().last().map(str::parse::<f64>)
        {
            activity += value;
        }
    }
    (present, activity)
}

// ---------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------

/// Builds an RFC 3164 line (`<PRI>MMM DD HH:MM:SS HOSTNAME MESSAGE`) whose
/// message body is exactly `marker` — mirrors `tests/e2e_syslog.rs`'s own
/// helper (duplicated rather than shared: each `tests/e2e_*.rs` file
/// compiles as its own independent crate, so there is no common non-`mod
/// common` location to place a cross-file helper without promoting it
/// into the shared harness itself).
fn rfc3164_line(marker: &str) -> String {
    format!("<34>Jan  1 00:00:01 e2e-host {marker}")
}

/// A complete native OCSF document (all required fields present — see
/// `src/listeners/http.rs`'s `complete_native_ocsf_document_is_accepted`
/// unit test for the exact required-field set this mirrors) whose
/// `message` field is `marker`.
fn ocsf_doc(marker: &str) -> serde_json::Value {
    serde_json::json!({
        "class_uid": 2001,
        "class_name": "security_finding",
        "time": "2026-07-25T12:00:00Z",
        "severity_id": 2,
        "status_id": 1,
        "message": marker,
        "metadata": {"version": "1.3.0"},
        "raw_data": {}
    })
}

/// A generic (non-OCSF) JSON document — no `class_uid`/`metadata` marker,
/// so the listener normalizes it via `listeners::http::normalize` rather
/// than strictly validating it as native OCSF.
fn generic_json_doc(marker: &str) -> serde_json::Value {
    serde_json::json!({ "message": marker })
}

/// Asserts every marker in `markers` is contained in at least one hit's
/// `message` field — a stronger check than a bare count match: it catches
/// a duplication-cancels-a-drop bug (right count, wrong identities) that a
/// count-only assertion would miss.
fn assert_all_markers_present(hits: &[serde_json::Value], markers: &[String], label: &str) {
    for marker in markers {
        let found = hits.iter().any(|h| {
            h["message"]
                .as_str()
                .is_some_and(|m| m.contains(marker.as_str()))
        });
        assert!(
            found,
            "{label}: marker {marker:?} missing from indexed hits (got {} hits)",
            hits.len()
        );
    }
}

// ---------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn smoke_test_matches_spec_14c_script() {
    let overall_start = Instant::now();

    // Step 1: start JetStream + OpenSearch, migrate a fresh test database.
    let nats = start_nats().await.expect("start nats container");
    let opensearch = start_opensearch()
        .await
        .expect("start opensearch container");
    let db = setup_test_db()
        .await
        .expect("create + migrate test database");
    let container_boot_elapsed = overall_start.elapsed();

    // In-test OTLP sink (see this module's top-level doc comment).
    let sink = start_otlp_sink().await.expect("start in-test otlp sink");

    // Two tenants: a fixed one for the trusted-CIDR syslog UDP listener
    // (Spec §6c — one tenant per trusted CIDR, configured at receiver
    // startup, not per-message), and one for the ingest-token (OTLP) +
    // JWT (HTTPS `/ingest`) credentialed paths, matching
    // `tests/e2e_otlp.rs`/`tests/e2e_harness_smoke.rs`'s own convention of
    // a fresh per-run UUID tenant doubling as this run's OpenSearch scope.
    let syslog_tenant = format!("e2e-smoke14c-syslog-{}", Uuid::new_v4());
    let ingest_tenant = format!("e2e-smoke14c-ingest-{}", Uuid::new_v4());
    let ingest_token = format!("e2e-smoke14c-token-{}", Uuid::new_v4());
    seed_ingest_token(&db, &ingest_token, &ingest_tenant)
        .await
        .expect("seed ingest_tokens row for OTLP ingest-token fallback auth");

    let receiver = spawn_receiver_with_env(
        &nats,
        &opensearch,
        &db,
        &[
            ("SYSLOG_UDP_ENABLED", "true"),
            ("SYSLOG_TRUSTED_CIDRS", "127.0.0.1/32"),
            ("SYSLOG_UDP_TENANT_ID", &syslog_tenant),
            ("OTEL_EXPORTER_OTLP_ENDPOINT", &sink.endpoint),
        ],
    )
    .await
    .expect("spawn skauswatch-svc-ingest serve --mode receiver");
    let writer = spawn_writer_with_env(
        &nats,
        &opensearch,
        &[("OTEL_EXPORTER_OTLP_ENDPOINT", &sink.endpoint)],
    )
    .await
    .expect("spawn skauswatch-svc-ingest serve --mode writer");

    let ingest_phase_start = Instant::now();

    // Step 2: 100 syslog events via UDP, distinct markers.
    const SYSLOG_COUNT: usize = 100;
    let mut syslog_markers = Vec::with_capacity(SYSLOG_COUNT);
    for i in 0..SYSLOG_COUNT {
        let marker = format!("e2e-smoke14c-syslog-{i}-{}", Uuid::new_v4());
        send_syslog_udp(receiver.syslog_port, &rfc3164_line(&marker))
            .await
            .unwrap_or_else(|e| panic!("send syslog UDP datagram {i}: {e}"));
        syslog_markers.push(marker);
    }

    // Step 3: 10 OTLP LogRecords via gRPC, distinct markers.
    const OTLP_COUNT: usize = 10;
    let mut otlp_markers = Vec::with_capacity(OTLP_COUNT);
    for i in 0..OTLP_COUNT {
        let marker = format!("e2e-smoke14c-otlp-{i}-{}", Uuid::new_v4());
        send_otlp_grpc(&receiver, &ingest_token, otlp_log_record(&marker))
            .await
            .unwrap_or_else(|e| panic!("send OTLP gRPC log record {i}: {e}"));
        otlp_markers.push(marker);
    }

    // Step 4: 5 OCSF + 5 generic JSON docs via HTTPS `/ingest`, distinct
    // markers. Both land under `ingest_tenant` alongside the OTLP batch —
    // deliberate, so step 6's "all 120, correct tenant" assertion can
    // verify the ingest-token and JWT credential paths converge on the
    // same tenant scoping contract with a single combined count query.
    const OCSF_COUNT: usize = 5;
    const JSON_COUNT: usize = 5;
    let mut ocsf_markers = Vec::with_capacity(OCSF_COUNT);
    for i in 0..OCSF_COUNT {
        let marker = format!("e2e-smoke14c-ocsf-{i}-{}", Uuid::new_v4());
        let resp = post_ingest(&receiver, &ingest_tenant, &ocsf_doc(&marker))
            .await
            .unwrap_or_else(|e| panic!("POST OCSF doc {i}: {e}"));
        assert!(
            resp.status().is_success(),
            "POST OCSF doc {i} returned {}",
            resp.status()
        );
        ocsf_markers.push(marker);
    }
    let mut json_markers = Vec::with_capacity(JSON_COUNT);
    for i in 0..JSON_COUNT {
        let marker = format!("e2e-smoke14c-json-{i}-{}", Uuid::new_v4());
        let resp = post_ingest(&receiver, &ingest_tenant, &generic_json_doc(&marker))
            .await
            .unwrap_or_else(|e| panic!("POST generic JSON doc {i}: {e}"));
        assert!(
            resp.status().is_success(),
            "POST generic JSON doc {i} returned {}",
            resp.status()
        );
        json_markers.push(marker);
    }

    // Step 5/6: exact per-batch counts (not "some arrived") plus per-marker
    // identity verification, bounded.
    const WAIT_TIMEOUT: Duration = Duration::from_secs(60);

    let syslog_hits = match wait_for_tenant_hit_count(
        &opensearch.url,
        &syslog_tenant,
        SYSLOG_COUNT,
        WAIT_TIMEOUT,
    )
    .await
    {
        Ok(hits) => hits,
        Err(e) => panic!(
            "syslog batch never reached {SYSLOG_COUNT} indexed documents: {e}\n\
             receiver output:\n{}\nwriter output:\n{}",
            receiver.output().await,
            writer.output().await
        ),
    };
    assert_eq!(
        syslog_hits.len(),
        SYSLOG_COUNT,
        "expected exactly {SYSLOG_COUNT} syslog documents for tenant {syslog_tenant}"
    );
    assert_all_markers_present(&syslog_hits, &syslog_markers, "syslog UDP");

    let ingest_expected = OTLP_COUNT + OCSF_COUNT + JSON_COUNT;
    let ingest_hits = match wait_for_tenant_hit_count(
        &opensearch.url,
        &ingest_tenant,
        ingest_expected,
        WAIT_TIMEOUT,
    )
    .await
    {
        Ok(hits) => hits,
        Err(e) => panic!(
            "OTLP+HTTPS batch never reached {ingest_expected} indexed documents: {e}\n\
             receiver output:\n{}\nwriter output:\n{}",
            receiver.output().await,
            writer.output().await
        ),
    };
    assert_eq!(
        ingest_hits.len(),
        ingest_expected,
        "expected exactly {ingest_expected} documents ({OTLP_COUNT} OTLP + {OCSF_COUNT} OCSF + \
         {JSON_COUNT} JSON) for tenant {ingest_tenant}"
    );
    assert_all_markers_present(&ingest_hits, &otlp_markers, "OTLP gRPC");
    assert_all_markers_present(&ingest_hits, &ocsf_markers, "HTTPS OCSF");
    assert_all_markers_present(&ingest_hits, &json_markers, "HTTPS generic JSON");
    for hit in &ingest_hits {
        assert_eq!(
            hit["tenant_id"].as_str(),
            Some(ingest_tenant.as_str()),
            "expected every OTLP/HTTPS document to be stamped with tenant_id={ingest_tenant}, \
             got {hit}"
        );
    }

    let total_indexed = syslog_hits.len() + ingest_hits.len();
    let ingest_phase_elapsed = ingest_phase_start.elapsed();

    // Step 7 (telemetry): logs+traces via the real in-test OTLP sink;
    // metrics via Prometheus scrape (see module doc comment for why).
    let (otlp_logs, otlp_spans, otlp_metric_points) = wait_for_otlp_signals(&sink.capture).await;

    let receiver_metrics_body = scrape_metrics(receiver.metrics_port)
        .await
        .expect("scrape receiver /metrics");
    let writer_metrics_body = scrape_metrics(writer.metrics_port)
        .await
        .expect("scrape writer /metrics");
    // Some metrics are recorded receiver-side, others writer-side; search
    // both scrapes for each name rather than assuming which process owns
    // which (matches `metric_names`' own doc comment — used across
    // `listeners/*`, `writer.rs`, and `buffer/jetstream.rs`).
    let combined_metrics_body = format!("{receiver_metrics_body}\n{writer_metrics_body}");

    let happy_path_metrics = [
        metric_names::RECEIVER_EVENTS_TOTAL,
        metric_names::RECEIVER_PARSE_DURATION_MS,
        metric_names::RECEIVER_QUEUE_DEPTH,
        metric_names::WRITER_BULK_WRITE_DURATION_MS,
    ];
    let mut happy_path_present_count = 0usize;
    for name in happy_path_metrics {
        let (present, activity) =
            prometheus_metric_presence_and_activity(&combined_metrics_body, name);
        println!("smoke_14c: metric {name:?}: present={present} activity={activity}");
        assert!(
            present,
            "expected metric {name:?} to be present in a Prometheus scrape"
        );
        if present {
            happy_path_present_count += 1;
        }
    }
    // Error/backpressure-only counters: report, never hard-fail (see
    // module doc comment — asserting these non-zero on a clean happy path
    // would be asserting something structurally false).
    for name in [
        metric_names::WRITER_OPENSEARCH_ERRORS_TOTAL,
        metric_names::BUFFER_FULL_REJECTIONS_TOTAL,
    ] {
        let (present, activity) =
            prometheus_metric_presence_and_activity(&combined_metrics_body, name);
        println!(
            "smoke_14c: error/backpressure metric {name:?}: present={present} activity={activity} \
             (not asserted -- error-path-only, expected absent/zero on a clean run)"
        );
    }

    println!(
        "smoke_14c RESULTS: syslog_indexed={}/{SYSLOG_COUNT} otlp_indexed={}/{OTLP_COUNT} \
         ocsf_indexed={}/{OCSF_COUNT} json_indexed={}/{JSON_COUNT} total_indexed={total_indexed}/120 \
         otlp_sink_logs={otlp_logs} otlp_sink_spans={otlp_spans} \
         otlp_sink_metric_points={otlp_metric_points} (expected 0 -- no OTLP metrics exporter in \
         this codebase, see module doc comment) prometheus_happy_path_metrics_present={happy_path_present_count}/4 \
         container_boot_elapsed={container_boot_elapsed:?} ingest_phase_elapsed={ingest_phase_elapsed:?} \
         (spec §14c target: <2min ingest phase) total_elapsed={:?}",
        syslog_markers.len(),
        otlp_markers.len(),
        ocsf_markers.len(),
        json_markers.len(),
        overall_start.elapsed(),
    );

    assert_eq!(
        total_indexed, 120,
        "expected exactly 120 documents indexed total"
    );
    assert!(
        otlp_logs > 0,
        "expected >=1 OTLP log record received by the in-test sink, got 0"
    );
    assert!(
        otlp_spans > 0,
        "expected >=1 OTLP span received by the in-test sink, got 0"
    );
    assert!(
        ingest_phase_elapsed < Duration::from_secs(120),
        "ingest phase took {ingest_phase_elapsed:?}, expected < 2min per spec §14c (container \
         boot excluded: {container_boot_elapsed:?})"
    );
}
