//! Writer-mode entry point: drains the JetStream consumer, bulk-writes to
//! OpenSearch, and acks/DLQs on failure (Spec §7-8,
//! `docs/v2-port/ingest-module-spec.md`). [`run`] is the Wave-1 integration
//! point `main.rs::serve()` calls for `RunMode::Writer` — see this module's
//! items for the consume → bulk-write → ack/nack/DLQ loop itself.
//!
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use skauswatch_ocsf::JsonVal;
use tracing::Instrument as _;

use crate::buffer::{DeliveredEvent, EventBuffer, JetStreamBuffer, NormalizedEvent};
use crate::config::Config;
use crate::opensearch;

/// Batch size pulled per `consume()` call (Spec §7a `NATS_CONSUMER_PREFETCH`
/// config example — "writer drains in batches (e.g., 100 msgs at a time,
/// then acks)").
pub const NATS_CONSUMER_PREFETCH: usize = 100;

/// Consecutive bulk-write failures for the same event before it is routed
/// to the dead-letter sink instead of nacked for another JetStream
/// redelivery attempt (Spec §7c "if OpenSearch bulk-write fails
/// repeatedly ... events ... are moved to a separate ... dlq stream").
/// Paired with [`backoff_for`]'s doubling delay so a transient blip
/// retries quickly while a sustained outage backs off between attempts
/// instead of hot-looping against a downed OpenSearch. Compared against
/// [`effective_failure_count`], not a raw process-local counter, so the
/// threshold survives a writer restart.
pub const DLQ_FAILURE_THRESHOLD: u32 = 5;

/// Subject prefix for the dead-letter sink's own JetStream stream. See
/// [`build_dlq_buffer`]'s doc comment for why this is deliberately NOT
/// nested under the ingest subject prefix (`svc-ingest.logs`, Spec §7a) —
/// [`subject_prefixes_collide`] enforces the disjointness at startup.
const DLQ_SUBJECT_PREFIX: &str = "svc-ingest-dlq";

/// Sleep between `consume()` polls that return no events, so a buffer that
/// returns immediately when empty (the in-memory fallback; a live
/// JetStream pull consumer already paces itself via its own `fetch`
/// expiry) doesn't spin the loop at 100% CPU.
const IDLE_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Backoff before nacking a failed batch, given the number of consecutive
/// failures already recorded for it — doubles per attempt (capped at
/// 500ms), so retries space out instead of hot-looping against a downed
/// OpenSearch. Exact calibration to the Spec's illustrative "cluster down
/// for >10 min" DLQ trigger is an operational/deployment tuning concern
/// (backoff schedule × [`DLQ_FAILURE_THRESHOLD`]), not a literal formula
/// hardcoded here — `Config` has no dedicated knob for either yet (frozen
/// for this task; see the Wave 1 file-scope note), so both constants are
/// conservative defaults an operator can promote to config later.
fn backoff_for(consecutive_failures: u32) -> Duration {
    let exponent = consecutive_failures.saturating_sub(1).min(10);
    let millis = 20u64.saturating_mul(1u64 << exponent);
    Duration::from_millis(millis).min(Duration::from_millis(500))
}

/// Combines a message's server-tracked JetStream delivery count (when
/// available — see `crate::buffer::AckHandle::delivery_count`) with the
/// process-local consecutive-failure counter (the only signal for the
/// in-memory fallback, which has no server-side delivery tracking). The
/// JetStream count wins outright when present: it is authoritative and,
/// unlike a counter held in this process's memory, it survives a writer
/// restart — Spec §7c's DLQ threshold must not reset to zero just because
/// the writer process happened to restart mid-outage (the exact failure
/// mode a process-local-only counter reintroduces: an event surviving
/// restarts would nack forever and never reach the DLQ).
fn effective_failure_count(delivery_count: Option<u64>, local_count: u32) -> u32 {
    match delivery_count {
        Some(n) => u32::try_from(n).unwrap_or(u32::MAX),
        None => local_count,
    }
}

/// Whether two JetStream stream subject prefixes — each expanded to the
/// wildcard `{prefix}.>` by [`JetStreamBuffer`] — would collide, one
/// capturing messages meant for the other. True when one prefix's
/// dot-separated tokens are a prefix of the other's (including exact
/// equality), the case a `{prefix}.>` wildcard cannot distinguish between.
fn subject_prefixes_collide(a: &str, b: &str) -> bool {
    let a_tokens: Vec<&str> = a.split('.').collect();
    let b_tokens: Vec<&str> = b.split('.').collect();
    let shorter_len = a_tokens.len().min(b_tokens.len());
    a_tokens[..shorter_len] == b_tokens[..shorter_len]
}

/// Stamps `tenant` onto `doc` as a top-level `tenant_id` field — mirrors
/// `services/logs/src/ingest.rs`'s `stamp_tenant`. `tenant` always comes
/// from `NormalizedEvent.tenant` (the buffer's own header-derived,
/// server-validated value — see
/// `buffer::jetstream::normalized_event_from_message`), never read back out
/// of the document body itself (the house tenant-isolation rule).
///
/// Overwrites an existing top-level `tenant_id` entry in place instead of
/// unconditionally appending a second one (production bug, Task 3.0c):
/// `JsonVal::Obj` is an insertion-ordered `Vec<(String, JsonVal)>` with no
/// key-uniqueness invariant of its own (unlike a `HashMap`), and the HTTP
/// `/ingest` listener already stamps its own top-level `tenant_id` before
/// enqueuing, for its own independent tenant-spoofing-resistance reasons
/// (see `listeners::http::stamp_tenant`) — so by the time this function
/// runs, `doc` may already carry one. Appending unconditionally produced a
/// genuinely duplicate `"tenant_id"` key in the JSON sent to OpenSearch's
/// `_bulk` API, which its strict parser rejects outright
/// (`mapper_parsing_exception` / `caused_by.json_parse_exception:
/// "Duplicate field 'tenant_id'"`) — every single HTTP-sourced document
/// failed every bulk write for exactly this reason, permanently (the
/// per-item error never resolves on retry, so the event eventually DLQs).
/// `tenant` here is always the same authoritative, JWT/header-derived
/// value regardless of which listener already stamped one, so overwriting
/// in place is always safe — never a downgrade of the tenant-isolation
/// guarantee.
fn stamp_tenant(doc: &mut JsonVal, tenant: &str) {
    if let JsonVal::Obj(entries) = doc {
        if let Some(existing) = entries.iter_mut().find(|(k, _)| k == "tenant_id") {
            existing.1 = JsonVal::Str(tenant.to_owned());
        } else {
            entries.push(("tenant_id".to_owned(), JsonVal::Str(tenant.to_owned())));
        }
    }
}

/// Pairs each delivered event's `dedup_key` (used as the OpenSearch `_id` —
/// see `opensearch::build_bulk_body_with_ids`) with its document, stamped
/// with the event's tenant. Borrows `delivered` so the caller can still
/// consume each entry's `handle` afterward.
fn docs_with_ids(delivered: &[DeliveredEvent]) -> Vec<(String, JsonVal)> {
    delivered
        .iter()
        .map(|d| {
            let mut doc = d.event.doc.clone();
            stamp_tenant(&mut doc, d.event.tenant.as_str());
            (d.event.dedup_key.clone(), doc)
        })
        .collect()
}

/// Wraps a permanently-failing event for the dead-letter sink, flagged
/// with a timestamp and the error reason (Spec §7c: DLQ'd events are
/// "never silently discarded ... flagged with a timestamp and the error
/// reason").
fn dlq_envelope(event: &NormalizedEvent, reason: &str, now: DateTime<Utc>) -> JsonVal {
    JsonVal::Obj(vec![
        (
            "tenant_id".to_owned(),
            JsonVal::Str(event.tenant.as_str().to_owned()),
        ),
        (
            "dedup_key".to_owned(),
            JsonVal::Str(event.dedup_key.clone()),
        ),
        ("dlq_reason".to_owned(), JsonVal::Str(reason.to_owned())),
        ("dlq_timestamp".to_owned(), JsonVal::Str(now.to_rfc3339())),
        ("original_event".to_owned(), event.doc.clone()),
    ])
}

/// Pushes `event` onto `dlq`, wrapped by [`dlq_envelope`]. Returns whether
/// the push succeeded — Spec §7c requires DLQ'd events are "never
/// silently discarded". If OpenSearch AND the dead-letter sink are both
/// unreachable, the caller (`handle_failed_batch`) must NOT ack the
/// original handle off the main stream on a failed push — that would lose
/// the event for good; it nacks instead, so JetStream keeps redelivering
/// until the DLQ sink recovers.
async fn route_to_dlq(
    dlq: &Arc<dyn EventBuffer>,
    event: &NormalizedEvent,
    reason: &str,
    now: DateTime<Utc>,
) -> bool {
    let envelope = dlq_envelope(event, reason, now);
    let dlq_event = NormalizedEvent {
        tenant: event.tenant.clone(),
        doc: envelope,
        dedup_key: event.dedup_key.clone(),
    };
    match dlq.push(dlq_event).await {
        Ok(()) => {
            tracing::warn!(
                dedup_key = %event.dedup_key,
                tenant = %event.tenant.as_str(),
                reason,
                "writer_event_routed_to_dlq"
            );
            metrics::counter!("svc_ingest_writer_events_dlq_total").increment(1);
            true
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                dedup_key = %event.dedup_key,
                "writer_dlq_push_failed"
            );
            metrics::counter!("svc_ingest_writer_dlq_push_failures_total").increment(1);
            false
        }
    }
}

/// Applies the failure-counting/backoff/DLQ-or-nack decision to a set of
/// events that failed to index — either the whole batch (a bulk-write
/// transport/status failure) or a subset of it (a 200 response with
/// per-item bulk errors — see `process_batch`). For each event: if it has
/// now failed [`DLQ_FAILURE_THRESHOLD`] times in a row
/// ([`effective_failure_count`]), route it to `dlq` and ack it off the
/// main stream ONLY if that DLQ push succeeds; otherwise (under threshold,
/// or the DLQ push itself failed) nack it for JetStream redelivery. A
/// no-op on an empty `failed`.
async fn handle_failed_batch(
    buffer: &Arc<dyn EventBuffer>,
    dlq: &Arc<dyn EventBuffer>,
    failures: &mut HashMap<String, u32>,
    failed: Vec<DeliveredEvent>,
    reason: &str,
) {
    if failed.is_empty() {
        return;
    }
    tracing::warn!(
        error = reason,
        batch_size = failed.len(),
        "writer_bulk_write_failed"
    );
    metrics::counter!("svc_ingest_writer_bulk_write_failures_total").increment(1);

    let mut to_nack = Vec::new();
    let mut max_consecutive = 0u32;
    for d in failed {
        let delivery_count = d.handle.delivery_count();
        let local_count = {
            let c = failures.entry(d.event.dedup_key.clone()).or_insert(0);
            *c += 1;
            *c
        };
        let count = effective_failure_count(delivery_count, local_count);

        if count >= DLQ_FAILURE_THRESHOLD && route_to_dlq(dlq, &d.event, reason, Utc::now()).await {
            failures.remove(&d.event.dedup_key);
            if let Err(ack_err) = buffer.ack(d.handle).await {
                tracing::error!(error = %ack_err, dedup_key = %d.event.dedup_key, "writer_dlq_ack_failed");
            }
            continue;
        }
        // Either still under threshold, or over it but the dead-letter
        // sink itself is unreachable — never ack on a failed DLQ push
        // (that would lose the event for good); fall through to nack so
        // JetStream keeps redelivering until the DLQ sink recovers. The
        // failure counter is intentionally left as-is in that case: once
        // the sink comes back, the very next failed attempt routes it
        // there immediately instead of restarting the threshold
        // countdown.
        max_consecutive = max_consecutive.max(count);
        to_nack.push(d.handle);
    }
    if !to_nack.is_empty() {
        tokio::time::sleep(backoff_for(max_consecutive)).await;
        for handle in to_nack {
            if let Err(nack_err) = buffer.nack(handle).await {
                tracing::error!(error = %nack_err, "writer_nack_failed");
            }
        }
    }
}

/// Processes exactly one delivered batch: stamps tenant onto every
/// document, computes the shared daily index (Spec's unified
/// `skauswatch-logs-YYYY.MM.DD` scheme — no per-tenant index; see the
/// Task 1.5 decision note), bulk-writes to OpenSearch with a deterministic
/// per-document `_id` derived from `dedup_key` (so a JetStream-redelivered
/// event overwrites the same document instead of duplicating it — Spec
/// §14b `writer_crash_mid_batch_causes_at_least_once_redelivery`), and
/// resolves every handle: `ack` on success, `ack` only the successfully
/// indexed subset on a 200-with-per-item-errors response, or defer the
/// rest to [`handle_failed_batch`] on any failure.
/// Wraps [`process_batch_inner`] in the `writer_consume_and_bulk_write`
/// span, reparented (when possible) to the first delivered event's
/// producer trace context (`DeliveredEvent::trace_context`, set by
/// `crate::buffer::jetstream::JetStreamBuffer::consume`'s
/// `extract_trace_context`) — propagates trace context across the
/// receiver -> NATS -> writer queue hop (`critical-rules.md`
/// Observability: "propagate trace context across every service
/// boundary ... queue hops"). A batch can carry events from many
/// distinct producer traces; OTel has no single-parent representation
/// for "N unrelated parents", so only the first event's trace is used —
/// a full fan-out would need span links to every producer trace instead
/// of a single parent, a documented simplification rather than a
/// silently-dropped requirement. `set_parent` failing (e.g. already
/// parented) is logged at DEBUG and never fails the batch — a
/// telemetry/propagation problem must never break ingest or writer
/// processing.
pub(crate) async fn process_batch(
    buffer: &Arc<dyn EventBuffer>,
    dlq: &Arc<dyn EventBuffer>,
    http: &reqwest::Client,
    opensearch_url: &str,
    delivered: Vec<DeliveredEvent>,
    failures: &mut HashMap<String, u32>,
) {
    let span = tracing::info_span!(
        "writer_consume_and_bulk_write",
        batch_size = delivered.len()
    );
    if let Some(cx) = delivered.first().and_then(|d| d.trace_context.clone()) {
        use tracing_opentelemetry::OpenTelemetrySpanExt as _;
        if let Err(e) = span.set_parent(cx) {
            tracing::debug!(
                error = %e,
                "writer span parent could not be set from the extracted trace context"
            );
        }
    }
    process_batch_inner(buffer, dlq, http, opensearch_url, delivered, failures)
        .instrument(span)
        .await;
}

/// The real batch-processing body — see [`process_batch`]'s doc comment
/// for the span/trace-context wiring wrapped around this.
async fn process_batch_inner(
    buffer: &Arc<dyn EventBuffer>,
    dlq: &Arc<dyn EventBuffer>,
    http: &reqwest::Client,
    opensearch_url: &str,
    delivered: Vec<DeliveredEvent>,
    failures: &mut HashMap<String, u32>,
) {
    let index = opensearch::daily_index(Utc::now());
    let pairs = docs_with_ids(&delivered);
    let body = opensearch::build_bulk_body_with_ids(&index, &pairs);

    let bulk_started = std::time::Instant::now();
    let bulk_result = opensearch::write_bulk(http, opensearch_url, body).await;
    metrics::histogram!(crate::otel::metric_names::WRITER_BULK_WRITE_DURATION_MS)
        .record(bulk_started.elapsed().as_secs_f64() * 1000.0);

    match bulk_result {
        Ok(outcome) if outcome.all_succeeded() => {
            metrics::counter!("svc_ingest_writer_events_written_total")
                .increment(delivered.len() as u64);
            for d in delivered {
                failures.remove(&d.event.dedup_key);
                if let Err(e) = buffer.ack(d.handle).await {
                    tracing::error!(error = %e, dedup_key = %d.event.dedup_key, "writer_ack_failed");
                }
            }
        }
        Ok(outcome) => {
            // OpenSearch returned 200 but rejected specific documents
            // (Spec §14b fix: a status-code-only check would silently ack
            // these away as if they had been written). Surface exactly
            // *why* each one was rejected (index/error type/reason) via
            // `tracing::error!` — previously the batch-level WARN below
            // only said "opensearch bulk response reported per-item
            // errors" with no indication of the actual cause (e.g. a
            // dynamic-mapping conflict on a specific OCSF field).
            for item_err in &outcome.item_errors {
                tracing::error!(
                    id = %item_err.id,
                    index = item_err.index.as_deref().unwrap_or("?"),
                    error_type = item_err.error_type.as_deref().unwrap_or("?"),
                    reason = item_err.reason.as_deref().unwrap_or("?"),
                    "opensearch_bulk_item_rejected"
                );
                metrics::counter!(
                    crate::otel::metric_names::WRITER_OPENSEARCH_ERRORS_TOTAL,
                    "error_code" => item_err.error_type.clone().unwrap_or_else(|| "unknown".to_owned())
                )
                .increment(1);
            }
            let failed_ids: HashSet<&str> = outcome.failed_ids.iter().map(String::as_str).collect();
            let (failed, succeeded): (Vec<_>, Vec<_>) = delivered
                .into_iter()
                .partition(|d| failed_ids.contains(d.event.dedup_key.as_str()));
            metrics::counter!("svc_ingest_writer_events_written_total")
                .increment(succeeded.len() as u64);
            for d in succeeded {
                failures.remove(&d.event.dedup_key);
                if let Err(e) = buffer.ack(d.handle).await {
                    tracing::error!(error = %e, dedup_key = %d.event.dedup_key, "writer_ack_failed");
                }
            }
            let reason = if outcome.item_errors.is_empty() {
                "opensearch bulk response reported per-item errors".to_owned()
            } else {
                let details = outcome
                    .item_errors
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                format!("opensearch bulk response reported per-item errors: {details}")
            };
            handle_failed_batch(buffer, dlq, failures, failed, &reason).await;
        }
        Err(e) => {
            let error_code = e
                .status()
                .map_or_else(|| "transport".to_owned(), |s| s.as_u16().to_string());
            metrics::counter!(
                crate::otel::metric_names::WRITER_OPENSEARCH_ERRORS_TOTAL,
                "error_code" => error_code
            )
            .increment(1);
            handle_failed_batch(buffer, dlq, failures, delivered, &e.to_string()).await;
        }
    }
}

/// The consume → process → (repeat) loop itself, parameterized over the
/// dead-letter sink so tests can supply an in-process fake instead of a
/// live NATS connection (see [`run`], which builds the real one). Never
/// resolves under normal operation — a `consume()` transport error is
/// logged and retried after a short pause rather than ending the loop, so
/// a brief NATS blip doesn't take the whole writer process down.
async fn run_loop(
    cfg: &Config,
    buffer: Arc<dyn EventBuffer>,
    dlq: Arc<dyn EventBuffer>,
    http: reqwest::Client,
) -> anyhow::Result<()> {
    let mut failures: HashMap<String, u32> = HashMap::new();
    loop {
        let delivered = match buffer.consume(NATS_CONSUMER_PREFETCH).await {
            Ok(batch) => batch,
            Err(e) => {
                tracing::error!(error = %e, "writer_consume_failed");
                tokio::time::sleep(IDLE_POLL_INTERVAL).await;
                continue;
            }
        };
        if delivered.is_empty() {
            tokio::time::sleep(IDLE_POLL_INTERVAL).await;
            continue;
        }
        process_batch(
            &buffer,
            &dlq,
            &http,
            &cfg.opensearch_url,
            delivered,
            &mut failures,
        )
        .await;
    }
}

/// Builds the dead-letter sink `run` routes permanently-failing events to
/// (Spec §7c "moved to a separate ... dlq stream"). Opens a fresh,
/// independent JetStream connection rather than reusing `run`'s `buffer`
/// parameter: [`JetStreamBuffer`]'s stream is created with the multi-token
/// wildcard subject `{subject_prefix}.>` (see
/// `buffer::jetstream::JetStreamBuffer::consumer`), so publishing a
/// literal `{subject_prefix}.dlq` message through the *same* buffer would
/// land in the *same* stream as ordinary tenant traffic — the writer's own
/// pull consumer would eventually redeliver its own dead-lettered events
/// back to itself, exactly the "endlessly nacking" failure mode the DLQ
/// exists to escape. [`subject_prefixes_collide`] enforces at startup that
/// [`DLQ_SUBJECT_PREFIX`] is genuinely disjoint from `cfg`'s ingest
/// subject prefix, so a misconfiguration cannot silently reintroduce that
/// loop.
///
/// # Errors
/// Returns an error if [`DLQ_SUBJECT_PREFIX`] collides with `cfg`'s
/// ingest subject prefix, the NATS connection cannot be established, the
/// dead-letter buffer fails to construct, or its backing JetStream stream
/// cannot be provisioned (see [`JetStreamBuffer::ensure_stream`]).
async fn build_dlq_buffer(cfg: &Config) -> anyhow::Result<Arc<dyn EventBuffer>> {
    if subject_prefixes_collide(DLQ_SUBJECT_PREFIX, &cfg.nats_jetstream_subject_prefix) {
        anyhow::bail!(
            "DLQ subject prefix {DLQ_SUBJECT_PREFIX:?} collides with the ingest subject prefix \
             {:?} — a JetStream stream subject wildcard ({{prefix}}.>) would capture both, \
             letting the writer redeliver its own dead-lettered events to itself; refusing to \
             start",
            cfg.nats_jetstream_subject_prefix
        );
    }
    let client = async_nats::connect(&cfg.nats_url)
        .await
        .map_err(|e| anyhow::anyhow!("dlq nats connect: {e}"))?;
    let context = async_nats::jetstream::new(client);
    let dlq = JetStreamBuffer::new(context, DLQ_SUBJECT_PREFIX)
        .map_err(|e| anyhow::anyhow!("dlq buffer init: {e}"))?;
    // The DLQ buffer is push-only — nothing ever calls `consume()` on it
    // (see `JetStreamBuffer::ensure_stream`'s doc comment), so unlike the
    // main ingest buffer its stream is never created as a side effect of
    // the writer's own loop. Provision it explicitly here, before the
    // buffer is ever handed to `route_to_dlq`, or every dead-letter push
    // would fail with "no stream found for given subject".
    dlq.ensure_stream()
        .await
        .map_err(|e| anyhow::anyhow!("dlq stream provisioning: {e}"))?;
    Ok(Arc::new(dlq))
}

/// Runs the writer loop until shutdown — drains the JetStream consumer in
/// batches ([`NATS_CONSUMER_PREFETCH`]), bulk-writes to OpenSearch with a
/// deterministic per-document id, acks each event only after a successful
/// write, and nacks (JetStream at-least-once redelivery) on failure —
/// after [`DLQ_FAILURE_THRESHOLD`] consecutive failures for the same event
/// it is routed to the dead-letter sink instead of nacked again (Spec
/// §7c). See [`run_loop`] for the loop body and [`build_dlq_buffer`] for
/// why the dead-letter sink is a separate connection.
///
/// # Errors
/// Returns an error if the dead-letter sink cannot be constructed (e.g.
/// the configured NATS server is unreachable, or its subject prefix
/// collides with the ingest prefix) — the loop itself does not otherwise
/// return under normal operation.
pub async fn run(
    cfg: &Config,
    buffer: Arc<dyn EventBuffer>,
    http: reqwest::Client,
) -> anyhow::Result<()> {
    let dlq = build_dlq_buffer(cfg).await?;
    run_loop(cfg, buffer, dlq, http).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration as StdDuration;

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;
    use crate::buffer::{BufferError, InMemoryBuffer};

    fn test_config(opensearch_url: &str) -> Config {
        Config {
            http_port: 8443,
            syslog_port: 5140,
            syslog_tls_port: 6514,
            otlp_grpc_port: 4317,
            otlp_http_port: 4318,
            opensearch_url: opensearch_url.to_owned(),
            nats_url: "nats://127.0.0.1:1".to_owned(),
            nats_jetstream_subject_prefix: "svc-ingest.logs".to_owned(),
            snapshot_repo: "skauswatch-snapshots".to_owned(),
            syslog_udp_enabled: false,
            syslog_trusted_cidrs: Vec::new(),
            syslog_udp_tenant_id: None,
        }
    }

    fn sample_event(dedup_key: &str, tenant: &str) -> NormalizedEvent {
        NormalizedEvent {
            tenant: skauswatch_auth::Tenant(tenant.to_owned()),
            doc: JsonVal::Obj(vec![(
                "message".to_owned(),
                JsonVal::Str("hello".to_owned()),
            )]),
            dedup_key: dedup_key.to_owned(),
        }
    }

    /// Responds 503 for the first `fail_first_n` calls, then 200 forever —
    /// simulates "OpenSearch down, then recovers" without timing games.
    struct FlakyResponder {
        calls: AtomicUsize,
        fail_first_n: usize,
    }

    impl Respond for FlakyResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_first_n {
                ResponseTemplate::new(503)
            } else {
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"errors": false}))
            }
        }
    }

    /// Wraps a real `EventBuffer`, injecting a single simulated crash on
    /// the FIRST `ack` call: the underlying handle is nacked (so the
    /// wrapped buffer observably redelivers it — the same externally
    /// visible outcome a live JetStream ack-wait-timeout produces after a
    /// genuinely lost ack) and the crash itself is surfaced as an `Err`,
    /// exactly what a dropped/reset ack RPC looks like to the caller.
    /// Lets `writer_crash_mid_batch_causes_at_least_once_redelivery` drive
    /// the REAL `run_loop`/`process_batch` path instead of hand-rolling
    /// the consume/write/ack sequence.
    struct CrashOnceBuffer {
        inner: Arc<dyn EventBuffer>,
        ack_calls: AtomicUsize,
    }

    impl CrashOnceBuffer {
        fn new(inner: Arc<dyn EventBuffer>) -> Self {
            Self {
                inner,
                ack_calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl EventBuffer for CrashOnceBuffer {
        async fn push(&self, event: NormalizedEvent) -> Result<(), BufferError> {
            self.inner.push(event).await
        }

        async fn consume(&self, batch_size: usize) -> Result<Vec<DeliveredEvent>, BufferError> {
            self.inner.consume(batch_size).await
        }

        async fn ack(&self, handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            if self.ack_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.inner.nack(handle).await?;
                return Err(BufferError::Transport(
                    "simulated crash before ack reached the broker".to_owned(),
                ));
            }
            self.inner.ack(handle).await
        }

        async fn nack(&self, handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            self.inner.nack(handle).await
        }
    }

    /// Wraps an `EventBuffer`, counting how many times `ack` is actually
    /// called through to the inner buffer — lets a test assert "never
    /// acked" without racing a forcibly-cancelled `run_loop` task against
    /// `consume()`'s in-flight bookkeeping (an event mid-nack, or sitting
    /// in the in-memory fallback's in-flight table, when the test's
    /// `tokio::time::timeout` fires is a false negative for "is it still
    /// on the main stream" — it is evidence of neither ack nor loss).
    struct AckCountingBuffer {
        inner: Arc<dyn EventBuffer>,
        ack_count: AtomicUsize,
    }

    impl AckCountingBuffer {
        fn new(inner: Arc<dyn EventBuffer>) -> Self {
            Self {
                inner,
                ack_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait::async_trait]
    impl EventBuffer for AckCountingBuffer {
        async fn push(&self, event: NormalizedEvent) -> Result<(), BufferError> {
            self.inner.push(event).await
        }

        async fn consume(&self, batch_size: usize) -> Result<Vec<DeliveredEvent>, BufferError> {
            self.inner.consume(batch_size).await
        }

        async fn ack(&self, handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            self.ack_count.fetch_add(1, Ordering::SeqCst);
            self.inner.ack(handle).await
        }

        async fn nack(&self, handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            self.inner.nack(handle).await
        }
    }

    /// An `EventBuffer` whose `push` always fails — simulates a
    /// dead-letter sink that is itself unreachable (e.g. its own NATS
    /// connection is down), so `route_to_dlq`'s push fails every time.
    struct FailingPushBuffer;

    #[async_trait::async_trait]
    impl EventBuffer for FailingPushBuffer {
        async fn push(&self, _event: NormalizedEvent) -> Result<(), BufferError> {
            Err(BufferError::Transport("dlq sink unreachable".to_owned()))
        }

        async fn consume(&self, _batch_size: usize) -> Result<Vec<DeliveredEvent>, BufferError> {
            Ok(Vec::new())
        }

        async fn ack(&self, _handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            Ok(())
        }

        async fn nack(&self, _handle: crate::buffer::AckHandle) -> Result<(), BufferError> {
            Ok(())
        }
    }

    // -- pure unit tests -------------------------------------------------

    #[test]
    fn backoff_grows_and_caps() {
        assert_eq!(backoff_for(1), StdDuration::from_millis(20));
        assert_eq!(backoff_for(2), StdDuration::from_millis(40));
        assert_eq!(backoff_for(3), StdDuration::from_millis(80));
        // Large counts must cap, never overflow or grow unbounded.
        assert_eq!(backoff_for(100), StdDuration::from_millis(500));
    }

    #[test]
    fn effective_failure_count_prefers_jetstream_delivery_count_over_fresh_local_counter() {
        // A message already redelivered past the threshold by JetStream
        // (e.g. by a prior writer process that crashed and restarted,
        // losing its local counter) must still count as over-threshold
        // even though THIS process's local counter starts fresh at 1.
        let count = effective_failure_count(Some(u64::from(DLQ_FAILURE_THRESHOLD) + 3), 1);
        assert!(
            count >= DLQ_FAILURE_THRESHOLD,
            "a restart-surviving delivery count must still route to the DLQ"
        );
    }

    #[test]
    fn effective_failure_count_falls_back_to_local_counter_without_jetstream_metadata() {
        assert_eq!(effective_failure_count(None, 3), 3);
    }

    #[tokio::test]
    async fn inmemory_ack_handle_has_no_jetstream_delivery_count() {
        let buffer = InMemoryBuffer::new(1);
        buffer.push(sample_event("k", "tenant-a")).await.unwrap();
        let delivered = buffer.consume(1).await.unwrap();
        assert_eq!(
            delivered[0].handle.delivery_count(),
            None,
            "the in-memory fallback has no server-side delivery tracking"
        );
    }

    #[test]
    fn subject_prefixes_collide_detects_nested_and_equal_prefixes() {
        assert!(subject_prefixes_collide(
            "svc-ingest.logs",
            "svc-ingest.logs.dlq"
        ));
        assert!(subject_prefixes_collide(
            "svc-ingest.logs",
            "svc-ingest.logs"
        ));
        assert!(!subject_prefixes_collide(
            "svc-ingest-dlq",
            "svc-ingest.logs"
        ));
        assert!(!subject_prefixes_collide(
            "svc-ingest.logs",
            "svc-ingest.other"
        ));
    }

    #[test]
    fn stamp_tenant_appends_top_level_field() {
        let mut doc = JsonVal::Obj(vec![("a".to_owned(), JsonVal::Num(1.into()))]);
        stamp_tenant(&mut doc, "acme-corp");
        assert_eq!(
            doc.get("tenant_id").and_then(JsonVal::as_str),
            Some("acme-corp")
        );
    }

    #[test]
    fn stamp_tenant_is_a_noop_on_non_object_values() {
        let mut doc = JsonVal::Str("not an object".to_owned());
        stamp_tenant(&mut doc, "acme-corp");
        assert_eq!(doc, JsonVal::Str("not an object".to_owned()));
    }

    /// Regression for the production DLQ/bulk-write durability bug fixed
    /// alongside this test (Task 3.0c): the HTTP `/ingest` listener already
    /// stamps a top-level `tenant_id` before enqueuing (see
    /// `listeners::http::stamp_tenant`), so a buffered doc reaching the
    /// writer may already carry one. Confirmed against a real OpenSearch
    /// `_bulk` response that the old unconditional-append behavior produced
    /// a literal duplicate `"tenant_id"` JSON key, rejected outright with
    /// `mapper_parsing_exception` / `caused_by.json_parse_exception:
    /// "Duplicate field 'tenant_id'"` — every HTTP-sourced document failed
    /// every bulk write. `stamp_tenant` must produce exactly one
    /// `tenant_id` entry, with its own authoritative value winning over
    /// any stale existing one.
    #[test]
    fn stamp_tenant_overwrites_existing_tenant_id_instead_of_duplicating() {
        let mut doc = JsonVal::Obj(vec![
            ("a".to_owned(), JsonVal::Num(1.into())),
            (
                "tenant_id".to_owned(),
                JsonVal::Str("stale-value".to_owned()),
            ),
        ]);
        stamp_tenant(&mut doc, "acme-corp");

        let JsonVal::Obj(entries) = &doc else {
            panic!("expected object");
        };
        let tenant_id_count = entries.iter().filter(|(k, _)| k == "tenant_id").count();
        assert_eq!(
            tenant_id_count, 1,
            "must never produce a duplicate tenant_id key: {doc:?}"
        );
        assert_eq!(
            doc.get("tenant_id").and_then(JsonVal::as_str),
            Some("acme-corp"),
            "the writer's own authoritative tenant value must win over a stale existing one"
        );
    }

    #[tokio::test]
    async fn docs_with_ids_pairs_dedup_key_and_stamps_tenant() {
        let buffer = InMemoryBuffer::new(1);
        buffer
            .push(sample_event("dedup-a", "tenant-a"))
            .await
            .unwrap();
        let delivered = buffer.consume(1).await.unwrap();

        let pairs = docs_with_ids(&delivered);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "dedup-a");
        assert_eq!(
            pairs[0].1.get("tenant_id").and_then(JsonVal::as_str),
            Some("tenant-a")
        );
    }

    #[test]
    fn dlq_envelope_carries_reason_and_timestamp() {
        let event = sample_event("dedup-a", "tenant-a");
        let now = Utc::now();
        let envelope = dlq_envelope(&event, "opensearch unreachable", now);
        assert_eq!(
            envelope.get("dlq_reason").and_then(JsonVal::as_str),
            Some("opensearch unreachable")
        );
        assert_eq!(
            envelope.get("dlq_timestamp").and_then(JsonVal::as_str),
            Some(now.to_rfc3339().as_str())
        );
        assert_eq!(
            envelope.get("dedup_key").and_then(JsonVal::as_str),
            Some("dedup-a")
        );
        assert!(
            envelope
                .get("original_event")
                .is_some_and(JsonVal::is_object)
        );
    }

    #[tokio::test]
    async fn build_dlq_buffer_refuses_to_start_on_subject_prefix_collision() {
        let mut cfg = test_config("http://127.0.0.1:1");
        cfg.nats_jetstream_subject_prefix = DLQ_SUBJECT_PREFIX.to_owned();

        let result = build_dlq_buffer(&cfg).await;

        assert!(
            result.is_err(),
            "must refuse to start rather than silently building a colliding DLQ stream"
        );
    }

    // -- durability tests (Spec §14b, in-memory buffer — no live broker) -

    /// `writer_crash_mid_batch_causes_at_least_once_redelivery`: drives
    /// the REAL `run_loop`/`process_batch` path (via `CrashOnceBuffer`,
    /// not a hand-rolled consume/write/ack sequence) so an ack-before/
    /// regardless-of-write regression in production code would be caught
    /// here. The first successful write "crashes" before its ack reaches
    /// the broker; the same `run_loop` invocation naturally redelivers
    /// and rewrites it on its next iteration, and both writes must carry
    /// the same deterministic `_id` — the property that lets OpenSearch's
    /// own overwrite-by-`_id` behavior absorb the redelivery without
    /// creating a duplicate document.
    #[tokio::test]
    async fn writer_crash_mid_batch_causes_at_least_once_redelivery() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"errors": false})),
            )
            .mount(&mock)
            .await;

        let inner: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        inner
            .push(sample_event("evt-crash", "tenant-a"))
            .await
            .unwrap();
        let buffer: Arc<dyn EventBuffer> = Arc::new(CrashOnceBuffer::new(inner.clone()));
        let dlq: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        let cfg = test_config(&mock.uri());
        let http = reqwest::Client::new();

        let _ = tokio::time::timeout(
            StdDuration::from_secs(5),
            run_loop(&cfg, buffer.clone(), dlq.clone(), http),
        )
        .await;

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            2,
            "the crashed write and the redelivered write must both reach OpenSearch"
        );
        for req in &requests {
            let text = String::from_utf8(req.body.clone()).unwrap();
            assert!(
                text.contains("\"_id\":\"evt-crash\""),
                "both writes must carry the same deterministic _id: {text}"
            );
        }

        assert!(
            inner.consume(10).await.unwrap().is_empty(),
            "nothing left pending after the final ack"
        );
        assert!(
            dlq.consume(10).await.unwrap().is_empty(),
            "a successfully-recovered crash must never reach the DLQ"
        );
    }

    /// `opensearch_down_for_ten_minutes_then_recovers_no_loss`: OpenSearch
    /// returns 503 for the first two bulk attempts, then recovers — every
    /// buffered event must eventually be written, none dropped, none
    /// DLQ'd (recovery happens before `DLQ_FAILURE_THRESHOLD`).
    #[tokio::test]
    async fn opensearch_down_for_ten_minutes_then_recovers_no_loss() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(FlakyResponder {
                calls: AtomicUsize::new(0),
                fail_first_n: 2,
            })
            .mount(&mock)
            .await;

        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        for key in ["evt-1", "evt-2", "evt-3"] {
            buffer.push(sample_event(key, "tenant-a")).await.unwrap();
        }
        let dlq: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        let cfg = test_config(&mock.uri());
        let http = reqwest::Client::new();

        let _ = tokio::time::timeout(
            StdDuration::from_secs(5),
            run_loop(&cfg, buffer.clone(), dlq.clone(), http),
        )
        .await;

        assert!(
            buffer.consume(10).await.unwrap().is_empty(),
            "every buffered event must eventually be written and acked — zero loss"
        );
        assert!(
            dlq.consume(10).await.unwrap().is_empty(),
            "a transient outage that recovers before the DLQ threshold must never DLQ anything"
        );
        let requests = mock.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            3,
            "two failed attempts plus the one that finally succeeds"
        );
    }

    /// `repeated_bulk_failure_routes_to_dlq_not_silent_drop` (Spec §7c): a
    /// permanently-failing OpenSearch must not be nacked forever — after
    /// `DLQ_FAILURE_THRESHOLD` consecutive failures the event is routed to
    /// the dead-letter sink, flagged with a timestamp and the error
    /// reason, and acked off the main stream (never silently dropped, and
    /// never left endlessly redelivering).
    #[tokio::test]
    async fn repeated_bulk_failure_routes_to_dlq_not_silent_drop() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        buffer
            .push(sample_event("evt-dlq", "tenant-a"))
            .await
            .unwrap();
        let dlq: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        let cfg = test_config(&mock.uri());
        let http = reqwest::Client::new();

        let _ = tokio::time::timeout(
            StdDuration::from_secs(5),
            run_loop(&cfg, buffer.clone(), dlq.clone(), http),
        )
        .await;

        let mut dlq_delivered = dlq.consume(10).await.unwrap();
        assert_eq!(
            dlq_delivered.len(),
            1,
            "the permanently-failing event must land in the DLQ"
        );
        let dlq_doc = &dlq_delivered.pop().unwrap().event.doc;
        assert_eq!(
            dlq_doc.get("dedup_key").and_then(JsonVal::as_str),
            Some("evt-dlq")
        );
        assert!(
            dlq_doc
                .get("dlq_reason")
                .and_then(JsonVal::as_str)
                .is_some_and(|s| !s.is_empty())
        );
        assert!(
            dlq_doc
                .get("dlq_timestamp")
                .and_then(JsonVal::as_str)
                .is_some()
        );

        assert!(
            buffer.consume(10).await.unwrap().is_empty(),
            "a DLQ'd event must be acked off the main stream, never left endlessly nacking"
        );

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            DLQ_FAILURE_THRESHOLD as usize,
            "exactly DLQ_FAILURE_THRESHOLD attempts before routing to the DLQ"
        );
    }

    /// Fix-round regression: if OpenSearch is down AND the dead-letter
    /// sink is also unreachable, the event must never be acked off the
    /// main stream (that would lose it for good) — it must keep being
    /// nacked (redelivered) past the threshold instead.
    #[tokio::test]
    async fn dlq_push_failure_never_acks_main_handle_nacks_instead() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let inner: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        inner
            .push(sample_event("evt-dlq-down", "tenant-a"))
            .await
            .unwrap();
        let tracking = Arc::new(AckCountingBuffer::new(inner));
        let buffer: Arc<dyn EventBuffer> = tracking.clone();
        let dlq: Arc<dyn EventBuffer> = Arc::new(FailingPushBuffer);
        let cfg = test_config(&mock.uri());
        let http = reqwest::Client::new();

        let _ = tokio::time::timeout(
            StdDuration::from_secs(5),
            run_loop(&cfg, buffer.clone(), dlq.clone(), http),
        )
        .await;

        let requests = mock.received_requests().await.unwrap();
        assert!(
            requests.len() as u32 > DLQ_FAILURE_THRESHOLD,
            "must keep retrying past the threshold when the DLQ sink itself is unreachable: {} requests",
            requests.len()
        );
        assert_eq!(
            tracking.ack_count.load(Ordering::SeqCst),
            0,
            "the event must never be acked off the main stream while the DLQ push keeps failing"
        );
    }

    /// Spec §14b fix: OpenSearch can return HTTP 200 with per-item bulk
    /// failures (`"errors": true`) — those specific documents must be
    /// nacked, not acked away alongside the documents in the same batch
    /// that genuinely succeeded.
    #[tokio::test]
    async fn partial_bulk_failure_acks_succeeded_docs_and_nacks_failed_ones() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/_bulk"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errors": true,
                "items": [
                    {"index": {"_index": "i", "_id": "evt-ok", "status": 201}},
                    {"index": {"_index": "i", "_id": "evt-bad", "status": 400, "error": {"type": "mapper_parsing_exception", "reason": "boom"}}}
                ]
            })))
            .mount(&mock)
            .await;

        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        buffer
            .push(sample_event("evt-ok", "tenant-a"))
            .await
            .unwrap();
        buffer
            .push(sample_event("evt-bad", "tenant-a"))
            .await
            .unwrap();
        let dlq: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        let cfg = test_config(&mock.uri());
        let http = reqwest::Client::new();

        let delivered = buffer.consume(10).await.unwrap();
        assert_eq!(delivered.len(), 2);
        let mut failures = HashMap::new();
        process_batch(
            &buffer,
            &dlq,
            &http,
            &cfg.opensearch_url,
            delivered,
            &mut failures,
        )
        .await;

        let remaining = buffer.consume(10).await.unwrap();
        assert_eq!(
            remaining.len(),
            1,
            "only the failed doc must be redelivered — the succeeded one was acked"
        );
        assert_eq!(remaining[0].event.dedup_key, "evt-bad");
        assert!(
            dlq.consume(10).await.unwrap().is_empty(),
            "a single partial failure must not hit the DLQ threshold yet"
        );
    }

    /// `run` propagates a dead-letter-sink construction failure cleanly
    /// (never panics) rather than silently starting the loop without a
    /// working DLQ path.
    #[tokio::test]
    async fn run_fails_cleanly_when_dlq_nats_is_unreachable() {
        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(1));
        let cfg = test_config("http://127.0.0.1:1");
        let http = reqwest::Client::new();

        let result =
            tokio::time::timeout(StdDuration::from_secs(10), run(&cfg, buffer, http)).await;

        match result {
            Ok(inner) => assert!(inner.is_err(), "unreachable NATS must surface as an Err"),
            Err(_) => panic!("run() should fail fast on an unreachable NATS connect, not hang"),
        }
    }
}
