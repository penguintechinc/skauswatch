//! Writer-mode entry point: drains the JetStream consumer, bulk-writes to
//! OpenSearch, and acks/DLQs on failure (Spec §7-8,
//! `docs/v2-port/ingest-module-spec.md`). [`run`] is the Wave-1 integration
//! point `main.rs::serve()` calls for `RunMode::Writer` — see this module's
//! items for the consume → bulk-write → ack/nack/DLQ loop itself.
//!
//! Dead-code note: nothing here is reachable from `main.rs::serve()` yet
//! (the per-mode dispatch lands at the Wave-1 integration gate once every
//! module it references exists — see `main.rs`'s own doc comment); a plain
//! (non-test) `cargo build`/`clippy` therefore sees this whole module as
//! unused, matching `buffer/mod.rs`'s identical interim
//! `#![allow(dead_code)]`.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use skauswatch_ocsf::JsonVal;

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
/// instead of hot-looping against a downed OpenSearch.
pub const DLQ_FAILURE_THRESHOLD: u32 = 5;

/// Subject prefix for the dead-letter sink's own JetStream stream. See
/// [`build_dlq_buffer`]'s doc comment for why this is deliberately NOT
/// nested under the ingest subject prefix (`svc-ingest.logs`, Spec §7a).
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

/// Stamps `tenant` onto `doc` as a top-level `tenant_id` field, appended
/// last — mirrors `services/logs/src/ingest.rs`'s `stamp_tenant`. `tenant`
/// always comes from `NormalizedEvent.tenant` (the buffer's own
/// header-derived, server-validated value — see
/// `buffer::jetstream::normalized_event_from_message`), never read back out
/// of the document body itself (the house tenant-isolation rule).
fn stamp_tenant(doc: &mut JsonVal, tenant: &str) {
    if let JsonVal::Obj(entries) = doc {
        entries.push(("tenant_id".to_owned(), JsonVal::Str(tenant.to_owned())));
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

/// Pushes `event` onto `dlq`, wrapped by [`dlq_envelope`]. Never propagates
/// an error to the caller: a DLQ push failure is logged loudly (Spec §7c
/// "never silently discarded" — never a silent `Ok`), but the caller still
/// acks the *original* handle off the main stream regardless (see
/// `process_batch`); retrying the DLQ push forever would just reintroduce
/// the "endlessly nacking" problem the DLQ exists to escape, one level
/// down.
async fn route_to_dlq(
    dlq: &Arc<dyn EventBuffer>,
    event: &NormalizedEvent,
    reason: &str,
    now: DateTime<Utc>,
) {
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
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                dedup_key = %event.dedup_key,
                "writer_dlq_push_failed"
            );
            metrics::counter!("svc_ingest_writer_dlq_push_failures_total").increment(1);
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
/// resolves every handle: `ack` on success; on failure, `nack` (JetStream
/// redelivery) unless the event has now failed [`DLQ_FAILURE_THRESHOLD`]
/// times in a row, in which case it is routed to `dlq` and acked off the
/// main stream instead (Spec §7c).
async fn process_batch(
    buffer: &Arc<dyn EventBuffer>,
    dlq: &Arc<dyn EventBuffer>,
    http: &reqwest::Client,
    opensearch_url: &str,
    delivered: Vec<DeliveredEvent>,
    failures: &mut HashMap<String, u32>,
) {
    let now = Utc::now();
    let index = opensearch::daily_index(now);
    let pairs = docs_with_ids(&delivered);
    let body = opensearch::build_bulk_body_with_ids(&index, &pairs);

    match opensearch::write_bulk(http, opensearch_url, body).await {
        Ok(()) => {
            metrics::counter!("svc_ingest_writer_events_written_total")
                .increment(pairs.len() as u64);
            for d in delivered {
                failures.remove(&d.event.dedup_key);
                if let Err(e) = buffer.ack(d.handle).await {
                    tracing::error!(error = %e, dedup_key = %d.event.dedup_key, "writer_ack_failed");
                }
            }
        }
        Err(e) => {
            let reason = e.to_string();
            tracing::warn!(error = %reason, batch_size = delivered.len(), "writer_bulk_write_failed");
            metrics::counter!("svc_ingest_writer_bulk_write_failures_total").increment(1);

            let mut to_nack = Vec::new();
            let mut max_consecutive = 0u32;
            for d in delivered {
                let count = {
                    let c = failures.entry(d.event.dedup_key.clone()).or_insert(0);
                    *c += 1;
                    *c
                };
                if count >= DLQ_FAILURE_THRESHOLD {
                    route_to_dlq(dlq, &d.event, &reason, now).await;
                    failures.remove(&d.event.dedup_key);
                    if let Err(ack_err) = buffer.ack(d.handle).await {
                        tracing::error!(error = %ack_err, dedup_key = %d.event.dedup_key, "writer_dlq_ack_failed");
                    }
                } else {
                    max_consecutive = max_consecutive.max(count);
                    to_nack.push(d.handle);
                }
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
/// exists to escape. [`DLQ_SUBJECT_PREFIX`] is disjoint from the ingest
/// prefix (`svc-ingest.logs`) so it is a genuinely separate stream.
///
/// # Errors
/// Returns an error if the NATS connection cannot be established, or the
/// dead-letter buffer fails to construct.
async fn build_dlq_buffer(cfg: &Config) -> anyhow::Result<Arc<dyn EventBuffer>> {
    let client = async_nats::connect(&cfg.nats_url)
        .await
        .map_err(|e| anyhow::anyhow!("dlq nats connect: {e}"))?;
    let context = async_nats::jetstream::new(client);
    let dlq = JetStreamBuffer::new(context, DLQ_SUBJECT_PREFIX)
        .map_err(|e| anyhow::anyhow!("dlq buffer init: {e}"))?;
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
/// the configured NATS server is unreachable) — the loop itself does not
/// otherwise return under normal operation.
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
    use crate::buffer::InMemoryBuffer;

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
            syslog_udp_enabled: false,
            syslog_trusted_cidrs: Vec::new(),
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

    // -- durability tests (Spec §14b, in-memory buffer — no live broker) -

    /// `writer_crash_mid_batch_causes_at_least_once_redelivery`: a batch
    /// that is written to OpenSearch but never acked (simulating the
    /// writer process dying between the write and the ack — the in-memory
    /// buffer has no ack-wait-timeout of its own, so an explicit `nack`
    /// stands in for "never acked", exactly the outcome JetStream's own
    /// ack-wait expiry produces in production) must be redelivered on the
    /// next `consume()`, and rewriting it must produce the SAME `_id` both
    /// times — the property that lets OpenSearch's own overwrite-by-`_id`
    /// behavior absorb the redelivery without creating a duplicate
    /// document.
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

        let buffer: Arc<dyn EventBuffer> = Arc::new(InMemoryBuffer::new(10));
        buffer
            .push(sample_event("evt-crash", "tenant-a"))
            .await
            .unwrap();
        let http = reqwest::Client::new();

        // First attempt: consume, write successfully, but "crash" before
        // acking — nack instead, simulating the process dying between the
        // write and the ack.
        let mut first = buffer.consume(10).await.unwrap();
        assert_eq!(first.len(), 1);
        let now = Utc::now();
        let index = opensearch::daily_index(now);
        let pairs = docs_with_ids(&first);
        let body = opensearch::build_bulk_body_with_ids(&index, &pairs);
        opensearch::write_bulk(&http, &mock.uri(), body)
            .await
            .unwrap();
        let crashed = first.pop().unwrap();
        buffer.nack(crashed.handle).await.unwrap();

        // "Restart consumption": the same event must be redelivered.
        let mut redelivered = buffer.consume(10).await.unwrap();
        assert_eq!(redelivered.len(), 1, "unacked event must be redelivered");
        assert_eq!(redelivered[0].event.dedup_key, "evt-crash");

        let pairs2 = docs_with_ids(&redelivered);
        let body2 = opensearch::build_bulk_body_with_ids(&index, &pairs2);
        opensearch::write_bulk(&http, &mock.uri(), body2)
            .await
            .unwrap();
        let completed = redelivered.pop().unwrap();
        buffer.ack(completed.handle).await.unwrap();

        let requests = mock.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            2,
            "both the crashed and redelivered write must reach OpenSearch"
        );
        for req in &requests {
            let text = String::from_utf8(req.body.clone()).unwrap();
            assert!(
                text.contains("\"_id\":\"evt-crash\""),
                "both writes must carry the same deterministic _id: {text}"
            );
        }

        assert!(
            buffer.consume(10).await.unwrap().is_empty(),
            "nothing left pending after the final ack"
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
