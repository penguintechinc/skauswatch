//! End-to-end durability tests for `skauswatch-svc-ingest`'s JetStream
//! buffer + dead-letter sink (Spec §14): a writer crash mid-drain followed
//! by a restart causes zero event loss (the durable consumer resumes from
//! the last ack), the same event published twice dedupes to exactly one
//! indexed document (`Nats-Msg-Id`), and a permanently-unreachable
//! OpenSearch routes events to the dead-letter sink instead of silently
//! dropping them.
//!
//! Every scenario drives the REAL compiled `skauswatch-svc-ingest` writer
//! process(es) against REAL NATS JetStream + OpenSearch containers
//! (`testcontainers`), publishing events directly onto the buffer via
//! `tests/common::RawEventProducer` — bypassing the receiver's protocol
//! listeners entirely. These are writer/buffer durability guarantees, not
//! decode/OCSF-mapping ones (already covered end to end by
//! `tests/e2e_syslog.rs`/`tests/e2e_otlp.rs`), so seeding the buffer
//! directly keeps each test focused on the consume → write → ack/nack/DLQ
//! loop itself.
//!
//! # Deviations from a literal production failure (documented, not skipped)
//!
//! - **Writer-crash timing**
//!   (`writer_crash_and_restart_causes_zero_loss`): there is no hook into
//!   the real writer process's internal consume/write/ack loop to
//!   guarantee a SIGKILL lands exactly mid-batch — it is a genuine
//!   subprocess, not a mock. The process is killed after a short, fixed
//!   delay chosen to be long enough for the bulk write to reach OpenSearch
//!   and for at least some of a 50-event batch's *sequential* per-event
//!   `ack()` RPCs (`crate::writer::process_batch_inner`) to plausibly still
//!   be in flight, but short enough that the whole batch is unlikely to
//!   have fully drained first. The load-bearing assertion — zero loss,
//!   exactly-once — holds regardless of exactly how many acks landed
//!   before the kill; see that test's own doc comment.
//! - **JetStream `AckWait`**: an event the first writer pulled but never
//!   acked is only redelivered to the second writer once the pull
//!   consumer's `AckWait` elapses. `crate::buffer::jetstream::
//!   JetStreamBuffer::consumer` sets no explicit `ack_wait` (server
//!   default, ~30s), so this test's bound accounts for that instead of
//!   assuming redelivery is instant.
//! - **DLQ scenario's "OpenSearch down for >10 min" framing** (Spec §14's
//!   illustrative window): `DLQ_FAILURE_THRESHOLD` consecutive failed
//!   attempts is what actually triggers the DLQ route
//!   (`src/writer.rs::handle_failed_batch`), not a literal wall-clock
//!   duration — this suite drives a genuine, permanent OpenSearch
//!   connection failure and waits for that attempt count to be reached,
//!   not for ten minutes of wall-clock time to pass.
//! - **DLQ scenario's "OpenSearch unavailable" simulation is a dead URL,
//!   not a stopped container**: a real `docker stop` + `docker start`
//!   cycle on the SAME `testcontainers`-managed OpenSearch container was
//!   attempted first and rejected — empirically, in this sandbox's Docker
//!   networking setup, the restarted container becomes healthy again
//!   *internally* (its own logs report `cluster health status changed ...
//!   GREEN` within seconds) but its published host port then refuses every
//!   connection, indefinitely. That is a Docker/environment networking
//!   quirk of restarting a container's port publishing in this sandbox, not
//!   a `skauswatch-svc-ingest` defect — verified independently of this test
//!   suite by driving the same container lifecycle directly against the
//!   Docker daemon. `opensearch_unreachable_routes_to_dlq_not_silent_drop`
//!   instead spawns its writer via `tests/common::
//!   spawn_writer_with_opensearch_url` pointed at a permanently unreachable
//!   address (`"http://127.0.0.1:1"`, the same convention
//!   `src/opensearch/mod.rs`'s own `write_bulk_propagates_transport_failure`
//!   unit test already uses), exercising the identical
//!   `opensearch::write_bulk` connection-failure → DLQ code path without
//!   depending on that Docker quirk. The real OpenSearch container is kept
//!   running throughout so the "writer recovers" half of the scenario can
//!   spawn a second writer pointed at it directly.
//! - **Syslog-TLS-style SPIRE gap does not apply here**: writer mode has no
//!   SPIFFE dependency (see `tests/common/mod.rs`'s `spawn_writer` doc
//!   comment), so none of these scenarios are affected by the receiver-mode
//!   SPIRE limitation documented there.

// Integration-test binary, not production code: `expect`/`panic` on setup
// failures here are the intended "fail this test with a clear message"
// idiom, matching every other `#[cfg(test)]`/e2e module in this workspace
// (see `tests/e2e_syslog.rs`).
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::collections::HashSet;
use std::time::Duration;

use common::{
    RawEventProducer, count_dlq_messages, search_opensearch, spawn_writer,
    spawn_writer_with_opensearch_url, start_nats, start_opensearch, wait_for_dlq_count,
    wait_for_message, wait_for_tenant_hit_count,
};
use uuid::Uuid;

/// A permanently unreachable OpenSearch endpoint — nothing listens on this
/// address, so every connection attempt fails immediately (no DNS lookup,
/// no slow-timeout hang). Mirrors `src/opensearch/mod.rs`'s own
/// `write_bulk_propagates_transport_failure` unit test's convention; see
/// this file's top-level "Deviations" note for why a dead URL is used
/// instead of stopping a real OpenSearch container.
const DEAD_OPENSEARCH_URL: &str = "http://127.0.0.1:1";

/// Upper bound for the crash-recovery scenario: an unacked message is only
/// redelivered once JetStream's pull-consumer `AckWait` elapses (server
/// default ~30s — see this file's top-level "Deviations" note), plus margin
/// for container/process overhead and the second writer's own processing.
const CRASH_RECOVERY_TIMEOUT: Duration = Duration::from_secs(90);
/// Upper bound for the dedup scenario — no server-side redelivery wait is
/// involved (the duplicate is dropped at publish time), so a single
/// bulk-write round trip is all that's needed.
const DEDUP_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound for the DLQ scenario to accumulate `DLQ_FAILURE_THRESHOLD`
/// failed attempts per event (backoff-limited to 500ms/attempt — see
/// `src/writer.rs::backoff_for` — plus connection-failure overhead against
/// a stopped container).
const DLQ_TIMEOUT: Duration = Duration::from_secs(90);

/// `writer_crash_and_restart_causes_zero_loss` (Spec §14 durability): 50
/// events are published directly onto the JetStream buffer, a writer is
/// spawned to start draining them, killed (SIGKILL, no graceful shutdown)
/// shortly after — before it can plausibly have acked the whole batch — and
/// a second writer is spawned against the SAME NATS/JetStream + OpenSearch.
/// The durable consumer (`{stream}-consumer`, a deterministic name — see
/// `JetStreamBuffer::consumer`) is shared across both writer processes, so
/// any event the first writer pulled but never acked is redelivered to the
/// second one once JetStream's `AckWait` elapses. Every event's OpenSearch
/// `_id` is its dedup key (`crate::writer::docs_with_ids`), so even a
/// redelivered, re-written event overwrites the same document rather than
/// duplicating it — the assertion is exact-count-N, not merely "at least
/// N".
#[tokio::test(flavor = "multi_thread")]
async fn writer_crash_and_restart_causes_zero_loss() {
    let nats = start_nats().await.expect("start nats container");
    let opensearch = start_opensearch()
        .await
        .expect("start opensearch container");
    let producer = RawEventProducer::connect(&nats)
        .await
        .expect("connect raw event producer");

    let tenant = format!("e2e-durability-crash-{}", Uuid::new_v4());
    let run_id = Uuid::new_v4();
    const N: usize = 50;
    let markers: Vec<String> = (0..N).map(|i| format!("crash-{run_id}-{i}")).collect();
    for marker in &markers {
        producer
            .publish(&tenant, marker, &serde_json::json!({ "message": marker }))
            .await
            .expect("publish event directly onto the jetstream buffer");
    }

    let mut writer1 = spawn_writer(&nats, &opensearch)
        .await
        .expect("spawn first writer");
    // Short, deliberate window before killing — see this file's top-level
    // "Deviations" note for why this cannot guarantee an exact mid-batch
    // hit against a real subprocess.
    tokio::time::sleep(Duration::from_millis(120)).await;
    writer1
        .kill_and_wait()
        .await
        .expect("SIGKILL the first writer mid-drain");

    let writer2 = spawn_writer(&nats, &opensearch)
        .await
        .expect("spawn second (restarted) writer against the same nats + opensearch");

    let hits = match wait_for_tenant_hit_count(&opensearch.url, &tenant, N, CRASH_RECOVERY_TIMEOUT)
        .await
    {
        Ok(hits) => hits,
        Err(e) => panic!(
            "crash-recovery: not all {N} events became searchable after restart: {e}\n\
             writer1 output:\n{}\nwriter2 output:\n{}",
            writer1.output().await,
            writer2.output().await
        ),
    };

    assert_eq!(
        hits.len(),
        N,
        "expected exactly {N} indexed documents (zero loss, zero duplicates) after \
         writer crash + restart, got {}",
        hits.len()
    );
    let indexed_markers: HashSet<String> = hits
        .iter()
        .filter_map(|s| s["message"].as_str().map(str::to_owned))
        .collect();
    let expected_markers: HashSet<String> = markers.into_iter().collect();
    assert_eq!(
        indexed_markers, expected_markers,
        "every published marker must be present exactly once after writer crash + restart"
    );
}

/// `duplicate_publish_dedupes_to_exactly_one_document` (Spec §14
/// durability — `Nats-Msg-Id` dedup): the SAME event (identical dedup key,
/// hence identical `Nats-Msg-Id`) is published twice in direct succession.
/// JetStream's server-side dedup window must drop the second publish as a
/// broker-side no-op, so exactly one message is ever delivered to the
/// writer and exactly one document is ever indexed — a count of two is a
/// dedup regression.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_publish_dedupes_to_exactly_one_document() {
    let nats = start_nats().await.expect("start nats container");
    let opensearch = start_opensearch()
        .await
        .expect("start opensearch container");
    let producer = RawEventProducer::connect(&nats)
        .await
        .expect("connect raw event producer");
    let writer = spawn_writer(&nats, &opensearch)
        .await
        .expect("spawn writer");

    let tenant = format!("e2e-durability-dedup-{}", Uuid::new_v4());
    let dedup_key = format!("dedup-{}", Uuid::new_v4());
    let doc = serde_json::json!({ "message": dedup_key });

    producer
        .publish(&tenant, &dedup_key, &doc)
        .await
        .expect("publish event (first)");
    producer
        .publish(&tenant, &dedup_key, &doc)
        .await
        .expect("publish event (exact duplicate — same Nats-Msg-Id)");

    let hits = match wait_for_tenant_hit_count(&opensearch.url, &tenant, 1, DEDUP_TIMEOUT).await {
        Ok(hits) => hits,
        Err(e) => panic!(
            "dedup: the single expected document never became searchable: {e}\n\
             writer output:\n{}",
            writer.output().await
        ),
    };
    assert_eq!(
        hits.len(),
        1,
        "duplicate publish must dedupe to exactly one document, got {}: {hits:?}",
        hits.len()
    );

    // Settle window: prove the duplicate never lands as a SECOND document
    // even after giving the writer ample time to have processed an
    // erroneous second message, had dedup failed to drop it at the broker.
    tokio::time::sleep(Duration::from_secs(5)).await;
    let final_body = search_opensearch(
        &opensearch.url,
        "skauswatch-logs-*",
        &serde_json::json!({
            "size": 0,
            "query": { "term": { "tenant_id.keyword": tenant } }
        }),
    )
    .await
    .expect("final dedup settle-window count query");
    let final_count = final_body["hits"]["total"]["value"].as_u64().unwrap_or(0);
    assert_eq!(
        final_count, 1,
        "a duplicate publish (same Nats-Msg-Id) must never produce a second document \
         after settling — dedup regression: {final_body}"
    );
}

/// `opensearch_unreachable_routes_to_dlq_not_silent_drop` (Spec §14/§7c):
/// a writer pointed at a permanently unreachable OpenSearch endpoint (see
/// this file's top-level "Deviations" note for why this is a dead URL
/// rather than a stopped container) is published to, and the events must
/// land on the dead-letter sink (`svc-ingest-dlq*`) after
/// `DLQ_FAILURE_THRESHOLD` failed bulk-write attempts — proving they are
/// never silently dropped, and regression-testing that the DLQ stream is
/// actually provisioned (the earlier "no stream found for given subject"
/// production bug — see `crate::writer::build_dlq_buffer`'s doc comment;
/// `Task 3.0c` fixed it by calling `ensure_stream()` before the writer's
/// first DLQ push). A second, independent writer pointed at the REAL
/// (always-running) OpenSearch is then used to confirm a fresh event flows
/// through normally — the already-DLQ'd events are never automatically
/// retried from the dead-letter sink (that is the sink's whole point), so
/// "recovery" is proven with a healthy writer and a fresh event, not a
/// replay of the DLQ'd ones.
#[tokio::test(flavor = "multi_thread")]
async fn opensearch_unreachable_routes_to_dlq_not_silent_drop() {
    let nats = start_nats().await.expect("start nats container");
    let opensearch = start_opensearch()
        .await
        .expect("start opensearch container");
    let producer = RawEventProducer::connect(&nats)
        .await
        .expect("connect raw event producer");

    let mut dead_writer = spawn_writer_with_opensearch_url(&nats, DEAD_OPENSEARCH_URL)
        .await
        .expect("spawn writer pointed at an unreachable opensearch endpoint");

    let tenant = format!("e2e-durability-dlq-{}", Uuid::new_v4());
    let run_id = Uuid::new_v4();
    const M: usize = 3;
    let markers: Vec<String> = (0..M).map(|i| format!("dlq-{run_id}-{i}")).collect();
    for marker in &markers {
        producer
            .publish(&tenant, marker, &serde_json::json!({ "message": marker }))
            .await
            .expect("publish event while opensearch is unreachable");
    }

    let dlq_count = match wait_for_dlq_count(&nats.url, M as u64, DLQ_TIMEOUT).await {
        Ok(n) => n,
        Err(e) => panic!(
            "events never reached the dead-letter sink (possible silent drop, or the \
             \"no stream found for given subject\" regression): {e}\ndead writer output:\n{}",
            dead_writer.output().await
        ),
    };
    assert!(
        dlq_count >= M as u64,
        "expected at least {M} dlq messages, got {dlq_count}"
    );

    // The DLQ'd events must never also have silently succeeded a write to
    // the main lake (that would mean they were double-counted, not
    // genuinely failed) — the real OpenSearch has been running untouched
    // this whole time, so zero hits for this tenant is the correct state
    // before any recovery event is published.
    let pre_recovery_body = search_opensearch(
        &opensearch.url,
        "skauswatch-logs-*",
        &serde_json::json!({
            "size": 0,
            "query": { "term": { "tenant_id.keyword": tenant } }
        }),
    )
    .await
    .expect("query main lake before recovery");
    let pre_recovery_count = pre_recovery_body["hits"]["total"]["value"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(
        pre_recovery_count, 0,
        "dlq'd events must never also appear in the main lake — got {pre_recovery_count} \
         unexpected documents: {pre_recovery_body}"
    );

    // The dead writer is permanently wedged against an unreachable
    // OpenSearch — kill it before starting a second, independently
    // configured writer against the real one, so only one writer process
    // is ever pulling from the shared durable consumer at a time.
    dead_writer
        .kill_and_wait()
        .await
        .expect("stop the writer pointed at the unreachable endpoint");

    // Recovery check: a fresh writer pointed at the REAL, always-running
    // OpenSearch must flow a new event through normally — proves the
    // writer's OpenSearch client itself works cleanly once pointed at
    // healthy infrastructure, not just that DLQ routing worked while it
    // wasn't.
    let recovery_writer = spawn_writer(&nats, &opensearch)
        .await
        .expect("spawn a second writer against the real opensearch");
    let recovery_marker = format!("dlq-recovery-{run_id}");
    producer
        .publish(
            &tenant,
            &recovery_marker,
            &serde_json::json!({ "message": recovery_marker }),
        )
        .await
        .expect("publish recovery event for the healthy writer to pick up");
    if let Err(e) = wait_for_message(&opensearch.url, &tenant, &recovery_marker).await {
        panic!(
            "a healthy writer against the real opensearch did not process a fresh event: {e}\n\
             recovery writer output:\n{}",
            recovery_writer.output().await
        );
    }

    // Regression guard: the dead-letter sink's stream must actually exist
    // by now (not just "the count query happened to return None the whole
    // time and the earlier `wait_for_dlq_count` succeeded some other way").
    assert!(
        count_dlq_messages(&nats.url)
            .await
            .expect("read dlq stream count")
            .is_some(),
        "dlq stream must exist by the time this test completes"
    );
}
