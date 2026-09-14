//! Proving test for the shared e2e harness (`tests/common`): starts real
//! NATS + OpenSearch containers, spawns the compiled `skauswatch-svc-ingest`
//! binary in both `receiver` and `writer` mode wired to them, `POST`s a
//! document to the HTTPS OCSF/JSON `/ingest` endpoint, then polls
//! `skauswatch-logs-*` (bounded timeout) until it is searchable — exercising
//! the harness's full container/process/client plumbing end to end so every
//! later Wave-3 e2e test can build on it with confidence.
//!
//! As of this task, this test is expected to fail at the
//! `spawn_receiver` step — see `tests/common/mod.rs`'s top-level doc
//! comment for the exact, out-of-file-scope upstream defect
//! (`listeners::syslog::run_tls` hard-fails without a live SPIFFE Workload
//! API, and `bootstrap::drain_listeners` cascades that into the whole
//! receiver process exiting before `/healthz` ever answers). The harness
//! itself — container startup, process spawn/readiness/output-capture,
//! JWT minting, OpenSearch polling — is exercised and verified up to that
//! point regardless.

// Integration-test binary, not production code: `expect`/`panic` on setup
// failures here are the intended "fail this test with a clear message"
// idiom, matching every other `#[cfg(test)]` module in this workspace's
// `#[allow(clippy::expect_used, clippy::panic)]` convention.
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use common::{
    post_ingest, setup_test_db, spawn_receiver, spawn_writer, start_nats, start_opensearch,
    wait_for_document,
};
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread")]
async fn ingest_document_flows_receiver_to_opensearch() {
    let nats = start_nats().await.expect("start nats container");
    let opensearch = start_opensearch()
        .await
        .expect("start opensearch container");
    let db = setup_test_db()
        .await
        .expect("create + migrate test database");

    let receiver = spawn_receiver(&nats, &opensearch, &db)
        .await
        .expect("spawn skauswatch-svc-ingest serve --mode receiver");
    let writer = spawn_writer(&nats, &opensearch)
        .await
        .expect("spawn skauswatch-svc-ingest serve --mode writer");

    // A unique tenant per run doubles as the document marker `wait_for_document`
    // polls on — see that function's doc comment for why.
    let tenant = format!("e2e-harness-{}", Uuid::new_v4());
    let body = serde_json::json!({
        "message": "svc-ingest e2e harness smoke test",
        "harness_run": tenant,
    });

    let resp = post_ingest(&receiver, &tenant, &body)
        .await
        .expect("POST /ingest");
    let status = resp.status();
    let resp_body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    assert!(
        status.is_success(),
        "POST /ingest returned {status}: {resp_body}\nreceiver output:\n{}",
        receiver.output().await
    );

    let hit = match wait_for_document(&opensearch.url, &tenant).await {
        Ok(hit) => hit,
        Err(e) => {
            panic!(
                "document never became searchable in skauswatch-logs-*: {e}\nwriter output:\n{}",
                writer.output().await
            )
        }
    };
    assert!(
        hit["hits"]["total"]["value"].as_u64().unwrap_or(0) > 0,
        "expected at least one indexed document for tenant {tenant}, got: {hit}"
    );
}
