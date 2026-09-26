//! End-to-end test for `skauswatch-svc-ingest`'s OTLP logs listener, both
//! transports: gRPC (`:4317`) and HTTP/protobuf (`:4318`). Seeds an
//! ingest-token fallback credential (Spec §6b) for a fixed test tenant,
//! sends one `ExportLogsServiceRequest` over each transport with a
//! distinct UUID marker in the log record body, then polls OpenSearch for
//! each to land as a normalized OCSF document (`message` and a mapped
//! `severity_id` present, `tenant_id` equal to the seeded tenant) --
//! exercising the full ingest-token tenant resolution, OTLP proto decode,
//! OCSF mapping, JetStream buffer, writer, and OpenSearch path end to end
//! for both transports.
//!
//! # mTLS SPIFFE tenant resolution is NOT covered here
//!
//! Same rationale as `tests/e2e_syslog.rs`'s syslog-over-TLS exclusion:
//! `listeners::otlp::serve_grpc`'s mTLS branch requires a live SPIFFE
//! Workload API to ever present a server certificate at all (see that
//! function's own doc comment and `tests/common/mod.rs`'s top-level doc
//! comment) -- this sandbox has no SPIRE deployed, so `serve_grpc` always
//! takes the plaintext fallback and every gRPC request here authenticates
//! via the ingest-token path below. `listeners::otlp::run_http` never
//! accepted an mTLS identity-provider parameter in the first place (see
//! that function's own doc comment), so the ingest-token fallback is
//! HTTP's *only* credential path, not a fallback from anything. A genuine
//! mTLS-handshake OTLP e2e is deferred to a SPIRE-equipped environment,
//! same as the syslog-TLS placeholder in `tests/e2e_syslog.rs`.

// Integration-test binary, not production code -- `expect`/`panic` on
// setup failures here are the intended "fail this test with a clear
// message" idiom, matching every other `#[cfg(test)]`/e2e module in this
// workspace (see `tests/e2e_syslog.rs`).
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use uuid::Uuid;

use common::{
    otlp_log_record, seed_ingest_token, send_otlp_grpc, send_otlp_http, setup_test_db,
    spawn_receiver, spawn_writer, start_nats, start_opensearch, wait_for_message,
};

#[tokio::test(flavor = "multi_thread")]
async fn otlp_grpc_and_http_flow_to_opensearch_as_ocsf() {
    let nats = start_nats().await.expect("start nats container");
    let opensearch = start_opensearch()
        .await
        .expect("start opensearch container");
    let db = setup_test_db()
        .await
        .expect("create + migrate test database");

    // Fixed for the lifetime of this one receiver process, resolved via
    // the ingest-token fallback (Spec §6b) rather than a per-request JWT --
    // unlike `tests/e2e_harness_smoke.rs`'s `/ingest` JWT tenant, OTLP's
    // credential is a long-lived bearer token an operator provisions once
    // per ingest source, so this test provisions exactly one (seeded via
    // `seed_ingest_token`) and expects every OTLP record sent with it to
    // resolve to this same tenant.
    let tenant = format!("e2e-otlp-{}", Uuid::new_v4());
    let token = format!("e2e-otlp-token-{}", Uuid::new_v4());
    seed_ingest_token(&db, &token, &tenant)
        .await
        .expect("seed ingest_tokens row for OTLP ingest-token fallback auth");

    let receiver = spawn_receiver(&nats, &opensearch, &db)
        .await
        .expect("spawn skauswatch-svc-ingest serve --mode receiver");
    let writer = spawn_writer(&nats, &opensearch)
        .await
        .expect("spawn skauswatch-svc-ingest serve --mode writer");

    let run_id = Uuid::new_v4();
    let http_marker = format!("e2e-otlp-http-{run_id}");
    let grpc_marker = format!("e2e-otlp-grpc-{run_id}");

    send_otlp_http(&receiver, &token, &otlp_log_record(&http_marker))
        .await
        .expect("send OTLP log record over HTTP/protobuf");
    send_otlp_grpc(&receiver, &token, otlp_log_record(&grpc_marker))
        .await
        .expect("send OTLP log record over gRPC");

    for (label, marker) in [("HTTP/protobuf", &http_marker), ("gRPC", &grpc_marker)] {
        let hit = match wait_for_message(&opensearch.url, &tenant, marker).await {
            Ok(hit) => hit,
            Err(e) => panic!(
                "{label} OTLP message never became searchable as OCSF: {e}\n\
                 receiver output:\n{}\nwriter output:\n{}",
                receiver.output().await,
                writer.output().await
            ),
        };
        let source = &hit["hits"]["hits"][0]["_source"];
        assert!(
            source["message"]
                .as_str()
                .is_some_and(|m| m.contains(marker.as_str())),
            "{label}: expected the indexed document's message to contain {marker:?}, got {source}"
        );
        assert!(
            source["severity_id"].is_number(),
            "{label}: expected a mapped OCSF severity_id on the indexed document, got {source}"
        );
        assert_eq!(
            source["tenant_id"].as_str(),
            Some(tenant.as_str()),
            "{label}: expected tenant_id to be the seeded ingest-token tenant, got {source}"
        );
    }
}
