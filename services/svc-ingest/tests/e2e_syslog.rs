//! End-to-end test for `skauswatch-svc-ingest`'s syslog listener (both RFC
//! 3164 and RFC 5424, over UDP and plain TCP): spawns a real receiver with
//! `SYSLOG_UDP_ENABLED` (via `tests/common::spawn_receiver_with_env`),
//! sends one RFC 3164 and one RFC 5424 line over each transport, then
//! polls OpenSearch for each message to land as a normalized OCSF document
//! (`message` and a mapped `severity_id` present) -- exercising the full
//! trusted-CIDR tenant resolution, parse, OCSF mapping, JetStream buffer,
//! writer, and OpenSearch path end to end.
//!
//! # Syslog-over-TLS (`:6514`, mTLS) is deliberately NOT covered here
//!
//! `listeners::syslog::run_tls` requires a live SPIFFE Workload API (a
//! SPIRE server+agent) to ever bind at all -- see that function's own doc
//! comment and `tests/common/mod.rs`'s top-level doc comment. This sandbox
//! has no SPIRE deployed, so `run_tls` degrades to a warned no-op and
//! `:6514` never binds; there is no TLS port here for a client to dial, and
//! attempting a real mTLS handshake against nothing would not exercise the
//! listener at all. A genuine syslog-TLS mTLS e2e is deferred to a
//! SPIRE-equipped environment -- see the `#[ignore]`d placeholder test
//! below.

// Integration-test binary, not production code: `expect`/`panic` on setup
// failures here are the intended "fail this test with a clear message"
// idiom, matching every other `#[cfg(test)]` module in this workspace's
// `#[allow(clippy::expect_used, clippy::panic)]` convention (see
// `tests/e2e_harness_smoke.rs`).
#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use common::{
    search_opensearch, send_syslog_tcp, send_syslog_udp, setup_test_db, spawn_receiver_with_env,
    spawn_writer, start_nats, start_opensearch,
};
use uuid::Uuid;

/// Upper bound on waiting for one specific syslog-originated message to
/// become searchable in `skauswatch-logs-*`. `tests/common/mod.rs`'s own
/// `DOCUMENT_INDEXED_TIMEOUT` is private to that module (and matched by
/// `wait_for_document`'s tenant-only query, which this test can't reuse
/// as-is -- see [`wait_for_message`]'s doc comment) so this test defines
/// its own, same duration.
const MESSAGE_INDEXED_TIMEOUT: Duration = Duration::from_secs(30);

/// Polls `{tenant}`-scoped `skauswatch-logs-*` documents for one whose
/// `message` field contains `marker`, bounded by
/// [`MESSAGE_INDEXED_TIMEOUT`]. This test can't reuse
/// `common::wait_for_document`'s tenant-only match: every syslog UDP/TCP
/// packet sent in this test resolves to the *same* fixed
/// `SYSLOG_UDP_TENANT_ID` tenant (Spec §6c -- trusted-CIDR UDP/TCP syslog
/// has no per-message tenant of its own, unlike `/ingest`'s per-request JWT
/// tenant that `tests/e2e_harness_smoke.rs`'s unique-tenant-per-run marker
/// relies on), so a bare "does this tenant have any document yet" check
/// would pass on the first of four messages and tell us nothing about the
/// other three.
async fn wait_for_message(
    opensearch_url: &str,
    tenant: &str,
    marker: &str,
) -> anyhow::Result<serde_json::Value> {
    let query = serde_json::json!({
        "query": {
            "bool": {
                "filter": [{ "term": { "tenant_id.keyword": tenant } }],
                "must": [{ "match_phrase": { "message": marker } }]
            }
        }
    });
    tokio::time::timeout(MESSAGE_INDEXED_TIMEOUT, async {
        loop {
            if let Ok(body) = search_opensearch(opensearch_url, "skauswatch-logs-*", &query).await {
                let hits = body["hits"]["total"]["value"].as_u64().unwrap_or(0);
                if hits > 0 {
                    return body;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "timed out after {MESSAGE_INDEXED_TIMEOUT:?} waiting for a document with \
             tenant_id={tenant} message~={marker}"
        )
    })
}

/// Builds an RFC 3164 line (`<PRI>MMM DD HH:MM:SS HOSTNAME MESSAGE`) whose
/// message body is exactly `marker` -- always parses (fixed, valid
/// header/timestamp shape; see `listeners::syslog::parser::RFC3164_RE`).
fn rfc3164_line(marker: &str) -> String {
    format!("<34>Jan  1 00:00:01 e2e-host {marker}")
}

/// Builds an RFC 5424 line (`<PRI>1 ISOTIMESTAMP HOSTNAME APP-NAME PROCID
/// MSGID STRUCTURED-DATA MESSAGE`, no structured data) whose message body
/// is exactly `marker`.
fn rfc5424_line(marker: &str) -> String {
    format!("<34>1 2025-01-15T12:30:00Z e2e-host e2e-app - - - {marker}")
}

#[tokio::test(flavor = "multi_thread")]
async fn syslog_udp_and_tcp_rfc3164_and_rfc5424_flow_to_opensearch_as_ocsf() {
    let nats = start_nats().await.expect("start nats container");
    let opensearch = start_opensearch()
        .await
        .expect("start opensearch container");
    let db = setup_test_db()
        .await
        .expect("create + migrate test database");

    // Fixed for the lifetime of this one receiver process -- exactly how a
    // real trusted-CIDR syslog deployment works (Spec §6c: the operator
    // assigns one fixed tenant to a trusted CIDR) -- but unique per test
    // run, so it doubles as this run's own OpenSearch scope, the same role
    // a fresh `Uuid::new_v4()`-per-tenant plays in
    // `tests/e2e_harness_smoke.rs`.
    let tenant = format!("e2e-syslog-{}", Uuid::new_v4());
    let run_id = Uuid::new_v4();

    let receiver = spawn_receiver_with_env(
        &nats,
        &opensearch,
        &db,
        &[
            ("SYSLOG_UDP_ENABLED", "true"),
            ("SYSLOG_TRUSTED_CIDRS", "127.0.0.1/32"),
            ("SYSLOG_UDP_TENANT_ID", &tenant),
        ],
    )
    .await
    .expect("spawn skauswatch-svc-ingest serve --mode receiver with syslog UDP/TCP enabled");
    let writer = spawn_writer(&nats, &opensearch)
        .await
        .expect("spawn skauswatch-svc-ingest serve --mode writer");

    let udp_3164_marker = format!("e2e-syslog-udp-3164-{run_id}");
    let udp_5424_marker = format!("e2e-syslog-udp-5424-{run_id}");
    let tcp_3164_marker = format!("e2e-syslog-tcp-3164-{run_id}");
    let tcp_5424_marker = format!("e2e-syslog-tcp-5424-{run_id}");

    send_syslog_udp(receiver.syslog_port, &rfc3164_line(&udp_3164_marker))
        .await
        .expect("send RFC 3164 syslog line over UDP");
    send_syslog_udp(receiver.syslog_port, &rfc5424_line(&udp_5424_marker))
        .await
        .expect("send RFC 5424 syslog line over UDP");
    send_syslog_tcp(receiver.syslog_port, &rfc3164_line(&tcp_3164_marker))
        .await
        .expect("send RFC 3164 syslog line over TCP");
    send_syslog_tcp(receiver.syslog_port, &rfc5424_line(&tcp_5424_marker))
        .await
        .expect("send RFC 5424 syslog line over TCP");

    for (label, marker) in [
        ("UDP RFC 3164", &udp_3164_marker),
        ("UDP RFC 5424", &udp_5424_marker),
        ("TCP RFC 3164", &tcp_3164_marker),
        ("TCP RFC 5424", &tcp_5424_marker),
    ] {
        let hit = match wait_for_message(&opensearch.url, &tenant, marker).await {
            Ok(hit) => hit,
            Err(e) => panic!(
                "{label} message never became searchable as OCSF: {e}\n\
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
    }
}

/// Placeholder: syslog-over-TLS (`:6514`, mTLS) mandates a live SPIFFE
/// Workload API to bind at all (see `listeners::syslog::run_tls`'s doc
/// comment and `tests/common/mod.rs`'s top-level doc comment) -- this
/// sandbox has no SPIRE server+agent deployed, so there is no TLS port to
/// dial and a genuine mTLS-handshake e2e cannot run here. Deferred to a
/// SPIRE-equipped environment; `#[ignore]`d rather than deleted so the
/// coverage gap stays visible in `cargo test -- --ignored` / CI's
/// ignored-test report instead of silently vanishing.
#[tokio::test]
#[ignore = "requires a live SPIFFE Workload API (SPIRE) not available in this sandbox -- see doc comment"]
async fn syslog_tls_mtls_e2e_requires_spire_deferred() {
    panic!(
        "not implemented here: syslog-over-TLS e2e needs a real SPIRE server+agent so \
         listeners::syslog::run_tls actually binds :6514 and a client can complete a genuine \
         mTLS handshake against it -- run this class of test only in a SPIRE-equipped \
         environment"
    );
}
