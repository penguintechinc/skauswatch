//! Writer-mode entry point: drains the JetStream consumer, bulk-writes to
//! OpenSearch, and acks/DLQs on failure — stub until Task 1.5 (see
//! `docs/v2-port/ingest-module-spec.md` §7-8).

/// Runs the writer loop until shutdown. Stub: never resolves — Task 1.5
/// replaces this with the real consume/bulk-write/ack loop against
/// `crate::buffer::EventBuffer` and `crate::opensearch`.
// dead_code: unwired until the Wave-1 integration gate merges this into
// `main.rs::serve()`.
#[allow(dead_code)]
pub async fn run() -> anyhow::Result<()> {
    std::future::pending().await
}
