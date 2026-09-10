//! OTLP gRPC (`:4317`) + HTTP (`:4318`) log listener — stub until Task 1.2
//! fills in the real `LogsGrpc` tonic service and `run_http` (see
//! `docs/v2-port/ingest-module-spec.md` §4b).

/// Runs the OTLP gRPC + HTTP listeners until shutdown. Stub: never resolves
/// — Task 1.2 replaces this with the real tonic/axum servers dispatching
/// into `crate::buffer::EventBuffer`.
// dead_code: unwired until the Wave-1 integration gate merges this into
// `main.rs::serve()`.
#[allow(dead_code)]
pub async fn run() -> anyhow::Result<()> {
    std::future::pending().await
}
