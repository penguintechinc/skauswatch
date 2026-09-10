//! Syslog RFC 3164 + RFC 5424 listener (UDP/TCP/TLS) — stub until Task 1.1
//! fills in `detect_and_parse`/`run_udp`/`run_tcp`/`run_tls` (see
//! `docs/v2-port/ingest-module-spec.md` §4a). Task 1.1 also adds a sibling
//! `parser.rs` alongside this file.

/// Runs the syslog listener set (UDP/TCP/TLS) until shutdown. Stub: never
/// resolves — Task 1.1 replaces this with the real per-transport listeners
/// dispatching into `crate::buffer::EventBuffer`.
// dead_code: unwired until the Wave-1 integration gate merges this into
// `main.rs::serve()`.
#[allow(dead_code)]
pub async fn run() -> anyhow::Result<()> {
    std::future::pending().await
}
