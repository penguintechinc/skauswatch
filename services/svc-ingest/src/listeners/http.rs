//! HTTPS OCSF/JSON ingest listener (`:8443`) — stub until Task 1.3 fills in
//! the real `/ingest` handler (mirrors `services/logs/src/ingest.rs`; see
//! `docs/v2-port/ingest-module-spec.md` §4c).

/// Placeholder router — Task 1.3 replaces this with the real `POST
/// /ingest` surface (tenant middleware, `skauswatch.log-ingest` flag gate,
/// OCSF/generic-JSON normalization).
// dead_code: unwired until the Wave-1 integration gate merges this into
// `main.rs::serve()`.
#[allow(dead_code)]
pub fn router() -> axum::Router {
    axum::Router::new()
}
