//! Router assembly. Every business-route module here is mounted twice by
//! `main.rs` — once flat (v1's paths, preserved verbatim) and once nested
//! under `/api/v1` (house standard alias, `backend.md` API Versioning) — so
//! existing v1 consumers keep working unmodified while new callers get the
//! versioned path. `openapi` is the one exception: `main.rs` mounts it only
//! under `/api/v1`, matching the canonical paths documented in
//! `openapi::ApiDoc` (see `docs/v2-port/openapi-pattern.md`).
//!
//! `events::router` needs the concrete `state` value (not just `Router<
//! AppState>`'s generic `S`) to build its `tenant_middleware` layer (finding
//! #1 — see that module's docs), so this function takes `state` and threads
//! it through rather than staying zero-argument.
//!
//! `health` is deliberately NOT part of [`router`]'s business route set —
//! `main.rs::serve()` wraps [`router`]'s output in `crate::rate_limit`'s
//! governor and mounts `health::router()` separately, outside it. Before
//! this split, `GET /health` (and `/api/v1/health`) sat inside the same
//! governed router as the business routes, so k8s probe traffic (high
//! frequency, no JWT) could 429 once the governor's burst was exhausted by
//! other traffic on the same bucket — a first-run microk8s deploy bug.

mod alerts;
mod dashboard;
mod events;
pub(crate) mod health;
pub(crate) mod openapi;
#[cfg(test)]
pub(crate) mod test_support;

use axum::Router;

use crate::state::AppState;

/// Builds the business route set only (dashboard/events/alerts/threat-intel)
/// — state-generic so the caller can mount it at both the flat and
/// `/api/v1`-prefixed paths before applying state. `main.rs::serve()` is
/// the only caller that also wraps this in the rate limiter; see the module
/// doc comment for why `health::router()` stays out of it.
pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .merge(dashboard::router())
        .merge(events::router(state.clone()))
        .merge(alerts::router())
        .merge(crate::threat_intel::routes::router(state))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use axum::http::StatusCode;

    use super::*;
    use crate::routes::test_support::dev_state;

    /// Mirrors `main.rs::serve()`'s router assembly exactly: the same route
    /// set is mounted flat (v1 paths, preserved verbatim) and nested under
    /// `/api/v1` (house standard alias, `backend.md` API Versioning) from
    /// one binary — both mount points must resolve. `health::router()` is
    /// asserted separately (`routes::health`'s own tests) — it is
    /// deliberately not part of this business route set; see this module's
    /// doc comment.
    #[tokio::test]
    async fn routes_are_reachable_both_flat_and_under_api_v1() {
        let api = router(dev_state());
        let app = Router::new()
            .merge(api.clone())
            .nest("/api/v1", api)
            .with_state(dev_state());
        let server = axum_test::TestServer::new(app);

        server.get("/metrics/dashboard").await.assert_status_ok();
        server
            .get("/api/v1/metrics/dashboard")
            .await
            .assert_status_ok();
    }

    /// `health::router()` is merged in `main.rs::serve()` separately from
    /// [`router`] (business routes), flat and nested under `/api/v1`, same
    /// as every other route module — this proves that alias mounting works
    /// even though it happens outside `router()` itself.
    #[tokio::test]
    async fn health_router_is_reachable_both_flat_and_under_api_v1() {
        let health = health::router();
        let app = Router::new()
            .merge(health.clone())
            .nest("/api/v1", health)
            .with_state(dev_state());
        let server = axum_test::TestServer::new(app);

        server
            .get("/health")
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        server
            .get("/api/v1/health")
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        server.get("/version").await.assert_status_ok();
        server.get("/api/v1/version").await.assert_status_ok();
    }
}
