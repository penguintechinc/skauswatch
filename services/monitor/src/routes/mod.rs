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

mod alerts;
mod dashboard;
mod events;
mod health;
pub(crate) mod openapi;
#[cfg(test)]
pub(crate) mod test_support;

use axum::Router;

use crate::state::AppState;

/// Builds the full route set, state-generic so the caller can mount it at
/// both the flat and `/api/v1`-prefixed paths before applying state.
pub fn router(state: AppState) -> Router<AppState> {
    Router::new()
        .merge(health::router())
        .merge(dashboard::router())
        .merge(events::router(state))
        .merge(alerts::router())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::routes::test_support::dev_state;

    /// Mirrors `main.rs::serve()`'s router assembly exactly: the same route
    /// set is mounted flat (v1 paths, preserved verbatim) and nested under
    /// `/api/v1` (house standard alias, `backend.md` API Versioning) from
    /// one binary — both mount points must resolve.
    #[tokio::test]
    async fn routes_are_reachable_both_flat_and_under_api_v1() {
        let api = router(dev_state());
        let app = Router::new()
            .merge(api.clone())
            .nest("/api/v1", api)
            .with_state(dev_state());
        let server = axum_test::TestServer::new(app);

        server.get("/version").await.assert_status_ok();
        server.get("/api/v1/version").await.assert_status_ok();
    }
}
