//! Router assembly. Every module here is mounted twice by `main.rs` — once
//! flat (v1's paths, preserved verbatim) and once nested under `/api/v1`
//! (house standard alias, `backend.md` API Versioning) — so existing v1
//! consumers keep working unmodified while new callers get the versioned
//! path.

mod alerts;
mod dashboard;
mod events;
mod health;

use axum::Router;

use crate::state::AppState;

/// Builds the full route set, state-generic so the caller can mount it at
/// both the flat and `/api/v1`-prefixed paths before applying state.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(health::router())
        .merge(dashboard::router())
        .merge(events::router())
        .merge(alerts::router())
}
