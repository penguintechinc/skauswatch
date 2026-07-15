//! /api/v1 router assembly. Routers are ported from the Quart service one
//! module at a time; each mounts its feature-flag gate when it lands.

mod auth;
mod license;

use axum::Router;

use crate::state::AppState;

/// Builds the full /api/v1 application router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .nest("/api/v1", license::router().merge(auth::router()))
        .with_state(state)
}
