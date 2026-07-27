//! /api/v1 router assembly. Routers are ported from the Quart service one
//! module at a time; each mounts its feature-flag gate when it lands.

mod alerts;
mod approvals;
mod asm;
mod auth;
mod codescan;
mod endpoint;
mod license;
mod research;
mod s3_scan;
mod siem;
mod threat_intel;
mod users;

use axum::Router;

use crate::state::AppState;

/// Builds the full /api/v1 application router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .nest(
            "/api/v1",
            license::router()
                .merge(auth::router())
                .merge(users::router())
                .merge(alerts::router())
                .merge(threat_intel::router())
                .merge(approvals::router())
                .merge(s3_scan::router())
                .merge(endpoint::router())
                .merge(siem::router())
                .merge(asm::router())
                .merge(codescan::router())
                .merge(research::router()),
        )
        .with_state(state)
}
