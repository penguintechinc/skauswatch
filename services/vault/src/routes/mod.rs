//! `/api/v1` router assembly for the Vault REST backend.

pub mod admin;
pub mod audit;
pub mod jit;
pub mod one_time;
pub mod secrets;
pub mod sync;

use axum::Router;
use axum::middleware;

use crate::state::AppState;

/// Builds the full `/api/v1` application router, wrapped in the global
/// license gate (v1 `license_middleware`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .nest(
            "/api/v1",
            secrets::router()
                .merge(jit::router())
                .merge(one_time::router())
                .merge(sync::router())
                .merge(admin::router())
                .merge(audit::router()),
        )
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state,
            crate::license_gate::require_license,
        ))
}
