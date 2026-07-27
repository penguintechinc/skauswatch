//! /api/v1 router assembly for the Darwin backend. Every route here is the
//! upstream target the manager proxies to at
//! `{WORKER_DARWIN_URL}/api/v1/darwin{path}` (services/manager/src/routes/darwin.rs)
//! plus the git-credential CRUD surface at `/api/v1/credentials`
//! (darwin/services/flask-backend/app/api/v1/credentials.py).

mod credentials;
mod plans;
mod repos;
mod reviews;
mod status;
#[cfg(test)]
pub(crate) mod test_support;

use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::{Json, http::StatusCode};

use crate::state::AppState;

/// PostHog module flag gating every darwin route — the v2 equivalent of v1
/// `has_feature("darwin")` (see services/manager/src/routes/darwin.rs, which
/// gates the same way one layer up before proxying here).
pub(crate) const DARWIN_FLAG: &str = "skauswatch.darwin";
/// v1 bare 403 body text when the darwin feature is not licensed.
const LICENSE_MSG: &str = "Darwin AI review requires a Darwin license.";

/// Builds the full /api/v1 application router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .nest(
            "/api/v1",
            status::router()
                .merge(repos::router())
                .merge(reviews::router())
                .merge(plans::router())
                .merge(credentials::router()),
        )
        .with_state(state)
}

/// Independent (defense-in-depth) license check — the manager already gates
/// `/api/v1/darwin/*` before proxying, but this service does not trust that
/// solely; every route re-checks the flag itself.
pub(crate) async fn license_denied(state: &AppState) -> Option<Response> {
    if state.license.flag_enabled(DARWIN_FLAG).await {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": LICENSE_MSG })),
            )
                .into_response(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use std::sync::Arc;

    #[allow(clippy::panic)]
    fn dev_license() -> Arc<LicenseClient> {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    #[tokio::test]
    async fn license_gate_allows_under_dev_bypass() {
        let state = crate::state::AppStateInner::for_tests(dev_license());
        assert!(license_denied(&state).await.is_none());
    }
}
