//! GET /api/v1/codescan/status — service status, proxied verbatim by the
//! manager. Port of the v1 `/api/v1/codescan/status` shape.

use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse};
use crate::state::AppState;

/// Router for GET /codescan/status.
pub fn router() -> Router<AppState> {
    Router::new().route("/codescan/status", get(codescan_status))
}

/// Documentation-only mirror of `codescan_status`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct StatusResponse {
    /// Always `"ok"`.
    status: String,
    /// Count of reviews not yet completed/failed/cancelled.
    queue_depth: i64,
}

/// GET /codescan/status — `{status, queue_depth}`, where `queue_depth` is the
/// count of reviews not yet completed/failed/cancelled.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/status",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Service status and review queue depth", body = StatusResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
    ),
)]
pub(crate) async fn codescan_status(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Response, ApiError> {
    if let Some(denied) = crate::routes::license_denied(&state).await {
        return Ok(denied);
    }

    let queue_depth: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM codescan_reviews WHERE status IN ('queued', 'in_progress', 'processing')",
    )
    .fetch_one(&state.db)
    .await?;

    Ok((
        axum::http::StatusCode::OK,
        Json(serde_json::json!({
            "status": "ok",
            "queue_depth": queue_depth,
        })),
    )
        .into_response())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use std::sync::Arc;

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

    fn gated_license() -> Arc<LicenseClient> {
        let mut cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        cfg.release_mode = true;
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    fn test_server(state: crate::state::AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    #[tokio::test]
    async fn status_requires_auth() {
        let server = test_server(AppStateInner::for_tests(dev_license()));
        let resp = server.get("/api/v1/codescan/status").await;
        resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = resp.json();
        assert_eq!(body["error"], "Missing or invalid authorization header");
    }

    #[tokio::test]
    async fn status_denied_without_license_even_with_valid_token() {
        let state = AppStateInner::for_tests(gated_license());
        let token = crate::routes::test_support::sign_token(&state, "1", "admin");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/status")
            .authorization_bearer(token)
            .await;
        resp.assert_status(axum::http::StatusCode::FORBIDDEN);
        let body: serde_json::Value = resp.json();
        assert_eq!(
            body["error"],
            "CodeScan AI review requires a CodeScan license."
        );
    }

    #[tokio::test]
    async fn status_reports_zero_queue_depth_against_an_empty_db() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = crate::routes::test_support::sign_token(&state, "1", "viewer");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/status")
            .authorization_bearer(token)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["status"], "ok");
        assert_eq!(body["queue_depth"], 0);
    }
}
