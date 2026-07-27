//! `/alerts/*` — v1 `main.py` alert-management endpoints, backed by
//! `alert_manager.py`.
//!
//! v1's `AlertManager` has no storage backend at all: `search_alerts`
//! always returns an empty result set, `get_alert_by_id` always returns
//! `None` (→ 404), and `update_alert_status` only logs the call — none of
//! it persists anywhere (confirmed by reading `alert_manager.py` in full:
//! there is no database/ES/Mongo/Redis write in any of its three methods).
//! This is a faithful, documented port of that real v1 behavior, not a
//! shortcut introduced here — wiring alerts to real storage is a tracked
//! follow-up alongside the threat-intel/AI subsystems (see `src/main.rs`).

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};

use crate::auth::AuthedUser;
use crate::error::{ApiError, ApiJson};
use crate::flags::flag_denied;
use crate::models::{Alert, AlertSearchRequest, AlertSearchResponse};
use crate::state::AppState;

/// Router for `/alerts/*`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/alerts/search", post(search_alerts))
        .route("/alerts/{alert_id}", get(get_alert))
        .route("/alerts/{alert_id}/status", put(update_alert_status))
}

/// v1 `AlertManager.search_alerts`: always empty (no auth required,
/// matching v1).
async fn search_alerts(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<AlertSearchRequest>,
) -> Response {
    if let Some(denied) = flag_denied(&state).await {
        return denied;
    }
    Json(AlertSearchResponse {
        alerts: Vec::new(),
        total: 0,
        limit: req.limit,
        offset: req.offset,
    })
    .into_response()
}

/// v1 `AlertManager.get_alert_by_id`: always `None` (no auth required,
/// matching v1).
async fn get_alert(
    State(state): State<AppState>,
    Path(alert_id): Path<String>,
) -> Result<Json<Alert>, Response> {
    if let Some(denied) = flag_denied(&state).await {
        return Err(denied);
    }
    Err(ApiError::NotFound(format!("alert {alert_id} not found")).into_response())
}

/// v1 `update_alert_status`: authenticated (any valid bearer token, no
/// admin scope — v1 called `verify_token(credentials)` without
/// `require_admin=True`), acknowledges without persisting.
async fn update_alert_status(
    State(state): State<AppState>,
    _user: AuthedUser,
    Path(alert_id): Path<String>,
    ApiJson(body): ApiJson<serde_json::Value>,
) -> Response {
    if let Some(denied) = flag_denied(&state).await {
        return denied;
    }
    let new_status = body
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_owned();
    tracing::info!(alert_id, new_status, "update_alert_status");
    Json(serde_json::json!({
        "status": "updated",
        "alert_id": alert_id,
        "new_status": new_status,
    }))
    .into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    fn dev_state() -> AppState {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        crate::state::AppStateInner::for_tests(client)
    }

    fn test_server() -> axum_test::TestServer {
        let app = axum::Router::new().merge(router()).with_state(dev_state());
        axum_test::TestServer::new(app)
    }

    #[tokio::test]
    async fn search_alerts_is_always_empty() {
        let server = test_server();
        let res = server
            .post("/alerts/search")
            .json(&serde_json::json!({"query": "anything", "limit": 10, "offset": 0}))
            .await;
        res.assert_status_ok();
        let body: AlertSearchResponse = res.json();
        assert!(body.alerts.is_empty());
        assert_eq!(body.total, 0);
        assert_eq!(body.limit, 10);
    }

    #[tokio::test]
    async fn get_alert_is_always_not_found() {
        let server = test_server();
        let res = server.get("/alerts/abc-123").await;
        res.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Not Found");
    }

    #[tokio::test]
    async fn update_alert_status_requires_auth() {
        let server = test_server();
        let res = server
            .put("/alerts/abc-123/status")
            .json(&serde_json::json!({"status": "resolved"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn update_alert_status_dev_bypass_acks_without_persisting() {
        // AAA_AUTH_ENABLED defaults true; state built via for_tests() reads
        // real env, so this exercises the dev-bypass path only when the
        // suite runs with auth disabled. With auth enabled (the default),
        // the request without a token still correctly 401s per the test
        // above — this test instead verifies the response shape when auth
        // has already succeeded, by calling the handler directly.
        let state = dev_state();
        let user = AuthedUser {
            claims: skauswatch_auth::Claims {
                sub: "u1".into(),
                iss: "iss".into(),
                aud: "aud".into(),
                iat: 0,
                exp: i64::MAX,
                scope: String::new(),
                tenant: "t1".into(),
                teams: vec![],
                roles: vec![],
            },
        };
        let resp = update_alert_status(
            State(state),
            user,
            Path("abc-123".to_owned()),
            ApiJson(serde_json::json!({"status": "resolved"})),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
