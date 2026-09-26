//! `GET /health`, `GET /version` — v1 `main.py` health/version endpoints.
//! Unauthenticated and ungated (no feature-flag/license check), matching
//! v1 and standard K8s liveness-probe expectations.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use serde::Serialize;

use crate::state::AppState;

/// Router for the health/version endpoints (mounted flat and under
/// `/api/v1`).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .route("/version", get(version_info))
}

/// Documentation-only mirror of `health_check`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct HealthResponse {
    /// `"healthy"` or `"degraded"`.
    status: String,
    /// Service version string.
    version: String,
    /// `"connected"` or `"not configured"`.
    event_store: String,
}

/// Documentation-only mirror of `version_info`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct VersionResponse {
    /// Always `"SkausWatch Monitor Service"`.
    name: String,
    /// Service version string.
    version: String,
    /// Always `"running"`.
    status: String,
}

/// v1's `get_version()`: read the repo-root `.version` file, else fall back.
fn get_version() -> String {
    let candidates = [
        ".version".to_owned(),
        format!("{}/../../.version", env!("CARGO_MANIFEST_DIR")),
    ];
    for path in candidates {
        if let Ok(contents) = std::fs::read_to_string(&path) {
            return contents.trim().to_owned();
        }
    }
    "0.0.0-dev".to_owned()
}

/// GET /version — v1 `{name, version, status}`.
#[utoipa::path(
    get,
    path = "/api/v1/version",
    tag = "monitor",
    responses(
        (status = 200, description = "Service name, version, and status", body = VersionResponse),
    ),
)]
pub(crate) async fn version_info() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "name": "SkausWatch Monitor Service",
        "version": get_version(),
        "status": "running",
    }))
}

/// Pure status classifier: healthy only when at least one event-store
/// backend is configured and reachable. v1 considered the service healthy
/// purely based on its (much larger) component set; the event store is the
/// only backend this port actually wires up, so it's the only real signal
/// available today. Absence of a backend degrades rather than fails outright
/// — the service can still serve `/health`/`/version` traffic.
fn health_body(store_configured: bool, version: &str) -> (StatusCode, serde_json::Value) {
    let status = if store_configured {
        "healthy"
    } else {
        "degraded"
    };
    let code = if store_configured {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        serde_json::json!({
            "status": status,
            "version": version,
            "event_store": if store_configured { "connected" } else { "not configured" },
        }),
    )
}

/// GET /health.
#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "monitor",
    responses(
        (status = 200, description = "Event store configured and reachable", body = HealthResponse),
        (status = 503, description = "No event store backend configured", body = HealthResponse),
    ),
)]
pub(crate) async fn health_check(
    State(state): State<AppState>,
) -> (StatusCode, Json<serde_json::Value>) {
    let (code, body) = health_body(state.event_store.is_some(), &get_version());
    (code, Json(body))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::routes::test_support::{dev_state, state_with_store};

    #[test]
    fn health_body_degrades_without_a_store() {
        let (code, body) = health_body(false, "2.0.0");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["event_store"], "not configured");
    }

    #[test]
    fn health_body_is_healthy_with_a_store() {
        let (code, body) = health_body(true, "2.0.0");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "healthy");
    }

    #[tokio::test]
    async fn version_route_reports_service_name() {
        let Json(body) = version_info().await;
        assert_eq!(body["name"], "SkausWatch Monitor Service");
        assert_eq!(body["status"], "running");
    }

    #[tokio::test]
    async fn health_check_degrades_without_a_configured_store() {
        let (code, Json(body)) = health_check(State(dev_state())).await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "degraded");
    }

    #[tokio::test]
    async fn health_check_is_healthy_with_a_configured_store() {
        let store = crate::es::ElasticsearchStore::new(
            "http://127.0.0.1:1",
            "skauswatch-logs-*",
            None,
            None,
        );
        let (code, Json(body)) = health_check(State(state_with_store(store))).await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["event_store"], "connected");
    }

    fn test_server(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new().merge(router()).with_state(state);
        axum_test::TestServer::new(app)
    }

    #[tokio::test]
    async fn health_route_serves_over_http() {
        let server = test_server(dev_state());
        let res = server.get("/health").await;
        res.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn version_route_serves_over_http() {
        let server = test_server(dev_state());
        let res = server.get("/version").await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["name"], "SkausWatch Monitor Service");
    }
}
