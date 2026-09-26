//! Health endpoints, matching the house shape documented in
//! docs/v2-port/manager-contract.md: `GET /healthz` ->
//! `{status,version,database,redis,timestamp}` (200 healthy / 503
//! otherwise), `GET /readyz` -> `{status:"ready"}`, `GET /version` ->
//! `{name,version,environment}`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use skauswatch_telemetry::Readiness;

use crate::state::AppState;

/// Builds the non-prefixed health router (`/healthz`, `/readyz`, `/version`).
pub fn router(state: AppState, readiness: Readiness) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/version", get(version_info))
        .with_state(state)
        .merge(
            Router::new()
                .route("/readyz", get(readyz))
                .with_state(readiness),
        )
}

async fn version_info() -> Json<serde_json::Value> {
    let environment = std::env::var("ENVIRONMENT").unwrap_or_else(|_| "production".to_owned());
    Json(serde_json::json!({
        "name": "SkausWatch CodeScan Backend",
        "version": get_version(),
        "environment": environment,
    }))
}

/// Reads the repo-root `.version` file, else falls back to a dev marker.
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

fn health_response(
    version: &str,
    database: &str,
    redis: &str,
    timestamp: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let healthy = database == "connected" && redis == "connected";
    let status = if healthy { "healthy" } else { "unhealthy" };
    let code = if healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(serde_json::json!({
            "status": status,
            "version": version,
            "database": database,
            "redis": redis,
            "timestamp": timestamp,
        })),
    )
}

async fn healthz(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let database = match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => "connected".to_owned(),
        Err(e) => format!("error: {e}"),
    };
    let redis = match &state.streams {
        None => "not initialized".to_owned(),
        Some(producer) => match producer.ping().await {
            Ok(()) => "connected".to_owned(),
            Err(e) => format!("error: {e}"),
        },
    };
    health_response(
        &get_version(),
        &database,
        &redis,
        &skauswatch_streams::py_now_isoformat(),
    )
}

async fn readyz(State(readiness): State<Readiness>) -> (StatusCode, Json<serde_json::Value>) {
    if readiness.is_ready() {
        (
            StatusCode::OK,
            Json(serde_json::json!({ "status": "ready" })),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "status": "not ready" })),
        )
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    fn test_state() -> AppState {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        AppStateInner::for_tests(client)
    }

    #[test]
    fn health_response_healthy_only_when_both_connected() {
        let (code, Json(body)) = health_response(
            "2.0.0",
            "connected",
            "connected",
            "2026-07-22T00:00:00.000000",
        );
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "healthy");
    }

    #[test]
    fn health_response_degrades_on_db_error() {
        let (code, Json(body)) = health_response(
            "2.0.0",
            "error: connection refused",
            "connected",
            "2026-07-22T00:00:00.000000",
        );
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "unhealthy");
    }

    #[tokio::test]
    async fn healthz_reports_degraded_shape_with_lazy_state() {
        let server = axum_test::TestServer::new(router(test_state(), Readiness::new()));
        let resp = server.get("/healthz").await;
        resp.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = resp.json();
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["redis"], "not initialized");
    }

    #[tokio::test]
    async fn readyz_gates_on_readiness_flag() {
        let readiness = Readiness::new();
        let server = axum_test::TestServer::new(router(test_state(), readiness.clone()));
        server
            .get("/readyz")
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        readiness.set_ready();
        server.get("/readyz").await.assert_status_ok();
    }
}
