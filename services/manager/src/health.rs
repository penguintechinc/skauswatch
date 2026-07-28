//! v1-parity health endpoints. `GET /healthz` returns the Quart manager's
//! `{status,version,database,redis,timestamp}` body (200 healthy / 503
//! otherwise, probing DB `SELECT 1` + Redis PING); `GET /readyz` keeps the
//! telemetry readiness gate with the v1 `{status:"ready"}` shape.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use skauswatch_telemetry::Readiness;

use crate::state::AppState;

/// Builds the non-prefixed health router (`/healthz` + `/readyz`), replacing
/// the generic `skauswatch_telemetry::health_router` for the manager.
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

/// GET /version — v1 `{name, version, environment}`; environment mirrors
/// v1's `QUART_ENV` default "production" (ENVIRONMENT honored first for
/// the Rust deployment).
async fn version_info() -> Json<serde_json::Value> {
    let environment = std::env::var("ENVIRONMENT")
        .or_else(|_| std::env::var("QUART_ENV"))
        .unwrap_or_else(|_| "production".to_owned());
    Json(serde_json::json!({
        "name": "SkausWatch Manager Service",
        "version": get_version(),
        "environment": environment,
    }))
}

/// v1 `get_version()`: read the repo-root `.version` file, else "0.0.0-dev".
/// Runtime lookup order: `.version` in the working directory (container
/// WORKDIR), then the build-tree repo root (cargo run/test), then fallback.
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

/// Pure v1 response builder: `healthy`/200 only when both probes report
/// `connected`, otherwise `unhealthy`/503. Key order matches v1.
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

/// GET /healthz — v1 probe semantics: DB `SELECT 1` → "connected" or
/// "error: {e}"; Redis PING → "connected", "not initialized" (no producer),
/// or "error: {e}".
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

/// GET /readyz — v1 always answers `{status:"ready"}` 200; the readiness
/// gate only bites before the listener is up, so the wire shape matches.
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
        assert_eq!(body["version"], "2.0.0");
        assert_eq!(body["database"], "connected");
        assert_eq!(body["redis"], "connected");
        assert_eq!(body["timestamp"], "2026-07-22T00:00:00.000000");
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
        assert_eq!(body["database"], "error: connection refused");
    }

    #[test]
    fn health_response_degrades_on_redis_not_initialized() {
        let (code, Json(body)) = health_response(
            "2.0.0",
            "connected",
            "not initialized",
            "2026-07-22T00:00:00.000000",
        );
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["redis"], "not initialized");
    }

    #[test]
    fn version_comes_from_repo_version_file_in_dev() {
        // The build tree has a repo-root .version; must not fall back.
        assert_ne!(get_version(), "0.0.0-dev");
    }

    #[tokio::test]
    async fn healthz_reports_v1_shape_when_degraded() {
        // Test state: unreachable lazy DB pool + no stream producer.
        let server = axum_test::TestServer::new(router(test_state(), Readiness::new()));
        let resp = server.get("/healthz").await;
        resp.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = resp.json();
        assert_eq!(body["status"], "unhealthy");
        assert_eq!(body["redis"], "not initialized");
        let db = body["database"].as_str().unwrap_or_default();
        assert!(db.starts_with("error: "), "database was: {db}");
        assert!(body["version"].is_string());
        assert!(body["timestamp"].is_string());
    }

    #[tokio::test]
    async fn healthz_reports_database_connected_against_real_db() {
        let license = skauswatch_testkit::license::dev_license("skauswatch");
        let state = crate::routes::test_support::db_state(license).await;
        let server = axum_test::TestServer::new(router(state, Readiness::new()));
        let resp = server.get("/healthz").await;
        let body: serde_json::Value = resp.json();
        assert_eq!(body["database"], "connected");
        // Streams producer is still None in tests, so overall status stays
        // unhealthy even with a real DB — see `for_tests_with_db`.
        assert_eq!(body["redis"], "not initialized");
        assert_eq!(body["status"], "unhealthy");
    }

    #[tokio::test]
    async fn version_endpoint_reports_name_version_and_environment() {
        let server = axum_test::TestServer::new(router(test_state(), Readiness::new()));
        let resp = server.get("/version").await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["name"], "SkausWatch Manager Service");
        assert!(body["version"].is_string());
        assert!(body["environment"].is_string());
    }

    #[tokio::test]
    async fn readyz_keeps_v1_ready_shape() {
        let readiness = Readiness::new();
        let server = axum_test::TestServer::new(router(test_state(), readiness.clone()));
        server
            .get("/readyz")
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);
        readiness.set_ready();
        let resp = server.get("/readyz").await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["status"], "ready");
    }
}
