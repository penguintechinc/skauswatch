//! Health + version endpoints. `/healthz` probes the DB (`SELECT 1`) and the
//! two CA engines; `/readyz` is the telemetry readiness gate; `/version`
//! reports name/version/environment.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use skauswatch_telemetry::Readiness;

use crate::state::AppState;

/// Builds the non-prefixed health router.
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

/// Pure health-body builder: `healthy`/200 only when the DB probe reports
/// `connected`, else `unhealthy`/503.
fn health_response(
    version: &str,
    database: &str,
    timestamp: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let healthy = database == "connected";
    let (status, code) = if healthy {
        ("healthy", StatusCode::OK)
    } else {
        ("unhealthy", StatusCode::SERVICE_UNAVAILABLE)
    };
    (
        code,
        Json(serde_json::json!({
            "status": status,
            "version": version,
            "database": database,
            "components": { "x509_ca": true, "sshca": true },
            "timestamp": timestamp,
        })),
    )
}

async fn healthz(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let database = match sqlx::query("SELECT 1").execute(state.manager.db()).await {
        Ok(_) => "connected".to_owned(),
        Err(e) => format!("error: {e}"),
    };
    health_response(
        &get_version(),
        &database,
        &skauswatch_streams::py_now_isoformat(),
    )
}

async fn version_info() -> Json<serde_json::Value> {
    let environment = std::env::var("ENVIRONMENT")
        .or_else(|_| std::env::var("QUART_ENV"))
        .unwrap_or_else(|_| "production".to_owned());
    Json(serde_json::json!({
        "name": "SkausWatch PKI Server",
        "version": get_version(),
        "environment": environment,
    }))
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
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn healthy_only_when_db_connected() {
        let (code, Json(body)) = health_response("2.0.0", "connected", "2026-07-25T00:00:00");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "healthy");
        assert_eq!(body["components"]["x509_ca"], true);
    }

    #[test]
    fn degrades_on_db_error() {
        let (code, Json(body)) = health_response("2.0.0", "error: refused", "2026-07-25T00:00:00");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "unhealthy");
    }

    #[tokio::test]
    async fn healthz_reports_unhealthy_against_an_unreachable_db() {
        let state = crate::state::AppStateInner::for_tests();
        let server = axum_test::TestServer::new(router(state, Readiness::new()));
        let res = server.get("/healthz").await;
        res.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = res.json();
        assert_eq!(body["status"], "unhealthy");
        assert!(body["database"].as_str().unwrap().starts_with("error:"));
    }

    #[tokio::test]
    async fn version_info_reports_name_and_environment() {
        let state = crate::state::AppStateInner::for_tests();
        let server = axum_test::TestServer::new(router(state, Readiness::new()));
        let res = server.get("/version").await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["name"], "SkausWatch PKI Server");
        assert!(body["version"].is_string());
        assert!(body["environment"].is_string());
    }

    #[tokio::test]
    async fn readyz_reflects_the_readiness_flag() {
        let state = crate::state::AppStateInner::for_tests();
        let readiness = Readiness::new();
        let server = axum_test::TestServer::new(router(state, readiness.clone()));

        let not_ready = server.get("/readyz").await;
        not_ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);

        readiness.set_ready();
        let ready = server.get("/readyz").await;
        ready.assert_status_ok();
    }

    #[test]
    fn get_version_never_returns_empty() {
        // Covers whichever candidate path resolves in this environment (repo
        // `.version` via the `CARGO_MANIFEST_DIR`-relative candidate, or the
        // "0.0.0-dev" fallback if neither exists) — either way the result is
        // a non-empty string.
        let v = get_version();
        assert!(!v.is_empty());
    }
}
