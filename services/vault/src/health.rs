//! v1-parity health endpoints — Rust port of `main.py`'s `/healthz`,
//! `/readyz`, and `/api/v1/status`. Unlike the manager, v1 Vault's
//! `/healthz` is a bare liveness probe (no DB/Redis probing); `/readyz`
//! reports license state.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};

use crate::state::{AppState, VAULT_FLAG};

/// Builds the non-prefixed health router (`/healthz`, `/readyz`) plus the
/// license-gate-exempt `/api/v1/status` version endpoint.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/v1/status", get(status))
        .with_state(state)
}

/// v1 `get_version()`: read the repo-root `.version` file, else "0.0.0-dev".
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

/// GET /healthz — v1 liveness probe: always `{"status":"healthy",...}` 200.
async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": skauswatch_streams::py_now_isoformat(),
    }))
}

/// GET /readyz — v1 readiness probe: `{"status","licensed","timestamp"}`,
/// 503 while the `skauswatch.vault` flag is disabled and not bypassed.
async fn readyz(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let licensed = state.license.flag_enabled(VAULT_FLAG).await;
    let code = if licensed {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        code,
        Json(serde_json::json!({
            "status": if licensed { "ready" } else { "degraded" },
            "licensed": licensed,
            "timestamp": skauswatch_streams::py_now_isoformat(),
        })),
    )
}

/// GET /api/v1/status — v1 version endpoint for the webui ConsoleVersion
/// component. Not in v1's license-gate bypass list, so it stays behind the
/// gate middleware like every other `/api/v1/*` route (preserved as-is).
async fn status() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version": get_version(),
        "service": "vault",
        "timestamp": skauswatch_streams::py_now_isoformat(),
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use skauswatch_vault::EnvelopeEncryption;

    use super::*;
    use crate::state::AppStateInner;

    fn gated_state() -> AppState {
        let mut cfg = LicenseConfig::new("skauswatch").expect("config");
        cfg.release_mode = true;
        let client = LicenseClient::new(cfg).expect("client");
        AppStateInner::for_tests(client, EnvelopeEncryption::default())
    }

    #[tokio::test]
    async fn healthz_is_always_ok() {
        let server = axum_test::TestServer::new(router(gated_state()));
        let resp = server.get("/healthz").await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["status"], "healthy");
    }

    #[tokio::test]
    async fn readyz_reports_degraded_when_unlicensed() {
        let server = axum_test::TestServer::new(router(gated_state()));
        let resp = server.get("/readyz").await;
        resp.assert_status(StatusCode::SERVICE_UNAVAILABLE);
        let body: serde_json::Value = resp.json();
        assert_eq!(body["status"], "degraded");
        assert_eq!(body["licensed"], false);
    }
}
