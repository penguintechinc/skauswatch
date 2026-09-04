//! Telemetry bootstrap shared by all skauswatch services: JSON structured
//! logging (tracing), Prometheus metrics on :9090, and the standard
//! `/healthz` + `/readyz` axum router required by every deployment.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};

/// Standard Prometheus metrics port for all PenguinTech services.
pub const METRICS_PORT: u16 = 9090;

/// Errors raised while bootstrapping telemetry.
#[derive(Debug, thiserror::Error)]
pub enum TelemetryError {
    /// The Prometheus exporter could not bind or install.
    #[error("metrics exporter error: {0}")]
    Metrics(String),
}

/// Initializes JSON structured logging with `RUST_LOG`-style env filtering.
/// Call once at service startup, before any tracing macros fire.
pub fn init_tracing(service: &str) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    tracing::info!(service, "telemetry initialized");
}

/// Installs the Prometheus exporter listening on `0.0.0.0:9090`.
/// Returns an error instead of panicking so callers can fail startup cleanly.
pub fn install_metrics_exporter() -> Result<(), TelemetryError> {
    let addr: SocketAddr = ([0, 0, 0, 0], METRICS_PORT).into();
    metrics_exporter_prometheus::PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| TelemetryError::Metrics(e.to_string()))
}

/// Shared readiness flag: services flip this once dependencies (DB, cache,
/// license client) are up; `/readyz` reports 503 until then.
#[derive(Clone, Default)]
pub struct Readiness(Arc<AtomicBool>);

impl Readiness {
    /// Creates a not-yet-ready flag.
    pub fn new() -> Self {
        Self::default()
    }

    /// Marks the service ready to receive traffic.
    pub fn set_ready(&self) {
        self.0.store(true, Ordering::Release);
    }

    /// Returns whether the service has been marked ready.
    pub fn is_ready(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

/// Builds the standard health router exposing `/healthz` (liveness, always
/// 200 once the process serves HTTP) and `/readyz` (readiness-gated).
pub fn health_router(readiness: Readiness) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(readiness)
}

async fn healthz() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
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
mod tests {
    use super::*;

    #[tokio::test]
    async fn healthz_is_ok_and_readyz_gates_on_flag() {
        let readiness = Readiness::new();
        let server = axum_test::TestServer::new(health_router(readiness.clone()));

        server.get("/healthz").await.assert_status_ok();
        server
            .get("/readyz")
            .await
            .assert_status(StatusCode::SERVICE_UNAVAILABLE);

        readiness.set_ready();
        server.get("/readyz").await.assert_status_ok();
    }
}
