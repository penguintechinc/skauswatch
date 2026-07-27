//! `GET /metrics/dashboard` — v1 `main.py` dashboard metrics endpoint.
//!
//! v1's `AnalysisEngine.get_dashboard_metrics` is a hard-coded stub that
//! always returns every field as zero — `pattern_detector.py`,
//! `anomaly_detector.py`, and `analysis_engine.py` never compute a single
//! real statistic anywhere in the v1 codebase (confirmed by reading all
//! three files in full: each is an `__init__`-only skeleton with a
//! `logger.info(...)` and no analysis logic). This is a faithful port of
//! that (documented, real) v1 behavior, not a shortcut introduced here.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::flags::flag_denied;
use crate::models::DashboardMetrics;
use crate::state::AppState;

/// Router for the dashboard metrics endpoint.
pub fn router() -> Router<AppState> {
    Router::new().route("/metrics/dashboard", get(get_dashboard_metrics))
}

/// v1 `AnalysisEngine.get_dashboard_metrics`: always all-zero. No auth
/// required, matching v1 (the route had no `Depends(security)`).
async fn get_dashboard_metrics(State(state): State<AppState>) -> Response {
    if let Some(denied) = flag_denied(&state).await {
        return denied;
    }
    Json(DashboardMetrics::default()).into_response()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
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

    #[tokio::test]
    async fn dashboard_metrics_are_all_zero() {
        let resp = get_dashboard_metrics(State(dev_state())).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: DashboardMetrics = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body.total_events, 0);
        assert_eq!(body.critical_alerts, 0);
        assert_eq!(body.ai_analyses, 0);
    }
}
