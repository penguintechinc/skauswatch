//! Feature-flag gate for the aaa-monitor business routes. Uses the
//! `skauswatch.aaa-monitor` key from the canonical flag registry
//! (`services/manager/src/flags.rs::CORE_FLAGS`) — v1 had no feature-flag
//! concept at all; this is a house-standard addition (`general.md` Feature
//! Toggling & License Enforcement: "Every feature MUST be behind a
//! toggle"), not a preserved v1 behavior.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// The flag key gating events/alerts/dashboard — kept in sync with
/// `services/manager/src/flags.rs::CORE_FLAGS`.
pub const AAA_MONITOR_FLAG: &str = "skauswatch.aaa-monitor";

/// Returns a 403 response if the flag is off; `None` (proceed) otherwise.
/// Mirrors `services/manager/src/routes/darwin.rs::license_denied`.
pub async fn flag_denied(state: &AppState) -> Option<Response> {
    if state.license.flag_enabled(AAA_MONITOR_FLAG).await {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Forbidden",
                    "detail": "AAA monitor is not enabled for this deployment.",
                })),
            )
                .into_response(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    fn dev_license() -> std::sync::Arc<LicenseClient> {
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
    async fn dev_bypass_allows_the_flag() {
        let state = crate::state::AppStateInner::for_tests(dev_license());
        assert!(flag_denied(&state).await.is_none());
    }
}
