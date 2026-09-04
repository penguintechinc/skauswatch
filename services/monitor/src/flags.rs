//! Feature-flag gate for the monitor business routes. Uses the
//! `skauswatch.monitor` key from the canonical flag registry
//! (`services/manager/src/flags.rs::MODULE_FLAGS`) — v1 had no feature-flag
//! concept at all; this is a house-standard addition (`general.md` Feature
//! Toggling & License Enforcement: "Every feature MUST be behind a
//! toggle"), not a preserved v1 behavior.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// The flag key gating events/alerts/dashboard — kept in sync with
/// `services/manager/src/flags.rs::MODULE_FLAGS`.
pub const MONITOR_FLAG: &str = "skauswatch.monitor";

/// Returns a 403 response if the flag is off; `None` (proceed) otherwise.
/// Mirrors `services/manager/src/routes/codescan.rs::license_denied`.
pub async fn flag_denied(state: &AppState) -> Option<Response> {
    flag_denied_for(
        state,
        MONITOR_FLAG,
        "monitor is not enabled for this deployment.",
    )
    .await
}

/// Generic form of [`flag_denied`] for a caller-supplied flag key — used by
/// `threat_intel::routes` to gate on `taxii::THREAT_INTEL_FLAG` instead of
/// [`MONITOR_FLAG`], with its own detail message.
pub async fn flag_denied_for(state: &AppState, flag: &str, detail: &str) -> Option<Response> {
    if state.license.flag_enabled(flag).await {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": "Forbidden",
                    "detail": detail,
                })),
            )
                .into_response(),
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dev_bypass_allows_the_flag() {
        let state = crate::state::AppStateInner::for_tests(
            skauswatch_testkit::license::dev_license("skauswatch"),
        );
        assert!(flag_denied(&state).await.is_none());
    }

    #[tokio::test]
    async fn gated_license_denies_the_flag_with_a_403_envelope() {
        let state = crate::state::AppStateInner::for_tests(
            skauswatch_testkit::license::gated_license("skauswatch"),
        );
        let resp = match flag_denied(&state).await {
            Some(r) => r,
            None => panic!("expected the gated license to deny the flag"),
        };
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
        let bytes = match axum::body::to_bytes(resp.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(e) => panic!("read body: {e}"),
        };
        let body: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => panic!("parse body: {e}"),
        };
        assert_eq!(body["error"], "Forbidden");
        assert_eq!(
            body["detail"],
            "monitor is not enabled for this deployment."
        );
    }

    #[tokio::test]
    async fn flag_denied_for_uses_the_caller_supplied_key_and_message() {
        let state = crate::state::AppStateInner::for_tests(
            skauswatch_testkit::license::gated_license("skauswatch"),
        );
        let resp =
            match flag_denied_for(&state, "skauswatch.threat-intel", "threat intel off").await {
                Some(r) => r,
                None => panic!("expected the gated license to deny the flag"),
            };
        let bytes = match axum::body::to_bytes(resp.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(e) => panic!("read body: {e}"),
        };
        let body: serde_json::Value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => panic!("parse body: {e}"),
        };
        assert_eq!(body["detail"], "threat intel off");
    }
}
