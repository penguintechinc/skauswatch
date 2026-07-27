//! Global license gate — v2 replacement for v1's DB-driven
//! `licensing/validator.py::license_middleware`. Every Vault route
//! answers 402 with the v1 body shape unless the `skauswatch.vault`
//! PostHog flag is enabled (or the deployment domain bypasses gating), per
//! `penguin-licensing` semantics — see `services/manager/src/routes/codescan.rs`
//! for the sibling pattern.

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::state::{AppState, VAULT_FLAG};

/// Paths served regardless of license state — v1 `BYPASS_PATHS`
/// (`/healthz`, `/readyz`, `/api/v1/admin/license`).
const BYPASS_PATHS: &[&str] = &["/healthz", "/readyz", "/api/v1/admin/license"];

/// Axum middleware: 402 `Vault license required` unless
/// `skauswatch.vault` evaluates enabled for this deployment.
pub async fn require_license(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if BYPASS_PATHS.contains(&request.uri().path()) {
        return Ok(next.run(request).await);
    }
    if state.license.flag_enabled(VAULT_FLAG).await {
        Ok(next.run(request).await)
    } else {
        Err(ApiError::LicenseRequired {
            license_server: state.license.config().server_url.to_string(),
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use skauswatch_vault::EnvelopeEncryption;
    use tower::ServiceExt as _;

    use super::*;
    use crate::state::AppStateInner;

    fn dev_license() -> std::sync::Arc<LicenseClient> {
        let cfg = LicenseConfig::new("skauswatch").expect("config");
        LicenseClient::new(cfg).expect("client")
    }

    fn gated_license() -> std::sync::Arc<LicenseClient> {
        let mut cfg = LicenseConfig::new("skauswatch").expect("config");
        cfg.release_mode = true;
        LicenseClient::new(cfg).expect("client")
    }

    fn app(state: AppState) -> Router {
        Router::new()
            .route("/api/v1/secrets", axum::routing::get(|| async { "ok" }))
            .route("/healthz", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_license,
            ))
            .with_state(state)
    }

    #[tokio::test]
    async fn gated_flag_denies_with_402_v1_body() {
        let state = AppStateInner::for_tests(gated_license(), EnvelopeEncryption::default());
        let resp = app(state)
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/secrets")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn dev_bypass_allows_request() {
        let state = AppStateInner::for_tests(dev_license(), EnvelopeEncryption::default());
        let resp = app(state)
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/secrets")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn healthz_bypasses_license_gate() {
        let state = AppStateInner::for_tests(gated_license(), EnvelopeEncryption::default());
        let resp = app(state)
            .oneshot(
                HttpRequest::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
