//! /api/v1 router assembly for the CodeScan backend. Every route here is the
//! upstream target the manager proxies to at
//! `{WORKER_CODESCAN_URL}/api/v1/codescan{path}` (services/manager/src/routes/codescan.rs)
//! plus the git-credential CRUD surface at `/api/v1/credentials`
//! (darwin/services/flask-backend/app/api/v1/credentials.py) and the
//! license-compliance policy CRUD surface at `/api/v1/license-policies`
//! (net-new — see `license_policies` module docs).
//!
//! Tenant-isolation layering (docs/v2-port/tenancy-model.md): unlike the
//! manager, this service has no public (unauthenticated) or agent-HMAC
//! surface at all — every route already requires a `CurrentUser` bearer
//! token, so there is no public/protected split to make here. The whole
//! `/api/v1` router is wrapped in `skauswatch_auth::tenant_middleware` as
//! the OUTERMOST layer (per that function's ordering contract: the last
//! `.layer()` call runs first), rejecting a request with no usable `tenant`
//! claim before it reaches any handler. Handlers still independently
//! enforce the same boundary via `CurrentUser` (`crate::auth::decode_access`)
//! — this middleware is defense in depth, not a replacement, since
//! `CurrentUser` is also reachable through the per-module test routers in
//! `routes/*.rs` tests, which never mount it.

mod credentials;
mod findings;
mod fix_batches;
mod license_policies;
pub(crate) mod openapi;
mod plans;
mod policy_rules;
mod repos;
mod reviews;
mod status;
#[cfg(test)]
pub(crate) mod test_support;

use axum::Router;
use axum::response::{IntoResponse, Response};
use axum::{Json, http::StatusCode};

use crate::state::AppState;

/// PostHog module flag gating every codescan route — the v2 equivalent of v1
/// `has_feature("codescan")` (see services/manager/src/routes/codescan.rs, which
/// gates the same way one layer up before proxying here).
pub(crate) const CODESCAN_FLAG: &str = "skauswatch.codescan";
/// v1 bare 403 body text when the codescan feature is not licensed.
const LICENSE_MSG: &str = "CodeScan AI review requires a CodeScan license.";

/// PostHog flag gating CodeScan Sentinel's report endpoints
/// (docs/v2-port/v2.1-codescan-sentinel.md §13) — independent of
/// `CODESCAN_FLAG`: Sentinel's deterministic SCA/CVE scanning stands alone
/// at Professional tier without the AI-review feature (or WaddleAI, which
/// only gates Sentinel's *AI-assisted* triage in a later phase). Must match
/// `worker-codescan`'s `sentinel::SENTINEL_FLAG` literal exactly — the same
/// flag gates the scheduler that produces the data this flag gates reading.
pub(crate) const SENTINEL_FLAG: &str = "skauswatch.codescan.sentinel";
/// 403 body text when Sentinel is not licensed/enabled.
const SENTINEL_LICENSE_MSG: &str = "CodeScan Sentinel requires the Sentinel feature to be enabled.";

/// Builds the full /api/v1 application router.
pub fn router(state: AppState) -> Router {
    let protected = status::router()
        .merge(repos::router())
        .merge(reviews::router())
        .merge(plans::router())
        .merge(credentials::router())
        .merge(license_policies::router())
        .merge(findings::router())
        .merge(policy_rules::router())
        .merge(fix_batches::router())
        .merge(openapi::router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            skauswatch_auth::tenant_middleware::<AppState>,
        ));

    Router::new().nest("/api/v1", protected).with_state(state)
}

/// Independent (defense-in-depth) license check — the manager already gates
/// `/api/v1/codescan/*` before proxying, but this service does not trust that
/// solely; every route re-checks the flag itself.
pub(crate) async fn license_denied(state: &AppState) -> Option<Response> {
    if state.license.flag_enabled(CODESCAN_FLAG).await {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": LICENSE_MSG })),
            )
                .into_response(),
        )
    }
}

/// Same pattern as [`license_denied`], gating on [`SENTINEL_FLAG`] instead.
pub(crate) async fn sentinel_denied(state: &AppState) -> Option<Response> {
    if state.license.flag_enabled(SENTINEL_FLAG).await {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": SENTINEL_LICENSE_MSG })),
            )
                .into_response(),
        )
    }
}

/// 403 body text when a P3 (AI triage / policy engine) route is used below
/// Enterprise tier.
const ENTERPRISE_LICENSE_MSG: &str =
    "CodeScan Sentinel's AI triage and policy engine require an Enterprise license.";

/// Gates CodeScan Sentinel P3 routes (docs/v2-port/v2.1-codescan-sentinel.md
/// §13: "AI-assisted capabilities ... gate at Enterprise"). Independent of
/// (and layered on top of) [`sentinel_denied`] — a route needing this also
/// calls `sentinel_denied` first, since P3 is meaningless without Sentinel
/// itself enabled.
pub(crate) async fn enterprise_denied(state: &AppState) -> Option<Response> {
    if state
        .license
        .check_tier(penguin_licensing::Tier::Enterprise)
        .await
    {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": ENTERPRISE_LICENSE_MSG })),
            )
                .into_response(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use std::sync::Arc;

    #[allow(clippy::panic)]
    fn dev_license() -> Arc<LicenseClient> {
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
    async fn license_gate_allows_under_dev_bypass() {
        let state = crate::state::AppStateInner::for_tests(dev_license());
        assert!(license_denied(&state).await.is_none());
    }

    /// Full app-wide router (this module's own [`router`], not a per-module
    /// test router) backed by a real DB — the only place `tenant_middleware`
    /// is actually mounted, so only tests against this server exercise it.
    async fn full_server() -> (axum_test::TestServer, crate::state::AppState) {
        let state = test_support::db_state(dev_license()).await;
        let server = axum_test::TestServer::new(router(state.clone()));
        (server, state)
    }

    #[tokio::test]
    async fn tenant_middleware_rejects_token_with_no_tenant_claim() {
        let (server, state) = full_server().await;
        let token = test_support::sign_token_without_tenant(&state, "1", "viewer");
        let resp = server
            .get("/api/v1/codescan/status")
            .authorization_bearer(token)
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn tenant_middleware_allows_a_valid_tenant_bearing_token() {
        let (server, state) = full_server().await;
        let token = test_support::sign_token(&state, "1", "viewer");
        let resp = server
            .get("/api/v1/codescan/status")
            .authorization_bearer(token)
            .await;
        // Reaching the handler (200, via `codescan_status`) proves
        // `tenant_middleware` let the request through — a rejection here
        // would be 401/403 before the handler ever ran.
        resp.assert_status_ok();
    }
}
