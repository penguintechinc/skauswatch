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
//!
//! Rate limiting (HIGH security hardening): [`GovernorLayer`] wraps
//! `/api/v1` as the new outermost layer — even further out than
//! `tenant_middleware` — so an excess-rate client is rejected with 429
//! before any token decode/DB work runs. Per-client-IP
//! (`PeerIpKeyExtractor`, `tower_governor`'s own recommended default);
//! `health::router`/metrics (merged separately in `main.rs::serve`, outside
//! this router) are deliberately NOT rate limited — k8s liveness probes and
//! Prometheus scraping must never 429. Requires the server to be bound with
//! `Router::into_make_service_with_connect_info::<SocketAddr>()`
//! (`main.rs::serve`) — without it `PeerIpKeyExtractor` has no peer address
//! to key on and every request fails closed with 500
//! (`GovernorError::UnableToExtractKey`); `routes::tests::full_server` does
//! the same for the app-wide test router.

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
use tower_governor::GovernorLayer;
use tower_governor::governor::GovernorConfigBuilder;

use crate::state::AppState;

/// Sustained per-client-IP request rate (requests/second, the rate the
/// burst bucket refills at) once the burst allowance is exhausted —
/// overridable via the `RATE_LIMIT_PER_SECOND` env var.
const DEFAULT_RATE_LIMIT_PER_SECOND: u64 = 10;
/// Per-client-IP burst allowance (requests) before rate limiting kicks in —
/// overridable via the `RATE_LIMIT_BURST_SIZE` env var.
const DEFAULT_RATE_LIMIT_BURST_SIZE: u32 = 20;

/// Reads an env var as the given numeric type, falling back to `default` on
/// absence *or* an unparseable value — never fails startup over a malformed
/// rate-limit override.
fn env_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

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
    // See module docs "Rate limiting": construction must not panic, so an
    // invalid override falls back to tower_governor's own built-in default
    // (8-request burst, 500ms refill) with a warning rather than crashing.
    let per_second = env_or("RATE_LIMIT_PER_SECOND", DEFAULT_RATE_LIMIT_PER_SECOND);
    let burst_size = env_or("RATE_LIMIT_BURST_SIZE", DEFAULT_RATE_LIMIT_BURST_SIZE);
    let governor_conf = GovernorConfigBuilder::default()
        .per_second(per_second)
        .burst_size(burst_size)
        .finish()
        .unwrap_or_else(|| {
            tracing::warn!(
                per_second,
                burst_size,
                "invalid RATE_LIMIT_PER_SECOND/RATE_LIMIT_BURST_SIZE (both must be non-zero); \
                 falling back to tower_governor's built-in default"
            );
            Default::default()
        });

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
        ))
        // Outermost: rejects an excess-rate client with 429 before any
        // token decode/tenant/DB work runs — see module docs.
        .layer(GovernorLayer::new(governor_conf));

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
    /// (and, since the rate-limit fix, [`GovernorLayer`]) is actually
    /// mounted, so only tests against this server exercise either. See
    /// [`test_support::full_app_test_server`] for why this must go through
    /// real HTTP transport with connect info rather than
    /// `axum_test::TestServer::new` directly.
    async fn full_server() -> (axum_test::TestServer, crate::state::AppState) {
        let state = test_support::db_state(dev_license()).await;
        (test_support::full_app_test_server(state.clone()), state)
    }

    /// Like [`full_server`] but backed by a lazy (unconnected) test pool —
    /// for tests that only need to exercise the outermost layers
    /// ([`GovernorLayer`]/`tenant_middleware`) against requests that are
    /// rejected before any handler (and therefore any DB access) runs.
    fn full_server_no_db() -> axum_test::TestServer {
        test_support::full_app_test_server(crate::state::AppStateInner::for_tests(dev_license()))
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

    /// [`GovernorLayer`] is the outermost layer, so it counts every request
    /// against the per-IP burst regardless of what the inner service would
    /// eventually return — an unauthenticated request (401, well before any
    /// handler runs) still consumes a token, so this test needs no minted
    /// JWT. `DEFAULT_RATE_LIMIT_BURST_SIZE` requests are allowed through
    /// (all still 401, having consumed the burst); the next one is rejected
    /// with 429 before reaching `tenant_middleware`/`CurrentUser` at all.
    #[tokio::test]
    async fn rate_limit_returns_429_after_burst_is_exhausted() {
        let server = full_server_no_db();
        for _ in 0..DEFAULT_RATE_LIMIT_BURST_SIZE {
            let resp = server.get("/api/v1/codescan/status").await;
            resp.assert_status(StatusCode::UNAUTHORIZED);
        }
        let resp = server.get("/api/v1/codescan/status").await;
        resp.assert_status(StatusCode::TOO_MANY_REQUESTS);
    }
}
