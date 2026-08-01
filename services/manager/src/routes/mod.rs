//! /api/v1 router assembly. Routers are ported from the Quart service one
//! module at a time; each mounts its feature-flag gate when it lands.
//!
//! Tenant-isolation layering (docs/v2-port/tenancy-model.md): the app-wide
//! router splits into three tiers, not two, because this service has more
//! than one non-bearer-JWT auth surface:
//!
//! 1. **Public** — no credential of any kind: `auth::login`/`refresh`/
//!    `register`, `openapi::public_router` (the login-only doc). None of
//!    these can carry a `tenant` claim (there's no token yet), so none may
//!    sit behind `tenant_middleware`.
//! 2. **Agent (HMAC)** — `endpoint::agent_router`: ENDPOINT agents
//!    authenticate via `X-API-Key`/`X-Agent-ID`, never a bearer JWT. Their
//!    tenant is resolved server-side from `endpoint_agents.tenant_id`
//!    (§3 of the design doc), a wholly different provenance mechanism
//!    `tenant_middleware` (JWT-only) cannot serve — wrapping this tier in it
//!    would reject every agent request before the HMAC check ever runs.
//! 3. **Protected (JWT)** — every other route. Wrapped in
//!    `skauswatch_auth::tenant_middleware` as the OUTERMOST layer (per that
//!    function's ordering contract: the last `.layer()` call runs first),
//!    so a request without a usable tenant claim is rejected before it ever
//!    reaches a handler. Handlers still independently enforce the same
//!    boundary via `CurrentUser` (`src/auth/mod.rs::decode_access`) — this
//!    layer is defense in depth for exactly this tier, not a replacement
//!    for it, since `CurrentUser` is also reachable through per-module test
//!    routers that never mount this middleware.

mod alerts;
mod approvals;
mod asm;
mod auth;
mod codescan;
mod endpoint;
mod license;
pub(crate) mod openapi;
mod research;
mod s3_scan;
mod siem;
mod tenants;
#[cfg(test)]
pub(crate) mod test_support;
mod threat_intel;
mod users;

use axum::Router;
use penguin_licensing::axum::{FlagGate, flag_gate};

use crate::state::AppState;

/// Wraps `router` in the crate-provided PostHog flag gate
/// (`penguin_licensing::axum::{FlagGate, flag_gate}` — see that module's own
/// doc example) rather than hand-rolling nine near-identical middleware
/// functions: 403 `{"error":"feature_disabled","flag":"<flag>"}` while
/// `flag` evaluates disabled for this deployment (dev/domain bypass
/// included via `LicenseClient::flag_enabled`). Applied to a module's
/// router BEFORE it merges into `protected` below, so it sits innermost
/// relative to `tenant_middleware` — matching this crate's
/// tenant → scope → feature layering contract (module docs above; see also
/// `skauswatch_auth::tenant_middleware`'s ordering note).
fn gated(router: Router<AppState>, state: &AppState, flag: &'static str) -> Router<AppState> {
    router.layer(axum::middleware::from_fn_with_state(
        FlagGate::new(state.license.clone(), flag),
        flag_gate,
    ))
}

/// Builds the full /api/v1 application router.
pub fn router(state: AppState) -> Router {
    let public = auth::public_router().merge(openapi::public_router());

    // Gated on the same flag as the operator half — see `flags::CORE_FLAGS`
    // `skauswatch.endpoint` and the module docs above (HMAC agent tier).
    let agent = gated(endpoint::agent_router(), &state, "skauswatch.endpoint");

    let protected = auth::protected_router()
        .merge(license::router())
        .merge(gated(users::router(), &state, "skauswatch.users"))
        .merge(tenants::router())
        .merge(gated(alerts::router(), &state, "skauswatch.alerts"))
        .merge(gated(
            threat_intel::router(),
            &state,
            "skauswatch.threat-intel",
        ))
        .merge(gated(approvals::router(), &state, "skauswatch.approvals"))
        .merge(gated(s3_scan::router(), &state, "skauswatch.s3-scan"))
        .merge(gated(
            endpoint::operator_router(),
            &state,
            "skauswatch.endpoint",
        ))
        .merge(gated(siem::router(), &state, "skauswatch.siem"))
        .merge(gated(asm::router(), &state, "skauswatch.asm"))
        .merge(codescan::router())
        .merge(gated(research::router(), &state, "skauswatch.research"))
        .merge(openapi::protected_router())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            skauswatch_auth::tenant_middleware::<AppState>,
        ));

    Router::new()
        .nest("/api/v1", public.merge(agent).merge(protected))
        .with_state(state)
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use axum::http::StatusCode;

    use super::{router, test_support};

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
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
    async fn protected_route_rejects_token_with_no_tenant_claim() {
        let (server, state) = full_server().await;
        let (id, _) = test_support::authed_user(&state, "no-tenant-mw@example.com", "admin").await;
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.auth.jwt_secret,
            &id.to_string(),
            "", // no tenant claim
            crate::auth::role_scope_bundle("admin"),
            &["admin"],
        );
        let res = server
            .get("/api/v1/auth/me")
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn protected_route_allows_a_valid_tenant_bearing_token() {
        let (server, state) = full_server().await;
        let (_, token) =
            test_support::authed_user(&state, "with-tenant-mw@example.com", "admin").await;
        let res = server
            .get("/api/v1/auth/me")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
    }

    #[tokio::test]
    async fn public_login_is_reachable_without_tenant_middleware_intercepting() {
        let (server, _state) = full_server().await;
        // A bad-credentials login must reach the handler (401 "Invalid email
        // or password"), not be rejected by tenant_middleware (which would
        // 401 "Missing or invalid authorization header" — a different
        // message — since there's no bearer token at all here).
        let res = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "ghost@example.com", "password": "whatever1"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Invalid email or password");
    }

    #[tokio::test]
    async fn agent_route_is_not_gated_by_tenant_middleware() {
        let (server, _state) = full_server().await;
        // No bearer token at all — if tenant_middleware wrapped this route
        // it would answer "Missing or invalid authorization header"; the
        // EndpointAgent HMAC extractor's distinct message proves the
        // request reached the agent tier's own auth check instead.
        let res = server.post("/api/v1/endpoint/heartbeat").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Missing API key or Agent ID");
    }

    // -- per-module feature-flag gates (finding #4) -------------------------

    #[tokio::test]
    async fn flag_off_hides_every_newly_gated_module_route() {
        let pool = test_support::db_state(dev_license()).await.db.clone();
        let gated = crate::state::AppStateInner::for_tests_with_db(
            skauswatch_testkit::license::gated_license("skauswatch"),
            pool,
        );
        let (_, token) = test_support::authed_user(&gated, "flagged@example.com", "admin").await;
        let server = axum_test::TestServer::new(router(gated));

        // One representative route per gated module — each must 403 with the
        // crate-provided flag_gate body while its flag is off, never a 404
        // (which would mean the route was never mounted at all) or a 200
        // (which would mean the gate never ran).
        for (method_path, flag) in [
            ("GET /api/v1/users", "skauswatch.users"),
            ("GET /api/v1/alerts", "skauswatch.alerts"),
            ("GET /api/v1/threat-intel/iocs", "skauswatch.threat-intel"),
            ("GET /api/v1/approvals", "skauswatch.approvals"),
            ("GET /api/v1/s3-scan/buckets", "skauswatch.s3-scan"),
            ("GET /api/v1/endpoint/agents", "skauswatch.endpoint"),
            ("GET /api/v1/siem/config", "skauswatch.siem"),
            ("GET /api/v1/asm/scans", "skauswatch.asm"),
            ("GET /api/v1/research/config", "skauswatch.research"),
        ] {
            let path = method_path.split_once(' ').map_or(method_path, |(_, p)| p);
            let res = server.get(path).authorization_bearer(&token).await;
            assert_eq!(
                res.status_code(),
                StatusCode::FORBIDDEN,
                "expected 403 for {method_path}, got {}",
                res.status_code()
            );
            let body: serde_json::Value = res.json();
            assert_eq!(body["error"], "feature_disabled", "route: {method_path}");
            assert_eq!(body["flag"], flag, "route: {method_path}");
        }

        // The agent (HMAC) tier shares the endpoint flag too.
        let agent_res = server
            .post("/api/v1/endpoint/heartbeat")
            .add_header("X-Agent-ID", "a")
            .add_header("X-API-Key", "whatever-fails-hmac-first-if-flag-were-off")
            .await;
        // Flag gate runs BEFORE the HMAC extractor in the agent tier's own
        // layer ordering (gate wraps the whole agent_router), so a bad HMAC
        // never even gets evaluated — this must still be the flag_gate body,
        // not "Invalid API key".
        agent_res.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = agent_res.json();
        assert_eq!(body["error"], "feature_disabled");

        // Ungated routes (license, tenants, codescan — its own separate
        // module flag) must still work under the same gated license.
        let license_res = server
            .get("/api/v1/license/features")
            .authorization_bearer(&token)
            .await;
        license_res.assert_status_ok();
    }

    #[tokio::test]
    async fn dev_bypass_allows_every_newly_gated_module_route() {
        // Already implicitly covered by the rest of this suite (every other
        // test here runs under `dev_license()`), but asserted directly once
        // for a module outside the always-tested `/auth/me` path.
        let (server, state) = full_server().await;
        let (_, token) = test_support::authed_user(&state, "unflagged@example.com", "admin").await;
        let res = server
            .get("/api/v1/users")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
    }
}
