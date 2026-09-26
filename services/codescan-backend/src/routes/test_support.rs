//! Shared test helpers for the /api/v1 route test modules.

use std::sync::Arc;

use penguin_licensing::LicenseClient;

use crate::state::{AppState, AppStateInner};

/// Fixed test tenant used by [`sign_token`] — an arbitrary, stable UUID
/// distinct from manager's real bootstrap tenant literal
/// (`00000000-0000-0000-0000-000000000001`), since this service's tests
/// never share a database with manager and only need a stable, parseable
/// UUID string.
pub(crate) const TEST_TENANT_ID: &str = "00000000-0000-0000-0000-0000000000aa";

/// A second, distinct tenant for cross-tenant-isolation tests (tenant A's
/// token must never see/modify tenant B's rows).
pub(crate) const OTHER_TENANT_ID: &str = "00000000-0000-0000-0000-0000000000bb";

/// Mirrors `services/manager/src/auth/mod.rs::role_scope_bundle` exactly —
/// the scope string a real manager-minted token carries for each role — so
/// tests exercise the same wildcard-matching `require_scope` calls
/// (`crate::auth::AdminOnly`/`MaintainerOnly`) a production token would.
/// Keep in sync if that bundle table changes (`security.md` "Scope
/// bundles"); unknown roles get no scope, matching the manager's fail-closed
/// behavior for unrecognized roles.
fn role_scope_bundle(role: &str) -> &'static str {
    match role {
        "admin" => "*:read *:write *:admin *:delete settings:write users:admin",
        "maintainer" => "*:read *:write teams:read reports:read analytics:read",
        "viewer" => "*:read",
        _ => "",
    }
}

/// Signs an access token in the house `skauswatch_auth::Claims` shape,
/// carrying [`TEST_TENANT_ID`], using the given state's configured JWT
/// secret — for exercising `CurrentUser` in the common case. Scope-based
/// authorization checks (`AdminOnly`/`MaintainerOnly`) key off `scope`, so
/// `role`'s [`role_scope_bundle`] equivalent is minted alongside it (`role`
/// itself is still carried as the token's sole `roles` entry, informational
/// only per `security.md`).
#[allow(clippy::panic)]
pub(crate) fn sign_token(state: &AppState, sub: &str, role: &str) -> String {
    sign_token_for_tenant(state, sub, role, TEST_TENANT_ID)
}

/// Like [`sign_token`] but for an explicitly chosen tenant — for
/// cross-tenant-isolation tests that need two distinct tenants in play.
#[allow(clippy::panic)]
pub(crate) fn sign_token_for_tenant(
    _state: &AppState,
    sub: &str,
    role: &str,
    tenant: &str,
) -> String {
    skauswatch_testkit::jwt::mint_claims_token(
        skauswatch_testkit::jwt::signing_key(),
        sub,
        tenant,
        role_scope_bundle(role),
        &[role],
    )
}

/// Signs an otherwise-valid access token with an empty `tenant` claim, for
/// exercising the tenant-isolation reject path (both `CurrentUser` and the
/// router-wide `tenant_middleware` must reject this with 403, never a
/// silent fallback to some default tenant).
#[allow(clippy::panic)]
pub(crate) fn sign_token_without_tenant(_state: &AppState, sub: &str, role: &str) -> String {
    skauswatch_testkit::jwt::mint_claims_token(
        skauswatch_testkit::jwt::signing_key(),
        sub,
        "",
        role_scope_bundle(role),
        &[role],
    )
}

/// Builds an `AppState` backed by a real, migrated Postgres pool (a fresh
/// isolated schema per call, via `skauswatch_testkit::db::test_pool`) —
/// for handler tests that issue real queries rather than only exercising
/// the pre-DB auth/license/validation gates. Requires a reachable Postgres
/// (see `docs/v2-port/testing-pattern.md`); panics loudly if none is
/// available rather than silently skipping DB coverage.
pub(crate) async fn db_state(license: Arc<LicenseClient>) -> AppState {
    let pool =
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await;
    AppStateInner::for_tests_with_db(license, pool)
}

/// Builds a `TestServer` around the *full* app-wide router
/// (`crate::routes::router`, not a per-module mini router) using real HTTP
/// transport with `into_make_service_with_connect_info` — required by
/// `GovernorLayer`'s `PeerIpKeyExtractor` (see `routes` module docs, "Rate
/// limiting"), which axum-test's default mock transport cannot supply.
/// Every test exercising the full router MUST go through this rather than
/// `axum_test::TestServer::new(crate::routes::router(state))` directly, or
/// every request 500s with `GovernorError::UnableToExtractKey` — the exact
/// regression this helper replaced across `routes::fix_batches`'s
/// tenant-scoping tests when the rate-limit fix first landed.
#[allow(clippy::panic)] // test-only: TestServerBuilder::build panics on failure
pub(crate) fn full_app_test_server(state: AppState) -> axum_test::TestServer {
    let make_service =
        crate::routes::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>();
    axum_test::TestServer::builder()
        .http_transport()
        .build(make_service)
}
