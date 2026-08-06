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

/// Signs an access token in the house `skauswatch_auth::Claims` shape,
/// carrying [`TEST_TENANT_ID`], using the given state's configured JWT
/// secret — for exercising `CurrentUser` in the common case. Role-based
/// authorization checks (`AdminOnly`/`MaintainerOnly`) key off `roles`, so
/// `role` is minted as the token's sole role entry.
#[allow(clippy::panic)]
pub(crate) fn sign_token(state: &AppState, sub: &str, role: &str) -> String {
    sign_token_for_tenant(state, sub, role, TEST_TENANT_ID)
}

/// Like [`sign_token`] but for an explicitly chosen tenant — for
/// cross-tenant-isolation tests that need two distinct tenants in play.
#[allow(clippy::panic)]
pub(crate) fn sign_token_for_tenant(
    state: &AppState,
    sub: &str,
    role: &str,
    tenant: &str,
) -> String {
    skauswatch_testkit::jwt::mint_claims_token(&state.auth.jwt_secret, sub, tenant, "", &[role])
}

/// Signs an otherwise-valid access token with an empty `tenant` claim, for
/// exercising the tenant-isolation reject path (both `CurrentUser` and the
/// router-wide `tenant_middleware` must reject this with 403, never a
/// silent fallback to some default tenant).
#[allow(clippy::panic)]
pub(crate) fn sign_token_without_tenant(state: &AppState, sub: &str, role: &str) -> String {
    skauswatch_testkit::jwt::mint_claims_token(&state.auth.jwt_secret, sub, "", "", &[role])
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
