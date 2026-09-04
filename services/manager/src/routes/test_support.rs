//! Shared test helpers for the /api/v1 route (and gRPC) test modules —
//! mirrors `services/codescan-backend/src/routes/test_support.rs` per
//! `docs/v2-port/testing-pattern.md`.

use std::path::Path;
use std::sync::Arc;

use penguin_licensing::LicenseClient;
use sqlx::PgPool;

use crate::state::{AppState, AppStateInner};

/// Builds an `AppState` backed by a real, migrated Postgres pool holding
/// only the tables this service owns (`migrations/0001_manager_schema.sql`,
/// `migrations/0002_tenancy.sql`) — for handler tests that never touch
/// s3scan-owned tables.
pub(crate) async fn db_state(license: Arc<LicenseClient>) -> AppState {
    let pool =
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await;
    AppStateInner::for_tests_with_db(license, pool)
}

/// Like [`db_state`] but also layers in `services/s3scan`'s migrations
/// (`s3_bucket_configs`/`s3_scan_jobs`/`s3_scan_results`/`adhoc_scan_results`)
/// into the SAME isolated schema — `routes/s3_scan.rs` and
/// `grpc/s3_scan_service.rs` query tables owned by the s3scan worker, not by
/// this service; see `crates/skauswatch-testkit::db::test_pool_multi`.
pub(crate) async fn db_state_with_s3scan(license: Arc<LicenseClient>) -> AppState {
    let pool = skauswatch_testkit::db::test_pool_multi(&[
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")),
        Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../s3scan/migrations")),
    ])
    .await;
    AppStateInner::for_tests_with_db(license, pool)
}

/// Fixed bootstrap tenant seeded by `migrations/0002_tenancy.sql`, as a
/// `Uuid` — every test helper below binds this by default.
pub(crate) fn default_tenant_id() -> uuid::Uuid {
    crate::auth::default_tenant_uuid()
}

/// Inserts a brand-new tenant row (distinct from the seeded default) and
/// returns its id — for tests that need genuine cross-tenant isolation (two
/// real tenants, not just two users sharing the one bootstrap tenant).
#[allow(clippy::panic)] // test-only helper fails loudly by design
pub(crate) async fn seed_tenant(pool: &PgPool, slug: &str) -> uuid::Uuid {
    let row: (uuid::Uuid,) = sqlx::query_as(
        "INSERT INTO tenants (slug, name, status) VALUES ($1, $1, 'active') RETURNING id",
    )
    .bind(slug)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed_tenant({slug}): {e}"));
    row.0
}

/// Inserts an active `users` row scoped to `tenant_id` and returns its
/// generated id — the prerequisite every authed handler test needs, since
/// `CurrentUser` (`src/auth/mod.rs`) re-fetches the caller from `users` on
/// every request.
#[allow(clippy::panic)] // test-only helper fails loudly by design
pub(crate) async fn seed_user_in_tenant(
    pool: &PgPool,
    email: &str,
    role: &str,
    tenant_id: uuid::Uuid,
) -> i32 {
    let row: (i32,) = sqlx::query_as(
        "INSERT INTO users (email, password_hash, full_name, role, is_active, mfa_enabled, \
         created_at, tenant_id) VALUES ($1, '$2b$12$abcdefghijklmnopqrstuv', 'Test User', $2, \
         true, false, now(), $3) RETURNING id",
    )
    .bind(email)
    .bind(role)
    .bind(tenant_id)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed_user_in_tenant({email}, {role}): {e}"));
    row.0
}

/// Mints an access token in the house `skauswatch_auth::Claims` shape for an
/// already-seeded `(user_id, tenant_id, role)` triple.
fn mint_token(state: &AppState, user_id: i32, tenant_id: uuid::Uuid, role: &str) -> String {
    skauswatch_testkit::jwt::mint_claims_token(
        &state.auth.jwt_signing_key,
        &user_id.to_string(),
        &tenant_id.to_string(),
        crate::auth::role_scope_bundle(role),
        &[role],
    )
}

/// Seeds a user scoped to `tenant_id` then mints a matching access token
/// (`skauswatch_testkit::jwt` — the house `skauswatch_auth::Claims` shape
/// `CurrentUser` verifies). Returns `(user_id, bearer_token)`.
pub(crate) async fn authed_user_in_tenant(
    state: &AppState,
    email: &str,
    role: &str,
    tenant_id: uuid::Uuid,
) -> (i32, String) {
    let id = seed_user_in_tenant(&state.db, email, role, tenant_id).await;
    (id, mint_token(state, id, tenant_id, role))
}

/// [`authed_user_in_tenant`] pinned to the seeded default tenant — the
/// common case used by the overwhelming majority of this service's handler
/// tests, which exercise role-based authz, not tenant isolation itself.
/// Returns `(user_id, bearer_token)`.
pub(crate) async fn authed_user(state: &AppState, email: &str, role: &str) -> (i32, String) {
    authed_user_in_tenant(state, email, role, default_tenant_id()).await
}

/// Seeds a `super_admin`-role user in the default tenant and mints a
/// matching token. `super_admin` is DB-only provisioned in v2.0 (never
/// settable via the public users API — see `routes/tenants.rs` module
/// docs), so tests provision it directly here rather than through
/// `POST /api/v1/users`.
pub(crate) async fn seed_super_admin(state: &AppState, email: &str) -> (i32, String) {
    authed_user(state, email, "super_admin").await
}
