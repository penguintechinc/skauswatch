//! Shared test helpers for the /api/v1 route (and gRPC) test modules —
//! mirrors `services/codescan-backend/src/routes/test_support.rs` per
//! `docs/v2-port/testing-pattern.md`.

use std::path::Path;
use std::sync::Arc;

use penguin_licensing::LicenseClient;
use sqlx::PgPool;

use crate::state::{AppState, AppStateInner};

/// Builds an `AppState` backed by a real, migrated Postgres pool holding
/// only the tables this service owns (`migrations/0001_manager_schema.sql`)
/// — for handler tests that never touch s3scan-owned tables.
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

/// Inserts an active `users` row and returns its generated id — the
/// prerequisite every authed handler test needs, since `CurrentUser`
/// (`src/auth/mod.rs`) re-fetches the caller from `users` on every request.
#[allow(clippy::panic)] // test-only helper fails loudly by design
pub(crate) async fn seed_user(pool: &PgPool, email: &str, role: &str) -> i32 {
    let row: (i32,) = sqlx::query_as(
        "INSERT INTO users (email, password_hash, full_name, role, is_active, mfa_enabled, \
         created_at) VALUES ($1, '$2b$12$abcdefghijklmnopqrstuv', 'Test User', $2, true, false, \
         now()) RETURNING id",
    )
    .bind(email)
    .bind(role)
    .fetch_one(pool)
    .await
    .unwrap_or_else(|e| panic!("seed_user({email}, {role}): {e}"));
    row.0
}

/// Seeds a user then mints a matching access token (`skauswatch_testkit::jwt`
/// — same `{sub,role,type:"access",exp,iat}` shape `CurrentUser` verifies).
/// Returns `(user_id, bearer_token)`.
pub(crate) async fn authed_user(state: &AppState, email: &str, role: &str) -> (i32, String) {
    let id = seed_user(&state.db, email, role).await;
    let token =
        skauswatch_testkit::jwt::mint_access_token(&state.auth.jwt_secret, &id.to_string(), role);
    (id, token)
}
