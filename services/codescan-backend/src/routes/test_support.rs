//! Shared test helpers for the /api/v1 route test modules.

use std::sync::Arc;

use jsonwebtoken::{EncodingKey, Header};
use penguin_licensing::LicenseClient;
use serde::Serialize;

use crate::state::{AppState, AppStateInner};

#[derive(Serialize)]
struct TestClaims<'a> {
    sub: &'a str,
    role: &'a str,
    #[serde(rename = "type")]
    token_type: &'a str,
    exp: i64,
    iat: i64,
}

/// Signs an access token matching the manager's claim shape, using the
/// given state's configured JWT secret — for exercising `CurrentUser`.
#[allow(clippy::panic)]
pub(crate) fn sign_token(state: &AppState, sub: &str, role: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let claims = TestClaims {
        sub,
        role,
        token_type: "access",
        exp: now + 300,
        iat: now,
    };
    match jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(state.auth.jwt_secret.as_bytes()),
    ) {
        Ok(t) => t,
        Err(e) => panic!("sign test token: {e}"),
    }
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
