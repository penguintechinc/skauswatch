//! Shared test helpers for the /api/v1 route test modules.

use jsonwebtoken::{EncodingKey, Header};
use serde::Serialize;

use crate::state::AppState;

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
