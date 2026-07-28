//! Test-only JWT minting for the shared manager access-token shape
//! (`{sub, role, type: "access", exp, iat}`, HS256) — the wire contract
//! verified by `skauswatch_auth::AuthenticatedCaller` (pki, sshca: router-wide
//! auth layer) and replicated locally by services with a per-handler
//! extractor instead (e.g. `codescan-backend`'s `CurrentUser`). Both
//! consumers decode the identical shape, so one minting helper — a thin
//! wrapper over the already-tested `skauswatch_auth::issue_service_token` —
//! covers every service's handler tests instead of each service hand-rolling
//! `jsonwebtoken::encode` in its own test module.

/// Default TTL (seconds) for tokens minted by [`mint_access_token`] — long
/// enough that a test suite's wall-clock time never causes flaky expiry.
const TEST_TTL_SECONDS: i64 = 300;

/// Mints a valid (unexpired) HS256 access token in the shared manager claim
/// shape, signed with `secret`. Panics on encode failure — a test-infra
/// fault (e.g. an unserializable claim), never a case under test.
#[allow(clippy::panic)]
pub fn mint_access_token(secret: &str, sub: &str, role: &str) -> String {
    skauswatch_auth::issue_service_token(sub, role, secret, TEST_TTL_SECONDS)
        .unwrap_or_else(|e| panic!("skauswatch-testkit: mint access token: {e}"))
}

/// Mints an already-expired access token, for exercising a service's 401
/// "Token expired" path without waiting on a real clock.
#[allow(clippy::panic)]
pub fn mint_expired_access_token(secret: &str, sub: &str, role: &str) -> String {
    skauswatch_auth::issue_service_token(sub, role, secret, -120)
        .unwrap_or_else(|e| panic!("skauswatch-testkit: mint expired access token: {e}"))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn minted_token_verifies_against_the_same_secret() {
        let token = mint_access_token("s3cret", "1", "admin");
        let claims = match skauswatch_auth::verify_service_token(&token, "s3cret") {
            Ok(c) => c,
            Err(e) => panic!("verify: {e:?}"),
        };
        assert_eq!(claims.sub, "1");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn expired_token_is_rejected_as_expired() {
        let token = mint_expired_access_token("s3cret", "1", "viewer");
        match skauswatch_auth::verify_service_token(&token, "s3cret") {
            Err(skauswatch_auth::ServiceTokenError::Expired) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }
}
