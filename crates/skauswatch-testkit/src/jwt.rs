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

/// Issuer/audience used by every `mint_claims_token`-minted token — matches
/// the fixture values already established across the workspace's own
/// `skauswatch_auth::Claims`-based test suites (e.g. `services/monitor`).
const CLAIMS_ISSUER: &str = "https://auth.skauswatch.app";
const CLAIMS_AUDIENCE: &str = "skauswatch";

/// Mints a valid (unexpired) HS256 token in the house tenant-aware
/// `skauswatch_auth::Claims` shape (`sub/iss/aud/iat/exp/scope/tenant/teams/
/// roles`), for services that have adopted the shared claims model per
/// `docs/v2-port/tenancy-model.md` (manager first; others fan out in R2).
/// Distinct from [`mint_access_token`], which mints the older
/// `skauswatch_auth::ServiceClaims` shape still used for service-to-service
/// gRPC auth (pki, sshca, this workspace's own gRPC surfaces) — the two
/// shapes are deliberately no longer interchangeable (see the tenancy
/// retrofit's auth-swap note). Panics on encode failure — test-infra fault,
/// never a case under test.
#[allow(clippy::panic)]
pub fn mint_claims_token(
    secret: &str,
    sub: &str,
    tenant: &str,
    scope: &str,
    roles: &[&str],
) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let claims = skauswatch_auth::Claims {
        sub: sub.to_owned(),
        iss: CLAIMS_ISSUER.to_owned(),
        aud: CLAIMS_AUDIENCE.to_owned(),
        iat: now,
        exp: now + TEST_TTL_SECONDS,
        scope: scope.to_owned(),
        tenant: tenant.to_owned(),
        teams: vec![],
        roles: roles.iter().map(|r| (*r).to_owned()).collect(),
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap_or_else(|e| panic!("skauswatch-testkit: mint claims token: {e}"))
}

/// Mints an already-expired [`mint_claims_token`]-shaped token, for
/// exercising a service's "Token expired" path without waiting on a real
/// clock.
#[allow(clippy::panic)]
pub fn mint_expired_claims_token(secret: &str, sub: &str, tenant: &str, scope: &str) -> String {
    let claims = skauswatch_auth::Claims {
        sub: sub.to_owned(),
        iss: CLAIMS_ISSUER.to_owned(),
        aud: CLAIMS_AUDIENCE.to_owned(),
        iat: 0,
        exp: 1,
        scope: scope.to_owned(),
        tenant: tenant.to_owned(),
        teams: vec![],
        roles: vec![],
    };
    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap_or_else(|e| panic!("skauswatch-testkit: mint expired claims token: {e}"))
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

    #[test]
    fn claims_token_round_trips_tenant_scope_and_roles() {
        let token = mint_claims_token("s3cret", "42", "tenant-a", "*:read *:write", &["admin"]);
        let claims = match skauswatch_auth::decode_claims(&token, "s3cret") {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(claims.sub, "42");
        assert_eq!(claims.tenant, "tenant-a");
        assert_eq!(claims.iss, CLAIMS_ISSUER);
        assert_eq!(claims.aud, CLAIMS_AUDIENCE);
        assert!(claims.has_scope("alerts:read"));
        assert_eq!(claims.roles, vec!["admin".to_owned()]);
    }

    #[test]
    fn expired_claims_token_is_rejected_as_expired() {
        let token = mint_expired_claims_token("s3cret", "1", "tenant-a", "*:read");
        match skauswatch_auth::decode_claims(&token, "s3cret") {
            Err(skauswatch_auth::TenantAuthError::Expired) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }
}
