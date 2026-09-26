//! Test-only JWT minting for the shared manager access-token shape
//! (`{sub, role, type: "access", exp, iat}`, ES256) — the wire contract
//! verified by `skauswatch_auth::AuthenticatedCaller` (pki, sshca: router-wide
//! auth layer) and replicated locally by services with a per-handler
//! extractor instead (e.g. `codescan-backend`'s `CurrentUser`). Both
//! consumers decode the identical shape, so one minting helper — a thin
//! wrapper over the already-tested `skauswatch_auth::issue_service_token` —
//! covers every service's handler tests instead of each service hand-rolling
//! `jsonwebtoken::encode` in its own test module.
//!
//! Audit finding H1b (ES256 migration): every mint/decode helper here takes
//! an explicit `&jsonwebtoken::EncodingKey`/`&jsonwebtoken::DecodingKey`
//! rather than a shared string secret — [`signing_key`]/[`verify_key`]
//! expose the canonical throwaway ES256 (P-256) fixture keypair, generated
//! once per process at runtime (never a hardcoded PEM literal — secret
//! scanners rightly flag any embedded EC private key, test fixture or not)
//! for every service's tests to mint/verify against; [`other_signing_key`]/
//! [`other_verify_key`] expose a second, independent keypair for exercising
//! "signed with the wrong key" rejection paths.

use std::sync::OnceLock;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
use pkcs8::{EncodePrivateKey, EncodePublicKey};

/// Default TTL (seconds) for tokens minted by [`mint_access_token`]/
/// [`mint_claims_token`] — long enough that a test suite's wall-clock time
/// never causes flaky expiry.
const TEST_TTL_SECONDS: i64 = 300;

/// Generates a fresh ES256 (P-256) keypair (PKCS#8 private / SPKI public
/// PEM, matching the exact shapes `skauswatch_auth::load_jwt_signing_key`/
/// `load_jwt_verify_key` parse in production) at runtime. Panics on encode
/// or parse failure — a broken keygen path is a test-infra fault caught the
/// moment any test first calls one of the accessors below, never a case
/// under test.
#[allow(clippy::panic)]
fn generate_es256_keypair() -> (EncodingKey, DecodingKey) {
    let secret = p256::SecretKey::random(&mut rand_core::OsRng);
    let private_pem = secret
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .unwrap_or_else(|e| panic!("skauswatch-testkit: fixture keypair private PEM encode: {e}"));
    let public_pem = secret
        .public_key()
        .to_public_key_pem(pkcs8::LineEnding::LF)
        .unwrap_or_else(|e| panic!("skauswatch-testkit: fixture keypair public PEM encode: {e}"));
    let enc = EncodingKey::from_ec_pem(private_pem.as_bytes())
        .unwrap_or_else(|e| panic!("skauswatch-testkit: fixture signing key: {e}"));
    let dec = DecodingKey::from_ec_pem(public_pem.as_bytes())
        .unwrap_or_else(|e| panic!("skauswatch-testkit: fixture verify key: {e}"));
    (enc, dec)
}

fn other_fixture_keypair() -> &'static (EncodingKey, DecodingKey) {
    static KEY: OnceLock<(EncodingKey, DecodingKey)> = OnceLock::new();
    KEY.get_or_init(generate_es256_keypair)
}

/// The canonical ES256 signing (private) key every test in this workspace
/// mints against — pair with [`verify_key`]. Delegates to
/// `skauswatch_auth::test_fixture_keypair`, the single process-lifetime
/// cache shared with `services/manager::state`'s test-only key construction
/// — see that function's docs for why this can't be an independently
/// generated local keypair (cross-crate byte-identical matching is
/// load-bearing for several of this workspace's existing tests).
pub fn signing_key() -> &'static EncodingKey {
    &skauswatch_auth::test_fixture_keypair().0
}

/// The canonical ES256 verify (public) key every test in this workspace
/// verifies against — pair with [`signing_key`].
pub fn verify_key() -> &'static DecodingKey {
    &skauswatch_auth::test_fixture_keypair().1
}

/// A second, independent ES256 signing key — for minting a token that must
/// fail verification against [`verify_key`] (the "wrong key" rejection
/// path). Nothing outside this crate needs this pair to match a duplicate
/// fixture elsewhere, so it's generated fresh per process, locally.
pub fn other_signing_key() -> &'static EncodingKey {
    &other_fixture_keypair().0
}

/// The public half of [`other_signing_key`] — for verifying that a token
/// signed with [`signing_key`] fails against a mismatched verify key.
pub fn other_verify_key() -> &'static DecodingKey {
    &other_fixture_keypair().1
}

/// Mints a valid (unexpired) ES256 access token in the shared manager claim
/// shape, signed with `key`. Panics on encode failure — a test-infra fault
/// (e.g. an unserializable claim), never a case under test.
#[allow(clippy::panic)]
pub fn mint_access_token(key: &EncodingKey, sub: &str, role: &str) -> String {
    skauswatch_auth::issue_service_token(sub, role, key, TEST_TTL_SECONDS)
        .unwrap_or_else(|e| panic!("skauswatch-testkit: mint access token: {e}"))
}

/// Mints an already-expired access token, for exercising a service's 401
/// "Token expired" path without waiting on a real clock.
#[allow(clippy::panic)]
pub fn mint_expired_access_token(key: &EncodingKey, sub: &str, role: &str) -> String {
    skauswatch_auth::issue_service_token(sub, role, key, -120)
        .unwrap_or_else(|e| panic!("skauswatch-testkit: mint expired access token: {e}"))
}

/// Issuer/audience used by every `mint_claims_token`-minted token — matches
/// the fixture values already established across the workspace's own
/// `skauswatch_auth::Claims`-based test suites (e.g. `services/monitor`).
const CLAIMS_ISSUER: &str = "https://auth.skauswatch.app";
const CLAIMS_AUDIENCE: &str = "skauswatch";

/// Mints a valid (unexpired) ES256 token in the house tenant-aware
/// `skauswatch_auth::Claims` shape (`sub/iss/aud/iat/exp/scope/tenant/teams/
/// roles`), signed with `key`, for services that have adopted the shared
/// claims model per `docs/v2-port/tenancy-model.md` (manager first; others
/// fan out in R2). Distinct from [`mint_access_token`], which mints the
/// older `skauswatch_auth::ServiceClaims` shape still used for
/// service-to-service gRPC auth (pki, sshca, this workspace's own gRPC
/// surfaces) — the two shapes are deliberately no longer interchangeable
/// (see the tenancy retrofit's auth-swap note). Panics on encode failure —
/// test-infra fault, never a case under test.
#[allow(clippy::panic)]
pub fn mint_claims_token(
    key: &EncodingKey,
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
    jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, key)
        .unwrap_or_else(|e| panic!("skauswatch-testkit: mint claims token: {e}"))
}

/// Mints an already-expired [`mint_claims_token`]-shaped token, for
/// exercising a service's "Token expired" path without waiting on a real
/// clock.
#[allow(clippy::panic)]
pub fn mint_expired_claims_token(
    key: &EncodingKey,
    sub: &str,
    tenant: &str,
    scope: &str,
) -> String {
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
    jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, key)
        .unwrap_or_else(|e| panic!("skauswatch-testkit: mint expired claims token: {e}"))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn minted_token_verifies_against_the_same_keypair() {
        let token = mint_access_token(signing_key(), "1", "admin");
        let claims = match skauswatch_auth::verify_service_token(&token, verify_key()) {
            Ok(c) => c,
            Err(e) => panic!("verify: {e:?}"),
        };
        assert_eq!(claims.sub, "1");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn minted_token_is_rejected_by_the_other_keypair() {
        let token = mint_access_token(signing_key(), "1", "admin");
        assert!(skauswatch_auth::verify_service_token(&token, other_verify_key()).is_err());
    }

    #[test]
    fn expired_token_is_rejected_as_expired() {
        let token = mint_expired_access_token(signing_key(), "1", "viewer");
        match skauswatch_auth::verify_service_token(&token, verify_key()) {
            Err(skauswatch_auth::ServiceTokenError::Expired) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn claims_token_round_trips_tenant_scope_and_roles() {
        let token = mint_claims_token(
            signing_key(),
            "42",
            "tenant-a",
            "*:read *:write",
            &["admin"],
        );
        let claims = match skauswatch_auth::decode_claims(&token, verify_key()) {
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
        let token = mint_expired_claims_token(signing_key(), "1", "tenant-a", "*:read");
        match skauswatch_auth::decode_claims(&token, verify_key()) {
            Err(skauswatch_auth::TenantAuthError::Expired) => {}
            other => panic!("expected Expired, got {other:?}"),
        }
    }

    #[test]
    fn signing_key_and_verify_key_are_a_matched_pair_distinct_from_the_other_keypair() {
        // Guards against the two fixture keypairs' PEM literals ever being
        // pasted in swapped/duplicated by accident.
        let token = mint_access_token(signing_key(), "x", "admin");
        assert!(skauswatch_auth::verify_service_token(&token, verify_key()).is_ok());
        assert!(skauswatch_auth::verify_service_token(&token, other_verify_key()).is_err());

        let other_token = mint_access_token(other_signing_key(), "x", "admin");
        assert!(skauswatch_auth::verify_service_token(&other_token, other_verify_key()).is_ok());
        assert!(skauswatch_auth::verify_service_token(&other_token, verify_key()).is_err());
    }
}
