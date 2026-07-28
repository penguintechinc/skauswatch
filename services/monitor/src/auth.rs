//! Bearer-JWT authentication for the monitor API, built on the house
//! `skauswatch-auth::Claims` model (OIDC-shaped: sub/iss/aud/iat/exp/scope/
//! tenant/teams/roles — see `security.md` Authentication & Authorization).
//!
//! v1 (`main.py::verify_token`) decoded an HS256 JWT and checked
//! `"admin" in payload.get("roles", [])` or `"admin" in payload.get(
//! "scope", "")` for admin-gated routes, with no tenant claim at all. This
//! port aligns with the house standard: authorization decisions are made on
//! `scope` only (`roles` stays audit/display), and a request without a
//! valid `tenant` claim is rejected before any scope check, per
//! `security.md`'s hard tenant-isolation boundary. None of the routes
//! ported so far require the admin scope (v1's only `require_admin=True`
//! call sites live in the deferred threat-intel routes), but the extractor
//! supports it for when that group lands.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{DecodingKey, Validation};
use skauswatch_auth::Claims;

use crate::error::ApiError;
use crate::state::AppState;

/// Scope required for admin-only operations (currently unused by any ported
/// route — see module docs).
pub const ADMIN_SCOPE: &str = "monitor:admin";

/// The authenticated caller, extracted from a validated Bearer JWT.
#[derive(Debug, Clone)]
pub struct AuthedUser {
    /// Decoded, validated claims.
    pub claims: Claims,
}

impl AuthedUser {
    /// v1 `require_admin=True` equivalent, expressed as a scope check
    /// (house standard) rather than a role-name branch.
    #[allow(dead_code)] // consumed once the threat-intel admin routes land
    pub fn require_admin(&self) -> Result<(), ApiError> {
        self.claims
            .require_scope(ADMIN_SCOPE)
            .map_err(|_| ApiError::Forbidden("Admin access required".to_owned()))
    }
}

/// Decodes and validates a bearer token: HS256 signature, expiry, and a
/// non-empty `tenant` claim. Kept as a free function so it's testable
/// without standing up an axum request.
///
/// `aud`/`iss` matching is intentionally not enforced — v1's `verify_token`
/// only ever checked HS256 signature + expiry, and this service has no
/// configured expected audience/issuer value yet (a real follow-up once one
/// is defined, not a silent gap: `jsonwebtoken`'s default `validate_aud =
/// true` would otherwise reject every real token, since it fails closed
/// when `aud` is present on the token but no expected value is configured).
pub fn decode_bearer(token: &str, secret: &str) -> Result<Claims, ApiError> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();
    let claims = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            ApiError::Unauthorized("Token expired".to_owned())
        }
        _ => ApiError::Unauthorized("Invalid token".to_owned()),
    })?;

    claims
        .require_tenant()
        .map_err(|_| ApiError::Forbidden("Missing or empty tenant claim".to_owned()))?;

    Ok(claims)
}

impl FromRequestParts<AppState> for AuthedUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        const HEADER_MSG: &str = "Missing or invalid authorization header";
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::Unauthorized(HEADER_MSG.to_owned()))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| ApiError::Unauthorized(HEADER_MSG.to_owned()))?;

        if !state.config.security.auth_enabled {
            // v1 dev-mode bypass (`config.security.auth_enabled == False`):
            // never the default, only set via explicit env override for
            // local development.
            return Ok(AuthedUser {
                claims: dev_claims(),
            });
        }

        let claims = decode_bearer(token, &state.config.security.secret_key)?;
        Ok(AuthedUser { claims })
    }
}

fn dev_claims() -> Claims {
    Claims {
        sub: "dev".to_owned(),
        iss: "dev".to_owned(),
        aud: "dev".to_owned(),
        iat: 0,
        exp: i64::MAX,
        scope: format!("*:read *:write {ADMIN_SCOPE}"),
        tenant: "dev".to_owned(),
        teams: vec![],
        roles: vec!["admin".to_owned()],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    const SECRET: &str = "test-secret";

    fn token_with(claims: &Claims) -> String {
        match jsonwebtoken::encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        ) {
            Ok(t) => t,
            Err(e) => panic!("encode: {e}"),
        }
    }

    fn base_claims() -> Claims {
        Claims {
            sub: "u1".into(),
            iss: "https://auth.skauswatch.app".into(),
            aud: "skauswatch".into(),
            iat: 0,
            exp: i64::MAX,
            scope: "events:read".into(),
            tenant: "tenant-a".into(),
            teams: vec![],
            roles: vec![],
        }
    }

    #[test]
    fn valid_token_with_tenant_decodes() {
        let token = token_with(&base_claims());
        let claims = match decode_bearer(&token, SECRET) {
            Ok(c) => c,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(claims.tenant, "tenant-a");
    }

    #[test]
    fn missing_tenant_claim_is_forbidden() {
        let mut c = base_claims();
        c.tenant = String::new();
        let token = token_with(&c);
        match decode_bearer(&token, SECRET) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Missing or empty tenant claim"),
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[test]
    fn expired_token_is_unauthorized() {
        let mut c = base_claims();
        c.exp = 1;
        let token = token_with(&c);
        match decode_bearer(&token, SECRET) {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "Token expired"),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn garbage_token_is_unauthorized() {
        match decode_bearer("not-a-jwt", SECRET) {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "Invalid token"),
            other => panic!("expected Unauthorized, got {other:?}"),
        }
    }

    #[test]
    fn admin_scope_gate_matches_house_scope_semantics() {
        let mut c = base_claims();
        c.scope = "*:admin".into();
        let admin = AuthedUser { claims: c };
        assert!(admin.require_admin().is_ok());

        let viewer = AuthedUser {
            claims: base_claims(),
        };
        match viewer.require_admin() {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Admin access required"),
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    // HTTP-level tests below exercise the `FromRequestParts<AppState>` impl
    // itself (header presence/shape, dev bypass, real decode) rather than
    // the pure `decode_bearer` function the tests above already cover.

    async fn probe(user: AuthedUser) -> axum::http::StatusCode {
        assert!(!user.claims.sub.is_empty());
        axum::http::StatusCode::OK
    }

    fn probe_server(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .route("/probe", axum::routing::get(probe))
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    #[tokio::test]
    async fn missing_authorization_header_is_unauthorized() {
        let server = probe_server(crate::routes::test_support::dev_state());
        let res = server.get("/probe").await;
        res.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn header_without_bearer_prefix_is_unauthorized() {
        let server = probe_server(crate::routes::test_support::dev_state());
        let res = server.get("/probe").authorization("Token abc").await;
        res.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dev_bypass_grants_access_when_auth_disabled() {
        // The dev bypass only skips JWT *decoding* — a bearer-shaped header
        // is still required to reach that branch (see the header/prefix
        // checks ahead of the `auth_enabled` check above), so this still
        // sends one, just not a valid/decodable one.
        let server = probe_server(crate::routes::test_support::dev_bypass_state());
        let res = server
            .get("/probe")
            .authorization_bearer("not-a-real-token")
            .await;
        res.assert_status_ok();
    }

    #[tokio::test]
    async fn valid_bearer_token_grants_access() {
        // MONITOR_AUTH_ENABLED defaults true (unset in the test env), so
        // dev_state() exercises the real decode path here.
        let state = crate::routes::test_support::dev_state();
        let token = crate::routes::test_support::sign_token(&state, "tenant-a", "events:read");
        let server = probe_server(state);
        let res = server.get("/probe").authorization_bearer(token).await;
        res.assert_status_ok();
    }

    #[tokio::test]
    async fn expired_bearer_token_is_unauthorized_over_http() {
        let state = crate::routes::test_support::dev_state();
        let mut claims = base_claims();
        claims.exp = 1;
        let token = crate::routes::test_support::sign_claims(&state, &claims);
        let server = probe_server(state);
        let res = server.get("/probe").authorization_bearer(token).await;
        res.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_tenant_claim_is_forbidden_over_http() {
        let state = crate::routes::test_support::dev_state();
        let mut claims = base_claims();
        claims.tenant = String::new();
        let token = crate::routes::test_support::sign_claims(&state, &claims);
        let server = probe_server(state);
        let res = server.get("/probe").authorization_bearer(token).await;
        res.assert_status(axum::http::StatusCode::FORBIDDEN);
    }
}
