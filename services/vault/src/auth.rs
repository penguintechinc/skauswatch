//! v1-parity JWT + OIDC-scope authorization — Rust port of
//! `icebox/services/flask-backend/api/v1/auth.py`.
//!
//! All permission checks use scopes from the `scope` JWT claim (space
//! separated), never role names. Roles (`vault_admin`, `secret_owner`,
//! `secret_user`, `auditor`) are pre-bundled scope sets expanded by the
//! auth service at token issuance — this module only ever checks
//! `CurrentUser::scopes`.

use std::collections::HashSet;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{DecodingKey, Validation};
use serde::Deserialize;
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

/// Deserialized JWT payload — presence of `sub`/`exp`/`scope` is enforced
/// by these being non-`Option` fields (v1's `options={"require": [...]}`).
/// `tenant` uses `#[serde(default)]` (empty string when absent) rather than
/// hard-failing decode, deliberately: this lets [`decode_bearer`] reject
/// "key absent" and "key present but empty" identically with a 403, instead
/// of the former surfacing as an unrelated 401 decode failure — see
/// `docs/v2-port/tenancy-model.md`.
#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[allow(dead_code)] // validated by jsonwebtoken's `validate_exp`, not read directly
    exp: i64,
    scope: String,
    #[serde(default)]
    tenant: String,
}

/// The authenticated caller, mirroring v1 `g.token_claims`/`g.user_id`/
/// `g.tenant_id`/`g.token_scopes`.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// `sub` claim — the caller's user id.
    pub user_id: String,
    /// `tenant` claim — the hard tenant-isolation boundary. Always
    /// non-empty by construction: [`decode_bearer`] rejects (403) any token
    /// whose `tenant` claim is absent or empty before a [`CurrentUser`] is
    /// ever built, per the house policy ("client cannot set tenant" /
    /// "tenant mismatch = immediate 403", `security.md`).
    pub tenant_id: String,
    /// Space-separated `scope` claim, split into a set.
    pub scopes: HashSet<String>,
    /// The raw bearer token. Decoded but not yet read by any route — v1
    /// (`g.raw_token`) set it for parity too; the JIT-token fallback path
    /// (`get_secret_value`) inspects the `Authorization` header directly
    /// instead, matching v1's own `secrets.py`.
    #[allow(dead_code)]
    pub raw_token: String,
}

impl CurrentUser {
    /// v1 `require_scope`: 403 unless every listed scope is present.
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        if self.scopes.contains(scope) {
            Ok(())
        } else {
            Err(ApiError::InsufficientScope {
                required: vec![scope.to_owned()],
                missing: vec![scope.to_owned()],
            })
        }
    }

    /// v1 `require_any_scope`: 403 unless at least one listed scope matches.
    pub fn require_any_scope(&self, scopes: &[&str]) -> Result<(), ApiError> {
        if scopes.iter().any(|s| self.scopes.contains(*s)) {
            Ok(())
        } else {
            Err(ApiError::Forbidden(format!(
                "Insufficient scope; requires any of: {}",
                scopes.join(", ")
            )))
        }
    }

    /// Parses [`Self::tenant_id`] into the `UUID` type every `tenant_id`
    /// database column uses (see `docs/v2-port/tenancy-model.md` §4). A
    /// parse failure means the JWT issuer minted a non-UUID tenant claim —
    /// never a client-controllable value — so it fails closed as 403, not a
    /// panic or a silent bypass.
    pub fn tenant_uuid(&self) -> Result<Uuid, ApiError> {
        self.tenant_id
            .parse()
            .map_err(|_| ApiError::Forbidden("Invalid tenant".to_owned()))
    }
}

/// Decodes and validates a bearer token per v1 `_decode_jwt`: HS256,
/// `sub`/`exp`/`scope` required, expiry checked. Signature/expiry/missing
/// required-claim failures map to the single v1 message
/// `"Invalid or expired token"` (401). A token that decodes and verifies
/// cleanly but carries no usable `tenant` claim (absent or empty after
/// trimming) is a *distinct* failure — 403, not 401 — per the house tenant
/// boundary: a well-formed credential that simply doesn't identify a tenant
/// is a tenant-isolation violation, not an authentication failure.
pub fn decode_bearer(token: &str, secret: &str) -> Result<CurrentUser, ApiError> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.validate_exp = true;
    let data = jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| ApiError::Unauthorized("Invalid or expired token".to_owned()))?;
    let claims = data.claims;
    let tenant_id = claims.tenant.trim().to_owned();
    if tenant_id.is_empty() {
        return Err(ApiError::Forbidden("Missing or invalid tenant".to_owned()));
    }
    Ok(CurrentUser {
        user_id: claims.sub,
        tenant_id,
        scopes: claims.scope.split_whitespace().map(str::to_owned).collect(),
        raw_token: token.to_owned(),
    })
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        const HEADER_MSG: &str = "Missing or invalid Authorization header";
        let header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::Unauthorized(HEADER_MSG.to_owned()))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| ApiError::Unauthorized(HEADER_MSG.to_owned()))?
            .trim();
        decode_bearer(token, &state.auth.jwt_secret)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use chrono::Utc;
    use jsonwebtoken::{EncodingKey, Header};
    use serde_json::json;

    const SECRET: &str = "test-secret";

    fn sign(claims: serde_json::Value) -> String {
        jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .expect("encode")
    }

    #[test]
    fn valid_token_decodes_scopes_and_tenant() {
        let now = Utc::now().timestamp();
        let token = sign(json!({
            "sub": "user-1",
            "exp": now + 3600,
            "scope": "secrets:read secrets:write",
            "tenant": "acme",
        }));
        let user = decode_bearer(&token, SECRET).expect("decode");
        assert_eq!(user.user_id, "user-1");
        assert_eq!(user.tenant_id, "acme");
        assert!(user.scopes.contains("secrets:read"));
        assert!(user.scopes.contains("secrets:write"));
    }

    #[test]
    fn missing_tenant_claim_is_rejected() {
        let now = Utc::now().timestamp();
        let token = sign(json!({"sub": "u", "exp": now + 3600, "scope": "secrets:read"}));
        match decode_bearer(&token, SECRET) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Missing or invalid tenant"),
            other => panic!("expected 403, got {other:?}"),
        }
    }

    #[test]
    fn empty_tenant_claim_is_rejected() {
        let now = Utc::now().timestamp();
        let token = sign(json!({
            "sub": "u", "exp": now + 3600, "scope": "secrets:read", "tenant": "   ",
        }));
        match decode_bearer(&token, SECRET) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Missing or invalid tenant"),
            other => panic!("expected 403, got {other:?}"),
        }
    }

    #[test]
    fn expired_token_is_rejected() {
        let now = Utc::now().timestamp();
        // jsonwebtoken's default 60s leeway means `exp` must be well past
        // "now minus leeway" to register as expired in this assertion.
        let token = sign(json!({"sub": "u", "exp": now - 300, "scope": "secrets:read"}));
        match decode_bearer(&token, SECRET) {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "Invalid or expired token"),
            other => panic!("expected 401, got {other:?}"),
        }
    }

    #[test]
    fn missing_scope_claim_is_rejected() {
        let now = Utc::now().timestamp();
        let token = sign(json!({"sub": "u", "exp": now + 3600}));
        assert!(decode_bearer(&token, SECRET).is_err());
    }

    #[test]
    fn wrong_secret_is_rejected() {
        let now = Utc::now().timestamp();
        let token = sign(json!({"sub": "u", "exp": now + 3600, "scope": "secrets:read"}));
        assert!(decode_bearer(&token, "other-secret").is_err());
    }

    #[test]
    fn require_scope_reports_required_and_missing() {
        let user = CurrentUser {
            user_id: "u".into(),
            tenant_id: "default".into(),
            scopes: HashSet::from(["secrets:read".to_owned()]),
            raw_token: "tok".into(),
        };
        assert!(user.require_scope("secrets:read").is_ok());
        match user.require_scope("secrets:write") {
            Err(ApiError::InsufficientScope { required, missing }) => {
                assert_eq!(required, vec!["secrets:write".to_owned()]);
                assert_eq!(missing, vec!["secrets:write".to_owned()]);
            }
            other => panic!("expected InsufficientScope, got {other:?}"),
        }
    }

    #[test]
    fn require_any_scope_matches_at_least_one() {
        let user = CurrentUser {
            user_id: "u".into(),
            tenant_id: "default".into(),
            scopes: HashSet::from(["jit:approve".to_owned()]),
            raw_token: "tok".into(),
        };
        assert!(
            user.require_any_scope(&["jit:request", "jit:approve"])
                .is_ok()
        );
        assert!(user.require_any_scope(&["audit:read"]).is_err());
    }

    #[test]
    fn tenant_uuid_parses_a_well_formed_claim() {
        let user = CurrentUser {
            user_id: "u".into(),
            tenant_id: "11111111-1111-1111-1111-111111111111".into(),
            scopes: HashSet::new(),
            raw_token: "tok".into(),
        };
        assert_eq!(
            user.tenant_uuid().expect("parse"),
            "11111111-1111-1111-1111-111111111111"
                .parse::<uuid::Uuid>()
                .expect("uuid")
        );
    }

    #[test]
    fn tenant_uuid_rejects_a_non_uuid_claim() {
        let user = CurrentUser {
            user_id: "u".into(),
            tenant_id: "not-a-uuid".into(),
            scopes: HashSet::new(),
            raw_token: "tok".into(),
        };
        match user.tenant_uuid() {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Invalid tenant"),
            other => panic!("expected 403, got {other:?}"),
        }
    }
}
