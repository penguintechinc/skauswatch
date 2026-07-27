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

use crate::error::ApiError;
use crate::state::AppState;

fn default_tenant() -> String {
    "default".to_owned()
}

/// Deserialized JWT payload — presence of `sub`/`exp`/`scope` is enforced
/// by these being non-`Option` fields (v1's `options={"require": [...]}`).
#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    #[allow(dead_code)] // validated by jsonwebtoken's `validate_exp`, not read directly
    exp: i64,
    scope: String,
    #[serde(default = "default_tenant")]
    tenant: String,
}

/// The authenticated caller, mirroring v1 `g.token_claims`/`g.user_id`/
/// `g.tenant_id`/`g.token_scopes`.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// `sub` claim — the caller's user id.
    pub user_id: String,
    /// `tenant` claim, defaulting to `"default"` (v1 parity). Decoded but
    /// not yet read by any route — v1 (`g.tenant_id`) never used it either;
    /// IceBox is currently single-tenant-per-deployment. Kept for future
    /// tenant-scoped query enforcement.
    #[allow(dead_code)]
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
}

/// Decodes and validates a bearer token per v1 `_decode_jwt`: HS256,
/// `sub`/`exp`/`scope` required, expiry checked. Any failure (bad
/// signature, expired, missing required claim) maps to the single v1
/// message `"Invalid or expired token"`.
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
    Ok(CurrentUser {
        user_id: claims.sub,
        tenant_id: claims.tenant,
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
    fn missing_tenant_claim_defaults() {
        let now = Utc::now().timestamp();
        let token = sign(json!({"sub": "u", "exp": now + 3600, "scope": "secrets:read"}));
        let user = decode_bearer(&token, SECRET).expect("decode");
        assert_eq!(user.tenant_id, "default");
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
}
