//! AuthN/Z for the CodeScan backend. Tokens are issued centrally by the
//! manager service (`services/manager/src/auth/mod.rs`) — same HS256 secret,
//! same claim shape `{sub, role, type, exp, iat}`. This service has no local
//! identity table (see migrations/0001_codescan_schema.sql), so `CurrentUser`
//! trusts the decoded claims directly rather than round-tripping to a users
//! table; authorization decisions are made on `role` only, matching the v1
//! Flask `role_required` decorator this service replaces.
//!
//! Every non-public route requires a valid `CurrentUser` — there is no
//! bypass. This is the defense-in-depth layer behind the manager's own JWT
//! check on `/api/v1/codescan/*` (services/manager/src/routes/codescan.rs).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use jsonwebtoken::{DecodingKey, Validation};
use serde::Deserialize;

use crate::error::ApiError;
use crate::state::AppState;

/// Access-token claims — exact shape issued by the manager service.
/// `token_type` is checked against the raw decoded JSON before this struct
/// is populated (see `decode_access`) and `exp` is enforced by
/// `jsonwebtoken`'s own validation; both fields are kept here to document
/// the full wire shape and are read back out in tests.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct AccessClaims {
    /// String-encoded user id.
    pub sub: String,
    /// Role name (admin/maintainer/viewer) — authorization decisions use
    /// this field only.
    pub role: String,
    /// Token type discriminator: must be `access`.
    #[serde(rename = "type")]
    pub token_type: String,
    /// Expiry (epoch seconds).
    pub exp: i64,
}

/// Decodes and type-checks an access token issued by the manager service.
pub fn decode_access(token: &str, secret: &str) -> Result<AccessClaims, ApiError> {
    let mut validation = Validation::default(); // HS256
    validation.validate_exp = true;
    validation.required_spec_claims.clear();
    let claims = jsonwebtoken::decode::<serde_json::Value>(
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

    if claims.get("type").and_then(|t| t.as_str()) != Some("access") {
        return Err(ApiError::Unauthorized("Invalid token type".to_owned()));
    }
    serde_json::from_value(claims).map_err(|_| ApiError::Unauthorized("Invalid token".to_owned()))
}

/// The authenticated caller, derived entirely from JWT claims — no DB lookup
/// (this service owns no local users table).
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// User id, from the token's `sub` claim.
    pub id: i64,
    /// Role name (admin/maintainer/viewer).
    pub role: String,
}

impl CurrentUser {
    /// v1 `role_required` equivalent: 403 unless role is in `roles`.
    pub fn require_role(&self, roles: &[&str]) -> Result<(), ApiError> {
        if roles.contains(&self.role.as_str()) {
            Ok(())
        } else {
            Err(ApiError::Forbidden("Insufficient permissions".to_owned()))
        }
    }
}

/// Extractor requiring the `admin` role. Implemented as a `FromRequestParts`
/// extractor (not an inline check in the handler body) so it runs — and can
/// reject with 403 — *before* axum evaluates a later body extractor like
/// `ApiJson`. This matters: axum evaluates extractors left-to-right and
/// short-circuits on the first failure, so an inline
/// `user.require_role(...)?` placed after the body parameter in the
/// function body would never run if the body itself failed to parse first.
/// Matches the v1 decorator ordering (`@auth_required` then
/// `@role_required(...)`, both ahead of the view function).
pub struct AdminOnly(pub CurrentUser);

impl FromRequestParts<AppState> for AdminOnly {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        user.require_role(&["admin"])?;
        Ok(AdminOnly(user))
    }
}

/// Extractor requiring the `maintainer` role only — see [`AdminOnly`] for
/// why this is an extractor rather than an inline check.
pub struct MaintainerOnly(pub CurrentUser);

impl FromRequestParts<AppState> for MaintainerOnly {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        user.require_role(&["maintainer"])?;
        Ok(MaintainerOnly(user))
    }
}

impl FromRequestParts<AppState> for CurrentUser {
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
        let claims = decode_access(token, &state.auth.jwt_secret)?;
        let user_id: i64 = claims
            .sub
            .parse()
            .map_err(|_| ApiError::Unauthorized("Invalid token".to_owned()))?;
        Ok(CurrentUser {
            id: user_id,
            role: claims.role,
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use chrono::Utc;
    use jsonwebtoken::{EncodingKey, Header};
    use serde::Serialize;

    const SECRET: &str = "test-secret";

    #[derive(Serialize)]
    struct RawClaims {
        sub: String,
        role: String,
        #[serde(rename = "type")]
        token_type: String,
        exp: i64,
        iat: i64,
    }

    fn sign(claims: &RawClaims) -> String {
        match jsonwebtoken::encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        ) {
            Ok(t) => t,
            Err(e) => panic!("encode: {e}"),
        }
    }

    #[test]
    fn decodes_manager_issued_access_token() {
        let now = Utc::now().timestamp();
        let token = sign(&RawClaims {
            sub: "42".to_owned(),
            role: "admin".to_owned(),
            token_type: "access".to_owned(),
            exp: now + 60,
            iat: now,
        });
        let claims = match decode_access(&token, SECRET) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(claims.sub, "42");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_type, "access");
        assert_eq!(claims.exp, now + 60);
    }

    #[test]
    fn extra_claims_beyond_the_minimal_shape_are_ignored() {
        // The Flask v1 token embeds tenant/team memberships beyond the
        // manager's minimal shape; decode_access must not choke on them.
        let now = Utc::now().timestamp();
        #[derive(Serialize)]
        struct WideClaims {
            sub: String,
            role: String,
            global_role: String,
            #[serde(rename = "type")]
            token_type: String,
            exp: i64,
            iat: i64,
        }
        let token = match jsonwebtoken::encode(
            &Header::default(),
            &WideClaims {
                sub: "7".to_owned(),
                role: "maintainer".to_owned(),
                global_role: "maintainer".to_owned(),
                token_type: "access".to_owned(),
                exp: now + 60,
                iat: now,
            },
            &EncodingKey::from_secret(SECRET.as_bytes()),
        ) {
            Ok(t) => t,
            Err(e) => panic!("encode: {e}"),
        };
        let claims = match decode_access(&token, SECRET) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(claims.sub, "7");
    }

    #[test]
    fn expired_token_maps_to_token_expired() {
        let now = Utc::now().timestamp();
        let token = sign(&RawClaims {
            sub: "1".to_owned(),
            role: "viewer".to_owned(),
            token_type: "access".to_owned(),
            exp: now - 120,
            iat: now - 240,
        });
        match decode_access(&token, SECRET) {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "Token expired"),
            other => panic!("expected 401 Token expired, got {other:?}"),
        }
    }

    #[test]
    fn refresh_token_type_is_rejected() {
        let now = Utc::now().timestamp();
        let token = sign(&RawClaims {
            sub: "1".to_owned(),
            role: "viewer".to_owned(),
            token_type: "refresh".to_owned(),
            exp: now + 60,
            iat: now,
        });
        match decode_access(&token, SECRET) {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "Invalid token type"),
            other => panic!("expected 401 Invalid token type, got {other:?}"),
        }
    }

    #[test]
    fn require_role_matches_v1_role_required() {
        let admin = CurrentUser {
            id: 1,
            role: "admin".to_owned(),
        };
        assert!(admin.require_role(&["admin", "maintainer"]).is_ok());
        let viewer = CurrentUser {
            id: 2,
            role: "viewer".to_owned(),
        };
        match viewer.require_role(&["admin", "maintainer"]) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Insufficient permissions"),
            other => panic!("expected 403, got {other:?}"),
        }
    }
}
