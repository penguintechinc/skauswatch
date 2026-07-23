//! v1-parity authentication: bcrypt password hashes, HS256 JWTs with the
//! exact v1 claim shapes (`{sub: str(user_id), role, type, exp, iat}`), and
//! the `CurrentUser` extractor that mirrors `@auth_required`.
//!
//! Do NOT swap in the house-standard claims model here until the webui and
//! EDR fleet migrate — the token shape is part of the v1 wire contract.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::ApiError;
use crate::state::AppState;

/// Access-token claims — exact v1 shape.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    /// String-encoded user id.
    pub sub: String,
    /// Role name (admin/maintainer/viewer) — v1 authorizes on this.
    pub role: String,
    /// Token type discriminator: `access`.
    #[serde(rename = "type")]
    pub token_type: String,
    /// Expiry (epoch seconds).
    pub exp: i64,
    /// Issued-at (epoch seconds).
    pub iat: i64,
}

/// Refresh-token claims — exact v1 shape.
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    /// String-encoded user id.
    pub sub: String,
    /// Token type discriminator: `refresh`.
    #[serde(rename = "type")]
    pub token_type: String,
    /// Expiry (epoch seconds).
    pub exp: i64,
    /// Issued-at (epoch seconds).
    pub iat: i64,
}

/// Issues a v1-shape access token.
pub fn create_access_token(
    user_id: i32,
    role: &str,
    secret: &str,
    expires_minutes: i64,
) -> Result<String, ApiError> {
    let now = Utc::now().timestamp();
    let claims = AccessClaims {
        sub: user_id.to_string(),
        role: role.to_owned(),
        token_type: "access".to_owned(),
        exp: now + expires_minutes * 60,
        iat: now,
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| ApiError::internal("jwt encode", e))
}

/// Issues a v1-shape refresh token.
pub fn create_refresh_token(
    user_id: i32,
    secret: &str,
    expires_days: i64,
) -> Result<String, ApiError> {
    let now = Utc::now().timestamp();
    let claims = RefreshClaims {
        sub: user_id.to_string(),
        token_type: "refresh".to_owned(),
        exp: now + expires_days * 86_400,
        iat: now,
    };
    jsonwebtoken::encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| ApiError::internal("jwt encode", e))
}

/// Decodes signature/exp into raw claims. Error strings are caller-supplied
/// because v1 words them per flow ("Token expired" vs "Refresh token
/// expired", ...); the type check happens after, exactly like v1's
/// jwt.decode-then-`payload.get("type")` ordering.
fn decode_claims(
    token: &str,
    secret: &str,
    expired_msg: &str,
    invalid_msg: &str,
) -> Result<serde_json::Value, ApiError> {
    let mut validation = Validation::default(); // HS256
    validation.validate_exp = true;
    validation.required_spec_claims.clear();
    jsonwebtoken::decode::<serde_json::Value>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
            ApiError::Unauthorized(expired_msg.to_owned())
        }
        _ => ApiError::Unauthorized(invalid_msg.to_owned()),
    })
}

/// Decodes and type-checks an access token (v1 `auth_required` strings).
pub fn decode_access(token: &str, secret: &str) -> Result<AccessClaims, ApiError> {
    let claims = decode_claims(token, secret, "Token expired", "Invalid token")?;
    if claims.get("type").and_then(|t| t.as_str()) != Some("access") {
        return Err(ApiError::Unauthorized("Invalid token type".to_owned()));
    }
    serde_json::from_value(claims).map_err(|_| ApiError::Unauthorized("Invalid token".to_owned()))
}

/// Decodes and type-checks a refresh token (v1 `/auth/refresh` strings).
pub fn decode_refresh(token: &str, secret: &str) -> Result<RefreshClaims, ApiError> {
    let claims = decode_claims(
        token,
        secret,
        "Refresh token expired",
        "Invalid refresh token",
    )?;
    if claims.get("type").and_then(|t| t.as_str()) != Some("refresh") {
        return Err(ApiError::Unauthorized("Invalid token type".to_owned()));
    }
    serde_json::from_value(claims)
        .map_err(|_| ApiError::Unauthorized("Invalid refresh token".to_owned()))
}

/// bcrypt hash (v1 parity: bcrypt.hashpw with default cost).
pub fn hash_password(password: &str) -> Result<String, ApiError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| ApiError::internal("bcrypt", e))
}

/// bcrypt verify.
pub fn verify_password(password: &str, hash: &str) -> bool {
    bcrypt::verify(password, hash).unwrap_or(false)
}

/// sha256 hex of a refresh JWT — the stored `refresh_tokens.token_hash`.
pub fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// The authenticated user, mirroring v1 `g.current_user`.
#[derive(Debug, Clone, Serialize)]
pub struct CurrentUser {
    /// User id.
    pub id: i32,
    /// Email address.
    pub email: String,
    /// Display name.
    pub full_name: Option<String>,
    /// Role (admin/maintainer/viewer).
    pub role: String,
    /// Active flag.
    pub is_active: bool,
    /// MFA enabled flag.
    pub mfa_enabled: bool,
    /// Creation timestamp (RFC3339).
    pub created_at: Option<String>,
}

impl CurrentUser {
    /// v1 `role_required` equivalent: 403 unless role is in `roles`.
    #[allow(dead_code)] // consumed by the users/alerts/... routers as they land
    pub fn require_role(&self, roles: &[&str]) -> Result<(), ApiError> {
        if roles.contains(&self.role.as_str()) {
            Ok(())
        } else {
            Err(ApiError::Forbidden("Insufficient permissions".to_owned()))
        }
    }
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        // v1 uses one message for both missing and non-Bearer headers.
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
        let user_id: i32 = claims
            .sub
            .parse()
            .map_err(|_| ApiError::Unauthorized("Invalid token".to_owned()))?;

        let row = sqlx::query_as::<_, UserRow>(
            "SELECT id, email, full_name, role, is_active, mfa_enabled, created_at::text \
             FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("User not found or inactive".to_owned()))?;

        if !row.is_active {
            return Err(ApiError::Unauthorized(
                "User not found or inactive".to_owned(),
            ));
        }
        Ok(row.into())
    }
}

/// sqlx row mapping for the users table subset the extractor needs.
#[derive(sqlx::FromRow)]
pub struct UserRow {
    /// User id.
    pub id: i32,
    /// Email.
    pub email: String,
    /// Display name.
    pub full_name: Option<String>,
    /// Role.
    pub role: String,
    /// Active flag.
    pub is_active: bool,
    /// MFA flag.
    pub mfa_enabled: bool,
    /// Creation timestamp as text.
    pub created_at: Option<String>,
}

impl From<UserRow> for CurrentUser {
    fn from(r: UserRow) -> Self {
        Self {
            id: r.id,
            email: r.email,
            full_name: r.full_name,
            role: r.role,
            is_active: r.is_active,
            mfa_enabled: r.mfa_enabled,
            created_at: r.created_at,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";

    #[test]
    fn access_token_roundtrips_with_v1_claims() {
        let token = match create_access_token(42, "admin", SECRET, 30) {
            Ok(t) => t,
            Err(e) => panic!("encode: {e:?}"),
        };
        let claims = match decode_access(&token, SECRET) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(claims.sub, "42");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn refresh_token_is_rejected_as_access() {
        let token = match create_refresh_token(42, SECRET, 7) {
            Ok(t) => t,
            Err(e) => panic!("encode: {e:?}"),
        };
        assert!(decode_access(&token, SECRET).is_err());
    }

    #[test]
    fn expired_token_maps_to_token_expired() {
        let now = Utc::now().timestamp();
        let claims = AccessClaims {
            sub: "1".into(),
            role: "viewer".into(),
            token_type: "access".into(),
            exp: now - 120,
            iat: now - 240,
        };
        let token = match jsonwebtoken::encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        ) {
            Ok(t) => t,
            Err(e) => panic!("encode: {e}"),
        };
        match decode_access(&token, SECRET) {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "Token expired"),
            other => panic!("expected 401 Token expired, got {other:?}"),
        }
    }

    #[test]
    fn password_hash_verifies_and_rejects() {
        let hash = match hash_password("hunter2!") {
            Ok(h) => h,
            Err(e) => panic!("hash: {e:?}"),
        };
        assert!(verify_password("hunter2!", &hash));
        assert!(!verify_password("wrong", &hash));
    }

    #[test]
    fn token_hash_is_sha256_hex() {
        assert_eq!(token_hash("abc").len(), 64);
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
