//! AuthN/Z primitives shared by all skauswatch services: the mandatory JWT
//! claims model (`sub/iss/aud/iat/exp/scope/tenant/teams/roles`) and
//! scope-based authorization helpers. Authorization decisions use `scope`
//! only — `roles` is informational/audit, never branched on.
//!
//! Middleware ordering contract (enforced where routers are assembled):
//! tenant check → scope check → feature/licensing check.
//!
//! This crate also carries the house fail-fast secret policy
//! ([`load_jwt_secret`]) and a service-to-service JWT verifier
//! ([`verify_service_token`], [`AuthenticatedCaller`], [`verify_grpc_bearer`])
//! shared by services (pki-server, ssh-ca) that have no local user database
//! and therefore can't run the manager's full `CurrentUser` extractor, but
//! still must require a valid HS256 access token signed with the same
//! `JWT_SECRET_KEY` on every request.

use axum::Json;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// Mandatory claims carried by every skauswatch token, per the PenguinTech
/// JWT standard. Requests without a valid `tenant` claim are rejected with
/// 403 before any scope evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — user or machine identity UUID (never PII).
    pub sub: String,
    /// Issuer.
    pub iss: String,
    /// Audience.
    pub aud: String,
    /// Issued-at (epoch seconds).
    pub iat: i64,
    /// Expiry (epoch seconds).
    pub exp: i64,
    /// Space-separated `resource:action` scopes — the sole authz input.
    pub scope: String,
    /// Tenant boundary — mandatory on all tokens.
    pub tenant: String,
    /// Team memberships (team-scoped permissions).
    #[serde(default)]
    pub teams: Vec<String>,
    /// Role names — audit/display only; never used for authz decisions.
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Authorization failures surfaced by claim checks.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AuthError {
    /// The token carried no usable tenant claim.
    #[error("missing or empty tenant claim")]
    MissingTenant,
    /// A required scope was absent from the token.
    #[error("missing required scope: {0}")]
    MissingScope(String),
}

impl Claims {
    /// Returns the token's scopes as an iterator of `resource:action` items.
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scope.split_whitespace()
    }

    /// Checks a single required scope. Wildcards on the resource segment are
    /// honored (`*:read` satisfies `alerts:read`); anything else is exact.
    pub fn has_scope(&self, required: &str) -> bool {
        let req_action = required.split_once(':').map(|(_, a)| a);
        self.scopes().any(|granted| {
            if granted == required {
                return true;
            }
            match (granted.split_once(':'), req_action) {
                (Some(("*", g_action)), Some(r_action)) => g_action == r_action,
                _ => false,
            }
        })
    }

    /// Enforces tenant presence, per the hard tenant-isolation boundary.
    pub fn require_tenant(&self) -> Result<&str, AuthError> {
        if self.tenant.trim().is_empty() {
            Err(AuthError::MissingTenant)
        } else {
            Ok(&self.tenant)
        }
    }

    /// Enforces a required scope, returning the standard error on failure.
    pub fn require_scope(&self, required: &str) -> Result<(), AuthError> {
        if self.has_scope(required) {
            Ok(())
        } else {
            Err(AuthError::MissingScope(required.to_owned()))
        }
    }
}

/// Claims carried by the shared HS256 access token issued by the manager's
/// login endpoint (`services/manager/src/auth::AccessClaims`): `sub`,
/// `role`, `type: "access"`, `exp`, `iat`. Any service that verifies with the
/// same `JWT_SECRET_KEY` can consume it — this is the "machine JWT" shape
/// used to gate pki-server, ssh-ca, and the manager's own gRPC surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceClaims {
    /// String-encoded caller id (user id, or a machine/service identifier).
    pub sub: String,
    /// Role name — informational only here; callers that need
    /// authorization beyond "is this a valid token" check it themselves.
    #[serde(default)]
    pub role: String,
    /// Token type discriminator — must be `"access"`; refresh tokens are
    /// rejected.
    #[serde(rename = "type", default)]
    pub token_type: String,
    /// Expiry (epoch seconds).
    pub exp: i64,
    /// Issued-at (epoch seconds).
    #[serde(default)]
    pub iat: i64,
}

/// Failures from verifying a service-to-service (or operator) bearer token.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum ServiceTokenError {
    /// No `Authorization: Bearer <token>` header/metadata present.
    #[error("Missing or invalid authorization header")]
    MissingOrInvalidHeader,
    /// Signature valid but the token has expired.
    #[error("Token expired")]
    Expired,
    /// Signature invalid, malformed token, or undecodable claims.
    #[error("Invalid token")]
    Invalid,
    /// Decoded successfully but `type` isn't `"access"` (e.g. a refresh
    /// token presented where an access token is required).
    #[error("Invalid token type")]
    InvalidType,
}

impl IntoResponse for ServiceTokenError {
    fn into_response(self) -> Response {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

impl From<ServiceTokenError> for tonic::Status {
    fn from(e: ServiceTokenError) -> Self {
        tonic::Status::unauthenticated(e.to_string())
    }
}

/// Verifies an HS256 token signed with `secret`: valid signature, unexpired,
/// and `type == "access"`. This is the sole authz input for services with no
/// local user database (pki-server, ssh-ca) — there is no role/scope check
/// here beyond "this is a genuine, current access token".
pub fn verify_service_token(token: &str, secret: &str) -> Result<ServiceClaims, ServiceTokenError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.required_spec_claims.clear();
    let data = jsonwebtoken::decode::<ServiceClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => ServiceTokenError::Expired,
        _ => ServiceTokenError::Invalid,
    })?;
    if data.claims.token_type != "access" {
        return Err(ServiceTokenError::InvalidType);
    }
    Ok(data.claims)
}

/// Issues an HS256 access token in the shared house shape. Mirrors
/// `services/manager/src/auth::create_access_token`; exposed here so any
/// service (or test) that needs to mint a machine/service token doesn't
/// hand-roll JWT encoding against a different claim shape.
pub fn issue_service_token(
    sub: &str,
    role: &str,
    secret: &str,
    ttl_seconds: i64,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let claims = ServiceClaims {
        sub: sub.to_owned(),
        role: role.to_owned(),
        token_type: "access".to_owned(),
        exp: now + ttl_seconds,
        iat: now,
    };
    jsonwebtoken::encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

fn bearer_token(raw: &str) -> Option<&str> {
    raw.strip_prefix("Bearer ")
}

/// Verifies the `authorization: Bearer <jwt>` gRPC metadata entry against
/// `secret` — the tonic-side counterpart to [`AuthenticatedCaller`], for
/// gating tonic services (pki-server's `PKIService`, the manager's
/// `ManagerService`/`S3ScanService`).
pub fn verify_grpc_bearer(
    metadata: &tonic::metadata::MetadataMap,
    secret: &str,
) -> Result<ServiceClaims, ServiceTokenError> {
    let token = metadata
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token)
        .ok_or(ServiceTokenError::MissingOrInvalidHeader)?;
    verify_service_token(token, secret)
}

/// Implemented by axum state types that expose the shared HS256 signing
/// secret, so [`AuthenticatedCaller`] can be used as an extractor (or, via
/// `axum::middleware::from_extractor_with_state`, as a router-wide layer)
/// without each service reimplementing bearer-header parsing.
pub trait JwtSecretSource {
    /// Returns the shared `JWT_SECRET_KEY` value used to verify tokens.
    fn jwt_secret(&self) -> &str;
}

impl<T: JwtSecretSource + ?Sized> JwtSecretSource for std::sync::Arc<T> {
    fn jwt_secret(&self) -> &str {
        (**self).jwt_secret()
    }
}

/// Axum extractor requiring a valid Bearer access token signed with the
/// state's JWT secret. Unlike the manager's `CurrentUser`, this performs no
/// database lookup — signature + expiry + token type only — because
/// pki-server and ssh-ca have no local user table.
#[derive(Debug, Clone)]
pub struct AuthenticatedCaller(pub ServiceClaims);

impl<S> FromRequestParts<S> for AuthenticatedCaller
where
    S: JwtSecretSource + Send + Sync,
{
    type Rejection = ServiceTokenError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(bearer_token)
            .ok_or(ServiceTokenError::MissingOrInvalidHeader)?;
        verify_service_token(token, state.jwt_secret()).map(AuthenticatedCaller)
    }
}

/// Pure decision: does `release_mode` denote production posture? Anything
/// other than `"false"` (case-insensitively), including `None`/unset —
/// production is the safe-by-default posture.
fn release_mode_is_production(release_mode: Option<&str>) -> bool {
    !release_mode
        .map(|v| v.eq_ignore_ascii_case("false"))
        .unwrap_or(false)
}

/// True when the current process is running in production posture, per
/// `RELEASE_MODE` (unset or anything other than `"false"`, case-insensitive).
pub fn is_production() -> bool {
    release_mode_is_production(std::env::var("RELEASE_MODE").ok().as_deref())
}

/// A required secret was missing/empty in production. Startup must abort
/// rather than fall back to a guessable or hardcoded value.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
#[error("JWT_SECRET_KEY must be set to a real secret in production (RELEASE_MODE != \"false\")")]
pub struct MissingProductionSecret;

/// Pure fail-fast decision for a required secret: `Ok(Some(value))` when
/// usable (trimmed non-empty), `Ok(None)` when absent but acceptable
/// (non-production), `Err` when production requires it and it's
/// missing/blank.
fn resolve_required_secret(
    value: Option<&str>,
    production: bool,
) -> Result<Option<&str>, MissingProductionSecret> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => Ok(Some(v)),
        None if production => Err(MissingProductionSecret),
        None => Ok(None),
    }
}

/// Loads the shared JWT signing secret from `JWT_SECRET_KEY` per the house
/// fail-fast policy: a missing/empty value FAILS STARTUP in production
/// (a guessable per-process fallback is worse than refusing to start). In
/// dev only (`RELEASE_MODE=false`), an unset value is logged and replaced
/// with a random ephemeral secret — never a hardcoded/guessable one.
pub fn load_jwt_secret() -> Result<String, MissingProductionSecret> {
    let raw = std::env::var("JWT_SECRET_KEY").ok();
    match resolve_required_secret(raw.as_deref(), is_production())? {
        Some(v) => Ok(v.to_owned()),
        None => {
            tracing::warn!("JWT_SECRET_KEY not set — using random ephemeral dev secret");
            Ok(uuid::Uuid::new_v4().to_string())
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod service_token_tests {
    use super::*;

    #[test]
    fn issued_token_round_trips() {
        let token = match issue_service_token("42", "admin", "s3cr3t", 300) {
            Ok(t) => t,
            Err(e) => panic!("issue: {e}"),
        };
        let claims = match verify_service_token(&token, "s3cr3t") {
            Ok(c) => c,
            Err(e) => panic!("verify: {e:?}"),
        };
        assert_eq!(claims.sub, "42");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn wrong_secret_is_invalid() {
        let token = match issue_service_token("1", "viewer", "right", 300) {
            Ok(t) => t,
            Err(e) => panic!("issue: {e}"),
        };
        assert_eq!(
            verify_service_token(&token, "wrong"),
            Err(ServiceTokenError::Invalid)
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        // jsonwebtoken's default `Validation` applies a 60s leeway, so the
        // expiry must be further in the past than that to actually trip.
        let token = match issue_service_token("1", "viewer", "s3cr3t", -120) {
            Ok(t) => t,
            Err(e) => panic!("issue: {e}"),
        };
        assert_eq!(
            verify_service_token(&token, "s3cr3t"),
            Err(ServiceTokenError::Expired)
        );
    }

    #[test]
    fn refresh_shaped_token_is_rejected_as_wrong_type() {
        let claims = ServiceClaims {
            sub: "1".into(),
            role: String::new(),
            token_type: "refresh".into(),
            exp: i64::MAX,
            iat: 0,
        };
        let token = match jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"s3cr3t"),
        ) {
            Ok(t) => t,
            Err(e) => panic!("encode: {e}"),
        };
        assert_eq!(
            verify_service_token(&token, "s3cr3t"),
            Err(ServiceTokenError::InvalidType)
        );
    }

    #[test]
    fn garbage_token_is_invalid_not_a_panic() {
        assert_eq!(
            verify_service_token("not-a-jwt", "s3cr3t"),
            Err(ServiceTokenError::Invalid)
        );
    }

    #[test]
    fn grpc_bearer_requires_authorization_metadata() {
        let md = tonic::metadata::MetadataMap::new();
        assert_eq!(
            verify_grpc_bearer(&md, "s3cr3t"),
            Err(ServiceTokenError::MissingOrInvalidHeader)
        );
    }

    #[test]
    fn grpc_bearer_accepts_valid_token() {
        let token = match issue_service_token("svc", "worker", "s3cr3t", 300) {
            Ok(t) => t,
            Err(e) => panic!("issue: {e}"),
        };
        let mut md = tonic::metadata::MetadataMap::new();
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        md.insert("authorization", value);
        assert!(verify_grpc_bearer(&md, "s3cr3t").is_ok());
    }

    #[test]
    fn arc_wrapped_state_forwards_jwt_secret() {
        struct Fixed(String);
        impl JwtSecretSource for Fixed {
            fn jwt_secret(&self) -> &str {
                &self.0
            }
        }
        let state = std::sync::Arc::new(Fixed("s3cr3t".to_owned()));
        assert_eq!(state.jwt_secret(), "s3cr3t");
    }

    #[test]
    fn production_posture_defaults_true_and_respects_false() {
        assert!(release_mode_is_production(None));
        assert!(release_mode_is_production(Some("true")));
        assert!(release_mode_is_production(Some("TRUE")));
        assert!(release_mode_is_production(Some("anything-else")));
        assert!(!release_mode_is_production(Some("false")));
        assert!(!release_mode_is_production(Some("FALSE")));
    }

    #[test]
    fn resolve_required_secret_fails_closed_in_production() {
        assert_eq!(
            resolve_required_secret(None, true),
            Err(MissingProductionSecret)
        );
        assert_eq!(
            resolve_required_secret(Some(""), true),
            Err(MissingProductionSecret)
        );
        assert_eq!(
            resolve_required_secret(Some("   "), true),
            Err(MissingProductionSecret)
        );
        assert_eq!(
            resolve_required_secret(Some("real"), true),
            Ok(Some("real"))
        );
    }

    #[test]
    fn resolve_required_secret_allows_absence_outside_production() {
        assert_eq!(resolve_required_secret(None, false), Ok(None));
        assert_eq!(resolve_required_secret(Some("x"), false), Ok(Some("x")));
        assert_eq!(resolve_required_secret(Some(""), false), Ok(None));
    }

    #[test]
    fn load_jwt_secret_never_panics_when_unset() {
        // Whatever the ambient RELEASE_MODE/JWT_SECRET_KEY happen to be in
        // this process, load_jwt_secret must not panic — either a real
        // secret, a random ephemeral one, or a clean Err.
        let _ = load_jwt_secret();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(scope: &str, tenant: &str) -> Claims {
        Claims {
            sub: "u-1".into(),
            iss: "https://auth.skauswatch.app".into(),
            aud: "skauswatch".into(),
            iat: 0,
            exp: i64::MAX,
            scope: scope.into(),
            tenant: tenant.into(),
            teams: vec![],
            roles: vec![],
        }
    }

    #[test]
    fn exact_scope_matches() {
        assert!(claims("alerts:read alerts:write", "t1").has_scope("alerts:write"));
    }

    #[test]
    fn wildcard_resource_matches_action() {
        let c = claims("*:read", "t1");
        assert!(c.has_scope("alerts:read"));
        assert!(!c.has_scope("alerts:write"));
    }

    #[test]
    fn missing_scope_is_rejected() {
        assert_eq!(
            claims("alerts:read", "t1").require_scope("users:admin"),
            Err(AuthError::MissingScope("users:admin".into()))
        );
    }

    #[test]
    fn empty_tenant_is_rejected() {
        assert_eq!(
            claims("*:read", "  ").require_tenant(),
            Err(AuthError::MissingTenant)
        );
    }
}
