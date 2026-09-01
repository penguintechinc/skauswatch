//! AuthN/Z primitives shared by all skauswatch services: the mandatory JWT
//! claims model (`sub/iss/aud/iat/exp/scope/tenant/teams/roles`) and
//! scope-based authorization helpers. Authorization decisions use `scope`
//! only — `roles` is informational/audit, never branched on.
//!
//! Middleware ordering contract (enforced where routers are assembled):
//! tenant check → scope check → feature/licensing check. [`tenant_middleware`]
//! is the shared implementation of the first stage: it decodes the bearer
//! token, enforces the tenant boundary, and publishes the result as a
//! [`TenantContext`] that every downstream layer/handler in the service can
//! extract — see that function's docs for the exact axum layer ordering
//! this requires.
//!
//! This crate also carries the house fail-fast secret policy
//! ([`load_jwt_secret`]) and a service-to-service JWT verifier
//! ([`verify_service_token`], [`AuthenticatedCaller`], [`verify_grpc_bearer`])
//! shared by services (pki, sshca) that have no local user database
//! and therefore can't run the manager's full `CurrentUser` extractor, but
//! still must require a valid HS256 access token signed with the same
//! `JWT_SECRET_KEY` on every request.

use axum::Json;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// Mandatory claims carried by every skauswatch token, per the PenguinTech
/// JWT standard. Requests without a valid `tenant` claim are rejected with
/// 403 before any scope evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Tenant boundary — mandatory on all tokens. `#[serde(default)]` is
    /// deliberate: it lets a token with the `tenant` key entirely absent
    /// decode successfully (as `""`) instead of hard-failing JSON
    /// deserialization, so [`Claims::require_tenant`]/[`decode_claims`]/
    /// [`tenant_middleware`] can reject *both* "key absent" and "key present
    /// but empty" the same way — a clean 403 — rather than the former
    /// surfacing as a generic 401 "invalid token" decode failure.
    #[serde(default)]
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

/// Failures from decoding and tenant-validating a bearer token via
/// [`decode_claims`]/[`tenant_middleware`]. Deliberately distinguishes an
/// *unauthenticated* request (no valid credential at all — 401) from an
/// *authenticated* request that fails the tenant-isolation gate (a
/// correctly signed, unexpired token that simply carries no usable
/// `tenant` — 403), per the house policy: "Tenant mismatch = immediate
/// 403" and requests without a valid `tenant` claim are rejected before
/// any scope evaluation.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum TenantAuthError {
    /// No `Authorization: Bearer <token>` header present.
    #[error("Missing or invalid authorization header")]
    MissingOrInvalidHeader,
    /// Signature valid but the token has expired.
    #[error("Token expired")]
    Expired,
    /// Signature invalid, malformed token, or undecodable claims.
    #[error("Invalid token")]
    Invalid,
    /// Token decoded and verified, but carried no usable `tenant` claim
    /// (absent or empty after trimming).
    #[error("missing or empty tenant claim")]
    MissingTenant,
}

impl IntoResponse for TenantAuthError {
    fn into_response(self) -> Response {
        let status = match self {
            TenantAuthError::MissingTenant => axum::http::StatusCode::FORBIDDEN,
            TenantAuthError::MissingOrInvalidHeader
            | TenantAuthError::Expired
            | TenantAuthError::Invalid => axum::http::StatusCode::UNAUTHORIZED,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

/// Canonical `iss` claim value for every `skauswatch`-issued access token.
/// [`decode_claims`] REQUIRES a token's `iss` to equal this exactly —
/// issuers (the manager's `create_access_token`, and any other service that
/// mints a [`Claims`] token) MUST stamp this value, not a hand-rolled
/// literal, to avoid silent drift between mint and verify sides. Matches
/// the fixture value already established across the workspace before this
/// constant existed (`services/manager/src/auth::CLAIMS_ISSUER`,
/// `crates/skauswatch-testkit::jwt::CLAIMS_ISSUER`, and the ad hoc test
/// literals in `services/monitor`/`services/depgate`/
/// `services/codescan-backend`).
pub const EXPECTED_ISS: &str = "https://auth.skauswatch.app";

/// Canonical `aud` claim value for every `skauswatch`-issued access token.
/// [`decode_claims`] REQUIRES a token's `aud` to equal this exactly —
/// issuers MUST stamp this value. Matches the fixture value already
/// established across the workspace (see [`EXPECTED_ISS`] docs for the
/// full list of prior call sites this constant now centralizes).
pub const EXPECTED_AUD: &str = "skauswatch";

/// Decodes and signature/expiry/issuer/audience-validates the mandatory
/// [`Claims`] shape from an HS256 token signed with `secret`. Does not
/// itself enforce the tenant boundary — callers needing that call
/// [`Claims::require_tenant`] on the result (this is exactly what
/// [`tenant_middleware`] does).
///
/// `iss` and `aud` are both REQUIRED and must equal [`EXPECTED_ISS`]/
/// [`EXPECTED_AUD`] exactly — a token missing either claim, or carrying a
/// mismatched value, is rejected as [`TenantAuthError::Invalid`] the same
/// as a bad signature. This closes a prior gap where `validate_aud` was
/// disabled and `iss` was never checked at all, so any correctly-signed
/// token was accepted regardless of who issued it or what audience it was
/// minted for. Every issuer of a [`Claims`] token MUST set `iss =
/// EXPECTED_ISS` and `aud = EXPECTED_AUD` or its tokens will be rejected.
pub fn decode_claims(token: &str, secret: &str) -> Result<Claims, TenantAuthError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_aud = true;
    validation.set_issuer(&[EXPECTED_ISS]);
    validation.set_audience(&[EXPECTED_AUD]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    jsonwebtoken::decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => TenantAuthError::Expired,
        _ => TenantAuthError::Invalid,
    })
}

/// A validated tenant identifier. The *only* legitimate source of a
/// `Tenant` is a successfully decoded, tenant-checked [`Claims`] token
/// (via [`tenant_middleware`]) — never a client-supplied path/body/query
/// parameter (see the house tenant-isolation rule: "client cannot set
/// tenant — auth service only").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tenant(pub String);

impl Tenant {
    /// Borrows the tenant id as a string slice, e.g. for use as an ORM
    /// filter value.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Tenant {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Tenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The validated tenant boundary for the current request. Inserted into
/// request extensions by [`tenant_middleware`] and read back out by the
/// `FromRequestParts` impl below — handlers and any layer running *after*
/// `tenant_middleware` extract this instead of re-decoding the token.
///
/// # Service usage contract
///
/// Every database query a handler issues MUST filter on this tenant — no
/// exceptions, and never take a tenant id from the request path/body/query
/// instead. With SeaORM (see `backend-rust.md`):
///
/// ```ignore
/// let rows = widget::Entity::find()
///     .filter(widget::Column::TenantId.eq(tenant_ctx.tenant.as_str()))
///     .all(&db)
///     .await?;
/// ```
///
/// The same pattern applies to cache keys and any other per-tenant lookup:
/// always key/filter on `tenant_ctx.tenant.as_str()`, never on a value the
/// caller supplied directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    /// The validated tenant for this request.
    pub tenant: Tenant,
}

impl<S> FromRequestParts<S> for TenantContext
where
    S: Send + Sync,
{
    type Rejection = TenantAuthError;

    /// Reads the [`TenantContext`] [`tenant_middleware`] already inserted
    /// into request extensions. If it's absent — meaning
    /// `tenant_middleware` was never run ahead of this extractor, a router
    /// wiring bug — this fails closed with the same 403 a genuinely missing
    /// tenant claim would produce, never a panic or a silent bypass.
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<TenantContext>()
            .cloned()
            .ok_or(TenantAuthError::MissingTenant)
    }
}

/// Router-wide layer implementing the first stage of the crate's middleware
/// ordering contract (tenant → scope → feature): decodes the bearer token
/// with `S`'s JWT secret, requires a non-empty `tenant` claim, and inserts
/// a [`TenantContext`] into request extensions for every downstream
/// extractor/handler/layer. A missing/invalid/expired token is 401; a
/// validly signed token with no usable tenant is 403 — no request reaches
/// the handler without a [`TenantContext`] available.
///
/// Register with `axum::middleware::from_fn_with_state`. **Ordering
/// matters**: axum layers execute outside-in in the *reverse* of the order
/// `.layer()` was called (the last `.layer()` call becomes the outermost —
/// and therefore first-executed — wrapper). To satisfy tenant → scope →
/// feature, add this layer LAST, after any scope/feature layers:
///
/// ```ignore
/// use axum::middleware::from_fn_with_state;
///
/// let app = Router::new()
///     .route("/api/v1/widgets", get(list_widgets))
///     .layer(from_fn_with_state(state.clone(), feature_gate_middleware)) // innermost — runs LAST
///     .layer(from_fn_with_state(state.clone(), scope_middleware))        // runs 2nd
///     .layer(from_fn_with_state(state.clone(), skauswatch_auth::tenant_middleware::<AppState>)) // outermost — runs FIRST
///     .with_state(state);
/// ```
pub async fn tenant_middleware<S>(
    State(state): State<S>,
    mut request: Request,
    next: Next,
) -> Response
where
    S: JwtSecretSource + Clone + Send + Sync + 'static,
{
    let token = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token);

    let outcome = match token {
        Some(token) => decode_claims(token, state.jwt_secret()).and_then(|claims| {
            claims
                .require_tenant()
                .map(|tenant| TenantContext {
                    tenant: Tenant(tenant.to_owned()),
                })
                .map_err(|_| TenantAuthError::MissingTenant)
        }),
        None => Err(TenantAuthError::MissingOrInvalidHeader),
    };

    match outcome {
        Ok(ctx) => {
            request.extensions_mut().insert(ctx);
            next.run(request).await
        }
        Err(err) => err.into_response(),
    }
}

/// Claims carried by the shared HS256 access token issued by the manager's
/// login endpoint (`services/manager/src/auth::AccessClaims`): `sub`,
/// `role`, `type: "access"`, `exp`, `iat`. Any service that verifies with the
/// same `JWT_SECRET_KEY` can consume it — this is the "machine JWT" shape
/// used to gate pki, sshca, and the manager's own gRPC surface.
///
/// Deliberately carries no `iss`/`aud` claims and is exempt from the
/// [`EXPECTED_ISS`]/[`EXPECTED_AUD`] enforcement added to [`decode_claims`]:
/// this is a structurally different, older wire shape (issued by
/// [`issue_service_token`], verified by [`verify_service_token`]) with no
/// issuer/audience fields to validate. Adding them would be a breaking
/// schema change across every current issuer (pki, sshca, the manager's own
/// gRPC surface) and is out of scope here — see the [`Claims`]-shape
/// tenancy retrofit notes above for the token family that *is* iss/aud
/// enforced.
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
/// local user database (pki, sshca) — there is no role/scope check
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
/// gating tonic services (pki's `PKIService`, the manager's
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
/// pki and sshca have no local user table.
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

/// Well-known placeholder secrets — shipped scaffold defaults, sample env
/// files, or values a developer might type without thinking — that must
/// never reach production as `JWT_SECRET_KEY`. Compared case-insensitively
/// (see [`is_denylisted_secret`]). Mirrors
/// `services/manager/src/state.rs::ENDPOINT_DEFAULT_SECRET`'s
/// fail-fast-on-known-default policy for `ENDPOINT_API_SECRET`, generalized
/// to the small set of defaults known to circulate for this secret.
const DENYLISTED_SECRETS: &[&str] = &[
    "changeme-in-production",
    "changeme",
    "change-me",
    "changeme-in-prod",
    "secret",
    "password",
];

/// True when `value` case-insensitively matches a well-known placeholder
/// default (see [`DENYLISTED_SECRETS`]) rather than a real secret.
fn is_denylisted_secret(value: &str) -> bool {
    DENYLISTED_SECRETS
        .iter()
        .any(|denied| value.eq_ignore_ascii_case(denied))
}

/// A required secret was missing/empty/a known placeholder default in
/// production. Startup must abort rather than fall back to a guessable or
/// hardcoded value.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
#[error("JWT_SECRET_KEY must be set to a real secret in production (RELEASE_MODE != \"false\")")]
pub struct MissingProductionSecret;

/// Pure fail-fast decision for a required secret: `Ok(Some(value))` when
/// usable (trimmed non-empty, and — in production — not a known
/// [`DENYLISTED_SECRETS`] placeholder), `Ok(None)` when absent but
/// acceptable (non-production), `Err` when production requires a real
/// secret and the value is missing/blank/a known default.
fn resolve_required_secret(
    value: Option<&str>,
    production: bool,
) -> Result<Option<&str>, MissingProductionSecret> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) if production && is_denylisted_secret(v) => Err(MissingProductionSecret),
        Some(v) => Ok(Some(v)),
        None if production => Err(MissingProductionSecret),
        None => Ok(None),
    }
}

/// Loads the shared JWT signing secret from `JWT_SECRET_KEY` per the house
/// fail-fast policy: a missing/empty value, OR a well-known placeholder
/// default (see [`DENYLISTED_SECRETS`]), FAILS STARTUP in production (a
/// guessable per-process fallback — or a shipped default — is worse than
/// refusing to start). In dev only (`RELEASE_MODE=false`), an unset value
/// is logged and replaced with a random ephemeral secret — never a
/// hardcoded/guessable one.
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
    fn resolve_required_secret_rejects_denylisted_defaults_in_production() {
        for denied in DENYLISTED_SECRETS {
            assert_eq!(
                resolve_required_secret(Some(denied), true),
                Err(MissingProductionSecret),
                "expected {denied:?} to be rejected"
            );
            // Case-insensitive: an upper-cased and a title-cased variant of
            // each denylisted value must also be rejected.
            let upper = denied.to_uppercase();
            assert_eq!(
                resolve_required_secret(Some(&upper), true),
                Err(MissingProductionSecret),
                "expected {upper:?} to be rejected"
            );
        }
    }

    #[test]
    fn resolve_required_secret_rejects_denylisted_default_with_surrounding_whitespace() {
        assert_eq!(
            resolve_required_secret(Some("  ChangeMe  "), true),
            Err(MissingProductionSecret)
        );
    }

    #[test]
    fn resolve_required_secret_accepts_real_secret_in_production() {
        assert_eq!(
            resolve_required_secret(Some("a-genuinely-random-32-byte-value"), true),
            Ok(Some("a-genuinely-random-32-byte-value"))
        );
    }

    #[test]
    fn resolve_required_secret_allows_denylisted_value_outside_production() {
        // Dev/local convenience values are only rejected once RELEASE_MODE
        // requires a real secret — mirrors
        // `resolve_required_secret_allows_absence_outside_production`.
        assert_eq!(
            resolve_required_secret(Some("changeme"), false),
            Ok(Some("changeme"))
        );
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

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)] // tests fail loudly by design
mod tenant_middleware_tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt as _;

    use super::*;

    const SECRET: &str = "s3cr3t";

    #[derive(Clone)]
    struct TestState;

    impl JwtSecretSource for TestState {
        fn jwt_secret(&self) -> &str {
            SECRET
        }
    }

    fn claims_with_tenant(tenant: &str) -> Claims {
        Claims {
            sub: "u-1".into(),
            iss: EXPECTED_ISS.into(),
            aud: EXPECTED_AUD.into(),
            iat: 0,
            exp: i64::MAX,
            scope: "*:read".into(),
            tenant: tenant.into(),
            teams: vec![],
            roles: vec![],
        }
    }

    fn sign(claims: &Claims, secret: &str) -> String {
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap_or_else(|e| panic!("sign: {e}"))
    }

    /// A hand-rolled claim set with no `tenant` key at all — simulates a
    /// pre-tenancy or third-party-issued token, exercising the
    /// `#[serde(default)]` decode path rather than an explicit empty string.
    #[derive(Serialize)]
    struct ClaimsWithoutTenant {
        sub: String,
        iss: String,
        aud: String,
        iat: i64,
        exp: i64,
        scope: String,
    }

    fn sign_without_tenant(secret: &str) -> String {
        let claims = ClaimsWithoutTenant {
            sub: "u-1".into(),
            iss: EXPECTED_ISS.into(),
            aud: EXPECTED_AUD.into(),
            iat: 0,
            exp: i64::MAX,
            scope: "*:read".into(),
        };
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap_or_else(|e| panic!("sign: {e}"))
    }

    /// A hand-rolled claim set with no `iss`/`aud` keys at all — simulates a
    /// pre-`EXPECTED_ISS`/`EXPECTED_AUD` or third-party-issued token, to
    /// prove [`decode_claims`] rejects a token that never carried either
    /// claim (not just one carrying a mismatched value).
    #[derive(Serialize)]
    struct ClaimsWithoutIssAud {
        sub: String,
        iat: i64,
        exp: i64,
        scope: String,
        tenant: String,
    }

    fn sign_without_iss_aud(secret: &str) -> String {
        let claims = ClaimsWithoutIssAud {
            sub: "u-1".into(),
            iat: 0,
            exp: i64::MAX,
            scope: "*:read".into(),
            tenant: "acme".into(),
        };
        jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .unwrap_or_else(|e| panic!("sign: {e}"))
    }

    // -- decode_claims -------------------------------------------------

    #[test]
    fn decode_claims_round_trips_tenant() {
        let token = sign(&claims_with_tenant("acme"), SECRET);
        let decoded = match decode_claims(&token, SECRET) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(decoded.tenant, "acme");
    }

    #[test]
    fn decode_claims_defaults_absent_tenant_to_empty_string() {
        let token = sign_without_tenant(SECRET);
        let decoded = match decode_claims(&token, SECRET) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(decoded.tenant, "");
    }

    #[test]
    fn decode_claims_rejects_wrong_secret() {
        let token = sign(&claims_with_tenant("acme"), SECRET);
        assert_eq!(
            decode_claims(&token, "wrong"),
            Err(TenantAuthError::Invalid)
        );
    }

    #[test]
    fn decode_claims_rejects_expired_token() {
        let mut c = claims_with_tenant("acme");
        // jsonwebtoken parses `exp` as an unsigned epoch-seconds value, so a
        // negative literal would fail as a malformed claim rather than
        // exercise expiry — use a tiny-but-non-negative, long-past value
        // instead (1970-01-01T00:00:01Z), comfortably beyond any leeway.
        c.exp = 1;
        let token = sign(&c, SECRET);
        assert_eq!(decode_claims(&token, SECRET), Err(TenantAuthError::Expired));
    }

    #[test]
    fn decode_claims_rejects_garbage() {
        assert_eq!(
            decode_claims("not-a-jwt", SECRET),
            Err(TenantAuthError::Invalid)
        );
    }

    #[test]
    fn decode_claims_accepts_correct_issuer_and_audience() {
        let token = sign(&claims_with_tenant("acme"), SECRET);
        assert!(decode_claims(&token, SECRET).is_ok());
    }

    #[test]
    fn decode_claims_rejects_wrong_issuer() {
        let mut c = claims_with_tenant("acme");
        c.iss = "https://evil.example.com".into();
        let token = sign(&c, SECRET);
        assert_eq!(decode_claims(&token, SECRET), Err(TenantAuthError::Invalid));
    }

    #[test]
    fn decode_claims_rejects_wrong_audience() {
        let mut c = claims_with_tenant("acme");
        c.aud = "not-skauswatch".into();
        let token = sign(&c, SECRET);
        assert_eq!(decode_claims(&token, SECRET), Err(TenantAuthError::Invalid));
    }

    #[test]
    fn decode_claims_rejects_missing_issuer_and_audience() {
        let token = sign_without_iss_aud(SECRET);
        assert_eq!(decode_claims(&token, SECRET), Err(TenantAuthError::Invalid));
    }

    // -- tenant_middleware / TenantContext extractor --------------------

    async fn tenant_probe(ctx: TenantContext) -> String {
        ctx.tenant.as_str().to_owned()
    }

    fn app() -> Router {
        Router::new()
            .route("/probe", get(tenant_probe))
            .layer(axum::middleware::from_fn_with_state(
                TestState,
                tenant_middleware::<TestState>,
            ))
            .with_state(TestState)
    }

    fn request_with_auth(auth: Option<&str>) -> HttpRequest<Body> {
        let mut builder = HttpRequest::builder().uri("/probe");
        if let Some(v) = auth {
            builder = builder.header(AUTHORIZATION, v);
        }
        builder
            .body(Body::empty())
            .unwrap_or_else(|e| panic!("request: {e}"))
    }

    #[tokio::test]
    async fn valid_tenant_reaches_handler_via_extractor() {
        let token = sign(&claims_with_tenant("acme"), SECRET);
        let resp = app()
            .oneshot(request_with_auth(Some(&format!("Bearer {token}"))))
            .await
            .unwrap_or_else(|e| panic!("response: {e}"));
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_authorization_header_is_401() {
        let resp = app()
            .oneshot(request_with_auth(None))
            .await
            .unwrap_or_else(|e| panic!("response: {e}"));
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_bearer_token_is_401() {
        let resp = app()
            .oneshot(request_with_auth(Some("Bearer not-a-jwt")))
            .await
            .unwrap_or_else(|e| panic!("response: {e}"));
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn empty_tenant_claim_is_403() {
        let token = sign(&claims_with_tenant("   "), SECRET);
        let resp = app()
            .oneshot(request_with_auth(Some(&format!("Bearer {token}"))))
            .await
            .unwrap_or_else(|e| panic!("response: {e}"));
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn absent_tenant_claim_is_403_not_401() {
        let token = sign_without_tenant(SECRET);
        let resp = app()
            .oneshot(request_with_auth(Some(&format!("Bearer {token}"))))
            .await
            .unwrap_or_else(|e| panic!("response: {e}"));
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn wrong_secret_is_401_not_403() {
        let token = sign(&claims_with_tenant("acme"), "wrong-secret");
        let resp = app()
            .oneshot(request_with_auth(Some(&format!("Bearer {token}"))))
            .await
            .unwrap_or_else(|e| panic!("response: {e}"));
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn extractor_rejects_when_middleware_never_ran() {
        // Directly exercises the FromRequestParts impl's fail-closed branch
        // (no TenantContext in extensions) without spinning up a router.
        let (mut parts, _body) = HttpRequest::builder()
            .uri("/probe")
            .body(Body::empty())
            .unwrap_or_else(|e| panic!("request: {e}"))
            .into_parts();
        let outcome = TenantContext::from_request_parts(&mut parts, &TestState).await;
        assert_eq!(outcome, Err(TenantAuthError::MissingTenant));
    }

    #[test]
    fn tenant_display_and_as_ref_match_inner_value() {
        let t = Tenant("acme".to_owned());
        assert_eq!(t.as_str(), "acme");
        assert_eq!(t.as_ref(), "acme");
        assert_eq!(t.to_string(), "acme");
    }
}
