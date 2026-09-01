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
//! Audit finding H1b: every token in this workspace used to be signed AND
//! verified with one shared symmetric `JWT_SECRET_KEY` (HS256) — a single
//! leak of that one value let the leaker forge any user or machine token
//! mesh-wide. This crate now mints/verifies with asymmetric ES256
//! (ECDSA P-256) instead: [`load_jwt_signing_key`] loads the PEM-encoded
//! **private** key (`JWT_SIGNING_KEY`) held only by the issuer (the
//! manager), and [`load_jwt_verify_key`] loads the PEM-encoded **public**
//! key (`JWT_VERIFY_KEY`) every verifying service holds — a leaked verify
//! key lets an attacker read/validate tokens, never forge them. Hard
//! cutover, no HS256 fallback. This crate also carries the house fail-fast
//! key-loading policy and a service-to-service JWT verifier
//! ([`verify_service_token`], [`AuthenticatedCaller`], [`verify_grpc_bearer`])
//! shared by services (pki, sshca) that have no local user database
//! and therefore can't run the manager's full `CurrentUser` extractor, but
//! still must require a valid ES256 access token verifiable with the same
//! `JWT_VERIFY_KEY` on every request.

use axum::Json;
use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use pkcs8::{EncodePrivateKey, EncodePublicKey};
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
/// [`Claims`] shape from an ES256 token verifiable with `key` (the public
/// half loaded by [`load_jwt_verify_key`]). Does not itself enforce the
/// tenant boundary — callers needing that call [`Claims::require_tenant`]
/// on the result (this is exactly what [`tenant_middleware`] does).
///
/// `iss` and `aud` are both REQUIRED and must equal [`EXPECTED_ISS`]/
/// [`EXPECTED_AUD`] exactly — a token missing either claim, or carrying a
/// mismatched value, is rejected as [`TenantAuthError::Invalid`] the same
/// as a bad signature. This closes a prior gap where `validate_aud` was
/// disabled and `iss` was never checked at all, so any correctly-signed
/// token was accepted regardless of who issued it or what audience it was
/// minted for. Every issuer of a [`Claims`] token MUST set `iss =
/// EXPECTED_ISS` and `aud = EXPECTED_AUD` or its tokens will be rejected.
pub fn decode_claims(token: &str, key: &DecodingKey) -> Result<Claims, TenantAuthError> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    validation.validate_aud = true;
    validation.set_issuer(&[EXPECTED_ISS]);
    validation.set_audience(&[EXPECTED_AUD]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    jsonwebtoken::decode::<Claims>(token, key, &validation)
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
        Some(token) => decode_claims(token, state.jwt_verify_key()).and_then(|claims| {
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

/// Claims carried by the shared ES256 machine access token: `sub`, `role`,
/// `type: "access"`, `exp`, `iat`. Any service holding the shared
/// `JWT_VERIFY_KEY` can verify it (only [`issue_service_token`]'s caller
/// needs `JWT_SIGNING_KEY`) — this is the "machine JWT" shape used to gate
/// pki, sshca, and the manager's own gRPC surface.
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

/// Verifies an ES256 token verifiable with `key`: valid signature,
/// unexpired, and `type == "access"`. This is the sole authz input for
/// services with no local user database (pki, sshca) — there is no
/// role/scope check here beyond "this is a genuine, current access token".
pub fn verify_service_token(
    token: &str,
    key: &DecodingKey,
) -> Result<ServiceClaims, ServiceTokenError> {
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_exp = true;
    validation.required_spec_claims.clear();
    let data =
        jsonwebtoken::decode::<ServiceClaims>(token, key, &validation).map_err(|e| {
            match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => ServiceTokenError::Expired,
                _ => ServiceTokenError::Invalid,
            }
        })?;
    if data.claims.token_type != "access" {
        return Err(ServiceTokenError::InvalidType);
    }
    Ok(data.claims)
}

/// Issues an ES256 access token in the shared house shape, signed with
/// `key` (the private half loaded by [`load_jwt_signing_key`]). Mirrors
/// `services/manager/src/auth::create_access_token`; exposed here so any
/// service (or test) that needs to mint a machine/service token doesn't
/// hand-roll JWT encoding against a different claim shape.
pub fn issue_service_token(
    sub: &str,
    role: &str,
    key: &EncodingKey,
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
    jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, key)
}

fn bearer_token(raw: &str) -> Option<&str> {
    raw.strip_prefix("Bearer ")
}

/// Verifies the `authorization: Bearer <jwt>` gRPC metadata entry against
/// `key` — the tonic-side counterpart to [`AuthenticatedCaller`], for
/// gating tonic services (pki's `PKIService`, the manager's
/// `ManagerService`/`S3ScanService`).
pub fn verify_grpc_bearer(
    metadata: &tonic::metadata::MetadataMap,
    key: &DecodingKey,
) -> Result<ServiceClaims, ServiceTokenError> {
    let token = metadata
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token)
        .ok_or(ServiceTokenError::MissingOrInvalidHeader)?;
    verify_service_token(token, key)
}

/// Implemented by axum state types that expose the shared `JWT_VERIFY_KEY`
/// public key, so [`AuthenticatedCaller`]/[`tenant_middleware`] can verify
/// tokens as an extractor (or, via
/// `axum::middleware::from_extractor_with_state`, as a router-wide layer)
/// without each service reimplementing bearer-header parsing. Only the
/// issuer (the manager) additionally holds the private `JWT_SIGNING_KEY` —
/// deliberately not part of this trait, since no verifier needs it.
pub trait JwtSecretSource {
    /// Returns the shared `JWT_VERIFY_KEY` (public EC key) used to verify
    /// tokens.
    fn jwt_verify_key(&self) -> &DecodingKey;
}

impl<T: JwtSecretSource + ?Sized> JwtSecretSource for std::sync::Arc<T> {
    fn jwt_verify_key(&self) -> &DecodingKey {
        (**self).jwt_verify_key()
    }
}

/// Axum extractor requiring a valid Bearer access token verifiable with the
/// state's `JWT_VERIFY_KEY`. Unlike the manager's `CurrentUser`, this
/// performs no database lookup — signature + expiry + token type only —
/// because pki and sshca have no local user table.
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
        verify_service_token(token, state.jwt_verify_key()).map(AuthenticatedCaller)
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

/// A required JWT key (`JWT_SIGNING_KEY`/`JWT_VERIFY_KEY`) failed to load:
/// either missing/blank in production, or present but not a well-formed
/// PEM-encoded EC (P-256) key. The malformed-PEM case fails closed in
/// *every* environment (not just production) — a configured-but-broken
/// value must never be silently swapped for something else (a dev
/// ephemeral fallback there would be far more confusing to debug than a
/// hard failure at startup). Mirrors the pre-ES256 `MissingProductionSecret`
/// fail-fast style; the old `changeme`-style denylist no longer applies —
/// there's no equivalent "guessable placeholder" concept for a PEM key.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JwtKeyError {
    /// The named env var (`JWT_SIGNING_KEY`/`JWT_VERIFY_KEY`) was
    /// missing/blank and `RELEASE_MODE != "false"` requires a real key.
    #[error(
        "{0} must be set to a PEM-encoded EC (P-256) key in production (RELEASE_MODE != \"false\")"
    )]
    MissingInProduction(&'static str),
    /// The named env var was set but did not parse as a PEM-encoded EC key;
    /// the second field carries the underlying `jsonwebtoken` parse error.
    #[error("{0} is set but is not a valid PEM-encoded EC key: {1}")]
    InvalidPem(&'static str, String),
}

/// Pure fail-fast decision for a required PEM env var: `Ok(Some(value))`
/// when present (trimmed non-empty), `Ok(None)` when absent but acceptable
/// (non-production — the ephemeral dev keypair fallback applies, see
/// [`ephemeral_dev_keypair`]), `Err` when production requires a real value
/// and none was set.
fn resolve_required_pem<'a>(
    value: Option<&'a str>,
    production: bool,
    var_name: &'static str,
) -> Result<Option<&'a str>, JwtKeyError> {
    match value.map(str::trim).filter(|v| !v.is_empty()) {
        Some(v) => Ok(Some(v)),
        None if production => Err(JwtKeyError::MissingInProduction(var_name)),
        None => Ok(None),
    }
}

/// A single, process-lifetime ephemeral EC (P-256) keypair, generated only
/// when `JWT_SIGNING_KEY`/`JWT_VERIFY_KEY` are unset outside production —
/// mirrors the pre-ES256 `load_jwt_secret`'s "random ephemeral value, never
/// a hardcoded/guessable one" dev fallback. Cached (rather than regenerated
/// per call) so a single unconfigured process's own mint/verify round-trips
/// internally (this crate's own tests aside — they use a fixed fixture
/// keypair, never this path); it still does NOT let separate
/// processes/services with no configured key interoperate, exactly like
/// the old per-process ephemeral HS256 secret never did either — this is a
/// "don't crash" convenience, not a substitute for real key configuration
/// in any multi-service environment.
fn ephemeral_dev_keypair() -> &'static (EncodingKey, DecodingKey) {
    static KEYPAIR: std::sync::OnceLock<(EncodingKey, DecodingKey)> = std::sync::OnceLock::new();
    KEYPAIR.get_or_init(|| {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let private_pem = secret
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .unwrap_or_else(|e| {
                unreachable!("in-memory EC key PKCS#8 PEM encoding cannot fail: {e}")
            });
        let public_pem = secret
            .public_key()
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .unwrap_or_else(|e| {
                unreachable!("in-memory EC public key SPKI PEM encoding cannot fail: {e}")
            });
        let enc = EncodingKey::from_ec_pem(private_pem.as_bytes())
            .unwrap_or_else(|e| unreachable!("freshly generated EC private PEM must parse: {e}"));
        let dec = DecodingKey::from_ec_pem(public_pem.as_bytes())
            .unwrap_or_else(|e| unreachable!("freshly generated EC public PEM must parse: {e}"));
        (enc, dec)
    })
}

/// Parses a `JWT_SIGNING_KEY` PEM value into an [`EncodingKey`], wrapping a
/// parse failure as [`JwtKeyError::InvalidPem`]. Split out from
/// [`load_jwt_signing_key`] so the parse failure path is unit-testable
/// without mutating process environment variables (house policy rules out
/// `std::env::set_var` in tests).
fn parse_signing_pem(pem: &str, var_name: &'static str) -> Result<EncodingKey, JwtKeyError> {
    EncodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|e| JwtKeyError::InvalidPem(var_name, e.to_string()))
}

/// Parses a `JWT_VERIFY_KEY` PEM value into a [`DecodingKey`] — see
/// [`parse_signing_pem`].
fn parse_verify_pem(pem: &str, var_name: &'static str) -> Result<DecodingKey, JwtKeyError> {
    DecodingKey::from_ec_pem(pem.as_bytes())
        .map_err(|e| JwtKeyError::InvalidPem(var_name, e.to_string()))
}

/// Loads the private EC signing key from `JWT_SIGNING_KEY` (PEM, PKCS#8) —
/// the issuer-only half of the keypair (audit finding H1b: replaces the
/// single shared `JWT_SECRET_KEY` symmetric secret every service used to
/// both sign AND verify with). FAILS STARTUP in production
/// (`RELEASE_MODE != "false"`) when unset/blank, or unconditionally (any
/// environment) when set but not a parseable PEM EC key. In dev only, an
/// unset value falls back to a per-process ephemeral keypair — see
/// [`ephemeral_dev_keypair`].
pub fn load_jwt_signing_key() -> Result<EncodingKey, JwtKeyError> {
    let raw = std::env::var("JWT_SIGNING_KEY").ok();
    match resolve_required_pem(raw.as_deref(), is_production(), "JWT_SIGNING_KEY")? {
        Some(pem) => parse_signing_pem(pem, "JWT_SIGNING_KEY"),
        None => {
            tracing::warn!(
                "JWT_SIGNING_KEY not set — using an ephemeral in-process dev EC keypair"
            );
            Ok(ephemeral_dev_keypair().0.clone())
        }
    }
}

/// Loads the public EC verification key from `JWT_VERIFY_KEY` (PEM, SPKI) —
/// held by every verifying service (all of them; only the issuer also holds
/// [`load_jwt_signing_key`]'s private half). Same fail-closed policy as
/// [`load_jwt_signing_key`].
pub fn load_jwt_verify_key() -> Result<DecodingKey, JwtKeyError> {
    let raw = std::env::var("JWT_VERIFY_KEY").ok();
    match resolve_required_pem(raw.as_deref(), is_production(), "JWT_VERIFY_KEY")? {
        Some(pem) => parse_verify_pem(pem, "JWT_VERIFY_KEY"),
        None => {
            tracing::warn!("JWT_VERIFY_KEY not set — using an ephemeral in-process dev EC keypair");
            Ok(ephemeral_dev_keypair().1.clone())
        }
    }
}

/// Generates (once, cached) the canonical fixture ES256 keypair's PEM text
/// (PKCS#8 private / SPKI public) — never a hardcoded literal (secret
/// scanners rightly flag any embedded EC private key, test fixture or not).
/// Crate-private: [`test_fixture_keypair`] is the pub accessor other crates
/// use; this one exists only so this crate's own tests can exercise the
/// PEM-parsing path itself with real PEM text.
fn test_fixture_keypair_pem() -> &'static (String, String) {
    static PEM: std::sync::OnceLock<(String, String)> = std::sync::OnceLock::new();
    PEM.get_or_init(|| {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let private_pem = secret
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .unwrap_or_else(|e| {
                unreachable!("in-memory EC key PKCS#8 PEM encoding cannot fail: {e}")
            })
            .to_string();
        let public_pem = secret
            .public_key()
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .unwrap_or_else(|e| {
                unreachable!("in-memory EC public key SPKI PEM encoding cannot fail: {e}")
            });
        (private_pem, public_pem)
    })
}

/// The canonical throwaway ES256 (P-256) fixture keypair, generated once
/// per process at runtime and cached — the single source of truth every
/// consumer that needs this exact matched pair draws from, rather than each
/// embedding its own copy of the PEM text. `crates/skauswatch-testkit::jwt`'s
/// `signing_key`/`verify_key` and `services/manager::state`'s test-only
/// `AuthSettings::for_tests` construction both call this directly (this
/// crate is already a regular, non-dev dependency of both, unlike
/// `skauswatch-testkit` itself, which can't be pulled into
/// `skauswatch-manager`'s production dependency graph — see that module's
/// docs) — because both draw from the *same cached instance* within one
/// test process, a token minted via one consumer's `signing_key()` verifies
/// against the other's `jwt_verify_key` without either crate needing to
/// embed a byte-identical literal.
///
/// Not `#[cfg(test)]`-gated for the same reason [`ephemeral_dev_keypair`]
/// isn't: `services/manager`'s test-support code that calls this (via
/// `skauswatch-testkit`) is itself compiled unconditionally in that crate
/// (see `services/manager/src/state.rs`'s module docs), so this must be a
/// normal always-available function, not a `#[cfg(test)]` item invisible
/// outside this crate's own test builds.
pub fn test_fixture_keypair() -> &'static (EncodingKey, DecodingKey) {
    static KEYPAIR: std::sync::OnceLock<(EncodingKey, DecodingKey)> = std::sync::OnceLock::new();
    KEYPAIR.get_or_init(|| {
        let (private_pem, public_pem) = test_fixture_keypair_pem();
        let enc = EncodingKey::from_ec_pem(private_pem.as_bytes())
            .unwrap_or_else(|e| unreachable!("freshly generated EC private PEM must parse: {e}"));
        let dec = DecodingKey::from_ec_pem(public_pem.as_bytes())
            .unwrap_or_else(|e| unreachable!("freshly generated EC public PEM must parse: {e}"));
        (enc, dec)
    })
}

/// Test-only fixture wrappers — never a hardcoded PEM literal (secret
/// scanners rightly flag any embedded EC private key, test fixture or not).
/// [`signing_key`]/[`verify_key`] delegate to the crate-wide
/// [`test_fixture_keypair`] cache (see its docs for why this must be a
/// shared cache rather than an independently-generated local keypair);
/// [`other_signing_key`]/[`other_verify_key`] expose a second, independent
/// keypair — generated fresh per process, matched only with each other —
/// for exercising "signed with the wrong key" rejection paths.
#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod fixtures {
    use std::sync::OnceLock;

    use jsonwebtoken::{DecodingKey, EncodingKey};
    use pkcs8::{EncodePrivateKey, EncodePublicKey};

    pub(super) fn signing_key() -> &'static EncodingKey {
        &super::test_fixture_keypair().0
    }

    pub(super) fn verify_key() -> &'static DecodingKey {
        &super::test_fixture_keypair().1
    }

    fn generate_other_keypair() -> (EncodingKey, DecodingKey) {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let private_pem = secret
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .unwrap_or_else(|e| panic!("test fixture other keypair: private PEM encode: {e}"));
        let public_pem = secret
            .public_key()
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .unwrap_or_else(|e| panic!("test fixture other keypair: public PEM encode: {e}"));
        let enc = EncodingKey::from_ec_pem(private_pem.as_bytes())
            .unwrap_or_else(|e| panic!("test fixture other signing key: {e}"));
        let dec = DecodingKey::from_ec_pem(public_pem.as_bytes())
            .unwrap_or_else(|e| panic!("test fixture other verify key: {e}"));
        (enc, dec)
    }

    fn other_keypair() -> &'static (EncodingKey, DecodingKey) {
        static KEY: OnceLock<(EncodingKey, DecodingKey)> = OnceLock::new();
        KEY.get_or_init(generate_other_keypair)
    }

    pub(super) fn other_signing_key() -> &'static EncodingKey {
        &other_keypair().0
    }

    pub(super) fn other_verify_key() -> &'static DecodingKey {
        &other_keypair().1
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod service_token_tests {
    use super::fixtures::{other_verify_key, signing_key, verify_key};
    use super::*;

    #[test]
    fn issued_token_round_trips() {
        let token = match issue_service_token("42", "admin", signing_key(), 300) {
            Ok(t) => t,
            Err(e) => panic!("issue: {e}"),
        };
        let claims = match verify_service_token(&token, verify_key()) {
            Ok(c) => c,
            Err(e) => panic!("verify: {e:?}"),
        };
        assert_eq!(claims.sub, "42");
        assert_eq!(claims.role, "admin");
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn wrong_key_is_invalid() {
        let token = match issue_service_token("1", "viewer", signing_key(), 300) {
            Ok(t) => t,
            Err(e) => panic!("issue: {e}"),
        };
        assert_eq!(
            verify_service_token(&token, other_verify_key()),
            Err(ServiceTokenError::Invalid)
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        // jsonwebtoken's default `Validation` applies a 60s leeway, so the
        // expiry must be further in the past than that to actually trip.
        let token = match issue_service_token("1", "viewer", signing_key(), -120) {
            Ok(t) => t,
            Err(e) => panic!("issue: {e}"),
        };
        assert_eq!(
            verify_service_token(&token, verify_key()),
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
        let token =
            match jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, signing_key()) {
                Ok(t) => t,
                Err(e) => panic!("encode: {e}"),
            };
        assert_eq!(
            verify_service_token(&token, verify_key()),
            Err(ServiceTokenError::InvalidType)
        );
    }

    #[test]
    fn garbage_token_is_invalid_not_a_panic() {
        assert_eq!(
            verify_service_token("not-a-jwt", verify_key()),
            Err(ServiceTokenError::Invalid)
        );
    }

    #[test]
    fn grpc_bearer_requires_authorization_metadata() {
        let md = tonic::metadata::MetadataMap::new();
        assert_eq!(
            verify_grpc_bearer(&md, verify_key()),
            Err(ServiceTokenError::MissingOrInvalidHeader)
        );
    }

    #[test]
    fn grpc_bearer_accepts_valid_token() {
        let token = match issue_service_token("svc", "worker", signing_key(), 300) {
            Ok(t) => t,
            Err(e) => panic!("issue: {e}"),
        };
        let mut md = tonic::metadata::MetadataMap::new();
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        md.insert("authorization", value);
        assert!(verify_grpc_bearer(&md, verify_key()).is_ok());
    }

    #[test]
    fn arc_wrapped_state_forwards_jwt_verify_key() {
        struct Fixed(DecodingKey);
        impl JwtSecretSource for Fixed {
            fn jwt_verify_key(&self) -> &DecodingKey {
                &self.0
            }
        }
        let state = std::sync::Arc::new(Fixed(verify_key().clone()));
        // No `PartialEq` on `DecodingKey` — round-trip a token through it
        // to prove the Arc-forwarded key is the genuine fixture key, not a
        // default/empty one.
        let token = issue_service_token("1", "admin", signing_key(), 300)
            .unwrap_or_else(|e| panic!("issue: {e}"));
        assert!(verify_service_token(&token, state.jwt_verify_key()).is_ok());
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
    fn resolve_required_pem_fails_closed_in_production() {
        assert!(matches!(
            resolve_required_pem(None, true, "JWT_SIGNING_KEY"),
            Err(JwtKeyError::MissingInProduction("JWT_SIGNING_KEY"))
        ));
        assert!(matches!(
            resolve_required_pem(Some(""), true, "JWT_SIGNING_KEY"),
            Err(JwtKeyError::MissingInProduction("JWT_SIGNING_KEY"))
        ));
        assert!(matches!(
            resolve_required_pem(Some("   "), true, "JWT_VERIFY_KEY"),
            Err(JwtKeyError::MissingInProduction("JWT_VERIFY_KEY"))
        ));
        assert_eq!(
            resolve_required_pem(Some("-----BEGIN..."), true, "JWT_SIGNING_KEY"),
            Ok(Some("-----BEGIN..."))
        );
    }

    #[test]
    fn resolve_required_pem_allows_absence_outside_production() {
        assert_eq!(
            resolve_required_pem(None, false, "JWT_SIGNING_KEY"),
            Ok(None)
        );
        assert_eq!(
            resolve_required_pem(Some("x"), false, "JWT_SIGNING_KEY"),
            Ok(Some("x"))
        );
        assert_eq!(
            resolve_required_pem(Some(""), false, "JWT_SIGNING_KEY"),
            Ok(None)
        );
    }

    #[test]
    fn parse_signing_pem_rejects_garbage_in_every_environment() {
        match parse_signing_pem("not a pem", "JWT_SIGNING_KEY") {
            Err(JwtKeyError::InvalidPem("JWT_SIGNING_KEY", _)) => {}
            other => panic!("expected InvalidPem, got {other:?}"),
        }
    }

    #[test]
    fn parse_verify_pem_rejects_garbage_in_every_environment() {
        match parse_verify_pem("not a pem", "JWT_VERIFY_KEY") {
            Err(JwtKeyError::InvalidPem("JWT_VERIFY_KEY", _)) => {}
            other => panic!("expected InvalidPem, got {other:?}"),
        }
    }

    #[test]
    fn parse_signing_pem_rejects_a_public_key_pem_as_a_signing_key() {
        // A syntactically valid PEM of the wrong kind (public, not
        // private) must still fail closed, not silently succeed.
        let (_, verify_pem) = super::test_fixture_keypair_pem();
        assert!(parse_signing_pem(verify_pem, "JWT_SIGNING_KEY").is_err());
    }

    #[test]
    fn parse_signing_pem_and_parse_verify_pem_accept_the_fixture_keypair() {
        let (signing_pem, verify_pem) = super::test_fixture_keypair_pem();
        assert!(parse_signing_pem(signing_pem, "JWT_SIGNING_KEY").is_ok());
        assert!(parse_verify_pem(verify_pem, "JWT_VERIFY_KEY").is_ok());
    }

    #[test]
    fn ephemeral_dev_keypair_mints_and_verifies_a_round_trip() {
        // Pure in-memory keygen — no env vars touched, so this is safe to
        // run in parallel with every other test in this crate.
        let (enc, dec) = ephemeral_dev_keypair();
        let token = issue_service_token("1", "admin", enc, 300)
            .unwrap_or_else(|e| panic!("issue with ephemeral key: {e}"));
        let claims = verify_service_token(&token, dec)
            .unwrap_or_else(|e| panic!("verify with ephemeral key: {e:?}"));
        assert_eq!(claims.sub, "1");
    }

    #[test]
    fn ephemeral_dev_keypair_is_cached_across_calls() {
        // OnceLock semantics: repeated calls return the same keypair, not a
        // freshly generated one each time — a token minted with the first
        // call's signing key must still verify against the second call's
        // verify key.
        let (enc1, _) = ephemeral_dev_keypair();
        let token =
            issue_service_token("1", "admin", enc1, 300).unwrap_or_else(|e| panic!("issue: {e}"));
        let (_, dec2) = ephemeral_dev_keypair();
        assert!(verify_service_token(&token, dec2).is_ok());
    }

    #[test]
    fn load_jwt_signing_key_never_panics_when_unset() {
        // Whatever the ambient RELEASE_MODE/JWT_SIGNING_KEY happen to be in
        // this process, this must not panic — either a real key, an
        // ephemeral one, or a clean Err.
        let _ = load_jwt_signing_key();
    }

    #[test]
    fn load_jwt_verify_key_never_panics_when_unset() {
        let _ = load_jwt_verify_key();
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

    use super::fixtures::{other_signing_key, signing_key, verify_key};
    use super::*;

    #[derive(Clone)]
    struct TestState;

    impl JwtSecretSource for TestState {
        fn jwt_verify_key(&self) -> &DecodingKey {
            verify_key()
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

    fn sign(claims: &Claims, key: &EncodingKey) -> String {
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), claims, key)
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

    fn sign_without_tenant(key: &EncodingKey) -> String {
        let claims = ClaimsWithoutTenant {
            sub: "u-1".into(),
            iss: EXPECTED_ISS.into(),
            aud: EXPECTED_AUD.into(),
            iat: 0,
            exp: i64::MAX,
            scope: "*:read".into(),
        };
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, key)
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

    fn sign_without_iss_aud(key: &EncodingKey) -> String {
        let claims = ClaimsWithoutIssAud {
            sub: "u-1".into(),
            iat: 0,
            exp: i64::MAX,
            scope: "*:read".into(),
            tenant: "acme".into(),
        };
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, key)
            .unwrap_or_else(|e| panic!("sign: {e}"))
    }

    // -- decode_claims -------------------------------------------------

    #[test]
    fn decode_claims_round_trips_tenant() {
        let token = sign(&claims_with_tenant("acme"), signing_key());
        let decoded = match decode_claims(&token, verify_key()) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(decoded.tenant, "acme");
    }

    #[test]
    fn decode_claims_defaults_absent_tenant_to_empty_string() {
        let token = sign_without_tenant(signing_key());
        let decoded = match decode_claims(&token, verify_key()) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(decoded.tenant, "");
    }

    #[test]
    fn decode_claims_rejects_wrong_key() {
        let token = sign(&claims_with_tenant("acme"), signing_key());
        assert_eq!(
            decode_claims(&token, super::fixtures::other_verify_key()),
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
        let token = sign(&c, signing_key());
        assert_eq!(
            decode_claims(&token, verify_key()),
            Err(TenantAuthError::Expired)
        );
    }

    #[test]
    fn decode_claims_rejects_garbage() {
        assert_eq!(
            decode_claims("not-a-jwt", verify_key()),
            Err(TenantAuthError::Invalid)
        );
    }

    #[test]
    fn decode_claims_accepts_correct_issuer_and_audience() {
        let token = sign(&claims_with_tenant("acme"), signing_key());
        assert!(decode_claims(&token, verify_key()).is_ok());
    }

    #[test]
    fn decode_claims_rejects_wrong_issuer() {
        let mut c = claims_with_tenant("acme");
        c.iss = "https://evil.example.com".into();
        let token = sign(&c, signing_key());
        assert_eq!(
            decode_claims(&token, verify_key()),
            Err(TenantAuthError::Invalid)
        );
    }

    #[test]
    fn decode_claims_rejects_wrong_audience() {
        let mut c = claims_with_tenant("acme");
        c.aud = "not-skauswatch".into();
        let token = sign(&c, signing_key());
        assert_eq!(
            decode_claims(&token, verify_key()),
            Err(TenantAuthError::Invalid)
        );
    }

    #[test]
    fn decode_claims_rejects_missing_issuer_and_audience() {
        let token = sign_without_iss_aud(signing_key());
        assert_eq!(
            decode_claims(&token, verify_key()),
            Err(TenantAuthError::Invalid)
        );
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
        let token = sign(&claims_with_tenant("acme"), signing_key());
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
        let token = sign(&claims_with_tenant("   "), signing_key());
        let resp = app()
            .oneshot(request_with_auth(Some(&format!("Bearer {token}"))))
            .await
            .unwrap_or_else(|e| panic!("response: {e}"));
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn absent_tenant_claim_is_403_not_401() {
        let token = sign_without_tenant(signing_key());
        let resp = app()
            .oneshot(request_with_auth(Some(&format!("Bearer {token}"))))
            .await
            .unwrap_or_else(|e| panic!("response: {e}"));
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn wrong_key_is_401_not_403() {
        let token = sign(&claims_with_tenant("acme"), other_signing_key());
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
