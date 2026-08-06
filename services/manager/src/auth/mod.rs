//! Authentication: bcrypt password hashes, HS256 access tokens in the house
//! `skauswatch_auth::Claims` shape (`sub/iss/aud/iat/exp/scope/tenant/teams/
//! roles` — see `security.md` Authentication & Authorization), and the
//! `CurrentUser` extractor that mirrors v1's `@auth_required`.
//!
//! Tenancy retrofit (docs/v2-port/tenancy-model.md): the access token used to
//! be the exact v1 shape (`{sub, role, type, exp, iat}`) — that is now
//! replaced by the shared `Claims` model so every access token carries a
//! `tenant` claim, per the hard tenant-isolation boundary in `security.md`.
//! This is a deliberate wire-contract break; `docs/v2-port/tenancy-model.md`
//! §8 records the confirmation that no in-repo client (webui, ENDPOINT
//! agents) decodes JWT claims directly — both only read the JSON response
//! *bodies* of `/auth/login`/`/auth/me` (unchanged shapes), never the token
//! payload, so this is safe. Refresh tokens keep their own minimal
//! `RefreshClaims` shape unchanged: they carry no `tenant` claim at all —
//! rotation reads `tenant_id` straight off the `refresh_tokens` row instead
//! (denormalized from `users` at issuance), never re-deriving it from a
//! second `users` join. `ServiceClaims` (pki/sshca/this service's own gRPC
//! surface) is a separate, tenant-free machine-token shape and is untouched
//! by this change — see `skauswatch_auth::ServiceClaims` docs.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use chrono::Utc;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use skauswatch_auth::Claims;

use crate::error::ApiError;
use crate::state::AppState;

/// Issuer/audience stamped on every access token this service mints —
/// matches the fixture values already established elsewhere in the
/// workspace for `skauswatch_auth::Claims` (e.g. `services/monitor`).
const CLAIMS_ISSUER: &str = "https://auth.skauswatch.app";
const CLAIMS_AUDIENCE: &str = "skauswatch";

/// Fixed, reproducible bootstrap tenant seeded by
/// `migrations/0002_tenancy.sql` — literal value must match the migration's
/// seed row exactly. Self-service `/auth/register` has no admin/inviter
/// context to derive a tenant from, so new registrants are attached here
/// (v2.0 decision: admin-provisioned tenants, single default tenant — see
/// docs/v2-port/tenancy-model.md §8; self-serve multi-tenant signup is a
/// v2.1 backlog item).
pub(crate) const DEFAULT_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";

/// Parses [`DEFAULT_TENANT_ID`] into a `Uuid`. The constant is a hardcoded,
/// compile-time-known literal — not user input, never fallible in practice
/// — so a parse failure here can only mean the literal itself was typo'd;
/// panicking immediately at the call site is preferable to threading a
/// spurious `Result` for an error that can never occur at runtime.
#[allow(clippy::panic)]
pub(crate) fn default_tenant_uuid() -> uuid::Uuid {
    DEFAULT_TENANT_ID
        .parse()
        .unwrap_or_else(|e| panic!("DEFAULT_TENANT_ID is not a valid UUID literal: {e}"))
}

/// Expands a role name into the house OIDC scope bundle it corresponds to
/// (`security.md` "Scope bundles"). `users.role` remains the authoritative
/// permission model for this service's existing role-gated routes
/// (`CurrentUser::require_role` — the ~89-site scope-based-authz migration
/// is out of scope for the tenancy retrofit); `scope` is populated on the
/// minted JWT so any current/future consumer that authorizes on
/// `skauswatch_auth::Claims::has_scope` instead sees an equivalent bundle.
/// Unknown roles get no scope at all — fail closed, never a guessed bundle.
pub(crate) fn role_scope_bundle(role: &str) -> &'static str {
    match role {
        "admin" => "*:read *:write *:admin *:delete settings:write users:admin",
        "maintainer" => "*:read *:write teams:read reports:read analytics:read",
        "viewer" => "*:read",
        // `super_admin` is a manager-internal, DB-only role (never settable
        // via the public users API — see `routes/users.rs::ROLES`) used
        // solely to gate `routes::tenants::create_tenant`; it needs no
        // scope bundle of its own today since that gate checks
        // `CurrentUser::require_role` directly, not `Claims::has_scope`.
        _ => "",
    }
}

/// Refresh-token claims — v1 shape (`sub`/`type`/`exp`/`iat`) plus a `jti`
/// nonce. Bug found via real-DB testing (`docs/v2-port/testing-pattern.md`):
/// v1's Python `datetime.utcnow().timestamp()` carries microsecond
/// precision, but the Rust port's `Utc::now().timestamp()` truncates to
/// whole seconds — so two refresh tokens minted for the same user within
/// the same wall-clock second (e.g. login immediately followed by refresh,
/// or two concurrent refreshes) become byte-identical JWTs. Since
/// `refresh_tokens.token_hash` is `UNIQUE` (schema authority:
/// `tests/parity/seed_v2.sql`), the second `INSERT` in `issue_token_pair`
/// then fails with a constraint violation, surfacing as a 500 on an
/// otherwise-valid request. `jti` is a fresh UUID per issuance, guaranteeing
/// `token_hash` uniqueness regardless of timing; it is never validated on
/// decode (`#[serde(default)]`), so it changes nothing about the v1 wire
/// contract — no client ever inspects individual JWT claims, only the
/// opaque `access_token`/`refresh_token` strings in the HTTP response body.
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
    /// Per-issuance random nonce — see struct docs.
    #[serde(default)]
    pub jti: String,
}

/// Issues an access token in the house `skauswatch_auth::Claims` shape.
/// `tenant` must be a stringified tenant UUID (see `DEFAULT_TENANT_ID`,
/// or a caller's own `CurrentUser::tenant_id`/`users.tenant_id` row) — never
/// empty, since every downstream consumer (this service's own
/// `tenant_middleware`/`CurrentUser`, and any future service that adopts
/// the shared `Claims` model) rejects a token with no usable tenant claim.
pub fn create_access_token(
    user_id: i32,
    role: &str,
    tenant: &str,
    secret: &str,
    expires_minutes: i64,
) -> Result<String, ApiError> {
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: user_id.to_string(),
        iss: CLAIMS_ISSUER.to_owned(),
        aud: CLAIMS_AUDIENCE.to_owned(),
        iat: now,
        exp: now + expires_minutes * 60,
        scope: role_scope_bundle(role).to_owned(),
        tenant: tenant.to_owned(),
        teams: vec![],
        roles: vec![role.to_owned()],
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
        jti: uuid::Uuid::new_v4().to_string(),
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
/// jwt.decode-then-`payload.get("type")` ordering. Used by [`decode_refresh`]
/// only — [`decode_access`] uses `skauswatch_auth::decode_claims` instead,
/// since the access token has moved to the shared `Claims` shape.
fn decode_generic_claims(
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

/// Decodes and tenant-validates an access token: HS256 signature, expiry,
/// and a non-empty `tenant` claim — the same tenant-isolation boundary
/// `skauswatch_auth::tenant_middleware` enforces at the router layer,
/// enforced again here so `CurrentUser` fails closed even for a handler
/// reached through a router that (for whatever reason, e.g. a per-module
/// test router) never mounted the outer middleware. "Token expired"/
/// "Invalid token" wording matches v1's `auth_required` messages.
pub fn decode_access(token: &str, secret: &str) -> Result<Claims, ApiError> {
    let claims = skauswatch_auth::decode_claims(token, secret).map_err(|e| match e {
        skauswatch_auth::TenantAuthError::Expired => {
            ApiError::Unauthorized("Token expired".to_owned())
        }
        _ => ApiError::Unauthorized("Invalid token".to_owned()),
    })?;
    claims
        .require_tenant()
        .map_err(|_| ApiError::Forbidden("missing or empty tenant claim".to_owned()))?;
    Ok(claims)
}

/// Decodes and type-checks a refresh token (v1 `/auth/refresh` strings).
pub fn decode_refresh(token: &str, secret: &str) -> Result<RefreshClaims, ApiError> {
    let claims = decode_generic_claims(
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
    /// Role (admin/maintainer/viewer/super_admin).
    pub role: String,
    /// Active flag.
    pub is_active: bool,
    /// MFA enabled flag.
    pub mfa_enabled: bool,
    /// Creation timestamp (RFC3339).
    pub created_at: Option<String>,
    /// The caller's tenant, read from `users.tenant_id` (the DB row, not
    /// the JWT claim — same convention `role` already followed before this
    /// field existed: the token authenticates identity, the database row is
    /// the authoritative source for everything else). Every tenant-scoped
    /// query/insert a handler issues must filter/stamp on this, never on a
    /// client-supplied value — see docs/v2-port/tenancy-model.md §4.
    pub tenant_id: uuid::Uuid,
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
            "SELECT id, email, full_name, role, is_active, mfa_enabled, created_at::text, \
                    tenant_id \
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
    /// Tenant — authoritative source for `CurrentUser::tenant_id`.
    pub tenant_id: uuid::Uuid,
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
            tenant_id: r.tenant_id,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    const SECRET: &str = "test-secret";

    #[test]
    fn access_token_roundtrips_with_tenant_and_scope() {
        let token = match create_access_token(42, "admin", "tenant-a", SECRET, 30) {
            Ok(t) => t,
            Err(e) => panic!("encode: {e:?}"),
        };
        let claims = match decode_access(&token, SECRET) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(claims.sub, "42");
        assert_eq!(claims.tenant, "tenant-a");
        assert_eq!(claims.iss, CLAIMS_ISSUER);
        assert_eq!(claims.aud, CLAIMS_AUDIENCE);
        assert!(claims.has_scope("users:admin"));
        assert_eq!(claims.roles, vec!["admin".to_owned()]);
    }

    #[test]
    fn role_scope_bundle_matches_security_md_and_fails_closed_on_unknown() {
        assert!(role_scope_bundle("admin").contains("users:admin"));
        assert!(role_scope_bundle("maintainer").contains("teams:read"));
        assert_eq!(role_scope_bundle("viewer"), "*:read");
        assert_eq!(role_scope_bundle("not-a-role"), "");
    }

    #[test]
    fn access_token_with_empty_tenant_is_rejected_by_decode() {
        // create_access_token itself never validates its `tenant` argument —
        // the tenant-isolation boundary is enforced on decode, matching
        // `skauswatch_auth::tenant_middleware`'s "reject if absent/empty"
        // contract (never a silent bypass at mint time).
        let token = match create_access_token(1, "viewer", "", SECRET, 30) {
            Ok(t) => t,
            Err(e) => panic!("encode: {e:?}"),
        };
        match decode_access(&token, SECRET) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "missing or empty tenant claim"),
            other => panic!("expected 403, got {other:?}"),
        }
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
        let claims = Claims {
            sub: "1".into(),
            iss: CLAIMS_ISSUER.into(),
            aud: CLAIMS_AUDIENCE.into(),
            iat: now - 240,
            exp: now - 120,
            scope: role_scope_bundle("viewer").to_owned(),
            tenant: "tenant-a".into(),
            teams: vec![],
            roles: vec!["viewer".into()],
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

    fn parts_with_auth(header: Option<&str>) -> axum::http::request::Parts {
        let mut builder = axum::http::Request::builder().method("GET").uri("/x");
        if let Some(h) = header {
            builder = builder.header(axum::http::header::AUTHORIZATION, h);
        }
        let req = match builder.body(()) {
            Ok(r) => r,
            Err(e) => panic!("request: {e}"),
        };
        req.into_parts().0
    }

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    #[tokio::test]
    async fn current_user_rejects_missing_header() {
        let state = crate::state::AppStateInner::for_tests(dev_license());
        let mut parts = parts_with_auth(None);
        match CurrentUser::from_request_parts(&mut parts, &state).await {
            Err(ApiError::Unauthorized(msg)) => {
                assert_eq!(msg, "Missing or invalid authorization header");
            }
            other => panic!("expected 401, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn current_user_rejects_non_bearer_scheme() {
        let state = crate::state::AppStateInner::for_tests(dev_license());
        let mut parts = parts_with_auth(Some("Token abc"));
        match CurrentUser::from_request_parts(&mut parts, &state).await {
            Err(ApiError::Unauthorized(msg)) => {
                assert_eq!(msg, "Missing or invalid authorization header");
            }
            other => panic!("expected 401, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn current_user_rejects_garbage_token() {
        let state = crate::state::AppStateInner::for_tests(dev_license());
        let mut parts = parts_with_auth(Some("Bearer not-a-jwt"));
        match CurrentUser::from_request_parts(&mut parts, &state).await {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "Invalid token"),
            other => panic!("expected 401, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn current_user_rejects_unknown_user_id_against_real_db() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = create_access_token(
            999_999,
            "admin",
            DEFAULT_TENANT_ID,
            &state.auth.jwt_secret,
            30,
        )
        .unwrap_or_else(|e| panic!("encode: {e:?}"));
        let mut parts = parts_with_auth(Some(&format!("Bearer {token}")));
        match CurrentUser::from_request_parts(&mut parts, &state).await {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "User not found or inactive"),
            other => panic!("expected 401, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn current_user_rejects_inactive_user() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let (id,): (i32,) = match sqlx::query_as(
            "INSERT INTO users (email, password_hash, full_name, role, is_active, created_at, \
             tenant_id) \
             VALUES ('inactive@example.com', 'x', 'Inactive', 'viewer', false, now(), $1) \
             RETURNING id",
        )
        .bind(default_tenant_uuid())
        .fetch_one(&state.db)
        .await
        {
            Ok(r) => r,
            Err(e) => panic!("seed: {e}"),
        };
        let token =
            create_access_token(id, "viewer", DEFAULT_TENANT_ID, &state.auth.jwt_secret, 30)
                .unwrap_or_else(|e| panic!("encode: {e:?}"));
        let mut parts = parts_with_auth(Some(&format!("Bearer {token}")));
        match CurrentUser::from_request_parts(&mut parts, &state).await {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "User not found or inactive"),
            other => panic!("expected 401, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn current_user_resolves_active_user_from_db() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let (id, token) =
            crate::routes::test_support::authed_user(&state, "active@example.com", "admin").await;
        let mut parts = parts_with_auth(Some(&format!("Bearer {token}")));
        let user = match CurrentUser::from_request_parts(&mut parts, &state).await {
            Ok(u) => u,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(user.id, id);
        assert_eq!(user.email, "active@example.com");
        assert_eq!(user.role, "admin");
        assert!(user.is_active);
        assert_eq!(user.tenant_id.to_string(), DEFAULT_TENANT_ID);
    }

    #[tokio::test]
    async fn current_user_rejects_token_with_no_tenant_even_without_outer_middleware() {
        // Defense in depth: CurrentUser enforces the tenant boundary itself
        // (see decode_access), independent of whether tenant_middleware ran
        // — this is what every per-module test router (which never mounts
        // tenant_middleware) implicitly relies on.
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let (id, _) =
            crate::routes::test_support::authed_user(&state, "no-tenant@example.com", "admin")
                .await;
        let token = create_access_token(id, "admin", "", &state.auth.jwt_secret, 30)
            .unwrap_or_else(|e| panic!("encode: {e:?}"));
        let mut parts = parts_with_auth(Some(&format!("Bearer {token}")));
        match CurrentUser::from_request_parts(&mut parts, &state).await {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "missing or empty tenant claim"),
            other => panic!("expected 403, got {other:?}"),
        }
    }

    #[test]
    fn require_role_allows_and_denies() {
        let user = CurrentUser {
            id: 1,
            email: "u@example.com".to_owned(),
            full_name: None,
            role: "viewer".to_owned(),
            is_active: true,
            mfa_enabled: false,
            created_at: None,
            tenant_id: uuid::Uuid::nil(),
        };
        assert!(user.require_role(&["viewer", "admin"]).is_ok());
        match user.require_role(&["admin"]) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Insufficient permissions"),
            other => panic!("expected 403, got {other:?}"),
        }
    }
}
