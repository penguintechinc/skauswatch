//! AuthN/Z for the CodeScan backend. Tokens are issued centrally by the
//! manager service (`services/manager/src/auth/mod.rs`) in the house
//! `skauswatch_auth::Claims` shape (`sub/iss/aud/iat/exp/scope/tenant/teams/
//! roles`). This service has no local identity table (see
//! migrations/0001_codescan_schema.sql), so `CurrentUser` trusts the decoded
//! claims directly rather than round-tripping to a users table; role-based
//! authorization decisions are made on `roles` (the JWT's role list) only,
//! matching the v1 Flask `role_required` decorator this service replaces.
//!
//! Tenancy retrofit (docs/v2-port/tenancy-model.md): this service used to
//! decode a local, tenant-free `AccessClaims` shape (`{sub, role, type, exp,
//! iat}`) and — separately, and incorrectly — read `tenant_id` straight off
//! the client-supplied request body in `repos.rs`/`reviews.rs` (a live IDOR:
//! any caller could stamp an arbitrary tenant on a row it created, or read
//! another tenant's `repo_config_id`-referenced rows). Both are fixed here:
//! `CurrentUser` now carries a `tenant_id` sourced *only* from the validated
//! JWT's `tenant` claim (never a request body/path/query value — see
//! `security.md`'s tenant-isolation rule), and every handler filters/stamps
//! on it (see `routes/*.rs`).
//!
//! Every non-public route requires a valid `CurrentUser` — there is no
//! bypass. This is the defense-in-depth layer behind both the manager's own
//! JWT check on `/api/v1/codescan/*` (services/manager/src/routes/codescan.rs)
//! and the router-wide `skauswatch_auth::tenant_middleware` layer
//! (`routes::router`) — `CurrentUser` decodes and tenant-checks the token
//! itself rather than relying on `TenantContext` from request extensions, so
//! it still fails closed for any per-module test router that never mounts
//! the outer middleware (mirrors `services/manager/src/auth/mod.rs`).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use skauswatch_auth::Claims;

use crate::error::ApiError;
use crate::state::AppState;

/// Decodes and tenant-validates an access token: HS256 signature, expiry,
/// and a non-empty `tenant` claim — the same boundary
/// `skauswatch_auth::tenant_middleware` enforces at the router layer.
/// "Token expired"/"Invalid token" wording matches the v1 `auth_required`
/// messages this service's error bodies still follow.
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

/// The authenticated caller, derived entirely from JWT claims — no DB lookup
/// (this service owns no local users table).
#[derive(Debug, Clone)]
pub struct CurrentUser {
    /// User id, from the token's `sub` claim.
    pub id: i64,
    /// Role name (admin/maintainer/viewer) — the token's primary role, i.e.
    /// the first entry of `Claims::roles` (the manager mints exactly one
    /// role per token today; see `role_scope_bundle` in
    /// `services/manager/src/auth/mod.rs`).
    pub role: String,
    /// Tenant boundary, parsed from the validated `Claims::tenant` claim.
    /// The *only* legitimate source of this value — never a client-supplied
    /// request body/path/query field. Every tenant-scoped query/insert a
    /// handler issues must filter/stamp on this (see
    /// docs/v2-port/tenancy-model.md §4).
    pub tenant_id: uuid::Uuid,
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
        // `require_tenant` in `decode_access` already rejected an
        // empty/absent claim, so this parse only fails on a malformed UUID
        // literal — treat identically to any other invalid-token case.
        let tenant_id: uuid::Uuid = claims
            .tenant
            .parse()
            .map_err(|_| ApiError::Forbidden("missing or empty tenant claim".to_owned()))?;
        Ok(CurrentUser {
            id: user_id,
            role: claims.roles.first().cloned().unwrap_or_default(),
            tenant_id,
        })
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};

    const SECRET: &str = "test-secret";
    const TENANT: &str = "00000000-0000-0000-0000-0000000000aa";

    fn claims(sub: &str, tenant: &str, roles: &[&str], exp_offset: i64) -> Claims {
        let now = chrono::Utc::now().timestamp();
        Claims {
            sub: sub.to_owned(),
            iss: "https://auth.skauswatch.app".to_owned(),
            aud: "skauswatch".to_owned(),
            iat: now,
            exp: now + exp_offset,
            scope: String::new(),
            tenant: tenant.to_owned(),
            teams: vec![],
            roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        }
    }

    fn sign(claims: &Claims) -> String {
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
        let token = sign(&claims("42", TENANT, &["admin"], 60));
        let decoded = match decode_access(&token, SECRET) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(decoded.sub, "42");
        assert_eq!(decoded.roles, vec!["admin".to_owned()]);
        assert_eq!(decoded.tenant, TENANT);
    }

    /// Regression: this service used to decode a local, tenant-free
    /// `AccessClaims` shape via `serde_json::from_value`, which silently
    /// dropped any `tenant`/`teams` fields present on the token (they simply
    /// weren't part of the target struct). That was the actual mechanism
    /// behind the tenant-isolation gap this change fixes — decoding onto the
    /// house `Claims` shape must do the opposite: honor `tenant` and reject
    /// a token that lacks one, never silently discard it.
    #[test]
    fn tenant_and_team_claims_are_honored_not_dropped() {
        let mut c = claims("7", TENANT, &["maintainer"], 60);
        c.teams = vec!["team-a".to_owned()];
        let token = sign(&c);
        let decoded = match decode_access(&token, SECRET) {
            Ok(c) => c,
            Err(e) => panic!("decode: {e:?}"),
        };
        assert_eq!(decoded.tenant, TENANT, "tenant claim must survive decode");
        assert_eq!(decoded.teams, vec!["team-a".to_owned()]);
    }

    #[test]
    fn missing_tenant_claim_is_rejected_as_forbidden() {
        let token = sign(&claims("1", "", &["viewer"], 60));
        match decode_access(&token, SECRET) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "missing or empty tenant claim"),
            other => panic!("expected 403 missing tenant, got {other:?}"),
        }
    }

    #[test]
    fn expired_token_maps_to_token_expired() {
        let token = sign(&claims("1", TENANT, &["viewer"], -120));
        match decode_access(&token, SECRET) {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "Token expired"),
            other => panic!("expected 401 Token expired, got {other:?}"),
        }
    }

    #[test]
    fn wrong_secret_is_rejected_as_invalid_token() {
        let token = sign(&claims("1", TENANT, &["viewer"], 60));
        match decode_access(&token, "wrong-secret") {
            Err(ApiError::Unauthorized(msg)) => assert_eq!(msg, "Invalid token"),
            other => panic!("expected 401 Invalid token, got {other:?}"),
        }
    }

    #[test]
    fn require_role_matches_v1_role_required() {
        let admin = CurrentUser {
            id: 1,
            role: "admin".to_owned(),
            tenant_id: TENANT.parse().unwrap_or_else(|e| panic!("uuid: {e}")),
        };
        assert!(admin.require_role(&["admin", "maintainer"]).is_ok());
        let viewer = CurrentUser {
            id: 2,
            role: "viewer".to_owned(),
            tenant_id: TENANT.parse().unwrap_or_else(|e| panic!("uuid: {e}")),
        };
        match viewer.require_role(&["admin", "maintainer"]) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Insufficient permissions"),
            other => panic!("expected 403, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn current_user_extractor_populates_tenant_id_from_claims() {
        use crate::state::AppStateInner;
        use axum::body::Body;
        use axum::http::Request as HttpRequest;
        use axum::http::header::AUTHORIZATION;
        use penguin_licensing::{LicenseClient, LicenseConfig};

        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let license = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        let state = AppStateInner::for_tests(license);
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.auth.jwt_secret,
            "5",
            TENANT,
            "",
            &["admin"],
        );
        let (mut parts, _body) = HttpRequest::builder()
            .uri("/probe")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap_or_else(|e| panic!("request: {e}"))
            .into_parts();
        let user = match CurrentUser::from_request_parts(&mut parts, &state).await {
            Ok(u) => u,
            Err(e) => panic!("extract: {e:?}"),
        };
        assert_eq!(user.id, 5);
        assert_eq!(user.role, "admin");
        assert_eq!(user.tenant_id.to_string(), TENANT);
    }
}
