//! AuthN/Z for the CodeScan backend. Tokens are issued centrally by the
//! manager service (`services/manager/src/auth/mod.rs`) in the house
//! `skauswatch_auth::Claims` shape (`sub/iss/aud/iat/exp/scope/tenant/teams/
//! roles`). This service has no local identity table (see
//! migrations/0001_codescan_schema.sql), so `CurrentUser` trusts the decoded
//! claims directly rather than round-tripping to a users table.
//!
//! Security hardening (`security.md` Authentication & Authorization:
//! "authorization decisions use `scope` only, never role names"):
//! authorization used to branch on `Claims::roles` directly
//! (`CurrentUser::require_role`, matching the v1 Flask `role_required`
//! decorator this service originally ported). That is replaced here with
//! scope checks against [`ADMIN_SCOPE`]/[`WRITE_SCOPE`] via
//! `skauswatch_auth::Claims::require_scope` — the same wildcard-aware
//! matcher `services/depgate/src/auth.rs`'s `AuthedUser` and
//! `services/vault/src/auth.rs` already authorize through. `roles` is now
//! purely informational/audit (still carried on [`CurrentUser`] for that
//! purpose), never branched on for an authz decision.
//!
//! The manager mints `scope` from `role_scope_bundle`
//! (`services/manager/src/auth/mod.rs`): `admin` gets `*:admin` (and
//! `*:write`/`*:read`), `maintainer` gets `*:write`/`*:read` only, `viewer`
//! gets `*:read` only. [`ADMIN_SCOPE`] (`codescan:admin`) is therefore
//! satisfied by `admin` alone — identical to the old `require_role(&
//! ["admin"])` gate. [`WRITE_SCOPE`] (`codescan:write`) is satisfied by
//! both `admin` and `maintainer` (both bundles carry the `*:write`
//! wildcard) — a deliberate broadening of the old `require_role(&
//! ["maintainer"])` gate on `POST /codescan/reviews`
//! (`routes::reviews::create_review`), which excluded `admin` outright.
//! `has_scope`'s wildcard semantics make "maintainer-only, admin excluded"
//! inexpressible without a codescan-specific scope literal the manager
//! doesn't mint (out of scope for this change — manager is untouched);
//! admin gaining the superset access every other admin-vs-lower-tier gate
//! in this service already grants is the correct, standard scope-hierarchy
//! outcome, not a regression. See `routes::reviews` test module for the
//! updated coverage.
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

/// Scope required by every admin-tier management endpoint in this service
/// (credential CRUD, repo-config admin mutations, license-policy mutations,
/// policy-rule mutations) — the [`AdminOnly`] gate. `{service}:{action}`
/// naming matches `depgate:admin`/`monitor:admin`/`secrets:admin`
/// (`services/depgate/src/auth.rs`, `services/monitor/src/auth.rs`,
/// `services/vault/src/auth.rs`).
pub const ADMIN_SCOPE: &str = "codescan:admin";
/// Scope required by maintainer-tier write endpoints (creating a review) —
/// the [`MaintainerOnly`] gate. Satisfied by both `admin` and `maintainer`
/// role bundles (see module docs for why this admin inclusion is
/// intentional, not a preserved-behavior gap).
pub const WRITE_SCOPE: &str = "codescan:write";

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
    /// Tenant boundary, parsed from the validated `Claims::tenant` claim.
    /// The *only* legitimate source of this value — never a client-supplied
    /// request body/path/query field. Every tenant-scoped query/insert a
    /// handler issues must filter/stamp on this (see
    /// docs/v2-port/tenancy-model.md §4).
    pub tenant_id: uuid::Uuid,
    /// Full decoded claims for this request. Scope-based authorization
    /// ([`require_scope`](CurrentUser::require_scope)) delegates to
    /// `skauswatch_auth::Claims::require_scope` rather than reimplementing
    /// scope matching; `claims.roles` remains available for audit/display
    /// but MUST NOT be branched on for an authz decision (`security.md`).
    pub claims: Claims,
}

impl CurrentUser {
    /// Enforces a required `resource:action` scope, mapping a miss to the
    /// same 403 body every role-based check in this service returned before
    /// this migration (`{"error": "Insufficient permissions"}`) — the wire
    /// contract asserted by `routes::repos`'s
    /// `mutations_require_admin_role` and documented on every
    /// `#[utoipa::path]` `responses(...)` clause is unchanged, only the
    /// enforcement mechanism is.
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        self.claims
            .require_scope(scope)
            .map_err(|_| ApiError::Forbidden("Insufficient permissions".to_owned()))
    }
}

/// Extractor requiring [`ADMIN_SCOPE`]. Implemented as a `FromRequestParts`
/// extractor (not an inline check in the handler body) so it runs — and can
/// reject with 403 — *before* axum evaluates a later body extractor like
/// `ApiJson`. This matters: axum evaluates extractors left-to-right and
/// short-circuits on the first failure, so an inline
/// `user.require_scope(...)?` placed after the body parameter in the
/// function body would never run if the body itself failed to parse first.
/// Matches the v1 decorator ordering (`@auth_required` then
/// `@role_required(...)`, both ahead of the view function).
pub struct AdminOnly(pub CurrentUser);

impl FromRequestParts<AppState> for AdminOnly {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        user.require_scope(ADMIN_SCOPE)?;
        Ok(AdminOnly(user))
    }
}

/// Extractor requiring [`WRITE_SCOPE`] (`admin` or `maintainer`) — see
/// [`AdminOnly`] for why this is an extractor rather than an inline check,
/// and the module docs for why `admin` is included here where the old
/// role-string gate excluded it.
pub struct MaintainerOnly(pub CurrentUser);

impl FromRequestParts<AppState> for MaintainerOnly {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        user.require_scope(WRITE_SCOPE)?;
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
            tenant_id,
            claims,
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

    /// Builds a [`CurrentUser`] carrying `scope` directly, for exercising
    /// [`CurrentUser::require_scope`] without a full token round-trip.
    fn current_user(scope: &str) -> CurrentUser {
        let mut c = claims("1", TENANT, &[], 60);
        c.scope = scope.to_owned();
        CurrentUser {
            id: 1,
            tenant_id: TENANT.parse().unwrap_or_else(|e| panic!("uuid: {e}")),
            claims: c,
        }
    }

    #[test]
    fn require_scope_matches_old_admin_only_gate() {
        let admin = current_user("*:read *:write *:admin *:delete settings:write users:admin");
        assert!(admin.require_scope(ADMIN_SCOPE).is_ok());
        let viewer = current_user("*:read");
        match viewer.require_scope(ADMIN_SCOPE) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Insufficient permissions"),
            other => panic!("expected 403, got {other:?}"),
        }
    }

    /// Regression: the old `require_role(&["maintainer"])` gate on
    /// `POST /codescan/reviews` excluded `admin` outright; the scope-based
    /// [`crate::auth::WRITE_SCOPE`] replacement deliberately includes it
    /// (both bundles carry `*:write`) — see module docs. `viewer` (read-only
    /// bundle) must remain excluded either way.
    #[test]
    fn require_scope_write_is_satisfied_by_admin_and_maintainer_not_viewer() {
        let admin = current_user("*:read *:write *:admin *:delete settings:write users:admin");
        assert!(admin.require_scope(WRITE_SCOPE).is_ok());
        let maintainer = current_user("*:read *:write teams:read reports:read analytics:read");
        assert!(maintainer.require_scope(WRITE_SCOPE).is_ok());
        let viewer = current_user("*:read");
        assert!(viewer.require_scope(WRITE_SCOPE).is_err());
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
        assert_eq!(user.claims.roles, vec!["admin".to_owned()]);
        assert_eq!(user.tenant_id.to_string(), TENANT);
    }
}
