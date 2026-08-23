//! Scope-based authorization for the admin/report API (`crate::routes::
//! admin`), built directly on the shared `skauswatch_auth::Claims` model
//! (`security.md`: authorization decisions use `scope` only, never role
//! names) rather than a hand-rolled fourth auth mechanism.
//!
//! `skauswatch_auth::tenant_middleware` (wired router-wide in
//! `crate::routes::router`) already decodes the bearer token and publishes
//! a tenant-only `TenantContext`; it does not expose `scope`. Rather than
//! changing that shared-crate middleware, [`AuthedUser`] independently
//! decodes the same token via the crate's own public
//! `skauswatch_auth::decode_claims`/`Claims::require_scope` — this mirrors
//! `services/codescan-backend/src/auth.rs`'s `CurrentUser` and
//! `services/monitor/src/auth.rs`'s `AuthedUser` (both decode a second time
//! for defense-in-depth, and both call straight through to the shared
//! `Claims` scope helpers rather than reimplementing scope matching).
//!
//! Scope strings follow the repo's `{service}:{action}` convention (see
//! `monitor:admin` in `services/monitor/src/auth.rs`, `sync:read`/
//! `sync:admin` in `services/vault/src/routes/sync.rs`): [`READ_SCOPE`]
//! (`depgate:read`) gates every read-only admin/report endpoint,
//! [`ADMIN_SCOPE`] (`depgate:admin`) gates quarantine-disposition and
//! policy-rule mutations. A real admin-bundle token also carries `*:read`/
//! `*:admin` (`security.md`'s scope-bundle table), which
//! `Claims::has_scope`'s wildcard matching already satisfies against these
//! exact strings.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use skauswatch_auth::Claims;

use crate::error::ApiError;
use crate::state::AppState;

/// Scope required by every read-only admin/report endpoint (artifact
/// index, risk findings, quarantine log, policy-rule reads, stats).
pub const READ_SCOPE: &str = "depgate:read";
/// Scope required to release a quarantined artifact or mutate policy
/// rules.
pub const ADMIN_SCOPE: &str = "depgate:admin";

/// The authenticated caller's validated claims, decoded independently of
/// (but redundantly with) `tenant_middleware` so scope can be enforced on
/// top of the tenant check every handler in this module already applies
/// via `TenantContext`.
#[derive(Debug, Clone)]
pub struct AuthedUser {
    /// Decoded, tenant-validated claims for the current request.
    pub claims: Claims,
}

impl AuthedUser {
    /// Enforces a required scope, mapping a miss to the same 403
    /// `ApiError::Forbidden` shape every other authorization failure in
    /// this service already returns.
    pub fn require_scope(&self, scope: &str) -> Result<(), ApiError> {
        self.claims
            .require_scope(scope)
            .map_err(|_| ApiError::Forbidden(format!("insufficient scope: requires {scope}")))
    }
}

impl FromRequestParts<AppState> for AuthedUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        const HEADER_MSG: &str = "Missing or invalid authorization header";
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ApiError::Forbidden(HEADER_MSG.to_owned()))?;
        let token = header
            .strip_prefix("Bearer ")
            .ok_or_else(|| ApiError::Forbidden(HEADER_MSG.to_owned()))?;
        let claims = skauswatch_auth::decode_claims(token, &state.jwt_secret)
            .map_err(|_| ApiError::Forbidden("Invalid or expired token".to_owned()))?;
        claims
            .require_tenant()
            .map_err(|_| ApiError::Forbidden("missing or empty tenant claim".to_owned()))?;
        Ok(AuthedUser { claims })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    fn claims(scope: &str) -> Claims {
        Claims {
            sub: "user-1".to_owned(),
            iss: "https://auth.skauswatch.app".to_owned(),
            aud: "skauswatch".to_owned(),
            iat: 0,
            exp: i64::MAX,
            scope: scope.to_owned(),
            tenant: "tenant-a".to_owned(),
            teams: vec![],
            roles: vec![],
        }
    }

    #[test]
    fn admin_scope_satisfied_by_exact_match() {
        let user = AuthedUser {
            claims: claims(ADMIN_SCOPE),
        };
        assert!(user.require_scope(ADMIN_SCOPE).is_ok());
    }

    #[test]
    fn admin_scope_satisfied_by_wildcard_bundle() {
        let user = AuthedUser {
            claims: claims("*:admin"),
        };
        assert!(user.require_scope(ADMIN_SCOPE).is_ok());
    }

    #[test]
    fn read_scope_alone_does_not_satisfy_admin_scope() {
        let user = AuthedUser {
            claims: claims(READ_SCOPE),
        };
        assert!(user.require_scope(ADMIN_SCOPE).is_err());
    }

    #[test]
    fn read_scope_satisfied_by_exact_match() {
        let user = AuthedUser {
            claims: claims(READ_SCOPE),
        };
        assert!(user.require_scope(READ_SCOPE).is_ok());
    }
}
