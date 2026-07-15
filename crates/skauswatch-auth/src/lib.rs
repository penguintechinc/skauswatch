//! AuthN/Z primitives shared by all skauswatch services: the mandatory JWT
//! claims model (`sub/iss/aud/iat/exp/scope/tenant/teams/roles`) and
//! scope-based authorization helpers. Authorization decisions use `scope`
//! only — `roles` is informational/audit, never branched on.
//!
//! Middleware ordering contract (enforced where routers are assembled):
//! tenant check → scope check → feature/licensing check.

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
