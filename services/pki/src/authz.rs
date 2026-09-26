//! Per-operation authorization for pki's machine-token surface.
//!
//! Security audit finding #1 hardened *authentication* (any validly-signed
//! `JWT_VERIFY_KEY`-verifiable token was accepted) but stopped short of
//! *authorization*: `skauswatch_auth::AuthenticatedCaller` (REST) and
//! `skauswatch_auth::verify_grpc_bearer` (gRPC) both check "is this a
//! genuine, current access token" only — `ServiceClaims.role` is decoded
//! but never consulted, so any caller holding ANY valid mesh JWT could
//! issue or revoke ANY certificate. This module closes that gap.
//!
//! `ServiceClaims` carries no dedicated `scope` field today (only `role` —
//! see `skauswatch_auth::ServiceClaims` docs: it's a deliberately
//! scope-free, older wire shape). Rather than widen that shared crate here,
//! this module maps `role` to the house `pki:*` capability vocabulary
//! locally — a service-local fallback, not a replacement for a future
//! `ServiceClaims`-scope helper landing in `crates/skauswatch-auth`.
//! Fails closed: an unrecognized role gets zero capabilities.
//!
//! `"admin"` is deliberately the fully-privileged role: it's the value
//! every existing `skauswatch_auth::issue_service_token`/test-fixture
//! call site across this workspace already uses as its generic "fully
//! privileged machine token" role (pki's own `routes::test_support::bearer`
//! included), so mapping it to every capability here means none of those
//! call sites need to change. Coordinating note, still open: no in-repo
//! caller mints a *production* pki machine token yet
//! (`grpc/pki_client.rs`'s "zero in-repo callers today"), so whichever role
//! a future manager caller uses must be `"admin"` (or a narrower role added
//! below) for issuance/revocation to work — this file doesn't, and can't,
//! coordinate that choice on its own.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use skauswatch_auth::{JwtSecretSource, ServiceClaims, ServiceTokenError};

use crate::state::AppState;

/// Certificate/CRL/KRL/OCSP lookup, list, search, CA info, statistics, and
/// the SSH config helper endpoints (known-hosts/authorized-keys/ssh-config/
/// verify) — nothing here mutates CA state.
pub const PKI_READ: &str = "pki:read";
/// X.509 + SSH certificate issuance.
pub const PKI_ISSUE: &str = "pki:issue";
/// X.509 + SSH certificate revocation.
pub const PKI_REVOKE: &str = "pki:revoke";
/// Audit log access — kept separate from `PKI_READ` since the audit trail
/// is more sensitive than routine certificate lookups.
pub const PKI_ADMIN: &str = "pki:admin";

/// Maps a `ServiceClaims.role` to the `pki:*` capabilities it carries. See
/// module docs for why `"admin"` is the fully-privileged value and why this
/// lives here instead of on `ServiceClaims` itself.
fn role_capabilities(role: &str) -> &'static [&'static str] {
    match role {
        "admin" => &[PKI_READ, PKI_ISSUE, PKI_REVOKE, PKI_ADMIN],
        "pki-issuer" => &[PKI_READ, PKI_ISSUE],
        "pki-revoker" => &[PKI_READ, PKI_REVOKE],
        "pki-reader" | "viewer" => &[PKI_READ],
        _ => &[],
    }
}

/// True when `claims.role` carries `required`.
pub fn has_capability(claims: &ServiceClaims, required: &str) -> bool {
    role_capabilities(&claims.role).contains(&required)
}

fn bearer_token(raw: &str) -> Option<&str> {
    raw.strip_prefix("Bearer ")
}

/// Decodes the caller's `ServiceClaims` from `parts` — the same signature/
/// expiry/type check `skauswatch_auth::AuthenticatedCaller` already ran as
/// the router-wide gate ahead of this middleware. Duplicated (rather than
/// reused) because that extractor is wired via
/// `axum::middleware::from_extractor_with_state`, which discards its
/// extracted value once the gate passes — handlers/downstream middleware
/// never see the decoded claims otherwise.
fn decode_caller(parts: &Parts, state: &AppState) -> Result<ServiceClaims, ServiceTokenError> {
    let token = parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(bearer_token)
        .ok_or(ServiceTokenError::MissingOrInvalidHeader)?;
    skauswatch_auth::verify_service_token(token, state.jwt_verify_key())
}

/// 403 — authenticated, but the caller's role lacks `required`. Distinct
/// from `ServiceTokenError`'s 401s ("not authenticated" vs "authenticated,
/// not permitted"), same bare `{"error": msg}` wire shape as `ApiError`.
pub struct InsufficientCapability(pub &'static str);

impl IntoResponse for InsufficientCapability {
    fn into_response(self) -> Response {
        (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": format!("missing required capability: {}", self.0)
            })),
        )
            .into_response()
    }
}

/// Runtime-parameterized gate config for [`scope_gate`] — mirrors
/// `penguin_licensing::axum::FlagGate`'s state-carried-config idiom already
/// used for `routes::ISSUANCE_FLAG`, so a required capability can be baked
/// into a sub-router's layer via `from_fn_with_state` without a distinct
/// function per capability.
#[derive(Clone)]
pub struct ScopeGate {
    state: AppState,
    required: &'static str,
}

impl ScopeGate {
    /// Builds a gate requiring `required` for every request through the
    /// layer it's attached to.
    pub fn new(state: AppState, required: &'static str) -> Self {
        Self { state, required }
    }
}

/// `axum::middleware::from_fn_with_state`-compatible layer: 401 if the
/// bearer token is missing/invalid/expired (belt-and-suspenders — the
/// router-wide `AuthenticatedCaller` layer this runs alongside should
/// already have caught that), 403 if the decoded role's capability set
/// doesn't include `gate.required`. Register on a sub-router *before* it
/// merges into the router-wide `AuthenticatedCaller`-layered whole, so
/// ordering is auth (401) → scope (403) → any feature-flag gate (404),
/// matching `crates/skauswatch-auth`'s documented tenant → scope → feature
/// contract adapted to this machine-token surface (no tenant stage here).
pub async fn scope_gate(State(gate): State<ScopeGate>, request: Request, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let claims = match decode_caller(&parts, &gate.state) {
        Ok(c) => c,
        Err(e) => return e.into_response(),
    };
    if !has_capability(&claims, gate.required) {
        return InsufficientCapability(gate.required).into_response();
    }
    next.run(Request::from_parts(parts, body)).await
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)] // tests fail loudly by design
mod tests {
    use super::*;

    fn claims(role: &str) -> ServiceClaims {
        ServiceClaims {
            sub: "svc".into(),
            role: role.into(),
            token_type: "access".into(),
            exp: i64::MAX,
            iat: 0,
        }
    }

    #[test]
    fn admin_role_carries_every_capability() {
        let c = claims("admin");
        assert!(has_capability(&c, PKI_READ));
        assert!(has_capability(&c, PKI_ISSUE));
        assert!(has_capability(&c, PKI_REVOKE));
        assert!(has_capability(&c, PKI_ADMIN));
    }

    #[test]
    fn pki_issuer_role_cannot_revoke_or_admin() {
        let c = claims("pki-issuer");
        assert!(has_capability(&c, PKI_READ));
        assert!(has_capability(&c, PKI_ISSUE));
        assert!(!has_capability(&c, PKI_REVOKE));
        assert!(!has_capability(&c, PKI_ADMIN));
    }

    #[test]
    fn pki_revoker_role_cannot_issue_or_admin() {
        let c = claims("pki-revoker");
        assert!(has_capability(&c, PKI_READ));
        assert!(!has_capability(&c, PKI_ISSUE));
        assert!(has_capability(&c, PKI_REVOKE));
        assert!(!has_capability(&c, PKI_ADMIN));
    }

    #[test]
    fn reader_and_viewer_roles_get_read_only() {
        for role in ["pki-reader", "viewer"] {
            let c = claims(role);
            assert!(has_capability(&c, PKI_READ));
            assert!(!has_capability(&c, PKI_ISSUE));
            assert!(!has_capability(&c, PKI_REVOKE));
            assert!(!has_capability(&c, PKI_ADMIN));
        }
    }

    #[test]
    fn unrecognized_role_gets_no_capabilities() {
        let c = claims("something-unmapped");
        assert!(!has_capability(&c, PKI_READ));
        assert!(!has_capability(&c, PKI_ISSUE));
        assert!(!has_capability(&c, PKI_REVOKE));
        assert!(!has_capability(&c, PKI_ADMIN));
    }

    #[test]
    fn empty_role_gets_no_capabilities() {
        let c = claims("");
        assert!(!has_capability(&c, PKI_READ));
    }
}
