//! Per-operation authorization for sshca's machine-token surface.
//!
//! Security audit finding #2 hardened *authentication* (any validly-signed
//! `JWT_VERIFY_KEY`-verifiable token was accepted — see `crate::routes` module docs)
//! but stopped short of *authorization*: `skauswatch_auth::AuthenticatedCaller`
//! checks "is this a genuine, current access token" only —
//! `ServiceClaims.role` is decoded but never consulted, so any caller
//! holding ANY valid mesh JWT could issue or revoke ANY SSH certificate.
//! This module closes that gap, mirroring `services/pki/src/authz.rs`'s
//! design (the two services can't share a crate-local module across the
//! workspace boundary without widening `crates/skauswatch-auth`, so the
//! same small pattern is duplicated here rather than factored out).
//!
//! `ServiceClaims` carries no dedicated `scope` field today (only `role` —
//! see `skauswatch_auth::ServiceClaims` docs), so this module maps `role`
//! to the house `sshca:*` capability vocabulary locally. Fails closed: an
//! unrecognized role gets zero capabilities.
//!
//! `"admin"` is deliberately the fully-privileged role — the value every
//! existing `skauswatch_auth::issue_service_token` call site in this
//! workspace already uses as its generic "fully privileged machine token"
//! role (this service's own test `auth_header()` included), so mapping it
//! to every capability here means none of those call sites need to change.
//! Coordinating note, still open: no in-repo caller mints a *production*
//! sshca machine token yet (`routes.rs`'s "No in-repo caller exists
//! today"), so whichever role a future caller uses must be `"admin"` (or a
//! narrower role added below) for issuance/revocation to work.

use axum::Json;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use skauswatch_auth::{JwtSecretSource, ServiceClaims, ServiceTokenError};

use crate::routes::AppState;

/// Certificate lookup, list, KRL, and CA public-key retrieval.
pub const SSHCA_READ: &str = "sshca:read";
/// SSH certificate issuance.
pub const SSHCA_ISSUE: &str = "sshca:issue";
/// SSH certificate revocation.
pub const SSHCA_REVOKE: &str = "sshca:revoke";

/// Maps a `ServiceClaims.role` to the `sshca:*` capabilities it carries.
/// See module docs for why `"admin"` is the fully-privileged value.
fn role_capabilities(role: &str) -> &'static [&'static str] {
    match role {
        "admin" => &[SSHCA_READ, SSHCA_ISSUE, SSHCA_REVOKE],
        "sshca-issuer" => &[SSHCA_READ, SSHCA_ISSUE],
        "sshca-revoker" => &[SSHCA_READ, SSHCA_REVOKE],
        "sshca-reader" | "viewer" => &[SSHCA_READ],
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
/// not permitted").
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
/// used for `routes::ISSUANCE_FLAG`.
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
/// ordering is auth (401) → scope (403) → feature flag (404), matching
/// `crates/skauswatch-auth`'s documented tenant → scope → feature contract
/// adapted to this machine-token surface (no tenant stage here).
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
        assert!(has_capability(&c, SSHCA_READ));
        assert!(has_capability(&c, SSHCA_ISSUE));
        assert!(has_capability(&c, SSHCA_REVOKE));
    }

    #[test]
    fn issuer_role_cannot_revoke() {
        let c = claims("sshca-issuer");
        assert!(has_capability(&c, SSHCA_READ));
        assert!(has_capability(&c, SSHCA_ISSUE));
        assert!(!has_capability(&c, SSHCA_REVOKE));
    }

    #[test]
    fn revoker_role_cannot_issue() {
        let c = claims("sshca-revoker");
        assert!(has_capability(&c, SSHCA_READ));
        assert!(!has_capability(&c, SSHCA_ISSUE));
        assert!(has_capability(&c, SSHCA_REVOKE));
    }

    #[test]
    fn reader_and_viewer_roles_get_read_only() {
        for role in ["sshca-reader", "viewer"] {
            let c = claims(role);
            assert!(has_capability(&c, SSHCA_READ));
            assert!(!has_capability(&c, SSHCA_ISSUE));
            assert!(!has_capability(&c, SSHCA_REVOKE));
        }
    }

    #[test]
    fn unrecognized_role_gets_no_capabilities() {
        let c = claims("something-unmapped");
        assert!(!has_capability(&c, SSHCA_READ));
        assert!(!has_capability(&c, SSHCA_ISSUE));
        assert!(!has_capability(&c, SSHCA_REVOKE));
    }
}
