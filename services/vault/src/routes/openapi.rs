//! OpenAPI 3.x spec generation and (flag-gated, authenticated) live serving
//! for the Vault REST surface — see `backend.md` OpenAPI and
//! `docs/v2-port/openapi-pattern.md` for the org-wide pattern this service
//! follows.
//!
//! Vault has no login endpoint of its own (tokens are issued by the
//! manager, see `crate::auth`), so there is no unauthenticated public doc
//! split here — the entire spec sits behind the same `CurrentUser` auth
//! every other route in this service uses (the manager's login-owning case
//! needs a second, narrower `PublicApiDoc`; see the pattern doc's step 6).

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use utoipa::OpenApi;

use super::{admin, audit, jit, one_time, secrets, sync};
use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse, InsufficientScopeResponse, LicenseRequiredResponse};
use crate::state::AppState;

/// PostHog flag gating the *live* `/api/v1/openapi.json` route. Independent
/// of `VAULT_FLAG` (`state.rs`) — Vault's REST surface being licensed and
/// its generated API documentation being served live are separate
/// concerns, matching `services/codescan-backend`'s own `/openapi.json`
/// (the reference implementation), whose `CODESCAN_FLAG` never gates it
/// either. This route is also listed in
/// `license_gate::BYPASS_PATHS` — see that constant's doc comment for why
/// it can't stay behind the router-wide `VAULT_FLAG` gate and still be
/// testable. The committed `openapi/v1.yaml` is generated separately
/// (`skauswatch-vault openapi` subcommand) and is unaffected by this flag
/// either way.
pub(crate) const OPENAPI_FLAG: &str = "skauswatch.openapi-docs";

/// Aggregated OpenAPI 3.x document for every `/api/v1/*` Vault route.
/// Generated from the `#[utoipa::path]` annotations on each handler below —
/// never hand-edit `openapi/v1.yaml`; regenerate it with
/// `skauswatch-vault openapi > openapi/v1.yaml`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "SkausWatch Vault API",
        version = "1",
        description = "Envelope-encrypted secrets storage, just-in-time access grants, \
            self-destructing one-time secrets, cloud vault sync integrations, MEK \
            rotation, and audit log."
    ),
    paths(
        secrets::list_secrets,
        secrets::create_secret,
        secrets::get_secret,
        secrets::update_secret,
        secrets::delete_secret,
        secrets::get_secret_value,
        secrets::list_secret_versions,
        secrets::rotate_secret,
        jit::list_jit_requests,
        jit::create_jit_request,
        jit::approve_jit_request,
        jit::reject_jit_request,
        one_time::create_one_time_secret,
        one_time::retrieve_one_time_secret,
        sync::list_integrations,
        sync::create_integration,
        sync::update_integration,
        sync::delete_integration,
        sync::trigger_sync,
        admin::get_license_status,
        admin::rotate_mek,
        audit::get_audit_log,
    ),
    components(schemas(
        ErrorResponse,
        InsufficientScopeResponse,
        LicenseRequiredResponse,
        secrets::SecretResponse,
        secrets::SecretListResponse,
        secrets::CreateSecretBody,
        secrets::UpdateSecretBody,
        secrets::SecretValueResponse,
        secrets::SecretVersionEntry,
        secrets::SecretVersionsResponse,
        secrets::RotateBody,
        secrets::RotateSecretResponse,
        jit::JitRequestResponse,
        jit::JitRequestListResponse,
        jit::CreateJitRequestBody,
        jit::ApproveBody,
        jit::JitApproveResponse,
        jit::JitRejectResponse,
        one_time::CreateBody,
        one_time::OneTimeCreateResponse,
        one_time::OneTimeValueResponse,
        sync::SyncIntegrationResponse,
        sync::SyncIntegrationListResponse,
        sync::CreateIntegrationBody,
        sync::UpdateIntegrationBody,
        sync::TriggerSyncResponse,
        admin::LicenseStatusResponse,
        admin::RotateMekBody,
        admin::RotateMekResponse,
        audit::AuditEntryResponse,
        audit::AuditLogResponse,
    )),
    tags(
        (name = "secrets", description = "CRUD, versioning, and plaintext retrieval for envelope-encrypted secrets"),
        (name = "jit", description = "Just-in-Time access requests and approvals"),
        (name = "one-time-secrets", description = "Self-destructing shared secrets"),
        (name = "sync", description = "Cloud vault integration management"),
        (name = "admin", description = "License status and Master Encryption Key rotation"),
        (name = "audit", description = "Read-only audit trail"),
    ),
    modifiers(&SecurityAddon),
)]
pub(crate) struct ApiDoc;

/// Registers the `bearer_jwt` HTTP Bearer security scheme referenced by
/// every `#[utoipa::path(security(("bearer_jwt" = [])))]` annotation above.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_jwt",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}

/// Router for GET /openapi.json.
pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/openapi.json", get(openapi_spec))
}

/// GET /openapi.json — the generated OpenAPI 3.x document, gated by
/// `OPENAPI_FLAG` (404 when disabled) and standard JWT auth (401 when
/// missing/invalid — enforced by the `CurrentUser` extractor, same as every
/// other route in this service). Not itself part of the generated spec
/// (`paths(...)` above) to avoid a self-referential schema.
async fn openapi_spec(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Response, ApiError> {
    if !state.license.flag_enabled(OPENAPI_FLAG).await {
        return Err(ApiError::NotFound("Not Found".to_owned()));
    }
    Ok((StatusCode::OK, Json(ApiDoc::openapi())).into_response())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use axum_test::TestServer;
    use skauswatch_testkit::license::{dev_license, gated_license};
    use skauswatch_vault::EnvelopeEncryption;

    use super::*;
    use crate::routes::test_support::sign_token;
    use crate::state::AppStateInner;

    fn test_server(state: AppState) -> TestServer {
        TestServer::new(crate::routes::router(state))
    }

    /// Exercised through the *full* production router
    /// (`crate::routes::router`), not a bare nest of just this module's
    /// routes — unlike codescan-backend, Vault has a router-wide license
    /// gate layer (`license_gate::require_license`) that this route must be
    /// proven to bypass (`license_gate::BYPASS_PATHS`), not just the
    /// in-handler `OPENAPI_FLAG` check.
    #[tokio::test]
    async fn openapi_requires_auth() {
        let state =
            AppStateInner::for_tests(dev_license("skauswatch"), EnvelopeEncryption::default());
        let server = test_server(state);
        let resp = server.get("/api/v1/openapi.json").await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn openapi_404s_when_flag_disabled() {
        // `gated_license` (release_mode = true) denies every flag,
        // including OPENAPI_FLAG — this route bypasses the router-wide
        // VAULT_FLAG gate entirely (BYPASS_PATHS), so a 404 here proves the
        // in-handler OPENAPI_FLAG check, not the outer gate.
        let state =
            AppStateInner::for_tests(gated_license("skauswatch"), EnvelopeEncryption::default());
        let token = sign_token(&state, "1", "secrets:read");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/openapi.json")
            .authorization_bearer(token)
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn openapi_returns_the_generated_document_when_authed_and_enabled() {
        let state =
            AppStateInner::for_tests(dev_license("skauswatch"), EnvelopeEncryption::default());
        let token = sign_token(&state, "1", "secrets:read");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/openapi.json")
            .authorization_bearer(token)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert!(
            body["openapi"]
                .as_str()
                .unwrap_or_default()
                .starts_with("3."),
            "expected an OpenAPI 3.x document, got: {body}"
        );
        assert!(body["paths"]["/api/v1/secrets"].is_object());
        assert!(body["components"]["securitySchemes"]["bearer_jwt"].is_object());
    }

    #[tokio::test]
    async fn gated_license_still_denies_every_other_route_via_the_outer_gate() {
        // Sanity check that BYPASS_PATHS didn't accidentally exempt
        // anything else — a sibling route under the same gated state must
        // still 402 from the outer VAULT_FLAG middleware.
        let state =
            AppStateInner::for_tests(gated_license("skauswatch"), EnvelopeEncryption::default());
        let token = sign_token(&state, "1", "secrets:read");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/secrets")
            .authorization_bearer(token)
            .await;
        resp.assert_status(StatusCode::PAYMENT_REQUIRED);
    }
}
