//! OpenAPI 3.x spec generation and (flag-gated, authenticated) live serving
//! for the SSH CA REST surface — see `backend.md` OpenAPI and
//! `docs/v2-port/openapi-pattern.md` for the org-wide pattern this service
//! follows.
//!
//! sshca has no login endpoint of its own and gates its entire
//! `/api/v1/ssh` surface with a single router-wide
//! `skauswatch_auth::AuthenticatedCaller` layer (see `super::router`)
//! rather than a per-handler extractor — so, per the pattern doc's
//! "router-wide auth" row, this route takes no extractor parameter of its
//! own: the layer already rejects an unauthenticated caller with 401
//! before `openapi_spec` ever runs. Only the independent `OPENAPI_FLAG`
//! kill-switch is checked here.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use utoipa::OpenApi;

use super::AppState;
use crate::error::{ApiError, ErrorResponse, ValidationErrorResponse};
use crate::model::{
    CaPublicKeyResponse, CertificateListResponse, CertificateRecord, CertificateType,
    IssueCertificateRequest, IssueCertificateResponse, KrlEntryResponse, KrlResponse,
    RevokeCertificateRequest, RevokeCertificateResponse,
};

/// PostHog flag gating the *live* `/api/v1/ssh/openapi.json` route — an
/// independent kill-switch from the router-wide auth layer, since serving
/// API documentation is a distinct concern from certificate issuance
/// itself. The committed `openapi/v1.yaml` in the repo is generated
/// separately (`skauswatch-sshca openapi` subcommand) and is unaffected by
/// this flag either way.
pub(crate) const OPENAPI_FLAG: &str = "skauswatch.openapi-docs";

/// Aggregated OpenAPI 3.x document for every `/api/v1/ssh/*` route.
/// Generated from the `#[utoipa::path]` annotations on each handler in
/// `super` — never hand-edit `openapi/v1.yaml`; regenerate it with
/// `skauswatch-sshca openapi > openapi/v1.yaml`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "SkausWatch SSH Certificate Authority API",
        version = "1",
        description = "OpenSSH user/host certificate issuance, lookup, \
            revocation, and Key Revocation List retrieval."
    ),
    paths(
        super::issue_certificate,
        super::list_certificates,
        super::get_certificate,
        super::revoke_certificate,
        super::get_krl,
        super::get_ca_public_key,
    ),
    components(schemas(
        ErrorResponse,
        ValidationErrorResponse,
        CertificateType,
        IssueCertificateRequest,
        IssueCertificateResponse,
        RevokeCertificateRequest,
        RevokeCertificateResponse,
        CertificateRecord,
        CertificateListResponse,
        KrlEntryResponse,
        KrlResponse,
        CaPublicKeyResponse,
    )),
    tags(
        (name = "sshca", description = "OpenSSH user/host certificate signing, lookup, revocation, and KRL"),
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

/// Router for GET /api/v1/ssh/openapi.json. Merged into `super::router`'s
/// chain *before* the router-wide auth layer is applied, so the layer
/// covers this route the same as every other one.
pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/api/v1/ssh/openapi.json", get(openapi_spec))
}

/// GET /api/v1/ssh/openapi.json — the generated OpenAPI 3.x document,
/// gated by `OPENAPI_FLAG` (404 when disabled). Auth (401 on a missing or
/// invalid token) is enforced by `super::router`'s router-wide
/// `AuthenticatedCaller` layer, not by an extractor on this handler. Not
/// itself part of the generated spec (`paths(...)` above) to avoid a
/// self-referential schema.
async fn openapi_spec(State(state): State<AppState>) -> Result<Response, ApiError> {
    if !state.license.flag_enabled(OPENAPI_FLAG).await {
        return Err(ApiError::NotFound("Not Found".to_owned()));
    }
    Ok((StatusCode::OK, Json(ApiDoc::openapi())).into_response())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::path::Path;
    use std::sync::Arc;

    use penguin_licensing::{LicenseClient, LicenseConfig};

    use super::*;
    use crate::ca::SshCa;
    use crate::store::CertStore;

    const TEST_JWT_SECRET: &str = "test-secret";

    fn dev_license() -> Arc<LicenseClient> {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    fn gated_license() -> Arc<LicenseClient> {
        let mut cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        cfg.release_mode = true;
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    fn test_state(license: Arc<LicenseClient>) -> AppState {
        // Missing path → ephemeral CA key (fine for tests). Lazy pool: none
        // of these tests reach the durable store (see `crate::store`'s
        // consolidation decision doc comment).
        let ca = SshCa::load_or_generate(Path::new("/nonexistent-skauswatch-sshca-key"))
            .expect("ephemeral ca");
        AppState {
            ca: Arc::new(ca),
            store: Arc::new(CertStore::new(crate::test_support::lazy_pool())),
            jwt_secret: TEST_JWT_SECRET.into(),
            license,
        }
    }

    /// `Authorization` header value with a valid bearer token signed with
    /// `TEST_JWT_SECRET`, matching `test_state()`.
    fn auth_header() -> (&'static str, String) {
        let token = skauswatch_auth::issue_service_token("tester", "admin", TEST_JWT_SECRET, 300)
            .expect("issue test token");
        ("Authorization", format!("Bearer {token}"))
    }

    /// Full service router (business routes + this module's route, all
    /// behind the same auth layer) — exercises the real stack, not an
    /// isolated sub-router.
    fn test_server(state: AppState) -> axum_test::TestServer {
        axum_test::TestServer::new(crate::routes::router(state))
    }

    #[tokio::test]
    async fn openapi_requires_auth() {
        let server = test_server(test_state(dev_license()));
        let resp = server.get("/api/v1/ssh/openapi.json").await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn openapi_404s_when_flag_disabled() {
        let server = test_server(test_state(gated_license()));
        let (hdr, val) = auth_header();
        let resp = server
            .get("/api/v1/ssh/openapi.json")
            .add_header(hdr, val)
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn openapi_returns_the_generated_document_when_authed_and_enabled() {
        let server = test_server(test_state(dev_license()));
        let (hdr, val) = auth_header();
        let resp = server
            .get("/api/v1/ssh/openapi.json")
            .add_header(hdr, val)
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
        assert!(body["paths"]["/api/v1/ssh/certificates"].is_object());
        assert!(body["components"]["securitySchemes"]["bearer_jwt"].is_object());
    }
}
