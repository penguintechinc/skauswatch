//! OpenAPI 3.x spec generation and (flag-gated, authenticated) live serving
//! for the PKI REST surface — see `backend.md` OpenAPI and
//! `docs/v2-port/openapi-pattern.md` for the org-wide pattern this
//! establishes.
//!
//! pki has no login endpoint of its own (every route requires a bearer
//! token signed with the shared `JWT_SECRET_KEY` — see `routes` module
//! docs), so there is no unauthenticated public doc split here — the entire
//! spec is reachable only via the router-wide auth layer applied in
//! `routes::router`. Unlike per-handler-auth services (codescan-backend,
//! manager, vault, monitor), the live `/api/v1/openapi.json` handler below
//! takes no `CurrentUser`-equivalent extractor of its own: the 401 is
//! already produced by that layer before this handler ever runs.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use utoipa::OpenApi;

use super::{common, ssh, x509};
use crate::error::{ApiError, ErrorResponse, ValidationErrorResponse};
use crate::models::{
    AuthorizedKeysRequest, RevokeRequest, SshCertificateRequest, SshConfigRequest,
    X509CertificateRequest,
};
use crate::state::AppState;

/// PostHog flag gating the *live* `/api/v1/openapi.json` route — an
/// independent kill-switch from any per-feature flag (pki has none today).
/// The committed `openapi/v1.yaml` in the repo is generated separately
/// (`skauswatch-pki openapi` subcommand) and is unaffected by this flag
/// either way.
pub(crate) const OPENAPI_FLAG: &str = "skauswatch.openapi-docs";

/// Aggregated OpenAPI 3.x document for every `/api/v1/certificates/*`,
/// `/api/v1/ssh/*`, and common `/api/v1/*` route. Generated from the
/// `#[utoipa::path]` annotations on each handler below — never hand-edit
/// `openapi/v1.yaml`; regenerate it with `skauswatch-pki openapi >
/// openapi/v1.yaml`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "SkausWatch PKI API",
        version = "1",
        description = "X.509 + SSH certificate authority: issuance, lookup, \
            revocation, CRL/KRL, OCSP, SSH config helpers, statistics, and \
            audit log."
    ),
    paths(
        x509::issue,
        x509::get_cert,
        x509::get_by_serial,
        x509::revoke_cert,
        x509::revoke_by_serial,
        x509::list,
        x509::search,
        x509::get_crl,
        x509::ocsp,
        x509::ca_info,
        x509::download_ca_cert,
        x509::cert_status,
        ssh::issue,
        ssh::get_cert,
        ssh::get_by_serial,
        ssh::revoke_cert,
        ssh::list,
        ssh::get_krl,
        ssh::ca_info,
        ssh::ca_public_key,
        ssh::known_hosts,
        ssh::authorized_keys,
        ssh::ssh_config,
        ssh::cert_status,
        ssh::verify,
        common::statistics,
        common::all_ca_info,
        common::audit,
        common::expiring,
        common::cleanup,
    ),
    components(schemas(
        ErrorResponse,
        ValidationErrorResponse,
        X509CertificateRequest,
        x509::SearchBody,
        RevokeRequest,
        SshCertificateRequest,
        SshConfigRequest,
        AuthorizedKeysRequest,
    )),
    tags(
        (name = "x509", description = "X.509 certificate issuance, lookup, revocation, CRL, and OCSP"),
        (name = "ssh", description = "SSH certificate issuance, lookup, revocation, KRL, and client config helpers"),
        (name = "common", description = "Combined statistics, CA info, audit log, expiring certificates, and cleanup"),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

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

/// Router for GET /openapi.json — merged into `routes::router`'s layered
/// `/api/v1` nest alongside every other route, so the router-wide auth
/// layer already covers it (see module docs).
pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/openapi.json", get(openapi_spec))
}

/// GET /openapi.json — the generated OpenAPI 3.x document, gated by
/// `OPENAPI_FLAG` (404 when disabled). No local auth extractor: the
/// router-wide `AuthenticatedCaller` layer already rejected an
/// unauthenticated caller with 401 before this handler runs (see
/// `routes::router`). Not itself part of the generated spec (`paths(...)`
/// above) to avoid a self-referential schema.
async fn openapi_spec(State(state): State<AppState>) -> Result<Response, ApiError> {
    if !state.license.flag_enabled(OPENAPI_FLAG).await {
        return Err(ApiError::NotFound("Not Found".to_owned()));
    }
    Ok((StatusCode::OK, Json(ApiDoc::openapi())).into_response())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::state::AppStateInner;

    fn test_server(state: AppState) -> axum_test::TestServer {
        axum_test::TestServer::new(crate::routes::router(state))
    }

    fn bearer() -> String {
        match skauswatch_auth::issue_service_token("tester", "admin", "test-secret", 300) {
            Ok(t) => format!("Bearer {t}"),
            Err(e) => panic!("issue test token: {e}"),
        }
    }

    fn gated_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        let mut cfg = match penguin_licensing::LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        cfg.release_mode = true;
        match penguin_licensing::LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    #[tokio::test]
    async fn openapi_404s_when_flag_disabled() {
        let state = AppStateInner::for_tests_with_license(gated_license());
        let server = test_server(state);
        let resp = server
            .get("/api/v1/openapi.json")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn openapi_returns_the_generated_document_when_authed_and_enabled() {
        let state = AppStateInner::for_tests();
        let server = test_server(state);
        let resp = server
            .get("/api/v1/openapi.json")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
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
        assert!(body["paths"]["/api/v1/certificates"].is_object());
        assert!(body["paths"]["/api/v1/ssh/certificates"].is_object());
        assert!(body["components"]["securitySchemes"]["bearer_jwt"].is_object());
    }
}
