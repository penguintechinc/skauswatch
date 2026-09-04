//! OpenAPI 3.x spec generation and (flag-gated, authenticated) live serving
//! for the CodeScan backend REST surface — see `backend.md` OpenAPI and
//! `docs/v2-port/openapi-pattern.md` for the org-wide pattern this
//! establishes.
//!
//! codescan-backend has no login endpoint of its own (tokens are issued by
//! the manager service, see `crate::auth`), so there is no unauthenticated
//! public doc split here — the entire spec sits behind the same
//! `CurrentUser` auth every other route in this service uses. Services that
//! *do* own a login endpoint (e.g. the manager) need a second, narrower
//! `PublicApiDoc` covering only that endpoint, served unauthenticated; see
//! the pattern doc.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use utoipa::OpenApi;

use super::{
    credentials, findings, fix_batches, license_policies, plans, policy_rules, repos, reviews,
    status,
};
use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

/// PostHog flag gating the *live* `/api/v1/openapi.json` route — an
/// independent kill-switch from `CODESCAN_FLAG` (see `super::CODESCAN_FLAG`),
/// since serving API documentation is a distinct concern from the CodeScan
/// feature itself. The committed `openapi/v1.yaml` in the repo is generated
/// separately (`codescan-backend openapi` subcommand) and is unaffected by
/// this flag either way.
pub(crate) const OPENAPI_FLAG: &str = "skauswatch.openapi-docs";

/// Aggregated OpenAPI 3.x document for every `/api/v1/codescan/*` and
/// `/api/v1/credentials/*` route. Generated from the `#[utoipa::path]`
/// annotations on each handler below — never hand-edit `openapi/v1.yaml`;
/// regenerate it with `codescan-backend openapi > openapi/v1.yaml`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "SkausWatch CodeScan Backend API",
        version = "1",
        description = "AI code review (repos/reviews/issue-plans) and git \
            credential management for the CodeScan worker pipeline."
    ),
    paths(
        status::codescan_status,
        repos::list_repos,
        repos::create_repo,
        repos::get_repo,
        repos::update_repo,
        repos::delete_repo,
        reviews::list_reviews,
        reviews::create_review,
        reviews::get_review,
        plans::list_plans,
        plans::create_plan,
        plans::get_plan,
        credentials::list_credentials,
        credentials::create_credential,
        credentials::get_credential,
        credentials::update_credential,
        credentials::delete_credential,
        credentials::test_credential,
        license_policies::list_policies,
        license_policies::create_policy,
        license_policies::get_policy,
        license_policies::update_policy,
        license_policies::delete_policy,
        findings::list_findings,
        findings::findings_summary,
        findings::get_sbom,
        policy_rules::list_rules,
        policy_rules::create_rule,
        policy_rules::get_rule,
        policy_rules::update_rule,
        policy_rules::delete_rule,
        fix_batches::list_batches,
        fix_batches::get_batch,
    ),
    components(schemas(
        ErrorResponse,
        ValidationErrorResponse,
        status::StatusResponse,
        repos::RepoConfig,
        repos::RepoListResponse,
        repos::CreateRepoRequest,
        repos::RepoCreateResponse,
        repos::UpdateRepoRequest,
        repos::RepoUpdateResponse,
        repos::RepoDeleteResponse,
        reviews::ReviewRow,
        reviews::ReviewComment,
        reviews::ReviewDetection,
        reviews::ReviewLicenseViolation,
        reviews::ReviewDetailResponse,
        reviews::PaginationMeta,
        reviews::ReviewListResponse,
        reviews::CreateReviewRequest,
        plans::PlanRow,
        plans::PlanListResponse,
        plans::CreatePlanRequest,
        credentials::CredentialSummary,
        credentials::CredentialListResponse,
        credentials::CreateCredentialRequest,
        credentials::CredentialCreateResponse,
        credentials::UpdateCredentialRequest,
        credentials::CredentialUpdateResponse,
        credentials::CredentialDeleteResponse,
        credentials::TestCredentialRequest,
        credentials::TestCredentialResponse,
        license_policies::LicensePolicy,
        license_policies::PolicyListResponse,
        license_policies::CreatePolicyRequest,
        license_policies::PolicyCreateResponse,
        license_policies::UpdatePolicyRequest,
        license_policies::PolicyUpdateResponse,
        license_policies::PolicyDeleteResponse,
        findings::Finding,
        findings::FindingListResponse,
        findings::SeverityCount,
        findings::FindingsSummaryResponse,
        findings::SbomResponse,
        policy_rules::PolicyRule,
        policy_rules::PolicyRuleListResponse,
        policy_rules::CreatePolicyRuleRequest,
        policy_rules::PolicyRuleCreateResponse,
        policy_rules::UpdatePolicyRuleRequest,
        policy_rules::PolicyRuleUpdateResponse,
        policy_rules::PolicyRuleDeleteResponse,
        fix_batches::FixBatch,
        fix_batches::FixBatchListResponse,
        fix_batches::FixBatchFinding,
        fix_batches::FixBatchDetailResponse,
    )),
    tags(
        (name = "codescan", description = "Repo configs, AI code reviews, and issue plans"),
        (name = "credentials", description = "Git credential storage for private repo access"),
        (name = "license-policies", description = "OSS license-compliance policy configuration"),
        (name = "codescan-sentinel", description = "Scheduled SCA/CVE dependency scanning and reports (report-only, no AI)"),
        (name = "codescan-sentinel-policy", description = "P3 AI reachability triage + policy engine rule CRUD (Enterprise-gated)"),
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
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use std::sync::Arc;

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

    fn test_server(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    #[tokio::test]
    async fn openapi_requires_auth() {
        let server = test_server(AppStateInner::for_tests(dev_license()));
        let resp = server.get("/api/v1/openapi.json").await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn openapi_404s_when_flag_disabled() {
        let state = AppStateInner::for_tests(gated_license());
        let token = crate::routes::test_support::sign_token(&state, "1", "viewer");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/openapi.json")
            .authorization_bearer(token)
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn openapi_returns_the_generated_document_when_authed_and_enabled() {
        let state = AppStateInner::for_tests(dev_license());
        let token = crate::routes::test_support::sign_token(&state, "1", "viewer");
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
        assert!(body["paths"]["/api/v1/codescan/status"].is_object());
        assert!(body["components"]["securitySchemes"]["bearer_jwt"].is_object());
    }
}
