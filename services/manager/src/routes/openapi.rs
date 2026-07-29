//! OpenAPI 3.x spec generation and (flag-gated) live serving for the
//! manager REST surface — see `backend.md` OpenAPI and
//! `docs/v2-port/openapi-pattern.md` for the org-wide pattern this
//! implements.
//!
//! The manager is the one v2 service that owns a login endpoint
//! (`POST /api/v1/auth/login`), so per the pattern doc's §6 "login-split" it
//! publishes **two** documents rather than one gated-or-not toggle:
//!
//! - [`PublicApiDoc`] — `auth::login` only, served **unauthenticated** at
//!   `GET /api/v1/openapi/login.json` (still flag-gated — an operator can
//!   still kill live doc serving entirely). This is the sole unauthenticated
//!   doc route in the service.
//! - [`ApiDoc`] — every other endpoint, served at `GET /api/v1/openapi.json`
//!   behind the normal per-handler `CurrentUser` extractor, same as every
//!   other route in this service.
//!
//! Two independent `#[derive(utoipa::OpenApi)]` blocks (never one document
//! with paths stripped at serve time) so the committed, full,
//! auth-required `openapi/v1.yaml` and the public login-only doc can never
//! silently drift apart.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use utoipa::OpenApi;

use super::{
    alerts, approvals, asm, auth, codescan, endpoint, research, s3_scan, siem, threat_intel, users,
};
use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

/// PostHog flag gating *live* `/api/v1/openapi*.json` serving — an
/// independent kill-switch from every feature-area flag, since serving API
/// documentation is a distinct concern. The committed `openapi/v1.yaml` in
/// the repo is generated separately (`skauswatch-manager openapi`
/// subcommand) and is unaffected by this flag either way.
pub(crate) const OPENAPI_FLAG: &str = "skauswatch.openapi-docs";

/// Unauthenticated public document — the login endpoint only. An
/// unauthenticated caller legitimately needs to discover this one endpoint
/// before it has a token; every other endpoint lives in [`ApiDoc`] instead.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "SkausWatch Manager API — Login",
        version = "1",
        description = "Public, unauthenticated subset of the manager API: the \
            login endpoint only. See GET /api/v1/openapi.json (authenticated) \
            for the full API surface."
    ),
    paths(auth::login),
    components(schemas(
        ErrorResponse,
        ValidationErrorResponse,
        auth::LoginRequest,
        auth::LoginUser,
        auth::LoginResponse,
    )),
    tags((name = "auth", description = "Authentication: login, refresh, logout, register, current user")),
)]
pub(crate) struct PublicApiDoc;

/// Aggregated OpenAPI 3.x document for every `/api/v1/*` route except
/// `POST /api/v1/auth/login` (see [`PublicApiDoc`]). Generated from the
/// `#[utoipa::path]` annotations on each handler below — never hand-edit
/// `openapi/v1.yaml`; regenerate it with
/// `skauswatch-manager openapi > openapi/v1.yaml`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "SkausWatch Manager API",
        version = "1",
        description = "SkausWatch manager service — users, alerts, threat \
            intelligence, approvals, ENDPOINT agent fleet, SIEM, ASM, \
            CodeScan proxy, S3 malware scanning, and research lookups."
    ),
    paths(
        // auth (login excluded — see PublicApiDoc)
        auth::refresh,
        auth::logout,
        auth::me,
        auth::register,
        // users
        users::list_users,
        users::get_user,
        users::create_user,
        users::update_user,
        users::delete_user,
        // license
        super::license::license_features,
        // alerts
        alerts::list_alerts,
        alerts::get_alert,
        alerts::create_alert,
        alerts::update_alert,
        alerts::update_alert_status,
        alerts::request_ai_review,
        alerts::search_alerts,
        alerts::alert_statistics,
        // threat-intel
        threat_intel::list_iocs,
        threat_intel::get_ioc,
        threat_intel::create_ioc,
        threat_intel::bulk_create_iocs,
        threat_intel::delete_ioc,
        threat_intel::search_iocs,
        threat_intel::lookup_ioc,
        threat_intel::get_statistics,
        threat_intel::list_feeds,
        // approvals
        approvals::list_approvals,
        approvals::list_pending_approvals,
        approvals::get_approval,
        approvals::create_approval,
        approvals::decide_approval,
        approvals::cancel_approval,
        approvals::get_statistics,
        // s3-scan
        s3_scan::list_buckets,
        s3_scan::create_bucket,
        s3_scan::get_bucket,
        s3_scan::update_bucket,
        s3_scan::delete_bucket,
        s3_scan::test_bucket_connection,
        s3_scan::trigger_scan,
        s3_scan::list_jobs,
        s3_scan::get_job,
        s3_scan::cancel_job,
        s3_scan::query_results,
        s3_scan::get_result,
        s3_scan::get_statistics,
        s3_scan::get_schedule,
        s3_scan::set_schedule,
        s3_scan::delete_schedule,
        s3_scan::upload_file,
        s3_scan::get_upload_result,
        s3_scan::list_upload_history,
        s3_scan::delete_upload_scan,
        s3_scan::create_ti_indicator,
        s3_scan::get_ti_enrichment,
        s3_scan::hash_lookup,
        // endpoint
        endpoint::register_agent,
        endpoint::heartbeat,
        endpoint::report_events,
        endpoint::agent_config,
        endpoint::list_agents,
        endpoint::get_agent,
        endpoint::get_agent_events,
        endpoint::deactivate_agent,
        endpoint::get_statistics,
        // siem
        siem::siem_health,
        siem::proxy_ingest,
        siem::search_logs,
        siem::siem_stats,
        siem::get_siem_config,
        siem::update_siem_config,
        // asm
        asm::create_asm_scan,
        asm::list_asm_scans,
        asm::get_asm_scan,
        asm::get_asm_scan_hosts,
        asm::get_asm_scan_screenshots,
        asm::get_asm_scan_certs,
        asm::get_asm_scan_diff,
        asm::get_asm_scan_report,
        asm::get_port_settings,
        asm::update_port_settings,
        // codescan
        codescan::codescan_status,
        codescan::list_repos,
        codescan::create_repo,
        codescan::get_repo,
        codescan::update_repo,
        codescan::delete_repo,
        codescan::list_reviews,
        codescan::create_review,
        codescan::get_review,
        codescan::list_plans,
        codescan::create_plan,
        codescan::get_plan,
        // research
        research::lookup,
        research::whois_lookup,
        research::dns_lookup,
        research::asn_lookup,
        research::shodan_lookup,
        research::maltego_lookup,
        research::get_config,
    ),
    components(schemas(
        ErrorResponse,
        ValidationErrorResponse,
        // auth
        auth::RefreshRequest,
        auth::RefreshResponse,
        auth::LogoutResponse,
        auth::MeResponse,
        auth::RegisterRequest,
        auth::RegisterUser,
        auth::RegisterResponse,
        // users
        users::UserItem,
        users::UserDetail,
        users::UserSummary,
        users::UserListResponse,
        users::CreateRequest,
        users::UserCreateResponse,
        users::UpdateRequest,
        users::UserUpdateResponse,
        users::UserDeleteResponse,
        // license
        super::license::LicenseFeaturesResponse,
        super::license::LicenseFeaturesData,
        super::license::LicenseFeaturesMeta,
        // alerts
        alerts::AlertItem,
        alerts::AlertSearchItem,
        alerts::AlertListResponse,
        alerts::CreateBody,
        alerts::AlertCreateSummary,
        alerts::AlertCreateResponse,
        alerts::UpdateBody,
        alerts::AlertUpdateSummary,
        alerts::AlertUpdateResponse,
        alerts::StatusBody,
        alerts::AlertStatusResponse,
        alerts::AiReviewBody,
        alerts::AiReviewResponse,
        alerts::SearchBody,
        alerts::AlertSearchResponse,
        alerts::AlertStatisticsResponse,
        // threat-intel
        threat_intel::IocItem,
        threat_intel::IocDetail,
        threat_intel::IocSearchItem,
        threat_intel::IocListResponse,
        threat_intel::IocBody,
        threat_intel::IocCreateSummary,
        threat_intel::IocCreateResponse,
        threat_intel::BulkBody,
        threat_intel::BulkCreateResponse,
        threat_intel::IocDeleteResponse,
        threat_intel::SearchBody,
        threat_intel::IocSearchResponse,
        threat_intel::LookupBody,
        threat_intel::ThreatIntelStatisticsResponse,
        threat_intel::FeedsResponse,
        // approvals
        approvals::ApprovalListItem,
        approvals::ApprovalListResponse,
        approvals::ApprovalPendingItem,
        approvals::ApprovalPendingResponse,
        approvals::ApprovalDetail,
        approvals::CreateBody,
        approvals::ApprovalCreateSummary,
        approvals::ApprovalCreateResponse,
        approvals::DecideBody,
        approvals::ApprovalDecisionSummary,
        approvals::ApprovalDecisionResponse,
        approvals::ApprovalCancelResponse,
        approvals::ApprovalStatisticsResponse,
        // s3-scan
        s3_scan::BucketItem,
        s3_scan::BucketListResponse,
        s3_scan::BucketCreateBody,
        s3_scan::BucketCreateSummary,
        s3_scan::BucketCreateResponse,
        s3_scan::BucketUpdateBody,
        s3_scan::BucketUpdateSummary,
        s3_scan::BucketUpdateResponse,
        s3_scan::BucketDeleteResponse,
        s3_scan::BucketTestSuccess,
        s3_scan::BucketTestFailure,
        s3_scan::TriggerBody,
        s3_scan::TriggerScanSummary,
        s3_scan::TriggerScanResponse,
        s3_scan::JobItem,
        s3_scan::JobListResponse,
        s3_scan::JobDetail,
        s3_scan::CancelJobResponse,
        s3_scan::ResultItem,
        s3_scan::ResultDetail,
        s3_scan::ResultsListResponse,
        s3_scan::S3ScanStatisticsResponse,
        s3_scan::ScheduleDetail,
        s3_scan::ScheduleBody,
        s3_scan::ScheduleSummary,
        s3_scan::ScheduleSetResponse,
        s3_scan::ScheduleDeleteResponse,
        s3_scan::UploadFileRequest,
        s3_scan::UploadCreateSummary,
        s3_scan::UploadCreateResponse,
        s3_scan::UploadDetail,
        s3_scan::UploadHistoryItem,
        s3_scan::UploadHistoryResponse,
        s3_scan::UploadDeleteResponse,
        s3_scan::TiIndicatorExistsResponse,
        s3_scan::TiIndicatorCreateSummary,
        s3_scan::TiIndicatorCreateResponse,
        s3_scan::HashLookupBody,
        // endpoint
        endpoint::RegisterBody,
        endpoint::RegisterResponse,
        endpoint::HeartbeatBody,
        endpoint::HeartbeatResponse,
        endpoint::ReportEventsResponse,
        endpoint::AgentConfigInner,
        endpoint::AgentConfigResponse,
        endpoint::AgentListItem,
        endpoint::AgentListResponse,
        endpoint::AgentDetail,
        endpoint::AgentEventItem,
        endpoint::AgentEventsResponse,
        endpoint::DeactivateResponse,
        endpoint::EndpointStatisticsResponse,
        // siem
        siem::SiemHealthResponse,
        siem::SiemSearchResponse,
        siem::SiemStatsResponse,
        siem::SiemConfigResponse,
        siem::SiemConfigUpdateResponse,
        // research
        research::LookupBody,
        research::QueryTypeBody,
        research::DnsBody,
        research::ResearchConfigResponse,
    )),
    tags(
        (name = "auth", description = "Authentication: login, refresh, logout, register, current user"),
        (name = "users", description = "User account management"),
        (name = "license", description = "License tier and feature-flag entitlements"),
        (name = "alerts", description = "Security alert lifecycle and AI-assisted review"),
        (name = "threat-intel", description = "Threat indicator (IOC) CRUD, search, and lookup"),
        (name = "approvals", description = "Multi-approver approval workflow"),
        (name = "s3-scan", description = "S3 bucket malware scanning: buckets, jobs, results, ad-hoc uploads"),
        (name = "endpoint", description = "ENDPOINT agent fleet: registration, heartbeat, events, operator views"),
        (name = "siem", description = "Log-pipeline health, ingest proxy, OpenSearch search/stats, configuration"),
        (name = "asm", description = "Attack surface management — authenticated proxy to the scanner service"),
        (name = "codescan", description = "AI code review — authenticated proxy to worker-codescan"),
        (name = "research", description = "Threat-research lookups: whois, dns, asn, shodan, maltego"),
    ),
    modifiers(&SecurityAddon),
)]
pub(crate) struct ApiDoc;

/// Registers every security scheme referenced by `#[utoipa::path(security(...))]`
/// annotations above: `bearer_jwt` (the standard JWT auth used by nearly
/// every route) and `endpoint_hmac` (the `X-API-Key`/`X-Agent-ID` HMAC
/// scheme used only by the ENDPOINT agent-facing routes in `routes/endpoint.rs`).
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
            components.add_security_scheme(
                "endpoint_hmac",
                utoipa::openapi::security::SecurityScheme::ApiKey(
                    utoipa::openapi::security::ApiKey::Header(
                        utoipa::openapi::security::ApiKeyValue::new("X-API-Key"),
                    ),
                ),
            );
        }
    }
}

/// Router for the live `/openapi.json` and `/openapi/login.json` routes.
pub(crate) fn router() -> Router<AppState> {
    Router::new()
        .route("/openapi.json", get(openapi_spec))
        .route("/openapi/login.json", get(public_openapi_spec))
}

/// GET /openapi.json — the generated full OpenAPI 3.x document, gated by
/// `OPENAPI_FLAG` (404 when disabled) and standard JWT auth (401 when
/// missing/invalid — enforced by the `CurrentUser` extractor, same as every
/// other route in this service). Not itself part of the generated spec to
/// avoid a self-referential schema.
async fn openapi_spec(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Response, ApiError> {
    if !state.license.flag_enabled(OPENAPI_FLAG).await {
        return Err(ApiError::NotFound("Not Found".to_owned()));
    }
    Ok((StatusCode::OK, Json(ApiDoc::openapi())).into_response())
}

/// GET /openapi/login.json — the public login-only document. Deliberately
/// unauthenticated (no `CurrentUser` extractor) — this is the sole
/// unauthenticated doc route in the service, per the login-split described
/// in the module docs. Still flag-gated so an operator can kill it.
async fn public_openapi_spec(State(state): State<AppState>) -> Result<Response, ApiError> {
    if !state.license.flag_enabled(OPENAPI_FLAG).await {
        return Err(ApiError::NotFound("Not Found".to_owned()));
    }
    Ok((StatusCode::OK, Json(PublicApiDoc::openapi())).into_response())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    fn dev_license() -> std::sync::Arc<LicenseClient> {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    fn gated_license() -> std::sync::Arc<LicenseClient> {
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
    async fn full_spec_requires_auth() {
        let server = test_server(AppStateInner::for_tests(dev_license()));
        let resp = server.get("/api/v1/openapi.json").await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn full_spec_404s_when_flag_disabled() {
        // `CurrentUser` re-fetches the caller from `users` on every request
        // (src/auth/mod.rs), so a real DB-backed state is required here —
        // the lazy `for_tests` pool would fail the extractor before the
        // handler's flag check ever runs.
        let state = crate::routes::test_support::db_state(gated_license()).await;
        let (_, token) =
            crate::routes::test_support::authed_user(&state, "openapi-gated@example.com", "viewer")
                .await;
        let server = test_server(state);
        let resp = server
            .get("/api/v1/openapi.json")
            .authorization_bearer(token)
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn full_spec_returns_the_generated_document_when_authed_and_enabled() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let (_, token) =
            crate::routes::test_support::authed_user(&state, "openapi-full@example.com", "viewer")
                .await;
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
        assert!(body["paths"]["/api/v1/users"].is_object());
        assert!(body["components"]["securitySchemes"]["bearer_jwt"].is_object());
        assert!(
            body["components"]["securitySchemes"]["endpoint_hmac"].is_object(),
            "expected the endpoint_hmac apiKey scheme to be registered"
        );
        // The login endpoint is NOT part of the full doc's own path list —
        // it lives exclusively in the public doc.
        assert!(
            !body["paths"]
                .as_object()
                .is_some_and(|p| p.contains_key("/api/v1/auth/login"))
        );
    }

    #[tokio::test]
    async fn public_login_doc_is_unauthenticated_and_flag_gated() {
        let gated_state = AppStateInner::for_tests(gated_license());
        let server = test_server(gated_state);
        let resp = server.get("/api/v1/openapi/login.json").await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn public_login_doc_serves_unauthenticated_and_contains_only_login() {
        let state = AppStateInner::for_tests(dev_license());
        let server = test_server(state);
        // No Authorization header at all — proving the route really is
        // unauthenticated.
        let resp = server.get("/api/v1/openapi/login.json").await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert!(
            body["openapi"]
                .as_str()
                .unwrap_or_default()
                .starts_with("3."),
            "expected an OpenAPI 3.x document, got: {body}"
        );
        let paths = match body["paths"].as_object() {
            Some(p) => p,
            None => panic!("expected paths object, got: {body}"),
        };
        assert_eq!(
            paths.keys().collect::<Vec<_>>(),
            vec!["/api/v1/auth/login"],
            "public doc must contain ONLY the login path"
        );
    }
}
