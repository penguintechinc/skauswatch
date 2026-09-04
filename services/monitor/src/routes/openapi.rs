//! OpenAPI 3.x spec generation and (flag-gated, authenticated) live serving
//! for the monitor REST surface — see `backend.md` OpenAPI and
//! `docs/v2-port/openapi-pattern.md` for the org-wide pattern this service
//! follows.
//!
//! monitor has no login endpoint of its own (tokens are issued and verified
//! elsewhere — see `crate::auth`), so there is no unauthenticated public doc
//! split here: the entire generated spec sits behind the same `AuthedUser`
//! extractor every authenticated route in this service uses. That's an
//! independent decision from what the *business* routes themselves require:
//! health/version/dashboard and the alert-search routes are intentionally
//! unauthenticated (matching v1 — see each module's docs), and their
//! `#[utoipa::path]` annotations correctly omit `security(...)` to document
//! that accurately. The doc route itself, `alerts::update_alert_status`, and
//! — as of the tenant-isolation hardening pass — every `events::*` route
//! (search/get/stream, gated by `skauswatch_auth::tenant_middleware` rather
//! than `AuthedUser`; see `events.rs` module docs) all require a bearer
//! token.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use utoipa::OpenApi;

use super::{alerts, dashboard, events, health};
use crate::auth::AuthedUser;
use crate::error::{ApiError, ErrorResponse};
use crate::models::{
    Alert, AlertSearchRequest, AlertSearchResponse, BaseEvent, DashboardMetrics,
    EventSearchRequest, EventSearchResponse, EventType, LogSource, Severity, ThreatFeed,
};
use crate::state::AppState;
use crate::threat_intel::routes as threat_intel_routes;

/// PostHog flag gating the *live* `/api/v1/openapi.json` route — independent
/// of `crate::flags::MONITOR_FLAG`, since serving API documentation is a
/// distinct concern from the monitor feature itself. The committed
/// `openapi/v1.yaml` in the repo is generated separately
/// (`skauswatch-monitor openapi` subcommand) and is unaffected by this flag
/// either way.
pub(crate) const OPENAPI_FLAG: &str = "skauswatch.openapi-docs";

/// Aggregated OpenAPI 3.x document for every monitor route. Generated from
/// the `#[utoipa::path]` annotations on each handler below — never
/// hand-edit `openapi/v1.yaml`; regenerate it with
/// `skauswatch-monitor openapi > openapi/v1.yaml`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "SkausWatch Monitor API",
        version = "1",
        description = "Security event/alert REST API over Elasticsearch/OpenSearch: \
            health/version, dashboard metrics, event search/get/stream, and alert \
            management."
    ),
    paths(
        health::health_check,
        health::version_info,
        dashboard::get_dashboard_metrics,
        events::search_events,
        events::get_event,
        events::stream_events,
        alerts::search_alerts,
        alerts::get_alert,
        alerts::update_alert_status,
        threat_intel_routes::search_indicators,
        threat_intel_routes::get_indicator,
        threat_intel_routes::list_feeds,
    ),
    components(schemas(
        ErrorResponse,
        health::HealthResponse,
        health::VersionResponse,
        DashboardMetrics,
        Severity,
        EventType,
        LogSource,
        BaseEvent,
        EventSearchRequest,
        EventSearchResponse,
        Alert,
        AlertSearchRequest,
        AlertSearchResponse,
        alerts::UpdateAlertStatusRequest,
        alerts::UpdateAlertStatusResponse,
        crate::models::ThreatLevel,
        crate::models::Ioc,
        ThreatFeed,
        threat_intel_routes::IndicatorSearchResponse,
    )),
    tags(
        (name = "monitor", description = "Health/version, dashboard metrics, event search, and alert management"),
        (name = "threat-intel", description = "TAXII feed status and threat indicator search — see crate::threat_intel::mod for how this differs from manager's IOC CRUD"),
    ),
    modifiers(&SecurityAddon),
)]
pub(crate) struct ApiDoc;

/// Registers the `bearer_jwt` HTTP Bearer security scheme referenced by
/// `#[utoipa::path(security(("bearer_jwt" = [])))]` on
/// `alerts::update_alert_status` — the only business route in this service
/// that actually requires auth (see module docs above).
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

/// Router for GET /openapi.json — mounted only under the `/api/v1` nest in
/// `main.rs::serve()` (not double-mounted flat like the business routes),
/// since `docs/v2-port/openapi-pattern.md` documents the canonical
/// `/api/v1/*` paths only.
pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/openapi.json", get(openapi_spec))
}

/// GET /openapi.json — the generated OpenAPI 3.x document, gated by
/// `OPENAPI_FLAG` (404 when disabled) and standard JWT auth (401 when
/// missing/invalid — enforced by the `AuthedUser` extractor, same as
/// `alerts::update_alert_status`). Not itself part of the generated spec
/// (`paths(...)` above) to avoid a self-referential schema.
async fn openapi_spec(
    State(state): State<AppState>,
    _user: AuthedUser,
) -> Result<Response, ApiError> {
    if !state.license.flag_enabled(OPENAPI_FLAG).await {
        return Err(ApiError::NotFound("Not Found".to_owned()));
    }
    Ok((StatusCode::OK, Json(ApiDoc::openapi())).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::test_support::{dev_state, gated_state, sign_token};

    fn test_server(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    #[tokio::test]
    async fn openapi_requires_auth() {
        let server = test_server(dev_state());
        let resp = server.get("/api/v1/openapi.json").await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn openapi_404s_when_flag_disabled() {
        let state = gated_state();
        let token = sign_token(&state, "tenant-a", "monitor:read");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/openapi.json")
            .authorization_bearer(token)
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn openapi_returns_the_generated_document_when_authed_and_enabled() {
        let state = dev_state();
        let token = sign_token(&state, "tenant-a", "monitor:read");
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
        assert!(body["paths"]["/api/v1/health"].is_object());
        assert!(body["components"]["securitySchemes"]["bearer_jwt"].is_object());
    }
}
