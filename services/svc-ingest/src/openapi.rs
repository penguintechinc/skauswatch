//! OpenAPI 3.x spec generation for the svc-ingest HTTP OCSF/JSON listener —
//! see `backend.md` OpenAPI and `docs/v2-port/openapi-pattern.md`.
//!
//! `POST /ingest` requires a valid bearer JWT (`skauswatch_auth::
//! tenant_middleware`) plus the `skauswatch.log-ingest` flag; `GET /healthz`
//! and `/readyz` remain the manager's unauthenticated liveness and readiness
//! probes. This service publishes only the **committed** `openapi/v1.yaml`
//! (regenerate via `skauswatch-svc-ingest openapi > openapi/v1.yaml`) and
//! adds no live `/openapi.json` route — standing up an authenticated live-doc
//! route is a separate piece of work once this service has an auth layer to
//! gate it with (per `docs/v2-port/openapi-pattern.md` §5-6).

use serde::Serialize;
use utoipa::ToSchema;

/// Documentation-only mirror of `handle_ingest`'s `202 {"ingested": N}` body.
#[derive(Serialize, ToSchema)]
pub(crate) struct IngestAcceptedResponse {
    /// Number of records accepted in this batch (post OCSF normalization).
    ingested: i64,
}

/// Documentation-only mirror of the `500 {"error": "..."}` body emitted on
/// OCSF normalization failure or an OpenSearch bulk-write error.
#[derive(Serialize, ToSchema)]
pub(crate) struct IngestErrorResponse {
    /// Human-readable error message.
    error: String,
}

/// Documentation-only mirror of `handle_health`'s
/// `200 {"status":"ok","service":"svc-ingest"}` body.
#[derive(Serialize, ToSchema)]
pub(crate) struct HealthResponse {
    /// Always `"ok"` when the process is serving requests.
    status: String,
    /// Always `"svc-ingest"` — identifies which service answered.
    service: String,
}

/// Documentation-only mirror of `handle_ready`'s readiness response.
#[derive(Serialize, ToSchema)]
pub(crate) struct ReadyResponse {
    /// `"ready"` when ready, `"not ready"` when not.
    status: String,
}

/// Aggregated OpenAPI 3.x document for the svc-ingest HTTP OCSF/JSON listener.
/// Generated from the `#[utoipa::path]` annotations on
/// `crate::listeners::http::handle_ingest`, `handle_health`, and `handle_ready`
/// — never hand-edit `openapi/v1.yaml`; regenerate it with
/// `skauswatch-svc-ingest openapi > openapi/v1.yaml`.
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "SkausWatch svc-ingest API",
        version = "1",
        description = "Internal, authenticated SIEM OCSF/JSON log ingest sink. \
            The manager's siem router is the only intended caller."
    ),
    paths(
        crate::listeners::http::handle_ingest,
        crate::listeners::http::handle_health,
        crate::listeners::http::handle_ready,
    ),
    components(schemas(IngestAcceptedResponse, IngestErrorResponse, HealthResponse, ReadyResponse)),
    tags((name = "svc-ingest", description = "OCSF/JSON ingest and liveness")),
    modifiers(&SecurityAddon),
)]
pub(crate) struct ApiDoc;

/// Registers the `bearer_jwt` HTTP Bearer security scheme referenced by
/// `handle_ingest`'s `#[utoipa::path(security(("bearer_jwt" = [])))]`
/// annotation.
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
