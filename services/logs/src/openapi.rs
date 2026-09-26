//! OpenAPI 3.x spec generation for the logs ingest surface — see
//! `backend.md` OpenAPI and `docs/v2-port/openapi-pattern.md`.
//!
//! `POST /ingest` now requires a valid bearer JWT (`skauswatch_auth::
//! tenant_middleware`) plus the `skauswatch.log-ingest` flag (see
//! `crate::ingest`); `GET /healthz` remains the manager's unauthenticated
//! liveness probe. This service still publishes only the **committed**
//! `openapi/v1.yaml` (regenerate via `skauswatch-logs openapi >
//! openapi/v1.yaml`) and adds no live `/openapi.json` route — standing up
//! an authenticated live-doc route (per `docs/v2-port/openapi-pattern.md`
//! §5-6) is a separate, not-yet-scheduled piece of work now that this
//! service has an auth layer to gate it with.

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
/// `200 {"status":"ok","service":"logs"}` body.
#[derive(Serialize, ToSchema)]
pub(crate) struct HealthResponse {
    /// Always `"ok"` when the process is serving requests.
    status: String,
    /// Always `"logs"` — identifies which service answered.
    service: String,
}

/// Aggregated OpenAPI 3.x document for the logs ingest surface. Generated
/// from the `#[utoipa::path]` annotations on `crate::ingest::handle_ingest`
/// and `crate::ingest::handle_health` — never hand-edit `openapi/v1.yaml`;
/// regenerate it with `skauswatch-logs openapi > openapi/v1.yaml`.
#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "SkausWatch Logs Ingest API",
        version = "1",
        description = "Internal, unauthenticated SIEM log ingest sink. The \
            manager's siem router (`LOGS_URL`) is the only intended caller; \
            this service is never exposed outside the cluster network and \
            has no auth layer of its own."
    ),
    paths(crate::ingest::handle_ingest, crate::ingest::handle_health),
    components(schemas(IngestAcceptedResponse, IngestErrorResponse, HealthResponse)),
    tags((name = "logs", description = "SIEM log ingest and liveness")),
    modifiers(&SecurityAddon),
)]
pub(crate) struct ApiDoc;

/// Registers the `bearer_jwt` HTTP Bearer security scheme referenced by
/// `handle_ingest`'s `#[utoipa::path(security(("bearer_jwt" = [])))]`
/// annotation — mirrors `services/pki/src/routes/openapi.rs`'s
/// `SecurityAddon`.
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
