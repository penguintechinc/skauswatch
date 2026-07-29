//! OpenAPI 3.x spec generation for the logs ingest surface — see
//! `backend.md` OpenAPI and `docs/v2-port/openapi-pattern.md`.
//!
//! logs has no authentication layer of its own (see `crate::ingest`) and
//! exposes exactly one business endpoint (`POST /ingest`, plus the
//! `GET /healthz` liveness probe consumed by the manager). Per
//! `docs/v2-port/openapi-pattern.md` §5-6, a *live* spec route on a service
//! with no auth to gate it would either sit unauthenticated (violating
//! `backend.md`'s "docs must be authenticated" rule) or need auth machinery
//! that doesn't otherwise exist here just to protect a doc route. This
//! service therefore publishes only the **committed** `openapi/v1.yaml`
//! (regenerate via `skauswatch-logs openapi > openapi/v1.yaml`) and adds no
//! `/openapi.json` route.

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
)]
pub(crate) struct ApiDoc;
