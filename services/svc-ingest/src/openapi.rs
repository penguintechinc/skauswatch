//! OpenAPI 3.x spec aggregator for `skauswatch-svc-ingest` — stub until
//! Task 1.3 adds real `#[utoipa::path]` annotations (mirrors
//! `services/logs/src/openapi.rs`; see `backend.md` OpenAPI).

/// Aggregated OpenAPI 3.x document. Empty (no paths) until Wave 1 Task 1.3
/// wires in the `/ingest` route annotations.
#[derive(utoipa::OpenApi)]
#[openapi(info(title = "SkausWatch svc-ingest API", version = "1"))]
pub(crate) struct ApiDoc;
