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
//!
//! Task 2.1 adds `crate::admin`'s `PUT /api/v1/admin/ingest/lifecycle` and
//! `POST /api/v1/admin/ingest/restore` — both bearer-JWT + scope gated (see
//! that module's doc comment), never the `skauswatch.log-ingest` flag
//! (cluster lifecycle configuration is not the tenant-facing ingest data
//! plane that flag gates).

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
        crate::admin::handle_put_lifecycle,
        crate::admin::handle_post_restore,
    ),
    components(schemas(
        IngestAcceptedResponse,
        IngestErrorResponse,
        HealthResponse,
        ReadyResponse,
        crate::admin::LifecycleRequest,
        crate::admin::LifecycleResponse,
        crate::admin::RestoreRequest,
        crate::admin::RestoreResponse,
        crate::admin::AdminErrorResponse,
    )),
    tags(
        (name = "svc-ingest", description = "OCSF/JSON ingest and liveness"),
        (name = "svc-ingest-admin", description = "ISM hot/warm/cold lifecycle configuration and cold-tier restore"),
    ),
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use utoipa::OpenApi as _;

    use super::*;

    /// `main.rs::print_openapi` (the `skauswatch-svc-ingest openapi`
    /// subcommand that regenerates `openapi/v1.yaml`) is this struct's only
    /// caller — this test proves [`ApiDoc::openapi`] actually builds a spec
    /// declaring every route this service serves, both the ingest listener
    /// (`crate::listeners::http`) and the admin surface
    /// (`crate::admin`, mounted onto the same server per
    /// `crate::bootstrap::run_receiver`), not just that the annotations
    /// compile.
    #[test]
    fn generated_spec_declares_every_ingest_and_admin_path() {
        let spec = ApiDoc::openapi();
        for path in [
            "/ingest",
            "/healthz",
            "/readyz",
            "/api/v1/admin/ingest/lifecycle",
            "/api/v1/admin/ingest/restore",
        ] {
            assert!(
                spec.paths.paths.contains_key(path),
                "openapi spec is missing path: {path}"
            );
        }
    }

    /// Every `components(schemas(...))` entry in [`ApiDoc`]'s `#[openapi]`
    /// attribute must actually register a schema (a typo'd/renamed struct
    /// silently drops from the spec rather than failing the derive), and
    /// [`SecurityAddon::modify`] must register the `bearer_jwt` scheme every
    /// `#[utoipa::path(security(("bearer_jwt" = [])))]` annotation
    /// references.
    #[test]
    fn generated_spec_registers_every_documented_schema_and_the_bearer_scheme() {
        let spec = ApiDoc::openapi();
        let components = spec
            .components
            .expect("modifiers(&SecurityAddon) requires components to be present");
        for schema in [
            "IngestAcceptedResponse",
            "IngestErrorResponse",
            "HealthResponse",
            "ReadyResponse",
            "LifecycleRequest",
            "LifecycleResponse",
            "RestoreRequest",
            "RestoreResponse",
            "AdminErrorResponse",
        ] {
            assert!(
                components.schemas.contains_key(schema),
                "openapi spec is missing schema: {schema}"
            );
        }
        assert!(
            components.security_schemes.contains_key("bearer_jwt"),
            "SecurityAddon must register the bearer_jwt scheme"
        );
    }

    /// `main.rs::print_openapi` calls `.to_yaml()` on the same spec this
    /// module builds — proves the whole document (not just individual
    /// fields) round-trips through utoipa's YAML serializer without error,
    /// the same path `skauswatch-svc-ingest openapi > openapi/v1.yaml` uses.
    #[test]
    fn generated_spec_serializes_to_yaml() {
        let spec = ApiDoc::openapi();
        let yaml = spec.to_yaml().expect("spec must serialize to YAML");
        assert!(yaml.contains("SkausWatch svc-ingest API"));
        assert!(yaml.contains("svc-ingest-admin"));
    }
}
