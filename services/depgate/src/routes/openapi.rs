//! OpenAPI 3.x spec generation for the admin/report REST surface
//! (`/api/v1/depgate/*`) — see `backend.md` OpenAPI and
//! `docs/v2-port/openapi-pattern.md`.
//!
//! Scope note, mirroring `services/logs`' documented precedent: this
//! service publishes only the **committed** `openapi/v1.yaml` (regenerate
//! via `skauswatch-depgate openapi > openapi/v1.yaml`) and stands up no
//! live `/openapi.json`/Swagger-UI route. The OCI Distribution surface
//! (`/v2/*`, `src/routes/oci.rs`) is a fixed external protocol (CNCF
//! Distribution spec), not a service-defined REST API, so it is
//! deliberately out of scope for this OpenAPI document — same reasoning
//! `backend.md` already applies to gRPC-only surfaces.

use utoipa::OpenApi;

/// Aggregated OpenAPI 3.x document for the `/api/v1/depgate` admin surface.
/// Generated from the `#[utoipa::path]` annotations on
/// `crate::routes::admin`'s handlers — never hand-edit `openapi/v1.yaml`.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "SkausWatch DepGate Admin API",
        version = "1",
        description = "Tenant-scoped report/audit surface over DepGate's OCI \
            pull-through cache (docs/v2-port/v2.1-depgate.md). Does not cover \
            the /v2/* OCI Distribution proxy surface itself, which is a fixed \
            external protocol rather than a service-defined REST API."
    ),
    paths(
        crate::routes::admin::list_artifacts,
        crate::routes::admin::list_risk_findings,
        crate::routes::admin::list_quarantine,
        crate::routes::admin::update_quarantine,
        crate::routes::admin::list_policy_rules,
        crate::routes::admin::create_policy_rule,
        crate::routes::admin::get_policy_rule,
        crate::routes::admin::update_policy_rule,
        crate::routes::admin::delete_policy_rule,
        crate::routes::admin::stats,
    ),
    components(schemas(
        crate::routes::admin::ArtifactItem,
        crate::routes::admin::ArtifactListResponse,
        crate::routes::admin::RiskFindingItem,
        crate::routes::admin::QuarantineItem,
        crate::routes::admin::QuarantineListResponse,
        crate::routes::admin::UpdateQuarantineRequest,
        crate::routes::admin::PolicyRuleItem,
        crate::routes::admin::PolicyRuleRequest,
        crate::routes::admin::StatsResponse,
        crate::error::ErrorResponse,
    )),
    tags((name = "depgate", description = "DepGate cache/scan index and audit reporting")),
    modifiers(&SecurityAddon),
)]
pub(crate) struct ApiDoc;

/// Registers the `bearer_jwt` HTTP Bearer security scheme referenced by
/// every handler's `#[utoipa::path(security(("bearer_jwt" = [])))]`
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
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn spec_generates_and_contains_expected_paths() {
        let doc = ApiDoc::openapi();
        let yaml = doc.to_yaml().expect("serialize");
        assert!(yaml.contains("/api/v1/depgate/artifacts"));
        assert!(yaml.contains("/api/v1/depgate/artifacts/{sha256}/risk-findings"));
        assert!(yaml.contains("/api/v1/depgate/quarantine"));
        assert!(yaml.contains("/api/v1/depgate/quarantine/{id}"));
        assert!(yaml.contains("/api/v1/depgate/policy-rules"));
        assert!(yaml.contains("/api/v1/depgate/policy-rules/{id}"));
        assert!(yaml.contains("/api/v1/depgate/stats"));
        assert!(yaml.contains("bearer_jwt"));
    }
}
