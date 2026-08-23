//! Top-level router assembly: the OCI proxy (`/v2/*`), the npm proxy
//! (`/npm/*`, P2), the PyPI proxy (`/pypi/*`, P2), and the admin/report API
//! (`/api/v1/depgate/*`), all behind the `skauswatch.depgate` flag gate and
//! `skauswatch_auth::tenant_middleware`. `/healthz`/`/readyz` are wired
//! separately in `main.rs` (unauthenticated, per the standard telemetry
//! surface).
//!
//! SPIFFE-READINESS ASYMMETRY (intentional, `security.md`/`backend.md`:
//! every service is SPIFFE-ready): the admin/report API additionally gains
//! an SVID-authenticated path *alongside* this JWT/tenant path — see
//! `crate::mesh_admin`, a distinct listener on its own port. The `/v2/*`,
//! `/npm/*`, and `/pypi/*` proxy surfaces do **not** gain one: their
//! callers are `docker`/`npm`/`pip` clients speaking each ecosystem's own
//! registry auth convention, not mesh peers, and cannot present a workload
//! SVID — this router (and the bearer-JWT gate below) remains the only way
//! to reach them, unchanged.

pub mod admin;
pub mod npm;
pub mod oci;
pub(crate) mod openapi;
pub mod pypi;

use axum::Router;
use penguin_licensing::axum::{FlagGate, flag_gate};

use crate::state::AppState;

/// PostHog flag key gating the entire DepGate surface, default OFF (see
/// `docs/v2-port/v2.1-depgate.md` §10).
pub const DEPGATE_FLAG: &str = "skauswatch.depgate";

/// Builds the full application router.
///
/// Middleware ordering contract (per `skauswatch_auth::tenant_middleware`'s
/// docs: the LAST `.layer()` call is outermost/first-executed): tenant
/// check runs before the feature-flag check, matching every other service
/// in this workspace.
pub fn router(state: AppState) -> Router {
    let api = Router::new().nest("/api/v1", admin::router());
    let protected = api
        .merge(oci::router())
        .merge(npm::router())
        .merge(pypi::router())
        .layer(axum::middleware::from_fn_with_state(
            FlagGate::new(state.license.clone(), DEPGATE_FLAG),
            flag_gate,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            skauswatch_auth::tenant_middleware::<AppState>,
        ));

    Router::new().merge(protected).with_state(state)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use penguin_licensing::LicenseClient;
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::router;
    use crate::db::{self, UpsertArtifact};
    use crate::state::AppStateInner;

    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    fn dev_license() -> Arc<LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    fn gated_license() -> Arc<LicenseClient> {
        skauswatch_testkit::license::gated_license("skauswatch")
    }

    fn test_server(state: crate::state::AppState) -> axum_test::TestServer {
        axum_test::TestServer::new(router(state))
    }

    async fn seed_artifact(pool: &PgPool, tenant_id: Uuid, name: &str, verdict: &str) {
        db::upsert_artifact(
            pool,
            &UpsertArtifact {
                ecosystem: "oci",
                name,
                reference: "latest",
                sha256: "deadbeefcafebabe",
                upstream: "https://registry-1.docker.io",
                content_type: Some("application/vnd.oci.image.manifest.v1+json"),
                size_bytes: 42,
                verdict,
                scanner_version: "test",
                pinned: false,
                tenant_id,
            },
        )
        .await
        .expect("seed artifact");
    }

    #[tokio::test]
    async fn artifacts_endpoint_requires_a_bearer_token() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let server = test_server(state);
        let res = server.get("/api/v1/depgate/artifacts").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn flag_off_blocks_the_whole_surface() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, gated_license());
        let tenant = Uuid::new_v4();
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.jwt_secret,
            "user-1",
            &tenant.to_string(),
            "*:read",
            &["admin"],
        );
        let server = test_server(state);
        let res = server
            .get("/api/v1/depgate/artifacts")
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn artifacts_endpoint_returns_only_the_caller_tenants_rows() {
        let pool = test_pool().await;
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        seed_artifact(&pool, tenant_a, "library/nginx", "clean").await;
        seed_artifact(&pool, tenant_b, "library/redis", "clean").await;

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.jwt_secret,
            "user-1",
            &tenant_a.to_string(),
            "*:read",
            &["admin"],
        );
        let server = test_server(state);
        let res = server
            .get("/api/v1/depgate/artifacts")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["name"], "library/nginx");
    }

    #[tokio::test]
    async fn artifacts_endpoint_filters_by_verdict() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        seed_artifact(&pool, tenant, "library/nginx", "clean").await;
        seed_artifact(&pool, tenant, "library/malicious", "infected").await;

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.jwt_secret,
            "user-1",
            &tenant.to_string(),
            "*:read",
            &["admin"],
        );
        let server = test_server(state);
        let res = server
            .get("/api/v1/depgate/artifacts?verdict=infected")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["name"], "library/malicious");
    }

    #[tokio::test]
    async fn quarantine_endpoint_lists_only_the_caller_tenants_events() {
        let pool = test_pool().await;
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        db::insert_quarantine(
            &pool,
            &db::QuarantineInsert {
                sha256: "badbad",
                ecosystem: "oci",
                name: "library/malicious",
                reference: "latest",
                reason: "YARA.EICAR_Test_File",
                threat: "infected",
                tenant_id: tenant_a,
            },
        )
        .await
        .expect("seed quarantine");
        db::insert_quarantine(
            &pool,
            &db::QuarantineInsert {
                sha256: "other",
                ecosystem: "oci",
                name: "library/other",
                reference: "latest",
                reason: "pup",
                threat: "pup",
                tenant_id: tenant_b,
            },
        )
        .await
        .expect("seed quarantine");

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.jwt_secret,
            "user-1",
            &tenant_a.to_string(),
            "*:read",
            &["admin"],
        );
        let server = test_server(state);
        let res = server
            .get("/api/v1/depgate/quarantine")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["total"], 1);
        assert_eq!(body["items"][0]["name"], "library/malicious");
    }

    #[tokio::test]
    async fn stats_endpoint_reports_verdict_counts_and_quarantine_total() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        seed_artifact(&pool, tenant, "library/nginx", "clean").await;
        seed_artifact(&pool, tenant, "library/nginx2", "clean").await;
        db::insert_quarantine(
            &pool,
            &db::QuarantineInsert {
                sha256: "badbad",
                ecosystem: "oci",
                name: "library/malicious",
                reference: "latest",
                reason: "infected",
                threat: "infected",
                tenant_id: tenant,
            },
        )
        .await
        .expect("seed quarantine");

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.jwt_secret,
            "user-1",
            &tenant.to_string(),
            "*:read",
            &["admin"],
        );
        let server = test_server(state);
        let res = server
            .get("/api/v1/depgate/stats")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["by_verdict"]["clean"], 2);
        assert_eq!(body["quarantine_count"], 1);
    }

    #[tokio::test]
    async fn a_tenant_claim_that_is_not_a_uuid_is_rejected() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.jwt_secret,
            "user-1",
            "not-a-uuid",
            "*:read",
            &["admin"],
        );
        let server = test_server(state);
        let res = server
            .get("/api/v1/depgate/artifacts")
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn push_methods_are_rejected_with_405() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let tenant = Uuid::new_v4();
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.jwt_secret,
            "user-1",
            &tenant.to_string(),
            "*:read",
            &["admin"],
        );
        let server = test_server(state);
        let res = server
            .post("/v2/library/nginx/blobs/uploads/")
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn version_check_requires_auth_too() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let server = test_server(state);
        let res = server.get("/v2/").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn version_check_succeeds_with_a_valid_tenant_token() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let tenant = Uuid::new_v4();
        let token = skauswatch_testkit::jwt::mint_claims_token(
            &state.jwt_secret,
            "user-1",
            &tenant.to_string(),
            "*:read",
            &["admin"],
        );
        let server = test_server(state);
        let res = server.get("/v2/").authorization_bearer(&token).await;
        res.assert_status_ok();
    }
}
