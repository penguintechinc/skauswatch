//! Top-level router assembly: the OCI proxy (`/v2/*`), the npm proxy
//! (`/npm/*`, P2), the PyPI proxy (`/pypi/*`, P2), the crates.io proxy
//! (`/crates/*`, P4), the Go module proxy (`/go/*`, P4), and the admin/
//! report API (`/api/v1/depgate/*`), all behind the `skauswatch.depgate`
//! flag gate and `skauswatch_auth::tenant_middleware`. `/healthz`/`/readyz`
//! are wired separately in `main.rs` (unauthenticated, per the standard
//! telemetry surface).
//!
//! SPIFFE-READINESS ASYMMETRY (intentional, `security.md`/`backend.md`:
//! every service is SPIFFE-ready): the admin/report API additionally gains
//! an SVID-authenticated path *alongside* this JWT/tenant path — see
//! `crate::mesh_admin`, a distinct listener on its own port. The `/v2/*`,
//! `/npm/*`, `/pypi/*`, `/crates/*`, and `/go/*` proxy surfaces do **not**
//! gain one: their callers are `docker`/`npm`/`pip`/`cargo`/`go` clients
//! speaking each ecosystem's own registry auth convention, not mesh peers,
//! and cannot present a workload SVID — this router (and the bearer-JWT
//! gate below) remains the only way to reach them, unchanged.

pub mod admin;
pub mod crates_io;
pub mod go;
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

/// Builds the full application router — the version every unit test in
/// this crate exercises. Carries no rate limiting; see
/// [`rate_limited_router`] and `crate::rate_limit` module docs for why that
/// is a deliberately separate entrypoint rather than a flag here.
/// `cfg(test)`-only: `main.rs::serve()` calls [`rate_limited_router`]
/// exclusively, so this has no production caller.
///
/// Middleware ordering contract (per `skauswatch_auth::tenant_middleware`'s
/// docs: the LAST `.layer()` call is outermost/first-executed): tenant
/// check runs before the feature-flag check, matching every other service
/// in this workspace.
#[cfg(test)]
pub fn router(state: AppState) -> Router {
    router_inner(state, false)
}

/// Identical route composition to [`router`], plus per-IP rate limiting on
/// the pull-through proxy and admin/report surfaces (`crate::rate_limit`).
/// This is the entrypoint `main.rs::serve()` uses; kept separate from
/// [`router`] because `tower_governor`'s key extractor needs a
/// forwarded-IP header or a populated `ConnectInfo` that `axum-test`'s
/// mock transport (what every existing test in this crate uses) doesn't
/// provide — see `crate::rate_limit` module docs.
pub fn rate_limited_router(state: AppState) -> Router {
    router_inner(state, true)
}

fn router_inner(state: AppState, rate_limit: bool) -> Router {
    let mut admin_router = admin::router();
    let mut proxy_router = oci::router()
        .merge(npm::router())
        .merge(pypi::router())
        .merge(crates_io::router())
        .merge(go::router());
    if rate_limit {
        admin_router = crate::rate_limit::admin(admin_router);
        proxy_router = crate::rate_limit::proxy(proxy_router);
    }

    let api = Router::new().nest("/api/v1", admin_router);
    let protected = api
        .merge(proxy_router)
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

    use aws_sdk_s3::Client as S3Client;
    use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
    use axum::http::StatusCode;
    use penguin_licensing::LicenseClient;
    use sqlx::PgPool;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{rate_limited_router, router};
    use crate::auth::{ADMIN_SCOPE, READ_SCOPE};
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

    /// Seeds a `pending` quarantine event and returns its id (`insert_quarantine`
    /// itself doesn't hand back the generated id — same round-trip
    /// `db::list_quarantine` already does in the read-path tests above).
    async fn seed_quarantine(pool: &PgPool, tenant_id: Uuid, sha256: &str, name: &str) -> Uuid {
        db::insert_quarantine(
            pool,
            &db::QuarantineInsert {
                sha256,
                ecosystem: "oci",
                name,
                reference: "latest",
                reason: "YARA.EICAR_Test_File",
                threat: "infected",
                policy_rule_id: None,
                tenant_id,
            },
        )
        .await
        .expect("seed quarantine");
        let (rows, _) = db::list_quarantine(pool, tenant_id, 10, 0)
            .await
            .expect("list quarantine");
        rows.into_iter()
            .find(|r| r.sha256 == sha256)
            .expect("seeded row present")
            .id
    }

    /// Mints a token carrying only [`ADMIN_SCOPE`] (no bundled `*:read`) —
    /// deliberately narrow, so an admin-gated test can't accidentally pass
    /// because it also satisfies a read check.
    fn admin_token(signing_key: &jsonwebtoken::EncodingKey, tenant: Uuid) -> String {
        skauswatch_testkit::jwt::mint_claims_token(
            signing_key,
            "admin-1",
            &tenant.to_string(),
            ADMIN_SCOPE,
            &["admin"],
        )
    }

    /// Mints a token carrying only [`READ_SCOPE`] — enough to list/read,
    /// never enough to mutate.
    fn read_only_token(signing_key: &jsonwebtoken::EncodingKey, tenant: Uuid) -> String {
        skauswatch_testkit::jwt::mint_claims_token(
            signing_key,
            "viewer-1",
            &tenant.to_string(),
            READ_SCOPE,
            &["viewer"],
        )
    }

    /// Builds an S3 client pointed at a wiremock server, same technique as
    /// `crate::cache`'s and `crate::scanpipe`'s own tests.
    fn mock_s3_client(uri: &str) -> S3Client {
        let creds = Credentials::new("AKTEST", "SKTEST", None, None, "depgate-test");
        let cfg = aws_sdk_s3::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(uri)
            .force_path_style(true)
            .credentials_provider(creds)
            .build();
        S3Client::from_conf(cfg)
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
            skauswatch_testkit::jwt::signing_key(),
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
            skauswatch_testkit::jwt::signing_key(),
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
            skauswatch_testkit::jwt::signing_key(),
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
                policy_rule_id: None,
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
                policy_rule_id: None,
                tenant_id: tenant_b,
            },
        )
        .await
        .expect("seed quarantine");

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = skauswatch_testkit::jwt::mint_claims_token(
            skauswatch_testkit::jwt::signing_key(),
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
                policy_rule_id: None,
                tenant_id: tenant,
            },
        )
        .await
        .expect("seed quarantine");

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = skauswatch_testkit::jwt::mint_claims_token(
            skauswatch_testkit::jwt::signing_key(),
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
            skauswatch_testkit::jwt::signing_key(),
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
            skauswatch_testkit::jwt::signing_key(),
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
            skauswatch_testkit::jwt::signing_key(),
            "user-1",
            &tenant.to_string(),
            "*:read",
            &["admin"],
        );
        let server = test_server(state);
        let res = server.get("/v2/").authorization_bearer(&token).await;
        res.assert_status_ok();
    }

    // -- admin-scope gating (the security fix this module exists to prove:
    // mutating endpoints, especially the quarantine-release path, must not
    // be reachable by a merely-authenticated, tenant-matched caller) -----

    #[tokio::test]
    async fn list_artifacts_is_forbidden_without_read_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        seed_artifact(&pool, tenant, "library/nginx", "clean").await;

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        // A validly signed, tenant-matched token that simply carries no
        // depgate scope at all (e.g. a token scoped for a different
        // service).
        let token = skauswatch_testkit::jwt::mint_claims_token(
            skauswatch_testkit::jwt::signing_key(),
            "user-1",
            &tenant.to_string(),
            "other-service:read",
            &[],
        );
        let server = test_server(state);
        let res = server
            .get("/api/v1/depgate/artifacts")
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn read_scope_token_can_read_but_cannot_mutate() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        seed_artifact(&pool, tenant, "library/nginx", "clean").await;
        let quarantine_id = seed_quarantine(&pool, tenant, "badbad", "library/malicious").await;

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = read_only_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);

        let read_res = server
            .get("/api/v1/depgate/artifacts")
            .authorization_bearer(&token)
            .await;
        read_res.assert_status_ok();

        let mutate_res = server
            .patch(&format!("/api/v1/depgate/quarantine/{quarantine_id}"))
            .authorization_bearer(&token)
            .json(&serde_json::json!({"disposition": "confirmed"}))
            .await;
        mutate_res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn quarantine_release_is_forbidden_without_admin_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let quarantine_id = seed_quarantine(&pool, tenant, "badbad", "library/malicious").await;

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = read_only_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);
        // The exact exploit this fix closes: a non-admin, tenant-matched
        // caller attempting to re-admit a quarantined (malware-flagged)
        // artifact.
        let res = server
            .patch(&format!("/api/v1/depgate/quarantine/{quarantine_id}"))
            .authorization_bearer(&token)
            .json(&serde_json::json!({"disposition": "released"}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn quarantine_confirm_succeeds_with_admin_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let quarantine_id = seed_quarantine(&pool, tenant, "badbad", "library/malicious").await;

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = admin_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);
        let res = server
            .patch(&format!("/api/v1/depgate/quarantine/{quarantine_id}"))
            .authorization_bearer(&token)
            .json(&serde_json::json!({"disposition": "confirmed"}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["disposition"], "confirmed");
    }

    #[tokio::test]
    async fn quarantine_release_succeeds_with_admin_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let quarantine_id = seed_quarantine(&pool, tenant, "badbad", "library/malicious").await;

        // The `released` disposition moves the object from the quarantine
        // prefix to the cache prefix and re-tags it clean — the one admin
        // route code path that talks to S3 (see `crate::state::AppStateInner
        // ::for_tests_with_s3`'s doc comment).
        let s3_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/depgate-test/quarantine/badbad"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(b"malware-bytes".to_vec()),
            )
            .mount(&s3_server)
            .await;
        Mock::given(method("PUT"))
            .and(path("/depgate-test/sha256/badbad"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s3_server)
            .await;

        let state =
            AppStateInner::for_tests_with_s3(pool, dev_license(), mock_s3_client(&s3_server.uri()));
        let token = admin_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);
        let res = server
            .patch(&format!("/api/v1/depgate/quarantine/{quarantine_id}"))
            .authorization_bearer(&token)
            .json(&serde_json::json!({"disposition": "released"}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["disposition"], "released");
    }

    #[tokio::test]
    async fn create_policy_rule_is_forbidden_without_admin_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = read_only_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);
        let res = server
            .post("/api/v1/depgate/policy-rules")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"action": "block"}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_policy_rule_succeeds_with_admin_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = admin_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);
        let res = server
            .post("/api/v1/depgate/policy-rules")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"action": "block"}))
            .await;
        res.assert_status_ok();
    }

    #[tokio::test]
    async fn update_policy_rule_is_forbidden_without_admin_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let rule = db::insert_policy_rule(
            &pool,
            tenant,
            &db::PolicyRuleInput {
                priority: 100,
                ecosystem: None,
                name_glob: None,
                version_glob: None,
                verdict: None,
                risk_check: None,
                min_severity: None,
                provenance: None,
                action: "block",
                description: None,
                enabled: true,
                created_by: None,
            },
        )
        .await
        .expect("seed policy rule");

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = read_only_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);
        let res = server
            .put(&format!("/api/v1/depgate/policy-rules/{}", rule.id))
            .authorization_bearer(&token)
            .json(&serde_json::json!({"action": "allow"}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn update_policy_rule_succeeds_with_admin_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let rule = db::insert_policy_rule(
            &pool,
            tenant,
            &db::PolicyRuleInput {
                priority: 100,
                ecosystem: None,
                name_glob: None,
                version_glob: None,
                verdict: None,
                risk_check: None,
                min_severity: None,
                provenance: None,
                action: "block",
                description: None,
                enabled: true,
                created_by: None,
            },
        )
        .await
        .expect("seed policy rule");

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = admin_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);
        let res = server
            .put(&format!("/api/v1/depgate/policy-rules/{}", rule.id))
            .authorization_bearer(&token)
            .json(&serde_json::json!({"action": "allow"}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["action"], "allow");
    }

    #[tokio::test]
    async fn delete_policy_rule_is_forbidden_without_admin_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let rule = db::insert_policy_rule(
            &pool,
            tenant,
            &db::PolicyRuleInput {
                priority: 100,
                ecosystem: None,
                name_glob: None,
                version_glob: None,
                verdict: None,
                risk_check: None,
                min_severity: None,
                provenance: None,
                action: "block",
                description: None,
                enabled: true,
                created_by: None,
            },
        )
        .await
        .expect("seed policy rule");

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = read_only_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);
        let res = server
            .delete(&format!("/api/v1/depgate/policy-rules/{}", rule.id))
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_policy_rule_succeeds_with_admin_scope() {
        let pool = test_pool().await;
        let tenant = Uuid::new_v4();
        let rule = db::insert_policy_rule(
            &pool,
            tenant,
            &db::PolicyRuleInput {
                priority: 100,
                ecosystem: None,
                name_glob: None,
                version_glob: None,
                verdict: None,
                risk_check: None,
                min_severity: None,
                provenance: None,
                action: "block",
                description: None,
                enabled: true,
                created_by: None,
            },
        )
        .await
        .expect("seed policy rule");

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let token = admin_token(skauswatch_testkit::jwt::signing_key(), tenant);
        let server = test_server(state);
        let res = server
            .delete(&format!("/api/v1/depgate/policy-rules/{}", rule.id))
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::NO_CONTENT);
    }

    // -- `rate_limited_router` wiring (`crate::rate_limit`) ------------------
    // Burst/429 behavior itself is covered in `crate::rate_limit`'s own
    // tests, in isolation from DB/auth setup; this proves the two
    // `GovernorLayer`s are actually wired into the real router assembly
    // (not just the standalone helper) without breaking the existing
    // auth/tenant middleware chain. A forwarded-for header is required
    // here — `SmartIpKeyExtractor` has no peer IP to fall back to under
    // `axum-test`'s mock transport (see module docs).

    #[tokio::test]
    async fn rate_limited_router_still_enforces_auth_on_the_admin_surface() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let server = axum_test::TestServer::new(rate_limited_router(state));
        let res = server
            .get("/api/v1/depgate/artifacts")
            .add_header("x-forwarded-for", "203.0.113.30")
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rate_limited_router_still_enforces_auth_on_the_proxy_surface() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let server = axum_test::TestServer::new(rate_limited_router(state));
        let res = server
            .get("/v2/")
            .add_header("x-forwarded-for", "203.0.113.31")
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }
}
