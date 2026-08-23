//! The npm registry pull-through surface (P2, `docs/v2-port/v2.1-depgate.md`
//! §1/§4). Implements the read-only subset a real `npm install` needs:
//!
//! - `GET /npm/{package}` / `GET /npm/@{scope}/{package}` — the packument,
//!   with every version's `dist.tarball` rewritten to point back at DepGate
//!   (`crate::npm::rewrite_packument`) so npm never fetches tarball bytes
//!   from the real upstream unscanned.
//! - `GET /npm/{package}/-/{filename}.tgz` (+ scoped form) — the tarball,
//!   through the shared `ScanPipeline` (`crate::scanpipe::ScanPipeline::
//!   resolve_named`), same scan/cache/quarantine/index path the OCI proxy
//!   uses.
//!
//! Same auth posture as `crate::routes::oci`: every route sits behind
//! `tenant_middleware`, so a real `npm install` needs a client capable of
//! presenting a SkausWatch-issued bearer JWT (e.g. `//host/:_authToken=`
//! in `.npmrc`) as its registry credential.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use skauswatch_auth::TenantContext;

use crate::error::{ApiError, tenant_uuid};
use crate::npm_path::{self, NpmRequest};
use crate::scanpipe::PipelineError;
use crate::state::AppState;

/// Router for the `/npm/*` surface.
pub fn router() -> Router<AppState> {
    Router::new().route("/npm/{*rest}", get(dispatch))
}

async fn dispatch(
    State(state): State<AppState>,
    tenant: TenantContext,
    Path(rest): Path<String>,
) -> Result<Response, ApiError> {
    let parsed = npm_path::parse(&rest)
        .ok_or_else(|| ApiError::NotFound("unsupported or malformed npm path".to_owned()))?;

    match parsed {
        NpmRequest::Packument { name } => {
            let doc = state
                .npm
                .fetch_packument(name, state.cfg.max_artifact_bytes)
                .await?;
            let rewritten = crate::npm::rewrite_packument(doc, &state.cfg.public_base_url);
            Ok(Json(rewritten).into_response())
        }
        NpmRequest::Tarball { name, filename } => {
            let tenant_id = tenant_uuid(&tenant.tenant)?;
            let pipeline = state.pipeline();
            let upstream_path = format!("/{name}/-/{filename}");
            let max_bytes = state.cfg.max_artifact_bytes;
            let npm = &state.npm;
            let upstream_label = npm.base_url().to_owned();
            let artifact = pipeline
                .resolve_named(
                    "npm",
                    name,
                    filename,
                    &upstream_label,
                    tenant_id,
                    move || async move {
                        npm.fetch_tarball(&upstream_path, max_bytes)
                            .await
                            .map(|f| (f.bytes, f.content_type))
                            .map_err(PipelineError::from)
                    },
                )
                .await?;
            Ok((
                [(axum::http::header::CONTENT_TYPE, artifact.content_type)],
                artifact.bytes,
            )
                .into_response())
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use axum::http::StatusCode;
    use sqlx::PgPool;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::config::NpmUpstreamConfig;
    use crate::npm::NpmUpstreamClient;
    use crate::state::AppStateInner;

    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    fn test_server(state: crate::state::AppState) -> axum_test::TestServer {
        axum_test::TestServer::new(crate::routes::router(state))
    }

    #[tokio::test]
    async fn packument_endpoint_rewrites_tarball_url_and_preserves_integrity() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "left-pad",
                "versions": {
                    "1.3.0": {
                        "dist": {
                            "shasum": "abc123",
                            "integrity": "sha512-deadbeef",
                            "tarball": format!("{}/left-pad/-/left-pad-1.3.0.tgz", upstream.uri()),
                        }
                    }
                }
            })))
            .mount(&upstream)
            .await;

        let pool = test_pool().await;
        let npm_client = NpmUpstreamClient::new(
            reqwest::Client::new(),
            NpmUpstreamConfig {
                registry_url: upstream.uri(),
                token: None,
            },
        );
        let state = AppStateInner::for_tests_with_npm(
            pool,
            dev_license(),
            npm_client,
            "https://depgate.internal",
        );

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
            .get("/npm/left-pad")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(
            body["versions"]["1.3.0"]["dist"]["tarball"],
            "https://depgate.internal/npm/left-pad/-/left-pad-1.3.0.tgz"
        );
        assert_eq!(body["versions"]["1.3.0"]["dist"]["shasum"], "abc123");
        assert_eq!(
            body["versions"]["1.3.0"]["dist"]["integrity"],
            "sha512-deadbeef"
        );
    }

    #[tokio::test]
    async fn tarball_endpoint_requires_a_bearer_token() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let server = test_server(state);
        let res = server.get("/npm/left-pad/-/left-pad-1.3.0.tgz").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tarball_endpoint_fetches_scans_caches_and_serves_through_the_full_router() {
        let body = b"fake tarball bytes".to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;

        let registry = MockServer::start().await;
        wiremock::Mock::given(method("GET"))
            .and(path("/left-pad/-/left-pad-1.3.0.tgz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(body.clone()),
            )
            .mount(&registry)
            .await;

        let s3 = MockServer::start().await;
        let s3_error_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>NoSuchKey</Code><Message>not found</Message>\
             <RequestId>req-1</RequestId><HostId>host-1</HostId></Error>";
        wiremock::Mock::given(method("GET"))
            .and(path(format!("/bkt/sha256/{hex}")))
            .respond_with(ResponseTemplate::new(404).set_body_raw(s3_error_xml, "application/xml"))
            .mount(&s3)
            .await;
        wiremock::Mock::given(method("PUT"))
            .and(path(format!("/bkt/sha256/{hex}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s3)
            .await;

        let pool = test_pool().await;
        let npm_client = NpmUpstreamClient::new(
            reqwest::Client::new(),
            NpmUpstreamConfig {
                registry_url: registry.uri(),
                token: None,
            },
        );
        let mut state = AppStateInner::for_tests_with_npm(
            pool,
            dev_license(),
            npm_client,
            "https://depgate.internal",
        );
        {
            let cfg = aws_sdk_s3::config::Builder::new()
                .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
                .region(aws_sdk_s3::config::Region::new("us-east-1"))
                .endpoint_url(s3.uri())
                .force_path_style(true)
                .credentials_provider(aws_sdk_s3::config::Credentials::new(
                    "test",
                    "test",
                    None,
                    None,
                    "depgate-test",
                ))
                .build();
            let inner = std::sync::Arc::get_mut(&mut state).expect("sole owner in test");
            inner.s3 = aws_sdk_s3::Client::from_conf(cfg);
            inner.cfg.cache_bucket = "bkt".to_owned();
        }

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
            .get("/npm/left-pad/-/left-pad-1.3.0.tgz")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        assert_eq!(res.as_bytes().as_ref(), body.as_slice());
    }
}
