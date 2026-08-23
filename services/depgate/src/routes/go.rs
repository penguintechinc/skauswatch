//! The Go module proxy (`GOPROXY` protocol) pull-through surface (P4,
//! `docs/v2-port/v2.1-depgate.md` §4/§9). Implements the four endpoints
//! `GOPROXY=<url>` needs:
//!
//! - `GET /go/{module}/@v/list` / `.../{version}.info` — metadata, proxied
//!   verbatim (no scan/cache — no binary module content).
//! - `GET /go/{module}/@v/{version}.mod` / `.../{version}.zip` — through the
//!   shared `ScanPipeline` (`crate::scanpipe::ScanPipeline::resolve_named`),
//!   same scan/cache/quarantine/index path every other ecosystem front end
//!   uses.
//!
//! Same auth posture as `crate::routes::oci`/`npm`/`pypi`/`crates_io`: every
//! route sits behind `tenant_middleware`.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use skauswatch_auth::TenantContext;

use crate::error::{ApiError, tenant_uuid};
use crate::go_path::{self, GoRequest};
use crate::scanpipe::PipelineError;
use crate::state::AppState;

/// Router for the `/go/*` surface.
pub fn router() -> Router<AppState> {
    Router::new().route("/go/{*rest}", get(dispatch))
}

/// Recovers a human-readable module name for `depgate_artifacts`/policy
/// purposes (`crate::go_path::unescape_module_path`), falling back to the
/// escaped form on any malformed escaping rather than refusing the request
/// outright — this is only ever a display/audit label, never used to
/// construct the upstream URL (which always uses the caller's original
/// escaped `module` string).
fn display_name(module: &str) -> String {
    go_path::unescape_module_path(module).unwrap_or_else(|| module.to_owned())
}

async fn dispatch(
    State(state): State<AppState>,
    tenant: TenantContext,
    Path(rest): Path<String>,
) -> Result<Response, ApiError> {
    let parsed = go_path::parse(&rest)
        .ok_or_else(|| ApiError::NotFound("unsupported or malformed go proxy path".to_owned()))?;
    let max_bytes = state.cfg.max_artifact_bytes;
    let go = &state.go_proxy;

    match parsed {
        GoRequest::List { module } => {
            let body = go.fetch_list(module, max_bytes).await?;
            Ok(([(axum::http::header::CONTENT_TYPE, "text/plain")], body).into_response())
        }
        GoRequest::Info { module, version } => {
            let body = go.fetch_info(module, version, max_bytes).await?;
            Ok(
                Json(serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default())
                    .into_response(),
            )
        }
        GoRequest::Mod { module, version } => {
            let tenant_id = tenant_uuid(&tenant.tenant)?;
            let pipeline = state.pipeline();
            let upstream_label = go.base_url().to_owned();
            let name = display_name(module);
            let reference = format!("{version}.mod");
            let module_owned = module.to_owned();
            let version_owned = version.to_owned();
            let artifact = pipeline
                .resolve_named(
                    "go",
                    &name,
                    &reference,
                    &upstream_label,
                    tenant_id,
                    move || async move {
                        go.fetch_mod(&module_owned, &version_owned, max_bytes)
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
        GoRequest::Zip { module, version } => {
            let tenant_id = tenant_uuid(&tenant.tenant)?;
            let pipeline = state.pipeline();
            let upstream_label = go.base_url().to_owned();
            let name = display_name(module);
            let reference = format!("{version}.zip");
            let module_owned = module.to_owned();
            let version_owned = version.to_owned();
            let artifact = pipeline
                .resolve_named(
                    "go",
                    &name,
                    &reference,
                    &upstream_label,
                    tenant_id,
                    move || async move {
                        go.fetch_zip(&module_owned, &version_owned, max_bytes)
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

    use crate::config::GoProxyUpstreamConfig;
    use crate::go_proxy::GoProxyUpstreamClient;
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

    fn token(state: &AppStateInner, tenant: Uuid) -> String {
        skauswatch_testkit::jwt::mint_claims_token(
            &state.jwt_secret,
            "user-1",
            &tenant.to_string(),
            "*:read",
            &["admin"],
        )
    }

    #[tokio::test]
    async fn list_endpoint_requires_a_bearer_token() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let server = test_server(state);
        let res = server.get("/go/github.com/pkg/errors/@v/list").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_endpoint_proxies_upstream_body_verbatim() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/github.com/pkg/errors/@v/list"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("v0.9.1\n", "text/plain"))
            .mount(&upstream)
            .await;

        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_go_proxy(
            pool,
            dev_license(),
            GoProxyUpstreamClient::new(
                reqwest::Client::new(),
                GoProxyUpstreamConfig {
                    base_url: upstream.uri(),
                },
            ),
        );
        let tenant = Uuid::new_v4();
        let tok = token(&state, tenant);
        let server = test_server(state);
        let res = server
            .get("/go/github.com/pkg/errors/@v/list")
            .authorization_bearer(&tok)
            .await;
        res.assert_status_ok();
        assert_eq!(res.as_bytes().as_ref(), b"v0.9.1\n");
    }

    #[tokio::test]
    async fn zip_endpoint_fetches_scans_caches_and_serves_through_the_full_router() {
        let body = b"fake module zip bytes".to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/github.com/pkg/errors/@v/v0.9.1.zip"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/zip")
                    .set_body_bytes(body.clone()),
            )
            .mount(&upstream)
            .await;

        let s3 = MockServer::start().await;
        let s3_error_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Error><Code>NoSuchKey</Code><Message>not found</Message>\
             <RequestId>req-1</RequestId><HostId>host-1</HostId></Error>";
        Mock::given(method("GET"))
            .and(path(format!("/bkt/sha256/{hex}")))
            .respond_with(ResponseTemplate::new(404).set_body_raw(s3_error_xml, "application/xml"))
            .mount(&s3)
            .await;
        Mock::given(method("PUT"))
            .and(path(format!("/bkt/sha256/{hex}")))
            .respond_with(ResponseTemplate::new(200))
            .mount(&s3)
            .await;

        let pool = test_pool().await;
        let mut state = AppStateInner::for_tests_with_go_proxy(
            pool,
            dev_license(),
            GoProxyUpstreamClient::new(
                reqwest::Client::new(),
                GoProxyUpstreamConfig {
                    base_url: upstream.uri(),
                },
            ),
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
        let tok = token(&state, tenant);
        let db = state.db.clone();
        let server = test_server(state);
        let res = server
            .get("/go/github.com/pkg/errors/@v/v0.9.1.zip")
            .authorization_bearer(&tok)
            .await;
        res.assert_status_ok();
        assert_eq!(res.as_bytes().as_ref(), body.as_slice());

        let row = crate::db::find_by_reference(&db, "go", "github.com/pkg/errors", "v0.9.1.zip")
            .await
            .expect("query")
            .expect("row indexed");
        assert_eq!(row.sha256, hex);
    }

    #[tokio::test]
    async fn dispatch_returns_not_found_for_a_malformed_path() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let tenant = Uuid::new_v4();
        let tok = token(&state, tenant);
        let server = test_server(state);
        let res = server
            .get("/go/github.com/pkg/errors")
            .authorization_bearer(&tok)
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
    }
}
