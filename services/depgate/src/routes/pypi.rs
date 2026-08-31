//! The PyPI pull-through surface (P2, `docs/v2-port/v2.1-depgate.md`
//! §1/§4). Implements the read-only subset `pip`/`uv` need:
//!
//! - `GET /pypi/simple/{project}/` — PEP 503 simple index, with every
//!   package-file link rewritten to point back at DepGate
//!   (`crate::pypi::rewrite_simple_index`), preserving the `#sha256=<hex>`
//!   fragment clients verify against.
//! - `GET /pypi/pypi/{project}/json` — the legacy JSON API, same link
//!   rewrite (`crate::pypi::rewrite_json_api`).
//! - `GET /pypi/packages/{*rest}` — the actual wheel/sdist bytes, through
//!   the shared `ScanPipeline` (`crate::scanpipe::ScanPipeline::
//!   resolve_named`), same scan/cache/quarantine/index path the OCI/npm
//!   proxies use.
//!
//! Same auth posture as `crate::routes::oci`/`crate::routes::npm`: every
//! route sits behind `tenant_middleware` — a real `pip install` needs
//! `--index-url https://<token>@host/pypi/simple/` or an equivalent
//! bearer-capable client config.

use axum::extract::{Path, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use skauswatch_auth::TenantContext;

use crate::error::{ApiError, tenant_uuid};
use crate::scanpipe::PipelineError;
use crate::state::AppState;

/// Router for the `/pypi/*` surface.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/pypi/simple/{project}/", get(simple_index))
        .route("/pypi/pypi/{project}/json", get(json_api))
        .route("/pypi/packages/{*rest}", get(package_file))
}

async fn simple_index(
    State(state): State<AppState>,
    _tenant: TenantContext,
    Path(project): Path<String>,
) -> Result<Response, ApiError> {
    // Regression guard (finding: air-gap offline-mode egress bypass,
    // metadata routes) — this metadata call has no cache to consult first,
    // so gate it unconditionally.
    crate::scanpipe::offline_guard(state.cfg.offline_mode, "pypi", &project, "simple-index")?;
    let html = state
        .pypi
        .fetch_simple_index(&project, state.cfg.max_artifact_bytes)
        .await?;
    let rewritten = crate::pypi::rewrite_simple_index(
        &html,
        state.pypi.index_url(),
        &state.cfg.public_base_url,
    );
    Ok((
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        rewritten,
    )
        .into_response())
}

async fn json_api(
    State(state): State<AppState>,
    _tenant: TenantContext,
    Path(project): Path<String>,
) -> Result<Response, ApiError> {
    // Regression guard (finding: air-gap offline-mode egress bypass,
    // metadata routes) — this metadata call has no cache to consult first,
    // so gate it unconditionally.
    crate::scanpipe::offline_guard(state.cfg.offline_mode, "pypi", &project, "json-api")?;
    let doc = state
        .pypi
        .fetch_json_api(&project, state.cfg.max_artifact_bytes)
        .await?;
    let rewritten =
        crate::pypi::rewrite_json_api(doc, state.pypi.index_url(), &state.cfg.public_base_url);
    Ok(Json(rewritten).into_response())
}

/// `rest` is the upstream-relative path after `/pypi/packages/` (e.g.
/// `aa/bb/requests-2.34.2.tar.gz`) — the same hash-sharded layout
/// `files.pythonhosted.org` itself uses, reconstructed by prefixing the
/// configured files-host base URL back on. There is no project name in
/// this path shape (unlike npm's tarball path), so `rest` doubles as the
/// `(ecosystem, name, reference)` index's `name` (globally unique per real
/// file already) with the trailing filename as `reference` — see
/// `src/pypi.rs` module docs for the same design note applied to seeding.
async fn package_file(
    State(state): State<AppState>,
    tenant: TenantContext,
    Path(rest): Path<String>,
) -> Result<Response, ApiError> {
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let filename = rest
        .rsplit('/')
        .next()
        .ok_or_else(|| ApiError::BadRequest("empty package file path".to_owned()))?
        .to_owned();
    let pipeline = state.pipeline();
    let upstream_path = format!("/packages/{rest}");
    let max_bytes = state.cfg.max_artifact_bytes;
    let pypi = &state.pypi;
    let upstream_label = pypi.index_url().to_owned();
    let artifact = pipeline
        .resolve_named(
            "pypi",
            &rest,
            &filename,
            &upstream_label,
            tenant_id,
            move || async move {
                pypi.fetch_file(&upstream_path, max_bytes)
                    .await
                    .map(|f| (f.bytes, f.content_type))
                    .map_err(PipelineError::from)
            },
        )
        .await?;
    Ok((
        [(header::CONTENT_TYPE, artifact.content_type)],
        artifact.bytes,
    )
        .into_response())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use axum::http::StatusCode;
    use sqlx::PgPool;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::config::PypiUpstreamConfig;
    use crate::pypi::PypiUpstreamClient;
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
    async fn simple_index_rewrites_links_and_preserves_sha256_fragment() {
        let upstream = MockServer::start().await;
        let html = format!(
            r#"<a href="{}/packages/aa/bb/requests-2.34.2.tar.gz#sha256=deadbeef">requests-2.34.2.tar.gz</a>"#,
            upstream.uri()
        );
        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_raw(html.into_bytes(), "text/html"),
            )
            .mount(&upstream)
            .await;

        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_pypi(
            pool,
            dev_license(),
            PypiUpstreamClient::new(
                reqwest::Client::new(),
                PypiUpstreamConfig {
                    index_url: upstream.uri(),
                    files_url: upstream.uri(),
                    username: None,
                    password: None,
                },
            ),
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
            .get("/pypi/simple/requests/")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body = res.text();
        assert!(body.contains(
            r#"href="https://depgate.internal/pypi/packages/aa/bb/requests-2.34.2.tar.gz#sha256=deadbeef""#
        ));
    }

    #[tokio::test]
    async fn package_file_endpoint_requires_a_bearer_token() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let server = test_server(state);
        let res = server
            .get("/pypi/packages/aa/bb/requests-2.34.2.tar.gz")
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn json_api_endpoint_rewrites_release_urls_and_preserves_digests() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/pypi/requests/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "releases": {
                    "2.34.2": [{
                        "url": format!("{}/packages/aa/bb/requests-2.34.2.tar.gz", upstream.uri()),
                        "digests": {"sha256": "deadbeef"},
                    }]
                }
            })))
            .mount(&upstream)
            .await;

        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_pypi(
            pool,
            dev_license(),
            PypiUpstreamClient::new(
                reqwest::Client::new(),
                PypiUpstreamConfig {
                    index_url: upstream.uri(),
                    files_url: upstream.uri(),
                    username: None,
                    password: None,
                },
            ),
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
            .get("/pypi/pypi/requests/json")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(
            body["releases"]["2.34.2"][0]["url"],
            "https://depgate.internal/pypi/packages/aa/bb/requests-2.34.2.tar.gz"
        );
        assert_eq!(
            body["releases"]["2.34.2"][0]["digests"]["sha256"],
            "deadbeef"
        );
    }

    #[tokio::test]
    async fn package_file_endpoint_fetches_scans_caches_and_serves_through_the_full_router() {
        let body = b"fake wheel bytes".to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;

        let files = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/packages/aa/bb/requests-2.34.2.tar.gz"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(body.clone()),
            )
            .mount(&files)
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
        let mut state = AppStateInner::for_tests_with_pypi(
            pool,
            dev_license(),
            PypiUpstreamClient::new(
                reqwest::Client::new(),
                PypiUpstreamConfig {
                    index_url: files.uri(),
                    files_url: files.uri(),
                    username: None,
                    password: None,
                },
            ),
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
            .get("/pypi/packages/aa/bb/requests-2.34.2.tar.gz")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        assert_eq!(res.as_bytes().as_ref(), body.as_slice());
    }

    /// Builds an offline-mode-enabled state pointed at `upstream` — shared
    /// by both PyPI metadata regression tests below.
    fn offline_pypi_state(pool: PgPool, upstream_uri: &str) -> crate::state::AppState {
        let mut state = AppStateInner::for_tests_with_pypi(
            pool,
            dev_license(),
            PypiUpstreamClient::new(
                reqwest::Client::new(),
                PypiUpstreamConfig {
                    index_url: upstream_uri.to_owned(),
                    files_url: upstream_uri.to_owned(),
                    username: None,
                    password: None,
                },
            ),
            "https://depgate.internal",
        );
        std::sync::Arc::get_mut(&mut state)
            .expect("sole owner in test")
            .cfg
            .offline_mode = true;
        state
    }

    // Regression: air-gap offline-mode egress bypass (metadata routes).
    // Neither PyPI metadata endpoint has a cache to consult, unlike the
    // package-file path — before the fix both reached upstream
    // unconditionally regardless of `offline_mode`.
    #[tokio::test]
    async fn simple_index_endpoint_refuses_upstream_egress_in_offline_mode() {
        // Deliberately no mock mounted — any real request would 404 from
        // wiremock's default "no matching stub" behavior, which we
        // additionally confirm was never even sent.
        let upstream = MockServer::start().await;
        let pool = test_pool().await;
        let state = offline_pypi_state(pool, &upstream.uri());

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
            .get("/pypi/simple/requests/")
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::NOT_FOUND);

        let received = upstream
            .received_requests()
            .await
            .expect("wiremock request recording is enabled by default");
        assert!(
            received.is_empty(),
            "offline mode must never contact the upstream index, saw: {received:?}"
        );
    }

    #[tokio::test]
    async fn json_api_endpoint_refuses_upstream_egress_in_offline_mode() {
        let upstream = MockServer::start().await;
        let pool = test_pool().await;
        let state = offline_pypi_state(pool, &upstream.uri());

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
            .get("/pypi/pypi/requests/json")
            .authorization_bearer(&token)
            .await;
        res.assert_status(StatusCode::NOT_FOUND);

        let received = upstream
            .received_requests()
            .await
            .expect("wiremock request recording is enabled by default");
        assert!(
            received.is_empty(),
            "offline mode must never contact the upstream index, saw: {received:?}"
        );
    }
}
