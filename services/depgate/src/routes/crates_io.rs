//! The crates.io pull-through surface (P4, `docs/v2-port/v2.1-depgate.md`
//! §4/§9):
//!
//! - `GET /crates/index/config.json` — DepGate's own sparse-index root
//!   document, `dl` pointing back at this deployment's own download route
//!   (`crate::crates_io::config_json`).
//! - `GET /crates/index/{*rest}` — the per-crate sparse-index NDJSON,
//!   proxied verbatim (no scan/cache — metadata only, and no URL rewriting
//!   is needed at all; see `crate::crates_io` module docs).
//! - `GET /crates/api/v1/crates/{name}/{version}/download` — the `.crate`
//!   file, through the shared `ScanPipeline`
//!   (`crate::scanpipe::ScanPipeline::resolve_named`), same scan/cache/
//!   quarantine/index path every other ecosystem front end uses.
//!
//! Same auth posture as `crate::routes::oci`/`npm`/`pypi`: every route sits
//! behind `tenant_middleware`.

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use skauswatch_auth::TenantContext;

use crate::error::{ApiError, tenant_uuid};
use crate::scanpipe::PipelineError;
use crate::state::AppState;

/// Router for the `/crates/*` surface.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/crates/index/config.json", get(index_config))
        .route("/crates/index/{*rest}", get(index_proxy))
        .route(
            "/crates/api/v1/crates/{name}/{version}/download",
            get(download),
        )
}

async fn index_config(State(state): State<AppState>, _tenant: TenantContext) -> Response {
    Json(crate::crates_io::config_json(&state.cfg.public_base_url)).into_response()
}

async fn index_proxy(
    State(state): State<AppState>,
    _tenant: TenantContext,
    Path(rest): Path<String>,
) -> Result<Response, ApiError> {
    // `rest` is the raw sparse-index sub-path (e.g. `se/rd/serde` or
    // `3/s/serde`) the `cargo` client itself computed and requested —
    // proxied straight through to the equivalent upstream path rather than
    // re-deriving it from a crate name, so this route works unmodified even
    // if crates.io's prefixing convention ever changes.
    //
    // Regression guard (finding: air-gap offline-mode egress bypass,
    // metadata routes) — this metadata call has no cache to consult first,
    // so gate it unconditionally.
    crate::scanpipe::offline_guard(state.cfg.offline_mode, "crates", &rest, "sparse-index")?;
    let fetched = state
        .cratesio
        .fetch_index_path(&rest, state.cfg.max_artifact_bytes)
        .await?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, fetched.content_type)],
        fetched.bytes,
    )
        .into_response())
}

async fn download(
    State(state): State<AppState>,
    tenant: TenantContext,
    Path((name, version)): Path<(String, String)>,
) -> Result<Response, ApiError> {
    let tenant_id = tenant_uuid(&tenant.tenant)?;
    let pipeline = state.pipeline();
    let max_bytes = state.cfg.max_artifact_bytes;
    let cratesio = &state.cratesio;
    let upstream_label = cratesio.index_url().to_owned();
    let filename = format!("{name}-{version}.crate");
    let name_for_fetch = name.clone();
    let version_for_fetch = version.clone();
    let artifact = pipeline
        .resolve_named(
            "crates",
            &name,
            &filename,
            &upstream_label,
            tenant_id,
            move || async move {
                cratesio
                    .fetch_crate_file(&name_for_fetch, &version_for_fetch, max_bytes)
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use axum::http::StatusCode;
    use sqlx::PgPool;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::config::CratesIoUpstreamConfig;
    use crate::crates_io::CratesIoUpstreamClient;
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

    fn token(_state: &AppStateInner, tenant: Uuid) -> String {
        skauswatch_testkit::jwt::mint_claims_token(
            skauswatch_testkit::jwt::signing_key(),
            "user-1",
            &tenant.to_string(),
            "*:read",
            &["admin"],
        )
    }

    #[tokio::test]
    async fn index_config_points_dl_back_at_this_deployment() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let tenant = Uuid::new_v4();
        let tok = token(&state, tenant);
        let server = test_server(state);
        let res = server
            .get("/crates/index/config.json")
            .authorization_bearer(&tok)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(
            body["dl"]
                .as_str()
                .expect("dl string")
                .contains("/crates/api/v1/crates/")
        );
    }

    #[tokio::test]
    async fn index_proxy_requires_a_bearer_token() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let server = test_server(state);
        let res = server.get("/crates/index/se/rd/serde").await;
        res.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn index_proxy_returns_the_upstream_body_verbatim() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/se/rd/serde"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw("{\"name\":\"serde\",\"vers\":\"1.0.0\"}\n", "text/plain"),
            )
            .mount(&upstream)
            .await;

        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_cratesio(
            pool,
            dev_license(),
            CratesIoUpstreamClient::new(
                reqwest::Client::new(),
                CratesIoUpstreamConfig {
                    index_url: upstream.uri(),
                    api_url: String::new(),
                },
            ),
        );
        let tenant = Uuid::new_v4();
        let tok = token(&state, tenant);
        let server = test_server(state);
        let res = server
            .get("/crates/index/se/rd/serde")
            .authorization_bearer(&tok)
            .await;
        res.assert_status_ok();
        assert_eq!(
            res.as_bytes().as_ref(),
            b"{\"name\":\"serde\",\"vers\":\"1.0.0\"}\n"
        );
    }

    #[tokio::test]
    async fn download_fetches_scans_caches_and_serves_through_the_full_router() {
        let body = b"fake crate bytes".to_vec();
        let hex = skauswatch_scan_core::compute_hashes(&body).sha256;

        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/serde/1.0.0/download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/x-tar")
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
        let mut state = AppStateInner::for_tests_with_cratesio(
            pool,
            dev_license(),
            CratesIoUpstreamClient::new(
                reqwest::Client::new(),
                CratesIoUpstreamConfig {
                    index_url: String::new(),
                    api_url: upstream.uri(),
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
        let server = test_server(state);
        let res = server
            .get("/crates/api/v1/crates/serde/1.0.0/download")
            .authorization_bearer(&tok)
            .await;
        res.assert_status_ok();
        assert_eq!(res.as_bytes().as_ref(), body.as_slice());
    }

    // Regression: air-gap offline-mode egress bypass (metadata routes).
    // The sparse-index proxy has no cache to consult, unlike the download
    // path — before the fix it reached upstream unconditionally regardless
    // of `offline_mode`.
    #[tokio::test]
    async fn index_proxy_refuses_upstream_egress_in_offline_mode() {
        // Deliberately no mock mounted — any real request would 404 from
        // wiremock's default "no matching stub" behavior, which we
        // additionally confirm was never even sent.
        let upstream = MockServer::start().await;

        let pool = test_pool().await;
        let mut state = AppStateInner::for_tests_with_cratesio(
            pool,
            dev_license(),
            CratesIoUpstreamClient::new(
                reqwest::Client::new(),
                CratesIoUpstreamConfig {
                    index_url: upstream.uri(),
                    api_url: String::new(),
                },
            ),
        );
        std::sync::Arc::get_mut(&mut state)
            .expect("sole owner in test")
            .cfg
            .offline_mode = true;

        let tenant = Uuid::new_v4();
        let tok = token(&state, tenant);
        let server = test_server(state);
        let res = server
            .get("/crates/index/se/rd/serde")
            .authorization_bearer(&tok)
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
