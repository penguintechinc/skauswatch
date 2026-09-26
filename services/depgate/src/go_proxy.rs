//! Go module proxy (`GOPROXY` protocol) client (P4,
//! `docs/v2-port/v2.1-depgate.md` §4/§9). Like `src/npm.rs`/`src/pypi.rs`,
//! no rewriting is needed at all: every GOPROXY endpoint's response either
//! carries no URLs (`list`, `.info`, `.mod`, `.zip` are all self-contained)
//! or is binary module content, so DepGate proxies `list`/`.info` verbatim
//! and scans `.mod`/`.zip` through the shared `ScanPipeline` — see
//! `src/routes/go.rs`.

use bytes::Bytes;

use crate::config::GoProxyUpstreamConfig;
use crate::fetch::{FetchError, Fetched, get_capped};

/// Talks to exactly one configured upstream GOPROXY-protocol server.
#[derive(Debug, Clone)]
pub struct GoProxyUpstreamClient {
    http: reqwest::Client,
    cfg: GoProxyUpstreamConfig,
}

impl GoProxyUpstreamClient {
    /// Builds a client for `cfg`, reusing the caller's `reqwest::Client`.
    #[must_use]
    pub fn new(http: reqwest::Client, cfg: GoProxyUpstreamConfig) -> Self {
        Self { http, cfg }
    }

    /// The configured upstream base URL — recorded on
    /// `depgate_artifacts.upstream` for audit purposes.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.cfg.base_url
    }

    /// `GET {module}/@v/list` — newline-separated known versions, proxied
    /// verbatim (metadata only, never scanned/cached).
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_list(&self, module: &str, max_bytes: u64) -> Result<Bytes, FetchError> {
        let url = format!("{}/{module}/@v/list", self.cfg.base_url);
        Ok(get_capped(self.http.get(url), max_bytes).await?.bytes)
    }

    /// `GET {module}/@v/{version}.info` — `{Version, Time}` JSON, proxied
    /// verbatim.
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_info(
        &self,
        module: &str,
        version: &str,
        max_bytes: u64,
    ) -> Result<Bytes, FetchError> {
        let url = format!("{}/{module}/@v/{version}.info", self.cfg.base_url);
        Ok(get_capped(self.http.get(url), max_bytes).await?.bytes)
    }

    /// `GET {module}/@v/{version}.mod` — that version's `go.mod` file.
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_mod(
        &self,
        module: &str,
        version: &str,
        max_bytes: u64,
    ) -> Result<Fetched, FetchError> {
        let url = format!("{}/{module}/@v/{version}.mod", self.cfg.base_url);
        get_capped(self.http.get(url), max_bytes).await
    }

    /// `GET {module}/@v/{version}.zip` — that version's full source zip.
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_zip(
        &self,
        module: &str,
        version: &str,
        max_bytes: u64,
    ) -> Result<Fetched, FetchError> {
        let url = format!("{}/{module}/@v/{version}.zip", self.cfg.base_url);
        get_capped(self.http.get(url), max_bytes).await
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn cfg(base_url: &str) -> GoProxyUpstreamConfig {
        GoProxyUpstreamConfig {
            base_url: base_url.to_owned(),
        }
    }

    #[tokio::test]
    async fn fetch_list_proxies_the_body_verbatim() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/github.com/pkg/errors/@v/list"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("v0.9.1\nv0.9.0\n", "text/plain"))
            .mount(&server)
            .await;

        let client = GoProxyUpstreamClient::new(reqwest::Client::new(), cfg(&server.uri()));
        let body = client
            .fetch_list("github.com/pkg/errors", 1024)
            .await
            .expect("fetch");
        assert_eq!(body.as_ref(), b"v0.9.1\nv0.9.0\n");
    }

    #[tokio::test]
    async fn fetch_info_proxies_the_body_verbatim() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/github.com/pkg/errors/@v/v0.9.1.info"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "Version": "v0.9.1", "Time": "2020-01-01T00:00:00Z"
            })))
            .mount(&server)
            .await;

        let client = GoProxyUpstreamClient::new(reqwest::Client::new(), cfg(&server.uri()));
        let body = client
            .fetch_info("github.com/pkg/errors", "v0.9.1", 1024)
            .await
            .expect("fetch");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("parse");
        assert_eq!(json["Version"], "v0.9.1");
    }

    #[tokio::test]
    async fn fetch_mod_downloads_the_go_mod_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/github.com/pkg/errors/@v/v0.9.1.mod"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_bytes(b"module github.com/pkg/errors\n".to_vec()),
            )
            .mount(&server)
            .await;

        let client = GoProxyUpstreamClient::new(reqwest::Client::new(), cfg(&server.uri()));
        let fetched = client
            .fetch_mod("github.com/pkg/errors", "v0.9.1", 1024)
            .await
            .expect("fetch");
        assert_eq!(fetched.bytes.as_ref(), b"module github.com/pkg/errors\n");
    }

    #[tokio::test]
    async fn fetch_zip_maps_404_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/github.com/ghost/pkg/@v/v9.9.9.zip"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = GoProxyUpstreamClient::new(reqwest::Client::new(), cfg(&server.uri()));
        let err = client
            .fetch_zip("github.com/ghost/pkg", "v9.9.9", 1024)
            .await
            .expect_err("expected not found");
        assert!(matches!(err, FetchError::NotFound));
    }
}
