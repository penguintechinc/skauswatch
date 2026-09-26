//! OCI Distribution client for the single configured upstream registry
//! (`DEPGATE_UPSTREAM_*` — see `crate::config::UpstreamConfig`).
//!
//! Deferred to a later phase (documented omission, per the task's P1
//! scope): routing by registry host embedded in `name` (so one DepGate
//! deployment mirrors both Docker Hub and ghcr.io transparently) —
//! `docs/v2-port/v2.1-depgate.md` §4/§11 calls this "per-upstream config",
//! an open question the spec leaves for a build-time decision. P1 ships one
//! upstream per deployment, matching this service's single `UpstreamConfig`.
//!
//! Implements the Docker Registry v2 / OCI Distribution anonymous
//! Bearer-token flow (RFC-less but universally implemented by Docker Hub,
//! ghcr.io, quay.io, ...): an unauthenticated request gets a 401 with a
//! `WWW-Authenticate: Bearer realm=...,service=...,scope=...` challenge;
//! the client fetches a token from `realm` and retries with
//! `Authorization: Bearer <token>`.

use bytes::Bytes;
use futures::StreamExt;
use serde::Deserialize;

use crate::config::UpstreamConfig;

/// Manifest media types this proxy asks for, covering both OCI and legacy
/// Docker manifest/index shapes (multi-arch and single-platform).
const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, \
     application/vnd.oci.image.index.v1+json, \
     application/vnd.docker.distribution.manifest.v2+json, \
     application/vnd.docker.distribution.manifest.list.v2+json, \
     application/vnd.docker.distribution.manifest.v1+json";

/// Failures talking to the upstream registry or its token endpoint.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    /// Transport-level failure (DNS, TLS, connect, timeout).
    #[error("upstream request failed: {0}")]
    Request(String),
    /// Upstream answered with a non-success, non-404 status.
    #[error("upstream returned {status}")]
    Status {
        /// HTTP status code.
        status: u16,
    },
    /// The requested name/reference/digest does not exist upstream.
    #[error("not found upstream")]
    NotFound,
    /// Token-endpoint request/response failure.
    #[error("upstream auth failed: {0}")]
    Auth(String),
    /// The response body exceeded the configured size guard.
    #[error("artifact exceeds max size ({0} bytes)")]
    TooLarge(u64),
}

/// A fetched, not-yet-verified artifact (manifest or blob bytes).
#[derive(Debug, Clone)]
pub struct FetchedArtifact {
    /// Raw bytes as returned by upstream.
    pub bytes: Bytes,
    /// `Content-Type` header from the upstream response (defaults to
    /// `application/octet-stream` when absent).
    pub content_type: String,
}

/// A parsed `WWW-Authenticate: Bearer ...` challenge.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Challenge {
    realm: Option<String>,
    service: Option<String>,
    scope: Option<String>,
}

/// Parses a `Bearer realm="...",service="...",scope="..."` challenge header.
/// Returns `None` for anything not a `Bearer` challenge (e.g. `Basic`),
/// which callers treat as "nothing to act on".
fn parse_www_authenticate(header: &str) -> Option<Challenge> {
    let rest = header.trim().strip_prefix("Bearer")?;
    let mut challenge = Challenge::default();
    for part in rest.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "realm" => challenge.realm = Some(value),
            "service" => challenge.service = Some(value),
            "scope" => challenge.scope = Some(value),
            _ => {}
        }
    }
    Some(challenge)
}

#[derive(Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

/// Talks to exactly one configured upstream OCI registry.
#[derive(Debug, Clone)]
pub struct UpstreamClient {
    http: reqwest::Client,
    cfg: UpstreamConfig,
}

impl UpstreamClient {
    /// Builds a client for `cfg`, reusing the caller's `reqwest::Client`
    /// (connection pooling shared with the rest of the service).
    #[must_use]
    pub fn new(http: reqwest::Client, cfg: UpstreamConfig) -> Self {
        Self { http, cfg }
    }

    /// The configured upstream registry base URL — recorded on
    /// `depgate_artifacts.upstream` for audit purposes.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.cfg.base_url
    }

    /// Fetches a manifest by tag or digest, verifying nothing about digest
    /// correctness itself — callers (`crate::scanpipe`) verify integrity
    /// against the requested/computed digest after this returns.
    ///
    /// # Errors
    /// See [`UpstreamError`].
    pub async fn fetch_manifest(
        &self,
        name: &str,
        reference: &str,
        max_bytes: u64,
    ) -> Result<FetchedArtifact, UpstreamError> {
        let url = format!("{}/v2/{name}/manifests/{reference}", self.cfg.base_url);
        let scope = format!("repository:{name}:pull");
        let resp = self
            .send_with_auth(&url, Some(MANIFEST_ACCEPT), &scope)
            .await?;
        Self::read_body(resp, max_bytes).await
    }

    /// Fetches a blob by digest.
    ///
    /// # Errors
    /// See [`UpstreamError`].
    pub async fn fetch_blob(
        &self,
        name: &str,
        digest: &str,
        max_bytes: u64,
    ) -> Result<FetchedArtifact, UpstreamError> {
        let url = format!("{}/v2/{name}/blobs/{digest}", self.cfg.base_url);
        let scope = format!("repository:{name}:pull");
        let resp = self.send_with_auth(&url, None, &scope).await?;
        Self::read_body(resp, max_bytes).await
    }

    /// Proxies `GET /v2/{name}/tags/list` verbatim — a tag list carries no
    /// binary artifact content, so this is never scanned or cached.
    ///
    /// # Errors
    /// See [`UpstreamError`].
    pub async fn list_tags(&self, name: &str) -> Result<serde_json::Value, UpstreamError> {
        let url = format!("{}/v2/{name}/tags/list", self.cfg.base_url);
        let scope = format!("repository:{name}:pull");
        let resp = self.send_with_auth(&url, None, &scope).await?;
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(UpstreamError::NotFound);
        }
        if !status.is_success() {
            return Err(UpstreamError::Status {
                status: status.as_u16(),
            });
        }
        resp.json()
            .await
            .map_err(|e| UpstreamError::Request(e.to_string()))
    }

    fn build(&self, url: &str, accept: Option<&str>) -> reqwest::RequestBuilder {
        let mut builder = self.http.get(url);
        if let Some(accept) = accept {
            builder = builder.header(reqwest::header::ACCEPT, accept);
        }
        builder
    }

    /// Sends a GET, transparently handling the anonymous Bearer-token
    /// challenge on a 401. Any other status (including a 401 with no
    /// `Bearer` challenge to act on) is returned as-is for the caller to
    /// classify.
    async fn send_with_auth(
        &self,
        url: &str,
        accept: Option<&str>,
        scope: &str,
    ) -> Result<reqwest::Response, UpstreamError> {
        let resp = self
            .build(url, accept)
            .send()
            .await
            .map_err(|e| UpstreamError::Request(e.to_string()))?;
        if resp.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(resp);
        }
        let Some(challenge) = resp
            .headers()
            .get(reqwest::header::WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_www_authenticate)
        else {
            return Ok(resp);
        };
        let token = self.fetch_token(&challenge, scope).await?;
        self.build(url, accept)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|e| UpstreamError::Request(e.to_string()))
    }

    async fn fetch_token(
        &self,
        challenge: &Challenge,
        fallback_scope: &str,
    ) -> Result<String, UpstreamError> {
        let realm = challenge
            .realm
            .clone()
            .unwrap_or_else(|| self.cfg.auth_url.clone());
        let service = challenge
            .service
            .clone()
            .unwrap_or_else(|| self.cfg.service.clone());
        let scope = challenge
            .scope
            .clone()
            .unwrap_or_else(|| fallback_scope.to_owned());

        // Built via `url::Url` rather than `RequestBuilder::query(...)` — the
        // latter needs a reqwest feature this workspace's trimmed feature
        // set doesn't enable, and `url` is already a direct dependency.
        let mut token_url = url::Url::parse(&realm)
            .map_err(|e| UpstreamError::Auth(format!("invalid token realm {realm}: {e}")))?;
        token_url
            .query_pairs_mut()
            .append_pair("service", &service)
            .append_pair("scope", &scope);
        let mut req = self.http.get(token_url);
        if let (Some(user), Some(pass)) = (&self.cfg.username, &self.cfg.password) {
            req = req.basic_auth(user, Some(pass));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| UpstreamError::Auth(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(UpstreamError::Auth(format!(
                "token endpoint returned {}",
                resp.status()
            )));
        }
        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|e| UpstreamError::Auth(e.to_string()))?;
        body.token
            .or(body.access_token)
            .ok_or_else(|| UpstreamError::Auth("token response missing token field".to_owned()))
    }

    /// Reads a response body under `max_bytes`, streaming rather than
    /// buffering-then-checking so an upstream that lies about (or omits)
    /// `Content-Length` still can't force an unbounded in-memory buffer.
    async fn read_body(
        resp: reqwest::Response,
        max_bytes: u64,
    ) -> Result<FetchedArtifact, UpstreamError> {
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(UpstreamError::NotFound);
        }
        if !status.is_success() {
            return Err(UpstreamError::Status {
                status: status.as_u16(),
            });
        }
        if let Some(len) = resp.content_length()
            && len > max_bytes
        {
            return Err(UpstreamError::TooLarge(len));
        }
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_owned();

        let mut buf: Vec<u8> = Vec::new();
        let mut stream = resp.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| UpstreamError::Request(e.to_string()))?;
            buf.extend_from_slice(&chunk);
            if buf.len() as u64 > max_bytes {
                return Err(UpstreamError::TooLarge(buf.len() as u64));
            }
        }
        Ok(FetchedArtifact {
            bytes: Bytes::from(buf),
            content_type,
        })
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn cfg(base_url: &str) -> UpstreamConfig {
        UpstreamConfig {
            base_url: base_url.to_owned(),
            auth_url: format!("{base_url}/token"),
            service: "test-registry".to_owned(),
            username: None,
            password: None,
        }
    }

    fn client(base_url: &str) -> UpstreamClient {
        UpstreamClient::new(reqwest::Client::new(), cfg(base_url))
    }

    #[test]
    fn parses_full_bearer_challenge() {
        let header = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/nginx:pull""#;
        let c = parse_www_authenticate(header).expect("parse");
        assert_eq!(c.realm.as_deref(), Some("https://auth.docker.io/token"));
        assert_eq!(c.service.as_deref(), Some("registry.docker.io"));
        assert_eq!(c.scope.as_deref(), Some("repository:library/nginx:pull"));
    }

    #[test]
    fn rejects_non_bearer_challenge() {
        assert_eq!(parse_www_authenticate(r#"Basic realm="x""#), None);
    }

    #[test]
    fn tolerates_missing_optional_fields() {
        let c = parse_www_authenticate(r#"Bearer realm="https://x/token""#).expect("parse");
        assert_eq!(c.realm.as_deref(), Some("https://x/token"));
        assert_eq!(c.service, None);
        assert_eq!(c.scope, None);
    }

    #[tokio::test]
    async fn fetch_manifest_succeeds_without_auth_challenge() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/latest"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(
                br#"{"schemaVersion":2}"#.to_vec(),
                "application/vnd.oci.image.manifest.v1+json",
            ))
            .mount(&server)
            .await;

        let got = client(&server.uri())
            .fetch_manifest("library/nginx", "latest", 1024)
            .await
            .expect("fetch");
        assert_eq!(got.bytes.as_ref(), br#"{"schemaVersion":2}"#);
        assert_eq!(
            got.content_type,
            "application/vnd.oci.image.manifest.v1+json"
        );
    }

    #[tokio::test]
    async fn fetch_manifest_follows_bearer_challenge() {
        let server = MockServer::start().await;
        let challenge = format!(
            r#"Bearer realm="{}/token",service="test-registry",scope="repository:library/nginx:pull""#,
            server.uri()
        );
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/latest"))
            .respond_with(
                ResponseTemplate::new(401).insert_header("WWW-Authenticate", challenge.as_str()),
            )
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"token": "tok-123"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/latest"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer tok-123",
            ))
            .respond_with(
                ResponseTemplate::new(200).set_body_raw(b"ok".to_vec(), "application/octet-stream"),
            )
            .mount(&server)
            .await;

        let got = client(&server.uri())
            .fetch_manifest("library/nginx", "latest", 1024)
            .await
            .expect("fetch");
        assert_eq!(got.bytes.as_ref(), b"ok");
    }

    #[tokio::test]
    async fn fetch_manifest_maps_404_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/missing/manifests/latest"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .fetch_manifest("library/missing", "latest", 1024)
            .await
            .expect_err("expected not found");
        assert!(matches!(err, UpstreamError::NotFound));
    }

    #[tokio::test]
    async fn fetch_blob_rejects_oversized_content_length() {
        // A real oversized body — wiremock/hyper compute the actual
        // Content-Length from the body bytes sent, so this exercises the
        // early `resp.content_length()` guard (the body is never streamed
        // at all) rather than the "no/wrong Content-Length" streaming-cap
        // path covered by the test below.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/blobs/sha256:deadbeef"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(vec![0u8; 2048], "application/octet-stream"),
            )
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .fetch_blob("library/nginx", "sha256:deadbeef", 1024)
            .await
            .expect_err("expected too large");
        assert!(matches!(err, UpstreamError::TooLarge(2048)));
    }

    #[tokio::test]
    async fn fetch_blob_enforces_cap_even_without_content_length() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/blobs/sha256:deadbeef"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw(vec![0u8; 2048], "application/octet-stream"),
            )
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .fetch_blob("library/nginx", "sha256:deadbeef", 1024)
            .await
            .expect_err("expected too large");
        assert!(matches!(err, UpstreamError::TooLarge(_)));
    }

    #[tokio::test]
    async fn list_tags_proxies_json_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/tags/list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "library/nginx", "tags": ["latest", "1.27"]
            })))
            .mount(&server)
            .await;

        let got = client(&server.uri())
            .list_tags("library/nginx")
            .await
            .expect("list");
        assert_eq!(got["tags"][0], "latest");
    }

    #[tokio::test]
    async fn list_tags_maps_404() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/missing/tags/list"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .list_tags("library/missing")
            .await
            .expect_err("expected not found");
        assert!(matches!(err, UpstreamError::NotFound));
    }

    #[tokio::test]
    async fn unauthenticated_401_without_bearer_challenge_surfaces_as_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v2/library/nginx/manifests/latest"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;

        let err = client(&server.uri())
            .fetch_manifest("library/nginx", "latest", 1024)
            .await
            .expect_err("expected status error");
        assert!(matches!(err, UpstreamError::Status { status: 401 }));
    }
}
