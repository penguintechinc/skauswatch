//! npm registry client + packument rewriting (P2,
//! `docs/v2-port/v2.1-depgate.md` §4). Deliberately simpler than
//! `src/upstream.rs`'s OCI client: npm has no Bearer-challenge dance —
//! public packages are anonymous, private ones use a static Bearer token
//! (`DEPGATE_NPM_TOKEN`) sent on every request.
//!
//! **Rewrite contract:** every version's `dist.tarball` in the fetched
//! packument is rewritten to `{public_base_url}/npm{upstream_path}` — the
//! upstream registry's own tarball path is already shaped exactly like
//! DepGate's own route (`/{name}/-/{filename}.tgz`), so only the
//! scheme+host prefix changes. `dist.shasum`/`dist.integrity` are left
//! completely untouched: DepGate never alters tarball bytes, only where
//! they are served from, so the original upstream-published integrity
//! values remain valid for the npm client to verify against.

use serde_json::Value;

use crate::config::NpmUpstreamConfig;
use crate::fetch::{FetchError, Fetched, get_capped};

/// Talks to exactly one configured upstream npm registry.
#[derive(Debug, Clone)]
pub struct NpmUpstreamClient {
    http: reqwest::Client,
    cfg: NpmUpstreamConfig,
}

impl NpmUpstreamClient {
    /// Builds a client for `cfg`, reusing the caller's `reqwest::Client`.
    #[must_use]
    pub fn new(http: reqwest::Client, cfg: NpmUpstreamConfig) -> Self {
        Self { http, cfg }
    }

    /// The configured upstream registry base URL — recorded on
    /// `depgate_artifacts.upstream` for audit purposes.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.cfg.registry_url
    }

    fn build(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.get(url);
        if let Some(token) = &self.cfg.token {
            req = req.bearer_auth(token);
        }
        req
    }

    /// Fetches the packument (package metadata document) for `name`
    /// (unscoped `left-pad` or scoped `@scope/name`), parsed as JSON.
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_packument(&self, name: &str, max_bytes: u64) -> Result<Value, FetchError> {
        let url = format!("{}/{name}", self.cfg.registry_url);
        let fetched = get_capped(self.build(&url), max_bytes).await?;
        serde_json::from_slice(&fetched.bytes)
            .map_err(|e| FetchError::Request(format!("malformed packument JSON: {e}")))
    }

    /// Fetches a tarball at `upstream_path` (e.g. `/left-pad/-/left-pad-1.3.0.tgz`,
    /// as reconstructed from a `GET /npm/{*rest}` request by prefixing the
    /// registry base URL back on).
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_tarball(
        &self,
        upstream_path: &str,
        max_bytes: u64,
    ) -> Result<Fetched, FetchError> {
        let url = format!("{}{upstream_path}", self.cfg.registry_url);
        get_capped(self.build(&url), max_bytes).await
    }
}

/// Rewrites every version's `dist.tarball` in `doc` to point back at
/// `public_base_url` under the `/npm` route prefix, preserving
/// `dist.shasum`/`dist.integrity` untouched. Malformed/missing fields are
/// left as-is rather than erroring — a packument DepGate can't fully
/// rewrite is still more useful proxied best-effort than refused outright
/// (this is metadata, never cached/scanned content).
#[must_use]
pub fn rewrite_packument(mut doc: Value, public_base_url: &str) -> Value {
    if let Some(versions) = doc.get_mut("versions").and_then(Value::as_object_mut) {
        for meta in versions.values_mut() {
            let Some(dist) = meta.get_mut("dist").and_then(Value::as_object_mut) else {
                continue;
            };
            let Some(tarball) = dist.get("tarball").and_then(Value::as_str) else {
                continue;
            };
            let Ok(parsed) = url::Url::parse(tarball) else {
                continue;
            };
            let rewritten = format!("{public_base_url}/npm{}", parsed.path());
            dist.insert("tarball".to_owned(), Value::String(rewritten));
        }
    }
    doc
}

/// Extracts the upstream-relative tarball path (`/{name}/-/{filename}`) for
/// `version` from a fetched packument — the seed warm-start path (§9),
/// where a name+version pair (not a filename) is the seed manifest's
/// natural unit. `None` if the version or its tarball URL is missing/
/// malformed.
#[must_use]
pub fn tarball_path_for_version(doc: &Value, version: &str) -> Option<String> {
    let tarball = doc
        .pointer(&format!("/versions/{version}/dist/tarball"))?
        .as_str()?;
    let parsed = url::Url::parse(tarball).ok()?;
    Some(parsed.path().to_owned())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn cfg(registry_url: &str) -> NpmUpstreamConfig {
        NpmUpstreamConfig {
            registry_url: registry_url.to_owned(),
            token: None,
        }
    }

    #[test]
    fn rewrite_packument_replaces_tarball_scheme_and_host_only() {
        let doc = serde_json::json!({
            "name": "left-pad",
            "versions": {
                "1.3.0": {
                    "dist": {
                        "shasum": "abc123",
                        "integrity": "sha512-deadbeef",
                        "tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    }
                }
            }
        });
        let rewritten = rewrite_packument(doc, "https://depgate.internal");
        let dist = &rewritten["versions"]["1.3.0"]["dist"];
        assert_eq!(
            dist["tarball"],
            "https://depgate.internal/npm/left-pad/-/left-pad-1.3.0.tgz"
        );
        assert_eq!(dist["shasum"], "abc123");
        assert_eq!(dist["integrity"], "sha512-deadbeef");
    }

    #[test]
    fn rewrite_packument_handles_scoped_package_tarballs() {
        let doc = serde_json::json!({
            "versions": {
                "20.0.0": {
                    "dist": {
                        "tarball": "https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz",
                    }
                }
            }
        });
        let rewritten = rewrite_packument(doc, "https://depgate.internal");
        assert_eq!(
            rewritten["versions"]["20.0.0"]["dist"]["tarball"],
            "https://depgate.internal/npm/@types/node/-/node-20.0.0.tgz"
        );
    }

    #[test]
    fn rewrite_packument_rewrites_every_version() {
        let doc = serde_json::json!({
            "versions": {
                "1.0.0": {"dist": {"tarball": "https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"}},
                "2.0.0": {"dist": {"tarball": "https://registry.npmjs.org/pkg/-/pkg-2.0.0.tgz"}},
            }
        });
        let rewritten = rewrite_packument(doc, "https://depgate.internal");
        assert_eq!(
            rewritten["versions"]["1.0.0"]["dist"]["tarball"],
            "https://depgate.internal/npm/pkg/-/pkg-1.0.0.tgz"
        );
        assert_eq!(
            rewritten["versions"]["2.0.0"]["dist"]["tarball"],
            "https://depgate.internal/npm/pkg/-/pkg-2.0.0.tgz"
        );
    }

    #[test]
    fn rewrite_packument_tolerates_missing_dist_or_tarball() {
        let doc = serde_json::json!({
            "versions": {
                "1.0.0": {},
                "2.0.0": {"dist": {}},
            }
        });
        let rewritten = rewrite_packument(doc.clone(), "https://depgate.internal");
        assert_eq!(rewritten, doc);
    }

    #[tokio::test]
    async fn fetch_packument_parses_json_body() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "name": "left-pad"
            })))
            .mount(&server)
            .await;

        let client = NpmUpstreamClient::new(reqwest::Client::new(), cfg(&server.uri()));
        let doc = client
            .fetch_packument("left-pad", 1024 * 1024)
            .await
            .expect("fetch");
        assert_eq!(doc["name"], "left-pad");
    }

    #[tokio::test]
    async fn fetch_packument_sends_bearer_token_when_configured() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/private-pkg"))
            .and(wiremock::matchers::header(
                "authorization",
                "Bearer tok-123",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let client = NpmUpstreamClient::new(
            reqwest::Client::new(),
            NpmUpstreamConfig {
                registry_url: server.uri(),
                token: Some("tok-123".to_owned()),
            },
        );
        client
            .fetch_packument("private-pkg", 1024)
            .await
            .expect("fetch");
    }

    #[test]
    fn tarball_path_for_version_extracts_the_path_component() {
        let doc = serde_json::json!({
            "versions": {
                "1.3.0": {
                    "dist": {"tarball": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}
                }
            }
        });
        assert_eq!(
            tarball_path_for_version(&doc, "1.3.0"),
            Some("/left-pad/-/left-pad-1.3.0.tgz".to_owned())
        );
    }

    #[test]
    fn tarball_path_for_version_returns_none_for_missing_version() {
        let doc = serde_json::json!({"versions": {}});
        assert_eq!(tarball_path_for_version(&doc, "9.9.9"), None);
    }

    #[tokio::test]
    async fn fetch_tarball_maps_404_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/left-pad/-/left-pad-9.9.9.tgz"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = NpmUpstreamClient::new(reqwest::Client::new(), cfg(&server.uri()));
        let err = client
            .fetch_tarball("/left-pad/-/left-pad-9.9.9.tgz", 1024)
            .await
            .expect_err("expected not found");
        assert!(matches!(err, FetchError::NotFound));
    }
}
