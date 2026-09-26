//! PyPI client + simple-index/JSON-API rewriting (P2,
//! `docs/v2-port/v2.1-depgate.md` §4). Like `src/npm.rs`, no Bearer-challenge
//! dance — public packages are anonymous, a private index uses static Basic
//! auth (`DEPGATE_PYPI_USERNAME`/`DEPGATE_PYPI_PASSWORD`).
//!
//! **Rewrite contract:** every package-file link (PEP 503 `<a href>` in the
//! simple index, or `url` in the JSON API) is rewritten from its real
//! upstream location (typically `files.pythonhosted.org/packages/...`) to
//! `{public_base_url}/pypi/packages/...`, preserving the `#sha256=<hex>`
//! fragment (simple index) / `digests.sha256` field (JSON API) untouched —
//! DepGate never alters file bytes, only where they are served from, so the
//! original upstream-published digest remains valid for the client
//! (`pip`/`uv`) to verify against.

use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value;

use crate::config::PypiUpstreamConfig;
use crate::fetch::{FetchError, Fetched, get_capped};

/// Matches `href="..."` attributes in a PEP 503 simple-index HTML page.
static HREF_RE: LazyLock<Regex> = LazyLock::new(|| match Regex::new(r#"href="([^"]*)""#) {
    Ok(re) => re,
    // Infallible: the pattern is a fixed literal compiled once at
    // first use, never derived from external input.
    Err(e) => unreachable!("static HREF_RE pattern is valid: {e}"),
});

/// Talks to exactly one configured upstream PyPI-compatible index.
#[derive(Debug, Clone)]
pub struct PypiUpstreamClient {
    http: reqwest::Client,
    cfg: PypiUpstreamConfig,
}

impl PypiUpstreamClient {
    /// Builds a client for `cfg`, reusing the caller's `reqwest::Client`.
    #[must_use]
    pub fn new(http: reqwest::Client, cfg: PypiUpstreamConfig) -> Self {
        Self { http, cfg }
    }

    /// The configured index base URL — recorded on
    /// `depgate_artifacts.upstream` for audit purposes.
    #[must_use]
    pub fn index_url(&self) -> &str {
        &self.cfg.index_url
    }

    fn build(&self, url: &str) -> reqwest::RequestBuilder {
        let mut req = self.http.get(url);
        if let (Some(user), Some(pass)) = (&self.cfg.username, &self.cfg.password) {
            req = req.basic_auth(user, Some(pass));
        }
        req
    }

    /// Fetches the PEP 503 simple index page for `project`, raw HTML.
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_simple_index(
        &self,
        project: &str,
        max_bytes: u64,
    ) -> Result<String, FetchError> {
        let url = format!("{}/simple/{project}/", self.cfg.index_url);
        let fetched = get_capped(self.build(&url), max_bytes).await?;
        Ok(String::from_utf8_lossy(&fetched.bytes).into_owned())
    }

    /// Fetches the legacy JSON API document for `project`.
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_json_api(&self, project: &str, max_bytes: u64) -> Result<Value, FetchError> {
        let url = format!("{}/pypi/{project}/json", self.cfg.index_url);
        let fetched = get_capped(self.build(&url), max_bytes).await?;
        serde_json::from_slice(&fetched.bytes)
            .map_err(|e| FetchError::Request(format!("malformed PyPI JSON API body: {e}")))
    }

    /// Fetches a package file at `upstream_path` (the `/packages/...` path
    /// as reconstructed from a `GET /pypi/packages/{*rest}` request by
    /// prefixing the files-host base URL back on).
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_file(
        &self,
        upstream_path: &str,
        max_bytes: u64,
    ) -> Result<Fetched, FetchError> {
        let url = format!("{}{upstream_path}", self.cfg.files_url);
        get_capped(self.build(&url), max_bytes).await
    }
}

/// Rewrites `href` to `{public_base_url}/pypi/packages/...` if it resolves
/// (absolute, or relative against `index_base`) to a `/packages/...` path —
/// i.e. an actual file link, never the index page's own self-links or
/// unrelated hrefs. Preserves query and fragment (`#sha256=<hex>`)
/// untouched. `None` for anything that doesn't match, meaning "leave this
/// href alone".
fn rewrite_file_href(href: &str, index_base: &str, public_base_url: &str) -> Option<String> {
    let base = url::Url::parse(index_base).ok()?;
    let joined = base.join(href).ok()?;
    if !joined.path().starts_with("/packages/") {
        return None;
    }
    let mut rewritten = format!("{public_base_url}/pypi{}", joined.path());
    if let Some(q) = joined.query() {
        rewritten.push('?');
        rewritten.push_str(q);
    }
    if let Some(f) = joined.fragment() {
        rewritten.push('#');
        rewritten.push_str(f);
    }
    Some(rewritten)
}

/// Rewrites every package-file `href` in a PEP 503 simple-index HTML page,
/// leaving everything else (markup, filename link text, non-file hrefs)
/// byte-for-byte unchanged.
#[must_use]
pub fn rewrite_simple_index(html: &str, index_base: &str, public_base_url: &str) -> String {
    HREF_RE
        .replace_all(html, |caps: &regex::Captures<'_>| {
            let raw = &caps[1];
            match rewrite_file_href(raw, index_base, public_base_url) {
                Some(new_url) => format!(r#"href="{new_url}""#),
                None => caps[0].to_owned(),
            }
        })
        .into_owned()
}

/// Rewrites every file `url` field under `releases`/`urls` in a PyPI legacy
/// JSON API document, leaving `digests`/`filename`/everything else
/// untouched.
#[must_use]
pub fn rewrite_json_api(mut doc: Value, index_base: &str, public_base_url: &str) -> Value {
    if let Some(releases) = doc.get_mut("releases").and_then(Value::as_object_mut) {
        for files in releases.values_mut() {
            if let Some(arr) = files.as_array_mut() {
                for f in arr.iter_mut() {
                    rewrite_file_url_field(f, index_base, public_base_url);
                }
            }
        }
    }
    if let Some(urls) = doc.get_mut("urls").and_then(Value::as_array_mut) {
        for f in urls.iter_mut() {
            rewrite_file_url_field(f, index_base, public_base_url);
        }
    }
    doc
}

fn rewrite_file_url_field(f: &mut Value, index_base: &str, public_base_url: &str) {
    let Some(obj) = f.as_object_mut() else {
        return;
    };
    let Some(url_str) = obj.get("url").and_then(Value::as_str) else {
        return;
    };
    if let Some(new_url) = rewrite_file_href(url_str, index_base, public_base_url) {
        obj.insert("url".to_owned(), Value::String(new_url));
    }
}

/// Extracts the first release file's upstream-relative path
/// (`/packages/...`) for `version` from a fetched JSON API document — the
/// seed warm-start path (§9), where a name+version pair (not a filename) is
/// the seed manifest's natural unit. `None` if the version or its file
/// entries are missing/malformed.
#[must_use]
pub fn file_path_for_version(doc: &Value, version: &str) -> Option<String> {
    let files = doc.pointer(&format!("/releases/{version}"))?.as_array()?;
    let first = files.first()?;
    let url_str = first.get("url")?.as_str()?;
    let parsed = url::Url::parse(url_str).ok()?;
    Some(parsed.path().to_owned())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn cfg(index_url: &str, files_url: &str) -> PypiUpstreamConfig {
        PypiUpstreamConfig {
            index_url: index_url.to_owned(),
            files_url: files_url.to_owned(),
            username: None,
            password: None,
        }
    }

    #[test]
    fn rewrite_simple_index_preserves_sha256_fragment_and_rewrites_host() {
        let html = r#"<!DOCTYPE html><html><body>
<a href="https://files.pythonhosted.org/packages/aa/bb/requests-2.34.2.tar.gz#sha256=deadbeef">requests-2.34.2.tar.gz</a><br/>
</body></html>"#;
        let rewritten = rewrite_simple_index(html, "https://pypi.org", "https://depgate.internal");
        assert!(rewritten.contains(
            r#"href="https://depgate.internal/pypi/packages/aa/bb/requests-2.34.2.tar.gz#sha256=deadbeef""#
        ));
        // Link text and surrounding markup untouched.
        assert!(rewritten.contains(">requests-2.34.2.tar.gz</a>"));
    }

    #[test]
    fn rewrite_simple_index_handles_root_relative_hrefs() {
        let html = r#"<a href="/packages/aa/bb/pkg-1.0.0.whl#sha256=abc123">pkg-1.0.0.whl</a>"#;
        let rewritten = rewrite_simple_index(html, "https://pypi.org", "https://depgate.internal");
        assert!(rewritten.contains(
            r#"href="https://depgate.internal/pypi/packages/aa/bb/pkg-1.0.0.whl#sha256=abc123""#
        ));
    }

    #[test]
    fn rewrite_simple_index_leaves_non_package_hrefs_untouched() {
        let html = r#"<a href="https://pypi.org/simple/">index</a>"#;
        let rewritten = rewrite_simple_index(html, "https://pypi.org", "https://depgate.internal");
        assert_eq!(rewritten, html);
    }

    #[test]
    fn rewrite_simple_index_rewrites_every_link() {
        let html = concat!(
            r#"<a href="https://files.pythonhosted.org/packages/aa/pkg-1.0.0.tar.gz#sha256=aaa">pkg-1.0.0.tar.gz</a>"#,
            r#"<a href="https://files.pythonhosted.org/packages/bb/pkg-2.0.0.tar.gz#sha256=bbb">pkg-2.0.0.tar.gz</a>"#,
        );
        let rewritten = rewrite_simple_index(html, "https://pypi.org", "https://depgate.internal");
        assert!(
            rewritten
                .contains("https://depgate.internal/pypi/packages/aa/pkg-1.0.0.tar.gz#sha256=aaa")
        );
        assert!(
            rewritten
                .contains("https://depgate.internal/pypi/packages/bb/pkg-2.0.0.tar.gz#sha256=bbb")
        );
    }

    #[test]
    fn rewrite_json_api_rewrites_release_urls_and_preserves_digests() {
        let doc = serde_json::json!({
            "releases": {
                "2.34.2": [{
                    "filename": "requests-2.34.2.tar.gz",
                    "url": "https://files.pythonhosted.org/packages/aa/bb/requests-2.34.2.tar.gz",
                    "digests": {"sha256": "deadbeef"},
                }]
            },
            "urls": [{
                "filename": "requests-2.34.2.tar.gz",
                "url": "https://files.pythonhosted.org/packages/aa/bb/requests-2.34.2.tar.gz",
                "digests": {"sha256": "deadbeef"},
            }]
        });
        let rewritten = rewrite_json_api(doc, "https://pypi.org", "https://depgate.internal");
        assert_eq!(
            rewritten["releases"]["2.34.2"][0]["url"],
            "https://depgate.internal/pypi/packages/aa/bb/requests-2.34.2.tar.gz"
        );
        assert_eq!(
            rewritten["releases"]["2.34.2"][0]["digests"]["sha256"],
            "deadbeef"
        );
        assert_eq!(
            rewritten["urls"][0]["url"],
            "https://depgate.internal/pypi/packages/aa/bb/requests-2.34.2.tar.gz"
        );
    }

    #[test]
    fn rewrite_json_api_tolerates_missing_releases_or_urls() {
        let doc = serde_json::json!({"info": {"name": "requests"}});
        let rewritten =
            rewrite_json_api(doc.clone(), "https://pypi.org", "https://depgate.internal");
        assert_eq!(rewritten, doc);
    }

    #[tokio::test]
    async fn fetch_simple_index_returns_raw_html() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/simple/requests/"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/html")
                    .set_body_raw(b"<html>ok</html>".to_vec(), "text/html"),
            )
            .mount(&server)
            .await;

        let client = PypiUpstreamClient::new(
            reqwest::Client::new(),
            cfg(&server.uri(), "https://files.pythonhosted.org"),
        );
        let html = client
            .fetch_simple_index("requests", 1024)
            .await
            .expect("fetch");
        assert_eq!(html, "<html>ok</html>");
    }

    #[test]
    fn file_path_for_version_extracts_the_first_files_path() {
        let doc = serde_json::json!({
            "releases": {
                "2.34.2": [{
                    "url": "https://files.pythonhosted.org/packages/aa/bb/requests-2.34.2.tar.gz",
                    "digests": {"sha256": "deadbeef"},
                }]
            }
        });
        assert_eq!(
            file_path_for_version(&doc, "2.34.2"),
            Some("/packages/aa/bb/requests-2.34.2.tar.gz".to_owned())
        );
    }

    #[test]
    fn file_path_for_version_returns_none_for_missing_version() {
        let doc = serde_json::json!({"releases": {}});
        assert_eq!(file_path_for_version(&doc, "9.9.9"), None);
    }

    #[tokio::test]
    async fn fetch_file_maps_404_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/packages/aa/missing.whl"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = PypiUpstreamClient::new(
            reqwest::Client::new(),
            cfg("https://pypi.org", &server.uri()),
        );
        let err = client
            .fetch_file("/packages/aa/missing.whl", 1024)
            .await
            .expect_err("expected not found");
        assert!(matches!(err, FetchError::NotFound));
    }
}
