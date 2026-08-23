//! crates.io sparse-index + `.crate` download client (P4,
//! `docs/v2-port/v2.1-depgate.md` §4/§9). Simpler than `src/npm.rs`/
//! `src/pypi.rs`: crates.io's sparse-index protocol needs no per-entry URL
//! rewriting at all — the download URL is declared exactly ONCE, in a
//! top-level `config.json` this proxy serves itself
//! ([`config_json`]) pointing `dl` back at DepGate's own
//! `/crates/api/v1/crates/{crate}/{version}/download` route — so every
//! per-version NDJSON line in the index proxies through completely
//! unmodified.
//!
//! Crate names never contain `/` (unlike scoped npm packages or OCI
//! repository names), so this ecosystem needs no dedicated path-parsing
//! module — `src/routes/crates_io.rs` uses axum's ordinary typed
//! `Path` extractors directly.

use serde_json::Value;

use crate::config::CratesIoUpstreamConfig;
use crate::fetch::{FetchError, Fetched, get_capped};

/// Talks to exactly one configured upstream crates.io-compatible registry.
#[derive(Debug, Clone)]
pub struct CratesIoUpstreamClient {
    http: reqwest::Client,
    cfg: CratesIoUpstreamConfig,
}

/// crates.io's sparse-index path convention for `name`:
/// - 1 char:  `1/{name}`
/// - 2 chars: `2/{name}`
/// - 3 chars: `3/{first-char}/{name}`
/// - 4+ chars: `{first-two}/{next-two}/{name}`
///
/// Matches `cargo`'s own documented sparse-index layout exactly.
#[must_use]
pub fn index_path(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    match lower.len() {
        0 => lower,
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => {
            let mut chars = lower.chars();
            let first = chars.next().unwrap_or_default();
            format!("3/{first}/{lower}")
        }
        _ => {
            let chars: Vec<char> = lower.chars().collect();
            let a: String = chars[0..2].iter().collect();
            let b: String = chars[2..4].iter().collect();
            format!("{a}/{b}/{lower}")
        }
    }
}

impl CratesIoUpstreamClient {
    /// Builds a client for `cfg`, reusing the caller's `reqwest::Client`.
    #[must_use]
    pub fn new(http: reqwest::Client, cfg: CratesIoUpstreamConfig) -> Self {
        Self { http, cfg }
    }

    /// The configured sparse-index base URL — recorded on
    /// `depgate_artifacts.upstream` for audit purposes.
    #[must_use]
    pub fn index_url(&self) -> &str {
        &self.cfg.index_url
    }

    /// Fetches the raw sparse-index NDJSON document for `name`, proxied
    /// verbatim — no rewriting needed (see module docs).
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_index(&self, name: &str, max_bytes: u64) -> Result<Fetched, FetchError> {
        self.fetch_index_path(&index_path(name), max_bytes).await
    }

    /// Fetches the raw sparse-index document at `index_relative_path` — the
    /// exact sub-path (e.g. `se/rd/serde`) a `cargo` client itself computed
    /// and requested from `/crates/index/{*rest}`
    /// (`crate::routes::crates_io::index_proxy`), reusing this client's
    /// pooled connection rather than the route handler standing up its own.
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_index_path(
        &self,
        index_relative_path: &str,
        max_bytes: u64,
    ) -> Result<Fetched, FetchError> {
        let url = format!("{}/{index_relative_path}", self.cfg.index_url);
        get_capped(self.http.get(url), max_bytes).await
    }

    /// Downloads the `.crate` file for `name`@`version`.
    ///
    /// # Errors
    /// See [`FetchError`].
    pub async fn fetch_crate_file(
        &self,
        name: &str,
        version: &str,
        max_bytes: u64,
    ) -> Result<Fetched, FetchError> {
        let url = format!("{}/{name}/{version}/download", self.cfg.api_url);
        get_capped(self.http.get(url), max_bytes).await
    }
}

/// Whether `ndjson` (a raw sparse-index document, one JSON object per
/// published version) declares `version` — used by the seed warm-start path
/// (`crate::seed::seed_crates_package`) to fail with a clear
/// `PipelineError::BadRequest` on a typo'd/unpublished seed version instead
/// of an opaque 404 from the download endpoint, mirroring
/// `crate::npm::tarball_path_for_version`/`crate::pypi::file_path_for_version`'s
/// same "consult metadata before downloading" pattern. Malformed lines are
/// skipped rather than erroring — one bad line in a large index must not
/// hide a real version match on another line.
#[must_use]
pub fn version_exists(ndjson: &[u8], version: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct IndexEntry {
        vers: String,
    }
    String::from_utf8_lossy(ndjson).lines().any(|line| {
        serde_json::from_str::<IndexEntry>(line).is_ok_and(|entry| entry.vers == version)
    })
}

/// Builds the sparse-index root `config.json` DepGate serves at
/// `/crates/index/config.json` — the one place the download URL template is
/// declared, pointing `dl` back at this deployment's own download route
/// rather than the real crates.io API.
#[must_use]
pub fn config_json(public_base_url: &str) -> Value {
    serde_json::json!({
        "dl": format!("{public_base_url}/crates/api/v1/crates/{{crate}}/{{version}}/download"),
        "api": public_base_url,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn cfg(index_url: &str, api_url: &str) -> CratesIoUpstreamConfig {
        CratesIoUpstreamConfig {
            index_url: index_url.to_owned(),
            api_url: api_url.to_owned(),
        }
    }

    #[test]
    fn index_path_handles_one_char_names() {
        assert_eq!(index_path("a"), "1/a");
    }

    #[test]
    fn index_path_handles_two_char_names() {
        assert_eq!(index_path("ab"), "2/ab");
    }

    #[test]
    fn index_path_handles_three_char_names() {
        assert_eq!(index_path("abc"), "3/a/abc");
    }

    #[test]
    fn index_path_handles_four_plus_char_names() {
        assert_eq!(index_path("serde"), "se/rd/serde");
        assert_eq!(index_path("tokio"), "to/ki/tokio");
    }

    #[test]
    fn index_path_lowercases_the_name() {
        assert_eq!(index_path("Serde"), "se/rd/serde");
    }

    #[test]
    fn version_exists_finds_a_matching_line() {
        let ndjson = "{\"name\":\"serde\",\"vers\":\"1.0.227\"}\n{\"name\":\"serde\",\"vers\":\"1.0.228\"}\n";
        assert!(version_exists(ndjson.as_bytes(), "1.0.228"));
    }

    #[test]
    fn version_exists_returns_false_for_a_missing_version() {
        let ndjson = "{\"name\":\"serde\",\"vers\":\"1.0.227\"}\n";
        assert!(!version_exists(ndjson.as_bytes(), "9.9.9"));
    }

    #[test]
    fn version_exists_skips_malformed_lines_without_erroring() {
        let ndjson = "not json\n{\"name\":\"serde\",\"vers\":\"1.0.228\"}\n";
        assert!(version_exists(ndjson.as_bytes(), "1.0.228"));
    }

    #[test]
    fn config_json_points_dl_back_at_this_deployment() {
        let json = config_json("https://depgate.internal");
        assert_eq!(
            json["dl"],
            "https://depgate.internal/crates/api/v1/crates/{crate}/{version}/download"
        );
        assert_eq!(json["api"], "https://depgate.internal");
    }

    #[tokio::test]
    async fn fetch_index_proxies_the_ndjson_body_verbatim() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/se/rd/serde"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_raw("{\"name\":\"serde\",\"vers\":\"1.0.0\"}\n", "text/plain"),
            )
            .mount(&server)
            .await;

        let client = CratesIoUpstreamClient::new(reqwest::Client::new(), cfg(&server.uri(), ""));
        let fetched = client.fetch_index("serde", 1024).await.expect("fetch");
        assert_eq!(
            fetched.bytes.as_ref(),
            b"{\"name\":\"serde\",\"vers\":\"1.0.0\"}\n"
        );
    }

    #[tokio::test]
    async fn fetch_crate_file_downloads_the_crate_bytes() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/serde/1.0.0/download"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/x-tar")
                    .set_body_bytes(b"fake crate bytes".to_vec()),
            )
            .mount(&server)
            .await;

        let client = CratesIoUpstreamClient::new(reqwest::Client::new(), cfg("", &server.uri()));
        let fetched = client
            .fetch_crate_file("serde", "1.0.0", 1024)
            .await
            .expect("fetch");
        assert_eq!(fetched.bytes.as_ref(), b"fake crate bytes");
    }

    #[tokio::test]
    async fn fetch_crate_file_maps_404_to_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/ghost/9.9.9/download"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = CratesIoUpstreamClient::new(reqwest::Client::new(), cfg("", &server.uri()));
        let err = client
            .fetch_crate_file("ghost", "9.9.9", 1024)
            .await
            .expect_err("expected not found");
        assert!(matches!(err, FetchError::NotFound));
    }
}
