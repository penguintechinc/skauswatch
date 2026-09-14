//! Branch working-tree fetch for CodeScan Sentinel's tool registry (P2,
//! docs/v2-port/v2.1-codescan-sentinel.md §3/§14): SAST/secrets/IaC/SBOM
//! tools need a real working copy of the branch, not just the individual
//! manifests P1's `sentinel::scan_branch` fetches via the Contents API.
//! Fetches the provider's zip archive of the branch (GitHub `zipball`,
//! GitLab `archive.zip`) into a size-capped temp directory rather than a
//! full git clone — lighter weight, and matches the Contents-API-first bias
//! the spec's open questions section leans toward (§14).
//!
//! Uses the `zip` crate, which is already resolved in the workspace
//! lockfile transitively via `yara-x` (`skauswatch-scan-core`) — pinning it
//! as a direct dependency here at that same version does not move anything
//! already locked, and avoids adding a brand-new tar/gzip dependency for
//! what both providers can serve as a zip just as easily (`ZipArchive`'s
//! `extract_unwrapped_root_dir` also does the GitHub/GitLab
//! single-top-level-directory unwrapping and zip-slip path sanitization for
//! us, which a hand-rolled tar.gz reader would have to reimplement).
//!
//! **Known limitation (private GitHub repos):** GitHub's `zipball` endpoint
//! answers with a `302` to `codeload.github.com` — a different host from
//! `api.github.com` — and codeload only honors the same `Authorization`
//! header if the client resends it explicitly (browsers/most HTTP clients'
//! default redirect handling strips `Authorization` across a host change).
//! [`fetch_github_zip`] therefore disables `reqwest`'s automatic redirect
//! handling and re-issues the follow-up request itself with the same
//! header, rather than relying on default redirect behavior.

use std::path::Path;

use reqwest::Client;

use crate::git_provider::{self, GitCredentials};

const USER_AGENT: &str = "skauswatch-worker-codescan (sentinel-tools)";

/// Hard cap on the archive's *compressed* download size — refuses to buffer
/// an unbounded response body in memory. 200 MiB comfortably covers any
/// legitimate application repo; anything bigger is almost certainly a
/// monorepo or binary-asset-heavy repo Sentinel's tool registry isn't meant
/// to scan wholesale in P2. Enforced via `Content-Length` when the server
/// sends one, and re-checked against the actual downloaded size afterward —
/// a server that omits `Content-Length` (or lies about it) can still cause
/// one oversized buffer allocation before the post-hoc check catches it;
/// see module docs for why a true streaming cap (needing `futures`'
/// `StreamExt`, not otherwise a dependency here) was not worth adding for a
/// P2 tool-scan pipeline that already treats a fetch failure as
/// skip-this-branch's-tool-scan rather than fatal.
const MAX_ARCHIVE_BYTES: u64 = 200 * 1024 * 1024;

/// Hard cap on total *extracted* bytes, checked against the zip's central
/// directory (`ZipFile::size()`) before any file is written to disk — a
/// zip-bomb defense independent of the compressed-size cap above.
const MAX_EXTRACTED_BYTES: u64 = 1024 * 1024 * 1024;

/// A fetched, extracted working copy of one (repo, branch) tree. Owns a
/// [`tempfile::TempDir`], which removes the directory on drop — callers
/// never need to remember cleanup on any early-return/error path in the
/// scan pipeline.
#[derive(Debug)]
pub struct WorkingTree {
    dir: tempfile::TempDir,
    /// Every regular file's path relative to the tree root, forward-slash
    /// separated — used by `scanner_tool::ScannerTool::is_applicable` for
    /// cheap applicability detection without re-walking the filesystem per
    /// tool.
    files: Vec<String>,
}

impl WorkingTree {
    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    pub fn files(&self) -> &[String] {
        &self.files
    }
}

/// Fetches and extracts `branch`'s tree for `repo_url` via `provider`'s zip
/// archive endpoint. Every failure (unsupported provider, HTTP error,
/// oversized archive, corrupt zip) is a plain `Err` — callers treat a
/// failure here as "skip tool-based scanning for this branch this run",
/// never as a reason to fail the whole branch scan (P1's manifest-based
/// SCA/CVE scan is unaffected either way).
pub async fn fetch_branch_tree(
    provider: &str,
    repo_url: &str,
    branch: &str,
    creds: &GitCredentials,
) -> anyhow::Result<WorkingTree> {
    let bytes = match provider.to_lowercase().as_str() {
        "github" => fetch_github_zip(repo_url, branch, creds).await?,
        "gitlab" => fetch_gitlab_zip(repo_url, branch, creds).await?,
        _ => anyhow::bail!("unsupported provider: {}", creds.provider),
    };
    extract_zip(&bytes)
}

async fn fetch_github_zip(
    repo_url: &str,
    branch: &str,
    creds: &GitCredentials,
) -> anyhow::Result<Vec<u8>> {
    let (owner, repo) = git_provider::parse_github_repo(repo_url)?;
    let api = creds
        .base_url
        .as_deref()
        .unwrap_or("https://api.github.com");
    let url = format!(
        "{api}/repos/{owner}/{repo}/zipball/{}",
        urlencoding::encode(branch)
    );
    let auth_header = format!("token {}", creds.token);

    // Redirects disabled deliberately — see module docs' Known limitation.
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let resp = client
        .get(&url)
        .header("Authorization", &auth_header)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .send()
        .await?;

    let resp = if resp.status().is_redirection() {
        let location = resp
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| anyhow::anyhow!("github zipball redirected with no Location header"))?
            .to_owned();
        client
            .get(&location)
            .header("Authorization", &auth_header)
            .header("User-Agent", USER_AGENT)
            .send()
            .await?
    } else {
        resp
    };

    if !resp.status().is_success() {
        anyhow::bail!("github zipball error: {}", resp.status());
    }
    download_capped(resp).await
}

async fn fetch_gitlab_zip(
    repo_url: &str,
    branch: &str,
    creds: &GitCredentials,
) -> anyhow::Result<Vec<u8>> {
    let project_path = git_provider::parse_gitlab_project_path(repo_url)?;
    let host = creds
        .base_url
        .as_deref()
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/repository/archive.zip?sha={}",
        urlencoding::encode(&project_path),
        urlencoding::encode(branch)
    );
    let resp = Client::new()
        .get(&url)
        .header("PRIVATE-TOKEN", &creds.token)
        .header("User-Agent", USER_AGENT)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("gitlab archive error: {}", resp.status());
    }
    download_capped(resp).await
}

async fn download_capped(resp: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    download_capped_max(resp, MAX_ARCHIVE_BYTES).await
}

async fn download_capped_max(resp: reqwest::Response, max_bytes: u64) -> anyhow::Result<Vec<u8>> {
    if let Some(len) = resp.content_length()
        && len > max_bytes
    {
        anyhow::bail!("archive exceeds size cap: {len} bytes (max {max_bytes})");
    }
    let bytes = resp.bytes().await?;
    let actual = bytes.len() as u64;
    if actual > max_bytes {
        anyhow::bail!("archive exceeds size cap during download: {actual} bytes (max {max_bytes})");
    }
    Ok(bytes.to_vec())
}

fn extract_zip(bytes: &[u8]) -> anyhow::Result<WorkingTree> {
    extract_zip_capped(bytes, MAX_EXTRACTED_BYTES)
}

fn extract_zip_capped(bytes: &[u8], max_extracted_bytes: u64) -> anyhow::Result<WorkingTree> {
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor)?;

    // Sum the central directory's declared uncompressed sizes before
    // extracting anything — a zip-bomb defense that never writes a byte to
    // disk for an archive that fails the check.
    let mut total_uncompressed: u64 = 0;
    for i in 0..archive.len() {
        let entry = archive.by_index(i)?;
        total_uncompressed += entry.size();
    }
    if total_uncompressed > max_extracted_bytes {
        anyhow::bail!(
            "archive exceeds extracted-size cap: {total_uncompressed} bytes \
             (max {max_extracted_bytes})"
        );
    }

    let dir = tempfile::Builder::new()
        .prefix("codescan-sentinel-")
        .tempdir()?;
    // Sanitizes every entry path via `ZipFile::enclosed_name` (rejects
    // zip-slip paths) and detects+strips the single top-level directory
    // every GitHub/GitLab branch archive wraps its contents in.
    archive.extract_unwrapped_root_dir(dir.path(), zip::read::root_dir_common_filter)?;

    let files = list_files_relative(dir.path());
    Ok(WorkingTree { dir, files })
}

fn list_files_relative(root: &Path) -> Vec<String> {
    walkdir::WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            entry
                .path()
                .strip_prefix(root)
                .ok()
                .map(|rel| rel.to_string_lossy().replace('\\', "/"))
        })
        .collect()
}

/// Only used by tests to build fixture zip archives in memory — kept out of
/// the runtime path (production archives always come from a provider's real
/// zip endpoint).
#[cfg(test)]
fn build_test_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    for (name, content) in entries {
        #[allow(clippy::unwrap_used)] // test-only fixture builder
        writer.start_file(*name, options).unwrap();
        #[allow(clippy::unwrap_used)]
        writer.write_all(content).unwrap();
    }
    #[allow(clippy::unwrap_used)]
    let cursor = writer.finish().unwrap();
    cursor.into_inner()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn extract_zip_strips_common_root_dir_and_lists_files() {
        let zip_bytes = build_test_zip(&[
            ("acme-widgets-abc123/README.md", b"hello"),
            ("acme-widgets-abc123/src/main.rs", b"fn main() {}"),
        ]);
        let tree = extract_zip(&zip_bytes).unwrap_or_else(|e| panic!("extract: {e}"));
        let mut files = tree.files().to_vec();
        files.sort_unstable();
        assert_eq!(
            files,
            vec!["README.md".to_owned(), "src/main.rs".to_owned()]
        );
        let content = std::fs::read_to_string(tree.root().join("README.md"))
            .unwrap_or_else(|e| panic!("read extracted file: {e}"));
        assert_eq!(content, "hello");
    }

    #[test]
    fn extract_zip_rejects_a_non_zip_blob() {
        assert!(extract_zip(b"not a zip file at all").is_err());
    }

    #[test]
    fn extract_zip_capped_rejects_an_archive_exceeding_the_extracted_size_cap() {
        let zip_bytes = build_test_zip(&[("repo-x/big.txt", &[0u8; 1024])]);
        let err = extract_zip_capped(&zip_bytes, 10)
            .expect_err("1024 declared bytes must exceed a 10-byte cap");
        assert!(err.to_string().contains("extracted-size cap"));
    }

    #[test]
    fn working_tree_cleans_up_its_temp_dir_on_drop() {
        let zip_bytes = build_test_zip(&[("repo-x/f.txt", b"x")]);
        let tree = extract_zip(&zip_bytes).unwrap_or_else(|e| panic!("extract: {e}"));
        let root = tree.root().to_path_buf();
        assert!(root.exists());
        drop(tree);
        assert!(!root.exists(), "temp dir must be removed once dropped");
    }

    #[tokio::test]
    async fn download_capped_max_rejects_a_response_whose_content_length_exceeds_the_cap() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/archive"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![0u8; 1000]))
            .mount(&mock)
            .await;
        let resp = reqwest::Client::new()
            .get(format!("{}/archive", mock.uri()))
            .send()
            .await
            .unwrap_or_else(|e| panic!("request: {e}"));
        let err = download_capped_max(resp, 100)
            .await
            .expect_err("1000-byte body must exceed a 100-byte cap");
        assert!(err.to_string().contains("size cap"));
    }

    #[tokio::test]
    async fn download_capped_max_accepts_a_response_within_the_cap() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/archive"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![1u8; 10]))
            .mount(&mock)
            .await;
        let resp = reqwest::Client::new()
            .get(format!("{}/archive", mock.uri()))
            .send()
            .await
            .unwrap_or_else(|e| panic!("request: {e}"));
        let bytes = download_capped_max(resp, 100)
            .await
            .unwrap_or_else(|e| panic!("download: {e}"));
        assert_eq!(bytes.len(), 10);
    }

    #[tokio::test]
    async fn fetch_branch_tree_rejects_an_unsupported_provider() {
        let creds = GitCredentials {
            provider: "bitbucket".to_owned(),
            token: "tok".to_owned(),
            base_url: None,
        };
        let err = fetch_branch_tree("bitbucket", "https://bitbucket.org/a/b", "main", &creds)
            .await
            .expect_err("unsupported provider must error");
        assert!(err.to_string().contains("unsupported provider"));
    }

    #[tokio::test]
    async fn fetch_github_zip_preserves_authorization_across_the_codeload_redirect() {
        let mock = MockServer::start().await;
        let zip_bytes = build_test_zip(&[("acme-widgets-abc123/f.txt", b"x")]);

        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/zipball/main"))
            .and(header("Authorization", "token tok"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/codeload-archive", mock.uri())),
            )
            .mount(&mock)
            .await;
        // The follow-up request to the "codeload" host must still carry the
        // same Authorization header — this is the whole point of disabling
        // reqwest's default redirect handling in `fetch_github_zip`.
        Mock::given(method("GET"))
            .and(path("/codeload-archive"))
            .and(header("Authorization", "token tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&mock)
            .await;

        let creds = GitCredentials {
            provider: "github".to_owned(),
            token: "tok".to_owned(),
            base_url: Some(mock.uri()),
        };
        let tree = fetch_branch_tree("github", "https://github.com/acme/widgets", "main", &creds)
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));
        assert_eq!(tree.files(), &["f.txt".to_owned()]);
    }

    #[tokio::test]
    async fn fetch_gitlab_zip_downloads_the_archive_directly_without_a_redirect() {
        let mock = MockServer::start().await;
        let zip_bytes = build_test_zip(&[("project-main-abc/g.txt", b"y")]);
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Fproject/repository/archive.zip",
            ))
            .and(header("PRIVATE-TOKEN", "tok"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&mock)
            .await;

        let creds = GitCredentials {
            provider: "gitlab".to_owned(),
            token: "tok".to_owned(),
            base_url: Some(mock.uri()),
        };
        let tree = fetch_branch_tree("gitlab", "https://gitlab.com/group/project", "main", &creds)
            .await
            .unwrap_or_else(|e| panic!("fetch: {e}"));
        assert_eq!(tree.files(), &["g.txt".to_owned()]);
    }

    #[tokio::test]
    async fn fetch_github_zip_surfaces_an_error_status_after_following_a_redirect() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/zipball/main"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let creds = GitCredentials {
            provider: "github".to_owned(),
            token: "tok".to_owned(),
            base_url: Some(mock.uri()),
        };
        let err = fetch_branch_tree("github", "https://github.com/acme/widgets", "main", &creds)
            .await
            .expect_err("404 must surface as an error");
        assert!(err.to_string().contains("github zipball error"));
    }
}
