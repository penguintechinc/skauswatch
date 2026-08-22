//! GitHub/GitLab PR diff fetching via REST APIs, plus the repo-scoped
//! (not PR-scoped) calls CodeScan Sentinel needs
//! (docs/v2-port/v2.1-codescan-sentinel.md §9-§10): default-branch lookup,
//! branch listing, and whole-file content fetch via each provider's
//! Contents API — reusing the same `GitCredentials`/base-URL-override
//! pattern the PR-diff functions above already established.

use reqwest::Client;
const USER_AGENT: &str = "skauswatch-worker-codescan (sentinel)";

/// Git provider credentials (from codescan_git_credentials table).
#[derive(Debug, Clone)]
pub struct GitCredentials {
    pub provider: String,         // github, gitlab
    pub token: String,            // API token
    pub base_url: Option<String>, // for self-hosted GitLab
}

/// Fetch PR/MR diff from GitHub or GitLab.
/// pr_url format: "https://github.com/owner/repo/pull/123" or
///               "https://gitlab.com/group/project/-/merge_requests/456"
pub async fn fetch_pr_diff(pr_url: &str, creds: &GitCredentials) -> anyhow::Result<String> {
    match creds.provider.to_lowercase().as_str() {
        "github" => fetch_github_diff(pr_url, &creds.token, creds.base_url.as_deref()).await,
        "gitlab" => fetch_gitlab_diff(pr_url, &creds.token, creds.base_url.as_deref()).await,
        _ => Err(anyhow::anyhow!("unsupported provider: {}", creds.provider)),
    }
}

/// Fetch unified diff from a GitHub PR. `base_url` overrides the API host
/// (GitHub Enterprise, or a test double); defaults to the public API.
async fn fetch_github_diff(
    pr_url: &str,
    token: &str,
    base_url: Option<&str>,
) -> anyhow::Result<String> {
    // Parse URL: https://github.com/owner/repo/pull/123
    let parts: Vec<&str> = pr_url.trim_end_matches('/').split('/').collect();
    if parts.len() < 4 {
        anyhow::bail!("invalid github pr url");
    }

    let owner = parts[parts.len() - 4];
    let repo = parts[parts.len() - 3];
    let pr_num = parts[parts.len() - 1];

    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!("{}/repos/{}/{}/pulls/{}", api, owner, repo, pr_num);
    let client = Client::new();

    let response = client
        .get(&url)
        .header("Authorization", format!("token {}", token))
        .header("Accept", "application/vnd.github.v3.diff")
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("github api error: {}", response.status());
    }

    let diff = response.text().await?;
    Ok(diff)
}

/// Fetch unified diff from GitLab MR.
async fn fetch_gitlab_diff(
    mr_url: &str,
    token: &str,
    base_url: Option<&str>,
) -> anyhow::Result<String> {
    // Parse URL: https://gitlab.com/group/project/-/merge_requests/456
    // or self-hosted: https://gitlab.company.com/group/project/-/merge_requests/456
    let parts: Vec<&str> = mr_url.trim_end_matches('/').split('/').collect();
    if parts.len() < 2 {
        anyhow::bail!("invalid gitlab mr url");
    }

    let mr_num = parts[parts.len() - 1];

    // Extract project path (group/project) from URL
    let url_start = if let Some(idx) = mr_url.find("://") {
        mr_url[idx + 3..]
            .find('/')
            .map(|i| i + idx + 3)
            .unwrap_or(mr_url.len())
    } else {
        0
    };

    // `url_start` points at the '/' separating host from path, so
    // `mr_url[url_start..]` always has a leading slash — strip it, or
    // `project_path` below picks up a stray leading "/" that gets
    // percent-encoded into the API URL (`%2Fgroup%2Fproject` instead of
    // `group%2Fproject`), breaking every GitLab request.
    let after_domain = mr_url[url_start..].trim_start_matches('/');
    let project_path = after_domain
        .split("/-/merge_requests/")
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid gitlab mr url"))?;

    let host = base_url
        .map(|base| base.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");

    let url = format!(
        "{}/api/v4/projects/{}/merge_requests/{}/diffs",
        host,
        urlencoding::encode(project_path),
        mr_num
    );

    let client = Client::new();
    let response = client
        .get(&url)
        .header("PRIVATE-TOKEN", token)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("gitlab api error: {}", response.status());
    }

    // Parse GitLab diff response JSON and build unified diff
    let data: serde_json::Value = response.json().await?;
    let mut diff_output = String::new();

    if let Some(diffs) = data.as_array() {
        for diff in diffs {
            let Some(d) = diff.get("diff").and_then(|d| d.as_str()) else {
                continue;
            };
            // GitLab's MR-diffs endpoint returns `old_path`/`new_path`
            // alongside the hunk body but the hunk body itself usually has
            // no `--- a/`/`+++ b/` header — synthesize one so downstream
            // diff-scanning (`detection::detect_from_diff`,
            // `license_scan::extract_dependencies`) can identify touched
            // files the same way it does for GitHub's native `.diff`
            // format. Harmless when the hunk already embeds its own
            // headers (as some test fixtures / older GitLab versions do):
            // both consumers dedupe touched files into a set.
            let old_path = diff.get("old_path").and_then(|v| v.as_str());
            let new_path = diff.get("new_path").and_then(|v| v.as_str());
            if let Some(path) = new_path.or(old_path) {
                diff_output.push_str(&format!(
                    "--- a/{}\n+++ b/{}\n",
                    old_path.unwrap_or(path),
                    path
                ));
            }
            diff_output.push_str(d);
            diff_output.push('\n');
        }
    }

    Ok(diff_output)
}

/// Extracts `(owner, repo)` from a GitHub *repository* URL (not a PR url),
/// e.g. `https://github.com/acme/widgets` → `("acme", "widgets")` — used by
/// Sentinel's branch/content lookups, which operate on the repo itself.
pub fn parse_github_repo(repo_url: &str) -> anyhow::Result<(String, String)> {
    let trimmed = repo_url.trim_end_matches('/').trim_end_matches(".git");
    let (_, path) = split_host(trimmed)?;
    let mut segments = path.trim_matches('/').rsplitn(2, '/');
    let repo = segments.next().filter(|s| !s.is_empty());
    let owner = segments.next().filter(|s| !s.is_empty());
    match (owner, repo) {
        (Some(o), Some(r)) => Ok((o.to_owned(), r.to_owned())),
        _ => anyhow::bail!("invalid github repo url"),
    }
}

/// Extracts the `group[/subgroup...]/project` path from a GitLab repository
/// URL — the same path shape GitLab's `/api/v4/projects/{id}` endpoint
/// accepts as a URL-encoded string in place of a numeric project id.
pub fn parse_gitlab_project_path(repo_url: &str) -> anyhow::Result<String> {
    let trimmed = repo_url.trim_end_matches('/').trim_end_matches(".git");
    let (_, path) = split_host(trimmed)?;
    let path = path.trim_matches('/');
    if path.is_empty() {
        anyhow::bail!("invalid gitlab repo url");
    }
    Ok(path.to_owned())
}

/// Splits a URL (with or without a scheme) into `(host, path)`; shared by
/// the two repo-identifier parsers above.
fn split_host(url: &str) -> anyhow::Result<(&str, &str)> {
    let after_scheme = url.find("://").map(|i| i + 3).unwrap_or(0);
    let rest = &url[after_scheme..];
    match rest.find('/') {
        Some(idx) => Ok((&rest[..idx], &rest[idx + 1..])),
        None => anyhow::bail!("invalid repo url: no path segment"),
    }
}

/// Resolves the repo's default branch (`main`/`master`/whatever the repo
/// configures) — the first of the two branches Sentinel scans every run.
pub async fn fetch_default_branch(
    provider: &str,
    repo_url: &str,
    creds: &GitCredentials,
) -> anyhow::Result<String> {
    match provider.to_lowercase().as_str() {
        "github" => {
            fetch_github_default_branch(repo_url, &creds.token, creds.base_url.as_deref()).await
        }
        "gitlab" => {
            fetch_gitlab_default_branch(repo_url, &creds.token, creds.base_url.as_deref()).await
        }
        _ => anyhow::bail!("unsupported provider: {}", creds.provider),
    }
}

/// Lists every branch name in the repo (single page, up to 100 — a P1
/// limitation for repos with more branches than that; see module docs).
pub async fn list_branch_names(
    provider: &str,
    repo_url: &str,
    creds: &GitCredentials,
) -> anyhow::Result<Vec<String>> {
    match provider.to_lowercase().as_str() {
        "github" => list_github_branches(repo_url, &creds.token, creds.base_url.as_deref()).await,
        "gitlab" => list_gitlab_branches(repo_url, &creds.token, creds.base_url.as_deref()).await,
        _ => anyhow::bail!("unsupported provider: {}", creds.provider),
    }
}

/// Fetches one file's raw content at `git_ref` (a branch name or SHA) via
/// the provider's Contents API. `Ok(None)` means the file does not exist at
/// that ref (404) — a routine, non-fatal outcome (not every repo has every
/// manifest kind); any other failure surfaces as `Err`.
pub async fn fetch_file_at_ref(
    provider: &str,
    repo_url: &str,
    file_path: &str,
    git_ref: &str,
    creds: &GitCredentials,
) -> anyhow::Result<Option<String>> {
    match provider.to_lowercase().as_str() {
        "github" => {
            fetch_github_file(
                repo_url,
                file_path,
                git_ref,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        "gitlab" => {
            fetch_gitlab_file(
                repo_url,
                file_path,
                git_ref,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        _ => anyhow::bail!("unsupported provider: {}", creds.provider),
    }
}

async fn fetch_github_default_branch(
    repo_url: &str,
    token: &str,
    base_url: Option<&str>,
) -> anyhow::Result<String> {
    let (owner, repo) = parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!("{api}/repos/{owner}/{repo}");
    let resp = Client::new()
        .get(&url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("github api error: {}", resp.status());
    }
    let json: serde_json::Value = resp.json().await?;
    json.get("default_branch")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("github repo response missing default_branch"))
}

async fn list_github_branches(
    repo_url: &str,
    token: &str,
    base_url: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let (owner, repo) = parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!("{api}/repos/{owner}/{repo}/branches?per_page=100");
    let resp = Client::new()
        .get(&url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("github api error: {}", resp.status());
    }
    let json: Vec<serde_json::Value> = resp.json().await?;
    Ok(json
        .iter()
        .filter_map(|b| b.get("name").and_then(|v| v.as_str()))
        .map(str::to_owned)
        .collect())
}

async fn fetch_github_file(
    repo_url: &str,
    file_path: &str,
    git_ref: &str,
    token: &str,
    base_url: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let (owner, repo) = parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!(
        "{api}/repos/{owner}/{repo}/contents/{file_path}?ref={}",
        urlencoding::encode(git_ref)
    );
    let resp = Client::new()
        .get(&url)
        .header("Authorization", format!("token {token}"))
        // The raw media type returns file bytes directly instead of the
        // default JSON-wrapped base64 envelope.
        .header("Accept", "application/vnd.github.raw")
        .header("User-Agent", USER_AGENT)
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("github api error: {}", resp.status());
    }
    Ok(Some(resp.text().await?))
}

async fn fetch_gitlab_default_branch(
    repo_url: &str,
    token: &str,
    base_url: Option<&str>,
) -> anyhow::Result<String> {
    let project_path = parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}",
        urlencoding::encode(&project_path)
    );
    let resp = Client::new()
        .get(&url)
        .header("PRIVATE-TOKEN", token)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("gitlab api error: {}", resp.status());
    }
    let json: serde_json::Value = resp.json().await?;
    json.get("default_branch")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("gitlab project response missing default_branch"))
}

async fn list_gitlab_branches(
    repo_url: &str,
    token: &str,
    base_url: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let project_path = parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/repository/branches?per_page=100",
        urlencoding::encode(&project_path)
    );
    let resp = Client::new()
        .get(&url)
        .header("PRIVATE-TOKEN", token)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("gitlab api error: {}", resp.status());
    }
    let json: Vec<serde_json::Value> = resp.json().await?;
    Ok(json
        .iter()
        .filter_map(|b| b.get("name").and_then(|v| v.as_str()))
        .map(str::to_owned)
        .collect())
}

async fn fetch_gitlab_file(
    repo_url: &str,
    file_path: &str,
    git_ref: &str,
    token: &str,
    base_url: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let project_path = parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/repository/files/{}/raw?ref={}",
        urlencoding::encode(&project_path),
        urlencoding::encode(file_path),
        urlencoding::encode(git_ref)
    );
    let resp = Client::new()
        .get(&url)
        .header("PRIVATE-TOKEN", token)
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        anyhow::bail!("gitlab api error: {}", resp.status());
    }
    Ok(Some(resp.text().await?))
}

/// Picks the highest-versioned `release/*` branch by a best-effort
/// semver-ish comparison of the segment after the `release/` prefix (e.g.
/// `release/v2.1.x` > `release/v2.0.x` > `release/v1.9.x`), tolerating a
/// non-numeric trailing placeholder the way this very repo's own
/// `release/v{Major}.{Minor}.X` convention does. `None` when no branch
/// starts with `release/`.
pub fn latest_release_branch(branches: &[String]) -> Option<String> {
    branches
        .iter()
        .filter(|b| b.starts_with("release/"))
        .max_by_key(|b| release_branch_sort_key(b))
        .cloned()
}

fn release_branch_sort_key(branch: &str) -> (u64, u64, u64) {
    let version_part = branch
        .trim_start_matches("release/")
        .trim_start_matches('v');
    let mut parts = version_part.split('.');
    let major = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let minor = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    // The third segment is frequently a literal "X" placeholder (this
    // repo's own convention) — parse failure just means 0, not an error.
    let patch = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (major, minor, patch)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};

    #[test]
    fn test_parse_github_pr_url() {
        let url = "https://github.com/owner/repo/pull/123";
        let parts: Vec<&str> = url.trim_end_matches('/').split('/').collect();
        assert_eq!(parts[parts.len() - 4], "owner");
        assert_eq!(parts[parts.len() - 3], "repo");
        assert_eq!(parts[parts.len() - 1], "123");
    }

    #[test]
    fn test_parse_gitlab_mr_url() {
        let url = "https://gitlab.com/group/project/-/merge_requests/456";
        let parts: Vec<&str> = url.trim_end_matches('/').split('/').collect();
        assert_eq!(parts[parts.len() - 1], "456");
        assert!(url.contains("group/project/-/merge_requests/"));
    }

    #[tokio::test]
    async fn test_fetch_github_diff_with_mock() {
        let mock_server = MockServer::start().await;
        let diff_content =
            "--- a/file.rs\n+++ b/file.rs\n@@ -1,3 +1,4 @@\nfn test() {}\n+// Added line\n";

        Mock::given(path("/repos/owner/repo/pulls/123"))
            .respond_with(ResponseTemplate::new(200).set_body_string(diff_content))
            .mount(&mock_server)
            .await;

        // Point the GitHub API host at the mock via base_url; the PR URL is
        // parsed for owner/repo/number, so the request actually hits the mock.
        let creds = GitCredentials {
            provider: "github".to_string(),
            token: "test-token".to_string(),
            base_url: Some(mock_server.uri()),
        };

        let github_url = "https://github.com/owner/repo/pull/123";
        let result = fetch_pr_diff(github_url, &creds).await;

        assert_eq!(
            result.expect("fetch should succeed against mock"),
            diff_content
        );
    }

    #[tokio::test]
    async fn test_fetch_pr_diff_unsupported_provider() {
        let creds = GitCredentials {
            provider: "bitbucket".to_string(),
            token: "tok".to_string(),
            base_url: None,
        };
        let result = fetch_pr_diff("https://bitbucket.org/x/y/pull/1", &creds).await;
        let err = result.expect_err("unsupported provider must error");
        assert!(err.to_string().contains("unsupported provider"));
    }

    #[tokio::test]
    async fn test_fetch_github_diff_rejects_malformed_url() {
        let creds = GitCredentials {
            provider: "github".to_string(),
            token: "tok".to_string(),
            base_url: None,
        };
        let result = fetch_pr_diff("not-a-url", &creds).await;
        let err = result.expect_err("malformed github url must error");
        assert!(err.to_string().contains("invalid github pr url"));
    }

    #[tokio::test]
    async fn test_fetch_github_diff_surfaces_api_error_status() {
        let mock_server = MockServer::start().await;
        Mock::given(path("/repos/owner/repo/pulls/123"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;

        let creds = GitCredentials {
            provider: "github".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let result = fetch_pr_diff("https://github.com/owner/repo/pull/123", &creds).await;
        let err = result.expect_err("404 must surface as an error");
        assert!(err.to_string().contains("github api error"));
    }

    #[tokio::test]
    async fn test_fetch_gitlab_diff_with_mock() {
        let mock_server = MockServer::start().await;
        Mock::given(path(
            "/api/v4/projects/group%2Fproject/merge_requests/456/diffs",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"diff": "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y"},
            {"diff": "--- a/g\n+++ b/g\n@@ -1 +1 @@\n-1\n+2"},
        ])))
        .mount(&mock_server)
        .await;

        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let result = fetch_pr_diff(
            "https://gitlab.com/group/project/-/merge_requests/456",
            &creds,
        )
        .await;
        let diff = result.expect("fetch should succeed against mock");
        assert!(diff.contains("-x\n+y"));
        assert!(diff.contains("-1\n+2"));
    }

    #[tokio::test]
    async fn test_fetch_gitlab_diff_self_hosted_base_url_trims_trailing_slash() {
        let mock_server = MockServer::start().await;
        Mock::given(path(
            "/api/v4/projects/group%2Fproject/merge_requests/1/diffs",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&mock_server)
        .await;

        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            // Trailing slash must be trimmed before building the API URL.
            base_url: Some(format!("{}/", mock_server.uri())),
        };
        let result = fetch_pr_diff(
            "https://gitlab.company.com/group/project/-/merge_requests/1",
            &creds,
        )
        .await;
        assert_eq!(result.expect("fetch should succeed"), "");
    }

    #[tokio::test]
    async fn test_fetch_gitlab_diff_surfaces_api_error_status() {
        let mock_server = MockServer::start().await;
        Mock::given(path(
            "/api/v4/projects/group%2Fproject/merge_requests/9/diffs",
        ))
        .respond_with(ResponseTemplate::new(500))
        .mount(&mock_server)
        .await;

        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let result = fetch_pr_diff(
            "https://gitlab.com/group/project/-/merge_requests/9",
            &creds,
        )
        .await;
        let err = result.expect_err("500 must surface as an error");
        assert!(err.to_string().contains("gitlab api error"));
    }

    #[tokio::test]
    async fn test_fetch_gitlab_diff_rejects_malformed_url() {
        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            base_url: None,
        };
        // A single path segment (no slashes at all) trips the `parts.len() <
        // 2` guard in fetch_gitlab_diff.
        let result = fetch_pr_diff("nakedstring", &creds).await;
        let err = result.expect_err("malformed gitlab url must error");
        assert!(err.to_string().contains("invalid gitlab mr url"));
    }

    #[tokio::test]
    async fn test_fetch_gitlab_diff_without_a_url_scheme() {
        let mock_server = MockServer::start().await;
        Mock::given(path(
            "/api/v4/projects/gitlab.example.com%2Fgroup%2Fproject/merge_requests/12/diffs",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&mock_server)
        .await;

        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        // No "://" at all — exercises the `mr_url.find("://")` `None` arm
        // (url_start falls back to 0, so the whole string is treated as the
        // path, including the host segment).
        let result = fetch_pr_diff(
            "gitlab.example.com/group/project/-/merge_requests/12",
            &creds,
        )
        .await;
        assert_eq!(result.expect("fetch should succeed against mock"), "");
    }

    #[tokio::test]
    async fn test_fetch_gitlab_diff_tolerates_non_array_response_body() {
        let mock_server = MockServer::start().await;
        Mock::given(path(
            "/api/v4/projects/group%2Fproject/merge_requests/3/diffs",
        ))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"error": "oops"})),
        )
        .mount(&mock_server)
        .await;

        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        // A 200 response whose body isn't a JSON array (`data.as_array()` is
        // `None`) must not panic — it just yields no diff content.
        let result = fetch_pr_diff(
            "https://gitlab.com/group/project/-/merge_requests/3",
            &creds,
        )
        .await;
        assert_eq!(result.expect("fetch should succeed against mock"), "");
    }

    #[test]
    fn test_review_comment_parsing() {
        let json = r#"[
            {
                "line_start": 10,
                "severity": "critical",
                "title": "Security Issue",
                "body": "Hardcoded secret"
            }
        ]"#;

        let parsed = serde_json::from_str::<Vec<serde_json::Value>>(json);
        assert!(parsed.is_ok());
        let values = parsed.unwrap();
        assert_eq!(values.len(), 1);
        assert_eq!(
            values[0].get("title").and_then(|t| t.as_str()),
            Some("Security Issue")
        );
    }

    #[test]
    fn parse_github_repo_extracts_owner_and_name() {
        let (owner, repo) = parse_github_repo("https://github.com/acme/widgets")
            .expect("should parse a well-formed url");
        assert_eq!(owner, "acme");
        assert_eq!(repo, "widgets");
    }

    #[test]
    fn parse_github_repo_tolerates_trailing_slash_and_dot_git() {
        let (owner, repo) =
            parse_github_repo("https://github.com/acme/widgets.git/").expect("should parse");
        assert_eq!(owner, "acme");
        assert_eq!(repo, "widgets");
    }

    #[test]
    fn parse_github_repo_rejects_missing_path() {
        assert!(parse_github_repo("https://github.com").is_err());
        assert!(parse_github_repo("https://github.com/acme").is_err());
    }

    #[test]
    fn parse_gitlab_project_path_extracts_nested_group() {
        let path = parse_gitlab_project_path("https://gitlab.com/group/subgroup/project")
            .expect("should parse");
        assert_eq!(path, "group/subgroup/project");
    }

    #[test]
    fn parse_gitlab_project_path_rejects_empty_path() {
        assert!(parse_gitlab_project_path("https://gitlab.com").is_err());
    }

    #[tokio::test]
    async fn fetch_default_branch_dispatches_to_github() {
        let mock_server = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"default_branch": "main"})),
            )
            .mount(&mock_server)
            .await;
        let creds = GitCredentials {
            provider: "github".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let branch = fetch_default_branch("github", "https://github.com/acme/widgets", &creds)
            .await
            .expect("fetch should succeed");
        assert_eq!(branch, "main");
    }

    #[tokio::test]
    async fn fetch_default_branch_dispatches_to_gitlab() {
        let mock_server = MockServer::start().await;
        Mock::given(path("/api/v4/projects/group%2Fproject"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"default_branch": "develop"})),
            )
            .mount(&mock_server)
            .await;
        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let branch = fetch_default_branch("gitlab", "https://gitlab.com/group/project", &creds)
            .await
            .expect("fetch should succeed");
        assert_eq!(branch, "develop");
    }

    #[tokio::test]
    async fn fetch_default_branch_rejects_unsupported_provider() {
        let creds = GitCredentials {
            provider: "bitbucket".to_string(),
            token: "tok".to_string(),
            base_url: None,
        };
        let err = fetch_default_branch("bitbucket", "https://bitbucket.org/a/b", &creds)
            .await
            .expect_err("unsupported provider must error");
        assert!(err.to_string().contains("unsupported provider"));
    }

    #[tokio::test]
    async fn list_branch_names_returns_github_branch_list() {
        let mock_server = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/branches"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"name": "main"},
                {"name": "release/v1.0.x"},
            ])))
            .mount(&mock_server)
            .await;
        let creds = GitCredentials {
            provider: "github".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let branches = list_branch_names("github", "https://github.com/acme/widgets", &creds)
            .await
            .expect("list should succeed");
        assert_eq!(branches, vec!["main", "release/v1.0.x"]);
    }

    #[tokio::test]
    async fn list_branch_names_returns_gitlab_branch_list() {
        let mock_server = MockServer::start().await;
        Mock::given(path("/api/v4/projects/group%2Fproject/repository/branches"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!([{"name": "main"}, {"name": "staging"}])),
            )
            .mount(&mock_server)
            .await;
        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let branches = list_branch_names("gitlab", "https://gitlab.com/group/project", &creds)
            .await
            .expect("list should succeed");
        assert_eq!(branches, vec!["main", "staging"]);
    }

    #[tokio::test]
    async fn fetch_file_at_ref_returns_content_for_github() {
        let mock_server = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/contents/package.json"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"name\": \"widgets\"}"))
            .mount(&mock_server)
            .await;
        let creds = GitCredentials {
            provider: "github".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let content = fetch_file_at_ref(
            "github",
            "https://github.com/acme/widgets",
            "package.json",
            "main",
            &creds,
        )
        .await
        .expect("fetch should succeed");
        assert_eq!(content.as_deref(), Some("{\"name\": \"widgets\"}"));
    }

    #[tokio::test]
    async fn fetch_file_at_ref_returns_none_on_404_for_github() {
        let mock_server = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/contents/go.mod"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock_server)
            .await;
        let creds = GitCredentials {
            provider: "github".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let content = fetch_file_at_ref(
            "github",
            "https://github.com/acme/widgets",
            "go.mod",
            "main",
            &creds,
        )
        .await
        .expect("a missing manifest is Ok(None), not an error");
        assert_eq!(content, None);
    }

    #[tokio::test]
    async fn fetch_file_at_ref_returns_content_for_gitlab() {
        let mock_server = MockServer::start().await;
        Mock::given(path(
            "/api/v4/projects/group%2Fproject/repository/files/Cargo.toml/raw",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_string("[package]\nname = \"x\"\n"))
        .mount(&mock_server)
        .await;
        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let content = fetch_file_at_ref(
            "gitlab",
            "https://gitlab.com/group/project",
            "Cargo.toml",
            "main",
            &creds,
        )
        .await
        .expect("fetch should succeed");
        assert_eq!(content.as_deref(), Some("[package]\nname = \"x\"\n"));
    }

    #[tokio::test]
    async fn fetch_file_at_ref_returns_none_on_404_for_gitlab() {
        let mock_server = MockServer::start().await;
        Mock::given(path(
            "/api/v4/projects/group%2Fproject/repository/files/requirements.txt/raw",
        ))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;
        let creds = GitCredentials {
            provider: "gitlab".to_string(),
            token: "tok".to_string(),
            base_url: Some(mock_server.uri()),
        };
        let content = fetch_file_at_ref(
            "gitlab",
            "https://gitlab.com/group/project",
            "requirements.txt",
            "main",
            &creds,
        )
        .await
        .expect("a missing manifest is Ok(None), not an error");
        assert_eq!(content, None);
    }

    #[test]
    fn latest_release_branch_picks_the_highest_semver() {
        let branches = vec![
            "main".to_owned(),
            "release/v1.0.x".to_owned(),
            "release/v2.1.x".to_owned(),
            "release/v2.0.x".to_owned(),
        ];
        assert_eq!(
            latest_release_branch(&branches),
            Some("release/v2.1.x".to_owned())
        );
    }

    #[test]
    fn latest_release_branch_is_none_without_a_release_branch() {
        let branches = vec!["main".to_owned(), "develop".to_owned()];
        assert_eq!(latest_release_branch(&branches), None);
    }

    #[test]
    fn latest_release_branch_tolerates_non_numeric_patch_placeholder() {
        // This repo's own convention (`release/v{Major}.{Minor}.X`) uses a
        // literal `X`, not a number — must not be treated as a parse error.
        let branches = vec!["release/v1.2.X".to_owned(), "release/v1.1.X".to_owned()];
        assert_eq!(
            latest_release_branch(&branches),
            Some("release/v1.2.X".to_owned())
        );
    }
}
