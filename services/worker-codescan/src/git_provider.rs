//! GitHub/GitLab PR diff fetching via REST APIs.

use reqwest::Client;

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
}
