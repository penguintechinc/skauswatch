//! GitHub/GitLab REST *write* path for CodeScan Sentinel's grouped auto-fix
//! (P4, docs/v2-port/v2.1-codescan-sentinel.md §7): branch creation, file
//! commits, PR/MR open + body update, and open-PR lookup by head branch.
//! `git_provider` stays read-only (PR diffs, default branch, branch
//! listing, whole-file fetch) — this module adds only the mutating calls
//! `fix.rs` needs, sharing `GitCredentials` and the repo-URL parsers rather
//! than forking them.
//!
//! Every function distinguishes [`GitWriteError::Forbidden`] (401/403 — the
//! stored token lacks write scope) from every other failure
//! ([`GitWriteError::Other`]): `fix.rs` treats the former as a safe,
//! expected condition to record and fall back from, never a crash or a
//! retry loop (spec §7: "human-gated", never silently dropped).

use base64::Engine as _;
use reqwest::{Client, StatusCode};

use crate::git_provider::{self, GitCredentials};

const USER_AGENT: &str = "skauswatch-worker-codescan (sentinel-fix)";

/// A git write-path failure. See module docs for why `Forbidden` is its own
/// variant rather than folding into `Other`.
#[derive(Debug)]
pub enum GitWriteError {
    /// The credential doesn't have write access (HTTP 401/403) — a
    /// configuration problem the caller must surface, not retry.
    Forbidden(String),
    Other(anyhow::Error),
}

impl std::fmt::Display for GitWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitWriteError::Forbidden(msg) => write!(f, "git write forbidden: {msg}"),
            GitWriteError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GitWriteError {}

impl From<anyhow::Error> for GitWriteError {
    fn from(e: anyhow::Error) -> Self {
        GitWriteError::Other(e)
    }
}

fn classify(status: StatusCode, context: &str) -> GitWriteError {
    if status == StatusCode::FORBIDDEN || status == StatusCode::UNAUTHORIZED {
        GitWriteError::Forbidden(format!("{context}: {status}"))
    } else {
        GitWriteError::Other(anyhow::anyhow!("{context}: {status}"))
    }
}

/// One file's content + the identifier needed to update it in place.
/// `sha` is `Some` for GitHub (its contents-update API requires the
/// current blob sha) and always `None` for GitLab (its file-update API
/// takes no such precondition).
#[derive(Debug)]
pub struct FileAtRef {
    pub content: String,
    pub sha: Option<String>,
}

/// One PR/MR, as returned by [`open_pull_request`] and [`list_open_prs_by_head`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrRef {
    pub number: i64,
    pub url: String,
}

/// The tracked PR/MR's current state, for deciding whether an
/// already-known [`crate::db::FixBatchRecord`] is still the batch to keep
/// updating or whether the next fix must start a fresh one (spec §7:
/// "merge → fresh batch").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrState {
    Open,
    Merged,
    Closed,
}

/// Fetches one file's content *and* its update precondition (GitHub sha) at
/// `git_ref`. Unlike `git_provider::fetch_file_at_ref` (which requests the
/// raw-bytes media type to avoid a base64 dependency on the read-only path),
/// this always requests GitHub's default JSON envelope — the only response
/// shape that carries `sha`. `Ok(None)` means the file does not exist at
/// that ref (404), mirroring `git_provider`'s convention.
pub async fn fetch_file_with_sha(
    provider: &str,
    repo_url: &str,
    file_path: &str,
    git_ref: &str,
    creds: &GitCredentials,
) -> Result<Option<FileAtRef>, GitWriteError> {
    match provider.to_lowercase().as_str() {
        "github" => {
            github_fetch_file_with_sha(
                repo_url,
                file_path,
                git_ref,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        "gitlab" => {
            gitlab_fetch_file_with_sha(
                repo_url,
                file_path,
                git_ref,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        _ => Err(GitWriteError::Other(anyhow::anyhow!(
            "unsupported provider: {}",
            creds.provider
        ))),
    }
}

async fn github_fetch_file_with_sha(
    repo_url: &str,
    file_path: &str,
    git_ref: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<Option<FileAtRef>, GitWriteError> {
    let (owner, repo) = git_provider::parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!(
        "{api}/repos/{owner}/{repo}/contents/{file_path}?ref={}",
        urlencoding::encode(git_ref)
    );
    let resp = Client::new()
        .get(&url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "github fetch file"));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    let sha = json.get("sha").and_then(|v| v.as_str()).map(str::to_owned);
    let encoded = json
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            GitWriteError::Other(anyhow::anyhow!("github contents response missing content"))
        })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.replace(['\n', '\r'], ""))
        .map_err(|e| GitWriteError::Other(anyhow::anyhow!("github contents base64 decode: {e}")))?;
    let content = String::from_utf8(decoded)
        .map_err(|e| GitWriteError::Other(anyhow::anyhow!("github contents utf8 decode: {e}")))?;
    Ok(Some(FileAtRef { content, sha }))
}

async fn gitlab_fetch_file_with_sha(
    repo_url: &str,
    file_path: &str,
    git_ref: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<Option<FileAtRef>, GitWriteError> {
    let project_path = git_provider::parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/repository/files/{}?ref={}",
        urlencoding::encode(&project_path),
        urlencoding::encode(file_path),
        urlencoding::encode(git_ref)
    );
    let resp = Client::new()
        .get(&url)
        .header("PRIVATE-TOKEN", token)
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "gitlab fetch file"));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    let encoded = json
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            GitWriteError::Other(anyhow::anyhow!("gitlab file response missing content"))
        })?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.replace(['\n', '\r'], ""))
        .map_err(|e| GitWriteError::Other(anyhow::anyhow!("gitlab file base64 decode: {e}")))?;
    let content = String::from_utf8(decoded)
        .map_err(|e| GitWriteError::Other(anyhow::anyhow!("gitlab file utf8 decode: {e}")))?;
    // GitLab's file-update API needs no precondition sha.
    Ok(Some(FileAtRef { content, sha: None }))
}

/// Idempotently ensures `branch` exists, created from `base_branch`'s
/// current tip. A branch that already exists (a prior batch's leftover, or
/// a concurrent scheduler tick) is treated as success rather than an
/// error — safe because every commit this module makes is a content-level
/// update via the provider's contents API, never a reset/force-push, so
/// reusing a pre-existing branch never loses history.
pub async fn ensure_branch(
    provider: &str,
    repo_url: &str,
    branch: &str,
    base_branch: &str,
    creds: &GitCredentials,
) -> Result<(), GitWriteError> {
    match provider.to_lowercase().as_str() {
        "github" => {
            github_ensure_branch(
                repo_url,
                branch,
                base_branch,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        "gitlab" => {
            gitlab_ensure_branch(
                repo_url,
                branch,
                base_branch,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        _ => Err(GitWriteError::Other(anyhow::anyhow!(
            "unsupported provider: {}",
            creds.provider
        ))),
    }
}

async fn github_ensure_branch(
    repo_url: &str,
    branch: &str,
    base_branch: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<(), GitWriteError> {
    let (owner, repo) = git_provider::parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let client = Client::new();

    let ref_url = format!("{api}/repos/{owner}/{repo}/git/ref/heads/{base_branch}");
    let resp = client
        .get(&ref_url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "github get base ref"));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    let base_sha = json
        .get("object")
        .and_then(|o| o.get("sha"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            GitWriteError::Other(anyhow::anyhow!("github base ref response missing sha"))
        })?;

    let create_url = format!("{api}/repos/{owner}/{repo}/git/refs");
    let resp = client
        .post(&create_url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .json(&serde_json::json!({ "ref": format!("refs/heads/{branch}"), "sha": base_sha }))
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if resp.status().is_success() {
        return Ok(());
    }
    // GitHub returns 422 "Reference already exists" — idempotent no-op.
    if resp.status() == StatusCode::UNPROCESSABLE_ENTITY {
        return Ok(());
    }
    Err(classify(resp.status(), "github create branch"))
}

async fn gitlab_ensure_branch(
    repo_url: &str,
    branch: &str,
    base_branch: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<(), GitWriteError> {
    let project_path = git_provider::parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/repository/branches?branch={}&ref={}",
        urlencoding::encode(&project_path),
        urlencoding::encode(branch),
        urlencoding::encode(base_branch)
    );
    let resp = Client::new()
        .post(&url)
        .header("PRIVATE-TOKEN", token)
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if resp.status().is_success() {
        return Ok(());
    }
    // GitLab returns 400 with a "Branch already exists" body — idempotent no-op.
    if resp.status() == StatusCode::BAD_REQUEST {
        return Ok(());
    }
    Err(classify(resp.status(), "gitlab create branch"))
}

/// Commits a single file update onto `branch` — always an update (the
/// manifest already exists; this is a version bump, never a new file).
pub async fn commit_file_update(
    provider: &str,
    repo_url: &str,
    branch: &str,
    file_path: &str,
    new_content: &str,
    message: &str,
    creds: &GitCredentials,
) -> Result<(), GitWriteError> {
    match provider.to_lowercase().as_str() {
        "github" => {
            github_commit_file(
                repo_url,
                branch,
                file_path,
                new_content,
                message,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        "gitlab" => {
            gitlab_commit_file(
                repo_url,
                branch,
                file_path,
                new_content,
                message,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        _ => Err(GitWriteError::Other(anyhow::anyhow!(
            "unsupported provider: {}",
            creds.provider
        ))),
    }
}

async fn github_commit_file(
    repo_url: &str,
    branch: &str,
    file_path: &str,
    new_content: &str,
    message: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<(), GitWriteError> {
    // Needs the file's current sha *on this branch* — the batch branch may
    // already carry earlier fix commits, so this must not reuse a sha
    // fetched from the base branch.
    let current = github_fetch_file_with_sha(repo_url, file_path, branch, token, base_url).await?;
    let sha = current.and_then(|f| f.sha).ok_or_else(|| {
        GitWriteError::Other(anyhow::anyhow!(
            "github: file to update not found on branch {branch}"
        ))
    })?;

    let (owner, repo) = git_provider::parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!("{api}/repos/{owner}/{repo}/contents/{file_path}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(new_content);
    let resp = Client::new()
        .put(&url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .json(&serde_json::json!({
            "message": message,
            "content": encoded,
            "sha": sha,
            "branch": branch,
        }))
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if resp.status().is_success() {
        return Ok(());
    }
    Err(classify(resp.status(), "github commit file"))
}

async fn gitlab_commit_file(
    repo_url: &str,
    branch: &str,
    file_path: &str,
    new_content: &str,
    message: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<(), GitWriteError> {
    let project_path = git_provider::parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/repository/files/{}",
        urlencoding::encode(&project_path),
        urlencoding::encode(file_path)
    );
    let resp = Client::new()
        .put(&url)
        .header("PRIVATE-TOKEN", token)
        .json(&serde_json::json!({
            "branch": branch,
            "content": new_content,
            "commit_message": message,
        }))
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if resp.status().is_success() {
        return Ok(());
    }
    Err(classify(resp.status(), "gitlab commit file"))
}

/// Opens a new PR/MR (`head_branch` → `base_branch`) — only ever called
/// once per batch, on the run that first has at least one successful edit.
pub async fn open_pull_request(
    provider: &str,
    repo_url: &str,
    head_branch: &str,
    base_branch: &str,
    title: &str,
    body: &str,
    creds: &GitCredentials,
) -> Result<PrRef, GitWriteError> {
    match provider.to_lowercase().as_str() {
        "github" => {
            github_open_pr(
                repo_url,
                head_branch,
                base_branch,
                title,
                body,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        "gitlab" => {
            gitlab_open_mr(
                repo_url,
                head_branch,
                base_branch,
                title,
                body,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        _ => Err(GitWriteError::Other(anyhow::anyhow!(
            "unsupported provider: {}",
            creds.provider
        ))),
    }
}

async fn github_open_pr(
    repo_url: &str,
    head_branch: &str,
    base_branch: &str,
    title: &str,
    body: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<PrRef, GitWriteError> {
    let (owner, repo) = git_provider::parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!("{api}/repos/{owner}/{repo}/pulls");
    let resp = Client::new()
        .post(&url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .json(&serde_json::json!({ "title": title, "head": head_branch, "base": base_branch, "body": body }))
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "github open pr"));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    parse_github_pr_ref(&json)
}

fn parse_github_pr_ref(json: &serde_json::Value) -> Result<PrRef, GitWriteError> {
    let number = json
        .get("number")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| {
            GitWriteError::Other(anyhow::anyhow!("github pr response missing number"))
        })?;
    let url = json
        .get("html_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    Ok(PrRef { number, url })
}

async fn gitlab_open_mr(
    repo_url: &str,
    head_branch: &str,
    base_branch: &str,
    title: &str,
    body: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<PrRef, GitWriteError> {
    let project_path = git_provider::parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/merge_requests",
        urlencoding::encode(&project_path)
    );
    let resp = Client::new()
        .post(&url)
        .header("PRIVATE-TOKEN", token)
        .json(&serde_json::json!({
            "source_branch": head_branch,
            "target_branch": base_branch,
            "title": title,
            "description": body,
        }))
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "gitlab open mr"));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    parse_gitlab_mr_ref(&json)
}

fn parse_gitlab_mr_ref(json: &serde_json::Value) -> Result<PrRef, GitWriteError> {
    let number = json
        .get("iid")
        .and_then(serde_json::Value::as_i64)
        .ok_or_else(|| GitWriteError::Other(anyhow::anyhow!("gitlab mr response missing iid")))?;
    let url = json
        .get("web_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_owned();
    Ok(PrRef { number, url })
}

/// Regenerates a PR/MR's body in place — called every run a batch gains a
/// new fix, so the itemized list always reflects the batch's full current
/// contents (spec §7: "keep it regenerated, not appended").
pub async fn update_pull_request_body(
    provider: &str,
    repo_url: &str,
    pr_number: i64,
    body: &str,
    creds: &GitCredentials,
) -> Result<(), GitWriteError> {
    match provider.to_lowercase().as_str() {
        "github" => {
            github_update_pr_body(
                repo_url,
                pr_number,
                body,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        "gitlab" => {
            gitlab_update_mr_body(
                repo_url,
                pr_number,
                body,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        _ => Err(GitWriteError::Other(anyhow::anyhow!(
            "unsupported provider: {}",
            creds.provider
        ))),
    }
}

async fn github_update_pr_body(
    repo_url: &str,
    pr_number: i64,
    body: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<(), GitWriteError> {
    let (owner, repo) = git_provider::parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!("{api}/repos/{owner}/{repo}/pulls/{pr_number}");
    let resp = Client::new()
        .patch(&url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .json(&serde_json::json!({ "body": body }))
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if resp.status().is_success() {
        return Ok(());
    }
    Err(classify(resp.status(), "github update pr body"))
}

async fn gitlab_update_mr_body(
    repo_url: &str,
    pr_number: i64,
    body: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<(), GitWriteError> {
    let project_path = git_provider::parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/merge_requests/{pr_number}",
        urlencoding::encode(&project_path)
    );
    let resp = Client::new()
        .put(&url)
        .header("PRIVATE-TOKEN", token)
        .json(&serde_json::json!({ "description": body }))
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if resp.status().is_success() {
        return Ok(());
    }
    Err(classify(resp.status(), "gitlab update mr body"))
}

/// Lists every currently-open PR/MR whose head/source branch is exactly
/// `head_branch` — used both to check a tracked batch is still open and,
/// before creating a brand new batch, to guard against a stray already-open
/// PR on the deterministic branch name (crash recovery / manual state) so
/// the anti-sprawl invariant (spec §7) holds even if this worker's own DB
/// row was somehow lost.
pub async fn list_open_prs_by_head(
    provider: &str,
    repo_url: &str,
    head_branch: &str,
    creds: &GitCredentials,
) -> Result<Vec<PrRef>, GitWriteError> {
    match provider.to_lowercase().as_str() {
        "github" => {
            github_list_open_prs(
                repo_url,
                head_branch,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        "gitlab" => {
            gitlab_list_open_mrs(
                repo_url,
                head_branch,
                &creds.token,
                creds.base_url.as_deref(),
            )
            .await
        }
        _ => Err(GitWriteError::Other(anyhow::anyhow!(
            "unsupported provider: {}",
            creds.provider
        ))),
    }
}

async fn github_list_open_prs(
    repo_url: &str,
    head_branch: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<Vec<PrRef>, GitWriteError> {
    let (owner, repo) = git_provider::parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!("{api}/repos/{owner}/{repo}/pulls?state=open&head={owner}:{head_branch}");
    let resp = Client::new()
        .get(&url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "github list prs"));
    }
    let json: Vec<serde_json::Value> = resp
        .json()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    json.iter().map(parse_github_pr_ref).collect()
}

async fn gitlab_list_open_mrs(
    repo_url: &str,
    head_branch: &str,
    token: &str,
    base_url: Option<&str>,
) -> Result<Vec<PrRef>, GitWriteError> {
    let project_path = git_provider::parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/merge_requests?state=opened&source_branch={}",
        urlencoding::encode(&project_path),
        urlencoding::encode(head_branch)
    );
    let resp = Client::new()
        .get(&url)
        .header("PRIVATE-TOKEN", token)
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "gitlab list mrs"));
    }
    let json: Vec<serde_json::Value> = resp
        .json()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    json.iter().map(parse_gitlab_mr_ref).collect()
}

/// Fetches one PR/MR's current state — used to decide whether a tracked
/// [`crate::db::FixBatchRecord`] is still live before piling another commit
/// onto it (spec §7: "updated in place until merged").
pub async fn get_pull_request_state(
    provider: &str,
    repo_url: &str,
    pr_number: i64,
    creds: &GitCredentials,
) -> Result<PrState, GitWriteError> {
    match provider.to_lowercase().as_str() {
        "github" => {
            github_pr_state(repo_url, pr_number, &creds.token, creds.base_url.as_deref()).await
        }
        "gitlab" => {
            gitlab_mr_state(repo_url, pr_number, &creds.token, creds.base_url.as_deref()).await
        }
        _ => Err(GitWriteError::Other(anyhow::anyhow!(
            "unsupported provider: {}",
            creds.provider
        ))),
    }
}

async fn github_pr_state(
    repo_url: &str,
    pr_number: i64,
    token: &str,
    base_url: Option<&str>,
) -> Result<PrState, GitWriteError> {
    let (owner, repo) = git_provider::parse_github_repo(repo_url)?;
    let api = base_url.unwrap_or("https://api.github.com");
    let url = format!("{api}/repos/{owner}/{repo}/pulls/{pr_number}");
    let resp = Client::new()
        .get(&url)
        .header("Authorization", format!("token {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", USER_AGENT)
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "github get pr"));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    let merged = json
        .get("merged")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let state = json.get("state").and_then(|v| v.as_str()).unwrap_or("open");
    Ok(if merged {
        PrState::Merged
    } else if state == "closed" {
        PrState::Closed
    } else {
        PrState::Open
    })
}

async fn gitlab_mr_state(
    repo_url: &str,
    pr_number: i64,
    token: &str,
    base_url: Option<&str>,
) -> Result<PrState, GitWriteError> {
    let project_path = git_provider::parse_gitlab_project_path(repo_url)?;
    let host = base_url
        .map(|b| b.trim_end_matches('/'))
        .unwrap_or("https://gitlab.com");
    let url = format!(
        "{host}/api/v4/projects/{}/merge_requests/{pr_number}",
        urlencoding::encode(&project_path)
    );
    let resp = Client::new()
        .get(&url)
        .header("PRIVATE-TOKEN", token)
        .send()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    if !resp.status().is_success() {
        return Err(classify(resp.status(), "gitlab get mr"));
    }
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| GitWriteError::Other(e.into()))?;
    let state = json
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("opened");
    Ok(match state {
        "merged" => PrState::Merged,
        "closed" | "locked" => PrState::Closed,
        _ => PrState::Open,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn github_creds(uri: &str) -> GitCredentials {
        GitCredentials {
            provider: "github".to_owned(),
            token: "tok".to_owned(),
            base_url: Some(uri.to_owned()),
        }
    }

    fn gitlab_creds(uri: &str) -> GitCredentials {
        GitCredentials {
            provider: "gitlab".to_owned(),
            token: "tok".to_owned(),
            base_url: Some(uri.to_owned()),
        }
    }

    #[tokio::test]
    async fn github_fetch_file_with_sha_decodes_base64_content() {
        let mock = MockServer::start().await;
        let encoded = base64::engine::general_purpose::STANDARD.encode("left-pad==1.3.0");
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/contents/requirements.txt"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "abc123",
                "content": encoded,
                "encoding": "base64",
            })))
            .mount(&mock)
            .await;

        let file = fetch_file_with_sha(
            "github",
            "https://github.com/acme/widgets",
            "requirements.txt",
            "main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect("fetch should succeed")
        .expect("file should exist");
        assert_eq!(file.content, "left-pad==1.3.0");
        assert_eq!(file.sha.as_deref(), Some("abc123"));
    }

    #[tokio::test]
    async fn fetch_file_with_sha_returns_none_on_404() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let result = fetch_file_with_sha(
            "github",
            "https://github.com/acme/widgets",
            "Cargo.toml",
            "main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect("404 must not error");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn fetch_file_with_sha_classifies_403_as_forbidden() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock)
            .await;
        let err = fetch_file_with_sha(
            "github",
            "https://github.com/acme/widgets",
            "Cargo.toml",
            "main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("403 must error");
        assert!(matches!(err, GitWriteError::Forbidden(_)));
    }

    #[tokio::test]
    async fn ensure_branch_treats_github_already_exists_as_ok() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": { "sha": "deadbeef" }
            })))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/git/refs"))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "message": "Reference already exists"
            })))
            .mount(&mock)
            .await;
        ensure_branch(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect("already-exists must be treated as success");
    }

    #[tokio::test]
    async fn ensure_branch_classifies_forbidden_create() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": { "sha": "deadbeef" }
            })))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/git/refs"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock)
            .await;
        let err = ensure_branch(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("403 must error");
        assert!(matches!(err, GitWriteError::Forbidden(_)));
    }

    #[tokio::test]
    async fn gitlab_ensure_branch_treats_already_exists_as_ok() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "message": "Branch already exists"
            })))
            .mount(&mock)
            .await;
        ensure_branch(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            "main",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("already-exists must be treated as success");
    }

    #[tokio::test]
    async fn open_pull_request_parses_github_response() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/pulls"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "number": 42,
                "html_url": "https://github.com/acme/widgets/pull/42",
            })))
            .mount(&mock)
            .await;
        let pr = open_pull_request(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "main",
            "CodeScan Sentinel fixes",
            "body",
            &github_creds(&mock.uri()),
        )
        .await
        .expect("open pr should succeed");
        assert_eq!(pr.number, 42);
        assert_eq!(pr.url, "https://github.com/acme/widgets/pull/42");
    }

    #[tokio::test]
    async fn open_pull_request_parses_gitlab_response() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "iid": 7,
                "web_url": "https://gitlab.com/group/project/-/merge_requests/7",
            })))
            .mount(&mock)
            .await;
        let pr = open_pull_request(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            "main",
            "CodeScan Sentinel fixes",
            "body",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("open mr should succeed");
        assert_eq!(pr.number, 7);
    }

    #[tokio::test]
    async fn list_open_prs_by_head_returns_matches() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/pulls"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "number": 42, "html_url": "https://github.com/acme/widgets/pull/42" }
            ])))
            .mount(&mock)
            .await;
        let prs = list_open_prs_by_head(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect("list should succeed");
        assert_eq!(
            prs,
            vec![PrRef {
                number: 42,
                url: "https://github.com/acme/widgets/pull/42".to_owned()
            }]
        );
    }

    #[tokio::test]
    async fn list_open_prs_by_head_empty_when_none_open() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;
        let prs = list_open_prs_by_head(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect("list should succeed");
        assert!(prs.is_empty());
    }

    #[tokio::test]
    async fn get_pull_request_state_reports_merged() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merged": true, "state": "closed"
            })))
            .mount(&mock)
            .await;
        let state = get_pull_request_state(
            "github",
            "https://github.com/acme/widgets",
            42,
            &github_creds(&mock.uri()),
        )
        .await
        .expect("get state should succeed");
        assert_eq!(state, PrState::Merged);
    }

    #[tokio::test]
    async fn get_pull_request_state_reports_closed_without_merge() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merged": false, "state": "closed"
            })))
            .mount(&mock)
            .await;
        let state = get_pull_request_state(
            "github",
            "https://github.com/acme/widgets",
            42,
            &github_creds(&mock.uri()),
        )
        .await
        .expect("get state should succeed");
        assert_eq!(state, PrState::Closed);
    }

    #[tokio::test]
    async fn get_pull_request_state_reports_gitlab_opened() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "opened"
            })))
            .mount(&mock)
            .await;
        let state = get_pull_request_state(
            "gitlab",
            "https://gitlab.com/group/project",
            7,
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("get state should succeed");
        assert_eq!(state, PrState::Open);
    }

    #[tokio::test]
    async fn commit_file_update_classifies_forbidden() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "abc123",
                "content": base64::engine::general_purpose::STANDARD.encode("x = \"1.0.0\"\n"),
            })))
            .mount(&mock)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock)
            .await;
        let err = commit_file_update(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "Cargo.toml",
            "x = \"1.0.1\"\n",
            "fix(deps): bump x",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("403 must error");
        assert!(matches!(err, GitWriteError::Forbidden(_)));
    }

    #[tokio::test]
    async fn update_pull_request_body_succeeds_on_gitlab() {
        let mock = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;
        update_pull_request_body(
            "gitlab",
            "https://gitlab.com/group/project",
            7,
            "updated body",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("update should succeed");
    }

    #[tokio::test]
    async fn fetch_file_with_sha_rejects_unsupported_provider() {
        let err = fetch_file_with_sha(
            "bitbucket",
            "https://bitbucket.org/acme/widgets",
            "Cargo.toml",
            "main",
            &GitCredentials {
                provider: "bitbucket".to_owned(),
                token: "tok".to_owned(),
                base_url: None,
            },
        )
        .await
        .expect_err("unsupported provider must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn fetch_file_with_sha_classifies_500_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;
        let err = fetch_file_with_sha(
            "github",
            "https://github.com/acme/widgets",
            "Cargo.toml",
            "main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("500 must error");
        assert!(
            matches!(err, GitWriteError::Other(_)),
            "5xx must classify as Other, never Forbidden"
        );
    }

    #[tokio::test]
    async fn github_fetch_file_with_sha_errors_on_missing_content_field() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "sha": "abc123" })),
            )
            .mount(&mock)
            .await;
        let err = fetch_file_with_sha(
            "github",
            "https://github.com/acme/widgets",
            "Cargo.toml",
            "main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("malformed response missing content must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn gitlab_fetch_file_with_sha_decodes_content_with_no_sha() {
        let mock = MockServer::start().await;
        let encoded = base64::engine::general_purpose::STANDARD.encode("gem \"rails\", \"7.0.0\"");
        Mock::given(method("GET"))
            .and(path(
                "/api/v4/projects/group%2Fproject/repository/files/Gemfile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "content": encoded,
                "encoding": "base64",
            })))
            .mount(&mock)
            .await;
        let file = fetch_file_with_sha(
            "gitlab",
            "https://gitlab.com/group/project",
            "Gemfile",
            "main",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("fetch should succeed")
        .expect("file should exist");
        assert_eq!(file.content, "gem \"rails\", \"7.0.0\"");
        assert!(
            file.sha.is_none(),
            "gitlab's file-update API needs no precondition sha"
        );
    }

    #[tokio::test]
    async fn gitlab_fetch_file_with_sha_returns_none_on_404() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let result = fetch_file_with_sha(
            "gitlab",
            "https://gitlab.com/group/project",
            "Gemfile",
            "main",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("404 must not error");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn gitlab_fetch_file_with_sha_classifies_401_as_forbidden() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock)
            .await;
        let err = fetch_file_with_sha(
            "gitlab",
            "https://gitlab.com/group/project",
            "Gemfile",
            "main",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect_err("401 must error");
        assert!(matches!(err, GitWriteError::Forbidden(_)));
    }

    #[tokio::test]
    async fn ensure_branch_rejects_unsupported_provider() {
        let err = ensure_branch(
            "bitbucket",
            "https://bitbucket.org/acme/widgets",
            "codescan/sentinel-fixes-main",
            "main",
            &GitCredentials {
                provider: "bitbucket".to_owned(),
                token: "tok".to_owned(),
                base_url: None,
            },
        )
        .await
        .expect_err("unsupported provider must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn github_ensure_branch_classifies_base_ref_lookup_failure_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let err = ensure_branch(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("missing base branch must error");
        assert!(
            matches!(err, GitWriteError::Other(_)),
            "a missing base branch is not a write-scope problem"
        );
    }

    #[tokio::test]
    async fn gitlab_ensure_branch_creates_new_branch_successfully() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v4/projects/group%2Fproject/repository/branches"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "name": "codescan/sentinel-fixes-main"
            })))
            .mount(&mock)
            .await;
        ensure_branch(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            "main",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("branch creation should succeed");
    }

    #[tokio::test]
    async fn gitlab_ensure_branch_classifies_forbidden() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock)
            .await;
        let err = ensure_branch(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            "main",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect_err("403 must error");
        assert!(matches!(err, GitWriteError::Forbidden(_)));
    }

    #[tokio::test]
    async fn gitlab_ensure_branch_classifies_non_already_exists_failure_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;
        let err = ensure_branch(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            "main",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect_err("500 must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    /// Structural safety net for the highest-consequence property of this
    /// module: it must never force-push and never mutate the default/base
    /// branch's ref directly. Proven two ways per call captured here: (1)
    /// the outgoing JSON payload names the *batch* branch, never `main`,
    /// and (2) the payload carries no `force` field — neither GitHub's
    /// create-ref nor its contents-update API even has one to set, so a
    /// force-push is not just untested here but unreachable through these
    /// calls.
    #[tokio::test]
    async fn git_write_never_force_pushes_or_targets_default_branch_directly() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/git/ref/heads/main"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "object": { "sha": "deadbeef" }
            })))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/repos/acme/widgets/git/refs"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;
        ensure_branch(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect("branch creation should succeed");

        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/contents/Cargo.toml"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "file-sha",
                "content": base64::engine::general_purpose::STANDARD.encode("x = \"1.0.0\"\n"),
            })))
            .mount(&mock)
            .await;
        Mock::given(method("PUT"))
            .and(path("/repos/acme/widgets/contents/Cargo.toml"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;
        commit_file_update(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "Cargo.toml",
            "x = \"1.0.1\"\n",
            "fix(deps): bump x",
            &github_creds(&mock.uri()),
        )
        .await
        .expect("commit should succeed");

        let requests = mock.received_requests().await.expect("recording enabled");

        let create_ref = requests
            .iter()
            .find(|r| {
                r.method == wiremock::http::Method::POST
                    && r.url.path() == "/repos/acme/widgets/git/refs"
            })
            .expect("create-ref request must have been sent");
        let ref_body: serde_json::Value = create_ref.body_json().expect("valid json body");
        assert_eq!(ref_body["ref"], "refs/heads/codescan/sentinel-fixes-main");
        assert_ne!(
            ref_body["ref"], "refs/heads/main",
            "branch creation must never target the default/base branch's ref directly"
        );
        assert!(
            ref_body.get("force").is_none(),
            "branch creation must never carry a force flag"
        );

        let commit = requests
            .iter()
            .find(|r| {
                r.method == wiremock::http::Method::PUT
                    && r.url.path() == "/repos/acme/widgets/contents/Cargo.toml"
            })
            .expect("commit request must have been sent");
        let commit_body: serde_json::Value = commit.body_json().expect("valid json body");
        assert_eq!(commit_body["branch"], "codescan/sentinel-fixes-main");
        assert_ne!(
            commit_body["branch"], "main",
            "file commits must never target the default/base branch directly"
        );
        assert!(
            commit_body.get("force").is_none(),
            "commits must never carry a force flag — the contents API is always a \
             precondition-checked (sha-matched) update, never a reset"
        );
    }

    #[tokio::test]
    async fn commit_file_update_rejects_unsupported_provider() {
        let err = commit_file_update(
            "bitbucket",
            "https://bitbucket.org/acme/widgets",
            "codescan/sentinel-fixes-main",
            "Cargo.toml",
            "x = \"1.0.1\"\n",
            "fix(deps): bump x",
            &GitCredentials {
                provider: "bitbucket".to_owned(),
                token: "tok".to_owned(),
                base_url: None,
            },
        )
        .await
        .expect_err("unsupported provider must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn github_commit_file_errors_when_file_missing_on_branch() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let err = commit_file_update(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "Cargo.toml",
            "x = \"1.0.1\"\n",
            "fix(deps): bump x",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("missing file on branch must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn github_commit_file_classifies_stale_sha_conflict_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "stale-sha",
                "content": base64::engine::general_purpose::STANDARD.encode("x = \"1.0.0\"\n"),
            })))
            .mount(&mock)
            .await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "message": "requested sha does not match current file sha"
            })))
            .mount(&mock)
            .await;
        let err = commit_file_update(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "Cargo.toml",
            "x = \"1.0.1\"\n",
            "fix(deps): bump x",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("stale sha conflict must error");
        assert!(
            matches!(err, GitWriteError::Other(_)),
            "409 conflict is not a write-scope problem"
        );
    }

    #[tokio::test]
    async fn gitlab_commit_file_succeeds() {
        let mock = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path(
                "/api/v4/projects/group%2Fproject/repository/files/Gemfile",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "file_path": "Gemfile",
                "branch": "codescan/sentinel-fixes-main",
            })))
            .mount(&mock)
            .await;
        commit_file_update(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            "Gemfile",
            "gem \"rails\", \"7.0.1\"",
            "fix(deps): bump rails",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("gitlab commit should succeed");
    }

    #[tokio::test]
    async fn gitlab_commit_file_classifies_forbidden() {
        let mock = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock)
            .await;
        let err = commit_file_update(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            "Gemfile",
            "gem \"rails\", \"7.0.1\"",
            "fix(deps): bump rails",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect_err("401 must error");
        assert!(matches!(err, GitWriteError::Forbidden(_)));
    }

    #[tokio::test]
    async fn open_pull_request_rejects_unsupported_provider() {
        let err = open_pull_request(
            "bitbucket",
            "https://bitbucket.org/acme/widgets",
            "codescan/sentinel-fixes-main",
            "main",
            "title",
            "body",
            &GitCredentials {
                provider: "bitbucket".to_owned(),
                token: "tok".to_owned(),
                base_url: None,
            },
        )
        .await
        .expect_err("unsupported provider must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn github_open_pr_classifies_422_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "message": "Validation Failed"
            })))
            .mount(&mock)
            .await;
        let err = open_pull_request(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "main",
            "title",
            "body",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("422 must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn github_open_pr_errors_on_missing_number() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "html_url": "https://github.com/acme/widgets/pull/42"
            })))
            .mount(&mock)
            .await;
        let err = open_pull_request(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            "main",
            "title",
            "body",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("missing number must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn gitlab_open_mr_classifies_failure_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
                "message": "merge request already exists"
            })))
            .mount(&mock)
            .await;
        let err = open_pull_request(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            "main",
            "title",
            "body",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect_err("409 must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn gitlab_open_mr_errors_on_missing_iid() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "web_url": "https://gitlab.com/group/project/-/merge_requests/7"
            })))
            .mount(&mock)
            .await;
        let err = open_pull_request(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            "main",
            "title",
            "body",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect_err("missing iid must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn update_pull_request_body_rejects_unsupported_provider() {
        let err = update_pull_request_body(
            "bitbucket",
            "https://bitbucket.org/acme/widgets",
            42,
            "updated body",
            &GitCredentials {
                provider: "bitbucket".to_owned(),
                token: "tok".to_owned(),
                base_url: None,
            },
        )
        .await
        .expect_err("unsupported provider must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn github_update_pr_body_classifies_failure_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("PATCH"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let err = update_pull_request_body(
            "github",
            "https://github.com/acme/widgets",
            42,
            "updated body",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("404 must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn gitlab_update_mr_body_classifies_forbidden() {
        let mock = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock)
            .await;
        let err = update_pull_request_body(
            "gitlab",
            "https://gitlab.com/group/project",
            7,
            "updated body",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect_err("403 must error");
        assert!(matches!(err, GitWriteError::Forbidden(_)));
    }

    #[tokio::test]
    async fn list_open_prs_by_head_rejects_unsupported_provider() {
        let err = list_open_prs_by_head(
            "bitbucket",
            "https://bitbucket.org/acme/widgets",
            "codescan/sentinel-fixes-main",
            &GitCredentials {
                provider: "bitbucket".to_owned(),
                token: "tok".to_owned(),
                base_url: None,
            },
        )
        .await
        .expect_err("unsupported provider must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn github_list_open_prs_classifies_failure_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;
        let err = list_open_prs_by_head(
            "github",
            "https://github.com/acme/widgets",
            "codescan/sentinel-fixes-main",
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("500 must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn gitlab_list_open_mrs_returns_matches() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v4/projects/group%2Fproject/merge_requests"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                { "iid": 7, "web_url": "https://gitlab.com/group/project/-/merge_requests/7" }
            ])))
            .mount(&mock)
            .await;
        let prs = list_open_prs_by_head(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("list should succeed");
        assert_eq!(
            prs,
            vec![PrRef {
                number: 7,
                url: "https://gitlab.com/group/project/-/merge_requests/7".to_owned()
            }]
        );
    }

    #[tokio::test]
    async fn gitlab_list_open_mrs_classifies_failure_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;
        let err = list_open_prs_by_head(
            "gitlab",
            "https://gitlab.com/group/project",
            "codescan/sentinel-fixes-main",
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect_err("500 must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn get_pull_request_state_rejects_unsupported_provider() {
        let err = get_pull_request_state(
            "bitbucket",
            "https://bitbucket.org/acme/widgets",
            42,
            &GitCredentials {
                provider: "bitbucket".to_owned(),
                token: "tok".to_owned(),
                base_url: None,
            },
        )
        .await
        .expect_err("unsupported provider must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn github_pr_state_classifies_failure_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&mock)
            .await;
        let err = get_pull_request_state(
            "github",
            "https://github.com/acme/widgets",
            42,
            &github_creds(&mock.uri()),
        )
        .await
        .expect_err("404 must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }

    #[tokio::test]
    async fn gitlab_mr_state_reports_merged() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "state": "merged" })),
            )
            .mount(&mock)
            .await;
        let state = get_pull_request_state(
            "gitlab",
            "https://gitlab.com/group/project",
            7,
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("get state should succeed");
        assert_eq!(state, PrState::Merged);
    }

    #[tokio::test]
    async fn gitlab_mr_state_reports_locked_as_closed() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "state": "locked" })),
            )
            .mount(&mock)
            .await;
        let state = get_pull_request_state(
            "gitlab",
            "https://gitlab.com/group/project",
            7,
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect("get state should succeed");
        assert_eq!(state, PrState::Closed);
    }

    #[tokio::test]
    async fn gitlab_mr_state_classifies_failure_as_other() {
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;
        let err = get_pull_request_state(
            "gitlab",
            "https://gitlab.com/group/project",
            7,
            &gitlab_creds(&mock.uri()),
        )
        .await
        .expect_err("500 must error");
        assert!(matches!(err, GitWriteError::Other(_)));
    }
}
