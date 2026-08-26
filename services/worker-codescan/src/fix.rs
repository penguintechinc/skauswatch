//! CodeScan Sentinel P4 grouped auto-fix orchestration
//! (docs/v2-port/v2.1-codescan-sentinel.md §7): given the findings one
//! branch scan resolved to the policy engine's `fix` action (plus the
//! default matrix's "critical/high + reachable+external" combined cell,
//! see `policy::should_also_fix`) with a known [`FixCandidate::fixed_version`],
//! opens or updates the single open PR/MR for `(repo, target_branch)` —
//! never a second one while the first is still open, never a git write at
//! all when the repo is report-only.
//!
//! This module never fails its caller (`handler::CodeScanReviewHandler`):
//! every git-write or DB error is logged and degrades to "try again next
//! scheduled scan", matching every other Sentinel pipeline stage's
//! degrade-not-abort convention. The one exception is a confirmed missing
//! write scope ([`git_write::GitWriteError::Forbidden`]), which is
//! recorded against the affected finding(s) via [`db::record_fix_failure`]
//! rather than silently retried forever.

use std::collections::HashSet;

use sqlx::PgPool;
use uuid::Uuid;

use crate::db;
use crate::git_provider::GitCredentials;
use crate::git_write::{self, GitWriteError, PrState};
use crate::manifest_edit::{self, EditOutcome};

/// Deterministic batch branch prefix (spec §7).
const BATCH_BRANCH_PREFIX: &str = "codescan/sentinel-fixes-";

fn batch_branch_name(target_branch: &str) -> String {
    format!("{BATCH_BRANCH_PREFIX}{target_branch}")
}

/// Maps a `sentinel::ScanFinding::ecosystem` wire name to the manifest file
/// `git_write`/`manifest_edit` operate on — the inverse of
/// `sentinel::MANIFEST_FILES` (indexed there by file, needed here by
/// ecosystem).
fn manifest_file_for_ecosystem(ecosystem: &str) -> Option<&'static str> {
    match ecosystem {
        "npm" => Some("package.json"),
        "pypi" => Some("requirements.txt"),
        "cargo" => Some("Cargo.toml"),
        "go" => Some("go.mod"),
        _ => None,
    }
}

/// The fallback action a fix-attempted finding reverts to when the fix
/// itself couldn't be applied (spec §7: "leave a document/alert outcome") —
/// mirrors `policy::default_matrix`'s severity split without depending on
/// reachability (the fix pipeline runs after policy evaluation already
/// happened; this is a *downgrade* from `fix`, not a re-evaluation).
fn fallback_action(severity: &str) -> &'static str {
    if matches!(severity.to_ascii_lowercase().as_str(), "critical" | "high") {
        "alert"
    } else {
        "document"
    }
}

/// One finding resolved to `fix` (or the combined alert+fix cell) with a
/// known remediation version — the unit `run_fix_batch` operates on. Built
/// by `handler::CodeScanReviewHandler::scan_and_persist_branch` from
/// `sentinel::ScanFinding` + the policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixCandidate {
    pub finding_id: i64,
    pub ecosystem: String,
    pub package_name: String,
    pub current_version: String,
    pub fixed_version: String,
    /// `""` for a plain-outdated (`sca`) finding — matches the findings
    /// table's own non-CVE sentinel convention.
    pub advisory_id: String,
    pub severity: String,
    /// Human-readable reachability summary for the PR body (e.g.
    /// `"reachable/external"`, `"not used"`, `""` when never triaged).
    pub reachability_verdict: String,
}

fn commit_message(candidate: &FixCandidate) -> String {
    let cve = if candidate.advisory_id.is_empty() {
        "outdated dependency".to_owned()
    } else {
        candidate.advisory_id.clone()
    };
    format!(
        "fix(deps): bump {} {} -> {} ({cve})",
        candidate.package_name, candidate.current_version, candidate.fixed_version
    )
}

/// Renders the itemized fix table shared by both the initial PR body and
/// every subsequent regeneration — spec §7: "pkg old→new · CVE(s) fixed ·
/// severity · reachability verdict", plus a lockfile-refresh note (spec:
/// "lockfile refresh is left to the maintainer/CI").
fn render_pr_body<'a>(
    target_branch: &str,
    rows: impl Iterator<
        Item = (
            &'a str,
            &'a str,
            &'a str,
            &'a str,
            &'a str,
            &'a str,
            &'a str,
        ),
    >,
) -> String {
    let mut body = format!(
        "CodeScan Sentinel grouped dependency fix batch for `{target_branch}`.\n\n\
         | Package | Ecosystem | Old → New | CVE(s) | Severity | Reachability |\n\
         |---|---|---|---|---|---|\n"
    );
    for (package, ecosystem, old_version, new_version, advisory_id, severity, reachability) in rows
    {
        let cve = if advisory_id.is_empty() {
            "-"
        } else {
            advisory_id
        };
        let reach = if reachability.is_empty() {
            "unknown"
        } else {
            reachability
        };
        body.push_str(&format!(
            "| {package} | {ecosystem} | {old_version} → {new_version} | {cve} | {severity} | {reach} |\n"
        ));
    }
    body.push_str(
        "\n_Lockfiles (package-lock.json / Cargo.lock / go.sum, etc.) are not regenerated by \
         this bot — please refresh them, or let CI do so, before merging._\n",
    );
    body
}

async fn record_skip(pool: &PgPool, tenant_id: Uuid, candidate: &FixCandidate, reason: &str) {
    if let Err(e) = db::record_fix_failure(
        pool,
        tenant_id,
        candidate.finding_id,
        fallback_action(&candidate.severity),
        reason,
    )
    .await
    {
        tracing::warn!(
            finding_id = candidate.finding_id,
            error = %e,
            "sentinel-fix: failed to record a fix-failure downgrade"
        );
    }
}

/// Outcome of one [`run_fix_batch`] call — logged, never propagated.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FixBatchOutcome {
    pub batch_id: Option<i64>,
    /// Findings newly committed into the batch this run.
    pub committed: usize,
    /// Findings that could not be committed this run (recorded via
    /// [`db::record_fix_failure`]).
    pub skipped: usize,
}

/// Orchestrates the grouped-fix pipeline for one (repo, branch)'s
/// fixable findings this scan. A no-op (zero git/DB calls) when auto-fix is
/// disabled for the repo or there is nothing to fix — see module docs.
#[allow(clippy::too_many_arguments)]
pub async fn run_fix_batch(
    pool: &PgPool,
    tenant_id: Uuid,
    repo_config_id: i64,
    provider: &str,
    repo_url: &str,
    target_branch: &str,
    creds: &GitCredentials,
    candidates: &[FixCandidate],
    auto_fix_enabled: bool,
) -> FixBatchOutcome {
    if !auto_fix_enabled || candidates.is_empty() {
        return FixBatchOutcome::default();
    }

    let branch_name = batch_branch_name(target_branch);

    let existing = match db::get_open_fix_batch(pool, tenant_id, repo_config_id, target_branch)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "sentinel-fix: failed to load open fix batch, skipping this run");
            return FixBatchOutcome::default();
        }
    };

    let active = match existing {
        Some(batch) => {
            match git_write::get_pull_request_state(provider, repo_url, batch.pr_number, creds)
                .await
            {
                Ok(PrState::Open) => {
                    tracing::debug!(
                        pr_url = %batch.pr_url,
                        "sentinel-fix: continuing the existing open grouped fix batch"
                    );
                    Some(batch)
                }
                Ok(PrState::Merged) => {
                    if let Err(e) = db::mark_fix_batch_status(pool, batch.id, "merged").await {
                        tracing::warn!(error = %e, "sentinel-fix: failed to mark batch merged");
                    }
                    None
                }
                Ok(PrState::Closed) => {
                    if let Err(e) = db::mark_fix_batch_status(pool, batch.id, "closed").await {
                        tracing::warn!(error = %e, "sentinel-fix: failed to mark batch closed");
                    }
                    None
                }
                Err(GitWriteError::Forbidden(msg)) => {
                    for candidate in candidates {
                        record_skip(
                            pool,
                            tenant_id,
                            candidate,
                            &format!("git write forbidden: {msg}"),
                        )
                        .await;
                    }
                    return FixBatchOutcome {
                        batch_id: Some(batch.id),
                        committed: 0,
                        skipped: candidates.len(),
                    };
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "sentinel-fix: failed to check the tracked PR's state, skipping this run"
                    );
                    return FixBatchOutcome::default();
                }
            }
        }
        None => None,
    };

    let already_included: HashSet<i64> = if let Some(b) = &active {
        db::list_fix_batch_finding_ids(pool, b.id)
            .await
            .unwrap_or_default()
    } else {
        HashSet::new()
    };
    let new_candidates: Vec<&FixCandidate> = candidates
        .iter()
        .filter(|c| !already_included.contains(&c.finding_id))
        .collect();
    if new_candidates.is_empty() {
        // Idempotent re-run: every candidate is already tracked in the
        // active batch (or there was nothing new to add) — zero git calls.
        return FixBatchOutcome {
            batch_id: active.map(|b| b.id),
            committed: 0,
            skipped: 0,
        };
    }

    let source_ref = active
        .as_ref()
        .map_or_else(|| target_branch.to_owned(), |b| b.branch_name.clone());

    let mut edited: Vec<(&FixCandidate, &'static str, String)> = Vec::new();
    let mut skipped = 0usize;
    let mut forbidden = false;
    for candidate in new_candidates {
        let Some(manifest_file) = manifest_file_for_ecosystem(&candidate.ecosystem) else {
            record_skip(
                pool,
                tenant_id,
                candidate,
                "unrecognized ecosystem, no known manifest file",
            )
            .await;
            skipped += 1;
            continue;
        };
        match git_write::fetch_file_with_sha(provider, repo_url, manifest_file, &source_ref, creds)
            .await
        {
            Ok(Some(file)) => match manifest_edit::edit_dependency_version(
                manifest_file,
                &file.content,
                &candidate.package_name,
                &candidate.fixed_version,
            ) {
                EditOutcome::Edited(new_content) => {
                    edited.push((candidate, manifest_file, new_content))
                }
                EditOutcome::Skipped(reason) => {
                    record_skip(
                        pool,
                        tenant_id,
                        candidate,
                        &format!("manifest edit skipped: {reason}"),
                    )
                    .await;
                    skipped += 1;
                }
            },
            Ok(None) => {
                record_skip(
                    pool,
                    tenant_id,
                    candidate,
                    &format!("{manifest_file} not present at current ref"),
                )
                .await;
                skipped += 1;
            }
            Err(GitWriteError::Forbidden(msg)) => {
                record_skip(
                    pool,
                    tenant_id,
                    candidate,
                    &format!("git write forbidden: {msg}"),
                )
                .await;
                skipped += 1;
                forbidden = true;
            }
            Err(e) => {
                tracing::warn!(
                    finding_id = candidate.finding_id,
                    error = %e,
                    "sentinel-fix: transient failure fetching manifest, will retry next scan"
                );
            }
        }
        if forbidden {
            break;
        }
    }

    if edited.is_empty() {
        return FixBatchOutcome {
            batch_id: active.map(|b| b.id),
            committed: 0,
            skipped,
        };
    }

    if active.is_none() {
        // Anti-sprawl safety net: refuse to open a second PR if one already
        // exists on this exact branch outside of tracked DB state (a lost
        // batch row, or manual repo state) — never silently duplicate.
        match git_write::list_open_prs_by_head(provider, repo_url, &branch_name, creds).await {
            Ok(strays) if !strays.is_empty() => {
                tracing::warn!(
                    branch = %branch_name,
                    "sentinel-fix: an open PR already exists on this branch outside of tracked \
                     state; skipping to avoid opening a duplicate"
                );
                for (candidate, _, _) in &edited {
                    record_skip(
                        pool,
                        tenant_id,
                        candidate,
                        "an open PR already exists on the fix branch outside of tracked state",
                    )
                    .await;
                }
                return FixBatchOutcome {
                    batch_id: None,
                    committed: 0,
                    skipped: skipped + edited.len(),
                };
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(error = %e, "sentinel-fix: failed to check for a stray open PR, skipping this run");
                return FixBatchOutcome {
                    batch_id: None,
                    committed: 0,
                    skipped,
                };
            }
        }
        if let Err(e) =
            git_write::ensure_branch(provider, repo_url, &branch_name, target_branch, creds).await
        {
            match e {
                GitWriteError::Forbidden(msg) => {
                    for (candidate, _, _) in &edited {
                        record_skip(
                            pool,
                            tenant_id,
                            candidate,
                            &format!("git write forbidden: {msg}"),
                        )
                        .await;
                    }
                    return FixBatchOutcome {
                        batch_id: None,
                        committed: 0,
                        skipped: skipped + edited.len(),
                    };
                }
                GitWriteError::Other(err) => {
                    tracing::warn!(error = %err, "sentinel-fix: failed to create fix branch, will retry next scan");
                    return FixBatchOutcome {
                        batch_id: None,
                        committed: 0,
                        skipped,
                    };
                }
            }
        }
    }

    let mut committed_now: Vec<&FixCandidate> = Vec::new();
    for (candidate, manifest_file, new_content) in &edited {
        let message = commit_message(candidate);
        match git_write::commit_file_update(
            provider,
            repo_url,
            &branch_name,
            manifest_file,
            new_content,
            &message,
            creds,
        )
        .await
        {
            Ok(()) => committed_now.push(candidate),
            Err(GitWriteError::Forbidden(msg)) => {
                record_skip(
                    pool,
                    tenant_id,
                    candidate,
                    &format!("git write forbidden: {msg}"),
                )
                .await;
                skipped += 1;
                break;
            }
            Err(e) => {
                tracing::warn!(
                    finding_id = candidate.finding_id,
                    error = %e,
                    "sentinel-fix: failed to commit fix, will retry next scan"
                );
            }
        }
    }

    if committed_now.is_empty() {
        return FixBatchOutcome {
            batch_id: active.map(|b| b.id),
            committed: 0,
            skipped,
        };
    }

    let batch = match active {
        Some(b) => b,
        None => {
            let title = format!("CodeScan Sentinel: dependency fixes for {target_branch}");
            let rows = committed_now.iter().map(|c| {
                (
                    c.package_name.as_str(),
                    c.ecosystem.as_str(),
                    c.current_version.as_str(),
                    c.fixed_version.as_str(),
                    c.advisory_id.as_str(),
                    c.severity.as_str(),
                    c.reachability_verdict.as_str(),
                )
            });
            let body = render_pr_body(target_branch, rows);
            match git_write::open_pull_request(
                provider,
                repo_url,
                &branch_name,
                target_branch,
                &title,
                &body,
                creds,
            )
            .await
            {
                Ok(pr) => match db::create_fix_batch(
                    pool,
                    tenant_id,
                    repo_config_id,
                    target_branch,
                    &branch_name,
                    pr.number,
                    &pr.url,
                )
                .await
                {
                    Ok(id) => db::FixBatchRecord {
                        id,
                        branch_name: branch_name.clone(),
                        pr_number: pr.number,
                        pr_url: pr.url,
                    },
                    Err(e) => {
                        tracing::warn!(error = %e, "sentinel-fix: opened a PR but failed to record the batch row");
                        return FixBatchOutcome {
                            batch_id: None,
                            committed: committed_now.len(),
                            skipped,
                        };
                    }
                },
                Err(GitWriteError::Forbidden(msg)) => {
                    for candidate in &committed_now {
                        record_skip(
                            pool,
                            tenant_id,
                            candidate,
                            &format!("git write forbidden: {msg}"),
                        )
                        .await;
                    }
                    return FixBatchOutcome {
                        batch_id: None,
                        committed: 0,
                        skipped: skipped + committed_now.len(),
                    };
                }
                Err(GitWriteError::Other(e)) => {
                    tracing::warn!(error = %e, "sentinel-fix: committed fixes but failed to open the PR, will retry next scan");
                    return FixBatchOutcome {
                        batch_id: None,
                        committed: 0,
                        skipped,
                    };
                }
            }
        }
    };

    for candidate in &committed_now {
        if let Err(e) = db::insert_fix_batch_finding(
            pool,
            tenant_id,
            batch.id,
            candidate.finding_id,
            &candidate.package_name,
            &candidate.ecosystem,
            &candidate.current_version,
            &candidate.fixed_version,
            &candidate.advisory_id,
            &candidate.severity,
            &candidate.reachability_verdict,
        )
        .await
        {
            tracing::warn!(finding_id = candidate.finding_id, error = %e, "sentinel-fix: failed to record batch finding");
        }
    }

    // Regenerate the body from the full, authoritative DB list (spec: "keep
    // it regenerated, not appended") — covers both the just-created batch
    // (redundant but harmless: same content) and a continuing batch (now
    // reflecting the newly-added findings alongside every prior one).
    match db::list_fix_batch_findings(pool, batch.id).await {
        Ok(records) => {
            let rows = records.iter().map(|r| {
                (
                    r.package_name.as_str(),
                    r.ecosystem.as_str(),
                    r.old_version.as_str(),
                    r.new_version.as_str(),
                    r.advisory_id.as_str(),
                    r.severity.as_str(),
                    r.reachability_verdict.as_str(),
                )
            });
            let body = render_pr_body(target_branch, rows);
            if let Err(e) = git_write::update_pull_request_body(
                provider,
                repo_url,
                batch.pr_number,
                &body,
                creds,
            )
            .await
            {
                tracing::warn!(error = %e, "sentinel-fix: failed to update PR body");
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "sentinel-fix: failed to reload batch findings for the PR body");
        }
    }

    FixBatchOutcome {
        batch_id: Some(batch.id),
        committed: committed_now.len(),
        skipped,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use sqlx::Row;
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const TEST_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";

    fn test_tenant() -> Uuid {
        TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("test tenant uuid: {e}"))
    }

    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../codescan-backend/migrations"
        ))
        .await
    }

    async fn seed_repo_config(pool: &PgPool) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name) \
             VALUES ($1, 'github', 'https://github.com/acme/widgets', 'acme/widgets') RETURNING id",
        )
        .bind(test_tenant())
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo config: {e}"));
        row.get::<i64, _>(0)
    }

    async fn seed_finding(pool: &PgPool, repo_config_id: i64, package_name: &str) -> i64 {
        let upserted = db::upsert_finding(
            pool,
            test_tenant(),
            repo_config_id,
            "main",
            "cve",
            "npm",
            package_name,
            "1.0.0",
            Some("1.0.1"),
            "GHSA-test-0001",
            "high",
        )
        .await
        .unwrap_or_else(|e| panic!("seed finding: {e}"));
        upserted.id
    }

    fn creds(uri: &str) -> GitCredentials {
        GitCredentials {
            provider: "github".to_owned(),
            token: "tok".to_owned(),
            base_url: Some(uri.to_owned()),
        }
    }

    fn candidate(finding_id: i64, package_name: &str) -> FixCandidate {
        FixCandidate {
            finding_id,
            ecosystem: "npm".to_owned(),
            package_name: package_name.to_owned(),
            current_version: "1.0.0".to_owned(),
            fixed_version: "1.0.1".to_owned(),
            advisory_id: "GHSA-test-0001".to_owned(),
            severity: "high".to_owned(),
            reachability_verdict: "reachable/external".to_owned(),
        }
    }

    fn encode(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    /// Mounts the fixed sequence of GitHub calls a brand-new batch makes:
    /// no stray PR, branch create, file fetch+commit, PR open (as PR #42,
    /// `.up_to_n_times(1)` since `merged_batch_starts_a_fresh_one_on_the_next_fix`
    /// mounts a second, distinct PR-open response for its second batch and
    /// the two must never both be eligible for the same request).
    ///
    /// The manifest content deliberately contains *both* `left-pad` and
    /// `axios` regardless of which test uses it — `edit_dependency_version`
    /// only ever touches the one package it's asked for, so every test can
    /// share one fetch mock without needing to differentiate by `ref` query
    /// param (which package a given call is editing already disambiguates
    /// what matters).
    async fn mount_fresh_batch_mocks(mock: &MockServer) {
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/git/ref/heads/main$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "object": { "sha": "base-sha" } })),
            )
            .mount(mock)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/repos/acme/widgets/git/refs$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "file-sha",
                "content": encode(
                    "{\n  \"dependencies\": {\n    \"left-pad\": \"^1.0.0\",\n    \"axios\": \"^1.0.0\"\n  }\n}\n",
                ),
            })))
            .mount(mock)
            .await;
        Mock::given(method("PUT"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(mock)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "number": 42,
                "html_url": "https://github.com/acme/widgets/pull/42",
            })))
            .up_to_n_times(1)
            .mount(mock)
            .await;
        Mock::given(method("PATCH"))
            .and(path_regex(r"^/repos/acme/widgets/pulls/42$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(mock)
            .await;
    }

    #[tokio::test]
    async fn first_fix_opens_a_pr_and_records_the_batch() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "left-pad").await;
        let mock = MockServer::start().await;
        mount_fresh_batch_mocks(&mock).await;

        let outcome = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            true,
        )
        .await;

        assert_eq!(outcome.committed, 1);
        assert_eq!(outcome.skipped, 0);
        let batch = db::get_open_fix_batch(&pool, test_tenant(), repo_config_id, "main")
            .await
            .expect("query should succeed")
            .expect("a batch should now be open");
        assert_eq!(batch.pr_number, 42);
        assert_eq!(batch.branch_name, "codescan/sentinel-fixes-main");
    }

    #[tokio::test]
    async fn second_fix_updates_the_same_pr_without_opening_a_second_one() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_a = seed_finding(&pool, repo_config_id, "left-pad").await;
        let finding_b = seed_finding(&pool, repo_config_id, "axios").await;
        let mock = MockServer::start().await;
        mount_fresh_batch_mocks(&mock).await;

        let first = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_a, "left-pad")],
            true,
        )
        .await;
        assert_eq!(first.committed, 1);

        // Second run: tracked PR still open — the second package is fetched
        // from the batch branch (not `main`) and committed on top; the
        // shared `contents/package.json` mock already covers both packages.
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls/42$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merged": false, "state": "open"
            })))
            .mount(&mock)
            .await;

        let second = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[
                candidate(finding_a, "left-pad"),
                candidate(finding_b, "axios"),
            ],
            true,
        )
        .await;
        assert_eq!(
            second.committed, 1,
            "only the new (axios) candidate should commit"
        );

        let pr_opens = mock
            .received_requests()
            .await
            .expect("recording enabled")
            .iter()
            .filter(|r| {
                r.method == wiremock::http::Method::POST
                    && r.url.path() == "/repos/acme/widgets/pulls"
            })
            .count();
        assert_eq!(
            pr_opens, 1,
            "exactly one PR must ever be opened for this batch"
        );

        let batch = db::get_open_fix_batch(&pool, test_tenant(), repo_config_id, "main")
            .await
            .expect("query should succeed")
            .expect("batch still open");
        let findings = db::list_fix_batch_findings(&pool, batch.id)
            .await
            .expect("list should succeed");
        assert_eq!(findings.len(), 2, "batch should now itemize both fixes");
    }

    #[tokio::test]
    async fn idempotent_rerun_with_no_new_findings_makes_zero_git_calls() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "left-pad").await;
        let mock = MockServer::start().await;
        mount_fresh_batch_mocks(&mock).await;

        let first = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            true,
        )
        .await;
        assert_eq!(first.committed, 1);
        let requests_after_first = mock
            .received_requests()
            .await
            .expect("recording enabled")
            .len();

        // Only the PR-state check is a new call this run — no branch/file/PR
        // writes for a finding that's already in the batch.
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls/42$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merged": false, "state": "open"
            })))
            .mount(&mock)
            .await;

        let second = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            true,
        )
        .await;
        assert_eq!(second.committed, 0);
        assert_eq!(second.skipped, 0);

        let requests_after_second = mock
            .received_requests()
            .await
            .expect("recording enabled")
            .len();
        assert_eq!(
            requests_after_second,
            requests_after_first + 1,
            "only the PR-state check should fire on an idempotent re-run"
        );
    }

    #[tokio::test]
    async fn merged_batch_starts_a_fresh_one_on_the_next_fix() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_a = seed_finding(&pool, repo_config_id, "left-pad").await;
        let finding_b = seed_finding(&pool, repo_config_id, "axios").await;
        let mock = MockServer::start().await;
        mount_fresh_batch_mocks(&mock).await;

        let first = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_a, "left-pad")],
            true,
        )
        .await;
        assert_eq!(first.committed, 1);

        // The tracked PR has since merged.
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls/42$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "merged": true, "state": "closed"
            })))
            .mount(&mock)
            .await;
        // A fresh batch: no stray open PR, branch create, file fetch from
        // `main` again (not the old batch branch), new PR #99.
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "number": 99,
                "html_url": "https://github.com/acme/widgets/pull/99",
            })))
            .mount(&mock)
            .await;
        Mock::given(method("PATCH"))
            .and(path_regex(r"^/repos/acme/widgets/pulls/99$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;

        let second = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_b, "axios")],
            true,
        )
        .await;
        assert_eq!(second.committed, 1);
        let batch = db::get_open_fix_batch(&pool, test_tenant(), repo_config_id, "main")
            .await
            .expect("query should succeed")
            .expect("a fresh batch should now be open");
        assert_eq!(
            batch.pr_number, 99,
            "must be the new PR, not the merged one"
        );
    }

    #[tokio::test]
    async fn missing_write_scope_is_recorded_and_never_panics() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "left-pad").await;
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/git/ref/heads/main$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "object": { "sha": "base-sha" } })),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "file-sha",
                "content": encode("{\n  \"dependencies\": {\n    \"left-pad\": \"^1.0.0\"\n  }\n}\n"),
            })))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/repos/acme/widgets/git/refs$"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&mock)
            .await;

        let outcome = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            true,
        )
        .await;
        assert_eq!(outcome.committed, 0);
        assert_eq!(outcome.skipped, 1);

        let row = sqlx::query("SELECT action FROM codescan_findings WHERE id = $1")
            .bind(finding_id)
            .fetch_one(&pool)
            .await
            .expect("finding should still exist");
        let action: String = row.get(0);
        assert_eq!(
            action, "alert",
            "critical/high severity must fall back to alert"
        );

        let reason_row = sqlx::query(
            "SELECT reason FROM codescan_policy_decisions WHERE finding_id = $1 ORDER BY decided_at DESC LIMIT 1",
        )
        .bind(finding_id)
        .fetch_one(&pool)
        .await
        .expect("a policy decision row should have been recorded");
        let reason: String = reason_row.get(0);
        assert!(reason.contains("git write forbidden"));
    }

    #[tokio::test]
    async fn unmechanical_version_spec_is_skipped_with_a_recorded_reason() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "@acme/shared").await;
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "file-sha",
                "content": encode(
                    "{\n  \"dependencies\": {\n    \"@acme/shared\": \"workspace:*\"\n  }\n}\n",
                ),
            })))
            .mount(&mock)
            .await;

        let outcome = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "@acme/shared")],
            true,
        )
        .await;
        assert_eq!(outcome.committed, 0);
        assert_eq!(outcome.skipped, 1);
        assert_eq!(
            outcome.batch_id, None,
            "an all-skip run must never create a batch/PR"
        );

        let reason_row = sqlx::query(
            "SELECT reason FROM codescan_policy_decisions WHERE finding_id = $1 ORDER BY decided_at DESC LIMIT 1",
        )
        .bind(finding_id)
        .fetch_one(&pool)
        .await
        .expect("a policy decision row should have been recorded");
        let reason: String = reason_row.get(0);
        assert!(reason.contains("manifest edit skipped"));
    }

    #[tokio::test]
    async fn report_only_repo_makes_zero_git_write_calls() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "left-pad").await;
        let mock = MockServer::start().await;
        // Deliberately mount nothing that would let any of these succeed —
        // if `run_fix_batch` made even one call it would 404 (or panic on
        // an unmatched request, depending on wiremock's strictness), but the
        // assertion below is the authoritative check regardless.

        let outcome = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            false, // report-only
        )
        .await;
        assert_eq!(outcome, FixBatchOutcome::default());

        let requests = mock.received_requests().await.expect("recording enabled");
        assert_eq!(
            requests.len(),
            0,
            "report-only must never touch the git provider"
        );
    }

    #[tokio::test]
    async fn transient_fetch_error_is_not_recorded_as_a_skip() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "left-pad").await;
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let outcome = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            true,
        )
        .await;

        assert_eq!(outcome.committed, 0);
        assert_eq!(
            outcome.skipped, 0,
            "a transient (non-forbidden) fetch failure must be retried next scan, never \
             recorded as a policy-decision skip"
        );
        assert_eq!(outcome.batch_id, None);

        let row = sqlx::query("SELECT action FROM codescan_findings WHERE id = $1")
            .bind(finding_id)
            .fetch_one(&pool)
            .await
            .expect("finding should still exist");
        let action: String = row.get(0);
        assert_eq!(
            action, "",
            "the finding's action must remain untouched by a transient failure, unlike a \
             Forbidden downgrade"
        );
    }

    #[tokio::test]
    async fn branch_creation_transient_failure_defers_without_recording_a_skip() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "left-pad").await;
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "file-sha",
                "content": encode("{\n  \"dependencies\": {\n    \"left-pad\": \"^1.0.0\"\n  }\n}\n"),
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/git/ref/heads/main$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "object": { "sha": "base-sha" } })),
            )
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/repos/acme/widgets/git/refs$"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let outcome = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            true,
        )
        .await;

        assert_eq!(outcome.committed, 0);
        assert_eq!(
            outcome.skipped, 0,
            "a transient branch-create failure must retry next scan, never record a skip"
        );
        assert_eq!(outcome.batch_id, None);
        assert!(
            db::get_open_fix_batch(&pool, test_tenant(), repo_config_id, "main")
                .await
                .expect("query should succeed")
                .is_none(),
            "no batch/PR must ever be recorded when branch creation itself failed"
        );
    }

    #[tokio::test]
    async fn stray_pr_lookup_transient_failure_defers_the_whole_run() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "left-pad").await;
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "file-sha",
                "content": encode("{\n  \"dependencies\": {\n    \"left-pad\": \"^1.0.0\"\n  }\n}\n"),
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let outcome = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            true,
        )
        .await;

        assert_eq!(
            outcome,
            FixBatchOutcome::default(),
            "a transient stray-PR-lookup failure must skip this run without recording anything"
        );
        assert!(
            db::get_open_fix_batch(&pool, test_tenant(), repo_config_id, "main")
                .await
                .expect("query should succeed")
                .is_none()
        );
    }

    #[tokio::test]
    async fn open_pr_transient_failure_after_commit_defers_without_recording_a_skip() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "left-pad").await;
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/git/ref/heads/main$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "object": { "sha": "base-sha" } })),
            )
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/repos/acme/widgets/git/refs$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "file-sha",
                "content": encode("{\n  \"dependencies\": {\n    \"left-pad\": \"^1.0.0\"\n  }\n}\n"),
            })))
            .mount(&mock)
            .await;
        Mock::given(method("PUT"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let outcome = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            true,
        )
        .await;

        assert_eq!(outcome.committed, 0);
        assert_eq!(
            outcome.skipped, 0,
            "committed-but-PR-open-failed must retry next scan, never record a skip — the \
             manifest edit already landed on the batch branch and will be reused"
        );
        assert_eq!(outcome.batch_id, None);
        assert!(
            db::get_open_fix_batch(&pool, test_tenant(), repo_config_id, "main")
                .await
                .expect("query should succeed")
                .is_none(),
            "no batch row without a PR number to record"
        );
    }

    #[tokio::test]
    async fn all_commits_transiently_failing_never_opens_a_pr() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_id = seed_finding(&pool, repo_config_id, "left-pad").await;
        let mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/git/ref/heads/main$"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "object": { "sha": "base-sha" } })),
            )
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path_regex(r"^/repos/acme/widgets/git/refs$"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({})))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sha": "file-sha",
                "content": encode("{\n  \"dependencies\": {\n    \"left-pad\": \"^1.0.0\"\n  }\n}\n"),
            })))
            .mount(&mock)
            .await;
        Mock::given(method("PUT"))
            .and(path_regex(r"^/repos/acme/widgets/contents/package\.json$"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock)
            .await;

        let outcome = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_id, "left-pad")],
            true,
        )
        .await;

        assert_eq!(outcome.committed, 0);
        assert_eq!(outcome.skipped, 0);
        assert_eq!(outcome.batch_id, None);

        let pr_opens = mock
            .received_requests()
            .await
            .expect("recording enabled")
            .iter()
            .filter(|r| {
                r.method == wiremock::http::Method::POST
                    && r.url.path() == "/repos/acme/widgets/pulls"
            })
            .count();
        assert_eq!(
            pr_opens, 0,
            "a batch with zero successful commits must never open a PR"
        );
    }

    #[tokio::test]
    async fn pr_state_check_transient_failure_skips_this_run() {
        let pool = test_pool().await;
        let repo_config_id = seed_repo_config(&pool).await;
        let finding_a = seed_finding(&pool, repo_config_id, "left-pad").await;
        let finding_b = seed_finding(&pool, repo_config_id, "axios").await;
        let mock = MockServer::start().await;
        mount_fresh_batch_mocks(&mock).await;

        let first = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[candidate(finding_a, "left-pad")],
            true,
        )
        .await;
        assert_eq!(first.committed, 1);

        Mock::given(method("GET"))
            .and(path_regex(r"^/repos/acme/widgets/pulls/42$"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock)
            .await;

        let second = run_fix_batch(
            &pool,
            test_tenant(),
            repo_config_id,
            "github",
            "https://github.com/acme/widgets",
            "main",
            &creds(&mock.uri()),
            &[
                candidate(finding_a, "left-pad"),
                candidate(finding_b, "axios"),
            ],
            true,
        )
        .await;
        assert_eq!(
            second,
            FixBatchOutcome::default(),
            "a transient PR-state-check failure must skip the whole run, not touch the batch"
        );

        let batch = db::get_open_fix_batch(&pool, test_tenant(), repo_config_id, "main")
            .await
            .expect("query should succeed")
            .expect("original batch still open");
        assert_eq!(batch.pr_number, 42, "the original batch must be untouched");
    }
}
