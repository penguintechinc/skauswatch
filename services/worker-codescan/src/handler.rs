//! Stream handler for CodeScan review tasks and (net-new) CodeScan Sentinel
//! scan tasks — both arrive on the same `codescan:tasks` stream,
//! discriminated by `message::stream_task_type` (spec
//! docs/v2-port/v2.1-codescan-sentinel.md §10).

use chrono::Utc;
use skauswatch_ai::{
    CompletionProvider, CompletionRequest, Message, anthropic::AnthropicProvider,
    ollama::OllamaProvider, openai::OpenaiProvider,
};
use skauswatch_streams::{StreamEntry, StreamHandler, StreamProducer};
use sqlx::PgPool;
use uuid::Uuid;

use skauswatch_vault::CredentialCipher;

use crate::config::WorkerConfig;
use crate::db::{self, RepoConfigRecord};
use crate::detection;
use crate::git_provider::{self, GitCredentials};
use crate::license_scan::RegistryClient;
use crate::message::{CodeScanReviewTask, SentinelScanTask, stream_task_type};
use crate::policy;
use crate::reachability;
use crate::review::ReviewOutput;
use crate::scanner_tool::{self, ScanOutcome, ScannerTool};
use crate::sentinel;
use crate::tree_fetch;
use crate::triage;

/// Handler for CodeScan review stream entries.
pub struct CodeScanReviewHandler {
    pool: PgPool,
    producer: StreamProducer,
    config: WorkerConfig,
    /// npm/PyPI/crates.io client for `codescan_license_detections` scanning
    /// (see `crate::license_scan`). Built once so tests/prod share one
    /// pooled `reqwest::Client`.
    registry_client: RegistryClient,
    /// CodeScan Sentinel P2 tool registry (SAST/secrets/IaC/SBOM) — see
    /// `crate::scanner_tool`. A `Vec` of trait objects rather than a fixed
    /// struct so adding a tool never touches this handler.
    tool_registry: Vec<Box<dyn ScannerTool>>,
    /// Subprocess execution seam for the tool registry above — real
    /// `TokioProcessRunner` in production; tests inject a fake at the
    /// `scanner_tool` unit level (this field always holds the real runner,
    /// which is itself what proves the "binary genuinely absent" path in
    /// this module's own integration tests, since the test container never
    /// installs semgrep/gitleaks/trivy/syft).
    process_runner: std::sync::Arc<dyn scanner_tool::ProcessRunner>,
    /// Gates CodeScan Sentinel P3's AI reachability triage + policy engine
    /// (docs/v2-port/v2.1-codescan-sentinel.md §13: Enterprise-only, since
    /// both route through WaddleAI). Deterministic P1/P2 scanning
    /// (sca/cve/sast/secret/iac/sbom findings, the pre-P3 alert bridge)
    /// never consults this — see [`Self::ai_triage_and_policy_enabled`].
    license: std::sync::Arc<penguin_licensing::LicenseClient>,
}

impl CodeScanReviewHandler {
    /// Create a new CodeScan review handler.
    pub fn new(
        pool: PgPool,
        producer: StreamProducer,
        config: WorkerConfig,
        license: std::sync::Arc<penguin_licensing::LicenseClient>,
    ) -> Self {
        let registry_client = RegistryClient::new(
            config.npm_registry_url.clone(),
            config.pypi_registry_url.clone(),
            config.crates_registry_url.clone(),
            config.go_registry_url.clone(),
        );
        Self {
            pool,
            producer,
            config,
            registry_client,
            tool_registry: scanner_tool::default_registry(),
            process_runner: std::sync::Arc::new(scanner_tool::TokioProcessRunner),
            license,
        }
    }

    /// Resolves which git credential to use for `task`'s repo — thin
    /// wrapper over [`Self::resolve_credentials`] logging by `review_id`.
    /// See that function for the fallback semantics.
    async fn resolve_git_credentials(
        &self,
        task: &CodeScanReviewTask,
        repo_config: &RepoConfigRecord,
    ) -> GitCredentials {
        self.resolve_credentials(task.tenant_id, repo_config, task.review_id)
            .await
    }

    /// Resolves which git credential to use for a Sentinel scan's repo —
    /// thin wrapper over [`Self::resolve_credentials`] logging by
    /// `repo_config_id` (Sentinel tasks have no `review_id`).
    async fn resolve_sentinel_git_credentials(
        &self,
        task: &crate::message::SentinelScanTask,
        repo_config: &RepoConfigRecord,
    ) -> GitCredentials {
        self.resolve_credentials(task.tenant_id, repo_config, task.repo_config_id)
            .await
    }

    /// Shared core of git-credential resolution: prefers a per-repo
    /// `codescan_git_credentials` row (via `repo_config.credential_id`) when
    /// one is configured and usable, falling back to the worker-wide
    /// `GIT_TOKEN`/`GIT_API_BASE_URL` config otherwise. Every failure mode
    /// (no credential configured, missing encryption key, credential not
    /// found/inactive/expired/wrong-type, decrypt failure) degrades to the
    /// fallback with a warning rather than failing the caller — mirrors how
    /// `git_provider::fetch_pr_diff` failures degrade to an empty diff
    /// rather than aborting. `log_id` is purely a tracing field (the
    /// review id for the AI-review pipeline, the repo config id for
    /// Sentinel) — it has no effect on which credential is chosen.
    async fn resolve_credentials(
        &self,
        tenant_id: Uuid,
        repo_config: &RepoConfigRecord,
        log_id: i64,
    ) -> GitCredentials {
        let fallback = || GitCredentials {
            provider: repo_config._provider.clone(),
            token: self.config.git_token.clone().unwrap_or_default(),
            base_url: self.config.git_api_base_url.clone(),
        };

        let Some(credential_id) = repo_config.credential_id else {
            return fallback();
        };

        let Some(key) = &self.config.credential_encryption_key else {
            tracing::warn!(
                log_id,
                credential_id,
                "repo has a git credential configured but CREDENTIAL_ENCRYPTION_KEY is unset, \
                 falling back to the worker-wide GIT_TOKEN"
            );
            return fallback();
        };

        let cipher = match CredentialCipher::from_base64_key(key) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    log_id,
                    error = ?e,
                    "invalid CREDENTIAL_ENCRYPTION_KEY, falling back to the worker-wide GIT_TOKEN"
                );
                return fallback();
            }
        };

        let credential = match db::get_git_credential(&self.pool, credential_id, tenant_id).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    log_id,
                    credential_id,
                    error = %e,
                    "git credential not found for this tenant, falling back to the worker-wide GIT_TOKEN"
                );
                return fallback();
            }
        };

        if !credential.is_active {
            tracing::warn!(
                log_id,
                credential_id,
                "git credential is inactive, falling back to the worker-wide GIT_TOKEN"
            );
            return fallback();
        }
        if credential.credential_type != "token" {
            tracing::warn!(
                log_id,
                credential_id,
                credential_type = %credential.credential_type,
                "only 'token' credentials are usable for API-based diff fetching, \
                 falling back to the worker-wide GIT_TOKEN"
            );
            return fallback();
        }
        if credential.platform != repo_config._provider {
            tracing::warn!(
                log_id,
                credential_id,
                credential_platform = %credential.platform,
                repo_provider = %repo_config._provider,
                "git credential platform does not match the repo's provider (misconfigured \
                 credential_id), falling back to the worker-wide GIT_TOKEN"
            );
            return fallback();
        }
        if let Some(expires_at) = credential.token_expires_at
            && expires_at < Utc::now()
        {
            tracing::warn!(
                log_id,
                credential_id,
                "git credential has expired, falling back to the worker-wide GIT_TOKEN"
            );
            return fallback();
        }

        match cipher.decrypt(&credential.encrypted_token) {
            Ok(token) => GitCredentials {
                provider: credential.platform,
                token,
                base_url: self.config.git_api_base_url.clone(),
            },
            Err(e) => {
                tracing::warn!(
                    log_id,
                    credential_id,
                    error = ?e,
                    "failed to decrypt git credential, falling back to the worker-wide GIT_TOKEN"
                );
                fallback()
            }
        }
    }

    /// Create the appropriate AI provider based on config. Every credential/
    /// URL is sourced from `self.config` (resolved once at startup by
    /// `WorkerConfig::from_env`) rather than re-read from `std::env::var`
    /// here — keeps env access centralized and makes this deterministically
    /// testable by constructing a `WorkerConfig` directly.
    fn create_provider(&self) -> anyhow::Result<Box<dyn CompletionProvider>> {
        match self.config.ai_provider.to_lowercase().as_str() {
            "anthropic" => {
                let api_key = self
                    .config
                    .anthropic_api_key
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("ANTHROPIC_API_KEY not set"))?;
                Ok(Box::new(AnthropicProvider::new(api_key)?))
            }
            "openai" => {
                let api_key = self
                    .config
                    .openai_api_key
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("OPENAI_API_KEY not set"))?;
                Ok(Box::new(OpenaiProvider::new(api_key)?))
            }
            "ollama" => Ok(Box::new(OllamaProvider::new(
                self.config.ollama_url.clone(),
            )?)),
            _ => Err(anyhow::anyhow!(
                "unknown AI provider: {}",
                self.config.ai_provider
            )),
        }
    }

    /// Whether CodeScan Sentinel P3's AI reachability triage + policy
    /// engine should run at all for this tenant
    /// (docs/v2-port/v2.1-codescan-sentinel.md §13: Enterprise-only). Checked
    /// fresh per scan (not cached at startup) so a tier change takes effect
    /// on the next scan without a restart, matching
    /// `scheduler::run`'s "re-checks on every tick" convention. Fails safe:
    /// an unreachable license server degrades to `Tier::Free`
    /// (`penguin_licensing::LicenseClient::tier`), never Enterprise.
    async fn ai_triage_and_policy_enabled(&self) -> bool {
        self.license
            .check_tier(penguin_licensing::Tier::Enterprise)
            .await
    }

    /// Builds the WaddleAI provider for this scan's AI triage calls, or
    /// `None` when unconfigured (`WADDLEAI_BASE_URL`/`WADDLEAI_API_KEY`
    /// unset) — the graceful-degradation path spec §4 requires: an
    /// Enterprise tenant with no WaddleAI deployment reachable from this
    /// worker still gets deterministic scanning + the policy engine's
    /// default matrix (`ReachabilityBucket::Unknown`), just no AI verdicts.
    /// Logged once per call (never per-finding) so an unreachable/
    /// misconfigured WaddleAI doesn't spam the log once per finding in a
    /// large scan.
    fn build_waddleai_provider(&self) -> Option<Box<dyn CompletionProvider>> {
        let (Some(base_url), Some(api_key)) = (
            self.config.waddleai_base_url.clone(),
            self.config.waddleai_api_key.clone(),
        ) else {
            tracing::info!(
                "sentinel: WaddleAI not configured (WADDLEAI_BASE_URL/WADDLEAI_API_KEY unset), \
                 skipping AI triage this scan — deterministic findings and the policy engine's \
                 default matrix still apply"
            );
            return None;
        };
        match skauswatch_ai::waddleai::WaddleAiProvider::new(base_url, api_key) {
            Ok(p) => Some(Box::new(p)),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "sentinel: failed to construct the WaddleAI provider, skipping AI triage \
                     this scan"
                );
                None
            }
        }
    }

    /// Execute the review pipeline for a task, calling AI provider with real PR diff.
    async fn execute_pipeline(
        &self,
        task: &CodeScanReviewTask,
        creds: &GitCredentials,
    ) -> anyhow::Result<ReviewOutput> {
        let provider = self.create_provider()?;

        // Fetch real PR/MR diff from GitHub or GitLab.
        let code_diff = git_provider::fetch_pr_diff(&task.pr_url, creds)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(
                    review_id = task.review_id,
                    error = %e,
                    "failed to fetch PR diff, using empty"
                );
                String::new()
            });

        // If diff is empty, return early with no findings.
        if code_diff.trim().is_empty() {
            return Ok(ReviewOutput {
                _files_reviewed: 0,
                comments: vec![],
                summary: "No code changes detected or failed to fetch PR diff".to_string(),
            });
        }

        // Language/framework detection and license-compliance scanning are
        // diff-only and independent of the AI call below — run them first so
        // they persist even if the AI provider subsequently fails (that
        // failure marks the review "failed" via `handle`, but these findings
        // remain valid metadata regardless of review outcome). Both are
        // best-effort: a write failure is logged and skipped, never
        // propagated as a pipeline error (matches `db::insert_review_comment`
        // call sites in `handle`).
        self.record_detections(task, &code_diff).await;
        self.record_license_findings(task, &code_diff).await;

        // Prepare review prompt with system context.
        let system_prompt = "You are a code reviewer. Analyze the diff for security, \
                            best practices, and performance issues. Return findings as JSON array \
                            with: line_start (int), severity (critical/major/minor/suggestion), \
                            title (str), body (str).";

        let user_prompt = format!("Review this code diff:\n\n{}", code_diff);

        let req = CompletionRequest {
            model: self.config.ai_model.clone(),
            messages: vec![
                Message {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                Message {
                    role: "user".to_string(),
                    content: user_prompt.clone(),
                },
            ],
            max_tokens: 2000,
        };

        let call_started = std::time::Instant::now();
        let response = provider.complete(req).await?;
        let latency_ms = i64::try_from(call_started.elapsed().as_millis()).unwrap_or(i64::MAX);

        self.record_provider_usage(
            task,
            system_prompt,
            &user_prompt,
            &response.content,
            &response.model,
            latency_ms,
        )
        .await;

        // Parse the AI response to extract findings/comments.
        let comments = crate::review::parse_ai_response(&response.content)?;

        let summary = format!(
            "Reviewed {} for security, best practices, and performance ({} comments)",
            task.repo_name,
            comments.len()
        );

        Ok(ReviewOutput {
            _files_reviewed: 1,
            comments,
            summary,
        })
    }

    /// Writes language/framework detections for `diff` (see
    /// `crate::detection`). Best-effort — logs and continues on any write
    /// failure rather than failing the review.
    async fn record_detections(&self, task: &CodeScanReviewTask, diff: &str) {
        for d in detection::detect_from_diff(diff) {
            if let Err(e) = db::insert_review_detection(
                &self.pool,
                task.review_id,
                task.tenant_id,
                d.detection_type,
                &d.name,
                d.confidence,
                d.file_count,
            )
            .await
            {
                tracing::warn!(
                    review_id = task.review_id,
                    error = %e,
                    detection = %d.name,
                    "failed to insert review detection"
                );
            }
        }
    }

    /// Scans `diff` for added dependencies (see `crate::license_scan`),
    /// resolves each one's license, evaluates it against
    /// `codescan_license_policies`, and records a
    /// `codescan_license_detections` row (plus a
    /// `codescan_license_violations` row when the tenant has a
    /// `review_required`/`blocked` policy for that license). Best-effort —
    /// logs and continues on any write failure rather than failing the
    /// review; a license this tenant has not configured a policy for is
    /// recorded but never treated as a violation (see
    /// `db::get_license_policy`'s doc comment).
    async fn record_license_findings(&self, task: &CodeScanReviewTask, diff: &str) {
        for finding in self.registry_client.scan_diff(diff).await {
            let policy = match &finding.license_name {
                Some(name) => {
                    match db::get_license_policy(&self.pool, task.tenant_id, name).await {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!(
                                review_id = task.review_id,
                                error = %e,
                                license = %name,
                                "failed to look up license policy"
                            );
                            None
                        }
                    }
                }
                None => None,
            };
            let policy_violation = matches!(
                policy.as_ref().map(|p| p.policy.as_str()),
                Some("review_required") | Some("blocked")
            );

            let detection_id = match db::insert_license_detection(
                &self.pool,
                task.review_id,
                task.tenant_id,
                &finding.package_name,
                &finding.package_version,
                finding.license_name.as_deref(),
                finding.license_source,
                &finding.file_path,
                finding.confidence,
                policy_violation,
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::warn!(
                        review_id = task.review_id,
                        error = %e,
                        package = %finding.package_name,
                        "failed to insert license detection"
                    );
                    continue;
                }
            };

            if !policy_violation {
                continue;
            }
            let Some(p) = &policy else { continue };
            let severity = if p.policy == "blocked" {
                "critical"
            } else {
                "medium"
            };
            let license_name = finding.license_name.as_deref().unwrap_or("unknown");
            if let Err(e) = db::insert_license_violation(
                &self.pool,
                task.review_id,
                task.tenant_id,
                detection_id,
                license_name,
                &finding.package_name,
                &p.policy,
                severity,
                p.actions.as_ref(),
            )
            .await
            {
                tracing::warn!(
                    review_id = task.review_id,
                    error = %e,
                    package = %finding.package_name,
                    "failed to insert license violation"
                );
            }
        }
    }

    /// Records approximate token usage/cost for one AI provider call.
    /// Best-effort — logs and continues on write failure.
    ///
    /// `skauswatch_ai::CompletionResponse` does not expose provider-reported
    /// token counts (see crates/skauswatch-ai/src/lib.rs, out of scope for
    /// this service to change), so token counts here are a `chars / 4`
    /// approximation — the commonly-cited rule of thumb for English text —
    /// not a billed-usage reconciliation figure. `cost_estimate` uses a
    /// small hardcoded blended per-1K-token rate per provider for the same
    /// reason; both are for cost-tracking dashboards, not invoicing.
    async fn record_provider_usage(
        &self,
        task: &CodeScanReviewTask,
        system_prompt: &str,
        user_prompt: &str,
        response_content: &str,
        response_model: &str,
        latency_ms: i64,
    ) {
        let prompt_tokens = estimate_tokens(system_prompt) + estimate_tokens(user_prompt);
        let completion_tokens = estimate_tokens(response_content);
        let cost_estimate =
            estimate_cost_usd(&self.config.ai_provider, prompt_tokens, completion_tokens);

        if let Err(e) = db::insert_provider_usage(
            &self.pool,
            task.review_id,
            task.tenant_id,
            &self.config.ai_provider,
            response_model,
            prompt_tokens,
            completion_tokens,
            latency_ms,
            cost_estimate,
        )
        .await
        {
            tracing::warn!(
                review_id = task.review_id,
                error = %e,
                "failed to insert provider usage"
            );
        }
    }

    // ── CodeScan Sentinel (docs/v2-port/v2.1-codescan-sentinel.md §9-§12) ──

    /// Orchestrates one Sentinel scan task: resolves the repo's default +
    /// latest release branch and scans each independently. One branch
    /// failing to resolve credentials/branches is a hard error (retried by
    /// the stream consumer); a single branch's *scan* failing is recorded
    /// on its own `codescan_scan_runs` row and never blocks the other
    /// branch (see `scan_and_persist_branch`).
    async fn handle_sentinel_scan(
        &self,
        entry: &StreamEntry,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let task = SentinelScanTask::from_stream_entry(entry)
            .map_err(|e| format!("parse sentinel task: {}", e))?;

        tracing::info!(
            repo_config_id = task.repo_config_id,
            repo = %task.repo_name,
            "processing CodeScan Sentinel scan task"
        );

        let repo_config =
            match db::get_repo_config(&self.pool, task.repo_config_id, task.tenant_id).await {
                Ok(rc) => rc,
                Err(e) => {
                    tracing::error!(
                        repo_config_id = task.repo_config_id,
                        error = %e,
                        "sentinel: repo config not found"
                    );
                    return Err(format!("get repo config: {}", e).into());
                }
            };

        let git_creds = self
            .resolve_sentinel_git_credentials(&task, &repo_config)
            .await;
        if git_creds.token.is_empty() {
            tracing::warn!(
                repo_config_id = task.repo_config_id,
                "sentinel: no usable git credential (neither a per-repo credential nor \
                 GIT_TOKEN), skipping scan"
            );
            return Ok(());
        }

        let branches =
            match sentinel::resolve_target_branches(&task.provider, &task.repo_url, &git_creds)
                .await
            {
                Ok(b) => b,
                Err(e) => {
                    tracing::error!(
                        repo_config_id = task.repo_config_id,
                        error = %e,
                        "sentinel: failed to resolve target branches"
                    );
                    return Err(format!("resolve target branches: {}", e).into());
                }
            };

        for branch in branches {
            self.scan_and_persist_branch(&task, &branch, &git_creds)
                .await;
        }

        Ok(())
    }

    /// Scans one (repo, branch), upserts every computed finding, resolves
    /// findings that vanished this run, records the `codescan_scan_runs`
    /// row, and bridges any newly-alertable critical/high CVE finding into
    /// `alerts`. Every failure here is logged and swallowed rather than
    /// propagated — one branch's persistence trouble must never abort the
    /// other branch's scan.
    async fn scan_and_persist_branch(
        &self,
        task: &SentinelScanTask,
        branch: &str,
        git_creds: &GitCredentials,
    ) {
        let run_id =
            match db::start_scan_run(&self.pool, task.tenant_id, task.repo_config_id, branch).await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!(
                        repo_config_id = task.repo_config_id,
                        branch,
                        error = %e,
                        "sentinel: failed to start scan run"
                    );
                    return;
                }
            };

        let findings = sentinel::scan_branch(
            &task.provider,
            &task.repo_url,
            branch,
            git_creds,
            &self.registry_client,
        )
        .await;

        // CodeScan Sentinel P3 (spec §4/§5/§6, Enterprise-only — see
        // `ai_triage_and_policy_enabled`): a second, independent fetch of
        // the branch tree from `scan_and_persist_tool_findings`'s own below
        // — a known, documented inefficiency (two archive downloads per
        // branch scan when both P3 and the P2 tool registry run) rather
        // than threading a shared `WorkingTree` through both, to keep this
        // change additive and not touch the already-covered P2 tool-registry
        // path. Only fetched when there's at least one sca/cve finding to
        // triage and the tenant is Enterprise-licensed.
        let ai_policy_enabled = self.ai_triage_and_policy_enabled().await;
        let (prefilter_tree, policy_rules, waddleai_provider) =
            if ai_policy_enabled && !findings.is_empty() {
                let tree = match tree_fetch::fetch_branch_tree(
                    &task.provider,
                    &task.repo_url,
                    branch,
                    git_creds,
                )
                .await
                {
                    Ok(t) => Some(t),
                    Err(e) => {
                        tracing::warn!(
                            repo_config_id = task.repo_config_id,
                            branch,
                            error = %e,
                            "sentinel: failed to fetch branch tree for the reachability \
                             prefilter, treating every dependency as used (fail open)"
                        );
                        None
                    }
                };
                let rules = match db::list_policy_rules(&self.pool, task.tenant_id).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!(
                            repo_config_id = task.repo_config_id,
                            branch,
                            error = %e,
                            "sentinel: failed to load policy rules, falling back to the \
                             default matrix only"
                        );
                        Vec::new()
                    }
                };
                (tree, rules, self.build_waddleai_provider())
            } else {
                (None, Vec::new(), None)
            };

        let mut seen_ids = Vec::with_capacity(findings.len());
        for finding in &findings {
            let upserted = match db::upsert_finding(
                &self.pool,
                task.tenant_id,
                task.repo_config_id,
                branch,
                finding.kind,
                finding.ecosystem,
                &finding.package_name,
                &finding.current_version,
                finding.latest_version.as_deref(),
                &finding.advisory_id,
                &finding.severity,
            )
            .await
            {
                Ok(u) => u,
                Err(e) => {
                    tracing::warn!(
                        repo_config_id = task.repo_config_id,
                        branch,
                        package = %finding.package_name,
                        error = %e,
                        "sentinel: failed to upsert finding"
                    );
                    continue;
                }
            };
            seen_ids.push(upserted.id);

            let should_alert = self
                .triage_and_resolve_action(
                    task,
                    finding,
                    upserted.id,
                    ai_policy_enabled,
                    prefilter_tree.as_ref(),
                    &policy_rules,
                    waddleai_provider.as_deref(),
                )
                .await;
            if upserted.needs_alert && should_alert {
                self.bridge_alert(task, branch, finding, upserted.id).await;
            }
        }

        if let Err(e) = db::resolve_stale_findings(
            &self.pool,
            task.tenant_id,
            task.repo_config_id,
            branch,
            &["sca", "cve"],
            &seen_ids,
        )
        .await
        {
            tracing::warn!(
                repo_config_id = task.repo_config_id,
                branch,
                error = %e,
                "sentinel: failed to resolve stale findings"
            );
        }

        let tool_findings_count = self
            .scan_and_persist_tool_findings(task, branch, git_creds, run_id)
            .await;

        let findings_count =
            i64::try_from(findings.len() + tool_findings_count).unwrap_or(i64::MAX);
        if let Err(e) =
            db::finish_scan_run(&self.pool, run_id, "completed", findings_count, None).await
        {
            tracing::warn!(
                repo_config_id = task.repo_config_id,
                branch,
                error = %e,
                "sentinel: failed to finish scan run"
            );
        }
    }

    /// Runs the P2 tool registry (SAST/secrets/IaC/SBOM,
    /// docs/v2-port/v2.1-codescan-sentinel.md §3) against `branch`'s fetched
    /// working tree, upserting every tool finding and persisting any SBOM
    /// document produced. Returns the number of tool findings upserted (for
    /// `scan_and_persist_branch`'s `codescan_scan_runs.findings_count`).
    ///
    /// A tree-fetch failure (network hiccup, oversized archive, unsupported
    /// provider) skips the entire tool pass for this run — logged, never
    /// fatal — and deliberately does *not* call `resolve_stale_findings` for
    /// the tool kinds in that case, so a transient fetch failure can never
    /// masquerade as "every previously-open tool finding vanished" (see
    /// `db::resolve_stale_findings`'s doc comment).
    async fn scan_and_persist_tool_findings(
        &self,
        task: &SentinelScanTask,
        branch: &str,
        git_creds: &GitCredentials,
        run_id: i64,
    ) -> usize {
        let tree =
            match tree_fetch::fetch_branch_tree(&task.provider, &task.repo_url, branch, git_creds)
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(
                        repo_config_id = task.repo_config_id,
                        branch,
                        error = %e,
                        "sentinel: failed to fetch branch tree, skipping tool-based scan"
                    );
                    return 0;
                }
            };

        let mut seen_ids = Vec::new();
        let mut count = 0usize;
        for tool in &self.tool_registry {
            if !tool.is_applicable(tree.files()) {
                continue;
            }
            let outcome = match tool.scan(tree.root(), self.process_runner.as_ref()).await {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(
                        repo_config_id = task.repo_config_id,
                        branch,
                        tool = tool.name(),
                        error = %e,
                        "sentinel: tool scan failed"
                    );
                    continue;
                }
            };

            match outcome {
                ScanOutcome::Unavailable => {
                    tracing::info!(
                        repo_config_id = task.repo_config_id,
                        branch,
                        tool = tool.name(),
                        "sentinel: tool binary unavailable in this image, skipped"
                    );
                }
                ScanOutcome::Findings(tool_findings) => {
                    count += tool_findings.len();
                    for finding in &tool_findings {
                        match db::upsert_tool_finding(
                            &self.pool,
                            task.tenant_id,
                            task.repo_config_id,
                            branch,
                            finding,
                        )
                        .await
                        {
                            Ok(u) => seen_ids.push(u.id),
                            Err(e) => tracing::warn!(
                                repo_config_id = task.repo_config_id,
                                branch,
                                tool = tool.name(),
                                error = %e,
                                "sentinel: failed to upsert tool finding"
                            ),
                        }
                    }
                }
                ScanOutcome::Sbom(doc) => {
                    if let Err(e) = self.persist_sbom(task, branch, run_id, &doc).await {
                        tracing::warn!(
                            repo_config_id = task.repo_config_id,
                            branch,
                            tool = tool.name(),
                            error = %e,
                            "sentinel: failed to persist sbom artifact"
                        );
                    }
                }
            }
        }

        if let Err(e) = db::resolve_stale_findings(
            &self.pool,
            task.tenant_id,
            task.repo_config_id,
            branch,
            &["sast", "secret", "iac"],
            &seen_ids,
        )
        .await
        {
            tracing::warn!(
                repo_config_id = task.repo_config_id,
                branch,
                error = %e,
                "sentinel: failed to resolve stale tool findings"
            );
        }

        count
    }

    /// Gzip-compresses `doc` and stores it in `codescan_sbom_artifacts`,
    /// scoped to this scan run — see `db::insert_sbom_artifact`.
    async fn persist_sbom(
        &self,
        task: &SentinelScanTask,
        branch: &str,
        run_id: i64,
        doc: &scanner_tool::SbomDocument,
    ) -> anyhow::Result<()> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&doc.content)?;
        let gzipped = encoder.finish()?;
        db::insert_sbom_artifact(
            &self.pool,
            task.tenant_id,
            task.repo_config_id,
            branch,
            run_id,
            doc.format,
            &gzipped,
        )
        .await
    }

    /// Runs P3's static prefilter, then (if configured) AI reachability
    /// triage, then the policy engine, for one SCA/CVE finding. Persists
    /// whatever verdict/action resulted and returns whether the resolved
    /// action is `"alert"` — the only action `bridge_alert` honors (spec
    /// §6: "the existing alert bridge should honour it").
    ///
    /// When `ai_policy_enabled` is `false` (below Enterprise tier), this
    /// is a no-op returning the pre-P3 deterministic rule unchanged: every
    /// critical/high `cve` finding alerts, exactly as
    /// `CodeScanReviewHandler` behaved before P3 existed — a
    /// Professional-tier tenant's alerting must never regress just because
    /// this module now exists (spec §13: deterministic scanning stands
    /// alone without WaddleAI/Enterprise).
    #[allow(clippy::too_many_arguments)]
    async fn triage_and_resolve_action(
        &self,
        task: &SentinelScanTask,
        finding: &sentinel::ScanFinding,
        finding_id: i64,
        ai_policy_enabled: bool,
        tree: Option<&tree_fetch::WorkingTree>,
        policy_rules: &[policy::PolicyRule],
        waddleai_provider: Option<&dyn CompletionProvider>,
    ) -> bool {
        let legacy_should_alert =
            finding.kind == "cve" && matches!(finding.severity.as_str(), "critical" | "high");
        if !ai_policy_enabled {
            return legacy_should_alert;
        }

        // Static prefilter (spec §5 point 1) — the cheap, deterministic
        // pass that runs before any AI spend. A missing tree (fetch failed
        // above) fails open (`used: true`) rather than ever asserting
        // "not used" from ignorance — see `reachability`'s module docs.
        let prefilter = tree
            .map(|t| {
                reachability::analyze(
                    t.root(),
                    t.files(),
                    finding.ecosystem,
                    &finding.package_name,
                    None,
                )
            })
            .unwrap_or(reachability::PrefilterResult {
                used: true,
                symbol_referenced: None,
                evidence: Vec::new(),
            });

        let reachability_verdict = if !prefilter.used {
            // Unused package: the cheap win — record the verdict and skip
            // AI triage entirely (spec §5: "kills most noise for free").
            if let Err(e) = db::upsert_prefilter_verdict(&self.pool, finding_id, false).await {
                tracing::warn!(
                    finding_id,
                    error = %e,
                    "sentinel: failed to persist prefilter verdict"
                );
            }
            policy::Reachability {
                used: Some(false),
                reachable: None,
                exposure: None,
            }
        } else if let Some(provider) = waddleai_provider {
            let input = triage::TriageInput {
                package_name: &finding.package_name,
                ecosystem: finding.ecosystem,
                current_version: &finding.current_version,
                advisory_id: &finding.advisory_id,
                severity: &finding.severity,
                cve_summary: None,
                evidence: &prefilter.evidence,
            };
            match triage::triage_finding(provider, &self.config.waddleai_tier, &input).await {
                Some(verdict) => {
                    if let Err(e) = db::upsert_ai_verdict(
                        &self.pool,
                        finding_id,
                        &db::AiVerdict {
                            used: verdict.used,
                            reachable: verdict.reachable,
                            exposure: verdict.exposure.as_str(),
                            ai_severity: verdict.severity_adjustment.clone(),
                            ai_rationale: verdict.rationale.clone(),
                        },
                    )
                    .await
                    {
                        tracing::warn!(
                            finding_id,
                            error = %e,
                            "sentinel: failed to persist AI verdict"
                        );
                    }
                    policy::Reachability {
                        used: Some(verdict.used),
                        reachable: Some(verdict.reachable),
                        exposure: Some(verdict.exposure),
                    }
                }
                // WaddleAI call failed or returned an unschema'd response —
                // `triage::triage_finding` already logged; the finding
                // keeps its deterministic verdict (no reachable/exposure
                // data), which the default matrix's `Unknown` bucket
                // handles by failing open on critical/high severity.
                None => policy::Reachability {
                    used: Some(true),
                    reachable: None,
                    exposure: None,
                },
            }
        } else {
            // WaddleAI unconfigured/unreachable this run (already logged
            // once by `build_waddleai_provider`) — same `Unknown`-bucket
            // fallback as an unparseable AI response above.
            policy::Reachability {
                used: Some(true),
                reachable: None,
                exposure: None,
            }
        };

        let ctx = policy::FindingContext {
            repo: task.repo_name.clone(),
            ecosystem: finding.ecosystem.to_owned(),
            package: finding.package_name.clone(),
            cve: finding.advisory_id.clone(),
            severity: finding.severity.clone(),
            tool: String::new(),
            kind: finding.kind.to_owned(),
            reachability: reachability_verdict,
        };
        let decision = policy::evaluate(&ctx, policy_rules);
        if let Err(e) =
            db::apply_policy_decision(&self.pool, task.tenant_id, finding_id, &decision).await
        {
            tracing::warn!(
                finding_id,
                error = %e,
                "sentinel: failed to persist policy decision"
            );
        }
        decision.action == "alert"
    }

    /// Writes one `alerts` row for a newly-alertable critical/high CVE
    /// finding and marks the finding alerted. Never propagates a failure —
    /// an alert-bridge problem must not fail the scan that found the CVE in
    /// the first place (the finding itself is already persisted).
    async fn bridge_alert(
        &self,
        task: &SentinelScanTask,
        branch: &str,
        finding: &sentinel::ScanFinding,
        finding_id: i64,
    ) {
        let title = format!(
            "{} in {}@{} ({})",
            finding.advisory_id, finding.package_name, finding.current_version, task.repo_name
        );
        let description = format!(
            "CodeScan Sentinel found {} affecting {} {} on {}:{} (ecosystem: {}, latest: {})",
            finding.advisory_id,
            finding.package_name,
            finding.current_version,
            task.repo_name,
            branch,
            finding.ecosystem,
            finding.latest_version.as_deref().unwrap_or("unknown"),
        );
        let indicators = serde_json::json!([
            task.repo_name,
            branch,
            finding.package_name,
            finding.advisory_id,
        ]);

        match db::insert_sentinel_alert(
            &self.pool,
            task.tenant_id,
            &title,
            &description,
            &finding.severity,
            &indicators,
        )
        .await
        {
            Ok(()) => {
                if let Err(e) = db::mark_finding_alerted(&self.pool, finding_id).await {
                    tracing::warn!(
                        finding_id,
                        error = %e,
                        "sentinel: alert written but failed to mark finding alerted"
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    finding_id,
                    error = %e,
                    "sentinel: failed to write alert for a critical/high finding"
                );
            }
        }
    }
}

/// `chars / 4` token-count approximation — see `record_provider_usage`'s doc
/// comment for why this is heuristic rather than provider-reported.
fn estimate_tokens(text: &str) -> i32 {
    let chars = text.chars().count();
    i32::try_from(chars.div_ceil(4)).unwrap_or(i32::MAX)
}

/// Best-effort blended USD-per-1K-token cost estimate. Rates are
/// approximate and not kept in sync with provider pricing pages — see
/// `record_provider_usage`'s doc comment.
fn estimate_cost_usd(provider: &str, prompt_tokens: i32, completion_tokens: i32) -> Option<f64> {
    let (in_per_1k, out_per_1k) = match provider.to_lowercase().as_str() {
        "anthropic" => (0.003, 0.015),
        "openai" => (0.0025, 0.01),
        // Self-hosted: no per-token billing to estimate.
        "ollama" => return None,
        _ => return None,
    };
    Some(
        (f64::from(prompt_tokens) / 1000.0) * in_per_1k
            + (f64::from(completion_tokens) / 1000.0) * out_per_1k,
    )
}

#[async_trait::async_trait]
impl StreamHandler for CodeScanReviewHandler {
    async fn handle(
        &self,
        entry: &StreamEntry,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // `codescan:tasks` carries two task shapes; entries with no
        // task_type field (the pre-existing AI-review pipeline) fall
        // through to the review parse below unchanged.
        if stream_task_type(entry) == "sentinel_scan" {
            return self.handle_sentinel_scan(entry).await;
        }

        // Parse the task from stream entry.
        let task = CodeScanReviewTask::from_stream_entry(entry)
            .map_err(|e| format!("parse task: {}", e))?;

        tracing::info!(
            review_id = task.review_id,
            repo = %task.repo_name,
            pr = %task.pr_url,
            "processing CodeScan review task"
        );

        // Mark review as processing. Scoped to the task's validated tenant —
        // a spoofed/mismatched tenant simply matches zero rows here; the
        // get_review call immediately below is what actually surfaces the
        // tenant mismatch as an error and aborts the task.
        if let Err(e) =
            db::update_review_status(&self.pool, task.review_id, task.tenant_id, "processing").await
        {
            tracing::error!(review_id = task.review_id, error = %e, "failed to mark review processing");
            return Err(format!("db update status: {}", e).into());
        }

        // Validate that review exists *for this tenant* and fetch details.
        // A review that exists under a different tenant is indistinguishable
        // from a missing review — see db::get_review's doc comment.
        let review = match db::get_review(&self.pool, task.review_id, task.tenant_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(review_id = task.review_id, error = %e, "review not found");
                let _ = db::mark_review_failed(
                    &self.pool,
                    task.review_id,
                    task.tenant_id,
                    "review not found",
                )
                .await;
                return Err(format!("get review: {}", e).into());
            }
        };

        // Fetch repo configuration and credentials, scoped to the same tenant.
        let repo_config = match db::get_repo_config(
            &self.pool,
            review.repo_config_id,
            task.tenant_id,
        )
        .await
        {
            Ok(rc) => rc,
            Err(e) => {
                tracing::error!(review_id = task.review_id, error = %e, "repo config not found");
                let _ = db::mark_review_failed(
                    &self.pool,
                    task.review_id,
                    task.tenant_id,
                    "repo config not found",
                )
                .await;
                return Err(format!("get repo config: {}", e).into());
            }
        };

        // Resolve git credentials: prefer the repo's own
        // codescan_git_credentials row (see `resolve_git_credentials`),
        // falling back to the worker-wide GIT_TOKEN/GIT_API_BASE_URL config.
        let git_creds = self.resolve_git_credentials(&task, &repo_config).await;
        if git_creds.token.is_empty() {
            tracing::warn!(
                review_id = task.review_id,
                "no usable git credential (neither a per-repo credential nor GIT_TOKEN), \
                 skipping PR diff fetch"
            );
        }

        // Execute the review pipeline.
        let review_result = match self.execute_pipeline(&task, &git_creds).await {
            Ok(result) => result,
            Err(e) => {
                tracing::error!(review_id = task.review_id, error = %e, "review execution failed");
                let error_msg = e.to_string();
                let _ =
                    db::mark_review_failed(&self.pool, task.review_id, task.tenant_id, &error_msg)
                        .await;
                return Err(format!("execute review: {}", e).into());
            }
        };

        // Persist review comments.
        let mut comments_count = 0i64;
        for comment in &review_result.comments {
            match db::insert_review_comment(
                &self.pool,
                task.review_id,
                task.tenant_id,
                &comment.file_path,
                comment.line_start,
                &format!("**{}**\n\n{}", comment.title, comment.body),
                &comment.severity,
            )
            .await
            {
                Ok(_) => comments_count += 1,
                Err(e) => {
                    tracing::warn!(review_id = task.review_id, error = %e, "failed to insert comment");
                }
            }
        }

        // Mark review as completed.
        if let Err(e) = db::complete_review(
            &self.pool,
            task.review_id,
            task.tenant_id,
            &review_result.summary,
            comments_count,
        )
        .await
        {
            tracing::error!(review_id = task.review_id, error = %e, "failed to complete review");
            return Err(format!("complete review: {}", e).into());
        }

        // Publish result to codescan:results stream for any downstream consumers.
        let result_fields = vec![
            ("review_id".to_string(), task.review_id.to_string()),
            ("status".to_string(), "completed".to_string()),
            ("comments_count".to_string(), comments_count.to_string()),
            ("summary".to_string(), review_result.summary),
            ("completed_at".to_string(), Utc::now().to_rfc3339()),
        ];

        if let Err(e) = self
            .producer
            .publish("codescan:results", result_fields)
            .await
        {
            tracing::warn!(review_id = task.review_id, error = %e, "failed to publish result");
        }

        tracing::info!(
            review_id = task.review_id,
            comments = comments_count,
            "CodeScan review completed"
        );

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use penguin_licensing::{LicenseClient, LicenseConfig};
    use sqlx::Row;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// Dev-bypass license client (`skauswatch.app` domain bypass — see
    /// `penguintech.md` License Bypass Domains) — behaves as `Tier::Enterprise`
    /// for every check, matching every other test module's `dev_license()`
    /// convention (e.g. `codescan-backend`'s `routes::tests`). The default
    /// for every pre-existing test in this module: P3's AI triage + policy
    /// engine runs, but with no `WADDLEAI_BASE_URL` configured (`base_config`
    /// never sets it), so it exercises the "Enterprise-licensed, WaddleAI
    /// unconfigured" degrade path unless a test opts into a real mock via
    /// `sentinel_config_with_waddleai`.
    #[allow(clippy::panic)]
    fn dev_license() -> Arc<LicenseClient> {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    /// A license client with the dev bypass disabled — resolves to
    /// `Tier::Free` with no license server reachable (fail-safe default),
    /// for proving P3's Enterprise gate actually gates.
    #[allow(clippy::panic)]
    fn gated_license() -> Arc<LicenseClient> {
        let mut cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        cfg.release_mode = true;
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    #[test]
    fn test_stream_handler_trait_object_safe() {
        // Verify that CodeScanReviewHandler can be used as a trait object.
        // This is a compile-time check; if it doesn't compile, the handler
        // isn't properly implementing StreamHandler.
        let _: Option<Box<dyn StreamHandler>> = None;
    }

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string())
    }

    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../codescan-backend/migrations"
        ))
        .await
    }

    /// Real Valkey connection (the verify harness runs a throwaway Valkey
    /// container alongside Postgres — see docs/v2-port/testing-pattern.md).
    /// A unique prefix per call keeps parallel tests from fighting over the
    /// same stream key, though `publish` failures are only warn-logged by
    /// the handler so this mostly matters for the connect step succeeding.
    async fn test_producer() -> StreamProducer {
        // Unique-enough prefix per call (std-only, no extra dependency) so
        // parallel tests don't share a stream key.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let prefix = format!("test-worker-codescan-{nanos}");
        StreamProducer::connect(&redis_url(), None, &prefix)
            .await
            .unwrap_or_else(|e| panic!("connect test redis: {e}"))
    }

    /// Deterministic base config for tests — every field is set explicitly
    /// (no env reads), so AI-provider/git credentials can be pointed at
    /// wiremock servers per test.
    fn base_config(ai_provider: &str) -> WorkerConfig {
        WorkerConfig {
            redis_url: redis_url(),
            redis_password: None,
            redis_prefix: "test".to_string(),
            consumer_group: "test-group".to_string(),
            consumer_name: "test-consumer".to_string(),
            max_concurrent_tasks: 1,
            health_port: 0,
            ai_provider: ai_provider.to_string(),
            ai_model: "test-model".to_string(),
            anthropic_api_key: None,
            openai_api_key: None,
            ollama_url: "http://localhost:11434".to_string(),
            git_token: None,
            git_api_base_url: None,
            _ai_timeout_sec: 60,
            _review_categories: vec![],
            credential_encryption_key: None,
            npm_registry_url: None,
            pypi_registry_url: None,
            crates_registry_url: None,
            go_registry_url: None,
            waddleai_base_url: None,
            waddleai_api_key: None,
            waddleai_tier: "reason".to_string(),
        }
    }

    /// Bootstrap tenant literal — matches manager's
    /// `crate::auth::DEFAULT_TENANT_ID` / codescan-backend's migration seed
    /// (see docs/v2-port/tenancy-model.md §8). Every seeded row and every
    /// `task_entry` in this module use this tenant by default so the two
    /// stay consistent; [`OTHER_TENANT_ID`] exists solely to prove
    /// cross-tenant isolation.
    const TEST_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";
    const OTHER_TENANT_ID: &str = "00000000-0000-0000-0000-0000000000bb";

    fn test_tenant() -> uuid::Uuid {
        TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("test tenant uuid: {e}"))
    }

    async fn seed_repo_config(pool: &PgPool, provider: &str) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(test_tenant())
        .bind(provider)
        .bind("https://github.com/acme/widgets")
        .bind("acme/widgets")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo config: {e}"));
        row.get::<i64, _>(0)
    }

    async fn seed_review(pool: &PgPool, repo_config_id: i64) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_reviews (repo_config_id, tenant_id, status) \
             VALUES ($1, $2, 'queued') RETURNING id",
        )
        .bind(repo_config_id)
        .bind(test_tenant())
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed review: {e}"));
        row.get::<i64, _>(0)
    }

    fn task_entry(review_id: i64, repo_config_id: i64, pr_url: &str) -> StreamEntry {
        let mut fields = HashMap::new();
        fields.insert("review_id".to_string(), review_id.to_string());
        fields.insert("repo_config_id".to_string(), repo_config_id.to_string());
        fields.insert("provider".to_string(), "github".to_string());
        fields.insert("repo_name".to_string(), "acme/widgets".to_string());
        fields.insert("pr_url".to_string(), pr_url.to_string());
        fields.insert("tenant_id".to_string(), TEST_TENANT_ID.to_string());
        StreamEntry {
            id: "1-0".to_string(),
            fields,
        }
    }

    /// A pool that never actually connects — fine for `create_provider`
    /// tests, which never touch `self.pool`.
    fn lazy_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@127.0.0.1:1/test")
            .unwrap_or_else(|e| panic!("lazy test pool: {e}"))
    }

    #[tokio::test]
    async fn create_provider_errors_without_anthropic_key() {
        let producer = test_producer().await;
        let handler = CodeScanReviewHandler::new(
            lazy_pool(),
            producer,
            base_config("anthropic"),
            dev_license(),
        );
        // `Box<dyn CompletionProvider>` isn't `Debug`, so `expect_err` isn't
        // usable here — match instead.
        let err = match handler.create_provider() {
            Err(e) => e,
            Ok(_) => panic!("expected an error when ANTHROPIC_API_KEY is unset"),
        };
        assert!(err.to_string().contains("ANTHROPIC_API_KEY"));
    }

    #[tokio::test]
    async fn create_provider_succeeds_with_anthropic_key() {
        let producer = test_producer().await;
        let mut cfg = base_config("anthropic");
        cfg.anthropic_api_key = Some("sk-test".to_string());
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg, dev_license());
        assert!(handler.create_provider().is_ok());
    }

    #[tokio::test]
    async fn create_provider_errors_with_empty_anthropic_key() {
        // Some(empty string) is a distinct branch from None (unset): the
        // `ok_or_else` above it succeeds, but `AnthropicProvider::new` itself
        // rejects an empty key.
        let producer = test_producer().await;
        let mut cfg = base_config("anthropic");
        cfg.anthropic_api_key = Some(String::new());
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg, dev_license());
        assert!(handler.create_provider().is_err());
    }

    #[tokio::test]
    async fn create_provider_errors_without_openai_key() {
        let producer = test_producer().await;
        let handler =
            CodeScanReviewHandler::new(lazy_pool(), producer, base_config("openai"), dev_license());
        let err = match handler.create_provider() {
            Err(e) => e,
            Ok(_) => panic!("expected an error when OPENAI_API_KEY is unset"),
        };
        assert!(err.to_string().contains("OPENAI_API_KEY"));
    }

    #[tokio::test]
    async fn create_provider_succeeds_with_openai_key() {
        let producer = test_producer().await;
        let mut cfg = base_config("openai");
        cfg.openai_api_key = Some("sk-test".to_string());
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg, dev_license());
        assert!(handler.create_provider().is_ok());
    }

    #[tokio::test]
    async fn create_provider_errors_with_empty_openai_key() {
        let producer = test_producer().await;
        let mut cfg = base_config("openai");
        cfg.openai_api_key = Some(String::new());
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg, dev_license());
        assert!(handler.create_provider().is_err());
    }

    #[tokio::test]
    async fn create_provider_succeeds_with_default_ollama_url() {
        let producer = test_producer().await;
        let handler =
            CodeScanReviewHandler::new(lazy_pool(), producer, base_config("ollama"), dev_license());
        assert!(handler.create_provider().is_ok());
    }

    #[tokio::test]
    async fn create_provider_errors_with_empty_ollama_url() {
        let producer = test_producer().await;
        let mut cfg = base_config("ollama");
        cfg.ollama_url = String::new();
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg, dev_license());
        assert!(handler.create_provider().is_err());
    }

    #[tokio::test]
    async fn create_provider_is_case_insensitive_and_rejects_unknown() {
        let producer = test_producer().await;
        let handler =
            CodeScanReviewHandler::new(lazy_pool(), producer, base_config("OLLAMA"), dev_license());
        assert!(handler.create_provider().is_ok());

        let producer = test_producer().await;
        let handler = CodeScanReviewHandler::new(
            lazy_pool(),
            producer,
            base_config("carrier-pigeon"),
            dev_license(),
        );
        let err = match handler.create_provider() {
            Err(e) => e,
            Ok(_) => panic!("expected an error for an unknown provider"),
        };
        assert!(err.to_string().contains("unknown AI provider"));
    }

    #[tokio::test]
    async fn handle_returns_err_on_malformed_stream_entry() {
        let pool = test_pool().await;
        let producer = test_producer().await;
        let handler =
            CodeScanReviewHandler::new(pool, producer, base_config("ollama"), dev_license());
        let entry = StreamEntry {
            id: "1-0".to_string(),
            fields: HashMap::new(),
        };
        let result = handler.handle(&entry).await;
        assert!(result.is_err(), "missing every field must fail to parse");
    }

    #[tokio::test]
    async fn handle_errors_when_review_does_not_exist() {
        let pool = test_pool().await;
        let producer = test_producer().await;
        let handler =
            CodeScanReviewHandler::new(pool, producer, base_config("ollama"), dev_license());
        // Never-inserted id in this isolated per-test schema.
        let entry = task_entry(999_999_999, 1, "https://github.com/acme/widgets/pull/1");
        let result = handler.handle(&entry).await;
        assert!(result.is_err(), "nonexistent review must fail");
    }

    #[tokio::test]
    async fn handle_marks_review_failed_when_ai_provider_unknown() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool, "github").await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;
        let handler = CodeScanReviewHandler::new(
            pool.clone(),
            producer,
            base_config("carrier-pigeon"),
            dev_license(),
        );
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/1");

        let result = handler.handle(&entry).await;
        assert!(result.is_err());

        let row = sqlx::query("SELECT status, error_message FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select review: {e}"));
        assert_eq!(row.get::<String, _>(0), "failed");
        let err_msg: String = row.get(1);
        assert!(err_msg.contains("unknown AI provider"), "got: {err_msg}");
    }

    #[tokio::test]
    async fn handle_completes_with_no_findings_when_diff_fetch_fails() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool, "github").await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        // No mock registered for the PR path -> wiremock replies 404, which
        // fetch_pr_diff turns into an Err the pipeline swallows to an empty
        // diff (early-return "no findings" path in execute_pipeline).
        let github_mock = MockServer::start().await;
        let mut cfg = base_config("ollama");
        cfg.git_token = Some("test-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/7");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let row = sqlx::query(
            "SELECT status, comments_count, summary FROM codescan_reviews WHERE id = $1",
        )
        .bind(review)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select review: {e}"));
        assert_eq!(row.get::<String, _>(0), "completed");
        assert_eq!(row.get::<i32, _>(1), 0);
        let summary: String = row.get(2);
        assert!(
            summary.contains("No code changes detected"),
            "got: {summary}"
        );
    }

    #[tokio::test]
    async fn handle_marks_review_failed_when_ai_response_is_unparsable() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool, "github").await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/7"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n"),
            )
            .mount(&github_mock)
            .await;

        let ollama_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {"content": "not json findings, just prose"}
            })))
            .mount(&ollama_mock)
            .await;

        let mut cfg = base_config("ollama");
        cfg.git_token = Some("test-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/7");

        let result = handler.handle(&entry).await;
        assert!(result.is_err());

        let row = sqlx::query("SELECT status, error_message FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select review: {e}"));
        assert_eq!(row.get::<String, _>(0), "failed");
        let err_msg: String = row.get(1);
        assert!(!err_msg.is_empty());
    }

    #[tokio::test]
    async fn handle_marks_review_failed_when_ai_provider_transport_fails() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool, "github").await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/8"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n"),
            )
            .mount(&github_mock)
            .await;

        // Ollama replies with a server error -> `provider.complete().await?`
        // in execute_pipeline propagates it as the pipeline's Err.
        let ollama_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&ollama_mock)
            .await;

        let mut cfg = base_config("ollama");
        cfg.git_token = Some("test-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/8");

        let result = handler.handle(&entry).await;
        assert!(result.is_err());

        let row = sqlx::query("SELECT status, error_message FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select review: {e}"));
        assert_eq!(row.get::<String, _>(0), "failed");
        let err_msg: String = row.get(1);
        assert!(err_msg.contains("Ollama returned status"), "got: {err_msg}");
    }

    #[tokio::test]
    async fn handle_completes_review_and_persists_comments_on_full_success() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool, "github").await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/9"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("--- a/f\n+++ b/f\n@@ -1 +1 @@\n-old\n+new\n"),
            )
            .mount(&github_mock)
            .await;

        let ollama_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {"content": r#"[{"line_start": 1, "severity": "minor", "title": "Nit", "body": "tidy up"}]"#}
            })))
            .mount(&ollama_mock)
            .await;

        let mut cfg = base_config("ollama");
        cfg.git_token = Some("test-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/9");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let row = sqlx::query("SELECT status, comments_count FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select review: {e}"));
        assert_eq!(row.get::<String, _>(0), "completed");
        assert_eq!(row.get::<i32, _>(1), 1);

        let comment_rows = sqlx::query(
            "SELECT comment, severity FROM codescan_review_comments WHERE review_id = $1",
        )
        .bind(review)
        .fetch_all(&pool)
        .await
        .unwrap_or_else(|e| panic!("select comments: {e}"));
        assert_eq!(comment_rows.len(), 1);
        assert_eq!(comment_rows[0].get::<String, _>(1), "minor");
        let comment_text: String = comment_rows[0].get(0);
        assert!(comment_text.contains("Nit"));
        assert!(comment_text.contains("tidy up"));
    }

    /// End-to-end tenant-isolation regression: a task claiming a tenant that
    /// does not own the review must fail, and — critically — must leave the
    /// review row completely untouched (not even flipped to "failed") since
    /// every write in the handler is scoped to the task's tenant.
    #[tokio::test]
    async fn handle_fails_and_does_not_touch_the_row_when_task_tenant_does_not_own_the_review() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool, "github").await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;
        let handler = CodeScanReviewHandler::new(
            pool.clone(),
            producer,
            base_config("ollama"),
            dev_license(),
        );

        let mut entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/1");
        entry
            .fields
            .insert("tenant_id".to_string(), OTHER_TENANT_ID.to_string());

        let result = handler.handle(&entry).await;
        assert!(
            result.is_err(),
            "a task claiming the wrong tenant must be rejected"
        );

        let row = sqlx::query("SELECT status FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select review: {e}"));
        assert_eq!(
            row.get::<String, _>(0),
            "queued",
            "review must be untouched by a task claiming the wrong tenant"
        );
    }

    // -- Git credential resolution (per-repo codescan_git_credentials wiring) --

    fn test_encryption_key() -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [4u8; 32])
    }

    #[allow(clippy::too_many_arguments)]
    async fn seed_repo_config_with_credential(
        pool: &PgPool,
        provider: &str,
        credential_tenant: uuid::Uuid,
        credential_type: &str,
        is_active: bool,
        token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
        plaintext_token: &str,
    ) -> (i64, i64) {
        let cipher = skauswatch_vault::CredentialCipher::from_base64_key(&test_encryption_key())
            .unwrap_or_else(|e| panic!("cipher: {e:?}"));
        let encrypted = cipher
            .encrypt(plaintext_token)
            .unwrap_or_else(|e| panic!("encrypt: {e:?}"));
        let cred_row = sqlx::query(
            "INSERT INTO codescan_git_credentials \
             (user_id, tenant_id, platform, credential_type, encrypted_token, is_active, token_expires_at) \
             VALUES (1, $1, $2, $3, $4, $5, $6) RETURNING id",
        )
        .bind(credential_tenant)
        .bind(provider)
        .bind(credential_type)
        .bind(&encrypted)
        .bind(is_active)
        .bind(token_expires_at)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed credential: {e}"));
        let credential_id: i64 = cred_row.get(0);

        let repo_row = sqlx::query(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name, credential_id) \
             VALUES ($1, $2, 'https://github.com/acme/widgets', 'acme/widgets', $3) RETURNING id",
        )
        .bind(test_tenant())
        .bind(provider)
        .bind(credential_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo config: {e}"));
        (repo_row.get(0), credential_id)
    }

    /// Every credential-resolution test below fetches a real (non-empty)
    /// diff, so `execute_pipeline` always reaches the AI-provider call —
    /// this mocks Ollama to return zero findings rather than hitting a real
    /// (likely absent, in CI) local Ollama instance.
    async fn mount_empty_ollama_mock() -> MockServer {
        let ollama_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {"content": "[]"}
            })))
            .mount(&ollama_mock)
            .await;
        ollama_mock
    }

    #[tokio::test]
    async fn handle_uses_the_per_repo_credential_over_the_worker_wide_git_token() {
        let pool = test_pool().await;
        let (repo, _credential_id) = seed_repo_config_with_credential(
            &pool,
            "github",
            test_tenant(),
            "token",
            true,
            None,
            "ghp_per_repo_secret",
        )
        .await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/1"))
            .and(wiremock::matchers::header(
                "Authorization",
                "token ghp_per_repo_secret",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n"),
            )
            .mount(&github_mock)
            .await;
        let ollama_mock = mount_empty_ollama_mock().await;

        let mut cfg = base_config("ollama");
        cfg.credential_encryption_key = Some(test_encryption_key());
        // Deliberately a different value than the credential's plaintext —
        // proves the per-repo credential (not this) was used.
        cfg.git_token = Some("worker-wide-token-must-not-be-used".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/1");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[tokio::test]
    async fn handle_falls_back_to_git_token_when_encryption_key_is_unset() {
        let pool = test_pool().await;
        let (repo, _credential_id) = seed_repo_config_with_credential(
            &pool,
            "github",
            test_tenant(),
            "token",
            true,
            None,
            "ghp_per_repo_secret",
        )
        .await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/1"))
            .and(wiremock::matchers::header(
                "Authorization",
                "token fallback-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n"),
            )
            .mount(&github_mock)
            .await;
        let ollama_mock = mount_empty_ollama_mock().await;

        let mut cfg = base_config("ollama");
        // credential_encryption_key intentionally left None.
        cfg.git_token = Some("fallback-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/1");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[tokio::test]
    async fn handle_falls_back_to_git_token_when_credential_is_inactive() {
        let pool = test_pool().await;
        let (repo, _credential_id) = seed_repo_config_with_credential(
            &pool,
            "github",
            test_tenant(),
            "token",
            false,
            None,
            "ghp_inactive",
        )
        .await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/1"))
            .and(wiremock::matchers::header(
                "Authorization",
                "token fallback-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n"),
            )
            .mount(&github_mock)
            .await;
        let ollama_mock = mount_empty_ollama_mock().await;

        let mut cfg = base_config("ollama");
        cfg.credential_encryption_key = Some(test_encryption_key());
        cfg.git_token = Some("fallback-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/1");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[tokio::test]
    async fn handle_falls_back_to_git_token_when_credential_is_expired() {
        let pool = test_pool().await;
        let expired = Utc::now() - chrono::Duration::hours(1);
        let (repo, _credential_id) = seed_repo_config_with_credential(
            &pool,
            "github",
            test_tenant(),
            "token",
            true,
            Some(expired),
            "ghp_expired",
        )
        .await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/1"))
            .and(wiremock::matchers::header(
                "Authorization",
                "token fallback-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n"),
            )
            .mount(&github_mock)
            .await;
        let ollama_mock = mount_empty_ollama_mock().await;

        let mut cfg = base_config("ollama");
        cfg.credential_encryption_key = Some(test_encryption_key());
        cfg.git_token = Some("fallback-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/1");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    #[tokio::test]
    async fn handle_falls_back_to_git_token_when_credential_belongs_to_another_tenant() {
        let pool = test_pool().await;
        // Credential row is owned by a *different* tenant than the repo
        // config/review/task below — a data inconsistency that must never
        // let one tenant's task use another tenant's credential.
        let (repo, _credential_id) = seed_repo_config_with_credential(
            &pool,
            "github",
            other_tenant(),
            "token",
            true,
            None,
            "ghp_wrong_tenant",
        )
        .await;
        // seed_repo_config_with_credential always stamps the repo config
        // itself under `test_tenant()`, so this exercises exactly the
        // credential-ownership mismatch described above.
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/1"))
            .and(wiremock::matchers::header(
                "Authorization",
                "token fallback-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n"),
            )
            .mount(&github_mock)
            .await;
        let ollama_mock = mount_empty_ollama_mock().await;

        let mut cfg = base_config("ollama");
        cfg.credential_encryption_key = Some(test_encryption_key());
        cfg.git_token = Some("fallback-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/1");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    fn other_tenant() -> uuid::Uuid {
        OTHER_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("other tenant uuid: {e}"))
    }

    #[tokio::test]
    async fn handle_falls_back_to_git_token_when_credential_platform_does_not_match_repo_provider()
    {
        let pool = test_pool().await;
        // Credential is a gitlab token, but the repo config's own `provider`
        // column is github — a data inconsistency (misconfigured
        // credential_id) that must never be used to auth a github API call.
        let cipher = skauswatch_vault::CredentialCipher::from_base64_key(&test_encryption_key())
            .unwrap_or_else(|e| panic!("cipher: {e:?}"));
        let encrypted = cipher
            .encrypt("glpat_mismatched_platform")
            .unwrap_or_else(|e| panic!("encrypt: {e:?}"));
        let cred_row = sqlx::query(
            "INSERT INTO codescan_git_credentials \
             (user_id, tenant_id, platform, credential_type, encrypted_token, is_active) \
             VALUES (1, $1, 'gitlab', 'token', $2, true) RETURNING id",
        )
        .bind(test_tenant())
        .bind(&encrypted)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("seed credential: {e}"));
        let credential_id: i64 = cred_row.get(0);
        let repo_row = sqlx::query(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name, credential_id) \
             VALUES ($1, 'github', 'https://github.com/acme/widgets', 'acme/widgets', $2) RETURNING id",
        )
        .bind(test_tenant())
        .bind(credential_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo config: {e}"));
        let repo: i64 = repo_row.get(0);
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/1"))
            .and(wiremock::matchers::header(
                "Authorization",
                "token fallback-token",
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("--- a/f\n+++ b/f\n@@ -1 +1 @@\n-x\n+y\n"),
            )
            .mount(&github_mock)
            .await;
        let ollama_mock = mount_empty_ollama_mock().await;

        let mut cfg = base_config("ollama");
        cfg.credential_encryption_key = Some(test_encryption_key());
        cfg.git_token = Some("fallback-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/1");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");
    }

    // -- provider_usage / review_detections wiring --

    #[tokio::test]
    async fn handle_records_provider_usage_and_language_detection_on_success() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool, "github").await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/10"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    "--- a/src/main.rs\n+++ b/src/main.rs\n@@ -1 +1 @@\n-old\n+new\n",
                ),
            )
            .mount(&github_mock)
            .await;

        let ollama_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {"content": "[]"}
            })))
            .mount(&ollama_mock)
            .await;

        let mut cfg = base_config("ollama");
        cfg.git_token = Some("test-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/10");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let usage_row = sqlx::query(
            "SELECT provider, prompt_tokens, completion_tokens, total_tokens, latency_ms, tenant_id \
             FROM codescan_provider_usage WHERE review_id = $1",
        )
        .bind(review)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select provider usage: {e}"));
        assert_eq!(usage_row.get::<String, _>(0), "ollama");
        assert!(usage_row.get::<i32, _>(1) > 0);
        assert_eq!(
            usage_row.get::<i32, _>(3),
            usage_row.get::<i32, _>(1) + usage_row.get::<i32, _>(2)
        );
        assert!(usage_row.get::<i32, _>(4) >= 0);
        assert_eq!(usage_row.get::<uuid::Uuid, _>(5), test_tenant());

        let detection_row = sqlx::query(
            "SELECT detection_type, name, file_count, tenant_id \
             FROM codescan_review_detections WHERE review_id = $1",
        )
        .bind(review)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select review detection: {e}"));
        assert_eq!(detection_row.get::<String, _>(0), "language");
        assert_eq!(detection_row.get::<String, _>(1), "Rust");
        assert_eq!(detection_row.get::<i32, _>(2), 1);
        assert_eq!(detection_row.get::<uuid::Uuid, _>(3), test_tenant());
    }

    // -- license-compliance scan + policy evaluation wiring --

    #[tokio::test]
    async fn handle_records_a_license_violation_for_a_blocked_license() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool, "github").await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        sqlx::query(
            "INSERT INTO codescan_license_policies (tenant_id, license_name, policy, actions) \
             VALUES ($1, 'GPL-3.0', 'blocked', $2)",
        )
        .bind(test_tenant())
        .bind(serde_json::json!(["block_merge"]))
        .execute(&pool)
        .await
        .unwrap_or_else(|e| panic!("seed license policy: {e}"));

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/11"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-x\n+  \"copyleft-pkg\": \"1.0.0\"\n",
            ))
            .mount(&github_mock)
            .await;

        let npm_mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/copyleft-pkg"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"license": "GPL-3.0"})),
            )
            .mount(&npm_mock)
            .await;

        let ollama_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {"content": "[]"}
            })))
            .mount(&ollama_mock)
            .await;

        let mut cfg = base_config("ollama");
        cfg.git_token = Some("test-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        cfg.npm_registry_url = Some(npm_mock.uri());
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/11");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let detection_row = sqlx::query(
            "SELECT package_name, license_name, policy_violation, tenant_id \
             FROM codescan_license_detections WHERE review_id = $1",
        )
        .bind(review)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select license detection: {e}"));
        assert_eq!(detection_row.get::<String, _>(0), "copyleft-pkg");
        assert_eq!(detection_row.get::<String, _>(1), "GPL-3.0");
        assert!(detection_row.get::<bool, _>(2));
        assert_eq!(detection_row.get::<uuid::Uuid, _>(3), test_tenant());

        let violation_row = sqlx::query(
            "SELECT license_name, package_name, policy, severity, status, tenant_id \
             FROM codescan_license_violations WHERE review_id = $1",
        )
        .bind(review)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select license violation: {e}"));
        assert_eq!(violation_row.get::<String, _>(0), "GPL-3.0");
        assert_eq!(violation_row.get::<String, _>(1), "copyleft-pkg");
        assert_eq!(violation_row.get::<String, _>(2), "blocked");
        assert_eq!(violation_row.get::<String, _>(3), "critical");
        assert_eq!(violation_row.get::<String, _>(4), "open");
        assert_eq!(violation_row.get::<uuid::Uuid, _>(5), test_tenant());
    }

    #[tokio::test]
    async fn handle_records_a_license_detection_without_a_violation_when_no_policy_is_configured() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool, "github").await;
        let review = seed_review(&pool, repo).await;
        let producer = test_producer().await;

        let github_mock = MockServer::start().await;
        Mock::given(path("/repos/acme/widgets/pulls/12"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n-x\n+  \"permissive-pkg\": \"1.0.0\"\n",
            ))
            .mount(&github_mock)
            .await;

        let npm_mock = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/permissive-pkg"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"license": "MIT"})),
            )
            .mount(&npm_mock)
            .await;

        let ollama_mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/chat"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "message": {"content": "[]"}
            })))
            .mount(&ollama_mock)
            .await;

        let mut cfg = base_config("ollama");
        cfg.git_token = Some("test-token".to_string());
        cfg.git_api_base_url = Some(github_mock.uri());
        cfg.ollama_url = ollama_mock.uri();
        cfg.npm_registry_url = Some(npm_mock.uri());
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg, dev_license());
        let entry = task_entry(review, repo, "https://github.com/acme/widgets/pull/12");

        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let detection_row = sqlx::query(
            "SELECT policy_violation FROM codescan_license_detections WHERE review_id = $1",
        )
        .bind(review)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select license detection: {e}"));
        assert!(!detection_row.get::<bool, _>(0));

        let violation_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM codescan_license_violations WHERE review_id = $1",
        )
        .bind(review)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("count violations: {e}"));
        assert_eq!(violation_count, 0);
    }

    // ── CodeScan Sentinel dispatch/orchestration ───────────────────────────

    fn sentinel_task_entry(repo_config_id: i64) -> StreamEntry {
        let mut fields = HashMap::new();
        fields.insert("task_type".to_string(), "sentinel_scan".to_string());
        fields.insert("repo_config_id".to_string(), repo_config_id.to_string());
        fields.insert("tenant_id".to_string(), TEST_TENANT_ID.to_string());
        fields.insert("provider".to_string(), "github".to_string());
        fields.insert("repo_name".to_string(), "acme/widgets".to_string());
        fields.insert(
            "repo_url".to_string(),
            "https://github.com/acme/widgets".to_string(),
        );
        StreamEntry {
            id: "2-0".to_string(),
            fields,
        }
    }

    /// Mounts the GitHub repo-identity mocks (`default_branch` + branch
    /// list, no `release/*` branch) every Sentinel handler test needs.
    async fn mount_github_repo_mocks(mock: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"default_branch": "main"})),
            )
            .mount(mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/branches"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{"name": "main"}])),
            )
            .mount(mock)
            .await;
    }

    fn sentinel_config(mock_uri: &str) -> WorkerConfig {
        let mut cfg = base_config("ollama");
        cfg.git_token = Some("test-token".to_string());
        cfg.git_api_base_url = Some(mock_uri.to_string());
        cfg.go_registry_url = Some(mock_uri.to_string());
        cfg
    }

    #[tokio::test]
    async fn handle_dispatches_sentinel_scan_and_completes_with_no_manifests() {
        let pool = test_pool().await;
        let producer = test_producer().await;
        let repo = seed_repo_config(&pool, "github").await;

        let mock = MockServer::start().await;
        mount_github_repo_mocks(&mock).await;
        for manifest in crate::sentinel::MANIFEST_FILES {
            Mock::given(method("GET"))
                .and(path(format!("/repos/acme/widgets/contents/{manifest}")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock)
                .await;
        }

        let handler = CodeScanReviewHandler::new(
            pool.clone(),
            producer,
            sentinel_config(&mock.uri()),
            dev_license(),
        );
        let entry = sentinel_task_entry(repo);
        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let run = sqlx::query(
            "SELECT status, findings_count FROM codescan_scan_runs WHERE repo_config_id = $1",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select scan run: {e}"));
        assert_eq!(run.get::<String, _>(0), "completed");
        assert_eq!(run.get::<i32, _>(1), 0);
    }

    #[tokio::test]
    async fn handle_sentinel_scan_errors_when_repo_config_does_not_exist() {
        let pool = test_pool().await;
        let producer = test_producer().await;
        let handler = CodeScanReviewHandler::new(
            pool.clone(),
            producer,
            sentinel_config("http://127.0.0.1:1"),
            dev_license(),
        );
        let entry = sentinel_task_entry(999_999_999);
        let result = handler.handle(&entry).await;
        assert!(result.is_err(), "a missing repo config must be an error");
    }

    #[tokio::test]
    async fn handle_sentinel_scan_records_an_outdated_dependency_as_an_sca_finding() {
        let pool = test_pool().await;
        let producer = test_producer().await;
        let repo = seed_repo_config(&pool, "github").await;

        let mock = MockServer::start().await;
        mount_github_repo_mocks(&mock).await;
        for manifest in crate::sentinel::MANIFEST_FILES {
            if *manifest == "package.json" {
                continue;
            }
            Mock::given(method("GET"))
                .and(path(format!("/repos/acme/widgets/contents/{manifest}")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/contents/package.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    "{\n  \"dependencies\": {\n    \"left-pad\": \"1.0.0\"\n  }\n}\n",
                ),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{"versionKey": {"version": "1.3.0"}, "isDefault": true}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad/versions/1.0.0"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"advisoryKeys": []})),
            )
            .mount(&mock)
            .await;

        let handler = CodeScanReviewHandler::new(
            pool.clone(),
            producer,
            sentinel_config(&mock.uri()),
            dev_license(),
        );
        let entry = sentinel_task_entry(repo);
        let result = handler.handle(&entry).await;
        assert!(result.is_ok(), "expected Ok, got {result:?}");

        let row = sqlx::query(
            "SELECT kind, severity, latest_version, advisory_id FROM codescan_findings \
             WHERE repo_config_id = $1 AND package_name = 'left-pad'",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select finding: {e}"));
        assert_eq!(row.get::<String, _>(0), "sca");
        assert_eq!(row.get::<String, _>(1), "low");
        assert_eq!(row.get::<Option<String>, _>(2).as_deref(), Some("1.3.0"));
        assert_eq!(row.get::<String, _>(3), "");
    }

    /// Mirrors manager's `alerts` table shape closely enough to exercise the
    /// alert bridge, without pulling in manager's own (concurrently
    /// evolving) migrations — see `db::tests::seed_alerts_fixture_table`.
    async fn seed_alerts_fixture_table(pool: &PgPool) {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alerts ( \
                id SERIAL PRIMARY KEY, \
                title VARCHAR(255) NOT NULL, \
                description TEXT, \
                severity VARCHAR(20) NOT NULL, \
                status VARCHAR(20) DEFAULT 'pending', \
                source VARCHAR(100), \
                indicators JSONB, \
                tenant_id UUID NOT NULL, \
                created_at TIMESTAMPTZ DEFAULT now(), \
                updated_at TIMESTAMPTZ \
            )",
        )
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("create alerts fixture table: {e}"));
    }

    #[tokio::test]
    async fn handle_sentinel_scan_bridges_one_alert_for_a_critical_cve_and_never_double_alerts() {
        let pool = test_pool().await;
        seed_alerts_fixture_table(&pool).await;
        let repo = seed_repo_config(&pool, "github").await;

        let mock = MockServer::start().await;
        mount_github_repo_mocks(&mock).await;
        for manifest in crate::sentinel::MANIFEST_FILES {
            if *manifest == "package.json" {
                continue;
            }
            Mock::given(method("GET"))
                .and(path(format!("/repos/acme/widgets/contents/{manifest}")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/contents/package.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    "{\n  \"dependencies\": {\n    \"axios\": \"1.0.0\"\n  }\n}\n",
                ),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/axios"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{"versionKey": {"version": "1.7.0"}, "isDefault": true}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/axios/versions/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "advisoryKeys": [{"id": "GHSA-critical-axios"}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/advisories/GHSA-critical-axios"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "Remote code execution",
                "cvss3Score": 9.8
            })))
            .mount(&mock)
            .await;

        let cfg = sentinel_config(&mock.uri());
        let handler = CodeScanReviewHandler::new(
            pool.clone(),
            test_producer().await,
            cfg.clone(),
            dev_license(),
        );
        let entry = sentinel_task_entry(repo);

        handler
            .handle(&entry)
            .await
            .unwrap_or_else(|e| panic!("first scan should succeed: {e:?}"));

        let alert_count_after_first: i64 =
            sqlx::query_scalar("SELECT count(*) FROM alerts WHERE source = 'codescan_sentinel'")
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("count alerts: {e}"));
        assert_eq!(
            alert_count_after_first, 1,
            "a critical CVE finding must bridge exactly one alert"
        );

        // Second scan of the same still-open finding must not alert again.
        let handler2 =
            CodeScanReviewHandler::new(pool.clone(), test_producer().await, cfg, dev_license());
        handler2
            .handle(&entry)
            .await
            .unwrap_or_else(|e| panic!("second scan should succeed: {e:?}"));
        let alert_count_after_second: i64 =
            sqlx::query_scalar("SELECT count(*) FROM alerts WHERE source = 'codescan_sentinel'")
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("count alerts: {e}"));
        assert_eq!(
            alert_count_after_second, 1,
            "an already-alerted, still-open finding must never alert twice"
        );

        let finding_row = sqlx::query(
            "SELECT kind, severity, action FROM codescan_findings \
             WHERE repo_config_id = $1 AND package_name = 'axios' AND kind = 'cve'",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select cve finding: {e}"));
        assert_eq!(finding_row.get::<String, _>(0), "cve");
        assert_eq!(finding_row.get::<String, _>(1), "critical");
        // CodeScan Sentinel P3 gating test: this handler is Enterprise
        // (`dev_license()` bypass) but `sentinel_config` never sets
        // `WADDLEAI_BASE_URL` — the policy engine's default matrix must
        // still run and resolve an action (spec §4 Gating: "a scan with
        // WaddleAI unconfigured still produces findings and applies the
        // default matrix").
        assert_eq!(
            finding_row.get::<String, _>(2),
            "alert",
            "default matrix must resolve critical+unknown-reachability to alert even with \
             WaddleAI unconfigured"
        );

        // axios is also outdated (1.0.0 -> 1.7.0), so a separate 'sca'
        // finding must exist alongside the 'cve' one — a package can be
        // both outdated and vulnerable at once (see
        // `sentinel::dependency_findings`'s doc comment).
        let sca_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM codescan_findings \
             WHERE repo_config_id = $1 AND package_name = 'axios' AND kind = 'sca'",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("count sca finding: {e}"));
        assert_eq!(sca_count, 1);
    }

    /// CodeScan Sentinel P3 gating (spec §13): below Enterprise tier, the
    /// AI triage + policy engine must never run at all — the pre-P3
    /// deterministic alert bridge (unconditional on critical/high `cve`
    /// severity) is the only thing that decides whether to alert, and the
    /// additive P3 columns (`action`, `used`, `reachable`, ...) must stay
    /// untouched. A Professional-tier tenant's alerting must never regress
    /// just because P3 exists in the binary.
    #[tokio::test]
    async fn handle_sentinel_scan_below_enterprise_tier_preserves_the_legacy_alert_path() {
        let pool = test_pool().await;
        seed_alerts_fixture_table(&pool).await;
        let repo = seed_repo_config(&pool, "github").await;

        let mock = MockServer::start().await;
        mount_github_repo_mocks(&mock).await;
        for manifest in crate::sentinel::MANIFEST_FILES {
            if *manifest == "package.json" {
                continue;
            }
            Mock::given(method("GET"))
                .and(path(format!("/repos/acme/widgets/contents/{manifest}")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/contents/package.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    "{\n  \"dependencies\": {\n    \"axios\": \"1.0.0\"\n  }\n}\n",
                ),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/axios"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{"versionKey": {"version": "1.7.0"}, "isDefault": true}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/axios/versions/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "advisoryKeys": [{"id": "GHSA-critical-axios"}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/advisories/GHSA-critical-axios"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "Remote code execution",
                "cvss3Score": 9.8
            })))
            .mount(&mock)
            .await;

        let cfg = sentinel_config(&mock.uri());
        let handler =
            CodeScanReviewHandler::new(pool.clone(), test_producer().await, cfg, gated_license());
        let entry = sentinel_task_entry(repo);
        handler
            .handle(&entry)
            .await
            .unwrap_or_else(|e| panic!("scan should succeed: {e:?}"));

        let alert_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM alerts WHERE source = 'codescan_sentinel'")
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("count alerts: {e}"));
        assert_eq!(
            alert_count, 1,
            "below Enterprise tier, a critical CVE must still alert via the legacy path"
        );

        let finding_row = sqlx::query(
            "SELECT action, used, reachable, triage_source FROM codescan_findings \
             WHERE repo_config_id = $1 AND package_name = 'axios' AND kind = 'cve'",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select cve finding: {e}"));
        assert_eq!(
            finding_row.get::<String, _>(0),
            "",
            "the policy engine must never run below Enterprise tier"
        );
        assert_eq!(finding_row.get::<Option<bool>, _>(1), None);
        assert_eq!(finding_row.get::<Option<bool>, _>(2), None);
        assert_eq!(finding_row.get::<String, _>(3), "");

        let decision_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM codescan_policy_decisions")
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("count decisions: {e}"));
        assert_eq!(
            decision_count, 0,
            "no policy decision should ever be recorded below Enterprise tier"
        );
    }

    /// Builds an in-memory zip archive (single top-level directory, matching
    /// GitHub's `zipball` shape) for mocking the branch-tree fetch in P3
    /// wiring tests below — a local duplicate of
    /// `tree_fetch::tests::build_test_zip` (private to that module).
    #[allow(clippy::unwrap_used)]
    fn build_zip_fixture(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for (name, content) in entries {
            writer
                .start_file(*name, options)
                .unwrap_or_else(|e| panic!("start_file: {e}"));
            writer
                .write_all(content)
                .unwrap_or_else(|e| panic!("write_all: {e}"));
        }
        writer
            .finish()
            .unwrap_or_else(|e| panic!("finish zip: {e}"))
            .into_inner()
    }

    /// CodeScan Sentinel P3 wiring: the static prefilter (`crate::reachability`)
    /// proving a package unused must short-circuit straight to the policy
    /// engine's "not used/dead path" bucket — `document`, never `alert`,
    /// regardless of severity — and skip AI triage entirely (spec §5 point
    /// 1: "kills most noise for free, before any LLM spend").
    #[tokio::test]
    async fn handle_sentinel_scan_prefilter_marks_an_unused_package_not_used_and_skips_ai() {
        let pool = test_pool().await;
        seed_alerts_fixture_table(&pool).await;
        let repo = seed_repo_config(&pool, "github").await;

        let mock = MockServer::start().await;
        mount_github_repo_mocks(&mock).await;
        for manifest in crate::sentinel::MANIFEST_FILES {
            if *manifest == "package.json" {
                continue;
            }
            Mock::given(method("GET"))
                .and(path(format!("/repos/acme/widgets/contents/{manifest}")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/contents/package.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    "{\n  \"dependencies\": {\n    \"left-pad\": \"1.0.0\"\n  }\n}\n",
                ),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad/versions/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "advisoryKeys": [{"id": "GHSA-critical-leftpad"}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/advisories/GHSA-critical-leftpad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "Remote code execution",
                "cvss3Score": 9.8
            })))
            .mount(&mock)
            .await;
        // Branch tree: a README that never references left-pad at all.
        let zip_bytes = build_zip_fixture(&[("acme-widgets-abc123/README.md", b"nothing here")]);
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/zipball/main"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&mock)
            .await;

        let cfg = sentinel_config(&mock.uri());
        let handler =
            CodeScanReviewHandler::new(pool.clone(), test_producer().await, cfg, dev_license());
        let entry = sentinel_task_entry(repo);
        handler
            .handle(&entry)
            .await
            .unwrap_or_else(|e| panic!("scan should succeed: {e:?}"));

        let row = sqlx::query(
            "SELECT severity, action, used, triage_source FROM codescan_findings \
             WHERE repo_config_id = $1 AND package_name = 'left-pad' AND kind = 'cve'",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "critical");
        assert_eq!(
            row.get::<Option<bool>, _>(2),
            Some(false),
            "the prefilter must prove the package unused"
        );
        assert_eq!(
            row.get::<String, _>(3),
            "prefilter",
            "AI triage must be skipped once the prefilter proves not-used"
        );
        assert_eq!(
            row.get::<String, _>(1),
            "document",
            "a not-used/dead-path critical finding documents, it never alerts"
        );

        let alert_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM alerts WHERE source = 'codescan_sentinel'")
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("count alerts: {e}"));
        assert_eq!(
            alert_count, 0,
            "an unused package must never alert regardless of severity"
        );
    }

    /// CodeScan Sentinel P3 end-to-end: a package the prefilter proves
    /// *used* proceeds to a real WaddleAI triage call, whose verdict is
    /// persisted (`used`/`reachable`/`exposure`/`ai_severity`/`ai_rationale`
    /// /`triage_source`) and drives the policy engine's default matrix —
    /// while the original scanner severity is left completely untouched
    /// (ground truth preserved, spec §4).
    #[tokio::test]
    async fn handle_sentinel_scan_runs_waddleai_triage_for_a_used_package_and_preserves_ground_truth()
     {
        let pool = test_pool().await;
        seed_alerts_fixture_table(&pool).await;
        let repo = seed_repo_config(&pool, "github").await;

        let mock = MockServer::start().await;
        mount_github_repo_mocks(&mock).await;
        for manifest in crate::sentinel::MANIFEST_FILES {
            if *manifest == "package.json" {
                continue;
            }
            Mock::given(method("GET"))
                .and(path(format!("/repos/acme/widgets/contents/{manifest}")))
                .respond_with(ResponseTemplate::new(404))
                .mount(&mock)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/contents/package.json"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(
                    "{\n  \"dependencies\": {\n    \"left-pad\": \"1.0.0\"\n  }\n}\n",
                ),
            )
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "versions": [{"versionKey": {"version": "1.0.0"}, "isDefault": true}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/systems/NPM/packages/left-pad/versions/1.0.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "advisoryKeys": [{"id": "GHSA-critical-leftpad"}]
            })))
            .mount(&mock)
            .await;
        Mock::given(method("GET"))
            .and(path("/v3/advisories/GHSA-critical-leftpad"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "title": "Remote code execution",
                "cvss3Score": 9.8
            })))
            .mount(&mock)
            .await;
        // Branch tree: an actual usage of left-pad, so the prefilter marks
        // it used and proceeds to AI triage.
        let zip_bytes = build_zip_fixture(&[(
            "acme-widgets-abc123/index.js",
            b"const pad = require('left-pad');\n",
        )]);
        Mock::given(method("GET"))
            .and(path("/repos/acme/widgets/zipball/main"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(zip_bytes))
            .mount(&mock)
            .await;
        Mock::given(method("POST"))
            .and(path("/v1/inference"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "model": "gemma-4-26b-moe",
                "content": "{\"used\":true,\"reachable\":true,\"exposure\":\"external\",\
                             \"severity_adjustment\":\"high\",\
                             \"rationale\":\"reachable from an exported HTTP handler\"}",
            })))
            .mount(&mock)
            .await;

        let mut cfg = sentinel_config(&mock.uri());
        cfg.waddleai_base_url = Some(mock.uri());
        cfg.waddleai_api_key = Some("test-waddleai-key".to_string());
        let handler =
            CodeScanReviewHandler::new(pool.clone(), test_producer().await, cfg, dev_license());
        let entry = sentinel_task_entry(repo);
        handler
            .handle(&entry)
            .await
            .unwrap_or_else(|e| panic!("scan should succeed: {e:?}"));

        let row = sqlx::query(
            "SELECT severity, ai_severity, used, reachable, exposure, ai_rationale, \
                    triage_source, action \
             FROM codescan_findings WHERE repo_config_id = $1 AND package_name = 'left-pad' \
             AND kind = 'cve'",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(
            row.get::<String, _>(0),
            "critical",
            "the AI's severity_adjustment must never overwrite the scanner's ground-truth severity"
        );
        assert_eq!(row.get::<Option<String>, _>(1).as_deref(), Some("high"));
        assert_eq!(row.get::<Option<bool>, _>(2), Some(true));
        assert_eq!(row.get::<Option<bool>, _>(3), Some(true));
        assert_eq!(row.get::<Option<String>, _>(4).as_deref(), Some("external"));
        assert_eq!(
            row.get::<String, _>(5),
            "reachable from an exported HTTP handler"
        );
        assert_eq!(row.get::<String, _>(6), "waddleai");
        assert_eq!(
            row.get::<String, _>(7),
            "alert",
            "critical + reachable+external resolves to alert via the default matrix"
        );

        let alert_count: i64 =
            sqlx::query_scalar("SELECT count(*) FROM alerts WHERE source = 'codescan_sentinel'")
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("count alerts: {e}"));
        assert_eq!(alert_count, 1);
    }
}
