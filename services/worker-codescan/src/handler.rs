//! Stream handler for CodeScan review tasks.

use chrono::Utc;
use skauswatch_ai::{
    CompletionProvider, CompletionRequest, Message, anthropic::AnthropicProvider,
    ollama::OllamaProvider, openai::OpenaiProvider,
};
use skauswatch_streams::{StreamEntry, StreamHandler, StreamProducer};
use sqlx::PgPool;

use skauswatch_vault::CredentialCipher;

use crate::config::WorkerConfig;
use crate::db::{self, RepoConfigRecord};
use crate::detection;
use crate::git_provider::{self, GitCredentials};
use crate::license_scan::RegistryClient;
use crate::message::CodeScanReviewTask;
use crate::review::ReviewOutput;

/// Handler for CodeScan review stream entries.
pub struct CodeScanReviewHandler {
    pool: PgPool,
    producer: StreamProducer,
    config: WorkerConfig,
    /// npm/PyPI/crates.io client for `codescan_license_detections` scanning
    /// (see `crate::license_scan`). Built once so tests/prod share one
    /// pooled `reqwest::Client`.
    registry_client: RegistryClient,
}

impl CodeScanReviewHandler {
    /// Create a new CodeScan review handler.
    pub fn new(pool: PgPool, producer: StreamProducer, config: WorkerConfig) -> Self {
        let registry_client = RegistryClient::new(
            config.npm_registry_url.clone(),
            config.pypi_registry_url.clone(),
            config.crates_registry_url.clone(),
        );
        Self {
            pool,
            producer,
            config,
            registry_client,
        }
    }

    /// Resolves which git credential to use for `task`'s repo: a per-repo
    /// `codescan_git_credentials` row (via `repo_config.credential_id`) when
    /// one is configured and usable, falling back to the worker-wide
    /// `GIT_TOKEN`/`GIT_API_BASE_URL` config otherwise. Every failure mode
    /// (no credential configured, missing encryption key, credential not
    /// found/inactive/expired/wrong-type, decrypt failure) degrades to the
    /// fallback with a warning rather than failing the review — mirrors how
    /// `git_provider::fetch_pr_diff` failures degrade to an empty diff
    /// rather than aborting (see `execute_pipeline`).
    async fn resolve_git_credentials(
        &self,
        task: &CodeScanReviewTask,
        repo_config: &RepoConfigRecord,
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
                review_id = task.review_id,
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
                    review_id = task.review_id,
                    error = ?e,
                    "invalid CREDENTIAL_ENCRYPTION_KEY, falling back to the worker-wide GIT_TOKEN"
                );
                return fallback();
            }
        };

        let credential = match db::get_git_credential(&self.pool, credential_id, task.tenant_id)
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    review_id = task.review_id,
                    credential_id,
                    error = %e,
                    "git credential not found for this tenant, falling back to the worker-wide GIT_TOKEN"
                );
                return fallback();
            }
        };

        if !credential.is_active {
            tracing::warn!(
                review_id = task.review_id,
                credential_id,
                "git credential is inactive, falling back to the worker-wide GIT_TOKEN"
            );
            return fallback();
        }
        if credential.credential_type != "token" {
            tracing::warn!(
                review_id = task.review_id,
                credential_id,
                credential_type = %credential.credential_type,
                "only 'token' credentials are usable for API-based diff fetching, \
                 falling back to the worker-wide GIT_TOKEN"
            );
            return fallback();
        }
        if credential.platform != repo_config._provider {
            tracing::warn!(
                review_id = task.review_id,
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
                review_id = task.review_id,
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
                    review_id = task.review_id,
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

    use sqlx::Row;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

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
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, base_config("anthropic"));
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
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg);
        assert!(handler.create_provider().is_err());
    }

    #[tokio::test]
    async fn create_provider_errors_without_openai_key() {
        let producer = test_producer().await;
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, base_config("openai"));
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
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg);
        assert!(handler.create_provider().is_ok());
    }

    #[tokio::test]
    async fn create_provider_errors_with_empty_openai_key() {
        let producer = test_producer().await;
        let mut cfg = base_config("openai");
        cfg.openai_api_key = Some(String::new());
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg);
        assert!(handler.create_provider().is_err());
    }

    #[tokio::test]
    async fn create_provider_succeeds_with_default_ollama_url() {
        let producer = test_producer().await;
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, base_config("ollama"));
        assert!(handler.create_provider().is_ok());
    }

    #[tokio::test]
    async fn create_provider_errors_with_empty_ollama_url() {
        let producer = test_producer().await;
        let mut cfg = base_config("ollama");
        cfg.ollama_url = String::new();
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, cfg);
        assert!(handler.create_provider().is_err());
    }

    #[tokio::test]
    async fn create_provider_is_case_insensitive_and_rejects_unknown() {
        let producer = test_producer().await;
        let handler = CodeScanReviewHandler::new(lazy_pool(), producer, base_config("OLLAMA"));
        assert!(handler.create_provider().is_ok());

        let producer = test_producer().await;
        let handler =
            CodeScanReviewHandler::new(lazy_pool(), producer, base_config("carrier-pigeon"));
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
        let handler = CodeScanReviewHandler::new(pool, producer, base_config("ollama"));
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
        let handler = CodeScanReviewHandler::new(pool, producer, base_config("ollama"));
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
        let handler =
            CodeScanReviewHandler::new(pool.clone(), producer, base_config("carrier-pigeon"));
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, base_config("ollama"));

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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
        let handler = CodeScanReviewHandler::new(pool.clone(), producer, cfg);
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
}
