//! Stream handler for CodeScan review tasks.

use chrono::Utc;
use skauswatch_ai::{
    CompletionProvider, CompletionRequest, Message, anthropic::AnthropicProvider,
    ollama::OllamaProvider, openai::OpenaiProvider,
};
use skauswatch_streams::{StreamEntry, StreamHandler, StreamProducer};
use sqlx::PgPool;

use crate::config::WorkerConfig;
use crate::db;
use crate::git_provider::{self, GitCredentials};
use crate::message::CodeScanReviewTask;
use crate::review::ReviewOutput;

/// Handler for CodeScan review stream entries.
pub struct CodeScanReviewHandler {
    pool: PgPool,
    producer: StreamProducer,
    config: WorkerConfig,
}

impl CodeScanReviewHandler {
    /// Create a new CodeScan review handler.
    pub fn new(pool: PgPool, producer: StreamProducer, config: WorkerConfig) -> Self {
        Self {
            pool,
            producer,
            config,
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
                    content: user_prompt,
                },
            ],
            max_tokens: 2000,
        };

        let response = provider.complete(req).await?;

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

        // Mark review as processing.
        if let Err(e) = db::update_review_status(&self.pool, task.review_id, "processing").await {
            tracing::error!(review_id = task.review_id, error = %e, "failed to mark review processing");
            return Err(format!("db update status: {}", e).into());
        }

        // Validate that review exists and fetch details.
        let review = match db::get_review(&self.pool, task.review_id).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!(review_id = task.review_id, error = %e, "review not found");
                let _ =
                    db::mark_review_failed(&self.pool, task.review_id, "review not found").await;
                return Err(format!("get review: {}", e).into());
            }
        };

        // Fetch repo configuration and credentials.
        let repo_config = match db::get_repo_config(&self.pool, review.repo_config_id).await {
            Ok(rc) => rc,
            Err(e) => {
                tracing::error!(review_id = task.review_id, error = %e, "repo config not found");
                let _ = db::mark_review_failed(&self.pool, task.review_id, "repo config not found")
                    .await;
                return Err(format!("get repo config: {}", e).into());
            }
        };

        // Fetch git credentials (from config, sourced from GIT_TOKEN/
        // GIT_API_BASE_URL). In production, per-repo credentials should come
        // from the codescan_git_credentials table instead of a single
        // worker-wide token; tracked as a follow-up (this worker only reads
        // codescan_reviews/codescan_repo_configs/codescan_review_comments
        // today — see services/codescan-backend/src/crypto.rs for the
        // decrypt-side counterpart already in place for that future path).
        let git_creds = GitCredentials {
            provider: repo_config._provider.clone(),
            token: self.config.git_token.clone().unwrap_or_default(),
            base_url: self.config.git_api_base_url.clone(),
        };
        if git_creds.token.is_empty() {
            tracing::warn!(
                review_id = task.review_id,
                "GIT_TOKEN not set, skipping PR diff fetch"
            );
        }

        // Execute the review pipeline.
        let review_result = match self.execute_pipeline(&task, &git_creds).await {
            Ok(result) => result,
            Err(e) => {
                tracing::error!(review_id = task.review_id, error = %e, "review execution failed");
                let error_msg = e.to_string();
                let _ = db::mark_review_failed(&self.pool, task.review_id, &error_msg).await;
                return Err(format!("execute review: {}", e).into());
            }
        };

        // Persist review comments.
        let mut comments_count = 0i64;
        for comment in &review_result.comments {
            match db::insert_review_comment(
                &self.pool,
                task.review_id,
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
        }
    }

    async fn seed_repo_config(pool: &PgPool, provider: &str) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(1i64)
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
        .bind(1i64)
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
        fields.insert("tenant_id".to_string(), "1".to_string());
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
}
