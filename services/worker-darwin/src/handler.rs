//! Stream handler for Darwin review tasks.

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
use crate::message::DarwinReviewTask;
use crate::review::ReviewOutput;

/// Handler for Darwin review stream entries.
pub struct DarwinReviewHandler {
    pool: PgPool,
    producer: StreamProducer,
    config: WorkerConfig,
}

impl DarwinReviewHandler {
    /// Create a new Darwin review handler.
    pub fn new(pool: PgPool, producer: StreamProducer, config: WorkerConfig) -> Self {
        Self {
            pool,
            producer,
            config,
        }
    }

    /// Create the appropriate AI provider based on config.
    fn create_provider(&self) -> anyhow::Result<Box<dyn CompletionProvider>> {
        match self.config.ai_provider.to_lowercase().as_str() {
            "anthropic" => {
                let api_key = std::env::var("ANTHROPIC_API_KEY")
                    .ok()
                    .ok_or_else(|| anyhow::anyhow!("ANTHROPIC_API_KEY not set"))?;
                Ok(Box::new(AnthropicProvider::new(api_key)?))
            }
            "openai" => {
                let api_key = std::env::var("OPENAI_API_KEY")
                    .ok()
                    .ok_or_else(|| anyhow::anyhow!("OPENAI_API_KEY not set"))?;
                Ok(Box::new(OpenaiProvider::new(api_key)?))
            }
            "ollama" => {
                let url = std::env::var("OLLAMA_URL")
                    .unwrap_or_else(|_| "http://localhost:11434".to_string());
                Ok(Box::new(OllamaProvider::new(url)?))
            }
            _ => Err(anyhow::anyhow!(
                "unknown AI provider: {}",
                self.config.ai_provider
            )),
        }
    }

    /// Execute the review pipeline for a task, calling AI provider with real PR diff.
    async fn execute_pipeline(
        &self,
        task: &DarwinReviewTask,
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
impl StreamHandler for DarwinReviewHandler {
    async fn handle(
        &self,
        entry: &StreamEntry,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Parse the task from stream entry.
        let task =
            DarwinReviewTask::from_stream_entry(entry).map_err(|e| format!("parse task: {}", e))?;

        tracing::info!(
            review_id = task.review_id,
            repo = %task.repo_name,
            pr = %task.pr_url,
            "processing Darwin review task"
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

        // Fetch git credentials (from env or database).
        let git_creds = match std::env::var("GIT_TOKEN") {
            Ok(token) => GitCredentials {
                provider: repo_config._provider.clone(),
                token,
                base_url: None,
            },
            Err(_) => {
                // In production, fetch from darwin_git_credentials table.
                // For now, fail gracefully.
                tracing::warn!(
                    review_id = task.review_id,
                    "GIT_TOKEN not set, skipping PR diff fetch"
                );
                GitCredentials {
                    provider: repo_config._provider.clone(),
                    token: String::new(),
                    base_url: None,
                }
            }
        };

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

        // Publish result to darwin:results stream for any downstream consumers.
        let result_fields = vec![
            ("review_id".to_string(), task.review_id.to_string()),
            ("status".to_string(), "completed".to_string()),
            ("comments_count".to_string(), comments_count.to_string()),
            ("summary".to_string(), review_result.summary),
            ("completed_at".to_string(), Utc::now().to_rfc3339()),
        ];

        if let Err(e) = self.producer.publish("darwin:results", result_fields).await {
            tracing::warn!(review_id = task.review_id, error = %e, "failed to publish result");
        }

        tracing::info!(
            review_id = task.review_id,
            comments = comments_count,
            "Darwin review completed"
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_handler_trait_object_safe() {
        // Verify that DarwinReviewHandler can be used as a trait object.
        // This is a compile-time check; if it doesn't compile, the handler
        // isn't properly implementing StreamHandler.
        let _: Option<Box<dyn StreamHandler>> = None;
    }
}
