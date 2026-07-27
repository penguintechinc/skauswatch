//! CodeScan review task message structures parsed from Redis streams.

use serde::{Deserialize, Serialize};
use skauswatch_streams::StreamEntry;

/// A CodeScan review task from the `codescan:tasks` stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeScanReviewTask {
    /// Review ID (database primary key).
    pub review_id: i64,
    /// Repository configuration ID.
    pub repo_config_id: i64,
    /// Git provider (github, gitlab).
    pub _provider: String,
    /// Repository name.
    pub repo_name: String,
    /// PR/MR URL or identifier.
    pub pr_url: String,
    /// Tenant ID (for multi-tenancy).
    pub _tenant_id: i64,
    /// AI provider to use (optional override).
    pub ai_provider: Option<String>,
    /// AI model to use (optional override).
    pub ai_model: Option<String>,
}

impl CodeScanReviewTask {
    /// Parse from a Redis stream entry.
    pub fn from_stream_entry(entry: &StreamEntry) -> anyhow::Result<Self> {
        let review_id = entry
            .get("review_id")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("missing/invalid review_id"))?;

        let repo_config_id = entry
            .get("repo_config_id")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("missing/invalid repo_config_id"))?;

        let provider = entry
            .get("provider")
            .ok_or_else(|| anyhow::anyhow!("missing provider"))?
            .to_string();

        let repo_name = entry
            .get("repo_name")
            .ok_or_else(|| anyhow::anyhow!("missing repo_name"))?
            .to_string();

        let pr_url = entry
            .get("pr_url")
            .ok_or_else(|| anyhow::anyhow!("missing pr_url"))?
            .to_string();

        let tenant_id = entry
            .get("tenant_id")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("missing/invalid tenant_id"))?;

        Ok(Self {
            review_id,
            repo_config_id,
            _provider: provider,
            repo_name,
            pr_url,
            _tenant_id: tenant_id,
            ai_provider: entry.get("ai_provider").map(String::from),
            ai_model: entry.get("ai_model").map(String::from),
        })
    }
}

/// Result of a code review (published to codescan:results stream).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ReviewResult {
    /// Review ID (matches the task).
    pub review_id: i64,
    /// Status: completed, failed.
    pub status: String,
    /// Summary of the review.
    pub summary: String,
    /// Number of comments/findings.
    pub comments_count: i64,
    /// ISO8601 timestamp when completed.
    pub completed_at: String,
}
