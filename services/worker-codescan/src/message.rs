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
    /// Validated tenant UUID this task belongs to. Sourced from the
    /// `codescan:tasks` stream `tenant_id` field, which codescan-backend
    /// stamps from the authenticated caller's `TenantContext`
    /// (`routes/reviews.rs::build_review_task_fields`) — never
    /// client-supplied. Every DB query in this worker must be scoped to
    /// this value; the nil UUID is rejected at parse time so a
    /// zero-value/sentinel can never be mistaken for a real tenant.
    pub tenant_id: uuid::Uuid,
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

        // Reject both an unparseable value and the nil UUID — a
        // zero/sentinel tenant is never a legitimate tenant identity, and
        // treating it as valid would open a fail-open hole identical to
        // "missing" (see docs/v2-port/tenancy-model.md §3: a receiver
        // missing a validated tenant provenance rejects the message).
        let tenant_id: uuid::Uuid = entry
            .get("tenant_id")
            .and_then(|v| v.parse::<uuid::Uuid>().ok())
            .filter(|id| !id.is_nil())
            .ok_or_else(|| anyhow::anyhow!("missing/invalid tenant_id"))?;

        Ok(Self {
            review_id,
            repo_config_id,
            _provider: provider,
            repo_name,
            pr_url,
            tenant_id,
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const TEST_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";

    fn test_tenant() -> uuid::Uuid {
        TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("test tenant uuid: {e}"))
    }

    fn entry(fields: &[(&str, &str)]) -> StreamEntry {
        let mut map = HashMap::new();
        for (k, v) in fields {
            map.insert((*k).to_string(), (*v).to_string());
        }
        StreamEntry {
            id: "1700000000000-0".to_string(),
            fields: map,
        }
    }

    fn full_fields() -> Vec<(&'static str, &'static str)> {
        vec![
            ("review_id", "42"),
            ("repo_config_id", "7"),
            ("provider", "github"),
            ("repo_name", "acme/widgets"),
            ("pr_url", "https://github.com/acme/widgets/pull/1"),
            ("tenant_id", TEST_TENANT_ID),
        ]
    }

    #[test]
    fn parses_a_well_formed_entry() {
        let task = CodeScanReviewTask::from_stream_entry(&entry(&full_fields()))
            .expect("parse should succeed");
        assert_eq!(task.review_id, 42);
        assert_eq!(task.repo_config_id, 7);
        assert_eq!(task._provider, "github");
        assert_eq!(task.repo_name, "acme/widgets");
        assert_eq!(task.pr_url, "https://github.com/acme/widgets/pull/1");
        assert_eq!(task.tenant_id, test_tenant());
        assert_eq!(task.ai_provider, None);
        assert_eq!(task.ai_model, None);
    }

    #[test]
    fn parses_optional_ai_overrides_when_present() {
        let mut fields = full_fields();
        fields.push(("ai_provider", "anthropic"));
        fields.push(("ai_model", "claude-opus-4-5"));
        let task =
            CodeScanReviewTask::from_stream_entry(&entry(&fields)).expect("parse should succeed");
        assert_eq!(task.ai_provider.as_deref(), Some("anthropic"));
        assert_eq!(task.ai_model.as_deref(), Some("claude-opus-4-5"));
    }

    #[test]
    fn missing_review_id_is_an_error() {
        let fields: Vec<_> = full_fields()
            .into_iter()
            .filter(|(k, _)| *k != "review_id")
            .collect();
        assert!(CodeScanReviewTask::from_stream_entry(&entry(&fields)).is_err());
    }

    #[test]
    fn non_numeric_review_id_is_an_error() {
        let mut fields = full_fields();
        fields.retain(|(k, _)| *k != "review_id");
        fields.push(("review_id", "not-a-number"));
        assert!(CodeScanReviewTask::from_stream_entry(&entry(&fields)).is_err());
    }

    #[test]
    fn missing_repo_config_id_is_an_error() {
        let fields: Vec<_> = full_fields()
            .into_iter()
            .filter(|(k, _)| *k != "repo_config_id")
            .collect();
        assert!(CodeScanReviewTask::from_stream_entry(&entry(&fields)).is_err());
    }

    #[test]
    fn missing_provider_is_an_error() {
        let fields: Vec<_> = full_fields()
            .into_iter()
            .filter(|(k, _)| *k != "provider")
            .collect();
        assert!(CodeScanReviewTask::from_stream_entry(&entry(&fields)).is_err());
    }

    #[test]
    fn missing_repo_name_is_an_error() {
        let fields: Vec<_> = full_fields()
            .into_iter()
            .filter(|(k, _)| *k != "repo_name")
            .collect();
        assert!(CodeScanReviewTask::from_stream_entry(&entry(&fields)).is_err());
    }

    #[test]
    fn missing_pr_url_is_an_error() {
        let fields: Vec<_> = full_fields()
            .into_iter()
            .filter(|(k, _)| *k != "pr_url")
            .collect();
        assert!(CodeScanReviewTask::from_stream_entry(&entry(&fields)).is_err());
    }

    #[test]
    fn missing_tenant_id_is_an_error() {
        let fields: Vec<_> = full_fields()
            .into_iter()
            .filter(|(k, _)| *k != "tenant_id")
            .collect();
        assert!(CodeScanReviewTask::from_stream_entry(&entry(&fields)).is_err());
    }

    #[test]
    fn invalid_tenant_id_is_an_error() {
        let mut fields = full_fields();
        fields.retain(|(k, _)| *k != "tenant_id");
        fields.push(("tenant_id", "nope"));
        assert!(CodeScanReviewTask::from_stream_entry(&entry(&fields)).is_err());
    }

    #[test]
    fn nil_tenant_id_is_an_error() {
        let mut fields = full_fields();
        fields.retain(|(k, _)| *k != "tenant_id");
        fields.push(("tenant_id", "00000000-0000-0000-0000-000000000000"));
        assert!(
            CodeScanReviewTask::from_stream_entry(&entry(&fields)).is_err(),
            "the nil UUID must never be treated as a valid tenant"
        );
    }

    #[test]
    fn review_result_roundtrips_through_json() {
        let result = ReviewResult {
            review_id: 1,
            status: "completed".to_string(),
            summary: "looks good".to_string(),
            comments_count: 2,
            completed_at: "2026-07-25T00:00:00Z".to_string(),
        };
        let encoded = serde_json::to_string(&result).expect("serialize");
        let decoded: ReviewResult = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded.review_id, 1);
        assert_eq!(decoded.status, "completed");
        assert_eq!(decoded.comments_count, 2);
    }
}
