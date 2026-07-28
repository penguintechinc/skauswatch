//! Configuration for the CodeScan review worker.
//!
//! Parsing is split into a pure [`WorkerConfig::from_values`] constructor
//! (testable without touching process env — `unsafe_code = "deny"` at the
//! workspace level rules out `std::env::set_var` in tests, see
//! `docs/v2-port/testing-pattern.md`) and a thin [`WorkerConfig::from_env`]
//! that resolves the process environment once at startup. Every value the
//! worker needs (AI provider credentials, the Ollama base URL, the git API
//! token/base-url override) is resolved here and carried on `WorkerConfig`
//! rather than re-read from `std::env::var` ad hoc deeper in the pipeline —
//! that keeps env access centralized and deterministic to construct in
//! tests.

use std::env;

/// Worker configuration loaded from environment variables.
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Redis URL (default: redis://localhost:6379).
    pub redis_url: String,
    /// Redis password (optional).
    pub redis_password: Option<String>,
    /// Redis key prefix (default: skauswatch).
    pub redis_prefix: String,
    /// Consumer group name (default: codescan-workers).
    pub consumer_group: String,
    /// Consumer name (unique per worker instance).
    pub consumer_name: String,
    /// Max concurrent tasks (default: 5).
    pub max_concurrent_tasks: u64,
    /// Health check port (default: 8080).
    pub health_port: u16,
    /// AI provider: anthropic, openai, ollama (default: anthropic).
    pub ai_provider: String,
    /// AI model to use (default: claude-opus-4-5).
    pub ai_model: String,
    /// Anthropic API key (used when `ai_provider` is `anthropic`).
    pub anthropic_api_key: Option<String>,
    /// OpenAI API key (used when `ai_provider` is `openai`).
    pub openai_api_key: Option<String>,
    /// Ollama base URL (used when `ai_provider` is `ollama`, default:
    /// http://localhost:11434).
    pub ollama_url: String,
    /// Git API token for fetching PR/MR diffs (`GIT_TOKEN`). `None` means no
    /// credential is configured; the worker still runs but skips diff
    /// fetching (see `handler::CodeScanReviewHandler::handle`).
    pub git_token: Option<String>,
    /// Git API base URL override for GitHub Enterprise / self-hosted GitLab
    /// (`GIT_API_BASE_URL`); `None` uses each provider's public API host.
    pub git_api_base_url: Option<String>,
    /// AI request timeout in seconds (default: 60).
    pub _ai_timeout_sec: u64,
    /// Review categories (default: security,best_practices).
    pub _review_categories: Vec<String>,
}

impl WorkerConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        // Dynamic (pid-based) default — resolved here, outside the pure
        // constructor, so `from_values` stays deterministic for tests.
        let consumer_name = env::var("CONSUMER_NAME")
            .or_else(|_| env::var("HOSTNAME"))
            .unwrap_or_else(|_| format!("codescan-worker-{}", std::process::id()));

        Ok(Self::from_values(
            env::var("REDIS_URL").ok().as_deref(),
            env::var("REDIS_PASSWORD").ok().as_deref(),
            env::var("REDIS_KEY_PREFIX").ok().as_deref(),
            env::var("CONSUMER_GROUP").ok().as_deref(),
            &consumer_name,
            env::var("MAX_CONCURRENT_TASKS").ok().as_deref(),
            env::var("HEALTH_PORT").ok().as_deref(),
            env::var("AI_PROVIDER").ok().as_deref(),
            env::var("AI_MODEL").ok().as_deref(),
            env::var("ANTHROPIC_API_KEY").ok().as_deref(),
            env::var("OPENAI_API_KEY").ok().as_deref(),
            env::var("OLLAMA_URL").ok().as_deref(),
            env::var("GIT_TOKEN").ok().as_deref(),
            env::var("GIT_API_BASE_URL").ok().as_deref(),
            env::var("AI_TIMEOUT_SEC").ok().as_deref(),
            env::var("REVIEW_CATEGORIES").ok().as_deref(),
        ))
    }

    /// Pure constructor over pre-resolved env values — the unit-testable
    /// core (no process env access, no `unsafe`).
    #[allow(clippy::too_many_arguments)]
    fn from_values(
        redis_url: Option<&str>,
        redis_password: Option<&str>,
        redis_prefix: Option<&str>,
        consumer_group: Option<&str>,
        consumer_name: &str,
        max_concurrent_tasks: Option<&str>,
        health_port: Option<&str>,
        ai_provider: Option<&str>,
        ai_model: Option<&str>,
        anthropic_api_key: Option<&str>,
        openai_api_key: Option<&str>,
        ollama_url: Option<&str>,
        git_token: Option<&str>,
        git_api_base_url: Option<&str>,
        ai_timeout_sec: Option<&str>,
        review_categories: Option<&str>,
    ) -> Self {
        Self {
            redis_url: redis_url.unwrap_or("redis://localhost:6379").to_owned(),
            redis_password: redis_password.map(str::to_owned),
            redis_prefix: redis_prefix.unwrap_or("skauswatch").to_owned(),
            consumer_group: consumer_group.unwrap_or("codescan-workers").to_owned(),
            consumer_name: consumer_name.to_owned(),
            max_concurrent_tasks: max_concurrent_tasks
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            health_port: health_port.and_then(|v| v.parse().ok()).unwrap_or(8080),
            ai_provider: ai_provider.unwrap_or("anthropic").to_owned(),
            ai_model: ai_model.unwrap_or("claude-opus-4-5").to_owned(),
            anthropic_api_key: anthropic_api_key.map(str::to_owned),
            openai_api_key: openai_api_key.map(str::to_owned),
            ollama_url: ollama_url.unwrap_or("http://localhost:11434").to_owned(),
            git_token: git_token.map(str::to_owned),
            git_api_base_url: git_api_base_url.map(str::to_owned),
            _ai_timeout_sec: ai_timeout_sec.and_then(|v| v.parse().ok()).unwrap_or(60),
            _review_categories: review_categories
                .unwrap_or("security,best_practices")
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_values() {
        let cfg = WorkerConfig::from_values(
            None,
            None,
            None,
            None,
            "consumer-1",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(cfg.redis_url, "redis://localhost:6379");
        assert_eq!(cfg.redis_password, None);
        assert_eq!(cfg.redis_prefix, "skauswatch");
        assert_eq!(cfg.consumer_group, "codescan-workers");
        assert_eq!(cfg.consumer_name, "consumer-1");
        assert_eq!(cfg.max_concurrent_tasks, 5);
        assert_eq!(cfg.health_port, 8080);
        assert_eq!(cfg.ai_provider, "anthropic");
        assert_eq!(cfg.ai_model, "claude-opus-4-5");
        assert_eq!(cfg.anthropic_api_key, None);
        assert_eq!(cfg.openai_api_key, None);
        assert_eq!(cfg.ollama_url, "http://localhost:11434");
        assert_eq!(cfg.git_token, None);
        assert_eq!(cfg.git_api_base_url, None);
        assert_eq!(cfg._ai_timeout_sec, 60);
        assert_eq!(cfg._review_categories, vec!["security", "best_practices"]);
    }

    #[test]
    fn explicit_values_override_defaults() {
        let cfg = WorkerConfig::from_values(
            Some("redis://cache:6379"),
            Some("s3cr3t"),
            Some("myprefix"),
            Some("mygroup"),
            "consumer-9",
            Some("12"),
            Some("9090"),
            Some("ollama"),
            Some("llama3"),
            Some("anthropic-key"),
            Some("openai-key"),
            Some("http://ollama:11434"),
            Some("git-token"),
            Some("https://github.example.com/api/v3"),
            Some("30"),
            Some("security, license"),
        );
        assert_eq!(cfg.redis_url, "redis://cache:6379");
        assert_eq!(cfg.redis_password.as_deref(), Some("s3cr3t"));
        assert_eq!(cfg.redis_prefix, "myprefix");
        assert_eq!(cfg.consumer_group, "mygroup");
        assert_eq!(cfg.consumer_name, "consumer-9");
        assert_eq!(cfg.max_concurrent_tasks, 12);
        assert_eq!(cfg.health_port, 9090);
        assert_eq!(cfg.ai_provider, "ollama");
        assert_eq!(cfg.ai_model, "llama3");
        assert_eq!(cfg.anthropic_api_key.as_deref(), Some("anthropic-key"));
        assert_eq!(cfg.openai_api_key.as_deref(), Some("openai-key"));
        assert_eq!(cfg.ollama_url, "http://ollama:11434");
        assert_eq!(cfg.git_token.as_deref(), Some("git-token"));
        assert_eq!(
            cfg.git_api_base_url.as_deref(),
            Some("https://github.example.com/api/v3")
        );
        assert_eq!(cfg._ai_timeout_sec, 30);
        // Split values are trimmed of surrounding whitespace.
        assert_eq!(cfg._review_categories, vec!["security", "license"]);
    }

    #[test]
    fn unparsable_numeric_values_fall_back_to_defaults() {
        let cfg = WorkerConfig::from_values(
            None,
            None,
            None,
            None,
            "consumer-x",
            Some("not-a-number"),
            Some("also-not-a-number"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("nope"),
            None,
        );
        assert_eq!(cfg.max_concurrent_tasks, 5);
        assert_eq!(cfg.health_port, 8080);
        assert_eq!(cfg._ai_timeout_sec, 60);
    }

    #[test]
    fn from_env_reads_process_environment_without_panicking() {
        // Does not set any env vars (unsafe_code = "deny" rules out
        // std::env::set_var in tests) — exercises the from_env -> from_values
        // wiring against whatever ambient env the test process inherited,
        // and asserts it always yields a usable config rather than erroring.
        let cfg = WorkerConfig::from_env().expect("from_env never fails");
        assert!(!cfg.consumer_name.is_empty());
        assert!(!cfg.redis_url.is_empty());
    }
}
