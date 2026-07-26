//! Configuration for the Darwin review worker.

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
    /// Consumer group name (default: darwin-workers).
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
    /// Anthropic API key (if provider is anthropic).
    pub _anthropic_api_key: Option<String>,
    /// OpenAI API key (if provider is openai).
    pub _openai_api_key: Option<String>,
    /// Ollama base URL (if provider is ollama, default: http://localhost:11434).
    pub _ollama_url: String,
    /// AI request timeout in seconds (default: 60).
    pub _ai_timeout_sec: u64,
    /// Review categories (default: security,best_practices).
    pub _review_categories: Vec<String>,
}

impl WorkerConfig {
    /// Load configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        let redis_url =
            env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());
        let redis_password = env::var("REDIS_PASSWORD").ok();
        let redis_prefix =
            env::var("REDIS_KEY_PREFIX").unwrap_or_else(|_| "skauswatch".to_string());

        let consumer_group =
            env::var("CONSUMER_GROUP").unwrap_or_else(|_| "darwin-workers".to_string());
        let consumer_name = env::var("CONSUMER_NAME")
            .or_else(|_| env::var("HOSTNAME"))
            .unwrap_or_else(|_| format!("darwin-worker-{}", std::process::id()));

        let max_concurrent_tasks = env::var("MAX_CONCURRENT_TASKS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        let health_port = env::var("HEALTH_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(8080);

        let ai_provider = env::var("AI_PROVIDER").unwrap_or_else(|_| "anthropic".to_string());
        let ai_model = env::var("AI_MODEL").unwrap_or_else(|_| "claude-opus-4-5".to_string());
        let anthropic_api_key = env::var("ANTHROPIC_API_KEY").ok();
        let openai_api_key = env::var("OPENAI_API_KEY").ok();
        let ollama_url =
            env::var("OLLAMA_URL").unwrap_or_else(|_| "http://localhost:11434".to_string());

        let ai_timeout_sec = env::var("AI_TIMEOUT_SEC")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60);

        let review_categories = env::var("REVIEW_CATEGORIES")
            .unwrap_or_else(|_| "security,best_practices".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        Ok(Self {
            redis_url,
            redis_password,
            redis_prefix,
            consumer_group,
            consumer_name,
            max_concurrent_tasks,
            health_port,
            ai_provider,
            ai_model,
            _anthropic_api_key: anthropic_api_key,
            _openai_api_key: openai_api_key,
            _ollama_url: ollama_url,
            _ai_timeout_sec: ai_timeout_sec,
            _review_categories: review_categories,
        })
    }
}
