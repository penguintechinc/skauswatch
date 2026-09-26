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
use std::sync::OnceLock;
use std::time::Duration;

/// Bounds every ad hoc `reqwest::Client` this crate builds for an outbound
/// hop (git_provider.rs/git_write.rs's GitHub/GitLab REST calls,
/// tree_fetch.rs's archive downloads, main.rs's own `/healthz` self-probe) —
/// audit finding (issue #149, HIGH): a hung/slow git host or self-probe
/// target must never wedge the worker indefinitely. Mirrors
/// `services/depgate/src/config.rs::HttpClientConfig` exactly.
#[derive(Debug, Clone, Copy)]
pub struct HttpClientConfig {
    /// Whole-request timeout in seconds
    /// (`WORKER_CODESCAN_HTTP_TIMEOUT_SECS`, default 30).
    pub timeout_secs: u64,
    /// TCP+TLS connect timeout in seconds
    /// (`WORKER_CODESCAN_HTTP_CONNECT_TIMEOUT_SECS`, default 10).
    pub connect_timeout_secs: u64,
}

impl HttpClientConfig {
    /// Loads the shared bounds from the environment. Back-compat: unset env
    /// vars preserve prior behavior except now bounded (previously
    /// unbounded — no timeout at all on a bare `reqwest::Client::new()`).
    pub fn from_env() -> Self {
        Self {
            timeout_secs: env::var("WORKER_CODESCAN_HTTP_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            connect_timeout_secs: env::var("WORKER_CODESCAN_HTTP_CONNECT_TIMEOUT_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10),
        }
    }
}

/// Builds a bounded `reqwest::Client` per [`HttpClientConfig`].
/// `ClientBuilder::build()` only fails on conflicting TLS-backend/proxy
/// config, none of which this call site sets, but the `Result` is still
/// surfaced (never `.unwrap()`/`.expect()`) so a future change to this
/// builder can't silently become a panic.
pub fn build_http_client() -> Result<reqwest::Client, reqwest::Error> {
    let cfg = HttpClientConfig::from_env();
    reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_secs))
        .connect_timeout(Duration::from_secs(cfg.connect_timeout_secs))
        .build()
}

/// Process-wide shared bounded client, replacing the per-request
/// `Client::new()`/`reqwest::Client::new()` this crate previously built
/// fresh (and unbounded) at every git_provider.rs/git_write.rs/
/// tree_fetch.rs/main.rs call site. `OnceLock::get_or_init`'s initializer
/// can't propagate a `Result`, so a builder failure (practically
/// unreachable — see [`build_http_client`]'s doc comment) logs and falls
/// back to an unbounded default rather than panicking.
pub fn http_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            build_http_client().unwrap_or_else(|e| {
                tracing::error!(
                    error = %e,
                    "bounded http client build failed, falling back to unbounded default"
                );
                reqwest::Client::new()
            })
        })
        .clone()
}

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
    /// Base64-encoded AES-256-GCM key (`CREDENTIAL_ENCRYPTION_KEY`) used to
    /// decrypt `codescan_git_credentials.encrypted_token` rows — must match
    /// the key codescan-backend encrypted with (same env var name, same
    /// format; see `skauswatch_vault::CredentialCipher`). `None` means
    /// per-repo credential
    /// resolution is disabled; the worker falls back to `git_token`.
    pub credential_encryption_key: Option<String>,
    /// npm registry base URL override for license lookups (`NPM_REGISTRY_URL`);
    /// `None` uses the public registry.
    pub npm_registry_url: Option<String>,
    /// PyPI base URL override for license lookups (`PYPI_REGISTRY_URL`);
    /// `None` uses the public index.
    pub pypi_registry_url: Option<String>,
    /// crates.io base URL override for license lookups
    /// (`CRATES_REGISTRY_URL`); `None` uses the public registry.
    pub crates_registry_url: Option<String>,
    /// deps.dev base URL override for Go (`go.mod`) license lookups
    /// (`GO_REGISTRY_URL`); `None` uses the public deps.dev API. Go has no
    /// registry of its own with a per-module license field, so this scans
    /// via deps.dev instead (see `crate::license_scan`).
    pub go_registry_url: Option<String>,
    /// WaddleAI inference endpoint for CodeScan Sentinel P3 reachability
    /// triage (`WADDLEAI_BASE_URL`, see `skauswatch_ai::waddleai`). `None`
    /// means AI triage is disabled/unconfigured — the deterministic
    /// prefilter and policy engine (default matrix) still run for an
    /// Enterprise-licensed tenant; only the AI call itself is skipped (see
    /// `handler::CodeScanReviewHandler`'s graceful-degradation path).
    pub waddleai_base_url: Option<String>,
    /// WaddleAI API key (`WADDLEAI_API_KEY`). `None` behaves identically to
    /// `waddleai_base_url` being `None` — both are required together.
    pub waddleai_api_key: Option<String>,
    /// WaddleAI model tier to request (`WADDLEAI_TIER`, default `"reason"`)
    /// — `"bulk"`/`"reason"`/`"hard"` per spec §4; WaddleAI itself resolves
    /// the concrete model.
    pub waddleai_tier: String,
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
            env::var("CREDENTIAL_ENCRYPTION_KEY").ok().as_deref(),
            env::var("NPM_REGISTRY_URL").ok().as_deref(),
            env::var("PYPI_REGISTRY_URL").ok().as_deref(),
            env::var("CRATES_REGISTRY_URL").ok().as_deref(),
            env::var("GO_REGISTRY_URL").ok().as_deref(),
            env::var("WADDLEAI_BASE_URL").ok().as_deref(),
            env::var("WADDLEAI_API_KEY").ok().as_deref(),
            env::var("WADDLEAI_TIER").ok().as_deref(),
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
        credential_encryption_key: Option<&str>,
        npm_registry_url: Option<&str>,
        pypi_registry_url: Option<&str>,
        crates_registry_url: Option<&str>,
        go_registry_url: Option<&str>,
        waddleai_base_url: Option<&str>,
        waddleai_api_key: Option<&str>,
        waddleai_tier: Option<&str>,
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
            credential_encryption_key: credential_encryption_key.map(str::to_owned),
            npm_registry_url: npm_registry_url.map(str::to_owned),
            pypi_registry_url: pypi_registry_url.map(str::to_owned),
            crates_registry_url: crates_registry_url.map(str::to_owned),
            go_registry_url: go_registry_url.map(str::to_owned),
            waddleai_base_url: waddleai_base_url.map(str::to_owned),
            waddleai_api_key: waddleai_api_key.map(str::to_owned),
            waddleai_tier: waddleai_tier.unwrap_or("reason").to_owned(),
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
        assert_eq!(cfg.credential_encryption_key, None);
        assert_eq!(cfg.npm_registry_url, None);
        assert_eq!(cfg.pypi_registry_url, None);
        assert_eq!(cfg.crates_registry_url, None);
        assert_eq!(cfg.go_registry_url, None);
        assert_eq!(cfg.waddleai_base_url, None);
        assert_eq!(cfg.waddleai_api_key, None);
        assert_eq!(cfg.waddleai_tier, "reason");
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
            Some("base64keymaterial"),
            Some("http://npm.example.com"),
            Some("http://pypi.example.com"),
            Some("http://crates.example.com"),
            Some("http://depsdev.example.com"),
            Some("https://waddleai.internal"),
            Some("waddleai-key"),
            Some("hard"),
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
        assert_eq!(
            cfg.credential_encryption_key.as_deref(),
            Some("base64keymaterial")
        );
        assert_eq!(
            cfg.npm_registry_url.as_deref(),
            Some("http://npm.example.com")
        );
        assert_eq!(
            cfg.pypi_registry_url.as_deref(),
            Some("http://pypi.example.com")
        );
        assert_eq!(
            cfg.crates_registry_url.as_deref(),
            Some("http://crates.example.com")
        );
        assert_eq!(
            cfg.go_registry_url.as_deref(),
            Some("http://depsdev.example.com")
        );
        assert_eq!(
            cfg.waddleai_base_url.as_deref(),
            Some("https://waddleai.internal")
        );
        assert_eq!(cfg.waddleai_api_key.as_deref(), Some("waddleai-key"));
        assert_eq!(cfg.waddleai_tier, "hard");
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
            None,
            None,
            None,
            None,
            None,
            None,
            None,
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

    #[test]
    fn http_client_config_defaults_are_bounded() {
        // regression: gh-149 — this crate's ad hoc reqwest::Client sites
        // must never build with an unbounded (no-timeout) default.
        assert!(std::env::var("WORKER_CODESCAN_HTTP_TIMEOUT_SECS").is_err());
        assert!(std::env::var("WORKER_CODESCAN_HTTP_CONNECT_TIMEOUT_SECS").is_err());
        let cfg = HttpClientConfig::from_env();
        assert_eq!(cfg.timeout_secs, 30);
        assert_eq!(cfg.connect_timeout_secs, 10);
    }

    #[test]
    fn http_client_builds_successfully_with_default_bounds() {
        // Asserts `ClientBuilder::build()` actually succeeds for the exact
        // options this crate sets (timeout + connect_timeout only).
        assert!(build_http_client().is_ok());
        // `http_client()`'s OnceLock-backed accessor must also return a
        // usable client on first (and repeat) call.
        let _ = http_client();
        let _ = http_client();
    }
}
