//! Environment-driven configuration. Rust port of the env-var subset of v1
//! `services/aaa-monitor/config.py::AAAMonitorConfig`.
//!
//! v1 only wired ~20 env vars (`AAA_REDIS_URL`, `AAA_DATABASE_*`,
//! `AAA_LOG_LEVEL`, `AAA_API_HOST/PORT`, `AAA_SECRET_KEY`, the AI provider
//! keys, and a handful of collector enable flags); everything else
//! (including the entire `elasticsearch`/`mongodb` sub-config used by
//! `log_processor.py`) was only reachable via an optional YAML/JSON file
//! path passed on the CLI — there was no env var for ES/Mongo connection
//! settings at all. Since this port's whole point is a working ES/Mongo
//! event store, `AAA_ES_*`/`AAA_MONGO_*` env vars are added here (a
//! deliberate improvement over v1, not a preserved quirk) so the service is
//! configurable the same way every other PenguinTech service is (12-factor
//! env vars, no config file).
//!
//! Parsing is split into pure `from_values` constructors (testable without
//! touching process env — `unsafe_code = "deny"` at the workspace level
//! rules out `std::env::set_var` in tests) and a thin `from_env` that reads
//! `std::env::var`, mirroring the house pattern in
//! `services/manager/src/routes/siem.rs`.

use std::env;

/// API server config. v1 `APIConfig` (subset actually reachable via env).
#[derive(Debug, Clone)]
pub struct ApiConfig {
    /// Bind host.
    pub host: String,
    /// Bind port.
    pub port: u16,
}

/// Auth/security config. v1 `SecurityConfig`.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// HS256 signing secret for bearer tokens (`AAA_SECRET_KEY`/
    /// `AAA_JWT_SECRET`).
    pub secret_key: String,
    /// Dev-only bypass (`AAA_AUTH_ENABLED=false`) — never the default.
    pub auth_enabled: bool,
}

/// Elasticsearch/OpenSearch connection settings for the event store.
#[derive(Debug, Clone)]
pub struct ElasticsearchConfig {
    /// Whether the ES/OpenSearch backend is enabled (`AAA_ES_ENABLED`).
    pub enabled: bool,
    /// Base URL, e.g. `http://elasticsearch:9200` (`AAA_ES_URL`).
    pub url: String,
    /// Index pattern used for search (`AAA_ES_INDEX_PATTERN`), v1 default
    /// `aaa-events-*`.
    pub index_pattern: String,
    /// Optional basic-auth username (`AAA_ES_USERNAME`).
    pub username: Option<String>,
    /// Optional basic-auth password (`AAA_ES_PASSWORD`).
    pub password: Option<String>,
}

/// Top-level service configuration, loaded once at startup from env vars.
#[derive(Debug, Clone)]
pub struct Config {
    /// API server settings.
    pub api: ApiConfig,
    /// Auth settings.
    pub security: SecurityConfig,
    /// Elasticsearch/OpenSearch settings.
    pub elasticsearch: ElasticsearchConfig,
}

/// Parses common truthy spellings (`true`/`1`/`yes`, case-insensitive);
/// anything else, including "false"/unset, is `false`.
fn parse_bool(value: Option<&str>, default: bool) -> bool {
    match value {
        None => default,
        Some(v) => v.eq_ignore_ascii_case("true") || v == "1" || v.eq_ignore_ascii_case("yes"),
    }
}

impl Config {
    /// Pure constructor taking pre-resolved env values — the unit-testable
    /// core (no process env access, no `unsafe`).
    #[allow(clippy::too_many_arguments)]
    fn from_values(
        api_host: Option<&str>,
        api_port: Option<&str>,
        secret_key: Option<&str>,
        auth_enabled: Option<&str>,
        es_enabled: Option<&str>,
        es_url: Option<&str>,
        es_index_pattern: Option<&str>,
        es_username: Option<&str>,
        es_password: Option<&str>,
    ) -> Self {
        let secret_key = secret_key.map(str::to_owned).unwrap_or_else(|| {
            // Random per-process secret (not the old guessable dev-{pid}) — an
            // unset secret fails closed (nothing can forge a token). Full
            // production fail-fast is tracked for the aaa-monitor security pass.
            tracing::warn!("AAA_SECRET_KEY not set — using a random ephemeral dev secret");
            uuid::Uuid::new_v4().to_string()
        });
        Self {
            api: ApiConfig {
                host: api_host.unwrap_or("0.0.0.0").to_owned(),
                port: api_port.and_then(|p| p.parse().ok()).unwrap_or(8003),
            },
            security: SecurityConfig {
                secret_key,
                auth_enabled: parse_bool(auth_enabled, true),
            },
            elasticsearch: ElasticsearchConfig {
                enabled: parse_bool(es_enabled, false),
                url: es_url.unwrap_or("http://localhost:9200").to_owned(),
                index_pattern: es_index_pattern.unwrap_or("aaa-events-*").to_owned(),
                username: es_username.map(str::to_owned),
                password: es_password.map(str::to_owned),
            },
        }
    }

    /// Loads configuration from the process environment. Never fails: every
    /// field has a v1-compatible default, matching v1's fully-optional env
    /// override design.
    pub fn from_env() -> Self {
        Self::from_values(
            env::var("AAA_API_HOST").ok().as_deref(),
            env::var("AAA_API_PORT").ok().as_deref(),
            env::var("AAA_SECRET_KEY")
                .or_else(|_| env::var("AAA_JWT_SECRET"))
                .ok()
                .as_deref(),
            env::var("AAA_AUTH_ENABLED").ok().as_deref(),
            env::var("AAA_ES_ENABLED").ok().as_deref(),
            env::var("AAA_ES_URL").ok().as_deref(),
            env::var("AAA_ES_INDEX_PATTERN").ok().as_deref(),
            env::var("AAA_ES_USERNAME").ok().as_deref(),
            env::var("AAA_ES_PASSWORD").ok().as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bool_accepts_common_truthy_spellings() {
        for v in ["true", "TRUE", "1", "yes", "YES"] {
            assert!(parse_bool(Some(v), false), "expected true for {v}");
        }
        assert!(!parse_bool(Some("false"), true));
        assert!(!parse_bool(Some("no"), true));
        assert!(parse_bool(None, true));
        assert!(!parse_bool(None, false));
    }

    #[test]
    fn defaults_match_v1_when_unset() {
        let cfg = Config::from_values(
            None,
            None,
            Some("test-secret"),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert_eq!(cfg.api.host, "0.0.0.0");
        assert_eq!(cfg.api.port, 8003);
        assert!(!cfg.elasticsearch.enabled);
        assert_eq!(cfg.elasticsearch.index_pattern, "aaa-events-*");
        assert!(cfg.security.auth_enabled);
    }

    #[test]
    fn overrides_are_honored() {
        let cfg = Config::from_values(
            Some("127.0.0.1"),
            Some("9999"),
            Some("s3cr3t"),
            Some("false"),
            Some("true"),
            Some("http://es:9200"),
            Some("custom-*"),
            Some("user"),
            Some("pass"),
        );
        assert_eq!(cfg.api.host, "127.0.0.1");
        assert_eq!(cfg.api.port, 9999);
        assert_eq!(cfg.security.secret_key, "s3cr3t");
        assert!(!cfg.security.auth_enabled);
        assert!(cfg.elasticsearch.enabled);
        assert_eq!(cfg.elasticsearch.url, "http://es:9200");
        assert_eq!(cfg.elasticsearch.index_pattern, "custom-*");
    }
}
