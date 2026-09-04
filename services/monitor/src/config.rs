//! Environment-driven configuration. Rust port of the env-var subset of v1
//! `services/monitor/config.py::MonitorConfig`.
//!
//! v1 only wired ~20 env vars (`MONITOR_REDIS_URL`, `MONITOR_DATABASE_*`,
//! `MONITOR_LOG_LEVEL`, `MONITOR_API_HOST/PORT`, `MONITOR_SECRET_KEY`, the AI provider
//! keys, and a handful of collector enable flags); everything else
//! (including the entire `elasticsearch`/`mongodb` sub-config used by
//! `log_processor.py`) was only reachable via an optional YAML/JSON file
//! path passed on the CLI — there was no env var for ES/Mongo connection
//! settings at all. Since this port's whole point is a working ES/Mongo
//! event store, `MONITOR_ES_*`/`MONITOR_MONGO_*` env vars are added here (a
//! deliberate improvement over v1, not a preserved quirk) so the service is
//! configurable the same way every other PenguinTech service is (12-factor
//! env vars, no config file).
//!
//! **JWT verify key (finding #3, hardened; ES256 per audit finding H1b):**
//! `MONITOR_SECRET_KEY`/`MONITOR_JWT_SECRET` are no longer read at all —
//! this service now shares the house `JWT_VERIFY_KEY` var with every other
//! JWT-verifying service (manager, vault, pki, sshca, codescan-backend),
//! loaded via `skauswatch_auth::load_jwt_verify_key` in
//! `state.rs::AppStateInner::from_env` (fail-fast in production, no
//! random-UUID fallback). It is intentionally not part of this module's
//! `Config`/`SecurityConfig` — the shared crate owns that env var's
//! parsing/fail-fast policy, not each service.
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

/// Auth/security config. v1 `SecurityConfig`. The ES256 verify key itself
/// is deliberately not a field here — see the module doc comment's
/// "JWT verify key (finding #3, hardened)" note: it lives on
/// `AppStateInner`, loaded via `skauswatch_auth::load_jwt_verify_key`.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// Dev-only bypass (`MONITOR_AUTH_ENABLED=false`) — never the default.
    pub auth_enabled: bool,
}

/// Elasticsearch/OpenSearch connection settings for the event store.
#[derive(Debug, Clone)]
pub struct ElasticsearchConfig {
    /// Whether the ES/OpenSearch backend is enabled (`MONITOR_ES_ENABLED`).
    pub enabled: bool,
    /// Base URL, e.g. `http://elasticsearch:9200` (`MONITOR_ES_URL`).
    pub url: String,
    /// Index pattern used for search (`MONITOR_ES_INDEX_PATTERN`), v1 default
    /// `aaa-events-*`.
    pub index_pattern: String,
    /// Optional basic-auth username (`MONITOR_ES_USERNAME`).
    pub username: Option<String>,
    /// Optional basic-auth password (`MONITOR_ES_PASSWORD`).
    pub password: Option<String>,
}

/// Owning tenant for every event this deployment's log collectors produce
/// (`MONITOR_TENANT_ID`) — added in the phase-12 collector port, not part of
/// v1 (v1 had no tenancy concept). Log collectors are host/cluster-level
/// integrations (auditd/journald/syslog/file/kubernetes/lxc/database) with
/// no per-request caller to derive a trusted tenant from the way REST routes
/// do via `tenant_middleware` — a monitor deployment instead *is* deployed
/// into exactly one tenant's infrastructure (its own cluster/hosts), so the
/// tenant is a server-side deployment-time fact, analogous to how
/// `endpoint-agent`'s enrollment token resolves a tenant server-side rather
/// than trusting anything the collected data itself claims (see
/// `docs/v2-port/tenancy-model.md` §3's "never accepted from a field the
/// remote party fully controls" rule — collected log/audit content is
/// exactly such a field, so it is never consulted for tenant identity).
/// Empty by default: collectors refuse to start without it (`collectors::
/// spawn_enabled`) rather than stamping events with an empty tenant that can
/// never match a real caller's filter (mirrors `BaseEvent::tenant_id`'s
/// documented empty-is-unreachable default).
#[derive(Debug, Clone)]
pub struct TenancyConfig {
    /// This deployment's tenant id (`MONITOR_TENANT_ID`).
    pub tenant_id: String,
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
    /// This deployment's tenant, stamped onto every collector-produced event.
    pub tenancy: TenancyConfig,
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
        auth_enabled: Option<&str>,
        es_enabled: Option<&str>,
        es_url: Option<&str>,
        es_index_pattern: Option<&str>,
        es_username: Option<&str>,
        es_password: Option<&str>,
        tenant_id: Option<&str>,
    ) -> Self {
        Self {
            api: ApiConfig {
                host: api_host.unwrap_or("0.0.0.0").to_owned(),
                port: api_port.and_then(|p| p.parse().ok()).unwrap_or(8003),
            },
            security: SecurityConfig {
                auth_enabled: parse_bool(auth_enabled, true),
            },
            elasticsearch: ElasticsearchConfig {
                enabled: parse_bool(es_enabled, false),
                url: es_url.unwrap_or("http://localhost:9200").to_owned(),
                index_pattern: es_index_pattern.unwrap_or("aaa-events-*").to_owned(),
                username: es_username.map(str::to_owned),
                password: es_password.map(str::to_owned),
            },
            tenancy: TenancyConfig {
                tenant_id: tenant_id.unwrap_or("").to_owned(),
            },
        }
    }

    /// Loads configuration from the process environment. Never fails: every
    /// field has a v1-compatible default, matching v1's fully-optional env
    /// override design. The JWT secret is loaded separately (and can fail,
    /// deliberately, in production) — see `state.rs::AppStateInner::from_env`.
    pub fn from_env() -> Self {
        Self::from_values(
            env::var("MONITOR_API_HOST").ok().as_deref(),
            env::var("MONITOR_API_PORT").ok().as_deref(),
            env::var("MONITOR_AUTH_ENABLED").ok().as_deref(),
            env::var("MONITOR_ES_ENABLED").ok().as_deref(),
            env::var("MONITOR_ES_URL").ok().as_deref(),
            env::var("MONITOR_ES_INDEX_PATTERN").ok().as_deref(),
            env::var("MONITOR_ES_USERNAME").ok().as_deref(),
            env::var("MONITOR_ES_PASSWORD").ok().as_deref(),
            env::var("MONITOR_TENANT_ID").ok().as_deref(),
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
        let cfg = Config::from_values(None, None, None, None, None, None, None, None, None);
        assert_eq!(cfg.api.host, "0.0.0.0");
        assert_eq!(cfg.api.port, 8003);
        assert!(!cfg.elasticsearch.enabled);
        assert_eq!(cfg.elasticsearch.index_pattern, "aaa-events-*");
        assert!(cfg.security.auth_enabled);
        assert_eq!(cfg.tenancy.tenant_id, "");
    }

    #[test]
    fn overrides_are_honored() {
        let cfg = Config::from_values(
            Some("127.0.0.1"),
            Some("9999"),
            Some("false"),
            Some("true"),
            Some("http://es:9200"),
            Some("custom-*"),
            Some("user"),
            Some("pass"),
            Some("tenant-a"),
        );
        assert_eq!(cfg.api.host, "127.0.0.1");
        assert_eq!(cfg.api.port, 9999);
        assert!(!cfg.security.auth_enabled);
        assert!(cfg.elasticsearch.enabled);
        assert_eq!(cfg.elasticsearch.url, "http://es:9200");
        assert_eq!(cfg.elasticsearch.index_pattern, "custom-*");
        assert_eq!(cfg.tenancy.tenant_id, "tenant-a");
    }
}
