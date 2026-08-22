//! Runtime configuration read from the environment. Each `env_*` reader is a
//! thin wrapper around a pure `resolve_*` function operating on
//! `Option<&str>`, the same split used by `services/s3scan/src/config.rs` —
//! `unsafe_code = "deny"` at the workspace level rules out
//! `std::env::set_var` in tests, so default-substitution/parsing logic has
//! to be reachable without touching process env at all.

/// Default REST port for the OCI proxy + admin API.
pub const DEFAULT_HTTP_PORT: u16 = 5050;

/// Reads an env var, falling back to `default` when unset or empty — mirrors
/// `services/pki/src/config.rs::env_or`.
fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_owned(),
    }
}

/// Deployment environment segment for this workload's SPIFFE ID
/// (`spiffe://penguintech.io/<env>/depgate` —
/// `docs/v2-port/service-auth-model.md` §1), read from `SPIFFE_ENV`
/// (default `"beta"`) — mirrors `services/pki/src/config.rs::spiffe_env`
/// and `services/manager/src/state.rs::spiffe_env` exactly, so all three
/// services resolve the same env segment from the same env var.
pub fn spiffe_env() -> String {
    env_or("SPIFFE_ENV", "beta")
}

fn resolve_or(v: Option<&str>, default: &str) -> String {
    match v {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => default.to_owned(),
    }
}

fn resolve_opt(v: Option<&str>) -> Option<String> {
    v.filter(|s| !s.is_empty()).map(str::to_owned)
}

fn resolve_num<T: std::str::FromStr>(v: Option<&str>, default: T) -> T {
    v.and_then(|s| s.parse().ok()).unwrap_or(default)
}

/// Upstream OCI registry settings — single default upstream for P1
/// (multi-upstream routing by registry host, per §4/§11's "per-upstream
/// config", is deferred to a later phase; see `src/upstream.rs` docs).
#[derive(Debug, Clone)]
pub struct UpstreamConfig {
    /// Registry API base (`DEPGATE_UPSTREAM_BASE_URL`).
    pub base_url: String,
    /// Fallback token-auth realm used only when the registry's own
    /// `WWW-Authenticate` challenge omits `realm` (`DEPGATE_UPSTREAM_AUTH_URL`).
    pub auth_url: String,
    /// Fallback `service` param for the same fallback case
    /// (`DEPGATE_UPSTREAM_SERVICE`).
    pub service: String,
    /// Optional Basic-auth username for the token endpoint
    /// (`DEPGATE_UPSTREAM_USERNAME`) — raises Docker Hub's anonymous-pull
    /// rate limit; never required for public images.
    pub username: Option<String>,
    /// Optional Basic-auth password (`DEPGATE_UPSTREAM_PASSWORD`).
    pub password: Option<String>,
}

fn resolve_upstream(
    base_url: Option<&str>,
    auth_url: Option<&str>,
    service: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> UpstreamConfig {
    UpstreamConfig {
        base_url: resolve_or(base_url, "https://registry-1.docker.io"),
        auth_url: resolve_or(auth_url, "https://auth.docker.io/token"),
        service: resolve_or(service, "registry.docker.io"),
        username: resolve_opt(username),
        password: resolve_opt(password),
    }
}

impl UpstreamConfig {
    /// Loads upstream settings from the environment.
    pub fn from_env() -> Self {
        resolve_upstream(
            std::env::var("DEPGATE_UPSTREAM_BASE_URL").ok().as_deref(),
            std::env::var("DEPGATE_UPSTREAM_AUTH_URL").ok().as_deref(),
            std::env::var("DEPGATE_UPSTREAM_SERVICE").ok().as_deref(),
            std::env::var("DEPGATE_UPSTREAM_USERNAME").ok().as_deref(),
            std::env::var("DEPGATE_UPSTREAM_PASSWORD").ok().as_deref(),
        )
    }
}

/// Cache-bucket + scan-engine + serving settings.
#[derive(Debug, Clone)]
pub struct DepgateConfig {
    /// REST bind port (`API_PORT`).
    pub http_port: u16,
    /// Dedicated cache bucket name (`DEPGATE_CACHE_BUCKET`).
    pub cache_bucket: String,
    /// Key prefix for servable, verdict-clean content-addressed objects
    /// (`DEPGATE_CACHE_PREFIX`, default `sha256/`).
    pub cache_prefix: String,
    /// Key prefix for flagged, never-served objects
    /// (`DEPGATE_QUARANTINE_PREFIX`, default `quarantine/`).
    pub quarantine_prefix: String,
    /// Upper bound on a single fetched artifact's size, in bytes
    /// (`DEPGATE_MAX_ARTIFACT_BYTES`, default 512 MiB) — oversized upstream
    /// responses are refused before they are ever buffered fully in memory.
    pub max_artifact_bytes: u64,
    /// Unix-socket path to clamd (`CLAMD_SOCKET`) — `None` disables ClamAV.
    pub clamd_socket: Option<String>,
    /// Per-scan clamd timeout in seconds (`CLAMD_TIMEOUT`, default 30).
    pub clamd_timeout_secs: u64,
    /// YARA rules directory/file (`YARA_RULES_PATH`) — `None` disables YARA.
    pub yara_rules_path: Option<String>,
}

// One argument per DEPGATE_* env var, mirroring `resolve_upstream` above and
// `services/s3scan/src/config.rs`'s identical split-for-testability pattern
// — a params struct would just move the same fields without adding clarity.
#[allow(clippy::too_many_arguments)]
fn resolve_depgate(
    http_port: Option<&str>,
    cache_bucket: Option<&str>,
    cache_prefix: Option<&str>,
    quarantine_prefix: Option<&str>,
    max_artifact_bytes: Option<&str>,
    clamd_socket: Option<&str>,
    clamd_timeout_secs: Option<&str>,
    yara_rules_path: Option<&str>,
) -> DepgateConfig {
    DepgateConfig {
        http_port: resolve_num(http_port, DEFAULT_HTTP_PORT),
        cache_bucket: resolve_or(cache_bucket, "depgate-cache"),
        cache_prefix: resolve_or(cache_prefix, "sha256/"),
        quarantine_prefix: resolve_or(quarantine_prefix, "quarantine/"),
        max_artifact_bytes: resolve_num(max_artifact_bytes, 512 * 1024 * 1024),
        clamd_socket: resolve_opt(clamd_socket),
        clamd_timeout_secs: resolve_num(clamd_timeout_secs, 30),
        yara_rules_path: resolve_opt(yara_rules_path),
    }
}

impl DepgateConfig {
    /// Loads config from the environment.
    pub fn from_env() -> Self {
        resolve_depgate(
            std::env::var("API_PORT").ok().as_deref(),
            std::env::var("DEPGATE_CACHE_BUCKET").ok().as_deref(),
            std::env::var("DEPGATE_CACHE_PREFIX").ok().as_deref(),
            std::env::var("DEPGATE_QUARANTINE_PREFIX").ok().as_deref(),
            std::env::var("DEPGATE_MAX_ARTIFACT_BYTES").ok().as_deref(),
            std::env::var("CLAMD_SOCKET").ok().as_deref(),
            std::env::var("CLAMD_TIMEOUT").ok().as_deref(),
            std::env::var("YARA_RULES_PATH").ok().as_deref(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_defaults_to_docker_hub() {
        let cfg = resolve_upstream(None, None, None, None, None);
        assert_eq!(cfg.base_url, "https://registry-1.docker.io");
        assert_eq!(cfg.auth_url, "https://auth.docker.io/token");
        assert_eq!(cfg.service, "registry.docker.io");
        assert_eq!(cfg.username, None);
        assert_eq!(cfg.password, None);
    }

    #[test]
    fn upstream_honors_overrides() {
        let cfg = resolve_upstream(
            Some("https://ghcr.io"),
            Some("https://ghcr.io/token"),
            Some("ghcr.io"),
            Some("user"),
            Some("pass"),
        );
        assert_eq!(cfg.base_url, "https://ghcr.io");
        assert_eq!(cfg.username.as_deref(), Some("user"));
        assert_eq!(cfg.password.as_deref(), Some("pass"));
    }

    #[test]
    fn upstream_blank_values_fall_back_to_defaults() {
        let cfg = resolve_upstream(Some(""), Some(""), Some(""), Some(""), Some(""));
        assert_eq!(cfg.base_url, "https://registry-1.docker.io");
        assert_eq!(cfg.username, None);
    }

    #[test]
    fn depgate_defaults() {
        let cfg = resolve_depgate(None, None, None, None, None, None, None, None);
        assert_eq!(cfg.http_port, DEFAULT_HTTP_PORT);
        assert_eq!(cfg.cache_bucket, "depgate-cache");
        assert_eq!(cfg.cache_prefix, "sha256/");
        assert_eq!(cfg.quarantine_prefix, "quarantine/");
        assert_eq!(cfg.max_artifact_bytes, 512 * 1024 * 1024);
        assert_eq!(cfg.clamd_socket, None);
        assert_eq!(cfg.clamd_timeout_secs, 30);
        assert_eq!(cfg.yara_rules_path, None);
    }

    #[test]
    fn depgate_honors_overrides() {
        let cfg = resolve_depgate(
            Some("9090"),
            Some("my-bucket"),
            Some("blobs/"),
            Some("bad/"),
            Some("1024"),
            Some("/var/run/clamd.sock"),
            Some("5"),
            Some("/etc/yara"),
        );
        assert_eq!(cfg.http_port, 9090);
        assert_eq!(cfg.cache_bucket, "my-bucket");
        assert_eq!(cfg.cache_prefix, "blobs/");
        assert_eq!(cfg.quarantine_prefix, "bad/");
        assert_eq!(cfg.max_artifact_bytes, 1024);
        assert_eq!(cfg.clamd_socket.as_deref(), Some("/var/run/clamd.sock"));
        assert_eq!(cfg.clamd_timeout_secs, 5);
        assert_eq!(cfg.yara_rules_path.as_deref(), Some("/etc/yara"));
    }

    #[test]
    fn depgate_invalid_numeric_values_fall_back_to_defaults() {
        let cfg = resolve_depgate(Some("not-a-port"), None, None, None, None, None, None, None);
        assert_eq!(cfg.http_port, DEFAULT_HTTP_PORT);
    }

    #[test]
    fn spiffe_env_defaults_to_beta_when_unset() {
        assert!(std::env::var("SPIFFE_ENV").is_err());
        assert_eq!(spiffe_env(), "beta");
    }
}
