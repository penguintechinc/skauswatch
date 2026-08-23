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

/// npm registry upstream settings (`docs/v2-port/v2.1-depgate.md` §4 P2).
/// Single default upstream, same posture as [`UpstreamConfig`] for OCI —
/// per-scope/per-upstream routing is a later-phase concern.
#[derive(Debug, Clone)]
pub struct NpmUpstreamConfig {
    /// Registry API base (`DEPGATE_NPM_REGISTRY_URL`).
    pub registry_url: String,
    /// Optional Bearer token for the upstream registry
    /// (`DEPGATE_NPM_TOKEN`) — raises rate limits / grants access to a
    /// private registry; never required for public packages.
    pub token: Option<String>,
}

fn resolve_npm_upstream(registry_url: Option<&str>, token: Option<&str>) -> NpmUpstreamConfig {
    NpmUpstreamConfig {
        registry_url: resolve_or(registry_url, "https://registry.npmjs.org"),
        token: resolve_opt(token),
    }
}

impl NpmUpstreamConfig {
    /// Loads npm upstream settings from the environment.
    pub fn from_env() -> Self {
        resolve_npm_upstream(
            std::env::var("DEPGATE_NPM_REGISTRY_URL").ok().as_deref(),
            std::env::var("DEPGATE_NPM_TOKEN").ok().as_deref(),
        )
    }
}

/// PyPI upstream settings (`docs/v2-port/v2.1-depgate.md` §4 P2). The index
/// (`pypi.org`, simple/JSON API) and the file host (`files.pythonhosted.org`,
/// actual wheel/sdist bytes) are configured separately because that is how
/// the real PyPI deployment is split, and a self-hosted index (devpi, etc.)
/// may split them differently too.
#[derive(Debug, Clone)]
pub struct PypiUpstreamConfig {
    /// Simple/JSON index API base (`DEPGATE_PYPI_INDEX_URL`).
    pub index_url: String,
    /// Package file host base (`DEPGATE_PYPI_FILES_URL`).
    pub files_url: String,
    /// Optional Basic-auth username for a private index
    /// (`DEPGATE_PYPI_USERNAME`).
    pub username: Option<String>,
    /// Optional Basic-auth password (`DEPGATE_PYPI_PASSWORD`).
    pub password: Option<String>,
}

fn resolve_pypi_upstream(
    index_url: Option<&str>,
    files_url: Option<&str>,
    username: Option<&str>,
    password: Option<&str>,
) -> PypiUpstreamConfig {
    PypiUpstreamConfig {
        index_url: resolve_or(index_url, "https://pypi.org"),
        files_url: resolve_or(files_url, "https://files.pythonhosted.org"),
        username: resolve_opt(username),
        password: resolve_opt(password),
    }
}

impl PypiUpstreamConfig {
    /// Loads PyPI upstream settings from the environment.
    pub fn from_env() -> Self {
        resolve_pypi_upstream(
            std::env::var("DEPGATE_PYPI_INDEX_URL").ok().as_deref(),
            std::env::var("DEPGATE_PYPI_FILES_URL").ok().as_deref(),
            std::env::var("DEPGATE_PYPI_USERNAME").ok().as_deref(),
            std::env::var("DEPGATE_PYPI_PASSWORD").ok().as_deref(),
        )
    }
}

/// How `crate::scanpipe::ScanPipeline::ingest` treats a scan-engine failure
/// (`ScanError` — the YARA-X engine itself erroring, not a plain
/// ClamAV-unreachable degrade-to-clean; see `skauswatch_scan_core::engine`'s
/// docs) — `docs/v2-port/v2.1-depgate.md` §6's configurable fail posture.
/// `infected`/`pup` verdicts are always blocked regardless of this setting;
/// it only governs the "scanning itself couldn't run" case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailPosture {
    /// Hardened default: a scan failure is treated as untrusted — refused,
    /// never cached or served.
    Closed,
    /// Dev convenience: a scan failure is logged and passed through
    /// best-effort, but never persisted as a vetted cache entry (an
    /// unscanned artifact must never become part of the trusted set).
    Open,
}

impl FailPosture {
    /// Parses `DEPGATE_FAIL_POSTURE` (`"closed"`/`"open"`, case-insensitive)
    /// — anything else (including unset) falls back to [`FailPosture::Closed`].
    fn from_env_str(v: Option<&str>) -> Self {
        match v.map(str::to_ascii_lowercase).as_deref() {
            Some("open") => FailPosture::Open,
            _ => FailPosture::Closed,
        }
    }
}

/// Cache-bucket + scan-engine + serving settings.
#[derive(Debug, Clone)]
pub struct DepgateConfig {
    /// REST bind port (`API_PORT`).
    pub http_port: u16,
    /// This deployment's own externally-reachable base URL
    /// (`DEPGATE_PUBLIC_BASE_URL`, default `http://localhost:{http_port}`) —
    /// used only to rewrite npm packument `dist.tarball` links and PyPI
    /// simple-index/JSON-API file links back at DepGate itself (§4 P2).
    /// The OCI proxy needs no equivalent: docker/containerd clients are
    /// pointed at DepGate directly via their own mirror config, never
    /// discover its address from a DepGate-served document.
    pub public_base_url: String,
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
    /// Air-gap serve mode (`DEPGATE_OFFLINE_MODE`, default `false`) — §6b.
    /// When `true`, every resolve path refuses to contact any upstream
    /// registry: a cache miss becomes a hard, explicit "not in the vetted
    /// set" error instead of a pull-through fetch. Unconditional — not
    /// governed by [`FailPosture`], which only concerns scan-engine
    /// failures.
    pub offline_mode: bool,
    /// Scan-error handling posture (`DEPGATE_FAIL_POSTURE`, default
    /// `closed`) — see [`FailPosture`].
    pub fail_posture: FailPosture,
    /// HMAC-SHA256 key used to sign/verify air-gap bundle manifests
    /// (`DEPGATE_BUNDLE_SIGNING_KEY`, §6b). `None` disables signing on
    /// export and signature verification on import (checksum/per-artifact
    /// hash verification still always applies). A symmetric MAC stands in
    /// for the spec's eventual cosign/sigstore asymmetric signing (P4,
    /// `docs/v2-port/v2.1-depgate.md` §9/§11) — reuses this workspace's
    /// existing `hmac`+`sha2` dependencies rather than adding a new
    /// signing stack for P3.
    pub bundle_signing_key: Option<String>,
}

// One argument per DEPGATE_* env var, mirroring `resolve_upstream` above and
// `services/s3scan/src/config.rs`'s identical split-for-testability pattern
// — a params struct would just move the same fields without adding clarity.
#[allow(clippy::too_many_arguments)]
fn resolve_depgate(
    http_port: Option<&str>,
    public_base_url: Option<&str>,
    cache_bucket: Option<&str>,
    cache_prefix: Option<&str>,
    quarantine_prefix: Option<&str>,
    max_artifact_bytes: Option<&str>,
    clamd_socket: Option<&str>,
    clamd_timeout_secs: Option<&str>,
    yara_rules_path: Option<&str>,
    offline_mode: Option<&str>,
    fail_posture: Option<&str>,
    bundle_signing_key: Option<&str>,
) -> DepgateConfig {
    let http_port = resolve_num(http_port, DEFAULT_HTTP_PORT);
    DepgateConfig {
        http_port,
        public_base_url: resolve_or(public_base_url, &format!("http://localhost:{http_port}")),
        cache_bucket: resolve_or(cache_bucket, "depgate-cache"),
        cache_prefix: resolve_or(cache_prefix, "sha256/"),
        quarantine_prefix: resolve_or(quarantine_prefix, "quarantine/"),
        max_artifact_bytes: resolve_num(max_artifact_bytes, 512 * 1024 * 1024),
        clamd_socket: resolve_opt(clamd_socket),
        clamd_timeout_secs: resolve_num(clamd_timeout_secs, 30),
        yara_rules_path: resolve_opt(yara_rules_path),
        offline_mode: matches!(
            offline_mode.map(str::to_ascii_lowercase).as_deref(),
            Some("true" | "1" | "yes")
        ),
        fail_posture: FailPosture::from_env_str(fail_posture),
        bundle_signing_key: resolve_opt(bundle_signing_key),
    }
}

impl DepgateConfig {
    /// Loads config from the environment.
    pub fn from_env() -> Self {
        resolve_depgate(
            std::env::var("API_PORT").ok().as_deref(),
            std::env::var("DEPGATE_PUBLIC_BASE_URL").ok().as_deref(),
            std::env::var("DEPGATE_CACHE_BUCKET").ok().as_deref(),
            std::env::var("DEPGATE_CACHE_PREFIX").ok().as_deref(),
            std::env::var("DEPGATE_QUARANTINE_PREFIX").ok().as_deref(),
            std::env::var("DEPGATE_MAX_ARTIFACT_BYTES").ok().as_deref(),
            std::env::var("CLAMD_SOCKET").ok().as_deref(),
            std::env::var("CLAMD_TIMEOUT").ok().as_deref(),
            std::env::var("YARA_RULES_PATH").ok().as_deref(),
            std::env::var("DEPGATE_OFFLINE_MODE").ok().as_deref(),
            std::env::var("DEPGATE_FAIL_POSTURE").ok().as_deref(),
            std::env::var("DEPGATE_BUNDLE_SIGNING_KEY").ok().as_deref(),
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
        let cfg = resolve_depgate(
            None, None, None, None, None, None, None, None, None, None, None, None,
        );
        assert_eq!(cfg.http_port, DEFAULT_HTTP_PORT);
        assert_eq!(
            cfg.public_base_url,
            format!("http://localhost:{DEFAULT_HTTP_PORT}")
        );
        assert_eq!(cfg.cache_bucket, "depgate-cache");
        assert_eq!(cfg.cache_prefix, "sha256/");
        assert_eq!(cfg.quarantine_prefix, "quarantine/");
        assert_eq!(cfg.max_artifact_bytes, 512 * 1024 * 1024);
        assert_eq!(cfg.clamd_socket, None);
        assert_eq!(cfg.clamd_timeout_secs, 30);
        assert_eq!(cfg.yara_rules_path, None);
        assert!(!cfg.offline_mode);
        assert_eq!(cfg.fail_posture, FailPosture::Closed);
        assert_eq!(cfg.bundle_signing_key, None);
    }

    #[test]
    fn depgate_honors_overrides() {
        let cfg = resolve_depgate(
            Some("9090"),
            Some("https://depgate.internal"),
            Some("my-bucket"),
            Some("blobs/"),
            Some("bad/"),
            Some("1024"),
            Some("/var/run/clamd.sock"),
            Some("5"),
            Some("/etc/yara"),
            Some("true"),
            Some("open"),
            Some("sekret"),
        );
        assert_eq!(cfg.http_port, 9090);
        assert_eq!(cfg.public_base_url, "https://depgate.internal");
        assert_eq!(cfg.cache_bucket, "my-bucket");
        assert_eq!(cfg.cache_prefix, "blobs/");
        assert_eq!(cfg.quarantine_prefix, "bad/");
        assert_eq!(cfg.max_artifact_bytes, 1024);
        assert_eq!(cfg.clamd_socket.as_deref(), Some("/var/run/clamd.sock"));
        assert_eq!(cfg.clamd_timeout_secs, 5);
        assert_eq!(cfg.yara_rules_path.as_deref(), Some("/etc/yara"));
        assert!(cfg.offline_mode);
        assert_eq!(cfg.fail_posture, FailPosture::Open);
        assert_eq!(cfg.bundle_signing_key.as_deref(), Some("sekret"));
    }

    #[test]
    fn depgate_invalid_numeric_values_fall_back_to_defaults() {
        let cfg = resolve_depgate(
            Some("not-a-port"),
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
        assert_eq!(cfg.http_port, DEFAULT_HTTP_PORT);
    }

    #[test]
    fn fail_posture_from_env_str_is_case_insensitive_and_defaults_closed() {
        assert_eq!(FailPosture::from_env_str(Some("OPEN")), FailPosture::Open);
        assert_eq!(FailPosture::from_env_str(Some("open")), FailPosture::Open);
        assert_eq!(
            FailPosture::from_env_str(Some("closed")),
            FailPosture::Closed
        );
        assert_eq!(
            FailPosture::from_env_str(Some("bogus")),
            FailPosture::Closed
        );
        assert_eq!(FailPosture::from_env_str(None), FailPosture::Closed);
    }

    #[test]
    fn offline_mode_accepts_common_truthy_spellings() {
        for v in ["true", "TRUE", "1", "yes"] {
            let cfg = resolve_depgate(
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Some(v),
                None,
                None,
            );
            assert!(cfg.offline_mode, "expected {v:?} to enable offline mode");
        }
        let cfg = resolve_depgate(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("false"),
            None,
            None,
        );
        assert!(!cfg.offline_mode);
    }

    #[test]
    fn npm_upstream_defaults_to_npmjs() {
        let cfg = resolve_npm_upstream(None, None);
        assert_eq!(cfg.registry_url, "https://registry.npmjs.org");
        assert_eq!(cfg.token, None);
    }

    #[test]
    fn npm_upstream_honors_overrides() {
        let cfg = resolve_npm_upstream(Some("https://npm.internal"), Some("tok-123"));
        assert_eq!(cfg.registry_url, "https://npm.internal");
        assert_eq!(cfg.token.as_deref(), Some("tok-123"));
    }

    #[test]
    fn npm_upstream_blank_values_fall_back_to_defaults() {
        let cfg = resolve_npm_upstream(Some(""), Some(""));
        assert_eq!(cfg.registry_url, "https://registry.npmjs.org");
        assert_eq!(cfg.token, None);
    }

    #[test]
    fn pypi_upstream_defaults_to_pypi_org() {
        let cfg = resolve_pypi_upstream(None, None, None, None);
        assert_eq!(cfg.index_url, "https://pypi.org");
        assert_eq!(cfg.files_url, "https://files.pythonhosted.org");
        assert_eq!(cfg.username, None);
        assert_eq!(cfg.password, None);
    }

    #[test]
    fn pypi_upstream_honors_overrides() {
        let cfg = resolve_pypi_upstream(
            Some("https://pypi.internal"),
            Some("https://files.internal"),
            Some("user"),
            Some("pass"),
        );
        assert_eq!(cfg.index_url, "https://pypi.internal");
        assert_eq!(cfg.files_url, "https://files.internal");
        assert_eq!(cfg.username.as_deref(), Some("user"));
        assert_eq!(cfg.password.as_deref(), Some("pass"));
    }

    #[test]
    fn spiffe_env_defaults_to_beta_when_unset() {
        assert!(std::env::var("SPIFFE_ENV").is_err());
        assert_eq!(spiffe_env(), "beta");
    }
}
