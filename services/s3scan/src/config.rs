//! Worker configuration loaded from the environment, preserving the v1
//! `s3scan` variable names and defaults (`CONSUMER_NAME`, `REDIS_URL`,
//! `CONSUMER_GROUP`, `MAX_*`, `CLAMD_*`, `TI_*`, …). Database settings reuse
//! the shared `skauswatch-db` `DB_*` loader so the worker and manager agree on
//! the connection contract.

// Each `env_*` reader below is a thin `std::env::var` wrapper around a pure
// `resolve_*` function operating on `Option<&str>`. The split exists purely
// for testability: `unsafe_code = "deny"` at the workspace level rules out
// `std::env::set_var` in tests (it is an `unsafe fn`; see the identical
// pattern in `services/sshca/src/config.rs` and `services/monitor/src/config.rs`),
// so the default-substitution/parsing *logic* has to be reachable without
// touching process env at all. Only the outermost `from_env` (thin glue,
// intentionally left uncovered — same as the other two services) actually
// calls `std::env::var`.

/// Pure default-substitution: `v` if `Some` and non-empty, else `default`.
fn resolve_or(v: Option<&str>, default: &str) -> String {
    match v {
        Some(s) if !s.is_empty() => s.to_owned(),
        _ => default.to_owned(),
    }
}

/// Pure optional resolution: `Some` only when `v` is present and non-empty.
fn resolve_opt(v: Option<&str>) -> Option<String> {
    v.filter(|s| !s.is_empty()).map(str::to_owned)
}

/// Pure boolean parse, the v1 way: `str.lower() == "true"`.
fn resolve_bool(v: Option<&str>, default: bool) -> bool {
    match v {
        Some(s) if !s.is_empty() => s.eq_ignore_ascii_case("true"),
        _ => default,
    }
}

/// Pure numeric parse, falling back to `default` on absence/parse error.
fn resolve_num<T: std::str::FromStr>(v: Option<&str>, default: T) -> T {
    v.and_then(|s| s.parse().ok()).unwrap_or(default)
}

/// Resolves the required consumer name: `CONSUMER_NAME` then `WORKER_NAME`,
/// erroring when neither is set.
fn resolve_consumer_name(
    consumer_name: Option<&str>,
    worker_name: Option<&str>,
) -> Result<String, ConfigError> {
    resolve_opt(consumer_name)
        .or_else(|| resolve_opt(worker_name))
        .ok_or(ConfigError::MissingConsumerName)
}

/// Resolves the stream key prefix: `REDIS_KEY_PREFIX` (the manager's
/// authoritative var) wins, then the v1 worker's `REDIS_PREFIX`, else
/// `skauswatch`.
fn resolve_redis_prefix(redis_key_prefix: Option<&str>, redis_prefix: Option<&str>) -> String {
    resolve_opt(redis_key_prefix)
        .or_else(|| resolve_opt(redis_prefix))
        .unwrap_or_else(|| "skauswatch".to_owned())
}

/// Resolves the ad-hoc bucket: `S3_SCAN_ADHOC_BUCKET` then `S3_ADHOC_BUCKET`.
fn resolve_adhoc_bucket(primary: Option<&str>, legacy: Option<&str>) -> Option<String> {
    resolve_opt(primary).or_else(|| resolve_opt(legacy))
}

/// Reads an environment variable, returning `default` when unset or empty.
fn env_or(key: &str, default: &str) -> String {
    resolve_or(std::env::var(key).ok().as_deref(), default)
}

/// Reads an optional environment variable (`None` when unset or empty).
fn env_opt(key: &str) -> Option<String> {
    resolve_opt(std::env::var(key).ok().as_deref())
}

/// Parses a boolean env var the v1 way: `str.lower() == "true"`.
fn env_bool(key: &str, default: bool) -> bool {
    resolve_bool(std::env::var(key).ok().as_deref(), default)
}

/// Parses a numeric env var, falling back to `default` on absence/parse error.
fn env_num<T: std::str::FromStr>(key: &str, default: T) -> T {
    resolve_num(std::env::var(key).ok().as_deref(), default)
}

/// Runtime configuration for one worker instance.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Unique consumer name within the group (`CONSUMER_NAME`, then
    /// `WORKER_NAME`). Required — startup fails when neither is set.
    pub consumer_name: String,
    /// Redis/Valkey URL (`REDIS_URL`, default `redis://redis:6379/0`).
    pub redis_url: String,
    /// Optional Redis password (`REDIS_PASSWORD`) — injected like the manager.
    pub redis_password: Option<String>,
    /// Stream key prefix. `REDIS_KEY_PREFIX` (the manager's authoritative var)
    /// wins, then the v1 worker's `REDIS_PREFIX`, else `skauswatch`.
    pub redis_prefix: String,
    /// Consumer group (`CONSUMER_GROUP`, default `s3scan-workers`).
    pub consumer_group: String,
    /// Max in-flight tasks per read (`MAX_CONCURRENT_TASKS`, default 10) — the
    /// consumer batch size.
    pub max_concurrent_tasks: u64,
    /// Max object size scanned (`MAX_FILE_SIZE_MB`, default 100); larger
    /// objects are skipped.
    pub max_file_size_mb: u64,
    /// Per-scan timeout seconds (`SCAN_TIMEOUT_SEC`, default 120).
    pub scan_timeout_sec: u64,
    /// ClamAV daemon socket (`CLAMD_SOCKET`, default
    /// `/var/run/clamav/clamd.sock`). Scanning degrades to "clean" when the
    /// daemon is absent, matching v1.
    pub clamd_socket: String,
    /// ClamAV socket timeout seconds (`CLAMD_TIMEOUT`, default 60).
    pub clamd_timeout: u64,
    /// Threat-intel enrichment toggle (`TI_ENABLED`, default true). Enrichment
    /// no-ops without API keys.
    pub ti_enabled: bool,
    /// VirusTotal API key (`VIRUSTOTAL_API_KEY`).
    pub virustotal_api_key: Option<String>,
    /// AlienVault OTX API key (`OTX_API_KEY`).
    pub otx_api_key: Option<String>,
    /// YARA toggle (`YARA_ENABLED`, default false). Carried for parity; the
    /// engine lives in scanner (see the port notes), so s3scan does
    /// not run YARA.
    pub yara_enabled: bool,
    /// Health/readiness HTTP port (`HEALTH_PORT`, default 8080).
    pub health_port: u16,
    /// Optional MinIO/S3 endpoint for ad-hoc uploads (`S3_ENDPOINT_URL`).
    pub s3_endpoint_url: Option<String>,
    /// Region for the ad-hoc S3 client (`S3_REGION`, default us-east-1).
    pub s3_region: String,
    /// Path-style addressing for the ad-hoc S3 client (`S3_FORCE_PATH_STYLE`,
    /// default true — MinIO).
    pub s3_force_path_style: bool,
    /// Bucket holding ad-hoc uploads (`S3_SCAN_ADHOC_BUCKET`). Ad-hoc scanning
    /// is only possible when this is configured and the object exists.
    pub adhoc_bucket: Option<String>,
}

impl WorkerConfig {
    /// Loads the worker configuration from the environment.
    ///
    /// # Errors
    /// Returns an error when neither `CONSUMER_NAME` nor `WORKER_NAME` is set.
    pub fn from_env() -> Result<Self, ConfigError> {
        let consumer_name = resolve_consumer_name(
            std::env::var("CONSUMER_NAME").ok().as_deref(),
            std::env::var("WORKER_NAME").ok().as_deref(),
        )?;
        let redis_prefix = resolve_redis_prefix(
            std::env::var("REDIS_KEY_PREFIX").ok().as_deref(),
            std::env::var("REDIS_PREFIX").ok().as_deref(),
        );
        Ok(Self {
            consumer_name,
            redis_url: env_or("REDIS_URL", "redis://redis:6379/0"),
            redis_password: env_opt("REDIS_PASSWORD"),
            redis_prefix,
            consumer_group: env_or("CONSUMER_GROUP", "s3scan-workers"),
            max_concurrent_tasks: env_num("MAX_CONCURRENT_TASKS", 10),
            max_file_size_mb: env_num("MAX_FILE_SIZE_MB", 100),
            scan_timeout_sec: env_num("SCAN_TIMEOUT_SEC", 120),
            clamd_socket: env_or("CLAMD_SOCKET", "/var/run/clamav/clamd.sock"),
            clamd_timeout: env_num("CLAMD_TIMEOUT", 60),
            ti_enabled: env_bool("TI_ENABLED", true),
            virustotal_api_key: env_opt("VIRUSTOTAL_API_KEY"),
            otx_api_key: env_opt("OTX_API_KEY"),
            yara_enabled: env_bool("YARA_ENABLED", false),
            health_port: env_num("HEALTH_PORT", 8080),
            s3_endpoint_url: env_opt("S3_ENDPOINT_URL"),
            s3_region: env_or("S3_REGION", "us-east-1"),
            s3_force_path_style: env_bool("S3_FORCE_PATH_STYLE", true),
            adhoc_bucket: resolve_adhoc_bucket(
                std::env::var("S3_SCAN_ADHOC_BUCKET").ok().as_deref(),
                std::env::var("S3_ADHOC_BUCKET").ok().as_deref(),
            ),
        })
    }

    /// Max object size in bytes (`max_file_size_mb * 1024 * 1024`).
    pub fn max_file_size_bytes(&self) -> u64 {
        self.max_file_size_mb.saturating_mul(1024 * 1024)
    }
}

/// Errors raised while loading [`WorkerConfig`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// Neither `CONSUMER_NAME` nor `WORKER_NAME` was provided.
    #[error("CONSUMER_NAME (or WORKER_NAME) environment variable is required")]
    MissingConsumerName,
}

#[cfg(test)]
impl WorkerConfig {
    /// Fixed test configuration shared by `db.rs`/`s3ops.rs`/`clamav.rs`/
    /// `handler.rs` test modules — mirrors the `for_tests()` builder
    /// convention used for `AppState` elsewhere in the workspace (see
    /// `docs/v2-port/testing-pattern.md`). `clamd_socket` points at a path
    /// nothing listens on (ClamAV verdicts degrade to "clean" by default);
    /// individual tests override fields with struct-update syntax.
    pub(crate) fn for_tests() -> Self {
        Self {
            consumer_name: "test-worker".to_owned(),
            redis_url: "redis://127.0.0.1:6379/0".to_owned(),
            redis_password: None,
            redis_prefix: "test".to_owned(),
            consumer_group: "s3scan-workers".to_owned(),
            max_concurrent_tasks: 10,
            max_file_size_mb: 100,
            scan_timeout_sec: 5,
            clamd_socket: "/nonexistent/clamd-test.sock".to_owned(),
            clamd_timeout: 2,
            ti_enabled: false,
            virustotal_api_key: None,
            otx_api_key: None,
            yara_enabled: false,
            health_port: 0,
            s3_endpoint_url: None,
            s3_region: "us-east-1".to_owned(),
            s3_force_path_style: true,
            adhoc_bucket: None,
        }
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn resolve_or_prefers_present_non_empty_value() {
        assert_eq!(resolve_or(Some("x"), "default"), "x");
        assert_eq!(resolve_or(Some(""), "default"), "default");
        assert_eq!(resolve_or(None, "default"), "default");
    }

    #[test]
    fn resolve_opt_filters_empty_string() {
        assert_eq!(resolve_opt(Some("x")), Some("x".to_owned()));
        assert_eq!(resolve_opt(Some("")), None);
        assert_eq!(resolve_opt(None), None);
    }

    #[test]
    fn resolve_bool_matches_python_str_lower_semantics() {
        assert!(resolve_bool(Some("true"), false));
        assert!(resolve_bool(Some("True"), false));
        assert!(resolve_bool(Some("TRUE"), false));
        assert!(!resolve_bool(Some("false"), true));
        assert!(!resolve_bool(Some("yes"), true)); // v1 only accepts "true"
        assert!(resolve_bool(None, true));
        // Empty is treated as absent — falls back to the default either way.
        assert!(resolve_bool(Some(""), true));
        assert!(!resolve_bool(Some(""), false));
    }

    #[test]
    fn resolve_num_parses_or_falls_back() {
        assert_eq!(resolve_num::<u64>(Some("42"), 7), 42);
        assert_eq!(resolve_num::<u64>(Some("not-a-number"), 7), 7);
        assert_eq!(resolve_num::<u64>(None, 7), 7);
    }

    #[test]
    fn consumer_name_prefers_consumer_name_over_worker_name() {
        assert_eq!(
            resolve_consumer_name(Some("primary"), Some("legacy")),
            Ok("primary".to_owned())
        );
        assert_eq!(
            resolve_consumer_name(None, Some("legacy")),
            Ok("legacy".to_owned())
        );
        assert_eq!(resolve_consumer_name(Some(""), Some("legacy")), {
            // Empty CONSUMER_NAME falls through to WORKER_NAME.
            Ok("legacy".to_owned())
        });
    }

    #[test]
    fn consumer_name_errors_when_neither_set() {
        assert_eq!(
            resolve_consumer_name(None, None),
            Err(ConfigError::MissingConsumerName)
        );
        assert_eq!(
            resolve_consumer_name(Some(""), Some("")),
            Err(ConfigError::MissingConsumerName)
        );
    }

    #[test]
    fn redis_prefix_precedence_and_default() {
        assert_eq!(
            resolve_redis_prefix(Some("mgr-prefix"), Some("legacy-prefix")),
            "mgr-prefix"
        );
        assert_eq!(
            resolve_redis_prefix(None, Some("legacy-prefix")),
            "legacy-prefix"
        );
        assert_eq!(resolve_redis_prefix(None, None), "skauswatch");
    }

    #[test]
    fn adhoc_bucket_precedence() {
        assert_eq!(
            resolve_adhoc_bucket(Some("primary-bkt"), Some("legacy-bkt")),
            Some("primary-bkt".to_owned())
        );
        assert_eq!(
            resolve_adhoc_bucket(None, Some("legacy-bkt")),
            Some("legacy-bkt".to_owned())
        );
        assert_eq!(resolve_adhoc_bucket(None, None), None);
    }

    #[test]
    fn max_file_size_bytes_converts_mb_to_bytes() {
        let mut cfg = WorkerConfig::for_tests();
        cfg.max_file_size_mb = 2;
        assert_eq!(cfg.max_file_size_bytes(), 2 * 1024 * 1024);
    }

    #[test]
    fn max_file_size_bytes_saturates_instead_of_overflowing() {
        let mut cfg = WorkerConfig::for_tests();
        cfg.max_file_size_mb = u64::MAX;
        assert_eq!(cfg.max_file_size_bytes(), u64::MAX);
    }

    #[test]
    fn config_error_message() {
        assert_eq!(
            ConfigError::MissingConsumerName.to_string(),
            "CONSUMER_NAME (or WORKER_NAME) environment variable is required"
        );
    }
}
