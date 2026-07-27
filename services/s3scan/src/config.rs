//! Worker configuration loaded from the environment, preserving the v1
//! `s3scan` variable names and defaults (`CONSUMER_NAME`, `REDIS_URL`,
//! `CONSUMER_GROUP`, `MAX_*`, `CLAMD_*`, `TI_*`, …). Database settings reuse
//! the shared `skauswatch-db` `DB_*` loader so the worker and manager agree on
//! the connection contract.

/// Reads an environment variable, returning `default` when unset or empty.
fn env_or(key: &str, default: &str) -> String {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v,
        _ => default.to_owned(),
    }
}

/// Reads an optional environment variable (`None` when unset or empty).
fn env_opt(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Some(v),
        _ => None,
    }
}

/// Parses a boolean env var the v1 way: `str.lower() == "true"`.
fn env_bool(key: &str, default: bool) -> bool {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v.eq_ignore_ascii_case("true"),
        _ => default,
    }
}

/// Parses a numeric env var, falling back to `default` on absence/parse error.
fn env_num<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
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
        let consumer_name = env_opt("CONSUMER_NAME")
            .or_else(|| env_opt("WORKER_NAME"))
            .ok_or(ConfigError::MissingConsumerName)?;
        let redis_prefix = env_opt("REDIS_KEY_PREFIX")
            .or_else(|| env_opt("REDIS_PREFIX"))
            .unwrap_or_else(|| "skauswatch".to_owned());
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
            adhoc_bucket: env_opt("S3_SCAN_ADHOC_BUCKET").or_else(|| env_opt("S3_ADHOC_BUCKET")),
        })
    }

    /// Max object size in bytes (`max_file_size_mb * 1024 * 1024`).
    pub fn max_file_size_bytes(&self) -> u64 {
        self.max_file_size_mb.saturating_mul(1024 * 1024)
    }
}

/// Errors raised while loading [`WorkerConfig`].
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Neither `CONSUMER_NAME` nor `WORKER_NAME` was provided.
    #[error("CONSUMER_NAME (or WORKER_NAME) environment variable is required")]
    MissingConsumerName,
}
