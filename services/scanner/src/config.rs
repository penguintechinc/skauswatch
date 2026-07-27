//! Worker configuration sourced from environment variables.

use std::env;

/// Scanner worker configuration.
#[derive(Clone, Debug)]
pub struct WorkerConfig {
    /// Health/metrics endpoint port (default 8080).
    pub health_port: u16,
    /// Redis URL (e.g., `redis://localhost:6379`).
    pub redis_url: String,
    /// Redis password (optional).
    pub redis_password: Option<String>,
    /// Redis key prefix (default `skauswatch`).
    pub redis_prefix: String,
    /// Consumer group name (default `scanner-workers`).
    pub consumer_group: String,
    /// Consumer name within group (default hostname or generated).
    pub consumer_name: String,
    /// Max concurrent tasks (default 5).
    pub max_concurrent_tasks: u64,
    /// ClamAV TCP host (default `clamav`).
    pub clamav_host: String,
    /// ClamAV TCP port (default 3310).
    pub clamav_port: u16,
    /// ClamAV scan timeout in seconds (default 30).
    pub clamav_timeout_sec: u64,
    /// ClamAV enabled (default true).
    pub clamav_enabled: bool,
    /// YARA rules directory (default `/etc/yara/rules`).
    pub yara_rules_path: String,
    /// YARA enabled (default true).
    pub yara_enabled: bool,
    /// ASM (Nuclei/ZAP/OpenVAS) enabled (default true).
    pub asm_enabled: bool,
}

impl WorkerConfig {
    /// Loads configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            health_port: env::var("HEALTH_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            redis_url: env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".to_string()),
            redis_password: env::var("REDIS_PASSWORD").ok(),
            redis_prefix: env::var("REDIS_KEY_PREFIX").unwrap_or_else(|_| "skauswatch".to_string()),
            consumer_group: env::var("CONSUMER_GROUP")
                .unwrap_or_else(|_| "scanner-workers".to_string()),
            consumer_name: env::var("CONSUMER_NAME")
                .unwrap_or_else(|_| format!("scanner-{}", uuid::Uuid::new_v4())),
            max_concurrent_tasks: env::var("MAX_CONCURRENT_TASKS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            clamav_host: env::var("CLAMAV_HOST").unwrap_or_else(|_| "clamav".to_string()),
            clamav_port: env::var("CLAMAV_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3310),
            clamav_timeout_sec: env::var("CLAMAV_TIMEOUT_SEC")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            clamav_enabled: env::var("CLAMAV_ENABLED")
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(true),
            yara_rules_path: env::var("YARA_RULES_PATH")
                .unwrap_or_else(|_| "/etc/yara/rules".to_string()),
            yara_enabled: env::var("YARA_ENABLED")
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(true),
            asm_enabled: env::var("ASM_ENABLED")
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(true),
        })
    }
}
