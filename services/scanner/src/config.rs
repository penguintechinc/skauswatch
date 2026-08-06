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
    /// ASM (masscan/banner/cert pipeline) enabled (default true).
    pub asm_enabled: bool,
    /// `masscan` binary path/name (default `masscan`) — overridable so
    /// deployments can point at a wrapper, and so tests can substitute a
    /// fake executable (real masscan needs `NET_RAW`/root, unavailable in
    /// CI — see `crate::asm` module docs).
    pub masscan_bin: String,
    /// Timeout for the whole `masscan` invocation, in seconds (default 60).
    pub asm_masscan_timeout_sec: u64,
    /// Per-port banner-grab timeout, in seconds (default 3).
    pub asm_banner_timeout_sec: u64,
    /// Per-port TLS certificate fetch timeout, in seconds (default 5).
    pub asm_cert_timeout_sec: u64,
    /// ASM screenshot capture stage enabled (default true) — kept separate
    /// from `asm_enabled` so operators can run masscan/banner/cert without
    /// the headless-chromium binary if it isn't provisioned in their image
    /// yet (see `crate::asm` module docs on the container requirement).
    pub asm_screenshot_enabled: bool,
    /// `chromium` binary path/name for headless screenshot capture (default
    /// `chromium`) — overridable so deployments can point at a wrapper, and
    /// so tests can substitute a fake executable.
    pub chromium_bin: String,
    /// Timeout for one screenshot capture (chromium spawn + navigate +
    /// render), in seconds (default 15).
    pub asm_screenshot_timeout_sec: u64,
    /// Screenshot viewport width in pixels (default 1280).
    pub asm_screenshot_window_width: u32,
    /// Screenshot viewport height in pixels (default 800).
    pub asm_screenshot_window_height: u32,
    /// S3/MinIO bucket screenshots upload to (`S3_*` env vars configure the
    /// endpoint/region via `skauswatch_s3::S3Config`). When
    /// `asm_screenshot_enabled` is true but this is unset, the screenshot
    /// stage is disabled with a startup warning rather than failing the
    /// worker — see `crate::asm` module docs.
    pub asm_screenshot_bucket: Option<String>,
}

impl WorkerConfig {
    /// Pure constructor taking pre-resolved env values — the unit-testable
    /// core (no process env access; `unsafe_code = "deny"` at the workspace
    /// level rules out `std::env::set_var` in tests). `consumer_name`
    /// defaults to a freshly generated UUID-suffixed name when `None`, same
    /// as [`Self::from_env`].
    #[allow(clippy::too_many_arguments)]
    fn from_values(
        health_port: Option<&str>,
        redis_url: Option<&str>,
        redis_password: Option<&str>,
        redis_prefix: Option<&str>,
        consumer_group: Option<&str>,
        consumer_name: Option<&str>,
        max_concurrent_tasks: Option<&str>,
        clamav_host: Option<&str>,
        clamav_port: Option<&str>,
        clamav_timeout_sec: Option<&str>,
        clamav_enabled: Option<&str>,
        yara_rules_path: Option<&str>,
        yara_enabled: Option<&str>,
        asm_enabled: Option<&str>,
        masscan_bin: Option<&str>,
        asm_masscan_timeout_sec: Option<&str>,
        asm_banner_timeout_sec: Option<&str>,
        asm_cert_timeout_sec: Option<&str>,
        asm_screenshot_enabled: Option<&str>,
        chromium_bin: Option<&str>,
        asm_screenshot_timeout_sec: Option<&str>,
        asm_screenshot_window_width: Option<&str>,
        asm_screenshot_window_height: Option<&str>,
        asm_screenshot_bucket: Option<&str>,
    ) -> Self {
        Self {
            health_port: health_port.and_then(|v| v.parse().ok()).unwrap_or(8080),
            redis_url: redis_url.unwrap_or("redis://redis:6379").to_string(),
            redis_password: redis_password.map(str::to_string),
            redis_prefix: redis_prefix.unwrap_or("skauswatch").to_string(),
            consumer_group: consumer_group.unwrap_or("scanner-workers").to_string(),
            consumer_name: consumer_name
                .map(str::to_string)
                .unwrap_or_else(|| format!("scanner-{}", uuid::Uuid::new_v4())),
            max_concurrent_tasks: max_concurrent_tasks
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            clamav_host: clamav_host.unwrap_or("clamav").to_string(),
            clamav_port: clamav_port.and_then(|v| v.parse().ok()).unwrap_or(3310),
            clamav_timeout_sec: clamav_timeout_sec
                .and_then(|v| v.parse().ok())
                .unwrap_or(30),
            clamav_enabled: clamav_enabled
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(true),
            yara_rules_path: yara_rules_path.unwrap_or("/etc/yara/rules").to_string(),
            yara_enabled: yara_enabled
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(true),
            asm_enabled: asm_enabled
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(true),
            masscan_bin: masscan_bin.unwrap_or("masscan").to_string(),
            asm_masscan_timeout_sec: asm_masscan_timeout_sec
                .and_then(|v| v.parse().ok())
                .unwrap_or(60),
            asm_banner_timeout_sec: asm_banner_timeout_sec
                .and_then(|v| v.parse().ok())
                .unwrap_or(3),
            asm_cert_timeout_sec: asm_cert_timeout_sec
                .and_then(|v| v.parse().ok())
                .unwrap_or(5),
            asm_screenshot_enabled: asm_screenshot_enabled
                .map(|v| v.to_lowercase() != "false")
                .unwrap_or(true),
            chromium_bin: chromium_bin.unwrap_or("chromium").to_string(),
            asm_screenshot_timeout_sec: asm_screenshot_timeout_sec
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
            asm_screenshot_window_width: asm_screenshot_window_width
                .and_then(|v| v.parse().ok())
                .unwrap_or(1280),
            asm_screenshot_window_height: asm_screenshot_window_height
                .and_then(|v| v.parse().ok())
                .unwrap_or(800),
            asm_screenshot_bucket: asm_screenshot_bucket.map(str::to_string),
        }
    }

    /// Loads configuration from environment variables.
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self::from_values(
            env::var("HEALTH_PORT").ok().as_deref(),
            env::var("REDIS_URL").ok().as_deref(),
            env::var("REDIS_PASSWORD").ok().as_deref(),
            env::var("REDIS_KEY_PREFIX").ok().as_deref(),
            env::var("CONSUMER_GROUP").ok().as_deref(),
            env::var("CONSUMER_NAME").ok().as_deref(),
            env::var("MAX_CONCURRENT_TASKS").ok().as_deref(),
            env::var("CLAMAV_HOST").ok().as_deref(),
            env::var("CLAMAV_PORT").ok().as_deref(),
            env::var("CLAMAV_TIMEOUT_SEC").ok().as_deref(),
            env::var("CLAMAV_ENABLED").ok().as_deref(),
            env::var("YARA_RULES_PATH").ok().as_deref(),
            env::var("YARA_ENABLED").ok().as_deref(),
            env::var("ASM_ENABLED").ok().as_deref(),
            env::var("MASSCAN_BIN").ok().as_deref(),
            env::var("ASM_MASSCAN_TIMEOUT_SEC").ok().as_deref(),
            env::var("ASM_BANNER_TIMEOUT_SEC").ok().as_deref(),
            env::var("ASM_CERT_TIMEOUT_SEC").ok().as_deref(),
            env::var("ASM_SCREENSHOT_ENABLED").ok().as_deref(),
            env::var("CHROMIUM_BIN").ok().as_deref(),
            env::var("ASM_SCREENSHOT_TIMEOUT_SEC").ok().as_deref(),
            env::var("ASM_SCREENSHOT_WINDOW_WIDTH").ok().as_deref(),
            env::var("ASM_SCREENSHOT_WINDOW_HEIGHT").ok().as_deref(),
            env::var("ASM_SCREENSHOT_BUCKET").ok().as_deref(),
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    fn defaults() -> WorkerConfig {
        WorkerConfig::from_values(
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None,
        )
    }

    #[test]
    fn defaults_match_documented_values_when_unset() {
        let cfg = defaults();
        assert_eq!(cfg.health_port, 8080);
        assert_eq!(cfg.redis_url, "redis://redis:6379");
        assert_eq!(cfg.redis_password, None);
        assert_eq!(cfg.redis_prefix, "skauswatch");
        assert_eq!(cfg.consumer_group, "scanner-workers");
        assert!(cfg.consumer_name.starts_with("scanner-"));
        assert_eq!(cfg.max_concurrent_tasks, 5);
        assert_eq!(cfg.clamav_host, "clamav");
        assert_eq!(cfg.clamav_port, 3310);
        assert_eq!(cfg.clamav_timeout_sec, 30);
        assert!(cfg.clamav_enabled);
        assert_eq!(cfg.yara_rules_path, "/etc/yara/rules");
        assert!(cfg.yara_enabled);
        assert!(cfg.asm_enabled);
        assert_eq!(cfg.masscan_bin, "masscan");
        assert_eq!(cfg.asm_masscan_timeout_sec, 60);
        assert_eq!(cfg.asm_banner_timeout_sec, 3);
        assert_eq!(cfg.asm_cert_timeout_sec, 5);
        assert!(cfg.asm_screenshot_enabled);
        assert_eq!(cfg.chromium_bin, "chromium");
        assert_eq!(cfg.asm_screenshot_timeout_sec, 15);
        assert_eq!(cfg.asm_screenshot_window_width, 1280);
        assert_eq!(cfg.asm_screenshot_window_height, 800);
        assert_eq!(cfg.asm_screenshot_bucket, None);
    }

    #[test]
    fn consumer_name_defaults_are_unique_per_call() {
        // No caller-supplied name ⇒ a fresh UUID-suffixed name every time,
        // so two workers never collide on the same consumer identity.
        assert_ne!(defaults().consumer_name, defaults().consumer_name);
    }

    #[test]
    fn invalid_numeric_values_fall_back_to_defaults() {
        let cfg = WorkerConfig::from_values(
            Some("not-a-number"),
            None,
            None,
            None,
            None,
            None,
            Some("also-bad"),
            None,
            Some("nope"),
            Some("nope"),
            None,
            None,
            None,
            None,
            None,
            Some("nope"),
            Some("nope"),
            Some("nope"),
            None,
            None,
            Some("nope"),
            Some("nope"),
            Some("nope"),
            None,
        );
        assert_eq!(cfg.health_port, 8080);
        assert_eq!(cfg.max_concurrent_tasks, 5);
        assert_eq!(cfg.clamav_port, 3310);
        assert_eq!(cfg.clamav_timeout_sec, 30);
        assert_eq!(cfg.asm_masscan_timeout_sec, 60);
        assert_eq!(cfg.asm_banner_timeout_sec, 3);
        assert_eq!(cfg.asm_cert_timeout_sec, 5);
        assert_eq!(cfg.asm_screenshot_timeout_sec, 15);
        assert_eq!(cfg.asm_screenshot_window_width, 1280);
        assert_eq!(cfg.asm_screenshot_window_height, 800);
    }

    #[test]
    fn overrides_are_honored() {
        let cfg = WorkerConfig::from_values(
            Some("9090"),
            Some("redis://valkey:6380/1"),
            Some("s3cr3t"),
            Some("custom-prefix"),
            Some("custom-group"),
            Some("custom-consumer"),
            Some("20"),
            Some("clamd.internal"),
            Some("3311"),
            Some("45"),
            Some("false"),
            Some("/opt/rules"),
            Some("false"),
            Some("false"),
            Some("/opt/bin/masscan"),
            Some("120"),
            Some("7"),
            Some("11"),
            Some("false"),
            Some("/opt/bin/chromium"),
            Some("30"),
            Some("1920"),
            Some("1080"),
            Some("asm-screenshots"),
        );
        assert_eq!(cfg.health_port, 9090);
        assert_eq!(cfg.redis_url, "redis://valkey:6380/1");
        assert_eq!(cfg.redis_password, Some("s3cr3t".to_owned()));
        assert_eq!(cfg.redis_prefix, "custom-prefix");
        assert_eq!(cfg.consumer_group, "custom-group");
        assert_eq!(cfg.consumer_name, "custom-consumer");
        assert_eq!(cfg.max_concurrent_tasks, 20);
        assert_eq!(cfg.clamav_host, "clamd.internal");
        assert_eq!(cfg.clamav_port, 3311);
        assert_eq!(cfg.clamav_timeout_sec, 45);
        assert!(!cfg.clamav_enabled);
        assert_eq!(cfg.yara_rules_path, "/opt/rules");
        assert!(!cfg.yara_enabled);
        assert!(!cfg.asm_enabled);
        assert_eq!(cfg.masscan_bin, "/opt/bin/masscan");
        assert_eq!(cfg.asm_masscan_timeout_sec, 120);
        assert_eq!(cfg.asm_banner_timeout_sec, 7);
        assert_eq!(cfg.asm_cert_timeout_sec, 11);
        assert!(!cfg.asm_screenshot_enabled);
        assert_eq!(cfg.chromium_bin, "/opt/bin/chromium");
        assert_eq!(cfg.asm_screenshot_timeout_sec, 30);
        assert_eq!(cfg.asm_screenshot_window_width, 1920);
        assert_eq!(cfg.asm_screenshot_window_height, 1080);
        assert_eq!(
            cfg.asm_screenshot_bucket,
            Some("asm-screenshots".to_owned())
        );
    }

    #[test]
    fn bool_flags_are_case_insensitive_and_only_literal_false_disables() {
        let cfg = WorkerConfig::from_values(
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
            Some("FALSE"),
            None,
            Some("False"),
            Some("anything-else-is-truthy"),
            None,
            None,
            None,
            None,
            Some("FALSE"),
            None,
            None,
            None,
            None,
            None,
        );
        assert!(!cfg.clamav_enabled);
        assert!(!cfg.yara_enabled);
        assert!(cfg.asm_enabled);
        assert!(!cfg.asm_screenshot_enabled);
    }

    #[test]
    fn from_env_reads_process_environment_without_panicking() {
        // Smoke-tests the from_env → from_values wiring itself; does not
        // assert specific values since other tests in the binary may set
        // process env vars concurrently (parallel test execution).
        let cfg = WorkerConfig::from_env().expect("from_env never fails");
        assert!(cfg.health_port > 0);
    }
}
