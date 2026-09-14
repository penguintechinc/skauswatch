//! Agent configuration — struct shapes and defaults mirror the v1 viper YAML
//! file (`config/endpoint-agent.yaml`) field-for-field so existing deployments'
//! config files keep parsing unchanged.
//!
//! v1's Go binary only ever read a handful of these fields at runtime
//! (`manager_url`, `api_key`, `agent_id`, `heartbeat_interval`,
//! `event_buffer_size`, `debug`, `collectors.{process,file,network}.enabled`)
//! — the rest of the YAML (per-collector poll intervals, watch lists,
//! `tls`, `logging`) was accepted by viper but never wired to any behavior.
//! This port wires those fields up for real (poll intervals, watch paths,
//! TLS transport, structured logging), always ADDITIVELY relative to v1's
//! hardcoded detection sets (suspicious process names / ports) so a
//! deployment's config can only ever widen detection coverage, never
//! silently narrow it. See `collectors::process`/`collectors::network` for
//! the union logic.

use std::path::Path;
use std::time::Duration;

use figment::Figment;
use figment::providers::{Env, Format, Serialized, Yaml};
use serde::{Deserialize, Serialize};

use skauswatch_common::Error;

/// Per-host config file search path when `--config` is absent — matches v1
/// viper's `AddConfigPath("/etc/skauswatch")` + config name `endpoint-agent`.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/skauswatch/endpoint-agent.yaml";
/// Fallback search path — v1 viper's `AddConfigPath(".")`.
pub const LOCAL_CONFIG_PATH: &str = "endpoint-agent.yaml";
/// Env var prefix — v1 `viper.SetEnvPrefix("ENDPOINT")` + `AutomaticEnv()`. Only
/// top-level flat keys are overridable this way, matching v1's actual
/// behavior: viper never registered a `.`-to-`_` key replacer, so
/// `AutomaticEnv` could never resolve nested keys like
/// `collectors.process.enabled` to an env var in practice.
pub const ENV_PREFIX: &str = "ENDPOINT_";

/// Top-level agent configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// Base URL of the SkausWatch manager (e.g. `https://manager:5000`).
    pub manager_url: String,
    /// Shared HMAC secret (manager env `ENDPOINT_API_SECRET`) used to compute the
    /// per-request `X-API-Key` header — see `crate::transport`. NEVER log
    /// this value.
    pub api_key: String,
    /// Stable agent identifier; auto-generated from hostname/pid/time if
    /// empty (see `crate::agent::finalize_agent_id`).
    pub agent_id: String,
    /// Per-tenant EDR enrollment token
    /// (`docs/v2-port/service-auth-model.md` §5), minted by a super-admin
    /// via `POST /tenants/{tenant_id}/enrollment-tokens` on the manager and
    /// baked into (or prompted into) this agent's install. Required only
    /// the first time a given `agent_id` registers — the manager resolves
    /// this agent's tenant from the token instead of a default; an
    /// already-registered agent re-registering can leave this empty, since
    /// the manager keeps its stored tenant unchanged either way. NEVER log
    /// this value.
    pub enrollment_token: String,
    /// Heartbeat interval in seconds.
    pub heartbeat_interval: u64,
    /// Capacity of the internal event channel before new events are dropped.
    pub event_buffer_size: usize,
    /// Enables debug-level logging (overrides `logging.level`).
    pub debug: bool,
    /// Per-signal collector settings.
    pub collectors: CollectorsConfig,
    /// TLS transport settings for the manager connection.
    pub tls: TlsConfig,
    /// Structured logging settings.
    pub logging: LoggingConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            manager_url: "https://manager:5000".to_owned(),
            api_key: String::new(),
            agent_id: String::new(),
            enrollment_token: String::new(),
            heartbeat_interval: 60,
            event_buffer_size: 1000,
            debug: false,
            collectors: CollectorsConfig::default(),
            tls: TlsConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Per-signal collector settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CollectorsConfig {
    /// Process creation/termination monitoring.
    pub process: ProcessCollectorConfig,
    /// File integrity monitoring (SHA-256 baseline + diff).
    pub file: FileCollectorConfig,
    /// Network connection monitoring.
    pub network: NetworkCollectorConfig,
    /// Windows registry monitoring (shape-only — see struct docs).
    pub registry: RegistryCollectorConfig,
}

/// Process creation/termination collector settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProcessCollectorConfig {
    /// Whether the process collector runs at all.
    pub enabled: bool,
    /// Go-style duration string (`"1s"`, `"500ms"`) — see `parse_duration`.
    pub poll_interval: String,
    /// Process names to never emit events for (case-insensitive). v1's own
    /// process name ("endpoint-agent") was listed here but never actually
    /// excluded — a self-monitoring noise bug this port fixes.
    pub exclude: Vec<String>,
    /// Additional names to treat as high severity, UNION'd with the
    /// built-in list in `collectors::process::BUILTIN_SUSPICIOUS_NAMES`.
    pub watch: Vec<String>,
}

impl Default for ProcessCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval: "1s".to_owned(),
            exclude: vec![
                "endpoint-agent".to_owned(),
                "systemd".to_owned(),
                "init".to_owned(),
            ],
            watch: vec![
                "powershell".to_owned(),
                "cmd".to_owned(),
                "bash".to_owned(),
                "nc".to_owned(),
                "netcat".to_owned(),
                "nmap".to_owned(),
            ],
        }
    }
}

impl ProcessCollectorConfig {
    /// Parsed poll interval, falling back to v1's hardcoded 1s on a
    /// malformed value (logged by the caller).
    pub fn poll_duration(&self) -> Duration {
        parse_duration(&self.poll_interval).unwrap_or(Duration::from_secs(1))
    }
}

/// File integrity collector settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FileCollectorConfig {
    /// Whether the file collector runs at all.
    pub enabled: bool,
    /// Go-style duration string (`"30s"`) — see `parse_duration`.
    pub poll_interval: String,
    /// Directories walked recursively on every poll.
    pub watch_paths: Vec<String>,
    /// Extensions UNION'd with the built-in high-severity extension set.
    pub priority_extensions: Vec<String>,
    /// Files larger than this are skipped entirely (never hashed or
    /// reported) — matches v1's hardcoded 10MB performance guard.
    pub max_hash_size: u64,
}

impl Default for FileCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval: "30s".to_owned(),
            watch_paths: default_watch_paths(),
            priority_extensions: vec![
                ".sh".to_owned(),
                ".py".to_owned(),
                ".exe".to_owned(),
                ".dll".to_owned(),
                ".so".to_owned(),
            ],
            max_hash_size: 10 * 1024 * 1024,
        }
    }
}

impl FileCollectorConfig {
    /// Parsed poll interval, falling back to v1's hardcoded 30s on a
    /// malformed value.
    pub fn poll_duration(&self) -> Duration {
        parse_duration(&self.poll_interval).unwrap_or(Duration::from_secs(30))
    }
}

/// v1 picked watch paths at runtime via a `os.Stat("C:\Windows")` probe,
/// which is equivalent (for a binary compiled for one OS) to a compile-time
/// `cfg(windows)` switch.
#[cfg(windows)]
fn default_watch_paths() -> Vec<String> {
    vec![
        "C:\\Windows\\System32".to_owned(),
        "C:\\Windows\\SysWOW64".to_owned(),
        "C:\\Users".to_owned(),
    ]
}

#[cfg(not(windows))]
fn default_watch_paths() -> Vec<String> {
    vec![
        "/etc".to_owned(),
        "/usr/bin".to_owned(),
        "/usr/sbin".to_owned(),
        "/var/log".to_owned(),
    ]
}

/// Network connection collector settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkCollectorConfig {
    /// Whether the network collector runs at all.
    pub enabled: bool,
    /// Go-style duration string (`"5s"`) — see `parse_duration`.
    pub poll_interval: String,
    /// When `true`, only report ESTABLISHED connections; when `false`
    /// (default, matching v1's hardcoded behavior), also report LISTEN.
    pub established_only: bool,
    /// Ports UNION'd with the built-in list in
    /// `collectors::network::BUILTIN_SUSPICIOUS_PORTS` — config can only
    /// ADD suspicious ports, never remove the built-in floor.
    pub suspicious_ports: Vec<u16>,
    /// CIDR ranges UNION'd with the built-in private/loopback/link-local
    /// ranges when deciding whether a remote address is "external".
    pub trusted_ranges: Vec<String>,
}

impl Default for NetworkCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            poll_interval: "5s".to_owned(),
            established_only: false,
            suspicious_ports: vec![4444, 5555, 6666, 31337],
            trusted_ranges: vec![
                "10.0.0.0/8".to_owned(),
                "172.16.0.0/12".to_owned(),
                "192.168.0.0/16".to_owned(),
            ],
        }
    }
}

impl NetworkCollectorConfig {
    /// Parsed poll interval, falling back to v1's hardcoded 5s on a
    /// malformed value.
    pub fn poll_duration(&self) -> Duration {
        parse_duration(&self.poll_interval).unwrap_or(Duration::from_secs(5))
    }
}

/// Windows registry monitoring — config shape preserved for backward
/// compatibility, but (matching v1, which never implemented a registry
/// collector despite this toggle existing) no collector runs for it. Honest
/// deferral: real registry-key-change monitoring is Windows-only, requires
/// the `winreg`/ETW APIs, and is out of scope for this port.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RegistryCollectorConfig {
    /// Whether the registry collector would run — always inert (see struct
    /// docs); accepted only for config-shape backward compatibility.
    pub enabled: bool,
    /// Go-style duration string (`"10s"`) — unused, shape-only.
    pub poll_interval: String,
    /// Registry keys that would be watched — unused, shape-only.
    pub watch_keys: Vec<String>,
}

impl Default for RegistryCollectorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            poll_interval: "10s".to_owned(),
            watch_keys: vec![
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_owned(),
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run".to_owned(),
                "HKLM\\SYSTEM\\CurrentControlSet\\Services".to_owned(),
            ],
        }
    }
}

/// TLS transport settings for the connection to the manager. v1 declared
/// this block in YAML but never implemented it (the Go reporter always used
/// a plain `http.Client`); this port wires it up for real since the
/// manager connection is the agent's sole network egress and security.md
/// requires TLS 1.2+ / rustls on external endpoints. Opt-in
/// (`enabled: false` default) so existing deployments are unaffected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TlsConfig {
    /// Enables custom TLS settings for the manager connection.
    pub enabled: bool,
    /// Path to a PEM client certificate for mTLS.
    pub cert_file: String,
    /// Path to the PEM private key matching `cert_file`.
    pub key_file: String,
    /// Path to a PEM CA bundle to trust in addition to the system roots.
    pub ca_file: String,
    /// Disables certificate validation — dangerous, dev-only; a loud
    /// warning is logged whenever this is set.
    pub skip_verify: bool,
}

/// Structured logging settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    /// `"debug"`/`"info"`/`"warn"`/`"error"` — overridden to `"debug"` when
    /// the top-level `debug` flag is set.
    pub level: String,
    /// `"json"` (default) or anything else for plain-text output.
    pub format: String,
    /// `"stdout"` or `"stderr"`; other values fall back to stdout with a
    /// startup warning (see `main::init_tracing`).
    pub output: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_owned(),
            format: "json".to_owned(),
            output: "stdout".to_owned(),
        }
    }
}

/// Parses a Go `time.Duration`-style string (`"1s"`, `"500ms"`, `"5m"`,
/// `"1h"`) — the subset of units v1's YAML actually uses.
pub fn parse_duration(raw: &str) -> Option<Duration> {
    let s = raw.trim();
    let split_at = s.find(|c: char| !c.is_ascii_digit() && c != '.')?;
    let (num, unit) = s.split_at(split_at);
    let value: f64 = num.parse().ok()?;
    if value < 0.0 || !value.is_finite() {
        return None;
    }
    let secs = match unit {
        "ms" => value / 1000.0,
        "s" => value,
        "m" => value * 60.0,
        "h" => value * 3600.0,
        _ => return None,
    };
    Some(Duration::from_secs_f64(secs))
}

/// CLI overrides applied on top of file/env config — mirrors the four
/// flags v1 bound via `viper.BindPFlag` (`manager-url`, `api-key`,
/// `agent-id`, `debug`); nested collector settings have no CLI flag in v1
/// either.
#[derive(Debug, Clone, Default)]
pub struct CliOverrides {
    /// `--manager-url`, if passed.
    pub manager_url: Option<String>,
    /// `--api-key`, if passed.
    pub api_key: Option<String>,
    /// `--agent-id`, if passed.
    pub agent_id: Option<String>,
    /// `--debug`, if passed.
    pub debug: Option<bool>,
}

/// Loads the agent config with v1 viper's precedence, highest first: CLI
/// flag (if passed), env var (`ENDPOINT_*`), config file, built-in default.
/// `config_path` picks the file explicitly (`--config`); when absent, the
/// default and local search paths are tried in order and a missing file is
/// not an error (matches v1: "Config file not found is OK, use defaults").
pub fn load(config_path: Option<&Path>, cli: &CliOverrides) -> Result<AgentConfig, Error> {
    let mut figment = Figment::from(Serialized::defaults(AgentConfig::default()));

    let resolved_path = match config_path {
        Some(p) if p.is_file() => Some(p.to_path_buf()),
        Some(p) => {
            return Err(Error::Config(format!(
                "config file not found: {}",
                p.display()
            )));
        }
        None => [DEFAULT_CONFIG_PATH, LOCAL_CONFIG_PATH]
            .into_iter()
            .map(std::path::PathBuf::from)
            .find(|p| p.is_file()),
    };
    if let Some(path) = &resolved_path {
        figment = figment.merge(Yaml::file(path));
    }

    figment = figment.merge(Env::prefixed(ENV_PREFIX));

    let mut cfg: AgentConfig = figment
        .extract()
        .map_err(|e| Error::Config(format!("failed to load agent config: {e}")))?;

    if let Some(v) = &cli.manager_url {
        cfg.manager_url = v.clone();
    }
    if let Some(v) = &cli.api_key {
        cfg.api_key = v.clone();
    }
    if let Some(v) = &cli.agent_id {
        cfg.agent_id = v.clone();
    }
    if let Some(v) = cli.debug {
        cfg.debug = v;
    }

    Ok(cfg)
}

#[cfg(test)]
#[allow(clippy::result_large_err)] // figment::Jail closures return figment::Error by contract
mod tests {
    use super::*;
    use crate::test_support::must;

    #[test]
    fn defaults_match_v1_shipped_yaml() {
        let cfg = AgentConfig::default();
        assert_eq!(cfg.manager_url, "https://manager:5000");
        assert_eq!(cfg.heartbeat_interval, 60);
        assert_eq!(cfg.event_buffer_size, 1000);
        assert!(cfg.collectors.process.enabled);
        assert!(cfg.collectors.file.enabled);
        assert!(cfg.collectors.network.enabled);
        assert!(!cfg.collectors.registry.enabled);
        assert_eq!(cfg.collectors.file.max_hash_size, 10 * 1024 * 1024);
        assert!(!cfg.tls.enabled);
        assert_eq!(cfg.logging.level, "info");
    }

    #[test]
    fn parses_shipped_yaml_file_shape() {
        let yaml = include_str!("../config/endpoint-agent.yaml");
        let cfg: AgentConfig = must(serde_yaml::from_str(yaml), "shipped config must parse");
        assert_eq!(cfg.manager_url, "https://manager:5000");
        assert_eq!(
            cfg.collectors.network.suspicious_ports,
            vec![4444, 5555, 6666, 31337]
        );
        assert_eq!(
            cfg.collectors.registry.watch_keys[0],
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        );
    }

    #[test]
    fn duration_parsing_matches_viper_subset() {
        assert_eq!(parse_duration("1s"), Some(Duration::from_secs(1)));
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("bogus"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn env_overrides_top_level_keys_only() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("ENDPOINT_MANAGER_URL", "https://override:9999");
            jail.set_env("ENDPOINT_HEARTBEAT_INTERVAL", "15");
            jail.set_env("ENDPOINT_DEBUG", "true");
            let cfg = load(None, &CliOverrides::default()).map_err(|e| e.to_string())?;
            assert_eq!(cfg.manager_url, "https://override:9999");
            assert_eq!(cfg.heartbeat_interval, 15);
            assert!(cfg.debug);
            Ok(())
        });
    }

    #[test]
    fn cli_override_wins_over_env() {
        figment::Jail::expect_with(|jail| {
            jail.set_env("ENDPOINT_MANAGER_URL", "https://from-env:1");
            let cli = CliOverrides {
                manager_url: Some("https://from-cli:2".to_owned()),
                ..Default::default()
            };
            let cfg = load(None, &cli).map_err(|e| e.to_string())?;
            assert_eq!(cfg.manager_url, "https://from-cli:2");
            Ok(())
        });
    }

    #[test]
    fn missing_explicit_config_path_is_an_error() {
        let res = load(
            Some(Path::new("/nonexistent/endpoint-agent.yaml")),
            &CliOverrides::default(),
        );
        assert!(res.is_err());
    }
}
