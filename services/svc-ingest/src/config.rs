//! Runtime configuration for `skauswatch-svc-ingest`, mirroring
//! `services/logs/src/config.rs`'s `from_env()`/`from_values()`/
//! `ConfigError` pattern for unit-testability. Values follow the port table
//! and NATS config block in `docs/v2-port/ingest-module-spec.md` §3b/§7a.

use std::net::IpAddr;
use std::time::Duration;

/// Default plain-HTTP OCSF/JSON ingest port (Spec §3b) — TLS is terminated
/// by the service mesh/ingress in front of this listener, not by the
/// process itself; see `listeners::http`'s module doc comment.
const DEFAULT_HTTP_PORT: u16 = 8443;
/// Default syslog UDP/TCP port — unprivileged; override + `NET_BIND_SERVICE`
/// for the standard privileged `:514` in production (Spec §3b).
const DEFAULT_SYSLOG_PORT: u16 = 5140;
/// Default syslog-over-TLS port (Spec §3b).
const DEFAULT_SYSLOG_TLS_PORT: u16 = 6514;
/// Default OTLP gRPC logs port (Spec §3b).
const DEFAULT_OTLP_GRPC_PORT: u16 = 4317;
/// Default OTLP HTTP logs port (Spec §3b).
const DEFAULT_OTLP_HTTP_PORT: u16 = 4318;
/// Default OpenSearch endpoint (parity with `services/logs`).
const DEFAULT_OPENSEARCH_URL: &str = "http://localhost:9200";
/// Default NATS server URL (Spec §7a).
const DEFAULT_NATS_URL: &str = "nats://localhost:4222";
/// Default JetStream subject prefix (Spec §7a example config block).
const DEFAULT_NATS_JETSTREAM_SUBJECT_PREFIX: &str = "svc-ingest.logs";
/// Default OpenSearch snapshot repository name (Spec §8a1
/// `SNAPSHOT_REPO_ENDPOINT` config note) — the WARM tier's searchable-snapshot
/// mount and the COLD tier's archival `snapshot`/`_restore` calls
/// (`crate::admin`, `crate::opensearch::ism`) all target this repository.
const DEFAULT_SNAPSHOT_REPO: &str = "skauswatch-snapshots";

/// Loaded configuration for `skauswatch-svc-ingest`.
#[derive(Debug, Clone)]
pub struct Config {
    /// Plain-HTTP OCSF/JSON ingest port (`HTTP_PORT`) — mesh/ingress
    /// terminates TLS in front of it (`listeners::http`'s module doc
    /// comment).
    pub http_port: u16,
    /// Syslog UDP/TCP port (`SYSLOG_PORT`).
    pub syslog_port: u16,
    /// Syslog-over-TLS port (`SYSLOG_TLS_PORT`).
    pub syslog_tls_port: u16,
    /// OTLP gRPC logs port (`OTLP_GRPC_PORT`).
    pub otlp_grpc_port: u16,
    /// OTLP HTTP logs port (`OTLP_HTTP_PORT`).
    pub otlp_http_port: u16,
    /// OpenSearch base URL (`OPENSEARCH_URL`).
    pub opensearch_url: String,
    /// NATS server URL (`NATS_URL`).
    pub nats_url: String,
    /// JetStream subject prefix (`NATS_JETSTREAM_SUBJECT_PREFIX`).
    pub nats_jetstream_subject_prefix: String,
    /// OpenSearch snapshot repository name (`SNAPSHOT_REPO`) — see
    /// [`DEFAULT_SNAPSHOT_REPO`].
    pub snapshot_repo: String,
    /// Whether the UDP syslog listener is enabled at all
    /// (`SYSLOG_UDP_ENABLED`) — OFF by default; UDP has no authentication,
    /// so enabling it is an explicit operator opt-in (Spec §6c).
    pub syslog_udp_enabled: bool,
    /// CIDR blocks trusted to send UDP syslog when `syslog_udp_enabled` is
    /// set (`SYSLOG_TRUSTED_CIDRS`, comma-separated). Empty by default.
    pub syslog_trusted_cidrs: Vec<CidrBlock>,
    /// The fixed tenant all trusted-CIDR UDP syslog packets are stamped
    /// with (`SYSLOG_UDP_TENANT_ID`) -- Spec §6c: "the operator must
    /// configure svc-ingest to assign a fixed tenant ID to all UDP packets
    /// from a given CIDR." `None` (unset, the default) means
    /// `crate::auth::resolve_via_udp_cidr` never stamps a tenant even from
    /// a trusted CIDR -- fail safe, never a silent/guessed default.
    pub syslog_udp_tenant_id: Option<String>,
}

/// A parsed CIDR block (`network/prefix_len`), used to validate
/// `SYSLOG_TRUSTED_CIDRS` entries without pulling in an extra crate for
/// what is a small, self-contained parse (see [`CidrBlock::parse`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrBlock {
    /// The network address portion (e.g. `10.0.0.0` in `10.0.0.0/8`).
    pub network: IpAddr,
    /// The prefix length in bits (0..=32 for IPv4, 0..=128 for IPv6).
    pub prefix_len: u8,
}

impl CidrBlock {
    /// Parses a single `network/prefix_len` entry. Returns
    /// [`ConfigError::Cidr`] (never panics) on any malformed input: missing
    /// `/`, an unparsable IP, an unparsable prefix length, or a prefix
    /// length exceeding the address family's bit width.
    fn parse(raw: &str) -> Result<Self, ConfigError> {
        let trimmed = raw.trim();
        let (ip_part, prefix_part) = trimmed
            .split_once('/')
            .ok_or_else(|| ConfigError::Cidr(trimmed.to_owned()))?;
        let network: IpAddr = ip_part
            .trim()
            .parse()
            .map_err(|_| ConfigError::Cidr(trimmed.to_owned()))?;
        let prefix_len: u8 = prefix_part
            .trim()
            .parse()
            .map_err(|_| ConfigError::Cidr(trimmed.to_owned()))?;
        let max_len = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix_len > max_len {
            return Err(ConfigError::Cidr(trimmed.to_owned()));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }

    /// Parses a comma-separated list of CIDR entries. An empty/blank input
    /// yields an empty list, not an error — `SYSLOG_TRUSTED_CIDRS` is
    /// legitimately unset when UDP syslog is disabled (the default).
    fn parse_list(raw: &str) -> Result<Vec<Self>, ConfigError> {
        raw.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(Self::parse)
            .collect()
    }
}

/// Raw string inputs mirroring the corresponding env vars, factored out so
/// parsing/validation is unit-testable without mutating process
/// environment state (see `services/logs/src/config.rs`'s
/// `from_env()`/`from_values()` split).
#[derive(Debug, Default, Clone, Copy)]
pub struct RawConfig<'a> {
    /// Raw `HTTP_PORT` value.
    pub http_port: Option<&'a str>,
    /// Raw `SYSLOG_PORT` value.
    pub syslog_port: Option<&'a str>,
    /// Raw `SYSLOG_TLS_PORT` value.
    pub syslog_tls_port: Option<&'a str>,
    /// Raw `OTLP_GRPC_PORT` value.
    pub otlp_grpc_port: Option<&'a str>,
    /// Raw `OTLP_HTTP_PORT` value.
    pub otlp_http_port: Option<&'a str>,
    /// Raw `OPENSEARCH_URL` value.
    pub opensearch_url: Option<&'a str>,
    /// Raw `NATS_URL` value.
    pub nats_url: Option<&'a str>,
    /// Raw `NATS_JETSTREAM_SUBJECT_PREFIX` value.
    pub nats_jetstream_subject_prefix: Option<&'a str>,
    /// Raw `SNAPSHOT_REPO` value.
    pub snapshot_repo: Option<&'a str>,
    /// Raw `SYSLOG_UDP_ENABLED` value.
    pub syslog_udp_enabled: Option<&'a str>,
    /// Raw `SYSLOG_TRUSTED_CIDRS` value.
    pub syslog_trusted_cidrs: Option<&'a str>,
    /// Raw `SYSLOG_UDP_TENANT_ID` value.
    pub syslog_udp_tenant_id: Option<&'a str>,
}

impl Config {
    /// Loads configuration from the environment.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when a port is not a valid `u16`,
    /// `SYSLOG_UDP_ENABLED` is not `true`/`false`, or any
    /// `SYSLOG_TRUSTED_CIDRS` entry is not a valid `network/prefix_len`
    /// CIDR block.
    pub fn from_env() -> Result<Self, ConfigError> {
        let http_port = std::env::var("HTTP_PORT").ok();
        let syslog_port = std::env::var("SYSLOG_PORT").ok();
        let syslog_tls_port = std::env::var("SYSLOG_TLS_PORT").ok();
        let otlp_grpc_port = std::env::var("OTLP_GRPC_PORT").ok();
        let otlp_http_port = std::env::var("OTLP_HTTP_PORT").ok();
        let opensearch_url = std::env::var("OPENSEARCH_URL").ok();
        let nats_url = std::env::var("NATS_URL").ok();
        let nats_jetstream_subject_prefix = std::env::var("NATS_JETSTREAM_SUBJECT_PREFIX").ok();
        let snapshot_repo = std::env::var("SNAPSHOT_REPO").ok();
        let syslog_udp_enabled = std::env::var("SYSLOG_UDP_ENABLED").ok();
        let syslog_trusted_cidrs = std::env::var("SYSLOG_TRUSTED_CIDRS").ok();
        let syslog_udp_tenant_id = std::env::var("SYSLOG_UDP_TENANT_ID").ok();

        Self::from_values(RawConfig {
            http_port: http_port.as_deref(),
            syslog_port: syslog_port.as_deref(),
            syslog_tls_port: syslog_tls_port.as_deref(),
            otlp_grpc_port: otlp_grpc_port.as_deref(),
            otlp_http_port: otlp_http_port.as_deref(),
            opensearch_url: opensearch_url.as_deref(),
            nats_url: nats_url.as_deref(),
            nats_jetstream_subject_prefix: nats_jetstream_subject_prefix.as_deref(),
            snapshot_repo: snapshot_repo.as_deref(),
            syslog_udp_enabled: syslog_udp_enabled.as_deref(),
            syslog_trusted_cidrs: syslog_trusted_cidrs.as_deref(),
            syslog_udp_tenant_id: syslog_udp_tenant_id.as_deref(),
        })
    }

    fn from_values(raw: RawConfig<'_>) -> Result<Self, ConfigError> {
        let http_port = parse_port(raw.http_port, "HTTP_PORT", DEFAULT_HTTP_PORT)?;
        let syslog_port = parse_port(raw.syslog_port, "SYSLOG_PORT", DEFAULT_SYSLOG_PORT)?;
        let syslog_tls_port = parse_port(
            raw.syslog_tls_port,
            "SYSLOG_TLS_PORT",
            DEFAULT_SYSLOG_TLS_PORT,
        )?;
        let otlp_grpc_port =
            parse_port(raw.otlp_grpc_port, "OTLP_GRPC_PORT", DEFAULT_OTLP_GRPC_PORT)?;
        let otlp_http_port =
            parse_port(raw.otlp_http_port, "OTLP_HTTP_PORT", DEFAULT_OTLP_HTTP_PORT)?;

        let opensearch_url = raw
            .opensearch_url
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_OPENSEARCH_URL)
            .to_owned();
        let nats_url = raw
            .nats_url
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_NATS_URL)
            .to_owned();
        let nats_jetstream_subject_prefix = raw
            .nats_jetstream_subject_prefix
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_NATS_JETSTREAM_SUBJECT_PREFIX)
            .to_owned();
        let snapshot_repo = raw
            .snapshot_repo
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_SNAPSHOT_REPO)
            .to_owned();

        let syslog_udp_enabled = match raw.syslog_udp_enabled.map(str::trim) {
            None | Some("") => false,
            Some(s) => match s.to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(ConfigError::Bool("SYSLOG_UDP_ENABLED")),
            },
        };

        let syslog_trusted_cidrs = match raw.syslog_trusted_cidrs.filter(|s| !s.is_empty()) {
            None => Vec::new(),
            Some(s) => CidrBlock::parse_list(s)?,
        };
        let syslog_udp_tenant_id = raw
            .syslog_udp_tenant_id
            .filter(|s| !s.is_empty())
            .map(str::to_owned);

        Ok(Self {
            http_port,
            syslog_port,
            syslog_tls_port,
            otlp_grpc_port,
            otlp_http_port,
            opensearch_url,
            nats_url,
            nats_jetstream_subject_prefix,
            snapshot_repo,
            syslog_udp_enabled,
            syslog_trusted_cidrs,
            syslog_udp_tenant_id,
        })
    }
}

/// Parses an optional port string, falling back to `default` when unset or
/// empty. Never panics: an unparsable value is a [`ConfigError::Int`].
fn parse_port(raw: Option<&str>, name: &'static str, default: u16) -> Result<u16, ConfigError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(default),
        Some(s) => s.parse::<u16>().map_err(|_| ConfigError::Int(name)),
    }
}

/// Errors raised while loading [`Config`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    /// A port env var was not a valid `u16`.
    #[error("{0} must be a valid port number")]
    Int(&'static str),
    /// A boolean env var was not `true`/`false` (case-insensitive).
    #[error("{0} must be \"true\" or \"false\"")]
    Bool(&'static str),
    /// A `SYSLOG_TRUSTED_CIDRS` entry was not a valid `network/prefix_len`.
    #[error("invalid CIDR entry: {0}")]
    Cidr(String),
    /// `NATS_USER`/`NATS_PASSWORD` were only partially set — fail closed
    /// rather than silently connecting unauthenticated when the operator
    /// clearly intended to configure auth (see [`NatsAuthConfig`]).
    #[error("NATS_USER and NATS_PASSWORD must both be set together, or neither")]
    NatsPartialUserPassword,
}

/// Default DLQ JetStream stream retention (`DLQ_RETENTION_DAYS`, Spec §15
/// open question #6) — bounds a dead-lettered event's lifetime instead of
/// growing the DLQ stream forever, while giving an operator a full month to
/// notice and drain a stuck DLQ.
const DEFAULT_DLQ_RETENTION_DAYS: u32 = 30;

/// Parses `DLQ_RETENTION_DAYS` into a [`Duration`], defaulting to
/// [`DEFAULT_DLQ_RETENTION_DAYS`] when unset/empty. A pure function of the
/// raw string (mirrors this module's own `from_env()`/`from_values()`
/// split) so the parsing logic is unit-testable without mutating process
/// environment state.
fn dlq_retention_from_value(raw: Option<&str>) -> Result<Duration, ConfigError> {
    let days = match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => DEFAULT_DLQ_RETENTION_DAYS,
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| ConfigError::Int("DLQ_RETENTION_DAYS"))?,
    };
    Ok(Duration::from_secs(u64::from(days) * 24 * 60 * 60))
}

/// Loads `DLQ_RETENTION_DAYS` from the environment (see
/// [`dlq_retention_from_value`]) — used by `crate::writer::build_dlq_buffer`
/// to set the dead-letter JetStream stream's `max_age`. Kept independent of
/// [`Config`] (a plain function, not a `Config` field) so adding this knob
/// never requires updating the several exhaustive `Config { .. }`
/// struct-literal test fixtures scattered across this crate (`auth.rs`,
/// `backfill.rs`, `listeners/otlp`, `listeners/syslog`) that construct
/// every `Config` field by hand with no `..Default::default()` spread.
pub fn dlq_retention_from_env() -> Result<Duration, ConfigError> {
    dlq_retention_from_value(std::env::var("DLQ_RETENTION_DAYS").ok().as_deref())
}

/// Default request timeout applied to every `reqwest::Client` this service
/// builds against OpenSearch (`OPENSEARCH_TIMEOUT_SECS`) — release audit
/// Finding A (HIGH): both the writer's `_bulk` client
/// (`crate::bootstrap::run_writer`) and the admin/ISM client
/// (`crate::bootstrap::build_admin_state`, used by `crate::admin`'s
/// lifecycle/restore handlers and `crate::opensearch::ism`) previously had
/// no request timeout at all, so a hung/slow OpenSearch wedged the caller
/// indefinitely. 30s comfortably covers a large `_bulk` batch under normal
/// load while still bounding a genuinely stuck connection; a bulk-write
/// timeout surfaces as an ordinary `reqwest::Error` — the exact same
/// `Err` arm `crate::writer::process_batch_inner` already routes through
/// the retry/backoff → DLQ path for any other transport failure, never a
/// silent drop or an ack.
const DEFAULT_OPENSEARCH_TIMEOUT_SECS: u32 = 30;

/// Parses `OPENSEARCH_TIMEOUT_SECS` into a [`Duration`], defaulting to
/// [`DEFAULT_OPENSEARCH_TIMEOUT_SECS`] when unset/empty — pure function of
/// the raw string, mirroring [`dlq_retention_from_value`]'s split for
/// unit-testability without mutating process environment state.
fn opensearch_timeout_from_value(raw: Option<&str>) -> Result<Duration, ConfigError> {
    let secs = match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => DEFAULT_OPENSEARCH_TIMEOUT_SECS,
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| ConfigError::Int("OPENSEARCH_TIMEOUT_SECS"))?,
    };
    Ok(Duration::from_secs(u64::from(secs)))
}

/// Loads `OPENSEARCH_TIMEOUT_SECS` from the environment (see
/// [`opensearch_timeout_from_value`]). Kept independent of [`Config`] for
/// the same reason as [`dlq_retention_from_env`]: adding this knob must
/// never require touching every exhaustive `Config { .. }` struct-literal
/// test fixture elsewhere in this crate.
pub fn opensearch_timeout_from_env() -> Result<Duration, ConfigError> {
    opensearch_timeout_from_value(std::env::var("OPENSEARCH_TIMEOUT_SECS").ok().as_deref())
}

/// NATS client authentication settings (Spec §7a / P2 hardening —
/// `buffer::jetstream::connect_options` applies these to
/// `async_nats::ConnectOptions`). Loaded independently of [`Config`] for
/// the same reason as [`dlq_retention_from_env`]: adding a new `NATS_*`
/// auth env var must never require touching every other exhaustive
/// `Config { .. }` struct-literal test fixture in this crate that doesn't
/// use `..Default::default()`.
///
/// All fields default to `None`/`false` — an operator who sets none of the
/// `NATS_*` auth env vars gets exactly today's unauthenticated connection
/// (local/dev); this never fails startup for missing NATS auth.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct NatsAuthConfig {
    /// Path to a `.creds` file (`NATS_CREDS_FILE`).
    pub creds_file: Option<String>,
    /// An NKey seed (`NATS_NKEY`) — secret, never logged (see
    /// [`NatsAuthConfig`]'s custom [`std::fmt::Debug`] impl below).
    pub nkey: Option<String>,
    /// Username (`NATS_USER`), always paired with `password`.
    pub user: Option<String>,
    /// Password (`NATS_PASSWORD`) — secret, never logged.
    pub password: Option<String>,
    /// Whether to require TLS to the NATS server (`NATS_TLS`).
    pub tls: bool,
}

impl std::fmt::Debug for NatsAuthConfig {
    /// Masks `nkey`/`password` — `Config` (and this type) may end up in an
    /// ad hoc `{cfg:?}` diagnostic someday; a secret must never be one
    /// `derive(Debug)` away from a log line (`critical-rules.md` Token &
    /// Secret Hygiene: "never log full token values").
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NatsAuthConfig")
            .field("creds_file", &self.creds_file)
            .field("nkey", &self.nkey.as_ref().map(|_| "***"))
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .field("tls", &self.tls)
            .finish()
    }
}

impl NatsAuthConfig {
    /// Loads NATS client auth settings from the environment. Never fails on
    /// missing/absent auth; only a set-but-invalid `NATS_TLS` value or a
    /// partially-set `NATS_USER`/`NATS_PASSWORD` pair produce a
    /// [`ConfigError`].
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_values(
            std::env::var("NATS_CREDS_FILE").ok().as_deref(),
            std::env::var("NATS_NKEY").ok().as_deref(),
            std::env::var("NATS_USER").ok().as_deref(),
            std::env::var("NATS_PASSWORD").ok().as_deref(),
            std::env::var("NATS_TLS").ok().as_deref(),
        )
    }

    /// Pure `from_values` counterpart to [`Self::from_env`], mirroring this
    /// module's own `Config::from_env()`/`Config::from_values()` split for
    /// unit-testability without mutating process environment state.
    fn from_values(
        creds_file: Option<&str>,
        nkey: Option<&str>,
        user: Option<&str>,
        password: Option<&str>,
        tls: Option<&str>,
    ) -> Result<Self, ConfigError> {
        let creds_file = creds_file.filter(|s| !s.is_empty()).map(str::to_owned);
        let nkey = nkey.filter(|s| !s.is_empty()).map(str::to_owned);
        let user = user.filter(|s| !s.is_empty()).map(str::to_owned);
        let password = password.filter(|s| !s.is_empty()).map(str::to_owned);
        if user.is_some() != password.is_some() {
            return Err(ConfigError::NatsPartialUserPassword);
        }
        let tls = match tls.map(str::trim) {
            None | Some("") => false,
            Some(s) => match s.to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => return Err(ConfigError::Bool("NATS_TLS")),
            },
        };
        Ok(Self {
            creds_file,
            nkey,
            user,
            password,
            tls,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_port_table() {
        let cfg = Config::from_values(RawConfig::default()).unwrap();
        assert_eq!(cfg.http_port, 8443);
        assert_eq!(cfg.syslog_port, 5140);
        assert_eq!(cfg.syslog_tls_port, 6514);
        assert_eq!(cfg.otlp_grpc_port, 4317);
        assert_eq!(cfg.otlp_http_port, 4318);
        assert_eq!(cfg.opensearch_url, "http://localhost:9200");
        assert_eq!(cfg.nats_url, "nats://localhost:4222");
        assert_eq!(cfg.nats_jetstream_subject_prefix, "svc-ingest.logs");
        assert_eq!(cfg.snapshot_repo, "skauswatch-snapshots");
    }

    #[test]
    fn snapshot_repo_reads_from_raw_value() {
        let cfg = Config::from_values(RawConfig {
            snapshot_repo: Some("custom-repo"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.snapshot_repo, "custom-repo");
    }

    #[test]
    fn snapshot_repo_empty_string_falls_back_to_default() {
        let cfg = Config::from_values(RawConfig {
            snapshot_repo: Some(""),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.snapshot_repo, "skauswatch-snapshots");
    }

    #[test]
    fn syslog_udp_enabled_defaults_false() {
        let cfg = Config::from_values(RawConfig::default()).unwrap();
        assert!(!cfg.syslog_udp_enabled);
        assert!(cfg.syslog_trusted_cidrs.is_empty());
    }

    #[test]
    fn syslog_udp_tenant_id_defaults_none() {
        let cfg = Config::from_values(RawConfig::default()).unwrap();
        assert_eq!(cfg.syslog_udp_tenant_id, None);
    }

    #[test]
    fn syslog_udp_tenant_id_reads_from_raw_value() {
        let cfg = Config::from_values(RawConfig {
            syslog_udp_tenant_id: Some("tenant-udp"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.syslog_udp_tenant_id, Some("tenant-udp".to_owned()));
    }

    #[test]
    fn syslog_udp_tenant_id_empty_string_is_none() {
        let cfg = Config::from_values(RawConfig {
            syslog_udp_tenant_id: Some(""),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.syslog_udp_tenant_id, None);
    }

    #[test]
    fn syslog_udp_enabled_parses_true_case_insensitively() {
        let cfg = Config::from_values(RawConfig {
            syslog_udp_enabled: Some("True"),
            ..Default::default()
        })
        .unwrap();
        assert!(cfg.syslog_udp_enabled);
    }

    #[test]
    fn syslog_udp_enabled_invalid_value_is_config_error() {
        let err = Config::from_values(RawConfig {
            syslog_udp_enabled: Some("yes"),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::Bool("SYSLOG_UDP_ENABLED"));
    }

    #[test]
    fn trusted_cidrs_parse_valid_list() {
        let cfg = Config::from_values(RawConfig {
            syslog_trusted_cidrs: Some("10.0.0.0/8, 172.16.0.0/12"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.syslog_trusted_cidrs.len(), 2);
        assert_eq!(cfg.syslog_trusted_cidrs[0].prefix_len, 8);
        assert_eq!(cfg.syslog_trusted_cidrs[1].prefix_len, 12);
    }

    #[test]
    fn invalid_cidr_is_config_error_not_panic() {
        let err = Config::from_values(RawConfig {
            syslog_trusted_cidrs: Some("not-a-cidr"),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::Cidr("not-a-cidr".to_owned()));
    }

    #[test]
    fn cidr_prefix_len_exceeding_address_width_is_config_error() {
        let err = Config::from_values(RawConfig {
            syslog_trusted_cidrs: Some("10.0.0.0/33"),
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(err, ConfigError::Cidr(_)));
    }

    #[test]
    fn ipv6_cidr_is_accepted_up_to_a_128_bit_prefix() {
        let cfg = Config::from_values(RawConfig {
            syslog_trusted_cidrs: Some("::1/128"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.syslog_trusted_cidrs.len(), 1);
        assert_eq!(cfg.syslog_trusted_cidrs[0].prefix_len, 128);
    }

    #[test]
    fn ipv6_cidr_prefix_len_exceeding_128_is_config_error() {
        let err = Config::from_values(RawConfig {
            syslog_trusted_cidrs: Some("::1/129"),
            ..Default::default()
        })
        .unwrap_err();
        assert!(matches!(err, ConfigError::Cidr(_)));
    }

    #[test]
    fn blank_entries_in_a_cidr_list_are_skipped_not_errors() {
        let cfg = Config::from_values(RawConfig {
            syslog_trusted_cidrs: Some("10.0.0.0/8,,172.16.0.0/12,"),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.syslog_trusted_cidrs.len(), 2);
    }

    #[test]
    fn invalid_port_is_config_error_not_panic() {
        let err = Config::from_values(RawConfig {
            http_port: Some("not-a-port"),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::Int("HTTP_PORT"));
    }

    #[test]
    fn port_empty_string_falls_back_to_default() {
        let cfg = Config::from_values(RawConfig {
            http_port: Some("  "),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(cfg.http_port, 8443);
    }

    // -- from_env ---------------------------------------------------------
    //
    // `Config::from_env` is thin glue (read each env var, delegate to the
    // already-thoroughly-tested `from_values`) but it's a real production
    // code path (`main.rs::serve`/`backfill_command`) with its own line
    // coverage. This workspace denies `unsafe_code` (`Cargo.toml`
    // `[workspace.lints.rust]`), so `std::env::set_var`/`remove_var` (both
    // `unsafe fn` as of this edition) are not an option here, even scoped
    // to a test -- unlike `from_values`, this function can only honestly be
    // exercised against whatever the ambient process environment already
    // is. Same defensive-assumption pattern `listeners::otlp::mod`'s own
    // tests use for `DB_TYPE`: assert the vars are unset rather than
    // silently skip, so a dev's shell accidentally exporting one of these
    // fails loudly instead of quietly weakening this test.
    #[test]
    fn from_env_uses_defaults_against_an_unset_environment() {
        for var in [
            "HTTP_PORT",
            "SYSLOG_PORT",
            "SYSLOG_TLS_PORT",
            "OTLP_GRPC_PORT",
            "OTLP_HTTP_PORT",
            "OPENSEARCH_URL",
            "NATS_URL",
            "NATS_JETSTREAM_SUBJECT_PREFIX",
            "SNAPSHOT_REPO",
            "SYSLOG_UDP_ENABLED",
            "SYSLOG_TRUSTED_CIDRS",
            "SYSLOG_UDP_TENANT_ID",
        ] {
            assert!(
                std::env::var(var).is_err(),
                "test assumes {var} is unset in the ambient test environment"
            );
        }

        let cfg = Config::from_env().expect("an unset environment is always valid");

        assert_eq!(cfg.http_port, 8443);
        assert_eq!(cfg.opensearch_url, "http://localhost:9200");
        assert_eq!(cfg.snapshot_repo, "skauswatch-snapshots");
        assert!(!cfg.syslog_udp_enabled);
        assert!(cfg.syslog_trusted_cidrs.is_empty());
        assert_eq!(cfg.syslog_udp_tenant_id, None);
    }

    // -- NatsAuthConfig -----------------------------------------------

    /// An operator setting none of the `NATS_*` auth env vars must get
    /// exactly today's unauthenticated behavior — the back-compat
    /// requirement this whole feature is optional on top of.
    #[test]
    fn nats_auth_config_defaults_to_no_auth() {
        let auth = NatsAuthConfig::from_values(None, None, None, None, None).unwrap();
        assert_eq!(auth.creds_file, None);
        assert_eq!(auth.nkey, None);
        assert_eq!(auth.user, None);
        assert_eq!(auth.password, None);
        assert!(!auth.tls);
    }

    #[test]
    fn nats_auth_config_reads_creds_file() {
        let auth =
            NatsAuthConfig::from_values(Some("/etc/nats/user.creds"), None, None, None, None)
                .unwrap();
        assert_eq!(auth.creds_file, Some("/etc/nats/user.creds".to_owned()));
    }

    #[test]
    fn nats_auth_config_reads_nkey() {
        let auth =
            NatsAuthConfig::from_values(None, Some("SUANQ...seed"), None, None, None).unwrap();
        assert_eq!(auth.nkey, Some("SUANQ...seed".to_owned()));
    }

    #[test]
    fn nats_auth_config_reads_user_and_password_together() {
        let auth =
            NatsAuthConfig::from_values(None, None, Some("derek"), Some("s3cr3t"), None).unwrap();
        assert_eq!(auth.user, Some("derek".to_owned()));
        assert_eq!(auth.password, Some("s3cr3t".to_owned()));
    }

    /// A half-set `NATS_USER`/`NATS_PASSWORD` pair is a misconfiguration,
    /// not a valid "no auth" state — fail closed rather than silently
    /// downgrading to an unauthenticated connection the operator didn't
    /// intend.
    #[test]
    fn nats_auth_config_rejects_user_without_password() {
        let err = NatsAuthConfig::from_values(None, None, Some("derek"), None, None).unwrap_err();
        assert_eq!(err, ConfigError::NatsPartialUserPassword);
    }

    #[test]
    fn nats_auth_config_rejects_password_without_user() {
        let err = NatsAuthConfig::from_values(None, None, None, Some("s3cr3t"), None).unwrap_err();
        assert_eq!(err, ConfigError::NatsPartialUserPassword);
    }

    #[test]
    fn nats_auth_config_parses_tls_true_case_insensitively() {
        let auth = NatsAuthConfig::from_values(None, None, None, None, Some("True")).unwrap();
        assert!(auth.tls);
    }

    #[test]
    fn nats_auth_config_rejects_invalid_tls_value() {
        let err = NatsAuthConfig::from_values(None, None, None, None, Some("yes")).unwrap_err();
        assert_eq!(err, ConfigError::Bool("NATS_TLS"));
    }

    /// Secrets must never appear verbatim in a `{auth:?}` diagnostic.
    #[test]
    fn nats_auth_config_debug_masks_secrets() {
        let auth = NatsAuthConfig::from_values(
            None,
            Some("SUPER-SECRET-SEED"),
            Some("derek"),
            Some("hunter2"),
            None,
        )
        .unwrap();
        let debug = format!("{auth:?}");
        assert!(!debug.contains("SUPER-SECRET-SEED"), "{debug}");
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("derek"), "username is not a secret: {debug}");
    }

    // -- dlq_retention_from_value ---------------------------------------

    #[test]
    fn dlq_retention_defaults_to_thirty_days() {
        let retention = dlq_retention_from_value(None).unwrap();
        assert_eq!(retention, Duration::from_secs(30 * 24 * 60 * 60));
    }

    #[test]
    fn dlq_retention_reads_custom_days() {
        let retention = dlq_retention_from_value(Some("7")).unwrap();
        assert_eq!(retention, Duration::from_secs(7 * 24 * 60 * 60));
    }

    #[test]
    fn dlq_retention_invalid_value_is_config_error_not_panic() {
        let err = dlq_retention_from_value(Some("not-a-number")).unwrap_err();
        assert_eq!(err, ConfigError::Int("DLQ_RETENTION_DAYS"));
    }

    // -- opensearch_timeout_from_value (release audit Finding A, HIGH) --

    #[test]
    fn opensearch_timeout_defaults_to_thirty_seconds() {
        let timeout = opensearch_timeout_from_value(None).unwrap();
        assert_eq!(timeout, Duration::from_secs(30));
    }

    #[test]
    fn opensearch_timeout_reads_custom_seconds() {
        let timeout = opensearch_timeout_from_value(Some("5")).unwrap();
        assert_eq!(timeout, Duration::from_secs(5));
    }

    #[test]
    fn opensearch_timeout_empty_value_falls_back_to_default() {
        let timeout = opensearch_timeout_from_value(Some("  ")).unwrap();
        assert_eq!(timeout, Duration::from_secs(30));
    }

    #[test]
    fn opensearch_timeout_invalid_value_is_config_error_not_panic() {
        let err = opensearch_timeout_from_value(Some("not-a-number")).unwrap_err();
        assert_eq!(err, ConfigError::Int("OPENSEARCH_TIMEOUT_SECS"));
    }
}
