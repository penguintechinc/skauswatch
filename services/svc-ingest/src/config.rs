//! Runtime configuration for `skauswatch-svc-ingest`, mirroring
//! `services/logs/src/config.rs`'s `from_env()`/`from_values()`/
//! `ConfigError` pattern for unit-testability. Values follow the port table
//! and NATS config block in `docs/v2-port/ingest-module-spec.md` §3b/§7a.

use std::net::IpAddr;

/// Default HTTPS OCSF/JSON ingest port (Spec §3b).
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

/// Loaded configuration for `skauswatch-svc-ingest`.
#[derive(Debug, Clone)]
pub struct Config {
    /// HTTPS OCSF/JSON ingest port (`HTTP_PORT`).
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
    /// Whether the UDP syslog listener is enabled at all
    /// (`SYSLOG_UDP_ENABLED`) — OFF by default; UDP has no authentication,
    /// so enabling it is an explicit operator opt-in (Spec §6c).
    pub syslog_udp_enabled: bool,
    /// CIDR blocks trusted to send UDP syslog when `syslog_udp_enabled` is
    /// set (`SYSLOG_TRUSTED_CIDRS`, comma-separated). Empty by default.
    pub syslog_trusted_cidrs: Vec<CidrBlock>,
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
    /// Raw `SYSLOG_UDP_ENABLED` value.
    pub syslog_udp_enabled: Option<&'a str>,
    /// Raw `SYSLOG_TRUSTED_CIDRS` value.
    pub syslog_trusted_cidrs: Option<&'a str>,
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
        let syslog_udp_enabled = std::env::var("SYSLOG_UDP_ENABLED").ok();
        let syslog_trusted_cidrs = std::env::var("SYSLOG_TRUSTED_CIDRS").ok();

        Self::from_values(RawConfig {
            http_port: http_port.as_deref(),
            syslog_port: syslog_port.as_deref(),
            syslog_tls_port: syslog_tls_port.as_deref(),
            otlp_grpc_port: otlp_grpc_port.as_deref(),
            otlp_http_port: otlp_http_port.as_deref(),
            opensearch_url: opensearch_url.as_deref(),
            nats_url: nats_url.as_deref(),
            nats_jetstream_subject_prefix: nats_jetstream_subject_prefix.as_deref(),
            syslog_udp_enabled: syslog_udp_enabled.as_deref(),
            syslog_trusted_cidrs: syslog_trusted_cidrs.as_deref(),
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

        Ok(Self {
            http_port,
            syslog_port,
            syslog_tls_port,
            otlp_grpc_port,
            otlp_http_port,
            opensearch_url,
            nats_url,
            nats_jetstream_subject_prefix,
            syslog_udp_enabled,
            syslog_trusted_cidrs,
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
    }

    #[test]
    fn syslog_udp_enabled_defaults_false() {
        let cfg = Config::from_values(RawConfig::default()).unwrap();
        assert!(!cfg.syslog_udp_enabled);
        assert!(cfg.syslog_trusted_cidrs.is_empty());
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
    fn invalid_port_is_config_error_not_panic() {
        let err = Config::from_values(RawConfig {
            http_port: Some("not-a-port"),
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(err, ConfigError::Int("HTTP_PORT"));
    }
}
