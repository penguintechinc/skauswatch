//! Syslog collector: binds a UDP socket and parses RFC 3164 syslog
//! messages. Rust port of the working core of v1 `collectors/
//! syslog_collector.py`'s UDP path (`_start_udp_server`/
//! `_classify_syslog_message`) — v1 also offered a TCP listener and
//! outbound client connections to remote syslog servers; UDP is the
//! dominant real-world syslog transport and the one this task's collector
//! brief calls out explicitly (socket-based collection), so it's the one
//! ported here.

use std::env;
use std::sync::LazyLock;
use std::time::Duration;

use chrono::{DateTime, Datelike, TimeZone, Utc};
use regex::Regex;
use tokio::net::UdpSocket;

use crate::ingest::IngestHandle;
use crate::models::{BaseEvent, EventType, LogSource, Severity};

/// Config for the syslog collector, loaded from `MONITOR_COLLECTOR_SYSLOG_*`.
#[derive(Debug, Clone)]
pub struct SyslogConfig {
    /// `MONITOR_COLLECTOR_SYSLOG_ENABLED` — off by default.
    pub enabled: bool,
    /// `MONITOR_COLLECTOR_SYSLOG_PORT`; default 1514 (unprivileged — binding
    /// the RFC-standard 514 needs `NET_BIND_SERVICE` or root, which this
    /// rootless-by-default deployment does not grant; an operator who needs
    /// 514 sets this explicitly and grants the capability, matching
    /// `devops-containers.md`'s exception-with-approval process, not
    /// something this collector silently requires).
    pub port: u16,
}

impl SyslogConfig {
    /// Loads from env. Never fails.
    pub fn from_env() -> Self {
        let enabled = env::var("MONITOR_COLLECTOR_SYSLOG_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let port = env::var("MONITOR_COLLECTOR_SYSLOG_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            .unwrap_or(1514);
        Self { enabled, port }
    }
}

/// RFC 3164: `<PRI>MMM DD HH:MM:SS HOSTNAME MESSAGE`.
static RFC3164_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"^<(\d+)>(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$").unwrap()
});

/// One parsed syslog message.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSyslog {
    /// Numeric facility (PRI / 8).
    pub facility: u8,
    /// Numeric severity (PRI % 8, RFC 5424 levels).
    pub severity_code: u8,
    /// Sending host, as reported in the message itself.
    pub host: String,
    /// Message body after the header.
    pub message: String,
}

/// Parses an RFC 3164 syslog line. Returns `None` for anything that doesn't
/// match the `<PRI>...` header shape (v1 silently dropped these too).
pub fn parse_rfc3164(raw: &str) -> Option<ParsedSyslog> {
    let caps = RFC3164_RE.captures(raw.trim())?;
    let pri: u32 = caps.get(1)?.as_str().parse().ok()?;
    Some(ParsedSyslog {
        facility: (pri / 8) as u8,
        severity_code: (pri % 8) as u8,
        host: caps.get(3)?.as_str().to_owned(),
        message: caps.get(4)?.as_str().to_owned(),
    })
}

/// RFC 5424 numeric severity → [`Severity`] (v1's `severity_map`).
fn map_severity(code: u8) -> Severity {
    match code {
        0..=2 => Severity::Critical,
        3 => Severity::High,
        4 => Severity::Medium,
        5 | 6 => Severity::Info,
        _ => Severity::Low,
    }
}

/// Best-effort "MMM DD HH:MM:SS" (no year in RFC 3164) → this year's
/// `DateTime<Utc>`; falls back to "now" on any parse failure — matches v1's
/// own best-effort behavior (RFC 3164 fundamentally can't disambiguate
/// year, and v1 always assumed the current one too).
fn parse_rfc3164_timestamp(raw: &str) -> DateTime<Utc> {
    let now = Utc::now();
    let with_year = format!("{} {}", now.year(), raw);
    chrono::NaiveDateTime::parse_from_str(&with_year, "%Y %b %e %H:%M:%S")
        .ok()
        .and_then(|naive| Utc.from_local_datetime(&naive).single())
        .unwrap_or(now)
}

/// Classifies a parsed syslog message — v1's SSH/sudo keyword checks folded
/// into event-type selection, PRI-derived severity kept as-is (v1 mapped
/// PRI severity directly, only escalating auth failures to High).
pub fn classify(parsed: &ParsedSyslog, timestamp: DateTime<Utc>, tenant_id: &str) -> BaseEvent {
    let lower = parsed.message.to_ascii_lowercase();
    let mut severity = map_severity(parsed.severity_code);

    let event_type = if lower.contains("sudo") {
        EventType::PrivilegeEscalation
    } else if lower.contains("ssh") || lower.contains("login") || lower.contains("password") {
        if contains_any(&lower, &["failed", "failure", "invalid", "denied"]) {
            severity = Severity::High;
        }
        EventType::Authentication
    } else {
        EventType::SystemEvent
    };

    BaseEvent {
        id: uuid::Uuid::new_v4().to_string(),
        source: LogSource::System,
        event_type,
        severity,
        message: parsed.message.clone(),
        timestamp,
        raw_data: serde_json::json!({
            "facility": parsed.facility,
            "syslog_severity": parsed.severity_code,
        }),
        tags: vec!["syslog".to_owned()],
        host: parsed.host.clone(),
        user: None,
        process: None,
        pid: None,
        enrichments: serde_json::Value::Null,
        threat_matches: vec![],
        ai_analysis: None,
        processed_data: serde_json::Value::Null,
        tenant_id: tenant_id.to_owned(),
        extra: Default::default(),
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Reads UDP datagrams from `socket` until it errors, parsing/classifying
/// and ingesting each one. Extracted from [`run`] so tests can drive a real
/// loopback socket without needing the well-known port (see tests below).
pub(crate) async fn consume_socket(socket: &UdpSocket, tenant_id: &str, sink: &IngestHandle) {
    let mut buf = [0u8; 65535];
    loop {
        let (len, _addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, "syslog UDP recv failed");
                return;
            }
        };
        let raw = String::from_utf8_lossy(&buf[..len]);
        let Some(parsed) = parse_rfc3164(&raw) else {
            continue;
        };
        let timestamp = RFC3164_RE
            .captures(raw.trim())
            .and_then(|c| c.get(2).map(|m| parse_rfc3164_timestamp(m.as_str())))
            .unwrap_or_else(Utc::now);
        let event = classify(&parsed, timestamp, tenant_id);
        sink.ingest(event).await;
    }
}

/// Binds `0.0.0.0:{cfg.port}` and consumes forever, restarting the bind
/// with a backoff on failure (e.g. port already in use during a restart
/// race).
pub async fn run(cfg: SyslogConfig, tenant_id: String, sink: IngestHandle) {
    loop {
        match UdpSocket::bind(("0.0.0.0", cfg.port)).await {
            Ok(socket) => {
                tracing::info!(port = cfg.port, "syslog UDP collector listening");
                consume_socket(&socket, &tenant_id, &sink).await;
            }
            Err(e) => {
                tracing::error!(port = cfg.port, error = %e, "failed to bind syslog UDP socket");
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_rfc3164_line() {
        let parsed = parse_rfc3164("<34>Oct 11 22:14:15 mymachine sudo: alice ran /bin/su")
            .unwrap_or_else(|| panic!("expected a parse"));
        assert_eq!(parsed.facility, 4);
        assert_eq!(parsed.severity_code, 2);
        assert_eq!(parsed.host, "mymachine");
        assert_eq!(parsed.message, "sudo: alice ran /bin/su");
    }

    #[test]
    fn rejects_a_line_with_no_pri_header() {
        assert!(parse_rfc3164("just a plain line, no header").is_none());
    }

    #[test]
    fn severity_mapping_matches_v1() {
        assert_eq!(map_severity(0), Severity::Critical);
        assert_eq!(map_severity(2), Severity::Critical);
        assert_eq!(map_severity(3), Severity::High);
        assert_eq!(map_severity(4), Severity::Medium);
        assert_eq!(map_severity(6), Severity::Info);
        assert_eq!(map_severity(7), Severity::Low);
    }

    #[test]
    fn classify_sudo_message_is_privilege_escalation() {
        let parsed = ParsedSyslog {
            facility: 4,
            severity_code: 6,
            host: "h1".to_owned(),
            message: "sudo: alice : COMMAND=/bin/bash".to_owned(),
        };
        let event = classify(&parsed, Utc::now(), "tenant-a");
        assert_eq!(event.event_type, EventType::PrivilegeEscalation);
        assert_eq!(event.tenant_id, "tenant-a");
    }

    #[test]
    fn classify_failed_ssh_login_escalates_to_high() {
        let parsed = ParsedSyslog {
            facility: 4,
            severity_code: 6,
            host: "h1".to_owned(),
            message: "sshd: Failed password for invalid user root".to_owned(),
        };
        let event = classify(&parsed, Utc::now(), "tenant-a");
        assert_eq!(event.event_type, EventType::Authentication);
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn classify_generic_message_is_system_event() {
        let parsed = ParsedSyslog {
            facility: 1,
            severity_code: 6,
            host: "h1".to_owned(),
            message: "cron[123]: job completed".to_owned(),
        };
        let event = classify(&parsed, Utc::now(), "tenant-a");
        assert_eq!(event.event_type, EventType::SystemEvent);
    }

    #[test]
    fn parse_rfc3164_timestamp_falls_back_on_bad_input() {
        let before = Utc::now();
        let ts = parse_rfc3164_timestamp("not a timestamp");
        assert!(ts >= before);
    }

    #[tokio::test]
    async fn consume_socket_ingests_a_real_udp_datagram() {
        let socket = UdpSocket::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = socket
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));

        let (bus, mut rx) = tokio::sync::broadcast::channel(16);
        let sink = crate::ingest::IngestPipeline::spawn(
            None,
            bus,
            None,
            skauswatch_testkit::license::dev_license("skauswatch"),
            crate::ingest::IngestConfig {
                channel_capacity: 16,
                batch_size: 1,
                flush_interval: Duration::from_millis(30),
            },
        );

        let consumer = tokio::spawn(async move {
            consume_socket(&socket, "tenant-a", &sink).await;
        });

        let client = UdpSocket::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|e| panic!("bind client: {e}"));
        client
            .send_to(
                b"<38>Oct 11 22:14:15 host1 sshd: Failed password for root",
                addr,
            )
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));

        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected the UDP datagram to be ingested"));
        assert!(got.is_ok());
        consumer.abort();
    }

    #[tokio::test]
    async fn consume_socket_ignores_malformed_datagrams_without_crashing() {
        let socket = UdpSocket::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = socket
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));

        let (bus, mut rx) = tokio::sync::broadcast::channel(16);
        let sink = crate::ingest::IngestPipeline::spawn(
            None,
            bus,
            None,
            skauswatch_testkit::license::dev_license("skauswatch"),
            crate::ingest::IngestConfig {
                channel_capacity: 16,
                batch_size: 1,
                flush_interval: Duration::from_millis(30),
            },
        );
        let consumer = tokio::spawn(async move {
            consume_socket(&socket, "tenant-a", &sink).await;
        });

        let client = UdpSocket::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|e| panic!("bind client: {e}"));
        client
            .send_to(b"not a syslog message", addr)
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));
        client
            .send_to(
                b"<38>Oct 11 22:14:15 host1 sshd: Failed password for root",
                addr,
            )
            .await
            .unwrap_or_else(|e| panic!("send: {e}"));

        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected only the well-formed datagram to be ingested"));
        assert!(got.is_ok());
        consumer.abort();
    }

    #[test]
    fn from_env_reads_process_env_without_panicking() {
        let cfg = SyslogConfig::from_env();
        assert!(!cfg.enabled);
        assert_eq!(cfg.port, 1514);
    }
}
