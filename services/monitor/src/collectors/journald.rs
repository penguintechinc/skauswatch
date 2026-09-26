//! journald collector: streams `journalctl -f -o json` (subprocess),
//! classifying each JSON journal entry. Rust port of the working core of
//! v1 `collectors/journald_collector.py` — v1 talked to a *remote*
//! `systemd-journal-remote` HTTP API (`_collect_from_journald`); this port
//! reads the local host/node journal directly via `journalctl`, the
//! standard way a container gets journal access (bind-mount `/run/log/journal`
//! or `/var/log/journal` read-only — see `collectors/mod.rs` deployment-
//! requirement note) — a more directly host-native mechanism than
//! replicating v1's remote-HTTP-API assumption, and the one this task's
//! collector brief calls out (subprocess-based collection).

use std::env;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::Value;

use crate::collectors::{consume_and_ingest, spawn_line_source};
use crate::ingest::IngestHandle;
use crate::models::{BaseEvent, EventType, LogSource, Severity};

/// Config for the journald collector, loaded from `MONITOR_COLLECTOR_JOURNALD_*`.
#[derive(Debug, Clone)]
pub struct JournaldConfig {
    /// `MONITOR_COLLECTOR_JOURNALD_ENABLED` — off by default (needs
    /// `/run/log/journal` mounted and `journalctl` in the image).
    pub enabled: bool,
    /// `MONITOR_COLLECTOR_JOURNALD_UNITS` (comma-separated systemd unit
    /// names to filter to via `journalctl -u`); empty = every unit.
    pub units: Vec<String>,
}

impl JournaldConfig {
    /// Loads from env. Never fails.
    pub fn from_env() -> Self {
        let enabled = env::var("MONITOR_COLLECTOR_JOURNALD_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let units = env::var("MONITOR_COLLECTOR_JOURNALD_UNITS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Self { enabled, units }
    }

    /// Builds the `journalctl` argv for this config — a pure function so
    /// the exact command shape is unit-tested without spawning a process.
    pub(crate) fn journalctl_args(&self) -> Vec<String> {
        let mut args = vec![
            "-f".to_owned(),
            "-o".to_owned(),
            "json".to_owned(),
            "--no-pager".to_owned(),
            "-n".to_owned(),
            "0".to_owned(),
        ];
        for unit in &self.units {
            args.push("-u".to_owned());
            args.push(unit.clone());
        }
        args
    }
}

/// v1's `journalctl -o json` `__REALTIME_TIMESTAMP` is microseconds since
/// the Unix epoch, encoded as a decimal string.
pub fn extract_timestamp(entry: &Value) -> DateTime<Utc> {
    entry
        .get("__REALTIME_TIMESTAMP")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(|micros| Utc.timestamp_micros(micros).single())
        .unwrap_or_else(Utc::now)
}

/// syslog `PRIORITY` (0-7, RFC 5424 numeric levels) → [`Severity`] — same
/// mapping v1's syslog/journald classification uses.
fn severity_from_priority(entry: &Value) -> Severity {
    let priority = entry
        .get("PRIORITY")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<u8>().ok());
    match priority {
        Some(0..=2) => Severity::Critical,
        Some(3) => Severity::High,
        Some(4) => Severity::Medium,
        Some(7) => Severity::Low,
        _ => Severity::Info,
    }
}

/// Classifies one journal entry by `MESSAGE` keyword, same priority order
/// as `file.rs`/`auditd.rs`'s classifiers: authentication, then privilege
/// escalation, then a generic event gated on severity (never emits a
/// generic event for a routine Info-level line — matches the rest of this
/// collector family's "don't manufacture noise" behavior).
pub fn classify_entry(
    entry: &Value,
    timestamp: DateTime<Utc>,
    tenant_id: &str,
) -> Option<BaseEvent> {
    let message = entry.get("MESSAGE").and_then(Value::as_str).unwrap_or("");
    if message.is_empty() {
        return None;
    }
    let lower = message.to_ascii_lowercase();
    let severity = severity_from_priority(entry);

    let event_type = if contains_any(
        &lower,
        &[
            "login",
            "authentication",
            "password",
            "ssh failed",
            "ssh accepted",
        ],
    ) {
        EventType::Authentication
    } else if contains_any(&lower, &["sudo", " su ", "privilege"]) {
        EventType::PrivilegeEscalation
    } else if matches!(
        severity,
        Severity::Critical | Severity::High | Severity::Medium
    ) {
        EventType::SystemEvent
    } else {
        return None;
    };

    let unit = entry
        .get("_SYSTEMD_UNIT")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();

    Some(BaseEvent {
        id: uuid::Uuid::new_v4().to_string(),
        source: LogSource::System,
        event_type,
        severity,
        message: message.to_owned(),
        timestamp,
        raw_data: entry.clone(),
        tags: vec!["journald".to_owned(), unit],
        host: entry
            .get("_HOSTNAME")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        user: None,
        process: entry
            .get("SYSLOG_IDENTIFIER")
            .and_then(Value::as_str)
            .map(str::to_owned),
        pid: entry
            .get("_PID")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<i64>().ok()),
        enrichments: serde_json::Value::Null,
        threat_matches: vec![],
        ai_analysis: None,
        processed_data: serde_json::Value::Null,
        tenant_id: tenant_id.to_owned(),
        extra: Default::default(),
    })
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

/// Streams `journalctl -f -o json` forever, restarting with a backoff if the
/// subprocess exits (e.g. journald restarted).
pub async fn run(cfg: JournaldConfig, tenant_id: String, sink: IngestHandle) {
    let args = cfg.journalctl_args();
    loop {
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        match spawn_line_source("journalctl", &arg_refs) {
            Ok((mut child, reader)) => {
                consume_and_ingest(reader, &sink, |line| {
                    let entry = serde_json::from_str::<Value>(line).ok()?;
                    let ts = extract_timestamp(&entry);
                    classify_entry(&entry, ts, &tenant_id)
                })
                .await;
                let _ = child.wait().await;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to start journalctl (is it on PATH / journal mounted?)");
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn entry(message: &str, priority: &str) -> Value {
        serde_json::json!({
            "MESSAGE": message,
            "PRIORITY": priority,
            "__REALTIME_TIMESTAMP": "1700000000000000",
            "_HOSTNAME": "node-1",
            "_SYSTEMD_UNIT": "sshd.service",
        })
    }

    #[test]
    fn journalctl_args_include_follow_and_json_output() {
        let cfg = JournaldConfig {
            enabled: true,
            units: vec![],
        };
        let args = cfg.journalctl_args();
        assert!(args.contains(&"-f".to_owned()));
        assert!(args.contains(&"json".to_owned()));
        assert!(!args.contains(&"-u".to_owned()));
    }

    #[test]
    fn journalctl_args_add_unit_filters() {
        let cfg = JournaldConfig {
            enabled: true,
            units: vec!["sshd.service".to_owned(), "sudo.service".to_owned()],
        };
        let args = cfg.journalctl_args();
        let u_count = args.iter().filter(|a| *a == "-u").count();
        assert_eq!(u_count, 2);
        assert!(args.contains(&"sshd.service".to_owned()));
    }

    #[test]
    fn extract_timestamp_parses_microseconds() {
        let e = entry("hi", "6");
        let ts = extract_timestamp(&e);
        assert_eq!(ts.timestamp(), 1_700_000_000);
    }

    #[test]
    fn extract_timestamp_falls_back_when_missing() {
        let before = Utc::now();
        let ts = extract_timestamp(&serde_json::json!({}));
        assert!(ts >= before);
    }

    #[test]
    fn classifies_ssh_failure_as_authentication() {
        let e = entry("ssh failed password for root from 10.0.0.1", "4");
        let event =
            classify_entry(&e, Utc::now(), "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.event_type, EventType::Authentication);
        assert_eq!(event.tenant_id, "tenant-a");
    }

    #[test]
    fn classifies_sudo_as_privilege_escalation() {
        let e = entry("sudo: alice : TTY=pts/0 ; COMMAND=/bin/su", "6");
        let event =
            classify_entry(&e, Utc::now(), "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.event_type, EventType::PrivilegeEscalation);
    }

    #[test]
    fn high_severity_generic_line_becomes_system_event() {
        let e = entry("segfault in process foo", "3");
        let event =
            classify_entry(&e, Utc::now(), "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.event_type, EventType::SystemEvent);
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn routine_info_line_yields_no_event() {
        let e = entry("heartbeat ok", "6");
        assert!(classify_entry(&e, Utc::now(), "tenant-a").is_none());
    }

    #[test]
    fn empty_message_yields_no_event() {
        let e = entry("", "6");
        assert!(classify_entry(&e, Utc::now(), "tenant-a").is_none());
    }

    #[test]
    fn severity_priority_mapping() {
        assert_eq!(severity_from_priority(&entry("x", "0")), Severity::Critical);
        assert_eq!(severity_from_priority(&entry("x", "3")), Severity::High);
        assert_eq!(severity_from_priority(&entry("x", "4")), Severity::Medium);
        assert_eq!(severity_from_priority(&entry("x", "6")), Severity::Info);
        assert_eq!(severity_from_priority(&entry("x", "7")), Severity::Low);
    }

    #[tokio::test]
    async fn consume_and_ingest_wiring_ingests_valid_json_and_skips_malformed_lines() {
        use std::io::Cursor;
        use tokio::io::BufReader;

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

        let mut data = Vec::new();
        data.extend_from_slice(b"not json at all\n");
        data.extend_from_slice(
            serde_json::to_string(&entry("sudo su - escalate", "6"))
                .unwrap_or_default()
                .as_bytes(),
        );
        data.extend_from_slice(b"\n");

        let reader = BufReader::new(Cursor::new(data));
        consume_and_ingest(reader, &sink, |line| {
            let parsed = serde_json::from_str::<Value>(line).ok()?;
            let ts = extract_timestamp(&parsed);
            classify_entry(&parsed, ts, "tenant-a")
        })
        .await;

        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected the valid journal line to be ingested"));
        assert!(got.is_ok());
    }

    #[test]
    fn from_env_reads_process_env_without_panicking() {
        let cfg = JournaldConfig::from_env();
        assert!(!cfg.enabled);
        assert!(cfg.units.is_empty());
    }
}
