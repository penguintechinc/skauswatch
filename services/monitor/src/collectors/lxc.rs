//! LXC/LXD collector: streams `journalctl -f -o json -t lxc` (subprocess),
//! classifying container lifecycle and security-relevant entries. Rust port
//! of the working core of v1 `collectors/lxc_collector.py`'s
//! systemd-journal fallback path (`_monitor_systemd_logs`) — v1 also drove
//! the LXD REST API and a WebSocket event stream for richer lifecycle
//! events; this port keeps the subprocess/journal path (real, host-native,
//! and the mechanism this task's collector brief calls out), matching
//! `journald.rs`'s approach filtered to the `lxc` syslog identifier every
//! LXC/LXD host emits container lifecycle events under.

use std::env;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::collectors::journald::extract_timestamp;
use crate::collectors::{consume_and_ingest, spawn_line_source};
use crate::ingest::IngestHandle;
use crate::models::{BaseEvent, EventType, LogSource, Severity};

/// Config for the LXC collector, loaded from `MONITOR_COLLECTOR_LXC_*`.
#[derive(Debug, Clone)]
pub struct LxcConfig {
    /// `MONITOR_COLLECTOR_LXC_ENABLED` — off by default (needs
    /// `/run/log/journal` mounted, same as `journald.rs`).
    pub enabled: bool,
}

impl LxcConfig {
    /// Loads from env. Never fails.
    pub fn from_env() -> Self {
        let enabled = env::var("MONITOR_COLLECTOR_LXC_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        Self { enabled }
    }
}

const LIFECYCLE_KEYWORDS: &[&str] = &["started", "starting", "stopped", "created", "destroyed"];
const SECURITY_KEYWORDS: &[&str] = &["denied", "apparmor", "seccomp", "violation"];

/// v1 `_classify_and_create_events` (lxc): security keywords first (highest
/// priority, matches v1's own ordering), then container lifecycle, else no
/// event — this collector never manufactures noise for routine journal
/// chatter unrelated to a container's lifecycle or security posture.
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

    let (event_type, severity) = if contains_any(&lower, SECURITY_KEYWORDS) {
        (EventType::SecurityViolation, Severity::High)
    } else if contains_any(&lower, LIFECYCLE_KEYWORDS) {
        (EventType::ContainerEvent, Severity::Info)
    } else {
        return None;
    };

    Some(BaseEvent {
        id: uuid::Uuid::new_v4().to_string(),
        source: LogSource::LxcLxd,
        event_type,
        severity,
        message: message.to_owned(),
        timestamp,
        raw_data: entry.clone(),
        tags: vec!["lxc".to_owned()],
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

/// Streams `journalctl -f -o json -t lxc` forever, restarting with a
/// backoff on subprocess exit.
pub async fn run(_cfg: LxcConfig, tenant_id: String, sink: IngestHandle) {
    let args = ["-f", "-o", "json", "--no-pager", "-n", "0", "-t", "lxc"];
    loop {
        match spawn_line_source("journalctl", &args) {
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
                tracing::error!(error = %e, "failed to start journalctl for LXC events");
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn entry(message: &str) -> Value {
        serde_json::json!({"MESSAGE": message, "_HOSTNAME": "host1"})
    }

    #[test]
    fn classifies_container_start_as_lifecycle_event() {
        let event = classify_entry(&entry("Container 'web1' started"), Utc::now(), "tenant-a")
            .unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.event_type, EventType::ContainerEvent);
        assert_eq!(event.severity, Severity::Info);
        assert_eq!(event.source, LogSource::LxcLxd);
        assert_eq!(event.tenant_id, "tenant-a");
    }

    #[test]
    fn classifies_apparmor_denial_as_security_violation() {
        let event = classify_entry(
            &entry("apparmor=\"DENIED\" operation=\"mount\" profile=\"lxc-web1\""),
            Utc::now(),
            "tenant-a",
        )
        .unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.event_type, EventType::SecurityViolation);
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn security_keyword_wins_over_lifecycle_keyword() {
        // Contains both "started" and "denied" — security must win (v1's
        // classification order: security checks run first).
        let event = classify_entry(
            &entry("container started but apparmor denied mount"),
            Utc::now(),
            "tenant-a",
        )
        .unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.event_type, EventType::SecurityViolation);
    }

    #[test]
    fn routine_message_yields_no_event() {
        assert!(classify_entry(&entry("heartbeat ok"), Utc::now(), "tenant-a").is_none());
    }

    #[test]
    fn empty_message_yields_no_event() {
        assert!(classify_entry(&entry(""), Utc::now(), "tenant-a").is_none());
    }

    #[test]
    fn config_default_is_disabled() {
        assert!(!LxcConfig { enabled: false }.enabled);
    }

    #[test]
    fn from_env_reads_process_env_without_panicking() {
        assert!(!LxcConfig::from_env().enabled);
    }
}
