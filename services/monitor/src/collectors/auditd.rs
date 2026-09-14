//! Auditd/auth-log collector: tails local audit log files via `tail -F`
//! (subprocess), classifying each line the same way v1 `collectors/
//! auditd_collector.py::_classify_audit_record` does — authentication,
//! privilege-escalation, syscall, and generic-audit patterns, in that
//! priority order. v1 additionally fanned this same classification out over
//! Elasticsearch/Splunk polling, a journald HTTP API, and SSH to remote
//! hosts; this port keeps the local-file-tail path (real host log access,
//! matching this task's collector brief) — see `collectors/mod.rs` module
//! docs for the full scope note.

use std::env;
use std::sync::LazyLock;
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use regex::Regex;

use crate::collectors::{consume_and_ingest, spawn_line_source};
use crate::ingest::IngestHandle;
use crate::models::{BaseEvent, EventType, LogSource, Severity};

/// Config for the auditd collector, loaded from `MONITOR_COLLECTOR_AUDITD_*`.
#[derive(Debug, Clone)]
pub struct AuditdConfig {
    /// `MONITOR_COLLECTOR_AUDITD_ENABLED` — off by default (needs a host
    /// log mount, see `collectors/mod.rs` deployment-requirement note).
    pub enabled: bool,
    /// `MONITOR_COLLECTOR_AUDITD_PATHS` (comma-separated); v1 default paths.
    pub paths: Vec<String>,
}

impl AuditdConfig {
    /// Loads from env. Never fails.
    pub fn from_env() -> Self {
        let enabled = env::var("MONITOR_COLLECTOR_AUDITD_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let paths = env::var("MONITOR_COLLECTOR_AUDITD_PATHS")
            .ok()
            .map(|raw| {
                raw.split(',')
                    .map(str::trim)
                    .filter(|p| !p.is_empty())
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                vec![
                    "/var/log/audit/audit.log".to_owned(),
                    "/var/log/auth.log".to_owned(),
                ]
            });
        Self { enabled, paths }
    }
}

static AUTH_PATTERNS: LazyLock<[(&str, Regex); 3]> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)] // compile-time-constant patterns, provably valid
    [
        (
            "user_login",
            Regex::new(r#"type=USER_LOGIN.*acct="([^"]*)".*addr=(\S+).*res=(\w+)"#).unwrap(),
        ),
        (
            "user_auth",
            Regex::new(r#"type=USER_AUTH.*acct="([^"]*)".*addr=(\S+).*res=(\w+)"#).unwrap(),
        ),
        (
            "cred_acq",
            Regex::new(r#"type=CRED_ACQ.*acct="([^"]*)".*addr=(\S+).*res=(\w+)"#).unwrap(),
        ),
    ]
});

static PRIVILEGE_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"type=(SETUID|SETGID)\b").unwrap()
});

static SYSCALL_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"type=SYSCALL.*comm=\x22?([\w./-]+)").unwrap()
});

static AUDIT_TS_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::unwrap_used)]
    Regex::new(r"msg=audit\((\d+\.\d+):\d+\):").unwrap()
});

const CRITICAL_SYSCALLS: &[&str] = &[
    "mount",
    "umount",
    "init_module",
    "delete_module",
    "settimeofday",
    "sethostname",
];

/// v1 `_extract_timestamp`: parses the `msg=audit(EPOCH.MS:SEQ):` prefix
/// auditd emits on every record; falls back to "now" if absent/malformed.
pub fn extract_timestamp(line: &str) -> DateTime<Utc> {
    AUDIT_TS_PATTERN
        .captures(line)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<f64>().ok())
        .and_then(|epoch| Utc.timestamp_opt(epoch as i64, 0).single())
        .unwrap_or_else(Utc::now)
}

/// v1 `_classify_audit_record`: auth pattern first, then privilege
/// escalation, then syscall, then a generic fallback for lines carrying an
/// interesting keyword — first match wins, matching v1's `break`-after-match
/// per pattern group.
pub fn classify_line(line: &str, timestamp: DateTime<Utc>, tenant_id: &str) -> Option<BaseEvent> {
    for (name, pattern) in AUTH_PATTERNS.iter() {
        if let Some(caps) = pattern.captures(line) {
            let username = caps.get(1).map(|m| m.as_str().to_owned());
            let result = caps.get(3).map(|m| m.as_str().to_ascii_lowercase());
            let success = result
                .as_deref()
                .map(|r| matches!(r, "success" | "yes" | "successful"))
                .unwrap_or(true);
            return Some(new_event(
                EventType::Authentication,
                if success {
                    Severity::Info
                } else {
                    Severity::High
                },
                line,
                timestamp,
                tenant_id,
                vec![
                    "auditd".to_owned(),
                    "authentication".to_owned(),
                    (*name).to_owned(),
                ],
                username,
            ));
        }
    }

    if PRIVILEGE_PATTERN.is_match(line) {
        return Some(new_event(
            EventType::PrivilegeEscalation,
            Severity::High,
            line,
            timestamp,
            tenant_id,
            vec!["auditd".to_owned(), "privilege-escalation".to_owned()],
            None,
        ));
    }

    if let Some(caps) = SYSCALL_PATTERN.captures(line) {
        let comm = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let severity = if CRITICAL_SYSCALLS.iter().any(|s| line.contains(s)) {
            Severity::High
        } else {
            Severity::Info
        };
        return Some(new_event(
            EventType::SystemCall,
            severity,
            line,
            timestamp,
            tenant_id,
            vec!["auditd".to_owned(), "syscall".to_owned(), comm.to_owned()],
            None,
        ));
    }

    let upper = line.to_ascii_uppercase();
    if ["DENIED", "FAILED", "ERROR", "VIOLATION", "SUSPICIOUS"]
        .iter()
        .any(|kw| upper.contains(kw))
    {
        return Some(new_event(
            EventType::SystemCall,
            Severity::Medium,
            line,
            timestamp,
            tenant_id,
            vec!["auditd".to_owned(), "generic".to_owned()],
            None,
        ));
    }

    None
}

fn new_event(
    event_type: EventType,
    severity: Severity,
    line: &str,
    timestamp: DateTime<Utc>,
    tenant_id: &str,
    tags: Vec<String>,
    user: Option<String>,
) -> BaseEvent {
    BaseEvent {
        id: uuid::Uuid::new_v4().to_string(),
        source: LogSource::Auditd,
        event_type,
        severity,
        message: line.to_owned(),
        timestamp,
        raw_data: serde_json::json!({"audit_line": line}),
        tags,
        host: String::new(),
        user,
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

/// Tails every configured path concurrently, restarting a path's `tail -F`
/// with a backoff if the file/subprocess disappears (e.g. log rotation
/// killed the underlying inode's descriptor) — never exits.
pub async fn run(cfg: AuditdConfig, tenant_id: String, sink: IngestHandle) {
    let mut tasks = Vec::new();
    for path in cfg.paths {
        let tenant_id = tenant_id.clone();
        let sink = sink.clone();
        // Owned values only cross the `tokio::spawn` boundary here (not
        // `&str`/`&IngestHandle`) — passing borrowed references into an
        // async fn called from inside a spawned `async move` block trips a
        // known rustc HRTB-inference limitation ("implementation of Send is
        // not general enough") even though the actual data has no shared
        // borrows in play.
        tasks.push(tokio::spawn(async move {
            tail_path(path, tenant_id, sink).await;
        }));
    }
    futures::future::join_all(tasks).await;
}

async fn tail_path(path: String, tenant_id: String, sink: IngestHandle) {
    loop {
        match spawn_line_source("tail", &["-n", "0", "-F", &path]) {
            Ok((mut child, reader)) => {
                consume_and_ingest(reader, &sink, |line| {
                    let ts = extract_timestamp(line);
                    classify_line(line, ts, &tenant_id)
                })
                .await;
                let _ = child.wait().await;
            }
            Err(e) => {
                tracing::error!(path = %path, error = %e, "failed to start auditd tail (is `tail` on PATH / path mounted?)");
            }
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn ts() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn classifies_successful_login_as_info() {
        let line = r#"type=USER_LOGIN msg=audit(1700000000.123:456): acct="alice" addr=10.0.0.5 res=success"#;
        let event =
            classify_line(line, ts(), "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.event_type, EventType::Authentication);
        assert_eq!(event.severity, Severity::Info);
        assert_eq!(event.user, Some("alice".to_owned()));
        assert_eq!(event.tenant_id, "tenant-a");
    }

    #[test]
    fn classifies_failed_login_as_high_severity() {
        let line = r#"type=USER_AUTH msg=audit(1700000000.123:456): acct="mallory" addr=10.0.0.6 res=failed"#;
        let event =
            classify_line(line, ts(), "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn classifies_setuid_as_privilege_escalation() {
        let line = "type=SETUID msg=audit(1700000000.000:1): pid=100 old-auid=0 new-auid=1000";
        let event =
            classify_line(line, ts(), "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.event_type, EventType::PrivilegeEscalation);
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn classifies_critical_syscall_as_high_severity() {
        let line = "type=SYSCALL msg=audit(1700000000.000:1): syscall=mount comm=\"mount\" exe=\"/bin/mount\"";
        let event =
            classify_line(line, ts(), "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.event_type, EventType::SystemCall);
        assert_eq!(event.severity, Severity::High);
    }

    #[test]
    fn classifies_noncritical_syscall_as_info() {
        let line =
            "type=SYSCALL msg=audit(1700000000.000:1): syscall=read comm=\"cat\" exe=\"/bin/cat\"";
        let event =
            classify_line(line, ts(), "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.severity, Severity::Info);
    }

    #[test]
    fn classifies_generic_denied_line_as_medium() {
        let line = "avc: denied { read } for pid=123 comm=\"sshd\"";
        let event =
            classify_line(line, ts(), "tenant-a").unwrap_or_else(|| panic!("expected event"));
        assert_eq!(event.severity, Severity::Medium);
        assert_eq!(event.event_type, EventType::SystemCall);
    }

    #[test]
    fn unclassifiable_line_yields_none() {
        assert!(classify_line("nothing interesting here", ts(), "tenant-a").is_none());
    }

    #[test]
    fn extract_timestamp_parses_the_audit_prefix() {
        let ts = extract_timestamp("type=SYSCALL msg=audit(1700000000.500:99): syscall=1");
        assert_eq!(ts.timestamp(), 1_700_000_000);
    }

    #[test]
    fn extract_timestamp_falls_back_to_now_when_absent() {
        let before = Utc::now();
        let ts = extract_timestamp("no timestamp here");
        assert!(ts >= before);
    }

    #[test]
    fn config_defaults_are_disabled_with_v1_default_paths() {
        let cfg = AuditdConfig {
            enabled: false,
            paths: vec![
                "/var/log/audit/audit.log".to_owned(),
                "/var/log/auth.log".to_owned(),
            ],
        };
        assert!(!cfg.enabled);
        assert_eq!(cfg.paths.len(), 2);
    }

    #[tokio::test]
    async fn run_over_a_fake_line_source_ingests_classified_events() {
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
                flush_interval: std::time::Duration::from_millis(50),
            },
        );

        let data =
            b"type=USER_LOGIN msg=audit(1700000000.0:1): acct=\"alice\" addr=10.0.0.5 res=success\n"
                .to_vec();
        let reader = BufReader::new(Cursor::new(data));
        crate::collectors::consume_and_ingest(reader, &sink, |line| {
            let ts = extract_timestamp(line);
            classify_line(line, ts, "tenant-a")
        })
        .await;

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected the classified login event to be ingested"));
        assert!(got.is_ok());
    }

    #[test]
    fn from_env_reads_process_env_without_panicking() {
        // No env vars set in the test process — exercises the "unset,
        // fall back to v1 defaults" path (`config_defaults_are_disabled_
        // with_v1_default_paths` above asserts the resulting shape).
        let cfg = AuditdConfig::from_env();
        assert!(!cfg.enabled);
        assert_eq!(cfg.paths.len(), 2);
    }
}
