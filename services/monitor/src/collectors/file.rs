//! File-based log collector: polls host-mounted log files for new content
//! and classifies each new line. Rust port of v1 `collectors/
//! file_collector.py`'s **polling** path specifically — v1 also offered an
//! `inotify`-backed (`watchdog`) push path, but its own polling loop ran
//! unconditionally alongside inotify ("for network mounts or fallback") and
//! is the one v1 code path guaranteed to observe every change regardless of
//! filesystem/mount type (network-mounted log volumes, the deployment case
//! this collector exists for, don't reliably support inotify at all). This
//! port keeps that always-correct path rather than adding an inotify crate
//! dependency for a redundant fast-path — documented scope choice, not a
//! silent gap.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};

use crate::ingest::IngestHandle;
use crate::models::{BaseEvent, EventType, LogSource, Severity};

/// Config for the file collector, loaded from `MONITOR_COLLECTOR_FILE_*`.
#[derive(Debug, Clone)]
pub struct FileConfig {
    /// `MONITOR_COLLECTOR_FILE_ENABLED` — off by default (needs host log
    /// mounts, see `collectors/mod.rs` deployment-requirement note).
    pub enabled: bool,
    /// `MONITOR_COLLECTOR_FILE_MOUNT_POINTS` (comma-separated directories).
    pub mount_points: Vec<String>,
    /// `MONITOR_COLLECTOR_FILE_PATTERNS` (comma-separated `*.ext` globs);
    /// v1 default `["*.log", "*.txt"]`.
    pub patterns: Vec<String>,
    /// `MONITOR_COLLECTOR_FILE_POLL_INTERVAL_SECS`; v1 default 30s.
    pub poll_interval: Duration,
}

impl FileConfig {
    /// Loads from env. Never fails.
    pub fn from_env() -> Self {
        let enabled = std::env::var("MONITOR_COLLECTOR_FILE_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        let mount_points = std::env::var("MONITOR_COLLECTOR_FILE_MOUNT_POINTS")
            .ok()
            .map(|raw| split_csv(&raw))
            .unwrap_or_default();
        let patterns = std::env::var("MONITOR_COLLECTOR_FILE_PATTERNS")
            .ok()
            .map(|raw| split_csv(&raw))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec!["*.log".to_owned(), "*.txt".to_owned()]);
        let poll_interval = std::env::var("MONITOR_COLLECTOR_FILE_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .unwrap_or(Duration::from_secs(30));
        Self {
            enabled,
            mount_points,
            patterns,
            poll_interval,
        }
    }
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Simple `*.ext` suffix glob (the only shape v1's default patterns use);
/// an exact-name pattern with no `*` matches literally.
pub(crate) fn glob_matches(pattern: &str, file_name: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(ext) => file_name.ends_with(&format!(".{ext}")),
        None => file_name == pattern,
    }
}

/// Recursively finds every file under `mount_points` whose name matches one
/// of `patterns` — v1 `_discover_log_files` (`Path.rglob`).
pub(crate) fn discover_files(mount_points: &[String], patterns: &[String]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for mount_point in mount_points {
        for entry in walkdir::WalkDir::new(mount_point)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let name = entry.file_name().to_string_lossy();
            if patterns.iter().any(|p| glob_matches(p, &name)) {
                found.push(entry.path().to_path_buf());
            }
        }
    }
    found
}

/// v1 `_extract_timestamp_from_line`: the ISO-8601 case only (the common
/// case for structured application logs) — v1's syslog/apache/`YYYY/MM/DD`
/// alternates are not reproduced (a documented, narrower scope: any line
/// without a leading ISO timestamp falls back to "now", same as v1's own
/// final fallback).
pub(crate) fn extract_timestamp(line: &str) -> DateTime<Utc> {
    if let Some(word) = line.split_whitespace().next()
        && let Ok(dt) = DateTime::parse_from_rfc3339(word)
    {
        return dt.with_timezone(&Utc);
    }
    Utc::now()
}

/// v1 `_classify_log_line`: severity from log-level keywords, then event
/// type from the first matching keyword group (auth > security > network >
/// process), falling back to a generic "accounting" event only when
/// severity is at least Medium — an unclassified Info/Low line yields no
/// event at all (matches v1: it never emits a generic event for routine
/// output, only for lines that also look like a problem).
pub fn classify_log_line(
    line: &str,
    file_name: &str,
    mount_point: &str,
    timestamp: DateTime<Utc>,
    tenant_id: &str,
) -> Option<BaseEvent> {
    let lower = line.to_ascii_lowercase();
    let severity = if contains_any(&lower, &["critical", "fatal", "emergency"]) {
        Severity::Critical
    } else if contains_any(&lower, &["error", "err"]) {
        Severity::High
    } else if contains_any(&lower, &["warning", "warn"]) {
        Severity::Medium
    } else if contains_any(&lower, &["debug"]) {
        Severity::Low
    } else {
        Severity::Info
    };

    let event_type = if contains_any(
        &lower,
        &["login", "authentication", "password", "ssh", "sudo"],
    ) {
        Some(EventType::Authentication)
    } else if contains_any(
        &lower,
        &["denied", "blocked", "firewall", "intrusion", "attack"],
    ) {
        Some(EventType::SecurityViolation)
    } else if contains_any(&lower, &["connection", "network", "tcp", "udp", "port"]) {
        Some(EventType::Network)
    } else if contains_any(
        &lower,
        &["started", "stopped", "crashed", "exception", "stack trace"],
    ) {
        Some(EventType::Process)
    } else if matches!(
        severity,
        Severity::Critical | Severity::High | Severity::Medium
    ) {
        Some(EventType::Accounting)
    } else {
        None
    };

    let event_type = event_type?;
    Some(BaseEvent {
        id: uuid::Uuid::new_v4().to_string(),
        source: LogSource::System,
        event_type,
        severity,
        message: line.to_owned(),
        timestamp,
        raw_data: serde_json::json!({"file_path": file_name, "mount_point": mount_point}),
        tags: vec!["file".to_owned(), file_name.to_owned()],
        host: String::new(),
        user: None,
        process: None,
        pid: None,
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

/// Reads any bytes appended to `path` since `positions[path]` (or, for a
/// newly-seen file, since its current size — v1 starts tailing new content
/// only, no backfill), classifying and ingesting each new line. Handles
/// rotation (current size < recorded position) by restarting from 0.
pub(crate) async fn poll_file(
    path: &Path,
    positions: &mut HashMap<PathBuf, u64>,
    tenant_id: &str,
    sink: &IngestHandle,
) {
    let Ok(metadata) = tokio::fs::metadata(path).await else {
        return;
    };
    let size = metadata.len();
    let pos = positions.entry(path.to_path_buf()).or_insert(size);
    if size < *pos {
        tracing::info!(path = %path.display(), "log file appears to have been rotated");
        *pos = 0;
    }
    if size <= *pos {
        return;
    }

    let Ok(mut file) = tokio::fs::File::open(path).await else {
        return;
    };
    if file.seek(SeekFrom::Start(*pos)).await.is_err() {
        return;
    }
    let mut buf = Vec::new();
    if file.read_to_end(&mut buf).await.is_err() {
        return;
    }
    *pos = size;

    let text = String::from_utf8_lossy(&buf);
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mount_point = path
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let ts = extract_timestamp(line);
        if let Some(event) = classify_log_line(line, &file_name, &mount_point, ts, tenant_id) {
            sink.ingest(event).await;
        }
    }
}

/// Poll loop: rediscovers matching files and polls each for new content
/// every `cfg.poll_interval` — rediscovery-on-every-tick subsumes v1's
/// separate "periodic rediscovery" task (new files matching a pattern are
/// picked up on the very next poll, not after a fixed 5-minute delay).
pub async fn run(cfg: FileConfig, tenant_id: String, sink: IngestHandle) {
    let mut positions: HashMap<PathBuf, u64> = HashMap::new();
    loop {
        for path in discover_files(&cfg.mount_points, &cfg.patterns) {
            poll_file(&path, &mut positions, &tenant_id, &sink).await;
        }
        tokio::time::sleep(cfg.poll_interval).await;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::io::Write;

    fn ts() -> DateTime<Utc> {
        Utc::now()
    }

    #[test]
    fn glob_matches_extension_patterns() {
        assert!(glob_matches("*.log", "syslog.log"));
        assert!(!glob_matches("*.log", "syslog.txt"));
        assert!(glob_matches("app.log", "app.log"));
        assert!(!glob_matches("app.log", "other.log"));
    }

    #[test]
    fn discover_files_finds_matching_files_recursively() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap_or_else(|e| panic!("mkdir: {e}"));
        std::fs::write(dir.path().join("a.log"), "x").unwrap_or_else(|e| panic!("write: {e}"));
        std::fs::write(sub.join("b.log"), "y").unwrap_or_else(|e| panic!("write: {e}"));
        std::fs::write(dir.path().join("ignore.bin"), "z").unwrap_or_else(|e| panic!("write: {e}"));

        let found = discover_files(
            &[dir.path().to_string_lossy().into_owned()],
            &["*.log".to_owned()],
        );
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn extract_timestamp_parses_leading_rfc3339() {
        let ts = extract_timestamp("2026-07-01T12:00:00Z something happened");
        let expected = DateTime::parse_from_rfc3339("2026-07-01T12:00:00Z")
            .unwrap_or_else(|e| panic!("expected parse: {e}"))
            .with_timezone(&Utc);
        assert_eq!(ts, expected);
    }

    #[test]
    fn extract_timestamp_falls_back_to_now() {
        let before = Utc::now();
        let ts = extract_timestamp("no timestamp prefix here");
        assert!(ts >= before);
    }

    #[test]
    fn classify_critical_keyword_is_critical_severity() {
        let e = classify_log_line("FATAL: disk full", "app.log", "/var/log", ts(), "tenant-a")
            .unwrap_or_else(|| panic!("expected event"));
        assert_eq!(e.severity, Severity::Critical);
        assert_eq!(e.event_type, EventType::Accounting);
    }

    #[test]
    fn classify_auth_keyword_wins_over_generic_severity() {
        let e = classify_log_line(
            "failed ssh login attempt",
            "auth.log",
            "/var/log",
            ts(),
            "tenant-a",
        )
        .unwrap_or_else(|| panic!("expected event"));
        assert_eq!(e.event_type, EventType::Authentication);
    }

    #[test]
    fn classify_security_keyword() {
        let e = classify_log_line(
            "connection denied by firewall",
            "app.log",
            "/var/log",
            ts(),
            "tenant-a",
        )
        .unwrap_or_else(|| panic!("expected event"));
        assert_eq!(e.event_type, EventType::SecurityViolation);
    }

    #[test]
    fn classify_network_keyword() {
        let e = classify_log_line(
            "tcp connection reset",
            "app.log",
            "/var/log",
            ts(),
            "tenant-a",
        )
        .unwrap_or_else(|| panic!("expected event"));
        assert_eq!(e.event_type, EventType::Network);
    }

    #[test]
    fn classify_process_keyword() {
        let e = classify_log_line(
            "worker process crashed unexpectedly",
            "app.log",
            "/var/log",
            ts(),
            "tenant-a",
        )
        .unwrap_or_else(|| panic!("expected event"));
        assert_eq!(e.event_type, EventType::Process);
    }

    #[test]
    fn routine_info_line_yields_no_event() {
        assert!(
            classify_log_line("heartbeat ok", "app.log", "/var/log", ts(), "tenant-a").is_none()
        );
    }

    #[test]
    fn tenant_id_is_stamped() {
        let e = classify_log_line(
            "ERROR something broke",
            "app.log",
            "/var/log",
            ts(),
            "tenant-a",
        )
        .unwrap_or_else(|| panic!("expected event"));
        assert_eq!(e.tenant_id, "tenant-a");
    }

    #[tokio::test]
    async fn poll_file_starts_from_eof_on_first_sight_no_backfill() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let path = dir.path().join("app.log");
        std::fs::write(&path, "ERROR pre-existing line\n").unwrap_or_else(|e| panic!("write: {e}"));

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

        let mut positions = HashMap::new();
        // First poll: file already existed with content — no backfill.
        poll_file(&path, &mut positions, "tenant-a", &sink).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .is_err(),
            "must not backfill pre-existing content on first sight"
        );

        // Append new content — the next poll must pick it up.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap_or_else(|e| panic!("open: {e}"));
            writeln!(f, "ERROR new line after first poll").unwrap_or_else(|e| panic!("write: {e}"));
        }
        poll_file(&path, &mut positions, "tenant-a", &sink).await;
        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected the appended line to be ingested"));
        assert!(got.is_ok());
    }

    #[tokio::test]
    async fn poll_file_handles_rotation_by_restarting_from_zero() {
        let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("tempdir: {e}"));
        let path = dir.path().join("app.log");
        std::fs::write(&path, "ERROR line one\nERROR line two\n")
            .unwrap_or_else(|e| panic!("write: {e}"));

        let mut positions = HashMap::new();
        positions.insert(path.clone(), 1_000_000u64); // pretend we were far past EOF

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
        poll_file(&path, &mut positions, "tenant-a", &sink).await;

        let got = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("expected rotation-recovery to re-read from zero"));
        assert!(got.is_ok());
    }

    #[test]
    fn from_env_reads_process_env_without_panicking() {
        let cfg = FileConfig::from_env();
        assert!(!cfg.enabled);
        assert!(cfg.mount_points.is_empty());
        assert_eq!(cfg.patterns, vec!["*.log".to_owned(), "*.txt".to_owned()]);
        assert_eq!(cfg.poll_interval, Duration::from_secs(30));
    }
}
