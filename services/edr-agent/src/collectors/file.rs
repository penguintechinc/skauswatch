//! File integrity collector — Rust port of v1
//! `internal/collectors/file.go`. Walks the configured watch paths on a
//! fixed interval, SHA-256 hashes every file under the size cap, and diffs
//! against the previous scan to emit created/modified/deleted events.
//!
//! Correctness note: v1's Go `checkFiles` built a `currentFiles` map that
//! `scanDirectory` never populated, so its deleted-file branch always took
//! the `os.Stat` fallback path (functionally correct, but dead/confusing
//! code). This port builds the current-scan map for real and diffs it
//! directly against the previous one — same observable behavior, no dead
//! code.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::Ordering;

use sha2::{Digest, Sha256};
use tokio::sync::mpsc::Sender;
use tracing::debug;
use walkdir::WalkDir;

use crate::collectors::{
    CollectedEvent, EVENT_TYPE_FILE, Severity, ShutdownFlag, emit, sleep_responsive,
};
use crate::config::FileCollectorConfig;

/// v1 `determineSeverity` hardcoded critical system paths — the
/// authoritative floor.
const BUILTIN_CRITICAL_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "C:\\Windows\\System32\\config",
];

/// v1 hardcoded executable extensions — UNION'd with
/// `config.priority_extensions`.
const BUILTIN_EXEC_EXTENSIONS: &[&str] = &[".exe", ".dll", ".so", ".sh", ".py", ".ps1"];

fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

fn determine_severity(path: &str, extra_extensions: &[String]) -> Severity {
    if BUILTIN_CRITICAL_PATHS.contains(&path) {
        return Severity::Critical;
    }
    let ext = Path::new(path)
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let ext_lower = ext.to_lowercase();
    let is_exec = BUILTIN_EXEC_EXTENSIONS.iter().any(|e| *e == ext_lower)
        || extra_extensions
            .iter()
            .any(|e| e.to_lowercase() == ext_lower);
    if is_exec {
        return Severity::High;
    }
    let parent_is_etc = Path::new(path)
        .parent()
        .map(|p| p == Path::new("/etc"))
        .unwrap_or(false);
    if parent_is_etc || ext_lower == ".conf" || ext_lower == ".cfg" {
        return Severity::Medium;
    }
    Severity::Low
}

/// Scans all watch paths, hashing every file at or under `max_size` bytes.
/// Unreadable files/dirs are skipped silently (matches v1: `filepath.Walk`
/// callback returns `nil` on any per-entry error, continuing the walk).
fn scan(watch_paths: &[String], max_size: u64) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for root in watch_paths {
        for entry in WalkDir::new(root).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.len() > max_size {
                continue;
            }
            let Ok(hash) = hash_file(entry.path()) else {
                continue;
            };
            out.insert(entry.path().to_string_lossy().into_owned(), hash);
        }
    }
    out
}

/// Runs the file collector loop until `shutdown` is set. Spawned via
/// `tokio::task::spawn_blocking` — directory walking and hashing are
/// blocking I/O.
pub fn run(cfg: FileCollectorConfig, tx: Sender<CollectedEvent>, shutdown: ShutdownFlag) {
    let poll = cfg.poll_duration();
    debug!(paths = ?cfg.watch_paths, "file collector baseline scan starting");
    let mut known = scan(&cfg.watch_paths, cfg.max_hash_size);
    debug!(files = known.len(), "file collector baseline established");

    while !shutdown.load(Ordering::Relaxed) {
        sleep_responsive(poll, &shutdown);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let current = scan(&cfg.watch_paths, cfg.max_hash_size);

        for (path, hash) in &current {
            match known.get(path) {
                None => emit(
                    &tx,
                    EVENT_TYPE_FILE,
                    determine_severity(path, &cfg.priority_extensions),
                    serde_json::json!({"action": "created", "path": path, "hash": hash}),
                ),
                Some(old_hash) if old_hash != hash => emit(
                    &tx,
                    EVENT_TYPE_FILE,
                    determine_severity(path, &cfg.priority_extensions),
                    serde_json::json!({
                        "action": "modified", "path": path,
                        "old_hash": old_hash, "new_hash": hash,
                    }),
                ),
                _ => {}
            }
        }

        for (path, old_hash) in &known {
            if !current.contains_key(path) {
                emit(
                    &tx,
                    EVENT_TYPE_FILE,
                    determine_severity(path, &cfg.priority_extensions),
                    serde_json::json!({"action": "deleted", "path": path, "old_hash": old_hash}),
                );
            }
        }

        known = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::must;
    use std::io::Write as _;

    #[test]
    fn critical_paths_are_always_critical() {
        assert_eq!(determine_severity("/etc/passwd", &[]), Severity::Critical);
        assert_eq!(determine_severity("/etc/shadow", &[]), Severity::Critical);
    }

    #[test]
    fn executable_extensions_are_high() {
        assert_eq!(determine_severity("/usr/bin/evil.sh", &[]), Severity::High);
        assert_eq!(determine_severity("/tmp/tool.exe", &[]), Severity::High);
    }

    #[test]
    fn priority_extensions_union_with_builtin() {
        assert_eq!(determine_severity("/tmp/thing.custom", &[]), Severity::Low);
        let extra = vec![".custom".to_owned()];
        assert_eq!(
            determine_severity("/tmp/thing.custom", &extra),
            Severity::High
        );
    }

    #[test]
    fn etc_config_files_are_medium() {
        assert_eq!(determine_severity("/etc/hosts", &[]), Severity::Medium);
        assert_eq!(
            determine_severity("/opt/app/app.conf", &[]),
            Severity::Medium
        );
    }

    #[test]
    fn ordinary_file_is_low() {
        assert_eq!(
            determine_severity("/home/user/notes.txt", &[]),
            Severity::Low
        );
    }

    #[test]
    fn scan_detects_create_modify_delete_via_hash_diff() {
        let dir = std::env::temp_dir().join(format!("edr-agent-test-{}", std::process::id()));
        must(std::fs::create_dir_all(&dir), "create tmp dir");
        let file_path = dir.join("a.txt");

        must(std::fs::write(&file_path, b"version-1"), "write v1");
        let first = scan(&[dir.to_string_lossy().into_owned()], 10 * 1024 * 1024);
        assert_eq!(first.len(), 1);

        must(std::fs::write(&file_path, b"version-2-longer"), "write v2");
        let second = scan(&[dir.to_string_lossy().into_owned()], 10 * 1024 * 1024);
        assert_ne!(
            first.get(&file_path.to_string_lossy().into_owned()),
            second.get(&file_path.to_string_lossy().into_owned())
        );

        must(std::fs::remove_file(&file_path), "remove");
        let third = scan(&[dir.to_string_lossy().into_owned()], 10 * 1024 * 1024);
        assert!(third.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oversized_files_are_skipped() {
        let dir = std::env::temp_dir().join(format!("edr-agent-test-big-{}", std::process::id()));
        must(std::fs::create_dir_all(&dir), "create tmp dir");
        let file_path = dir.join("big.bin");
        let mut f = must(std::fs::File::create(&file_path), "create big file");
        must(f.write_all(&[0u8; 128]), "write");
        drop(f);

        let scanned = scan(&[dir.to_string_lossy().into_owned()], 64);
        assert!(
            scanned.is_empty(),
            "file over max_hash_size must be skipped"
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
