//! Process creation/termination collector — Rust port of v1
//! `internal/collectors/process.go`, using `sysinfo` in place of gopsutil
//! (both wrap the same per-OS process-table syscalls: `/proc` on Linux,
//! `EnumProcesses`/`NtQuerySystemInformation` on Windows, `sysctl`/libproc
//! on macOS).
//!
//! Polls the process table on a fixed interval, diffs against the previous
//! snapshot, and emits high-severity events for known attacker tooling
//! names or processes running as root/SYSTEM. `config.exclude` is honored
//! (v1 shipped `exclude: ["endpoint-agent", "systemd", "init"]` in its default
//! YAML but never wired it up, so the agent noisily reported its own
//! startup as a "suspicious" process on every deployment — fixed here).
//! `config.watch` only ever ADDS to the built-in high-severity name list,
//! never replaces it.

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use sysinfo::{Pid, ProcessesToUpdate, System, Users};
use tokio::sync::mpsc::Sender;

use crate::collectors::{
    CollectedEvent, EVENT_TYPE_PROCESS, Severity, ShutdownFlag, emit, sleep_responsive,
};
use crate::config::ProcessCollectorConfig;

/// v1 `determineProcessSeverity` hardcoded attacker-tool names — the
/// authoritative floor; `config.watch` can only add to this set.
pub const BUILTIN_SUSPICIOUS_NAMES: &[&str] = &[
    "mimikatz",
    "psexec",
    "powershell",
    "cmd",
    "nc",
    "netcat",
    "nmap",
    "whoami",
];

#[derive(Clone, Debug, PartialEq)]
struct ProcInfo {
    name: String,
    cmdline: String,
    username: String,
    start_time: u64,
}

fn determine_severity(info: &ProcInfo, watch: &[String]) -> Severity {
    let name_lower = info.name.to_lowercase();
    let is_watched = BUILTIN_SUSPICIOUS_NAMES.iter().any(|n| *n == name_lower)
        || watch.iter().any(|w| w.to_lowercase() == name_lower);
    if is_watched {
        return Severity::High;
    }
    if info.username == "root" || info.username.eq_ignore_ascii_case("SYSTEM") {
        return Severity::Medium;
    }
    Severity::Low
}

fn snapshot(sys: &mut System, users: &Users) -> HashMap<Pid, ProcInfo> {
    sys.refresh_processes(ProcessesToUpdate::All, true);
    sys.processes()
        .iter()
        .map(|(pid, proc_)| {
            let username = proc_
                .user_id()
                .and_then(|uid| users.get_user_by_id(uid))
                .map(|u| u.name().to_owned())
                .unwrap_or_default();
            let cmdline = proc_
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            (
                *pid,
                ProcInfo {
                    name: proc_.name().to_string_lossy().into_owned(),
                    cmdline,
                    username,
                    start_time: proc_.start_time(),
                },
            )
        })
        .collect()
}

/// Runs the process collector loop until `shutdown` is set. Intended to be
/// spawned via `tokio::task::spawn_blocking` — `sysinfo` performs blocking
/// syscalls and must never run on an async worker thread.
pub fn run(cfg: ProcessCollectorConfig, tx: Sender<CollectedEvent>, shutdown: ShutdownFlag) {
    let mut sys = System::new_all();
    let users = Users::new_with_refreshed_list();
    let poll = cfg.poll_duration();
    let exclude: Vec<String> = cfg.exclude.iter().map(|s| s.to_lowercase()).collect();

    let mut known = snapshot(&mut sys, &users);

    while !shutdown.load(Ordering::Relaxed) {
        sleep_responsive(poll, &shutdown);
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        let current = snapshot(&mut sys, &users);

        for (pid, info) in &current {
            if exclude.contains(&info.name.to_lowercase()) {
                continue;
            }
            if !known.contains_key(pid) {
                let severity = determine_severity(info, &cfg.watch);
                emit(
                    &tx,
                    EVENT_TYPE_PROCESS,
                    severity,
                    serde_json::json!({
                        "action": "created",
                        "pid": pid.as_u32(),
                        "name": info.name,
                        "cmdline": info.cmdline,
                        "username": info.username,
                        "create_time": info.start_time,
                    }),
                );
            }
        }

        for (pid, info) in &known {
            if current.contains_key(pid) || exclude.contains(&info.name.to_lowercase()) {
                continue;
            }
            emit(
                &tx,
                EVENT_TYPE_PROCESS,
                Severity::Info,
                serde_json::json!({
                    "action": "terminated",
                    "pid": pid.as_u32(),
                    "name": info.name,
                    "username": info.username,
                }),
            );
        }

        known = current;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_names_trigger_high_severity() {
        let info = ProcInfo {
            name: "powershell".to_owned(),
            cmdline: String::new(),
            username: "alice".to_owned(),
            start_time: 0,
        };
        assert_eq!(determine_severity(&info, &[]), Severity::High);
    }

    #[test]
    fn watch_list_adds_without_replacing_builtin() {
        let info = ProcInfo {
            name: "sneaky-tool".to_owned(),
            cmdline: String::new(),
            username: "alice".to_owned(),
            start_time: 0,
        };
        assert_eq!(determine_severity(&info, &[]), Severity::Low);
        let watched = vec!["sneaky-tool".to_owned()];
        assert_eq!(determine_severity(&info, &watched), Severity::High);

        // Builtin name still flags High even with an unrelated watch list.
        let mimikatz = ProcInfo {
            name: "mimikatz".to_owned(),
            ..info.clone()
        };
        assert_eq!(determine_severity(&mimikatz, &watched), Severity::High);
    }

    #[test]
    fn root_process_is_medium_severity() {
        let info = ProcInfo {
            name: "some-daemon".to_owned(),
            cmdline: String::new(),
            username: "root".to_owned(),
            start_time: 0,
        };
        assert_eq!(determine_severity(&info, &[]), Severity::Medium);
    }

    #[test]
    fn ordinary_process_is_low_severity() {
        let info = ProcInfo {
            name: "vim".to_owned(),
            cmdline: String::new(),
            username: "alice".to_owned(),
            start_time: 0,
        };
        assert_eq!(determine_severity(&info, &[]), Severity::Low);
    }
}
