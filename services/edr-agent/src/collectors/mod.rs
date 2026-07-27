//! Shared collector types — Rust port of v1's `internal/collectors` package.
//! Each collector runs its own OS-polling loop on a blocking thread (spawned
//! via `tokio::task::spawn_blocking`, since process/file/network enumeration
//! are all blocking syscalls) and emits `CollectedEvent`s on a shared
//! channel that `Agent` batches and reports to the manager.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use tokio::sync::mpsc::Sender;
use tracing::warn;

pub mod file;
pub mod network;
pub mod process;

/// Severity levels — string values match v1's `ThreatLevel` exactly
/// (critical/high/medium/low/info), the enum the manager validates against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Informational only (e.g. a routine process/connection termination).
    Info,
    /// Low — ordinary, unremarkable activity.
    Low,
    /// Medium — activity that warrants attention (root process, external IP).
    Medium,
    /// High — matches a known attacker-tooling signature.
    High,
    /// Critical — a known critical system file changed.
    Critical,
}

impl Severity {
    /// The wire string the manager's `ThreatLevel` enum accepts.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// Process collector event type — matches v1's `EventTypeProcess`.
pub const EVENT_TYPE_PROCESS: &str = "process";
/// File collector event type — matches v1's `EventTypeFile`.
pub const EVENT_TYPE_FILE: &str = "file";
/// Network collector event type — matches v1's `EventTypeNetwork`.
pub const EVENT_TYPE_NETWORK: &str = "network";

/// A single collected system event, queued for the reporting pipeline to
/// translate into the manager's wire format.
#[derive(Debug, Clone)]
pub struct CollectedEvent {
    /// One of `EVENT_TYPE_PROCESS`/`EVENT_TYPE_FILE`/`EVENT_TYPE_NETWORK`.
    pub event_type: &'static str,
    /// When the collector observed this event.
    pub timestamp: SystemTime,
    /// Assigned severity.
    pub severity: Severity,
    /// Collector-specific detail payload.
    pub data: serde_json::Value,
}

/// Sleeps for `total`, checking `shutdown` every 200ms so a collector loop
/// reacts to shutdown promptly instead of blocking for the full interval —
/// the blocking-thread analogue of Go's `select { case <-ticker.C: ...;
/// case <-stopChan: return }`.
pub fn sleep_responsive(total: Duration, shutdown: &AtomicBool) {
    let step = Duration::from_millis(200);
    let mut waited = Duration::ZERO;
    while waited < total {
        if shutdown.load(Ordering::Relaxed) {
            return;
        }
        let chunk = step.min(total - waited);
        std::thread::sleep(chunk);
        waited += chunk;
    }
}

/// Sends a collected event, dropping (with a warning) if the channel is
/// full or the receiver has gone away — matches v1's
/// `select { case c.events <- event: default: log warn }` non-blocking
/// semantics exactly (never backpressures the OS-polling loop).
pub fn emit(
    tx: &Sender<CollectedEvent>,
    event_type: &'static str,
    severity: Severity,
    data: serde_json::Value,
) {
    let event = CollectedEvent {
        event_type,
        timestamp: SystemTime::now(),
        severity,
        data,
    };
    if tx.try_send(event).is_err() {
        warn!(event_type, "event channel full or closed, dropping event");
    }
}

/// Convenience alias used by collector loops for their shutdown flag.
pub type ShutdownFlag = Arc<AtomicBool>;
