//! Agent orchestration — Rust port of v1 `internal/agent/agent.go`. Wires
//! together host identification, the manager `Reporter`, the three
//! collectors, and the heartbeat/event-batch loops, then runs until a
//! shutdown signal (Ctrl-C or, on Unix, SIGTERM) arrives.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sysinfo::System;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use skauswatch_common::Error;

use crate::collectors::{CollectedEvent, file, network, process};
use crate::config::AgentConfig;
use crate::transport::{EventPayload, RegisterRequest, Reporter};

/// v1's event-batch flush cadence (`eventReporterLoop`'s 5s ticker).
const EVENT_FLUSH_INTERVAL: Duration = Duration::from_secs(5);
/// v1's in-memory batch cap before an early flush
/// (`if len(batch) >= 100 { send }`) — also the manager's hard per-request
/// limit, so a flush here never needs client-side chunking.
const EVENT_BATCH_CAP: usize = crate::transport::MAX_EVENTS_PER_REQUEST;

/// Resolves the agent ID: the configured value if set, else a generated
/// `{hostname}-{pid}-{unix_timestamp}` — matches v1's `generateAgentID`.
pub fn finalize_agent_id(configured: &str, hostname: &str) -> String {
    if !configured.is_empty() {
        return configured.to_owned();
    }
    let pid = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{hostname}-{pid}-{ts}")
}

/// Best-effort local host identification. `os_type` uses
/// `std::env::consts::OS` (a compile-time-accurate "linux"/"windows"/
/// "macos") rather than v1's combined `"{OS.Name} {OS.Version}"` string,
/// which the manager's `RegisterBody` has no field for and silently
/// dropped — see `crate::transport` module docs.
pub fn host_info() -> (String, String, String) {
    let hostname = System::host_name().unwrap_or_else(|| "unknown".to_owned());
    let os_type = std::env::consts::OS.to_owned();
    let os_version = System::os_version().unwrap_or_default();
    (hostname, os_type, os_version)
}

/// Builds the `POST /endpoint/register` body — pure and directly unit-testable;
/// the async `Agent::run` is integration-tested against a mock manager.
pub fn build_register_request(
    agent_id: &str,
    hostname: &str,
    os_type: &str,
    os_version: &str,
    agent_version: &str,
    collector_names: &[&str],
) -> RegisterRequest {
    RegisterRequest {
        agent_id: agent_id.to_owned(),
        hostname: hostname.to_owned(),
        ip_address: String::new(),
        os_type: os_type.to_owned(),
        os_version: os_version.to_owned(),
        agent_version: agent_version.to_owned(),
        metadata: serde_json::json!({ "collectors": collector_names }),
    }
}

/// Enabled collector names, in the fixed order v1 checked them — used both
/// for `RegisterRequest.metadata.collectors` and collector task startup.
fn enabled_collector_names(cfg: &AgentConfig) -> Vec<&'static str> {
    let mut names = Vec::new();
    if cfg.collectors.process.enabled {
        names.push("process");
    }
    if cfg.collectors.file.enabled {
        names.push("file");
    }
    if cfg.collectors.network.enabled {
        names.push("network");
    }
    names
}

/// Runs the agent until shutdown: registers, starts collectors, and drives
/// the heartbeat and event-reporting loops. Returns once a shutdown signal
/// has been handled and all in-flight events flushed.
pub async fn run(cfg: AgentConfig) -> Result<(), Error> {
    let (hostname, os_type, os_version) = host_info();
    let agent_id = finalize_agent_id(&cfg.agent_id, &hostname);
    info!(agent_id, %hostname, manager_url = %cfg.manager_url, "starting ENDPOINT agent");

    let reporter = Reporter::new(
        cfg.manager_url.clone(),
        cfg.api_key.clone(),
        agent_id.clone(),
        &cfg.tls,
    )?;

    let collector_names = enabled_collector_names(&cfg);
    let register_req = build_register_request(
        &agent_id,
        &hostname,
        &os_type,
        &os_version,
        reporter.agent_version(),
        &collector_names,
    );
    reporter.register(&register_req).await?;
    info!(agent_id, "registered with manager");

    let shutdown = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<CollectedEvent>(cfg.event_buffer_size.max(1));

    let mut collector_handles: Vec<JoinHandle<()>> = Vec::new();
    if cfg.collectors.process.enabled {
        let (c, t, s) = (
            cfg.collectors.process.clone(),
            tx.clone(),
            Arc::clone(&shutdown),
        );
        collector_handles.push(tokio::task::spawn_blocking(move || process::run(c, t, s)));
    }
    if cfg.collectors.file.enabled {
        let (c, t, s) = (
            cfg.collectors.file.clone(),
            tx.clone(),
            Arc::clone(&shutdown),
        );
        collector_handles.push(tokio::task::spawn_blocking(move || file::run(c, t, s)));
    }
    if cfg.collectors.network.enabled {
        let (c, t, s) = (
            cfg.collectors.network.clone(),
            tx.clone(),
            Arc::clone(&shutdown),
        );
        collector_handles.push(tokio::task::spawn_blocking(move || network::run(c, t, s)));
    }
    // Drop the orchestrator's own sender clone so the channel closes once
    // every collector has stopped (each collector holds its own clone).
    drop(tx);

    let heartbeat_task = tokio::spawn(heartbeat_loop(
        reporter_for_heartbeat(&cfg, &agent_id)?,
        Duration::from_secs(cfg.heartbeat_interval.max(1)),
        Arc::clone(&shutdown),
        register_req,
    ));

    let event_task = tokio::spawn(event_loop(
        reporter_for_events(&cfg, &agent_id)?,
        rx,
        agent_id.clone(),
    ));

    wait_for_shutdown_signal().await;
    info!("shutdown signal received, stopping agent");
    shutdown.store(true, Ordering::Relaxed);

    for handle in collector_handles {
        if let Err(e) = handle.await {
            warn!(error = %e, "collector task panicked");
        }
    }
    if let Err(e) = heartbeat_task.await {
        warn!(error = %e, "heartbeat task panicked");
    }
    if let Err(e) = event_task.await {
        warn!(error = %e, "event task panicked");
    }

    info!("ENDPOINT agent stopped");
    Ok(())
}

/// Each background loop owns its own `Reporter` (cheap: one `reqwest::Client`
/// plus a few config strings) so collector, heartbeat, and event tasks never
/// share mutable state or contend on a lock.
fn reporter_for_heartbeat(cfg: &AgentConfig, agent_id: &str) -> Result<Reporter, Error> {
    Reporter::new(
        cfg.manager_url.clone(),
        cfg.api_key.clone(),
        agent_id.to_owned(),
        &cfg.tls,
    )
}

fn reporter_for_events(cfg: &AgentConfig, agent_id: &str) -> Result<Reporter, Error> {
    Reporter::new(
        cfg.manager_url.clone(),
        cfg.api_key.clone(),
        agent_id.to_owned(),
        &cfg.tls,
    )
}

/// Heartbeats on `interval` until `shutdown`. On a 404 ("Agent not
/// registered") — reachable if the manager restarted with a fresh database
/// — re-registers once and continues; v1 never self-healed here (see
/// `crate::transport` docs), but this is safe, low-risk resilience given
/// the agent already holds everything needed to re-register.
async fn heartbeat_loop(
    reporter: Reporter,
    interval: Duration,
    shutdown: Arc<AtomicBool>,
    register_req: RegisterRequest,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // first tick fires immediately; skip it like Go's ticker semantics
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if shutdown.load(Ordering::Relaxed) {
                    return;
                }
                match reporter.heartbeat("active").await {
                    Ok(true) => debug!("heartbeat ok"),
                    Ok(false) => {
                        warn!("agent not registered with manager, re-registering");
                        if let Err(e) = reporter.register(&register_req).await {
                            error!(error = %e, "re-registration failed");
                        }
                    }
                    Err(e) => warn!(error = %e, "heartbeat failed"),
                }
            }
            () = wait_while(&shutdown) => return,
        }
    }
}

/// Batches events from `rx` and flushes to the manager every
/// `EVENT_FLUSH_INTERVAL` or once `EVENT_BATCH_CAP` is reached — mirrors
/// v1's `eventReporterLoop` exactly, including draining any remainder when
/// the channel closes (agent shutdown).
async fn event_loop(reporter: Reporter, mut rx: mpsc::Receiver<CollectedEvent>, agent_id: String) {
    let mut batch: Vec<EventPayload> = Vec::with_capacity(EVENT_BATCH_CAP);
    let mut ticker = tokio::time::interval(EVENT_FLUSH_INTERVAL);
    ticker.tick().await;

    loop {
        tokio::select! {
            maybe_event = rx.recv() => {
                match maybe_event {
                    Some(event) => {
                        batch.push(EventPayload::from_collected(&agent_id, &event));
                        if batch.len() >= EVENT_BATCH_CAP {
                            flush(&reporter, &mut batch).await;
                        }
                    }
                    None => {
                        // All collectors stopped and their senders dropped.
                        flush(&reporter, &mut batch).await;
                        return;
                    }
                }
            }
            _ = ticker.tick() => {
                flush(&reporter, &mut batch).await;
            }
        }
    }
}

async fn flush(reporter: &Reporter, batch: &mut Vec<EventPayload>) {
    if batch.is_empty() {
        return;
    }
    match reporter.report_events(batch).await {
        Ok(stored) => debug!(sent = batch.len(), stored, "events reported"),
        Err(e) => warn!(error = %e, count = batch.len(), "failed to report events"),
    }
    batch.clear();
}

/// Resolves once `shutdown` becomes true — lets `tokio::select!` race a
/// timer against the shutdown flag without a dedicated broadcast channel.
async fn wait_while(shutdown: &AtomicBool) {
    while !shutdown.load(Ordering::Relaxed) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Waits for Ctrl-C, or on Unix, either Ctrl-C or SIGTERM (the signal
/// systemd sends on `systemctl stop`).
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let ctrl_c = tokio::signal::ctrl_c();
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "failed to install SIGTERM handler, Ctrl-C only");
                let _ = ctrl_c.await;
                return;
            }
        };
        tokio::select! {
            _ = ctrl_c => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finalize_agent_id_keeps_configured_value() {
        assert_eq!(finalize_agent_id("fixed-id", "host1"), "fixed-id");
    }

    #[test]
    fn finalize_agent_id_generates_when_empty() {
        let id = finalize_agent_id("", "myhost");
        assert!(id.starts_with("myhost-"));
        let parts: Vec<&str> = id.split('-').collect();
        assert!(
            parts.len() >= 3,
            "expected hostname-pid-timestamp, got {id}"
        );
    }

    #[test]
    fn register_request_shape_matches_manager_contract() {
        let req = build_register_request(
            "agent-1",
            "host1",
            "linux",
            "6.8.0",
            "2.0.0",
            &["process", "file"],
        );
        assert_eq!(req.agent_id, "agent-1");
        assert_eq!(req.hostname, "host1");
        assert_eq!(
            req.ip_address, "",
            "v1 never determined an IP; empty is the manager's own default"
        );
        assert_eq!(req.os_type, "linux");
        assert_eq!(req.os_version, "6.8.0");
        assert_eq!(req.agent_version, "2.0.0");
        assert_eq!(
            req.metadata["collectors"],
            serde_json::json!(["process", "file"])
        );
    }

    #[test]
    fn enabled_collector_names_reflects_config_order() {
        let mut cfg = AgentConfig::default();
        cfg.collectors.network.enabled = false;
        let names = enabled_collector_names(&cfg);
        assert_eq!(names, vec!["process", "file"]);
    }
}
