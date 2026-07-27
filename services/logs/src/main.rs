//! SkausWatch logs entry point — the SIEM HTTP ingest endpoint the
//! manager's siem router proxies to (`LOGS_URL`). `serve` (default)
//! runs `POST /ingest` + `GET /healthz` on `HTTP_PORT`, applies the OpenSearch
//! ISM policy at startup, and exposes Prometheus metrics on :9090.
//! `healthcheck` is the container-native probe (no curl in images).
//!
//! Scope note: this port covers the HTTP→OpenSearch path that the manager
//! contract depends on. The v1 secondary paths — the S3/Parquet mirror sink,
//! the `skauswatch:logs:ingest` Redis-stream consumer, and the syslog-UDP
//! listener — are deferred; see docs/v2-port/logs-contract.md.

mod config;
mod ingest;
mod jsonord;
mod ocsf;
mod opensearch;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::ingest::{AppState, Clock};

/// SkausWatch logs service.
#[derive(Parser)]
#[command(name = "skauswatch-logs", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

/// Top-level subcommands.
#[derive(Subcommand)]
enum Command {
    /// Run the service (default).
    Serve,
    /// Probe the local /healthz endpoint and exit 0/1 (container HEALTHCHECK).
    Healthcheck,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Healthcheck => healthcheck().await,
    }
}

/// Runs the ingest HTTP server and the metrics exporter until a shutdown signal.
async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-logs");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let cfg = Config::from_env().map_err(|e| anyhow::anyhow!("config: {e}"))?;
    let http = reqwest::Client::builder()
        .build()
        .map_err(|e| anyhow::anyhow!("http client: {e}"))?;

    // v1 `ensure_ism_policy` at startup — best-effort; errors are swallowed so
    // the service still serves ingest when OpenSearch is briefly unavailable.
    opensearch::ensure_ism_policy(&http, &cfg.opensearch_url, cfg.log_retention_days).await;

    let state = AppState {
        http: http.clone(),
        opensearch_url: cfg.opensearch_url.clone().into(),
        clock: Clock::System,
    };
    let app = ingest::router(state);

    let addr: SocketAddr = ([0, 0, 0, 0], cfg.http_port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, opensearch = %cfg.opensearch_url, "logs ingest listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    tracing::info!("logs stopped cleanly");
    Ok(())
}

/// Resolves on SIGTERM/SIGINT (Ctrl-C), gating graceful shutdown.
async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut term =
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(error = %e, "failed to install SIGTERM handler");
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
        let _ = ctrl_c.await;
    }
    tracing::info!("shutdown signal received");
}

/// Container-native health probe: GET the local /healthz and exit 0/1.
async fn healthcheck() -> anyhow::Result<()> {
    let port = std::env::var("HTTP_PORT")
        .ok()
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or(5010u16);
    let url = format!("http://127.0.0.1:{port}/healthz");
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await?;
    if resp.status().is_success() {
        Ok(())
    } else {
        anyhow::bail!("healthcheck failed: {}", resp.status())
    }
}
