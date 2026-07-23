//! SkausWatch manager service entry point. `serve` (default) runs the REST
//! /api/v1 + health/metrics stack and the v1-parity gRPC control plane;
//! `healthcheck` is the container-native health probe (no curl in images,
//! per container standards).

mod auth;
mod error;
mod flags;
mod grpc;
mod health;
mod routes;
mod state;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};

/// SkausWatch manager service.
#[derive(Parser)]
#[command(name = "skauswatch-manager", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

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

/// Default REST port — parity with the v1 Quart manager (env `API_PORT`).
const DEFAULT_HTTP_PORT: u16 = 5000;

fn http_port() -> u16 {
    std::env::var("API_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_HTTP_PORT)
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-manager");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let readiness = skauswatch_telemetry::Readiness::new();
    let state = state::AppStateInner::from_env().await?;

    // License/flag refresh loop — fail-safe by design; startup never blocks
    // on the license server.
    let _license_bg = state.license.spawn_refresh();

    // v1-shape /healthz (DB + Redis probes) replaces the generic telemetry
    // health router; /readyz keeps the readiness gate.
    let app = routes::router(state.clone()).merge(health::router(state.clone(), readiness.clone()));

    let addr: SocketAddr = ([0, 0, 0, 0], http_port()).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "manager REST listening");
    readiness.set_ready();

    // One signal fans out to both servers so REST and gRPC shut down
    // together (v1 cancelled its gRPC task alongside hypercorn).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let http = async {
        axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()))
            .await
            .map_err(anyhow::Error::from)
    };

    if grpc::enabled() {
        let grpc_fut = grpc::serve(state.clone(), wait_for_shutdown(shutdown_rx.clone()));
        tokio::try_join!(http, grpc_fut)?;
    } else {
        // v1 `GRPC_ENABLED=false` path: REST only.
        tracing::info!("gRPC server disabled");
        http.await?;
    }
    Ok(())
}

/// Resolves once the shutdown broadcast fires (or its sender is dropped),
/// gating graceful shutdown for both the REST and gRPC servers.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

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

async fn healthcheck() -> anyhow::Result<()> {
    let url = format!("http://127.0.0.1:{}/healthz", http_port());
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
