//! SkausWatch SSH CA service entry point. `serve` (default) runs the REST
//! `/api/v1/ssh` surface plus the standard health/metrics endpoints;
//! `healthcheck` is the container-native probe (no curl in images, per
//! container standards).
//!
//! Security note: this service holds an SSH CA signing key. The private key is
//! never logged — only its algorithm and public SHA256 fingerprint are.

mod ca;
mod config;
mod error;
mod model;
mod routes;
mod store;

use std::net::SocketAddr;
use std::sync::Arc;

use clap::{Parser, Subcommand};

use crate::ca::SshCa;
use crate::config::SshCaConfig;
use crate::routes::AppState;
use crate::store::CertStore;

/// SkausWatch SSH CA service.
#[derive(Parser)]
#[command(name = "skauswatch-ssh-ca", version)]
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

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-ssh-ca");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    // Fails fast (before any CA key material is touched) if JWT_SECRET_KEY
    // is missing in production — see skauswatch_auth::load_jwt_secret and
    // finding #2 (this service previously had no authentication at all).
    let jwt_secret: Arc<str> = skauswatch_auth::load_jwt_secret()?.into();

    let cfg = SshCaConfig::from_env();
    tracing::info!(
        port = cfg.http_port,
        ca_key_path = %cfg.ca_key_path.display(),
        ssh_ca_dir = %cfg.ssh_ca_dir.display(),
        ssh_keys_dir = %cfg.ssh_keys_dir.display(),
        "starting SSH CA service"
    );

    let ca = Arc::new(SshCa::load_or_generate(&cfg.ca_key_path)?);
    tracing::info!(ca_fingerprint = %ca.fingerprint(), "CA ready");
    let store = Arc::new(CertStore::new());
    let state = AppState {
        ca,
        store,
        jwt_secret,
    };

    let readiness = skauswatch_telemetry::Readiness::new();
    let app = routes::router(state)
        .merge(skauswatch_telemetry::health_router(readiness.clone()))
        .fallback(error::fallback_not_found);

    let addr: SocketAddr = ([0, 0, 0, 0], cfg.http_port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "SSH CA REST listening");
    readiness.set_ready();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
        .await?;
    tracing::info!("SSH CA service stopped cleanly");
    Ok(())
}

/// Resolves once the shutdown broadcast fires, gating graceful shutdown.
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
    let port = std::env::var("SERVICE_PORT")
        .or_else(|_| std::env::var("API_PORT"))
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(config::DEFAULT_HTTP_PORT);
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
