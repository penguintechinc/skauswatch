//! SkausWatch DepGate entry point — the OCI/docker pull-through registry
//! proxy: scan-on-ingest, content-addressed cache, verdict-as-object-tags
//! (`docs/v2-port/v2.1-depgate.md`, P1). `serve` (default) runs the `/v2/*`
//! proxy + `/api/v1/depgate/*` admin API + health/metrics; `healthcheck` is
//! the container-native probe (no curl in images); `seed` warm-starts the
//! cache from a seed manifest; `openapi` regenerates the committed spec.

mod cache;
mod config;
mod db;
mod error;
mod mesh_admin;
mod oci_path;
mod routes;
mod scanpipe;
mod seed;
mod state;
mod upstream;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};

use crate::state::AppStateInner;

/// SkausWatch DepGate server.
#[derive(Parser)]
#[command(name = "skauswatch-depgate", version)]
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
    /// Warm-starts the cache from a seed manifest (default
    /// `seeds/penguintech.yaml`) — see `docs/v2-port/v2.1-depgate.md` §2/§9.
    Seed {
        /// Path to a seed manifest (YAML).
        #[arg(long, default_value = "seeds/penguintech.yaml")]
        manifest: String,
    },
    /// Print the generated OpenAPI 3.x spec (YAML) to stdout and exit.
    /// Regenerates `openapi/v1.yaml`: `skauswatch-depgate openapi > openapi/v1.yaml`.
    Openapi,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Healthcheck => healthcheck().await,
        Command::Seed { manifest } => run_seed(&manifest).await,
        Command::Openapi => print_openapi(),
    }
}

/// Emits the aggregated OpenAPI document as YAML — the source of truth for
/// `openapi/v1.yaml` (see `routes::openapi::ApiDoc`). Generated, never
/// hand-edited.
fn print_openapi() -> anyhow::Result<()> {
    use utoipa::OpenApi as _;
    let yaml = routes::openapi::ApiDoc::openapi()
        .to_yaml()
        .map_err(|e| anyhow::anyhow!("serialize openapi spec: {e}"))?;
    print!("{yaml}");
    Ok(())
}

async fn run_seed(manifest: &str) -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-depgate");
    let state = AppStateInner::from_env().await?;
    seed::run(&state, manifest).await
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-depgate");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let readiness = skauswatch_telemetry::Readiness::new();
    let state = AppStateInner::from_env().await?;

    // License/flag refresh loop — fail-safe by design; startup never blocks
    // on the license server.
    let _license_bg = state.license.spawn_refresh();

    let http_port = state.cfg.http_port;
    let app = routes::router(state.clone())
        .merge(skauswatch_telemetry::health_router(readiness.clone()))
        .fallback(crate::error::fallback_not_found);

    let addr: SocketAddr = ([0, 0, 0, 0], http_port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "depgate listening");
    readiness.set_ready();

    // One signal fans out to both servers so the primary REST listener and
    // the mesh admin mTLS listener shut down together — mirrors
    // `services/pki/src/main.rs`'s identical REST+maintenance fan-out.
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

    // Mesh-only mTLS admin listener (SPIFFE-readiness for the admin/report
    // API, `src/mesh_admin.rs`) — always part of the join; it degrades to
    // "disabled" on its own when no SPIFFE identity is held rather than
    // needing an enabled/disabled flag here (see `mesh_admin::serve`'s docs).
    let mesh_addr: SocketAddr = ([0, 0, 0, 0], mesh_admin::port()).into();
    let mesh_fut = mesh_admin::serve(state, mesh_addr, wait_for_shutdown(shutdown_rx.clone()));

    tokio::try_join!(http, mesh_fut)?;
    tracing::info!("depgate stopped cleanly");
    Ok(())
}

/// Resolves once the shutdown broadcast fires, gating graceful shutdown —
/// mirrors `services/pki/src/main.rs`'s identical helper.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
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
    let port = std::env::var("API_PORT")
        .ok()
        .and_then(|p| p.trim().parse().ok())
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
