//! SkausWatch CodeScan AI-code-review backend entry point. `serve` (default)
//! runs the `/api/v1/codescan` + `/api/v1/credentials` REST surface and the
//! standard health/version endpoints; `healthcheck` is the container-native
//! health probe (no curl in images, per container standards). Rust port of
//! `darwin/services/flask-backend`.

mod auth;
mod dt;
mod error;
mod health;
mod routes;
mod state;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};

/// SkausWatch CodeScan backend service.
#[derive(Parser)]
#[command(name = "skauswatch-codescan-backend", version)]
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
    /// Print the generated OpenAPI 3.x spec (YAML) to stdout and exit.
    /// Regenerates `openapi/v1.yaml`: `codescan-backend openapi > openapi/v1.yaml`.
    Openapi,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Healthcheck => healthcheck().await,
        Command::Openapi => print_openapi(),
    }
}

/// Emits the aggregated OpenAPI document as YAML — the source of truth for
/// `openapi/v1.yaml` (see `routes::openapi::ApiDoc` and
/// `docs/v2-port/openapi-pattern.md`). Generated, never hand-edited.
fn print_openapi() -> anyhow::Result<()> {
    use utoipa::OpenApi;
    let yaml = routes::openapi::ApiDoc::openapi()
        .to_yaml()
        .map_err(|e| anyhow::anyhow!("serialize openapi spec: {e}"))?;
    print!("{yaml}");
    Ok(())
}

/// Default REST port for the CodeScan backend (env `API_PORT`). Matches the
/// `WORKER_CODESCAN_URL` default port the manager proxies to
/// (services/manager/src/routes/codescan.rs).
const DEFAULT_HTTP_PORT: u16 = 5005;

fn http_port() -> u16 {
    std::env::var("API_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_HTTP_PORT)
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-codescan-backend");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let readiness = skauswatch_telemetry::Readiness::new();
    let state = state::AppStateInner::from_env().await?;

    // License/flag refresh loop — fail-safe by design; startup never blocks
    // on the license server.
    let _license_bg = state.license.spawn_refresh();

    let app = routes::router(state.clone())
        .merge(health::router(state.clone(), readiness.clone()))
        .fallback(error::fallback_not_found);

    let addr: SocketAddr = ([0, 0, 0, 0], http_port()).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "codescan-backend REST listening");
    readiness.set_ready();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    // `into_make_service_with_connect_info` (rather than plain `app`) is
    // required by `routes::router`'s `GovernorLayer` (rate limiting, see
    // that module's docs): its `PeerIpKeyExtractor` reads the peer address
    // from the `ConnectInfo<SocketAddr>` extension this populates — without
    // it every request would fail closed with 500
    // (`GovernorError::UnableToExtractKey`).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
    .await?;
    tracing::info!("codescan-backend stopped cleanly");
    Ok(())
}

/// Resolves once the shutdown broadcast fires (or its sender is dropped).
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
