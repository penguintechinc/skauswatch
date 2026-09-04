//! Vault secrets vault REST backend. `serve` (default) runs the
//! `/api/v1` API plus health endpoints; `healthcheck` is the container-
//! native health probe (no curl in images, per container standards).

mod auth;
mod error;
mod health;
mod license_gate;
mod rate_limit;
mod routes;
mod state;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};

/// Vault secrets vault service.
#[derive(Parser)]
#[command(name = "skauswatch-vault", version)]
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
    /// Regenerates `openapi/v1.yaml`: `skauswatch-vault openapi > openapi/v1.yaml`.
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

/// Default REST port — matches v1 `PORT` default.
const DEFAULT_HTTP_PORT: u16 = 8080;

fn http_port() -> u16 {
    std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_HTTP_PORT)
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-vault");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let state = state::AppStateInner::from_env().await?;
    let _license_bg = state.license.spawn_refresh();

    // `rate_limit::apply` (not applied inside `routes::router` itself) —
    // see `crate::rate_limit` module docs for why the two stay separate.
    let app = rate_limit::apply(routes::router(state.clone()))
        .merge(health::router(state.clone()))
        .fallback(error::fallback_not_found);

    let addr: SocketAddr = ([0, 0, 0, 0], http_port()).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "vault REST listening");

    // `into_make_service_with_connect_info` — `tower_governor`'s
    // `SmartIpKeyExtractor` (`crate::rate_limit`) falls back to the TCP
    // peer address when no forwarded-for header is present.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
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
