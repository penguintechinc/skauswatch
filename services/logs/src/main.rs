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
mod openapi;
mod opensearch;
mod rate_limit;

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
    /// Print the generated OpenAPI 3.x spec (YAML) to stdout and exit.
    /// Regenerates `openapi/v1.yaml`: `skauswatch-logs openapi > openapi/v1.yaml`.
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
/// `openapi/v1.yaml` (see `openapi::ApiDoc` and
/// `docs/v2-port/openapi-pattern.md`). Generated, never hand-edited.
fn print_openapi() -> anyhow::Result<()> {
    use utoipa::OpenApi as _;
    let yaml = openapi::ApiDoc::openapi()
        .to_yaml()
        .map_err(|e| anyhow::anyhow!("serialize openapi spec: {e}"))?;
    print!("{yaml}");
    Ok(())
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

    // Fail-fast (before serving a single request) if `JWT_SECRET_KEY` is
    // missing in production — see `skauswatch_auth::load_jwt_secret`.
    // `/ingest` requires a valid bearer token verified against this secret.
    let jwt_secret = skauswatch_auth::load_jwt_secret().map_err(|e| anyhow::anyhow!("{e}"))?;

    let license_cfg = penguin_licensing::LicenseConfig::from_env("skauswatch")
        .map_err(|e| anyhow::anyhow!("license config: {e}"))?
        .with_bypass_domain("skauswatch.app");
    let license = penguin_licensing::LicenseClient::new(license_cfg)
        .map_err(|e| anyhow::anyhow!("license client: {e}"))?;
    let _ = license.refresh().await;
    // License/flag refresh loop — fail-safe by design; startup never blocks
    // on the license server.
    let _license_bg = license.spawn_refresh();

    // v1 `ensure_ism_policy` at startup — best-effort; errors are swallowed so
    // the service still serves ingest when OpenSearch is briefly unavailable.
    opensearch::ensure_ism_policy(&http, &cfg.opensearch_url, cfg.log_retention_days).await;

    let state = AppState {
        http: http.clone(),
        opensearch_url: cfg.opensearch_url.clone().into(),
        clock: Clock::System,
        jwt_secret: jwt_secret.into(),
        license,
    };
    // `rate_limit::apply` wraps only the production build of
    // `ingest::router`, not the function itself — see `crate::rate_limit`
    // module docs for why the two stay separate. Unlike vault/monitor/
    // depgate, `GET /healthz` is mounted inside `ingest::router` itself
    // (not merged in separately here), so it is technically inside the
    // governed surface — harmless in practice, since the manager's
    // liveness probe hits it from a distinct source IP with its own
    // independent quota, never sharing a bucket with client `/ingest`
    // traffic.
    let app = rate_limit::apply(ingest::router(state));

    let addr: SocketAddr = ([0, 0, 0, 0], cfg.http_port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, opensearch = %cfg.opensearch_url, "logs ingest listening");

    // `into_make_service_with_connect_info` — `tower_governor`'s
    // `SmartIpKeyExtractor` (`crate::rate_limit`) falls back to the TCP
    // peer address when no forwarded-for header is present.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
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
