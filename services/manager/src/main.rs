//! SkausWatch manager service entry point. `serve` (default) runs the REST
//! /api/v1 + health/metrics stack and the v1-parity gRPC control plane;
//! `healthcheck` is the container-native health probe (no curl in images,
//! per container standards).

mod auth;
mod deprecated;
mod error;
mod flags;
mod grpc;
mod health;
mod rate_limit;
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
    /// Print the generated OpenAPI 3.x spec (YAML) to stdout and exit —
    /// the authenticated full document (`routes::openapi::ApiDoc`), never
    /// hand-edited. See `docs/v2-port/openapi-pattern.md`.
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

/// Emits `routes::openapi::ApiDoc`'s generated spec as YAML — the source of
/// truth for `services/manager/openapi/v1.yaml`. The public login-only
/// document (`routes::openapi::PublicApiDoc`) is intentionally not emitted
/// here; it is served live only (see `routes/openapi.rs`), never committed,
/// since it's a strict subset of the full spec.
fn print_openapi() -> anyhow::Result<()> {
    use utoipa::OpenApi;
    let yaml = routes::openapi::ApiDoc::openapi()
        .to_yaml()
        .map_err(|e| anyhow::anyhow!("serialize openapi spec: {e}"))?;
    print!("{yaml}");
    Ok(())
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
    // health router; /readyz keeps the readiness gate; /version stays
    // alongside them. The fallback serves the v1 Quart framework-404
    // envelope for unknown routes.
    // Global rate limit (security hardening Fix 2) is applied here, at the
    // outermost layer of the fully assembled app, never inside
    // `routes::router()` — see `rate_limit` module docs for why: the many
    // per-module/full-router unit tests build their own `axum_test`
    // servers directly from a `Router` and never go through `serve()`, so
    // this placement keeps every one of them unaffected. The stricter
    // `/auth/*` limiter is scoped inside `routes::router()` itself, since
    // it wraps a small dedicated sub-router (`auth::public_router()`)
    // rather than the whole app.
    //
    // `health::router` (`/healthz`, `/readyz`, `/version`) is merged in
    // AFTER `rate_limit::apply_global`, never as part of the `Router` value
    // passed into it — first-run microk8s deploy bug (same anti-pattern
    // already fixed on `services/logs`/`services/monitor`): health used to
    // be merged inside the argument to `apply_global`, so k8s probe
    // traffic (no JWT, high frequency) shared the same governed bucket as
    // ordinary API traffic and could be 429'd once the global burst was
    // exhausted.
    let app = rate_limit::apply_global(routes::router(state.clone()))
        .merge(health::router(state.clone(), readiness.clone()))
        .fallback(error::fallback_not_found);

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
        // `with_connect_info` gives the rate limiters' `SmartIpKeyExtractor`
        // a real peer `SocketAddr` fallback for requests that (unlike
        // traffic through the K8s ingress) carry no X-Forwarded-For/
        // X-Real-Ip/Forwarded header — e.g. same-namespace or direct calls.
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
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
