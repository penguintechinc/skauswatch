//! SkausWatch DepGate entry point — the OCI/npm/PyPI pull-through registry
//! proxy: scan-on-ingest, content-addressed cache, verdict-as-object-tags
//! (`docs/v2-port/v2.1-depgate.md`, P1 OCI + P2 npm/PyPI). `serve` (default)
//! runs the `/v2/*` + `/npm/*` + `/pypi/*` proxies + `/api/v1/depgate/*`
//! admin API + health/metrics; `healthcheck` is the container-native probe
//! (no curl in images); `seed` warm-starts the cache from a seed manifest;
//! `openapi` regenerates the committed spec.

mod auth;
mod bundle;
mod cache;
mod config;
mod crates_io;
mod db;
mod error;
mod fetch;
mod go_path;
mod go_proxy;
mod heuristics;
mod mesh_admin;
mod npm;
mod npm_path;
mod oci_path;
mod policy;
mod provenance;
mod pypi;
mod rescan;
mod routes;
mod scanpipe;
mod seed;
mod socket;
mod state;
mod tarutil;
#[cfg(test)]
mod test_support;
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
    /// Air-gap bundle export/import (`docs/v2-port/v2.1-depgate.md` §6b).
    Bundle {
        #[command(subcommand)]
        action: BundleAction,
    },
    /// Re-scans every cached artifact whose recorded scanner version is
    /// stale, then exits — the CLI trigger for the §6 re-scan sweep. Never
    /// run on the hot serve path.
    RescanSweep,
}

/// `skauswatch-depgate bundle <export|import>` subcommands.
#[derive(Subcommand)]
enum BundleAction {
    /// Exports every vetted (`verdict = clean`) artifact into a portable,
    /// checksummed (and, if `DEPGATE_BUNDLE_SIGNING_KEY` is set, signed)
    /// `.zip` bundle.
    Export {
        /// Output path for the bundle `.zip` file.
        #[arg(long)]
        out: String,
    },
    /// Imports a bundle `.zip`, verifying the manifest checksum, optional
    /// signature, and every artifact's own content hash before admitting
    /// anything — all-or-nothing.
    Import {
        /// Path to the bundle `.zip` file.
        path: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Healthcheck => healthcheck().await,
        Command::Seed { manifest } => run_seed(&manifest).await,
        Command::Openapi => print_openapi(),
        Command::Bundle { action } => run_bundle(action).await,
        Command::RescanSweep => run_rescan_sweep().await,
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

/// Runs `skauswatch-depgate bundle export|import` (§6b).
async fn run_bundle(action: BundleAction) -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-depgate");
    let state = AppStateInner::from_env().await?;
    match action {
        BundleAction::Export { out } => {
            let stats = bundle::export_bundle(
                &state.db,
                &state.s3,
                &state.cfg.cache_bucket,
                &state.cfg.cache_prefix,
                std::path::Path::new(&out),
                state.cfg.bundle_signing_private_key_pem.as_deref(),
            )
            .await?;
            println!(
                "bundle exported: entries={} unique_blobs={} manifest_sha256={} signed={}",
                stats.entry_count, stats.unique_blob_count, stats.manifest_sha256, stats.signed
            );
            Ok(())
        }
        BundleAction::Import { path } => {
            let tenant_id: uuid::Uuid = seed::BOOTSTRAP_TENANT.parse().map_err(|e| {
                anyhow::anyhow!("bootstrap tenant literal is not a valid UUID: {e}")
            })?;
            let bundle_name = std::path::Path::new(&path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&path)
                .to_owned();
            let stats = bundle::import_bundle(
                &state.db,
                &state.s3,
                &state.cfg.cache_bucket,
                &state.cfg.cache_prefix,
                tenant_id,
                std::path::Path::new(&path),
                state.cfg.bundle_signing_key.as_deref(),
                state.cfg.bundle_verify_public_key_pem.as_deref(),
                &bundle_name,
            )
            .await?;
            println!(
                "bundle imported: entries={} unique_blobs={} manifest_sha256={} signature_verified={}",
                stats.entry_count, stats.unique_blob_count, stats.manifest_sha256, stats.signed
            );
            Ok(())
        }
    }
}

/// Runs `skauswatch-depgate rescan-sweep` (§6).
async fn run_rescan_sweep() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-depgate");
    let state = AppStateInner::from_env().await?;
    let stats = rescan::sweep(&state).await?;
    println!(
        "rescan sweep: examined={} rescanned={} verdict_changed={} errors={}",
        stats.examined, stats.rescanned, stats.verdict_changed, stats.errors
    );
    Ok(())
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
