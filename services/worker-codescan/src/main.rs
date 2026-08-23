//! SkausWatch CodeScan code review worker entry point. Consumes the
//! `codescan:tasks` stream with the shared consumer-group harness and runs the
//! standard health/metrics endpoints; `healthcheck` is the container-native
//! probe (no curl in images, per container standards). `scheduler` runs the
//! CodeScan Sentinel polling loop
//! (docs/v2-port/v2.1-codescan-sentinel.md §10) as a separate process/
//! container from `serve` — same pattern as any other cron-replacement
//! sidecar in this stack, just supercronic-free since the interval lives in
//! a `tokio::time::interval` rather than a crontab entry.

mod config;
mod db;
mod detection;
mod git_provider;
mod handler;
mod lease;
mod license_scan;
mod message;
mod review;
mod scanner_tool;
mod scheduler;
mod sentinel;
mod tree_fetch;

use std::net::SocketAddr;
use std::time::Duration;

use clap::{Parser, Subcommand};
use skauswatch_streams::{ConsumerConfig, STREAM_CODESCAN_TASKS, StreamConsumer, StreamProducer};

use crate::config::WorkerConfig;
use crate::handler::CodeScanReviewHandler;

/// SkausWatch CodeScan code review worker.
#[derive(Parser)]
#[command(name = "skauswatch-worker-codescan", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the worker (default).
    Serve,
    /// Probe the local /healthz endpoint and exit 0/1 (container HEALTHCHECK).
    Healthcheck,
    /// Run the CodeScan Sentinel scheduler loop (polls due repos, enqueues
    /// scan tasks onto `codescan:tasks`) — a separate long-running process
    /// from `serve`, meant to run as its own container/replica.
    Scheduler,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Healthcheck => healthcheck().await,
        Command::Scheduler => run_scheduler().await,
    }
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-worker-codescan");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let cfg = WorkerConfig::from_env()?;
    tracing::info!(
        consumer = %cfg.consumer_name,
        group = %cfg.consumer_group,
        prefix = %cfg.redis_prefix,
        ai_provider = %cfg.ai_provider,
        ai_model = %cfg.ai_model,
        "starting CodeScan review worker"
    );

    // DB pool (per-service account, shared v2 schema) with retry/backoff.
    let db_cfg =
        skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
    let pool = skauswatch_db::connect_postgres(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;

    // Producer (onward review results) and consumer share the v1 REDIS_*
    // semantics; startup fails if the broker is unreachable.
    let producer = StreamProducer::connect(
        &cfg.redis_url,
        cfg.redis_password.as_deref(),
        &cfg.redis_prefix,
    )
    .await
    .map_err(|e| anyhow::anyhow!("redis producer connect: {e}"))?;
    let consumer = StreamConsumer::connect(
        &cfg.redis_url,
        cfg.redis_password.as_deref(),
        &cfg.redis_prefix,
    )
    .await
    .map_err(|e| anyhow::anyhow!("redis consumer connect: {e}"))?;

    let consumer_cfg = {
        let mut c = ConsumerConfig::new(
            STREAM_CODESCAN_TASKS,
            cfg.consumer_group.clone(),
            cfg.consumer_name.clone(),
        );
        c.batch = cfg.max_concurrent_tasks.max(1);
        c
    };
    let handler = CodeScanReviewHandler::new(pool, producer, cfg.clone());

    // Health/readiness + metrics endpoints (standard telemetry surface).
    let readiness = skauswatch_telemetry::Readiness::new();
    let health = skauswatch_telemetry::health_router(readiness.clone());
    let addr: SocketAddr = ([0, 0, 0, 0], cfg.health_port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "worker health endpoint listening");
    readiness.set_ready();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let health_srv = async {
        axum::serve(listener, health)
            .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()))
            .await
            .map_err(anyhow::Error::from)
    };
    let consume = async {
        consumer
            .run(&consumer_cfg, &handler, shutdown_rx.clone())
            .await
            .map_err(|e| anyhow::anyhow!("consumer: {e}"))
    };
    tokio::try_join!(health_srv, consume)?;
    tracing::info!("worker stopped cleanly");
    Ok(())
}

/// Tick interval for the Sentinel scheduler loop (env `SENTINEL_TICK_SECONDS`,
/// default 60s) — deliberately not part of [`WorkerConfig`], which is shared
/// with `serve` and already has 21 constructor parameters; this and the
/// lease TTL below are read directly here, the only place that needs them.
fn sentinel_tick_interval() -> Duration {
    let secs = std::env::var("SENTINEL_TICK_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60u64);
    Duration::from_secs(secs)
}

/// Per-repo Valkey lease TTL in milliseconds (env `SENTINEL_LEASE_TTL_MS`,
/// default 300_000 = 5 minutes) — must comfortably exceed one scheduler tick
/// interval so a slow tick can never let two replicas both win the lease
/// race for the same repo (see `scheduler::tick`).
fn sentinel_lease_ttl_ms() -> i64 {
    std::env::var("SENTINEL_LEASE_TTL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000i64)
}

/// Runs the CodeScan Sentinel scheduler loop (spec §10) as a standalone
/// process — same DB/Redis config surface as `serve`, plus its own license
/// client so the loop can gate itself on `sentinel::SENTINEL_FLAG` without
/// requiring `serve`'s consumer-group machinery.
async fn run_scheduler() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-worker-codescan-scheduler");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let cfg = WorkerConfig::from_env()?;
    tracing::info!(
        prefix = %cfg.redis_prefix,
        tick_interval = ?sentinel_tick_interval(),
        "starting CodeScan Sentinel scheduler"
    );

    let db_cfg =
        skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
    let pool = skauswatch_db::connect_postgres(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;

    let producer = StreamProducer::connect(
        &cfg.redis_url,
        cfg.redis_password.as_deref(),
        &cfg.redis_prefix,
    )
    .await
    .map_err(|e| anyhow::anyhow!("redis producer connect: {e}"))?;
    let lease = crate::lease::LeaseClient::connect(&cfg.redis_url, cfg.redis_password.as_deref())
        .await
        .map_err(|e| anyhow::anyhow!("redis lease client connect: {e}"))?;

    let license_cfg = penguin_licensing::LicenseConfig::from_env("skauswatch")
        .map_err(|e| anyhow::anyhow!("license config: {e}"))?
        .with_bypass_domain("skauswatch.app");
    let license = penguin_licensing::LicenseClient::new(license_cfg)
        .map_err(|e| anyhow::anyhow!("license client: {e}"))?;
    let _ = license.refresh().await;
    let _license_bg = license.spawn_refresh();

    let readiness = skauswatch_telemetry::Readiness::new();
    let health = skauswatch_telemetry::health_router(readiness.clone());
    let addr: SocketAddr = ([0, 0, 0, 0], cfg.health_port).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "scheduler health endpoint listening");
    readiness.set_ready();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let health_srv = async {
        axum::serve(listener, health)
            .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()))
            .await
            .map_err(anyhow::Error::from)
    };
    let scheduler_loop = async {
        crate::scheduler::run(
            pool,
            producer,
            lease,
            cfg.redis_prefix.clone(),
            sentinel_lease_ttl_ms(),
            sentinel_tick_interval(),
            license,
            shutdown_rx.clone(),
        )
        .await;
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(health_srv, scheduler_loop)?;
    tracing::info!("scheduler stopped cleanly");
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
    let port = std::env::var("HEALTH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080u16);
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
