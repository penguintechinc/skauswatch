//! SkausWatch scanner worker entry point. Consumes `scanner:tasks` stream
//! and performs YARA + ClamAV + ASM (masscan/banner/cert/screenshot —
//! nuclei/zap/openvas are intentionally not implemented, see `crate::asm`
//! module docs) scanning. `serve` (default) runs the consumer loop +
//! health/metrics endpoints; `healthcheck` is the container-native probe
//! (no curl in images, per container standards); `migrate` applies
//! pending SQL migrations (K8s Job target only — never run at `serve`
//! startup).

mod asm;
mod clamav;
mod config;
mod db;
mod handler;
mod message;
mod scan;
mod target_safety;
mod yara;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use skauswatch_streams::{ConsumerConfig, STREAM_SCANNER_TASKS, StreamConsumer, StreamProducer};

use crate::config::WorkerConfig;
use crate::handler::ScannerHandler;

/// SkausWatch malware & vulnerability scanner worker.
#[derive(Parser)]
#[command(name = "skauswatch-scanner", version)]
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
    /// Applies pending SQL migrations from `services/scanner/migrations`
    /// against the configured database and exits — the K8s Job migration
    /// target (`skauswatch-scanner migrate`). Schema authority is `sqlx
    /// migrate`, never an auto-run at `serve` startup (see
    /// `skauswatch_db` crate docs).
    Migrate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Healthcheck => healthcheck().await,
        Command::Migrate => migrate().await,
    }
}

/// Embeds this service's `migrations/` directory at compile time (no DB
/// required to build) — applied only via `Command::Migrate`.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// Applies every pending migration in [`MIGRATOR`] and exits — see
/// `Command::Migrate`. Fails closed: any connection or migration error
/// returns a non-zero exit rather than leaving the schema partially
/// applied and reporting success.
async fn migrate() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-scanner");
    let db_cfg =
        skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
    let pool = skauswatch_db::connect_postgres(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;
    skauswatch_db::run_migrations(&pool, &MIGRATOR)
        .await
        .map_err(|e| anyhow::anyhow!("migration failed: {e}"))?;
    tracing::info!("migrations applied");
    Ok(())
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-scanner");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let cfg = WorkerConfig::from_env()?;
    tracing::info!(
        consumer = %cfg.consumer_name, group = %cfg.consumer_group,
        prefix = %cfg.redis_prefix, yara_enabled = cfg.yara_enabled,
        clamav_enabled = cfg.clamav_enabled, asm_enabled = cfg.asm_enabled,
        "starting scanner worker"
    );

    // DB pool (per-service account, shared v1 schema) with retry/backoff.
    let db_cfg =
        skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
    let pool = skauswatch_db::connect_postgres(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;

    // Producer (results onward) and consumer share the v1 REDIS_* semantics;
    // startup fails if the broker is unreachable.
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
            STREAM_SCANNER_TASKS,
            cfg.consumer_group.clone(),
            cfg.consumer_name.clone(),
        );
        c.batch = cfg.max_concurrent_tasks.max(1);
        c
    };
    let screenshot_uploader = build_screenshot_uploader(&cfg).await;
    let handler = ScannerHandler::new(pool, producer, cfg.clone(), screenshot_uploader);

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

/// Builds the ASM screenshot S3 uploader from `S3_*` env vars
/// (`skauswatch_s3::S3Config`) and `cfg.asm_screenshot_bucket`. Returns
/// `None` — logged, not fatal — whenever the screenshot stage is disabled,
/// no bucket is configured, or the S3 config itself is malformed; a worker
/// must never fail to start over an optional capture stage (see
/// `crate::asm` module docs' fail-safe posture).
async fn build_screenshot_uploader(cfg: &WorkerConfig) -> Option<crate::asm::ScreenshotUploader> {
    if !cfg.asm_screenshot_enabled {
        tracing::info!("ASM screenshot stage disabled (ASM_SCREENSHOT_ENABLED=false)");
        return None;
    }
    let Some(bucket) = cfg.asm_screenshot_bucket.clone() else {
        tracing::warn!(
            "ASM_SCREENSHOT_ENABLED is true but ASM_SCREENSHOT_BUCKET is unset; \
             screenshot capture disabled"
        );
        return None;
    };
    let s3_cfg = match skauswatch_s3::S3Config::from_env() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "invalid S3_* config; ASM screenshot capture disabled");
            return None;
        }
    };
    let client = skauswatch_s3::client(&s3_cfg).await;
    tracing::info!(bucket = %bucket, "ASM screenshot stage enabled");
    Some(crate::asm::ScreenshotUploader::new(client, bucket))
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

#[cfg(test)]
mod migrate_tests {
    use super::MIGRATOR;

    /// Guards the embedded migrator against silent drift from
    /// `services/scanner/migrations/*.sql` — see `Command::Migrate`.
    /// Update this count when adding a new migration file.
    #[test]
    fn migrator_embeds_expected_migration_count() {
        assert_eq!(MIGRATOR.iter().count(), 2);
    }
}
