//! SkausWatch S3 scan worker entry point. `serve` (default) consumes the
//! `s3scan:tasks` stream with the shared consumer-group harness and runs the
//! standard health/metrics endpoints; `healthcheck` is the container-native
//! probe (no curl in images, per container standards).

mod clamav;
mod config;
mod db;
mod enumerate;
mod handler;
mod message;
mod s3ops;
mod scan;
mod ti;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use skauswatch_streams::{ConsumerConfig, STREAM_S3_SCAN_TASKS, StreamConsumer, StreamProducer};

use crate::config::WorkerConfig;
use crate::handler::S3ScanHandler;

/// SkausWatch S3 scan worker.
#[derive(Parser)]
#[command(name = "skauswatch-s3scan", version)]
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Healthcheck => healthcheck().await,
    }
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-s3scan");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let cfg = WorkerConfig::from_env()?;
    tracing::info!(
        consumer = %cfg.consumer_name, group = %cfg.consumer_group,
        prefix = %cfg.redis_prefix, ti_enabled = cfg.ti_enabled,
        yara_enabled = cfg.yara_enabled, scan_timeout_sec = cfg.scan_timeout_sec,
        "starting S3 scan worker (YARA runs in scanner, not s3scan)"
    );

    // DB pool (per-service account, shared v1 schema) with retry/backoff.
    let db_cfg =
        skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
    let pool = skauswatch_db::connect_postgres(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;

    // Envelope encryption for `static`-mode stored bucket credentials
    // (security finding #2 — see `skauswatch_s3::credentials`). Same
    // `VAULT_MEK*` env vars as the `vault`/`worker-vault-sync` services —
    // one master-key infrastructure product-wide. Fails startup rather than
    // running with a service that can never decrypt a stored credential.
    let envelope = skauswatch_vault::EnvelopeEncryption::from_env()
        .map_err(|e| anyhow::anyhow!("envelope encryption init failed: {e}"))?;

    // Producer (per-object re-dispatch + onward events) and consumer share the
    // v1 REDIS_* semantics; startup fails if the broker is unreachable.
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
            STREAM_S3_SCAN_TASKS,
            cfg.consumer_group.clone(),
            cfg.consumer_name.clone(),
        );
        c.batch = cfg.max_concurrent_tasks.max(1);
        c
    };
    let handler = S3ScanHandler::new(pool, producer, cfg.clone(), envelope);
    let handler = match own_aws_federation().await {
        Some((identity, role_arn)) => handler.with_federation(identity, role_arn),
        None => handler,
    };

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

/// Resolves once the shutdown broadcast fires, gating graceful shutdown.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Resolves this worker's own-AWS JWT-SVID federation, if configured — see
/// `docs/v2-port/aws-identity-runbook.md`. Opt-in via `AWS_FEDERATION_ROLE_ARN`
/// (this worker's own service-owned IAM role, never a customer's): when
/// unset, this returns `None` immediately without even attempting to reach
/// a SPIRE agent, leaving `adhoc_client` byte-for-byte unchanged from
/// before this feature existed. When set but the local SPIFFE identity is
/// unavailable (no SPIRE agent reachable), logs a warning and returns
/// `None` — federation is an opportunistic enhancement over the default
/// AWS credential-provider chain, never a startup-blocking requirement.
async fn own_aws_federation() -> Option<(
    std::sync::Arc<dyn skauswatch_s3::credentials::JwtSvidSource>,
    String,
)> {
    let role_arn = std::env::var("AWS_FEDERATION_ROLE_ARN")
        .ok()
        .filter(|v| !v.is_empty())?;
    match skauswatch_identity::IdentityProvider::connect().await {
        Ok(identity) => {
            tracing::info!(
                "own-AWS JWT-SVID federation enabled for ad-hoc S3 access (AWS_FEDERATION_ROLE_ARN set)"
            );
            Some((std::sync::Arc::new(identity), role_arn))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "AWS_FEDERATION_ROLE_ARN is set but no SPIFFE identity is available — \
                 own-AWS federation disabled, ad-hoc S3 access falls back to the default \
                 AWS credential-provider chain"
            );
            None
        }
    }
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
