//! Vault cloud-sync worker. `serve` (default) consumes all five provider
//! streams (`vault:sync:{aws,azure,gcp,oracle,kubernetes}`) with the shared
//! consumer-group harness and runs standard health/metrics endpoints;
//! `healthcheck` is the container-native probe. Rust port of
//! `icebox/services/sync-worker/worker.py`.

mod handler;
mod providers;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use skauswatch_streams::{ConsumerConfig, StreamConsumer};
use skauswatch_vault::EnvelopeEncryption;

use crate::handler::SyncHandler;

/// Vault cloud-sync worker.
#[derive(Parser)]
#[command(name = "skauswatch-worker-vault-sync", version)]
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

/// Providers this worker consumes — matches v1 `PROVIDERS`.
const PROVIDERS: &[&str] = &["aws", "azure", "gcp", "oracle", "kubernetes"];

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Healthcheck => healthcheck().await,
    }
}

fn health_port() -> u16 {
    std::env::var("HEALTH_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080)
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-worker-vault-sync");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let db_cfg =
        skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
    let db = skauswatch_db::connect_postgres(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;

    let envelope = EnvelopeEncryption::from_env()
        .map_err(|e| anyhow::anyhow!("envelope encryption init failed: {e}"))?;

    let redis_url =
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379/0".to_owned());
    let redis_password = std::env::var("REDIS_PASSWORD").ok();
    // Same shared `skauswatch` namespace as the vault REST service (see
    // services/vault/src/routes/sync.rs::sync_stream_name).
    let prefix = std::env::var("REDIS_KEY_PREFIX").unwrap_or_else(|_| "skauswatch".to_owned());
    let consumer_group =
        std::env::var("CONSUMER_GROUP").unwrap_or_else(|_| "sync-worker".to_owned());
    let worker_id =
        std::env::var("WORKER_ID").unwrap_or_else(|_| format!("worker-{}", std::process::id()));

    let consumer = StreamConsumer::connect(&redis_url, redis_password.as_deref(), &prefix)
        .await
        .map_err(|e| anyhow::anyhow!("redis consumer connect: {e}"))?;

    let readiness = skauswatch_telemetry::Readiness::new();
    let health = skauswatch_telemetry::health_router(readiness.clone());
    let addr: SocketAddr = ([0, 0, 0, 0], health_port()).into();
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

    // Own-AWS JWT-SVID federation (see `docs/v2-port/aws-identity-runbook.md`)
    // — resolved once and shared across the loop below; only the `"aws"`
    // provider's handler ever consults it.
    let federation = own_aws_federation().await;

    let mut consumer_futs = Vec::new();
    for provider in PROVIDERS {
        let mut handler = SyncHandler::new(*provider, db.clone(), envelope.clone());
        if *provider == "aws"
            && let Some((identity, role_arn)) = &federation
        {
            handler = handler.with_federation(std::sync::Arc::clone(identity), role_arn.clone());
        }
        let cfg = ConsumerConfig::new(
            format!("vault:sync:{provider}"),
            consumer_group.clone(),
            format!("{worker_id}-{provider}"),
        );
        let consumer = consumer.clone();
        let shutdown_rx = shutdown_rx.clone();
        consumer_futs.push(async move {
            consumer
                .run(&cfg, &handler, shutdown_rx)
                .await
                .map_err(|e| anyhow::anyhow!("consumer[{provider}]: {e}"))
        });
    }

    tokio::try_join!(health_srv, futures::future::try_join_all(consumer_futs))?;
    tracing::info!("worker stopped cleanly");
    Ok(())
}

async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Resolves this worker's own-AWS JWT-SVID federation, if configured — see
/// `docs/v2-port/aws-identity-runbook.md`. Opt-in via `AWS_FEDERATION_ROLE_ARN`
/// (this worker's own service-owned IAM role, never a customer's): when
/// unset, this returns `None` immediately without even attempting to reach
/// a SPIRE agent, leaving the `"aws"` provider's `SyncHandler` byte-for-byte
/// unchanged from before this feature existed. When set but the local
/// SPIFFE identity is unavailable (no SPIRE agent reachable), logs a
/// warning and returns `None` — federation is an opportunistic enhancement
/// over the default AWS credential-provider chain, never a
/// startup-blocking requirement.
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
                "own-AWS JWT-SVID federation enabled for vault cloud sync (AWS_FEDERATION_ROLE_ARN set)"
            );
            Some((std::sync::Arc::new(identity), role_arn))
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "AWS_FEDERATION_ROLE_ARN is set but no SPIFFE identity is available — \
                 own-AWS federation disabled, vault cloud sync falls back to the default \
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
    let url = format!("http://127.0.0.1:{}/healthz", health_port());
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
