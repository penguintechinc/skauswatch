//! SkausWatch svc-ingest entry point — multi-protocol SIEM log ingest
//! (syslog UDP/TCP/TLS, OTLP gRPC/HTTP, HTTPS OCSF/JSON), normalizing
//! everything to OCSF and buffering through NATS JetStream ahead of the
//! unified `skauswatch-logs-*` OpenSearch lake. `serve --mode receiver`
//! (default) terminates the protocol listeners; `serve --mode writer`
//! drains the JetStream consumer and bulk-writes to OpenSearch — the two
//! modes scale independently as separate K8s Deployments. `healthcheck` is
//! the container-native health probe (no curl in images); `migrate`
//! applies pending SQL migrations (K8s Job target only — never run at
//! `serve` startup). See `docs/v2-port/ingest-module-spec.md` for the full
//! design.
//!
//! Every listener/writer/auth/buffer module was built and reviewed as an
//! independently-testable, unwired stub across Wave 0/1's own tasks (see
//! each module's doc comment). This file's `serve()` is the Wave-1
//! integration gate those tasks anticipated: it no longer stands up a
//! bare health surface — `crate::bootstrap::run_receiver`/`run_writer`
//! assemble the shared dependencies (NATS JetStream buffer, Postgres
//! identity store, SPIFFE workload identity, JWT/license config) and run
//! every real listener/writer concurrently. See `crate::bootstrap`'s own
//! doc comment for the wiring itself.

mod admin;
mod auth;
mod bootstrap;
mod buffer;
mod config;
mod identity_store;
mod listeners;
mod openapi;
mod opensearch;
mod writer;

use clap::{Parser, Subcommand, ValueEnum};

use crate::config::Config;

/// SkausWatch svc-ingest service.
#[derive(Parser)]
#[command(name = "skauswatch-svc-ingest", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

/// Top-level subcommands.
#[derive(Subcommand)]
enum Command {
    /// Run the service (default).
    Serve {
        /// Which half of the ingest pipeline to run — `receiver`
        /// (protocol listeners) or `writer` (JetStream consumer →
        /// OpenSearch). Each mode is a separate K8s Deployment so they
        /// scale independently.
        #[arg(long, value_enum, default_value_t = RunMode::Receiver)]
        mode: RunMode,
    },
    /// Probe the local /healthz endpoint and exit 0/1 (container HEALTHCHECK).
    Healthcheck,
    /// Print the generated OpenAPI 3.x spec (YAML) to stdout and exit.
    /// Regenerates `openapi/v1.yaml`: `skauswatch-svc-ingest openapi >
    /// openapi/v1.yaml`.
    Openapi,
    /// Applies pending SQL migrations from `services/svc-ingest/migrations`
    /// against the configured database and exits — the K8s Job migration
    /// target (`skauswatch-svc-ingest migrate`). Schema authority is `sqlx
    /// migrate`, never an auto-run at `serve` startup (see `skauswatch_db`
    /// crate docs).
    Migrate,
}

/// Which half of the ingest pipeline a `serve` process runs — see
/// `Command::Serve`.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RunMode {
    /// Terminates the protocol listeners (syslog/OTLP/HTTPS), normalizes to
    /// OCSF, and enqueues onto the JetStream buffer.
    Receiver,
    /// Drains the JetStream consumer in batches and bulk-writes to
    /// OpenSearch, acking only after a successful write.
    Writer,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve {
        mode: RunMode::Receiver,
    }) {
        Command::Serve { mode } => serve(mode).await,
        Command::Healthcheck => healthcheck().await,
        Command::Openapi => print_openapi(),
        Command::Migrate => migrate().await,
    }
}

/// Emits the aggregated OpenAPI document as YAML — the source of truth for
/// `openapi/v1.yaml` (see `openapi::ApiDoc`). Generated, never hand-edited.
fn print_openapi() -> anyhow::Result<()> {
    use utoipa::OpenApi as _;
    let yaml = openapi::ApiDoc::openapi()
        .to_yaml()
        .map_err(|e| anyhow::anyhow!("serialize openapi spec: {e}"))?;
    print!("{yaml}");
    Ok(())
}

/// Embeds this service's `migrations/` directory at compile time (no DB
/// required to build) — applied only via `Command::Migrate`. Empty until
/// Task 1.4 adds `0001_ingest_identity.sql`.
static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// Applies every pending migration in [`MIGRATOR`] and exits — see
/// `Command::Migrate`. Fails closed: any connection or migration error
/// returns a non-zero exit rather than leaving the schema partially
/// applied and reporting success.
async fn migrate() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-svc-ingest");
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

/// Runs the ingest service in the given [`RunMode`] until a shutdown
/// signal — dispatches to `crate::bootstrap::run_receiver`/`run_writer`,
/// which own the real per-mode listener/writer wiring (see that module's
/// doc comment). `RunMode::Writer` gets its own `skauswatch_telemetry::
/// Readiness` flag (fed into its minimal health surface); `RunMode::
/// Receiver` does not need one — see `crate::bootstrap`'s doc comment for
/// why.
async fn serve(mode: RunMode) -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-svc-ingest");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let cfg = Config::from_env().map_err(|e| anyhow::anyhow!("config: {e}"))?;
    tracing::debug!(
        http_port = cfg.http_port,
        syslog_port = cfg.syslog_port,
        syslog_tls_port = cfg.syslog_tls_port,
        otlp_grpc_port = cfg.otlp_grpc_port,
        otlp_http_port = cfg.otlp_http_port,
        opensearch_url = %cfg.opensearch_url,
        nats_url = %cfg.nats_url,
        nats_jetstream_subject_prefix = %cfg.nats_jetstream_subject_prefix,
        syslog_udp_enabled = cfg.syslog_udp_enabled,
        syslog_trusted_cidrs = cfg.syslog_trusted_cidrs.len(),
        ?mode,
        "svc-ingest configuration loaded"
    );

    match mode {
        RunMode::Receiver => bootstrap::run_receiver(cfg).await,
        RunMode::Writer => {
            let readiness = skauswatch_telemetry::Readiness::new();
            bootstrap::run_writer(cfg, readiness).await
        }
    }
}

/// Container-native health probe: GET the local /healthz and exit 0/1.
async fn healthcheck() -> anyhow::Result<()> {
    let port = std::env::var("HTTP_PORT")
        .ok()
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or(8443u16);
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod migrate_tests {
    use super::MIGRATOR;

    /// Guards the embedded migrator against silent drift from
    /// `services/svc-ingest/migrations/*.sql` — see `Command::Migrate`.
    /// Zero at scaffold time (Task 0.2); Task 1.4 added the first
    /// migration (`0001_ingest_identity.sql`) and bumps this count, per
    /// this comment's own instruction.
    #[test]
    fn migrator_embeds_expected_migration_count() {
        assert_eq!(MIGRATOR.iter().count(), 1);
    }
}
