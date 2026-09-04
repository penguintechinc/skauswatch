//! SkausWatch PKI server entry point. `serve` (default) runs the REST
//! `/api/v1` certificate surface plus the `skauswatch.pki` gRPC control plane;
//! `healthcheck` is the container-native health probe (no curl in images);
//! `migrate` applies pending SQL migrations (K8s Job target only — never
//! run at `serve` startup).

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use skauswatch_pki::{grpc, health, maintenance, routes, state};

/// SkausWatch PKI server.
#[derive(Parser)]
#[command(name = "skauswatch-pki", version)]
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
    /// Regenerates `openapi/v1.yaml`: `skauswatch-pki openapi > openapi/v1.yaml`.
    Openapi,
    /// Applies pending SQL migrations from `services/pki/migrations`
    /// against the configured database and exits — the K8s Job migration
    /// target (`skauswatch-pki migrate`). Schema authority is `sqlx
    /// migrate`, never an auto-run at `serve` startup (see
    /// `skauswatch_db` crate docs).
    Migrate,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command.unwrap_or(Command::Serve) {
        Command::Serve => serve().await,
        Command::Healthcheck => healthcheck().await,
        Command::Openapi => print_openapi(),
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
    skauswatch_telemetry::init_tracing("skauswatch-pki");
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

/// Default REST port — parity with the v1 PKI service (env `API_PORT`).
const DEFAULT_HTTP_PORT: u16 = 8001;

fn http_port() -> u16 {
    std::env::var("API_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_HTTP_PORT)
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-pki");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let readiness = skauswatch_telemetry::Readiness::new();
    let state = state::AppStateInner::from_env().await?;

    // License/flag refresh loop — fail-safe by design; startup never blocks
    // on the license server.
    let _license_bg = state.license.spawn_refresh();

    let app = routes::router(state.clone())
        .merge(health::router(state.clone(), readiness.clone()))
        .fallback(skauswatch_pki::error::fallback_not_found);

    let addr: SocketAddr = ([0, 0, 0, 0], http_port()).into();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "pki REST listening");
    readiness.set_ready();

    // One signal fans out to every server so REST, gRPC, and the
    // maintenance listener shut down together.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let http = async {
        // `with_connect_info` — required for `routes::router`'s
        // `tower_governor::GovernorLayer` (default `PeerIpKeyExtractor`) to
        // see the real TCP peer address; see that module's docs.
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx.clone()))
        .await
        .map_err(anyhow::Error::from)
    };

    // mTLS-required maintenance listener (docs/v2-port/service-auth-model.md
    // §3) — always part of the join; it degrades to "disabled" on its own
    // when no SPIFFE identity is held rather than needing an enabled/
    // disabled flag here (see maintenance::serve's docs).
    let maintenance_addr: SocketAddr = ([0, 0, 0, 0], maintenance::port()).into();
    let maintenance_fut = maintenance::serve(
        state.clone(),
        maintenance_addr,
        wait_for_shutdown(shutdown_rx.clone()),
    );

    if grpc::enabled() {
        let grpc_addr: SocketAddr = ([0, 0, 0, 0], grpc::port()).into();
        let grpc_fut = grpc::serve(
            state.clone(),
            grpc_addr,
            wait_for_shutdown(shutdown_rx.clone()),
        );
        tokio::try_join!(http, grpc_fut, maintenance_fut)?;
    } else {
        tracing::info!("gRPC server disabled");
        tokio::try_join!(http, maintenance_fut)?;
    }
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

#[cfg(test)]
mod migrate_tests {
    use super::MIGRATOR;

    /// Guards the embedded migrator against silent drift from
    /// `services/pki/migrations/*.sql` — see `Command::Migrate`. Update
    /// this count when adding a new migration file.
    #[test]
    fn migrator_embeds_expected_migration_count() {
        assert_eq!(MIGRATOR.iter().count(), 2);
    }
}
