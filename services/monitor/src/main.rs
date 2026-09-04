//! SkausWatch monitor service entry point — Rust port of the v1 Python
//! `services/monitor` (FastAPI). `serve` (default) runs the REST API;
//! `healthcheck` is the container-native health probe (no curl in images,
//! per `devops-containers.md`); `migrate` applies pending SQL migrations
//! (K8s Job target only — never run at `serve` startup).
//!
//! ## Port coverage
//!
//! Fully ported (real, tested): the ES/OpenSearch + MongoDB event store
//! (`src/es.rs`, `src/mongo.rs`), the event search/get/stream API
//! (`src/routes/events.rs` — hardened: every one of these three endpoints
//! previously had zero authentication and no tenant filter on the
//! underlying Elasticsearch query, a critical cross-tenant data-exposure
//! finding; see that module's docs for the fix), the alert API
//! (`src/routes/alerts.rs` — a faithful port of v1's genuinely unbacked stub
//! behavior, not a shortcut; see that module's docs), the dashboard metrics
//! stub (`src/routes/dashboard.rs` — same story), health/version
//! (`src/routes/health.rs`), house-standard bearer-JWT + tenant-claim auth
//! (`src/auth.rs`, `skauswatch_auth::tenant_middleware`), the data model
//! layer (`src/models.rs`), and OpenAPI 3.x publication
//! (`src/routes/openapi.rs`, `openapi/v1.yaml`).
//!
//! **Phase 12 (this pass) — log collectors + ingest pipeline + TAXII
//! threat-intel engine**, closing the two largest tracked follow-ups below:
//!
//! - `src/collectors/*` (auditd/file/journald/syslog/kubernetes/lxc/
//!   database): the event producers `GET /events/stream` and the ES event
//!   store previously had none of — see `src/collectors/mod.rs` module docs
//!   for the exact scope (subprocess/socket/poll mechanisms kept, several
//!   of v1's remote-transport fan-outs per collector not reproduced) and
//!   the flagged-not-silent deployment requirements (host log mounts,
//!   in-cluster K8s RBAC) this needs once actually deployed.
//! - `src/ingest.rs`: the batching/backpressure glue between collectors and
//!   the event store, and — critically — where every collector-produced
//!   event's `tenant_id` is validated non-empty before it can reach
//!   storage. **Closes the tenant-provenance gap flagged in
//!   `src/es.rs::EventStore::index_event`'s doc comment**: every collector
//!   stamps `tenant_id` from `config.rs::TenancyConfig` (server-side
//!   deployment config, never anything the collected log content itself
//!   claims — see that struct's doc comment for the trust-boundary
//!   reasoning), so `crate::es::build_search_body`'s tenant filter (already
//!   hardened in an earlier pass) now actually has same-tenant data to
//!   return instead of an empty index.
//! - `src/threat_intel/*`: the TAXII 2.x feed engine (`taxii.rs`/`stix.rs`)
//!   ported for real — discovery, collection polling, STIX indicator
//!   parsing, Postgres-backed storage (`store.rs`) — plus a matcher
//!   (`matcher.rs`) wired into the ingest pipeline, and a clean, new,
//!   read-only REST surface (`routes.rs`) that does **not** restore v1's
//!   ~15 broken routes described below. See `src/threat_intel/mod.rs` for
//!   the disambiguation from manager's separate, already-shipped IOC-CRUD
//!   `threat_intel` subsystem.
//!
//! ## Tracked follow-ups (deferred, not stubbed-and-claimed-done)
//!
//! The groups below remain out of scope for this port. Each is a
//! genuinely separate subsystem, deferred with its own tracking note
//! rather than faked:
//!
//! 1. **Alerting and core analysis** (`alert_manager.py`, `escalation.py`,
//!    `pattern_detector.py`, `anomaly_detector.py`, `event_classifier.py`,
//!    top-level `analysis_engine.py`) — **confirmed v1 dead code, not a
//!    parity gap**: `search_alerts` always returns empty, `get_alert_by_id`
//!    always `None`, `start_processing` is an infinite no-op sleep loop,
//!    `escalation.handle_status_change` only logs, and every
//!    pattern/anomaly/classification module is an `__init__`-only skeleton
//!    (`classify_event` hardcodes `{"category": "unknown", "confidence":
//!    0.0}`). `src/routes/alerts.rs` and `src/routes/dashboard.rs` already
//!    faithfully preserve this non-functional behavior — see
//!    `docs/v2-port/phase12-scope-scan-monitor.md` §2 for the full
//!    verification (including a latent v1 `NameError` in
//!    `analysis_engine.py`'s constructor, silently swallowed at startup).
//! 2. **AI integration** (`ai_integration/*` — `ai_provider.py`,
//!    `analysis_engine.py`, `prompt_templates.py`, `response_processor.py`,
//!    the OpenAI/Anthropic/Ollama clients — ~3,957 lines) plus the
//!    `/ai/*` routes (~9 routes). Real but inert without operator-supplied
//!    API keys even in v1; depends on the now-ported collectors/ingest for
//!    real input if it's ever built.
//!
//! OpenAPI publication (`openapi/v1.yaml` via `utoipa`, see
//! `src/routes/openapi.rs`) *is* in place for this service, following
//! `docs/v2-port/openapi-pattern.md` (established on `codescan-backend`).

mod auth;
mod collectors;
mod config;
mod error;
mod es;
mod flags;
mod ingest;
mod models;
mod rate_limit;
mod routes;
mod state;
mod threat_intel;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use clap::{Parser, Subcommand};

/// SkausWatch monitor service.
#[derive(Parser)]
#[command(name = "skauswatch-monitor", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the service (default).
    Serve,
    /// Probe the local /health endpoint and exit 0/1 (container HEALTHCHECK).
    Healthcheck,
    /// Print the generated OpenAPI 3.x spec (YAML) to stdout and exit.
    Openapi,
    /// Applies pending SQL migrations from `services/monitor/migrations`
    /// against the configured TAXII threat-intel database and exits — the
    /// K8s Job migration target (`skauswatch-monitor migrate`). Schema
    /// authority is `sqlx migrate`, never an auto-run at `serve` startup
    /// (see `skauswatch_db` crate docs). Unlike `serve`'s own DB wiring
    /// (`state.rs::build_threat_store`, which degrades to `None` when
    /// unconfigured), this subcommand fails closed if `DB_*` is missing —
    /// it exists to apply a schema, so an unconfigured database is an
    /// error, not something to silently skip.
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
    skauswatch_telemetry::init_tracing("skauswatch-monitor");
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

/// Regenerates `openapi/v1.yaml`: `skauswatch-monitor openapi >
/// openapi/v1.yaml` (see `routes::openapi::ApiDoc` and
/// `docs/v2-port/openapi-pattern.md`). Generated, never hand-edited.
fn print_openapi() -> anyhow::Result<()> {
    use utoipa::OpenApi;
    let yaml = routes::openapi::ApiDoc::openapi()
        .to_yaml()
        .map_err(|e| anyhow::anyhow!("serialize openapi spec: {e}"))?;
    print!("{yaml}");
    Ok(())
}

async fn serve() -> anyhow::Result<()> {
    skauswatch_telemetry::init_tracing("skauswatch-monitor");
    skauswatch_telemetry::install_metrics_exporter()
        .map_err(|e| anyhow::anyhow!("metrics exporter: {e}"))?;

    let readiness = skauswatch_telemetry::Readiness::new();
    let state = state::AppStateInner::from_env().await?;
    let _license_bg = state.license.spawn_refresh();

    spawn_background_workers(&state);

    let api = routes::router(state.clone());
    // `rate_limit::apply` wraps only the fully-assembled business-route
    // app, not `routes::router` itself — see `crate::rate_limit` module
    // docs for why the two stay separate. Health/readiness stays outside
    // it: k8s probes hit it constantly and shouldn't be throttled.
    let governed = rate_limit::apply(
        Router::new()
            .merge(api.clone())
            // The openapi doc route is nested only, not double-mounted flat
            // — `docs/v2-port/openapi-pattern.md` documents the canonical
            // `/api/v1/*` paths only.
            .nest("/api/v1", api.merge(routes::openapi::router()))
            .with_state(state.clone()),
    );
    let app: Router<()> = governed.merge(skauswatch_telemetry::health_router(readiness.clone()));

    let host = state.config.api.host.clone();
    let port = state.config.api.port;
    let bind_addr = format!("{host}:{port}");
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    let addr: SocketAddr = listener.local_addr()?;
    tracing::info!(%addr, "monitor REST listening");
    readiness.set_ready();

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

/// Spawns the log collectors (`collectors::spawn_enabled`) and the TAXII
/// feed poller (`threat_intel::taxii::run`) as background tasks, wiring
/// them through `ingest::IngestPipeline`. Both degrade gracefully: no
/// collectors start without `MONITOR_TENANT_ID` (see `collectors::
/// spawn_enabled`'s doc comment) and the TAXII poller no-ops without
/// `MONITOR_TAXII_ENABLED`/a threat-intel database — neither failure here
/// prevents the REST API from serving.
fn spawn_background_workers(state: &state::AppState) {
    let matcher: Option<Arc<dyn threat_intel::matcher::EventMatcher>> = state
        .threat_store
        .clone()
        .map(|store| Arc::new(threat_intel::matcher::IndicatorMatcher::new(store)) as _);

    let sink = ingest::IngestPipeline::spawn(
        state.event_store.clone(),
        state.event_bus.clone(),
        matcher,
        state.license.clone(),
        ingest::IngestConfig::default(),
    );
    collectors::spawn_enabled(&state.config, sink);

    if let Some(store) = state.threat_store.clone() {
        let taxii_cfg = threat_intel::taxii::TaxiiConfig::from_env();
        let license = state.license.clone();
        tokio::spawn(threat_intel::taxii::run(store, taxii_cfg, license));
    } else {
        tracing::info!("threat-intel database not configured — TAXII feed poller not started");
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
    let port = config::Config::from_env().api.port;
    let url = format!("http://127.0.0.1:{port}/health");
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
    /// `services/monitor/migrations/*.sql` — see `Command::Migrate`.
    /// Update this count when adding a new migration file.
    #[test]
    fn migrator_embeds_expected_migration_count() {
        assert_eq!(MIGRATOR.iter().count(), 1);
    }
}
