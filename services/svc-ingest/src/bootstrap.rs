//! Wave-1 integration gate: assembles every listener/writer/auth/buffer
//! module `main.rs`'s own doc comment promised would land here, and runs
//! `serve()`'s two [`crate::RunMode`]s end to end.
//!
//! # Receiver mode ([`run_receiver`])
//!
//! Builds the shared, once-per-process dependencies every listener needs
//! (the JetStream-backed [`crate::buffer::EventBuffer`], the OTLP gRPC
//! listener's `IdentityStore` + shared SPIFFE workload identity, and the
//! HTTPS ingest listener's `AppState`), then runs every protocol listener
//! concurrently in a [`JoinSet`]: syslog UDP/TCP/TLS, OTLP gRPC/HTTP, and
//! the HTTPS OCSF/JSON listener (which already carries its own
//! `/healthz`+`/readyz` — see `listeners::http`, `docs/v2-port/
//! ingest-module-spec.md` §3b). The same HTTPS server also carries
//! `crate::admin`'s ISM hot/warm/cold admin surface (`PUT /api/v1/admin/
//! ingest/lifecycle`, `POST /api/v1/admin/ingest/restore`), merged onto the
//! ingest router — a distinct `/api/v1/admin/...` path prefix from
//! `/ingest`, so `.merge()` is unambiguous and the admin routes keep their
//! own super-admin/SIEM-admin bearer-token auth untouched. A shared
//! shutdown signal (SIGTERM/SIGINT)
//! is raced against every listener; if any one of them exits with an error
//! before shutdown was ever requested, it is logged and every other
//! listener is torn down too rather than leaving the process serving a
//! half-degraded protocol surface.
//!
//! No separate `skauswatch_telemetry::Readiness` flag is threaded through
//! receiver mode: `listeners::http::router`'s own `/readyz` (out of this
//! gate's file scope — Task 1.3) already answers 200 unconditionally once
//! the HTTPS listener is bound and serving, which is the same "ready once
//! bound" contract a `Readiness` flag would otherwise express.
//!
//! # Writer mode ([`run_writer`])
//!
//! Drains the same kind of JetStream buffer (as a consumer, never a
//! publisher) and bulk-writes to OpenSearch via [`crate::writer::run`].
//! Unlike receiver mode, the writer has no public protocol listener of its
//! own, so [`run_writer`] binds a minimal `skauswatch_telemetry::
//! health_router` on `WRITER_HEALTH_PORT` (default
//! [`DEFAULT_WRITER_HEALTH_PORT`]) purely so k8s can still probe it.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::admin;
use crate::buffer::{EventBuffer, JetStreamBuffer};
use crate::config::Config;
use crate::identity_store::IdentityStore;
use crate::listeners::{http, otlp, syslog};

/// Default port for the writer mode's minimal health/readiness surface
/// (`WRITER_HEALTH_PORT`) — writer mode has no public protocol listener of
/// its own for k8s to probe otherwise.
const DEFAULT_WRITER_HEALTH_PORT: u16 = 9091;

/// One listener task's outcome — its name (for logging) paired with its
/// result, so [`drain_listeners`]'s drain loop can report which listener
/// failed rather than surfacing an anonymous error.
type ListenerOutcome = (&'static str, anyhow::Result<()>);

/// Connects to NATS and builds the shared [`EventBuffer`] every
/// receiver-mode listener publishes through (and every writer-mode
/// consumer drains), per `cfg.nats_url`/`cfg.nats_jetstream_subject_prefix`.
///
/// # Errors
/// Returns an error if the NATS server is unreachable or the configured
/// subject prefix is invalid (see [`JetStreamBuffer::new`]).
async fn build_event_buffer(cfg: &Config) -> anyhow::Result<Arc<dyn EventBuffer>> {
    let client = async_nats::connect(&cfg.nats_url)
        .await
        .map_err(|e| anyhow::anyhow!("connect nats: {e}"))?;
    let context = async_nats::jetstream::new(client);
    let buffer = JetStreamBuffer::new(context, &cfg.nats_jetstream_subject_prefix)
        .map_err(|e| anyhow::anyhow!("event buffer init: {e}"))?;
    Ok(Arc::new(buffer))
}

/// Connects to Postgres and wraps the pool in an [`IdentityStore`] for the
/// OTLP gRPC listener's mTLS/ingest-token tenant resolution — the syslog
/// and OTLP HTTP listeners build their own internally (see
/// `listeners::syslog::build_identity_store`/`listeners::otlp::run_http`'s
/// own doc comments), so this one is only ever needed once per process,
/// for `otlp::run_grpc`.
///
/// # Errors
/// Returns an error if `skauswatch_db::DbConfig` cannot be loaded from the
/// environment, or the database is unreachable.
async fn build_grpc_identity_store() -> anyhow::Result<IdentityStore> {
    let db_cfg =
        skauswatch_db::DbConfig::from_env().map_err(|e| anyhow::anyhow!("db config: {e}"))?;
    let pool = skauswatch_db::connect_postgres(&db_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("db connect: {e}"))?;
    Ok(IdentityStore::new(pool))
}

/// Builds the HTTPS OCSF/JSON ingest listener's shared [`http::AppState`]
/// — factored out of [`run_receiver`] so it is unit-testable without a
/// live NATS/license-server connection (see this module's own tests).
/// Takes the same [`EventBuffer`] every other receiver-mode listener
/// publishes through (Task 3.0b: `/ingest` used to write straight to
/// OpenSearch instead, bypassing the buffer's durability guarantee — see
/// `listeners::http`'s own doc comment).
fn build_ingest_state(
    buffer: Arc<dyn EventBuffer>,
    jwt_verify_key: jsonwebtoken::DecodingKey,
    license: Arc<penguin_licensing::LicenseClient>,
) -> http::AppState {
    http::AppState {
        buffer,
        clock: http::Clock::System,
        jwt_verify_key,
        license,
    }
}

/// Builds `crate::admin`'s shared [`admin::AppState`] for the ISM
/// hot/warm/cold admin surface — factored out of [`run_receiver`] mirroring
/// [`build_ingest_state`], so it is unit-testable (see this module's own
/// tests) without a live OpenSearch cluster: building a [`reqwest::Client`]
/// and wrapping already-loaded config/key values never makes network calls.
/// `audit` always uses [`admin::TracingAuditSink`] — see that type's own
/// doc comment for why this is a `tracing`-backed sink rather than a
/// database table for now.
///
/// # Errors
/// Returns an error only if the underlying `reqwest::Client` cannot be
/// built (e.g. the platform's TLS backend fails to initialize).
fn build_admin_state(
    opensearch_url: Arc<str>,
    snapshot_repo: Arc<str>,
    jwt_verify_key: jsonwebtoken::DecodingKey,
) -> anyhow::Result<admin::AppState> {
    let http = reqwest::Client::builder()
        .build()
        .map_err(|e| anyhow::anyhow!("admin http client: {e}"))?;
    Ok(admin::AppState {
        http,
        opensearch_url,
        snapshot_repo,
        jwt_verify_key,
        audit: Arc::new(admin::TracingAuditSink),
    })
}

/// Resolves on SIGTERM/SIGINT (Ctrl-C) — the trigger [`run_receiver`]/
/// [`run_writer`] forward onto their own shared shutdown channel. Mirrors
/// `main.rs`'s pre-Wave-1 health-surface-only implementation of the same
/// signal handling.
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

/// Resolves once `rx` observes `true` (see [`run_receiver`]/[`run_writer`]'s
/// shared `watch` channel) — the cancellation future every listener/server
/// task races its own work against.
async fn wait_for_shutdown(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Drains `tasks` to completion, logging and broadcasting shutdown to the
/// rest of the set the moment any one of them exits with an error before
/// shutdown was ever requested (e.g. a listener that could never bind, or
/// one whose required SPIFFE identity was unreachable in production
/// posture) — never leaves the process silently running with only some
/// listeners still serving. Returns the first such error, if any; `Ok(())`
/// once every task has resolved cleanly (the normal SIGTERM/SIGINT path).
async fn drain_listeners(
    mut tasks: JoinSet<ListenerOutcome>,
    shutdown_tx: &watch::Sender<bool>,
) -> anyhow::Result<()> {
    let mut first_error: Option<anyhow::Error> = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((name, Ok(()))) => {
                tracing::info!(listener = name, "listener stopped");
            }
            Ok((name, Err(e))) => {
                tracing::error!(
                    listener = name,
                    error = %e,
                    "listener exited with an error; shutting down the rest of the receiver"
                );
                let _ = shutdown_tx.send(true);
                first_error.get_or_insert(e);
            }
            Err(join_err) => {
                tracing::error!(
                    error = %join_err,
                    "listener task panicked or was cancelled; shutting down the rest of the receiver"
                );
                let _ = shutdown_tx.send(true);
                first_error.get_or_insert_with(|| {
                    anyhow::anyhow!("listener task join failed: {join_err}")
                });
            }
        }
    }
    match first_error {
        Some(e) => Err(e),
        None => {
            tracing::info!("svc-ingest receiver stopped cleanly");
            Ok(())
        }
    }
}

/// Runs every receiver-mode protocol listener concurrently until a
/// SIGTERM/SIGINT shutdown signal — see this module's top-level doc
/// comment.
///
/// # Errors
/// Returns an error if a shared dependency (NATS, Postgres, the SPIFFE
/// Workload API in production posture, `JWT_VERIFY_KEY`, the license
/// client config) cannot be built, the HTTPS ingest port cannot be bound,
/// or any listener exits with an error before shutdown was requested.
pub(crate) async fn run_receiver(cfg: Config) -> anyhow::Result<()> {
    let buffer = build_event_buffer(&cfg).await?;
    let otlp_grpc_store = Arc::new(build_grpc_identity_store().await?);
    // Shared SPIFFE workload identity for the OTLP gRPC listener's mTLS
    // termination (`otlp::run_grpc` itself degrades to a warned plaintext
    // fallback when `has_identity()` is false — see that function's own
    // doc comment; `IdentityProvider::connect` only ever returns `Err` in
    // production posture with no identity available at all). The
    // syslog-TLS listener connects to the Workload API independently
    // (`syslog::run_tls` is self-contained and mTLS-mandatory, with no
    // plaintext fallback) — the two listeners deliberately don't share one
    // provider instance; see `listeners::syslog`'s own doc comment.
    let identity = Arc::new(
        skauswatch_identity::IdentityProvider::connect()
            .await
            .map_err(|e| anyhow::anyhow!("otlp gRPC SPIFFE workload identity: {e}"))?,
    );

    let jwt_verify_key =
        skauswatch_auth::load_jwt_verify_key().map_err(|e| anyhow::anyhow!("{e}"))?;
    let license_cfg = penguin_licensing::LicenseConfig::from_env("skauswatch")
        .map_err(|e| anyhow::anyhow!("license config: {e}"))?
        .with_bypass_domain("skauswatch.app");
    let license = penguin_licensing::LicenseClient::new(license_cfg)
        .map_err(|e| anyhow::anyhow!("license client: {e}"))?;
    let _ = license.refresh().await;
    // License/flag refresh loop — fail-safe by design; startup never blocks
    // on the license server (mirrors `services/logs/src/main.rs`).
    let _license_bg = license.spawn_refresh();
    // `admin::AppState` needs its own copy of the verify key — `AppState`
    // below takes ownership of `jwt_verify_key` itself; `DecodingKey` is
    // cheaply `Clone` (wraps parsed key material, no I/O).
    let admin_state = build_admin_state(
        cfg.opensearch_url.as_str().into(),
        cfg.snapshot_repo.as_str().into(),
        jwt_verify_key.clone(),
    )?;
    // Shares the same `EventBuffer` every other receiver-mode listener
    // publishes through — the writer, never this listener, owns all
    // OpenSearch writes (Task 3.0b).
    let ingest_state = build_ingest_state(Arc::clone(&buffer), jwt_verify_key, license);
    // Merged, not nested: `crate::admin`'s `/api/v1/admin/...` paths are
    // disjoint from `crate::listeners::http`'s `/ingest`+`/healthz`+
    // `/readyz`, so `.merge()` is unambiguous and each router keeps its own
    // auth extractor untouched (see this module's top-level doc comment).
    let http_router = http::router(ingest_state).merge(admin::router(admin_state));

    let addr: SocketAddr = ([0, 0, 0, 0], cfg.http_port).into();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind ingest http {addr}: {e}"))?;
    tracing::info!(%addr, "svc-ingest http (OCSF/JSON) listening");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    {
        let shutdown_tx = shutdown_tx.clone();
        tokio::spawn(async move {
            shutdown_signal().await;
            let _ = shutdown_tx.send(true);
        });
    }

    let mut tasks: JoinSet<ListenerOutcome> = JoinSet::new();
    tasks.spawn({
        let cfg = cfg.clone();
        let buffer = Arc::clone(&buffer);
        let rx = shutdown_rx.clone();
        async move {
            let result: anyhow::Result<()> = tokio::select! {
                res = syslog::run_udp(&cfg, buffer) => res,
                _ = wait_for_shutdown(rx) => Ok(()),
            };
            ("syslog_udp", result)
        }
    });
    tasks.spawn({
        let cfg = cfg.clone();
        let buffer = Arc::clone(&buffer);
        let rx = shutdown_rx.clone();
        async move {
            let result: anyhow::Result<()> = tokio::select! {
                res = syslog::run_tcp(&cfg, buffer) => res,
                _ = wait_for_shutdown(rx) => Ok(()),
            };
            ("syslog_tcp", result)
        }
    });
    tasks.spawn({
        let cfg = cfg.clone();
        let buffer = Arc::clone(&buffer);
        let rx = shutdown_rx.clone();
        async move {
            let result: anyhow::Result<()> = tokio::select! {
                res = syslog::run_tls(&cfg, buffer) => res,
                _ = wait_for_shutdown(rx) => Ok(()),
            };
            ("syslog_tls", result)
        }
    });
    tasks.spawn({
        let cfg = cfg.clone();
        let buffer = Arc::clone(&buffer);
        let identity = Arc::clone(&identity);
        let store = Arc::clone(&otlp_grpc_store);
        let rx = shutdown_rx.clone();
        async move {
            let result: anyhow::Result<()> = tokio::select! {
                res = otlp::run_grpc(&cfg, buffer, Some(identity), store) => res,
                _ = wait_for_shutdown(rx) => Ok(()),
            };
            ("otlp_grpc", result)
        }
    });
    tasks.spawn({
        let cfg = cfg.clone();
        let buffer = Arc::clone(&buffer);
        let rx = shutdown_rx.clone();
        async move {
            let result: anyhow::Result<()> = tokio::select! {
                res = otlp::run_http(&cfg, buffer) => res,
                _ = wait_for_shutdown(rx) => Ok(()),
            };
            ("otlp_http", result)
        }
    });
    tasks.spawn({
        let rx = shutdown_rx.clone();
        async move {
            let result: anyhow::Result<()> = axum::serve(listener, http_router)
                .with_graceful_shutdown(wait_for_shutdown(rx))
                .await
                .map_err(|e| anyhow::anyhow!("http ingest server: {e}"));
            ("http_ingest", result)
        }
    });

    drain_listeners(tasks, &shutdown_tx).await
}

/// Parses `WRITER_HEALTH_PORT`'s raw value, falling back to
/// [`DEFAULT_WRITER_HEALTH_PORT`] when unset or unparsable — factored out
/// so it's unit-testable without mutating process environment state
/// (mirrors `config.rs`'s `RawConfig` pattern).
fn writer_health_port(raw: Option<&str>) -> u16 {
    raw.map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_WRITER_HEALTH_PORT)
}

/// Runs the writer-mode consume→bulk-write loop ([`crate::writer::run`])
/// until a SIGTERM/SIGINT shutdown signal, alongside a minimal
/// `/healthz`+`/readyz` surface on `WRITER_HEALTH_PORT` — see this module's
/// top-level doc comment for why writer mode needs one at all.
///
/// # Errors
/// Returns an error if NATS is unreachable (the main buffer, or the
/// dead-letter sink — see [`crate::writer::run`]), the health surface port
/// cannot be bound, or the writer loop itself exits with an error.
pub(crate) async fn run_writer(
    cfg: Config,
    readiness: skauswatch_telemetry::Readiness,
) -> anyhow::Result<()> {
    let buffer = build_event_buffer(&cfg).await?;
    let http_client = reqwest::Client::builder()
        .build()
        .map_err(|e| anyhow::anyhow!("http client: {e}"))?;

    let port = writer_health_port(std::env::var("WRITER_HEALTH_PORT").ok().as_deref());
    let addr: SocketAddr = ([0, 0, 0, 0], port).into();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| anyhow::anyhow!("bind writer health surface {addr}: {e}"))?;
    tracing::info!(%addr, "svc-ingest writer health surface listening");
    readiness.set_ready();

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let health = async {
        axum::serve(listener, skauswatch_telemetry::health_router(readiness))
            .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
            .await
            .map_err(|e| anyhow::anyhow!("writer health server: {e}"))
    };

    // `writer::run` never returns under normal operation (an infinite
    // consume/write/ack loop) except on a startup failure (e.g. the
    // dead-letter sink's NATS connection is unreachable — see
    // `writer::build_dlq_buffer`) — racing it against the health surface's
    // own graceful-shutdown lifecycle means a SIGTERM stops the whole
    // writer cleanly, and a genuine writer startup failure still surfaces
    // as this function's error instead of leaving a health endpoint
    // reporting ready forever with no writer actually running behind it.
    tokio::select! {
        result = health => result,
        result = crate::writer::run(&cfg, buffer, http_client) => result,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // -- wait_for_shutdown --------------------------------------------------

    /// `wait_for_shutdown` is the cancellation future every listener/server
    /// task in [`run_receiver`]/[`run_writer`] races its own work against —
    /// proves it actually resolves once the shared channel reports `true`,
    /// with no live listener/server involved.
    #[tokio::test]
    async fn wait_for_shutdown_resolves_once_the_channel_reports_true() {
        let (tx, rx) = watch::channel(false);
        tx.send(true).expect("send on an open channel");
        wait_for_shutdown(rx).await;
    }

    // -- drain_listeners ------------------------------------------------------

    /// The clean-shutdown path: every listener task exits `Ok(())` (the
    /// normal SIGTERM/SIGINT path, per this function's own doc comment) —
    /// `drain_listeners` must return `Ok(())` too, and must NOT itself
    /// broadcast a shutdown signal (that's reserved for the error path).
    #[tokio::test]
    async fn drain_listeners_returns_ok_when_every_task_succeeds() {
        let mut tasks: JoinSet<ListenerOutcome> = JoinSet::new();
        tasks.spawn(async { ("test_listener_ok", Ok(())) });
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        let result = drain_listeners(tasks, &shutdown_tx).await;

        assert!(result.is_ok());
        assert!(
            !*shutdown_tx.borrow(),
            "a clean stop must not itself trigger a shutdown broadcast"
        );
    }

    /// A listener task that exits with an `Err` before shutdown was ever
    /// requested must (a) surface as `drain_listeners`'s own `Err` and (b)
    /// broadcast shutdown so every other still-running listener is torn
    /// down too — never leave the process serving a half-degraded protocol
    /// surface (this function's own doc comment).
    #[tokio::test]
    async fn drain_listeners_propagates_the_first_error_and_signals_shutdown() {
        let mut tasks: JoinSet<ListenerOutcome> = JoinSet::new();
        tasks.spawn(async { ("test_listener_err", Err(anyhow::anyhow!("boom"))) });
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        let result = drain_listeners(tasks, &shutdown_tx).await;

        assert!(result.is_err());
        assert!(
            *shutdown_tx.borrow(),
            "an error exit must broadcast shutdown to the rest of the set"
        );
    }

    /// A panicking listener task surfaces to `tasks.join_next()` as
    /// `Err(JoinError)`, not the task's own `Result` — `drain_listeners`
    /// must treat that the same as an explicit `Err` exit: propagate it and
    /// broadcast shutdown, never silently swallow a panicked listener.
    #[tokio::test]
    async fn drain_listeners_treats_a_panicked_task_as_an_error_and_signals_shutdown() {
        let mut tasks: JoinSet<ListenerOutcome> = JoinSet::new();
        tasks.spawn(async {
            panic!("simulated listener panic");
        });
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        let result = drain_listeners(tasks, &shutdown_tx).await;

        assert!(result.is_err());
        assert!(*shutdown_tx.borrow());
    }

    /// Once one task has already failed (broadcasting shutdown), a second,
    /// still-draining task's own later `Err` must not replace the
    /// already-recorded first error — `drain_listeners` reports the FIRST
    /// failure, matching its own doc comment ("Returns the first such
    /// error, if any").
    #[tokio::test]
    async fn drain_listeners_keeps_the_first_error_when_a_second_task_also_fails() {
        let mut tasks: JoinSet<ListenerOutcome> = JoinSet::new();
        tasks.spawn(async { ("first", Err(anyhow::anyhow!("first failure"))) });
        tasks.spawn(async { ("second", Err(anyhow::anyhow!("second failure"))) });
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);

        let result = drain_listeners(tasks, &shutdown_tx).await;

        let err = result.expect_err("both tasks failed");
        assert!(
            err.to_string().contains("first failure"),
            "expected the FIRST failing task's error to be retained, got: {err}"
        );
        assert!(*shutdown_tx.borrow());
    }

    #[test]
    fn writer_health_port_defaults_when_unset() {
        assert_eq!(writer_health_port(None), DEFAULT_WRITER_HEALTH_PORT);
    }

    #[test]
    fn writer_health_port_parses_a_valid_override() {
        assert_eq!(writer_health_port(Some("9999")), 9999);
    }

    #[test]
    fn writer_health_port_falls_back_on_an_unparsable_value() {
        assert_eq!(
            writer_health_port(Some("not-a-port")),
            DEFAULT_WRITER_HEALTH_PORT
        );
    }

    #[test]
    fn writer_health_port_falls_back_on_an_empty_value() {
        assert_eq!(writer_health_port(Some("  ")), DEFAULT_WRITER_HEALTH_PORT);
    }

    /// Gate-1→2 wiring smoke test: the shared dependencies `run_receiver`
    /// assembles (the `EventBuffer`, a JWT verify key, a license client)
    /// really do fit `listeners::http::AppState`'s shape, and
    /// `listeners::http::router` accepts the result and builds a router
    /// without panicking — proves this integration point compiles *and*
    /// runs, not just that the types happen to line up on paper. A live
    /// end-to-end run against real NATS/Postgres is Wave 3, not this gate.
    #[test]
    fn build_ingest_state_produces_a_router_without_panicking() {
        let license = skauswatch_testkit::license::dev_license("skauswatch");
        let buffer: Arc<dyn EventBuffer> = Arc::new(crate::buffer::InMemoryBuffer::new(10));
        let state = build_ingest_state(
            buffer,
            skauswatch_testkit::jwt::verify_key().clone(),
            license,
        );
        let _router = http::router(state);
    }

    /// Regression guard for the whole-branch review finding: `crate::admin`'s
    /// router was built but never merged into the receiver's HTTP server, so
    /// `PUT /api/v1/admin/ingest/lifecycle`/`POST /api/v1/admin/ingest/
    /// restore` were unreachable in the running binary despite passing their
    /// own unit tests in isolation. Assembles the exact same merged router
    /// [`run_receiver`] serves (a lazy, never-dialed OpenSearch URL — this
    /// only proves route *resolution*, not a live OpenSearch round-trip,
    /// which stays this module's Wave 3 e2e responsibility) and drives it
    /// with `tower::ServiceExt::oneshot`: a 404 here means "still unmounted",
    /// full stop, regardless of the 401 an unauthenticated request also
    /// deserves.
    #[tokio::test]
    async fn admin_routes_are_mounted_on_the_receiver_http_router() {
        use tower::ServiceExt;

        let license = skauswatch_testkit::license::dev_license("skauswatch");
        let buffer: Arc<dyn EventBuffer> = Arc::new(crate::buffer::InMemoryBuffer::new(10));
        let jwt_verify_key = skauswatch_testkit::jwt::verify_key().clone();
        let ingest_state = build_ingest_state(buffer, jwt_verify_key.clone(), license);
        let admin_state = build_admin_state(
            "http://opensearch.invalid:9200".into(),
            "skauswatch-snapshots".into(),
            jwt_verify_key,
        )
        .expect("admin state builds with no live OpenSearch cluster required");
        let router = http::router(ingest_state).merge(admin::router(admin_state));

        for (method, uri) in [
            (axum::http::Method::PUT, "/api/v1/admin/ingest/lifecycle"),
            (axum::http::Method::POST, "/api/v1/admin/ingest/restore"),
        ] {
            let request = axum::http::Request::builder()
                .method(method.clone())
                .uri(uri)
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from("{}"))
                .expect("build request");
            let response = router
                .clone()
                .oneshot(request)
                .await
                .expect("router invocation");
            assert_ne!(
                response.status(),
                axum::http::StatusCode::NOT_FOUND,
                "{method} {uri} returned 404 -- route is not mounted"
            );
        }
    }
}
