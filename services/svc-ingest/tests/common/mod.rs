//! Shared end-to-end test harness for `skauswatch-svc-ingest` — the
//! foundation every Wave-3 e2e test (`tests/e2e_*.rs`) reuses instead of
//! hand-rolling its own container/process wiring. Starts real NATS
//! (JetStream) and OpenSearch containers via `testcontainers`, spawns the
//! *actual compiled* `skauswatch-svc-ingest` binary (never an in-process
//! mock) in `receiver`/`writer` mode wired to those containers plus the
//! shared test Postgres, and exposes bounded-wait client helpers for
//! driving `/ingest` and querying OpenSearch.
//!
//! # Formerly a blocker, now fixed upstream — `listeners::syslog::run_tls`
//! degrades gracefully without a live SPIFFE Workload API
//!
//! An earlier revision of this harness documented `run_tls` as hard-failing
//! (and, via `bootstrap::drain_listeners`, taking the whole receiver down
//! with it) whenever no live SPIFFE Workload API was reachable — the state
//! of every sandbox/CI runner that hasn't stood up SPIRE. That has since
//! been fixed at the source (`run_tls` now warns and returns `Ok(())`
//! without binding `SYSLOG_TLS_PORT`, mirroring `otlp::run_grpc`'s
//! plaintext-fallback precedent — see that function's own doc comment for
//! the exact degrade contract). No harness change was needed for the fix
//! to take effect: [`spawn_receiver`] already wired the environment a
//! working receiver needs.
//!
//! Still true: no real SPIFFE Workload API (SPIRE server+agent) is stood up
//! by this harness — correctly emulating the Workload API's X.509-SVID
//! streaming gRPC protocol from scratch is a large, failure-prone
//! undertaking for a test harness, and a genuine SPIRE deployment is heavy
//! test infrastructure of its own. This means `:6514` (syslog mTLS) never
//! actually binds in this environment; a real mTLS-handshake e2e test
//! against it needs a SPIRE-equipped environment (see `tests/e2e_syslog.rs`'s
//! `#[ignore]`d placeholder).
//!
//! # Public surface
//!
//! | Function | Purpose |
//! |---|---|
//! | [`start_nats`] | NATS 2.14+ container, JetStream + `sync_interval: always` (the config-file durability knob equivalent to "sync always" — `sync_always` is not a real nats-server config key, see that function's doc comment) |
//! | [`start_opensearch`] | Single-node OpenSearch 2.x container, security plugin disabled |
//! | [`setup_test_db`] | Creates + migrates a fresh, uniquely-named Postgres database on the shared test instance |
//! | [`JwtFixture::generate`] / [`JwtFixture::mint`] | ES256 keypair + tenant-bearing bearer tokens for `/ingest` |
//! | [`spawn_receiver`] | Spawns `skauswatch-svc-ingest serve --mode receiver` wired to the above |
//! | [`spawn_receiver_with_env`] | Same as `spawn_receiver`, plus caller-supplied extra env vars (e.g. `SYSLOG_UDP_ENABLED`) |
//! | [`spawn_writer`] | Spawns `skauswatch-svc-ingest serve --mode writer` wired to NATS + OpenSearch |
//! | [`post_ingest`] | `POST /ingest` against a running receiver |
//! | [`send_syslog_udp`] / [`send_syslog_tcp`] | Send one raw syslog line to a receiver's `syslog_port` over UDP/TCP |
//! | [`wait_for_document`] | Bounded poll of OpenSearch for a document matching a `tenant_id` term |

// This module is `mod common;`-included independently by every Wave-3
// `tests/e2e_*.rs` binary (each integration test file compiles as its own
// crate), and each one only exercises the subset of this harness's public
// surface its own scenario needs — e.g. `tests/e2e_harness_smoke.rs` never
// reads `ReceiverProcess::syslog_port`, but a future syslog e2e test will.
// `dead_code` can't see across that per-binary boundary, so it flags every
// currently-unused-by-this-test-binary `pub` field; same rationale as the
// `#![allow(dead_code)]` already used across `src/*.rs` for modules wired
// for a later integration gate (see e.g. `src/listeners/syslog/mod.rs`).
#![allow(dead_code)]

use std::future::Future;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use pkcs8::{EncodePrivateKey, EncodePublicKey};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tokio::time::Instant;
use uuid::Uuid;

/// Upper bound on every container-startup wait in this harness. No wait
/// anywhere in this module is allowed to block indefinitely (house rule —
/// `critical-rules.md` Verification Integrity).
const CONTAINER_STARTUP_TIMEOUT: Duration = Duration::from_secs(180);
/// Upper bound on waiting for a spawned `skauswatch-svc-ingest` process to
/// either answer its health endpoint or exit early.
const PROCESS_READY_TIMEOUT: Duration = Duration::from_secs(20);
/// Upper bound on polling OpenSearch for a just-written document to become
/// searchable (default OpenSearch refresh interval is 1s; generous margin
/// for a cold single-node dev container).
const DOCUMENT_INDEXED_TIMEOUT: Duration = Duration::from_secs(30);
/// Upper bound on any single HTTP call this harness makes.
const HTTP_CALL_TIMEOUT: Duration = Duration::from_secs(10);

/// Runs `fut`, converting a timeout into a descriptive `anyhow::Error`
/// rather than ever blocking indefinitely.
async fn bounded<T>(dur: Duration, what: &str, fut: impl Future<Output = Result<T>>) -> Result<T> {
    match tokio::time::timeout(dur, fut).await {
        Ok(inner) => inner,
        Err(_) => bail!("timed out after {dur:?} waiting for {what}"),
    }
}

/// Binds `count` distinct ephemeral TCP ports on loopback simultaneously
/// (all sockets held open until every one is bound), then releases them
/// together, for handing a batch of free port numbers to one spawned
/// process. Binding the whole batch before releasing any of them is
/// deliberate: releasing-then-rebinding one probe at a time let the OS
/// ephemeral allocator hand the very next probe in the *same batch* the
/// port just freed by the previous one — observed empirically here (two
/// `free_tcp_port`-style sequential calls returned the identical port,
/// which surfaced downstream as a genuine listener bind collision). This
/// only closes that self-collision within one batch; the general TOCTOU
/// window against the rest of the system (something else grabbing a port
/// between release and the child's own bind) is the standard, widely-used
/// test-harness tradeoff absent OS-level socket inheritance support in the
/// target binary.
fn free_tcp_ports(count: usize) -> Result<Vec<u16>> {
    let listeners: Vec<std::net::TcpListener> = (0..count)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").context("bind ephemeral port probe"))
        .collect::<Result<_>>()?;
    listeners
        .iter()
        .map(|l| {
            Ok(l.local_addr()
                .context("read ephemeral port probe addr")?
                .port())
        })
        .collect()
}

// ---------------------------------------------------------------------
// NATS (JetStream) container
// ---------------------------------------------------------------------

/// A running NATS JetStream container plus the URL to reach it. Dropping
/// this (via the held [`ContainerAsync`]) removes the container.
pub struct NatsHandle {
    _container: ContainerAsync<GenericImage>,
    /// `nats://host:port` — pass as `NATS_URL` to a spawned receiver/writer.
    pub url: String,
}

/// Starts a NATS 2.14+ container with JetStream enabled and the file
/// store's true "sync every write to disk" durability mode.
///
/// `sync_always` (as literally named in the Task 3.0 brief) is not a real
/// nats-server config key — verified empirically against `nats:2.14-alpine`
/// (`unknown field "sync_always"` at both top level and nested under
/// `jetstream {}`). The real equivalent is the jetstream block's
/// `sync_interval` config key accepting the special string value
/// `"always"` (as opposed to a duration, which throttles fsync to that
/// interval instead) — confirmed to start cleanly against the same image.
/// Passed via a config file (`-c`) copied into the container rather than
/// CLI flags, since `sync_interval` has no CLI-flag equivalent
/// (`nats-server -h`'s JetStream Options section only exposes `-js`/`-sd`).
pub async fn start_nats() -> Result<NatsHandle> {
    const NATS_CONF: &str =
        "port: 4222\njetstream {\n  store_dir: \"/data\"\n  sync_interval: \"always\"\n}\n";

    let image = GenericImage::new("nats", "2.14-alpine")
        .with_exposed_port(4222.tcp())
        .with_wait_for(WaitFor::message_on_stderr("Server is ready"))
        .with_copy_to("/etc/nats/nats.conf", NATS_CONF.as_bytes().to_vec())
        .with_cmd(["-c", "/etc/nats/nats.conf"])
        .with_startup_timeout(CONTAINER_STARTUP_TIMEOUT);

    let container = bounded(
        CONTAINER_STARTUP_TIMEOUT,
        "nats container to start",
        async { image.start().await.context("start nats container") },
    )
    .await?;

    let host = container.get_host().await.context("nats container host")?;
    let port = container
        .get_host_port_ipv4(4222)
        .await
        .context("nats container mapped port")?;
    let url = format!("nats://{host}:{port}");

    // The log-line wait strategy already gates container start, but a
    // bounded active dial closes the (small) gap between "log line
    // printed" and "actually accepting connections" instead of trusting
    // the log message alone.
    bounded(
        CONTAINER_STARTUP_TIMEOUT,
        "nats to accept a client connection",
        async {
            loop {
                match async_nats::connect(&url).await {
                    Ok(_client) => return Ok(()),
                    Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
                }
            }
        },
    )
    .await?;

    Ok(NatsHandle {
        _container: container,
        url,
    })
}

// ---------------------------------------------------------------------
// OpenSearch container
// ---------------------------------------------------------------------

/// A running single-node OpenSearch container plus the URL to reach it.
pub struct OpenSearchHandle {
    _container: ContainerAsync<GenericImage>,
    /// `http://host:port` — pass as `OPENSEARCH_URL` to a spawned
    /// receiver/writer, or use directly with [`search_opensearch`]/
    /// [`wait_for_document`].
    pub url: String,
}

/// Starts a single-node OpenSearch 2.x container with the security plugin
/// disabled (no auth/TLS needed for a hermetic test cluster — matches the
/// "security demo disabled for tests" brief).
pub async fn start_opensearch() -> Result<OpenSearchHandle> {
    let image = GenericImage::new("opensearchproject/opensearch", "2")
        .with_exposed_port(9200.tcp())
        .with_wait_for(WaitFor::Nothing)
        .with_env_var("discovery.type", "single-node")
        .with_env_var("DISABLE_SECURITY_PLUGIN", "true")
        .with_env_var("DISABLE_INSTALL_DEMO_CONFIG", "true")
        .with_env_var("OPENSEARCH_JAVA_OPTS", "-Xms512m -Xmx512m")
        .with_startup_timeout(CONTAINER_STARTUP_TIMEOUT);

    let container = bounded(
        CONTAINER_STARTUP_TIMEOUT,
        "opensearch container to start",
        async { image.start().await.context("start opensearch container") },
    )
    .await?;

    let host = container
        .get_host()
        .await
        .context("opensearch container host")?;
    let port = container
        .get_host_port_ipv4(9200)
        .await
        .context("opensearch container mapped port")?;
    let url = format!("http://{host}:{port}");

    // `WaitFor::Nothing` above deliberately defers all readiness to this
    // active poll: OpenSearch's JSON log lines are too version/plugin-set
    // dependent to pattern-match reliably, whereas polling the cluster
    // health API is the documented readiness contract.
    let client = reqwest::Client::new();
    let health_url = format!("{url}/_cluster/health");
    bounded(
        CONTAINER_STARTUP_TIMEOUT,
        "opensearch cluster health to report ready",
        async {
            loop {
                match client
                    .get(&health_url)
                    .timeout(Duration::from_secs(2))
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => return Ok(()),
                    _ => tokio::time::sleep(Duration::from_millis(300)).await,
                }
            }
        },
    )
    .await?;

    Ok(OpenSearchHandle {
        _container: container,
        url,
    })
}

/// `POST {opensearch_url}/{index_pattern}/_search` with an arbitrary query
/// body, returning the parsed JSON response. A non-2xx status is an error
/// (rather than returning the error body as if it were a result), so
/// callers never mistake an OpenSearch-side failure for "zero hits".
pub async fn search_opensearch(
    opensearch_url: &str,
    index_pattern: &str,
    query: &serde_json::Value,
) -> Result<serde_json::Value> {
    let url = format!("{opensearch_url}/{index_pattern}/_search");
    let resp = reqwest::Client::new()
        .post(&url)
        .json(query)
        .timeout(HTTP_CALL_TIMEOUT)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let body: serde_json::Value = resp
        .json()
        .await
        .context("parse opensearch _search response body")?;
    if !status.is_success() {
        bail!("opensearch _search on {index_pattern} returned {status}: {body}");
    }
    Ok(body)
}

/// Polls `{index_pattern}/_search` (default `skauswatch-logs-*`, the daily
/// index pattern every listener/writer in this service writes to) for a
/// document whose top-level `tenant_id` field exactly matches `tenant`,
/// bounded by [`DOCUMENT_INDEXED_TIMEOUT`]. Every listener path
/// (`crate::listeners::http::stamp_tenant`, and the OCSF mapping every
/// syslog/OTLP event goes through before the writer indexes it) stamps
/// `tenant_id` from the caller's validated JWT tenant claim, so minting a
/// fresh, unique tenant per test run (see [`JwtFixture::mint`]) doubles as
/// a collision-free "did my specific write land" marker without depending
/// on how any particular listener normalizes the rest of the document.
pub async fn wait_for_document(opensearch_url: &str, tenant: &str) -> Result<serde_json::Value> {
    let query = serde_json::json!({
        "query": { "term": { "tenant_id.keyword": tenant } }
    });
    bounded(
        DOCUMENT_INDEXED_TIMEOUT,
        &format!("a document with tenant_id={tenant} to become searchable"),
        async {
            loop {
                if let Ok(body) =
                    search_opensearch(opensearch_url, "skauswatch-logs-*", &query).await
                {
                    let hits = body["hits"]["total"]["value"].as_u64().unwrap_or(0);
                    if hits > 0 {
                        return Ok(body);
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        },
    )
    .await
}

// ---------------------------------------------------------------------
// Test Postgres database
// ---------------------------------------------------------------------

/// A dedicated, migrated Postgres database on the shared test instance
/// (`localhost:5432`, `postgres`/`postgres` — already running per the
/// harness's environment contract). Uniquely named per call so parallel
/// `cargo test` runs (and parallel worktrees sharing the same Postgres
/// instance) never collide.
pub struct TestDb {
    /// The created database's name.
    pub name: String,
    admin_url: String,
}

/// Standard `DB_*` connection env vars (see `skauswatch_db::DbConfig`) for
/// this database — pass directly via [`Command::envs`].
pub fn db_env_vars(db: &TestDb) -> Vec<(&'static str, String)> {
    vec![
        ("DB_TYPE", "postgresql".to_owned()),
        ("DB_HOST", "localhost".to_owned()),
        ("DB_PORT", "5432".to_owned()),
        ("DB_NAME", db.name.clone()),
        ("DB_USER", "postgres".to_owned()),
        ("DB_PASS", "postgres".to_owned()),
        ("DB_MAX_RETRIES", "3".to_owned()),
        ("DB_RETRY_DELAY", "1".to_owned()),
    ]
}

/// Creates a fresh `svc_ingest_e2e_<uuid>` database on the shared test
/// Postgres instance and applies every pending migration by invoking the
/// compiled binary's own `migrate` subcommand (the same K8s Job code path
/// production uses — see `main.rs::migrate`), rather than re-implementing
/// migration application here.
pub async fn setup_test_db() -> Result<TestDb> {
    let admin_url = "postgres://postgres:postgres@localhost:5432/postgres".to_owned();
    let name = format!("svc_ingest_e2e_{}", Uuid::new_v4().simple());

    bounded(Duration::from_secs(30), "test database creation", async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&admin_url)
            .await
            .context("connect to admin postgres database")?;
        // `AssertSqlSafe`: `name` is never attacker/caller-controlled — it's
        // this function's own `svc_ingest_e2e_<uuid-simple-hex>` literal
        // (see above), and CREATE DATABASE's identifier can't be a sqlx
        // bind parameter anyway. Manually audited per sqlx 0.9's
        // `SqlSafeStr` contract.
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
            .execute(&pool)
            .await
            .context("CREATE DATABASE")?;
        Ok(())
    })
    .await?;

    let db = TestDb { name, admin_url };

    let bin = env!("CARGO_BIN_EXE_skauswatch-svc-ingest");
    let status = bounded(Duration::from_secs(30), "migrate subcommand", async {
        Command::new(bin)
            .arg("migrate")
            .envs(db_env_vars(&db))
            .env("RELEASE_MODE", "false")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .status()
            .await
            .context("run migrate subcommand")
    })
    .await?;
    if !status.success() {
        bail!(
            "skauswatch-svc-ingest migrate exited with {status} for database {}",
            db.name
        );
    }

    Ok(db)
}

impl Drop for TestDb {
    /// Best-effort async cleanup: `DROP DATABASE` on a detached task. Drop
    /// itself can't be async, and test-database accumulation on a
    /// throwaway local Postgres instance is a hygiene concern, not a
    /// correctness one, so a failed/skipped cleanup is only ever logged,
    /// never propagated.
    fn drop(&mut self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let admin_url = self.admin_url.clone();
        let name = self.name.clone();
        handle.spawn(async move {
            let Ok(pool) = sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                .connect(&admin_url)
                .await
            else {
                eprintln!("test-harness: TestDb cleanup: could not connect to drop {name}");
                return;
            };
            // See the matching `AssertSqlSafe` note at `CREATE DATABASE`
            // above — `name` is this struct's own generated identifier,
            // never external input.
            if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"
            )))
            .execute(&pool)
            .await
            {
                eprintln!("test-harness: TestDb cleanup: DROP DATABASE {name} failed: {e}");
            }
        });
    }
}

// ---------------------------------------------------------------------
// JWT fixture (bearer tokens for /ingest)
// ---------------------------------------------------------------------

/// A freshly generated ES256 (P-256) keypair for minting `/ingest` bearer
/// tokens, plus the public key's PEM text to hand the spawned receiver as
/// `JWT_VERIFY_KEY`.
///
/// Generated independently per harness run rather than reusing
/// `skauswatch_auth`'s/`skauswatch_testkit::jwt`'s shared in-process
/// fixture keypair: that cache is a `std::sync::OnceLock` scoped to one OS
/// process, and the receiver this harness mints tokens for runs as a
/// *separate* spawned process with its own, unrelated cache — there is no
/// way to read that subprocess's ephemeral key back out to sign a token
/// against it, so this harness must supply (and know) the key pair itself.
pub struct JwtFixture {
    signing_key: EncodingKey,
    /// SPKI PEM text — pass as `JWT_VERIFY_KEY` when spawning a receiver.
    pub verify_key_pem: String,
}

impl JwtFixture {
    /// Generates a new keypair. Mirrors
    /// `skauswatch_auth::shared_dev_keypair`'s exact keygen/PEM-encode
    /// sequence (same crates, same key type) so the resulting PEM is
    /// guaranteed parseable by `skauswatch_auth::load_jwt_verify_key`.
    pub fn generate() -> Result<Self> {
        let secret = p256::SecretKey::random(&mut rand_core::OsRng);
        let private_pem = secret
            .to_pkcs8_pem(pkcs8::LineEnding::LF)
            .context("encode fixture private key to PKCS#8 PEM")?
            .to_string();
        let verify_key_pem = secret
            .public_key()
            .to_public_key_pem(pkcs8::LineEnding::LF)
            .context("encode fixture public key to SPKI PEM")?;
        let signing_key = EncodingKey::from_ec_pem(private_pem.as_bytes())
            .context("build jsonwebtoken EncodingKey from fixture PEM")?;
        Ok(Self {
            signing_key,
            verify_key_pem,
        })
    }

    /// Mints a short-lived, tenant-bearing bearer token satisfying
    /// `skauswatch_auth::tenant_middleware` (`iss`/`aud` set to the house
    /// `EXPECTED_ISS`/`EXPECTED_AUD` constants, non-empty `tenant`). No
    /// scopes are set: `/ingest`'s router only layers `FlagGate` +
    /// `tenant_middleware`, neither of which checks `scope`.
    pub fn mint(&self, tenant: &str) -> Result<String> {
        let now = chrono::Utc::now().timestamp();
        let claims = skauswatch_auth::Claims {
            sub: "svc-ingest-e2e-harness".to_owned(),
            iss: skauswatch_auth::EXPECTED_ISS.to_owned(),
            aud: skauswatch_auth::EXPECTED_AUD.to_owned(),
            iat: now,
            exp: now + 300,
            scope: String::new(),
            tenant: tenant.to_owned(),
            teams: vec![],
            roles: vec![],
        };
        jsonwebtoken::encode(&Header::new(Algorithm::ES256), &claims, &self.signing_key)
            .context("mint e2e harness bearer token")
    }
}

// ---------------------------------------------------------------------
// Spawned-process output capture
// ---------------------------------------------------------------------

/// Captures a spawned child's combined stdout/stderr line-by-line into an
/// in-memory buffer, so a readiness timeout or early-exit failure can
/// report exactly what the process printed instead of a bare exit code.
#[derive(Clone, Default)]
struct OutputCapture(Arc<Mutex<String>>);

impl OutputCapture {
    fn spawn_reader<R>(&self, reader: R, label: &'static str)
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        let buf = Arc::clone(&self.0);
        tokio::spawn(async move {
            let mut lines = BufReader::new(reader).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let mut b = buf.lock().await;
                b.push_str(label);
                b.push_str(": ");
                b.push_str(&line);
                b.push('\n');
            }
        });
    }

    async fn snapshot(&self) -> String {
        self.0.lock().await.clone()
    }
}

/// Polls `{url}` (a `GET /healthz`-shaped endpoint) until it answers 2xx,
/// bounded by [`PROCESS_READY_TIMEOUT`] — and fails fast, with captured
/// process output, the moment `child` exits before ever becoming ready.
/// This is the check that surfaces this harness's known upstream blocker
/// (see this module's top-level doc comment) as a clear, immediate error
/// instead of a 20-second silent hang.
async fn wait_process_ready(child: &mut Child, url: &str, output: &OutputCapture) -> Result<()> {
    let client = reqwest::Client::new();
    let deadline = Instant::now() + PROCESS_READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait().context("poll child process status")? {
            let captured = output.snapshot().await;
            bail!(
                "skauswatch-svc-ingest exited ({status}) before {url} became ready — captured output:\n{captured}"
            );
        }
        if Instant::now() >= deadline {
            let captured = output.snapshot().await;
            bail!(
                "timed out after {PROCESS_READY_TIMEOUT:?} waiting for {url} to become ready — captured output:\n{captured}"
            );
        }
        match client.get(url).timeout(Duration::from_secs(2)).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(150)).await,
        }
    }
}

// ---------------------------------------------------------------------
// Receiver / writer process handles
// ---------------------------------------------------------------------

/// A spawned `skauswatch-svc-ingest serve --mode receiver` process and the
/// ports it bound. Killed (best-effort, non-blocking) on drop.
pub struct ReceiverProcess {
    child: Child,
    output: OutputCapture,
    /// Bound HTTPS OCSF/JSON `/ingest` port (`HTTP_PORT`) — actually plain
    /// HTTP at the process level; TLS termination is an ingress/mesh
    /// concern in production (see `bootstrap::run_receiver`, which binds a
    /// bare `TcpListener`, never a `tokio_rustls::TlsAcceptor`, for this
    /// listener specifically).
    pub http_port: u16,
    /// Plain syslog UDP/TCP port (`SYSLOG_PORT`) — unauthenticated
    /// transports, left disabled by default (`SYSLOG_UDP_ENABLED=false`,
    /// this harness's default) per Spec §6c.
    pub syslog_port: u16,
    /// Syslog mTLS port (`SYSLOG_TLS_PORT`) — see this module's top-level
    /// doc comment: this listener cannot currently bind without a live
    /// SPIFFE Workload API, so the whole receiver process exits before any
    /// port (including `http_port`) ever becomes reachable.
    pub syslog_tls_port: u16,
    /// OTLP gRPC logs port (`OTLP_GRPC_PORT`).
    pub otlp_grpc_port: u16,
    /// OTLP HTTP logs port (`OTLP_HTTP_PORT`).
    pub otlp_http_port: u16,
    /// The JWT fixture this receiver was started with — mint bearer
    /// tokens against it via [`JwtFixture::mint`] to call `/ingest`.
    pub jwt: JwtFixture,
}

impl ReceiverProcess {
    /// Snapshot of everything the process has printed to stdout/stderr so
    /// far, for assertion failure messages beyond the readiness wait's own
    /// bundled diagnostics.
    pub async fn output(&self) -> String {
        self.output.snapshot().await
    }
}

impl Drop for ReceiverProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Spawns the compiled `skauswatch-svc-ingest` binary in `serve --mode
/// receiver`, wired to `nats`/`opensearch`/`db` via the standard env vars,
/// on freshly allocated ports. `RELEASE_MODE=false` (dev posture): without
/// it, `skauswatch_auth::is_production`/`skauswatch_identity::
/// IdentityProvider::connect`/`penguin_licensing::LicenseConfig` all
/// default to (or require) production-grade secrets/attestation this
/// harness has no way to supply, and every request would additionally be
/// denied by the `skauswatch.log-ingest` PostHog flag (unreachable license
/// server, default-OFF) — dev posture makes `penguin_licensing`'s
/// `release_mode` follow the same `RELEASE_MODE` value and evaluate every
/// flag enabled (see `LicenseConfig::from_env`/`LicenseConfig::new`'s
/// `release_mode: false` default).
///
/// Waits (bounded, [`PROCESS_READY_TIMEOUT`]) for `/healthz` to answer —
/// see this module's top-level doc comment for the known upstream blocker
/// this wait currently surfaces (`run_tls` hard-failing without a live
/// SPIFFE Workload API, which cascades to the whole receiver exiting).
///
/// # Errors
/// Returns an error if the process cannot be spawned, or exits/times out
/// before `/healthz` answers 2xx (captured stdout/stderr included in the
/// message).
pub async fn spawn_receiver(
    nats: &NatsHandle,
    opensearch: &OpenSearchHandle,
    db: &TestDb,
) -> Result<ReceiverProcess> {
    spawn_receiver_with_env(nats, opensearch, db, &[]).await
}

/// Identical to [`spawn_receiver`], additionally applying every `(name,
/// value)` pair in `extra_env` on top of the standard wiring — the seam a
/// later Wave-3 e2e test reaches for instead of hand-rolling its own
/// process spawn. Introduced for the syslog e2e test's
/// `SYSLOG_UDP_ENABLED`/`SYSLOG_TRUSTED_CIDRS`/`SYSLOG_UDP_TENANT_ID`, but
/// generic over any env var: an OTLP or durability e2e test can pass its
/// own opt-in knobs the same way without another harness change.
/// `extra_env` is applied via `Command::envs` *after* every other `.env()`
/// call below, so a caller can also override one of the defaults set here
/// (e.g. a non-default `HTTP_PORT`) if a future test ever needs to,
/// though today's only caller ([`spawn_receiver`], via `&[]`) adds new
/// keys rather than replacing existing ones.
///
/// # Errors
/// Returns an error if the process cannot be spawned, or exits/times out
/// before `/healthz` answers 2xx (captured stdout/stderr included in the
/// message).
pub async fn spawn_receiver_with_env(
    nats: &NatsHandle,
    opensearch: &OpenSearchHandle,
    db: &TestDb,
    extra_env: &[(&str, &str)],
) -> Result<ReceiverProcess> {
    let bin = env!("CARGO_BIN_EXE_skauswatch-svc-ingest");
    let jwt = JwtFixture::generate().context("generate receiver JWT fixture")?;

    let ports = free_tcp_ports(6).context("allocate receiver ports")?;
    let &[
        http_port,
        syslog_port,
        syslog_tls_port,
        otlp_grpc_port,
        otlp_http_port,
        metrics_port,
    ] = ports.as_slice()
    else {
        bail!(
            "free_tcp_ports(6) returned {} ports, expected 6",
            ports.len()
        );
    };

    let mut cmd = Command::new(bin);
    cmd.arg("serve")
        .arg("--mode")
        .arg("receiver")
        .env("RELEASE_MODE", "false")
        .env("HTTP_PORT", http_port.to_string())
        .env("SYSLOG_PORT", syslog_port.to_string())
        .env("SYSLOG_TLS_PORT", syslog_tls_port.to_string())
        .env("OTLP_GRPC_PORT", otlp_grpc_port.to_string())
        .env("OTLP_HTTP_PORT", otlp_http_port.to_string())
        // Distinct per-process metrics port: the harness co-locates
        // receiver + writer on one host (in K8s they're separate pods on
        // the same well-known :9090), so both would otherwise race to bind
        // the telemetry crate's default Prometheus port. See
        // `skauswatch_telemetry::install_metrics_exporter`.
        .env("METRICS_PORT", metrics_port.to_string())
        .env("OPENSEARCH_URL", &opensearch.url)
        .env("NATS_URL", &nats.url)
        .env("JWT_VERIFY_KEY", &jwt.verify_key_pem)
        .envs(db_env_vars(db))
        .envs(extra_env.iter().copied())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .context("spawn skauswatch-svc-ingest serve --mode receiver")?;
    let output = OutputCapture::default();
    if let Some(stdout) = child.stdout.take() {
        output.spawn_reader(stdout, "receiver stdout");
    }
    if let Some(stderr) = child.stderr.take() {
        output.spawn_reader(stderr, "receiver stderr");
    }

    let healthz = format!("http://127.0.0.1:{http_port}/healthz");
    wait_process_ready(&mut child, &healthz, &output).await?;

    Ok(ReceiverProcess {
        child,
        output,
        http_port,
        syslog_port,
        syslog_tls_port,
        otlp_grpc_port,
        otlp_http_port,
        jwt,
    })
}

/// A spawned `skauswatch-svc-ingest serve --mode writer` process. Killed
/// (best-effort, non-blocking) on drop. Unlike [`ReceiverProcess`], writer
/// mode needs no database (see `bootstrap::run_writer`: it builds only the
/// NATS-backed event buffer and an HTTP client for OpenSearch bulk
/// writes) and has no SPIFFE dependency, so it is unaffected by this
/// module's documented receiver-mode blocker.
pub struct WriterProcess {
    child: Child,
    output: OutputCapture,
    /// Bound minimal `/healthz`+`/readyz` surface port (`WRITER_HEALTH_PORT`).
    pub health_port: u16,
}

impl WriterProcess {
    /// Snapshot of everything the process has printed to stdout/stderr so far.
    pub async fn output(&self) -> String {
        self.output.snapshot().await
    }
}

impl Drop for WriterProcess {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
    }
}

/// Spawns the compiled `skauswatch-svc-ingest` binary in `serve --mode
/// writer`, wired to `nats`/`opensearch` via the standard env vars, on a
/// freshly allocated health port. Waits (bounded, [`PROCESS_READY_TIMEOUT`])
/// for `/healthz` to answer.
///
/// # Errors
/// Returns an error if the process cannot be spawned, or exits/times out
/// before `/healthz` answers 2xx (captured stdout/stderr included in the
/// message).
pub async fn spawn_writer(
    nats: &NatsHandle,
    opensearch: &OpenSearchHandle,
) -> Result<WriterProcess> {
    let bin = env!("CARGO_BIN_EXE_skauswatch-svc-ingest");
    let ports = free_tcp_ports(2).context("allocate writer ports")?;
    let &[health_port, metrics_port] = ports.as_slice() else {
        bail!(
            "free_tcp_ports(2) returned {} ports, expected 2",
            ports.len()
        );
    };

    let mut cmd = Command::new(bin);
    cmd.arg("serve")
        .arg("--mode")
        .arg("writer")
        .env("RELEASE_MODE", "false")
        .env("WRITER_HEALTH_PORT", health_port.to_string())
        // See the matching comment in `spawn_receiver`: distinct per-process
        // metrics port so receiver + writer don't race to bind :9090 when
        // co-located on one host.
        .env("METRICS_PORT", metrics_port.to_string())
        .env("OPENSEARCH_URL", &opensearch.url)
        .env("NATS_URL", &nats.url)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd
        .spawn()
        .context("spawn skauswatch-svc-ingest serve --mode writer")?;
    let output = OutputCapture::default();
    if let Some(stdout) = child.stdout.take() {
        output.spawn_reader(stdout, "writer stdout");
    }
    if let Some(stderr) = child.stderr.take() {
        output.spawn_reader(stderr, "writer stderr");
    }

    let healthz = format!("http://127.0.0.1:{health_port}/healthz");
    wait_process_ready(&mut child, &healthz, &output).await?;

    Ok(WriterProcess {
        child,
        output,
        health_port,
    })
}

// ---------------------------------------------------------------------
// /ingest client helper
// ---------------------------------------------------------------------

/// `POST /ingest` against a running [`ReceiverProcess`] with a bearer
/// token minted from its own [`JwtFixture`], bounded by
/// [`HTTP_CALL_TIMEOUT`].
pub async fn post_ingest(
    receiver: &ReceiverProcess,
    tenant: &str,
    body: &serde_json::Value,
) -> Result<reqwest::Response> {
    let token = receiver.jwt.mint(tenant)?;
    let url = format!("http://127.0.0.1:{}/ingest", receiver.http_port);
    reqwest::Client::new()
        .post(&url)
        .bearer_auth(token)
        .json(body)
        .timeout(HTTP_CALL_TIMEOUT)
        .send()
        .await
        .with_context(|| format!("POST {url}"))
}

// ---------------------------------------------------------------------
// Raw syslog client helpers (UDP/TCP)
// ---------------------------------------------------------------------

/// Upper bound on sending a single raw syslog line over UDP or TCP to a
/// locally spawned receiver.
const SYSLOG_SEND_TIMEOUT: Duration = Duration::from_secs(5);

/// Sends `line` as a single UDP datagram to `127.0.0.1:{port}` — one
/// datagram per call, mirroring how a real syslog UDP sender emits one
/// whole message per packet (no trailing newline needed or added; see
/// `listeners::syslog::consume_udp`, which parses the entire received
/// datagram as one message). Bound by [`SYSLOG_SEND_TIMEOUT`].
///
/// # Errors
/// Returns an error if the ephemeral send socket cannot be bound, or the
/// datagram cannot be sent, within [`SYSLOG_SEND_TIMEOUT`].
pub async fn send_syslog_udp(port: u16, line: &str) -> Result<()> {
    bounded(SYSLOG_SEND_TIMEOUT, "send syslog UDP datagram", async {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .context("bind ephemeral UDP socket for syslog send")?;
        socket
            .send_to(line.as_bytes(), ("127.0.0.1", port))
            .await
            .context("send syslog UDP datagram")?;
        Ok(())
    })
    .await
}

/// Sends `line` as a single newline-delimited syslog message to
/// `127.0.0.1:{port}` over a fresh TCP connection — one message per call
/// (dial, write, flush, then let the connection close on drop), mirroring
/// `listeners::syslog::read_and_enqueue_lines`'s newline-framed read loop.
/// A trailing `\n` is appended to `line` only if it doesn't already have
/// one. Bound by [`SYSLOG_SEND_TIMEOUT`].
///
/// # Errors
/// Returns an error if the connection cannot be established, or the line
/// cannot be written and flushed, within [`SYSLOG_SEND_TIMEOUT`].
pub async fn send_syslog_tcp(port: u16, line: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    bounded(SYSLOG_SEND_TIMEOUT, "send syslog TCP line", async {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .context("connect syslog TCP")?;
        let mut payload = line.as_bytes().to_vec();
        if !line.ends_with('\n') {
            payload.push(b'\n');
        }
        stream
            .write_all(&payload)
            .await
            .context("write syslog TCP line")?;
        stream.flush().await.context("flush syslog TCP line")?;
        Ok(())
    })
    .await
}
