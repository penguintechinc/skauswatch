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
//! | [`spawn_writer_with_env`] | Same as `spawn_writer`, plus caller-supplied extra env vars (e.g. `OTEL_EXPORTER_OTLP_ENDPOINT`) |
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
use prost::Message as _;
use skauswatch_proto::opentelemetry::proto::collector::logs::v1::{
    ExportLogsServiceRequest, logs_service_client::LogsServiceClient,
};
use skauswatch_proto::opentelemetry::proto::common::v1::{
    AnyValue, KeyValue, any_value::Value as OtlpAnyValue,
};
use skauswatch_proto::opentelemetry::proto::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
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
    wait_for_opensearch_health(&url).await?;

    Ok(OpenSearchHandle {
        _container: container,
        url,
    })
}

/// Polls `{url}/_cluster/health` until it answers 2xx, bounded by
/// [`CONTAINER_STARTUP_TIMEOUT`] — [`start_opensearch`]'s own first-boot
/// readiness gate.
async fn wait_for_opensearch_health(url: &str) -> Result<()> {
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
    .await
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

/// Upper bound on waiting for one specific marker-bearing message to become
/// searchable in `skauswatch-logs-*`.
const MESSAGE_INDEXED_TIMEOUT: Duration = Duration::from_secs(30);

/// Polls `{tenant}`-scoped `skauswatch-logs-*` documents for one whose
/// `message` field contains `marker`, bounded by
/// [`MESSAGE_INDEXED_TIMEOUT`]. Unlike [`wait_for_document`] (which only
/// matches on `tenant_id` and returns the first hit for that tenant), this
/// is the helper to reach for whenever more than one message can land under
/// the same tenant in one test run — e.g. two OTLP transports (gRPC/HTTP)
/// or multiple syslog lines sharing one trusted-CIDR tenant — where a bare
/// tenant-only match would pass on the first message and tell the caller
/// nothing about the rest. Mirrors `tests/e2e_syslog.rs`'s own
/// (independently defined, since this helper postdates that test) marker
/// convention.
///
/// # Errors
/// Returns an error if no matching document becomes searchable within
/// [`MESSAGE_INDEXED_TIMEOUT`].
pub async fn wait_for_message(
    opensearch_url: &str,
    tenant: &str,
    marker: &str,
) -> Result<serde_json::Value> {
    let query = serde_json::json!({
        "query": {
            "bool": {
                "filter": [{ "term": { "tenant_id.keyword": tenant } }],
                "must": [{ "match_phrase": { "message": marker } }]
            }
        }
    });
    bounded(
        MESSAGE_INDEXED_TIMEOUT,
        &format!("a document with tenant_id={tenant} message~={marker} to become searchable"),
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

/// Upper bound on seeding one `ingest_tokens` row directly against a
/// [`TestDb`] (a connection separate from [`setup_test_db`]'s own admin
/// connection).
const SEED_TOKEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Hex-encoded SHA-256 digest of `raw_token` — mirrors
/// `crate::auth::hash_token` (private to the service binary; this harness
/// runs as a separate crate/process and cannot call it directly), so a row
/// seeded via [`seed_ingest_token`] is found by the real
/// `crate::auth::resolve_via_token` lookup unmodified.
fn hash_ingest_token(raw_token: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(raw_token.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Inserts one unrevoked `ingest_tokens` row (expires in 1 hour) into
/// `db`'s own database, so a subsequently spawned receiver's ingest-token
/// fallback (`crate::auth::resolve_via_token`, Spec §6b — the credential
/// path this harness uses since no live SPIFFE Workload API is available,
/// see this module's top-level doc comment) resolves `raw_token` to
/// `tenant`. `raw_token` is the plaintext value a caller then presents as
/// `authorization: Bearer {raw_token}` via [`send_otlp_http`]/
/// [`send_otlp_grpc`] — only its SHA-256 hash is ever written to the
/// database, mirroring the production `resolve_via_token` contract.
/// Bounded by [`SEED_TOKEN_TIMEOUT`].
///
/// # Errors
/// Returns an error if the connection or insert fails, within
/// [`SEED_TOKEN_TIMEOUT`].
pub async fn seed_ingest_token(db: &TestDb, raw_token: &str, tenant: &str) -> Result<()> {
    let url = format!("postgres://postgres:postgres@localhost:5432/{}", db.name);
    bounded(SEED_TOKEN_TIMEOUT, "seed ingest_tokens row", async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .context("connect to test database to seed ingest token")?;
        sqlx::query(
            "INSERT INTO ingest_tokens (token_hash, tenant_id, revoked_at, expires_at) \
             VALUES ($1, $2, NULL, $3)",
        )
        .bind(hash_ingest_token(raw_token))
        .bind(tenant)
        .bind(chrono::Utc::now() + chrono::Duration::hours(1))
        .execute(&pool)
        .await
        .context("insert ingest_tokens row")?;
        Ok(())
    })
    .await
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
    /// Prometheus exporter port (`METRICS_PORT`) — scrape
    /// `http://127.0.0.1:{metrics_port}/metrics` to verify the six Spec
    /// §11a metrics (`skauswatch_telemetry::install_metrics_exporter`).
    pub metrics_port: u16,
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
        metrics_port,
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
    /// Prometheus exporter port (`METRICS_PORT`) — scrape
    /// `http://127.0.0.1:{metrics_port}/metrics` to verify the six Spec
    /// §11a metrics (`skauswatch_telemetry::install_metrics_exporter`).
    pub metrics_port: u16,
}

impl WriterProcess {
    /// Snapshot of everything the process has printed to stdout/stderr so far.
    pub async fn output(&self) -> String {
        self.output.snapshot().await
    }

    /// SIGKILLs this writer process immediately (`Child::start_kill` — no
    /// graceful SIGTERM/shutdown) and waits (bounded,
    /// [`PROCESS_READY_TIMEOUT`]) for it to actually exit. Simulates an
    /// ungraceful writer crash (Spec §14 durability) so a subsequently
    /// [`spawn_writer`]ed process against the SAME NATS/JetStream +
    /// OpenSearch can prove the durable-consumer-resume guarantee, rather
    /// than merely a graceful restart.
    ///
    /// # Errors
    /// Returns an error if the kill signal cannot be sent, or the process
    /// does not exit within [`PROCESS_READY_TIMEOUT`].
    pub async fn kill_and_wait(&mut self) -> Result<()> {
        self.child.start_kill().context("SIGKILL writer process")?;
        bounded(
            PROCESS_READY_TIMEOUT,
            "killed writer process to exit",
            async {
                self.child
                    .wait()
                    .await
                    .context("wait for killed writer process to exit")?;
                Ok(())
            },
        )
        .await
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
    spawn_writer_with_opensearch_url(nats, &opensearch.url).await
}

/// Identical to [`spawn_writer`], additionally applying every `(name,
/// value)` pair in `extra_env` on top of the standard wiring — the writer
/// counterpart of [`spawn_receiver_with_env`], introduced for
/// `tests/e2e_smoke_14c.rs`'s `OTEL_EXPORTER_OTLP_ENDPOINT` opt-in (so the
/// writer's own `buffer_consume`/`buffer_ack` spans and log records flow to
/// an in-test OTLP sink alongside the receiver's), but generic over any env
/// var for future callers.
///
/// # Errors
/// Returns an error if the process cannot be spawned, or exits/times out
/// before `/healthz` answers 2xx (captured stdout/stderr included in the
/// message).
pub async fn spawn_writer_with_env(
    nats: &NatsHandle,
    opensearch: &OpenSearchHandle,
    extra_env: &[(&str, &str)],
) -> Result<WriterProcess> {
    spawn_writer_with_opensearch_url_and_env(nats, &opensearch.url, extra_env).await
}

/// Identical to [`spawn_writer`], except the writer's `OPENSEARCH_URL` is
/// `opensearch_url` verbatim rather than a live [`OpenSearchHandle`]'s own
/// URL — the seam `tests/e2e_durability.rs`'s DLQ scenario uses to point a
/// writer at a deliberately unreachable OpenSearch endpoint (e.g.
/// `"http://127.0.0.1:1"`, the same unreachable-address convention
/// `src/opensearch/mod.rs`'s own `write_bulk_propagates_transport_failure`
/// unit test uses) without ever needing to stop or restart a real
/// container. Stopping/restarting the SAME `testcontainers`-managed
/// OpenSearch container was evaluated and rejected for that scenario: in
/// this sandbox's Docker networking setup, a container's published port
/// forwarding does not reliably survive a `stop`+`start` cycle on the same
/// container — the container itself becomes healthy again internally (its
/// own logs report `cluster health status changed ... GREEN`), but the
/// host-side published port then refuses connections, empirically verified
/// against a real `opensearchproject/opensearch:2` container outside of
/// this harness. A dead URL sidesteps that Docker/environment quirk
/// entirely while exercising the exact same `opensearch::write_bulk`
/// connection-failure code path.
///
/// # Errors
/// Returns an error if the process cannot be spawned, or exits/times out
/// before `/healthz` answers 2xx (captured stdout/stderr included in the
/// message).
pub async fn spawn_writer_with_opensearch_url(
    nats: &NatsHandle,
    opensearch_url: &str,
) -> Result<WriterProcess> {
    spawn_writer_with_opensearch_url_and_env(nats, opensearch_url, &[]).await
}

/// Identical to [`spawn_writer_with_opensearch_url`], additionally applying
/// every `(name, value)` pair in `extra_env` on top of the standard wiring
/// — the shared implementation behind both [`spawn_writer_with_opensearch_url`]
/// (via `&[]`) and [`spawn_writer_with_env`].
///
/// # Errors
/// Returns an error if the process cannot be spawned, or exits/times out
/// before `/healthz` answers 2xx (captured stdout/stderr included in the
/// message).
async fn spawn_writer_with_opensearch_url_and_env(
    nats: &NatsHandle,
    opensearch_url: &str,
    extra_env: &[(&str, &str)],
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
        .env("OPENSEARCH_URL", opensearch_url)
        .env("NATS_URL", &nats.url)
        .envs(extra_env.iter().copied())
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
        metrics_port,
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

// ---------------------------------------------------------------------
// OTLP client helpers (gRPC :4317, HTTP/protobuf :4318)
// ---------------------------------------------------------------------

/// Upper bound on sending one OTLP export call, either transport.
const OTLP_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Builds a minimal, valid OTLP `ExportLogsServiceRequest` — one
/// `ResourceLogs` → one `ScopeLogs` → one `LogRecord` whose body is
/// exactly `marker` (severity INFO, OTLP `severity_number = 9`), plus a
/// `e2e.marker` attribute carrying the same value. `marker` doubles as the
/// searchable text [`wait_for_message`] polls OpenSearch for, mirroring
/// `tests/e2e_syslog.rs`'s marker-per-message convention — every field
/// besides `marker` is a fixed, always-valid placeholder (this helper
/// exists to drive the listener/decode/OCSF-mapping path end to end, not
/// to exercise every possible OTLP field shape; that is
/// `skauswatch-ocsf`'s and `listeners::otlp::convert`'s own unit-test
/// responsibility).
#[must_use]
pub fn otlp_log_record(marker: &str) -> ExportLogsServiceRequest {
    ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: None,
            scope_logs: vec![ScopeLogs {
                scope: None,
                log_records: vec![LogRecord {
                    time_unix_nano: 1_726_000_000_000_000_000,
                    severity_number: 9, // OTLP INFO
                    body: Some(AnyValue {
                        value: Some(OtlpAnyValue::StringValue(marker.to_owned())),
                    }),
                    attributes: vec![KeyValue {
                        key: "e2e.marker".to_owned(),
                        value: Some(AnyValue {
                            value: Some(OtlpAnyValue::StringValue(marker.to_owned())),
                        }),
                    }],
                    ..Default::default()
                }],
                schema_url: String::new(),
            }],
            schema_url: String::new(),
        }],
    }
}

/// POSTs `request` to a running [`ReceiverProcess`]'s `otlp_http_port` at
/// `/v1/logs`, binary-encoded as `application/x-protobuf` (Spec §4b/§14b's
/// protobuf variant — distinct from the JSON variant
/// `listeners::otlp::mod::tests` already covers directly), with `token` as
/// the `authorization: Bearer` ingest-token credential (Spec §6b — the only
/// credential path HTTP accepts, see `listeners::otlp::run_http`'s doc
/// comment). Bounded by [`OTLP_SEND_TIMEOUT`].
///
/// # Errors
/// Returns an error if the request cannot be sent, or the response is not
/// 2xx, within [`OTLP_SEND_TIMEOUT`].
pub async fn send_otlp_http(
    receiver: &ReceiverProcess,
    token: &str,
    request: &ExportLogsServiceRequest,
) -> Result<()> {
    let body = request.encode_to_vec();
    let url = format!("http://127.0.0.1:{}/v1/logs", receiver.otlp_http_port);
    bounded(
        OTLP_SEND_TIMEOUT,
        "POST OTLP HTTP/protobuf /v1/logs",
        async {
            let resp = reqwest::Client::new()
                .post(&url)
                .bearer_auth(token)
                .header(reqwest::header::CONTENT_TYPE, "application/x-protobuf")
                .body(body.clone())
                .timeout(OTLP_SEND_TIMEOUT)
                .send()
                .await
                .with_context(|| format!("POST {url}"))?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                bail!("POST {url} returned {status}: {text}");
            }
            Ok(())
        },
    )
    .await
}

/// Sends `request` via OTLP gRPC (`LogsService.Export`) to a running
/// [`ReceiverProcess`]'s `otlp_grpc_port`, with `token` as the
/// `authorization: Bearer` gRPC-metadata ingest-token credential (Spec
/// §6b). Dials plaintext `http://` rather than attempting mTLS:
/// `listeners::otlp::serve_grpc` falls back to plaintext without a live
/// SPIFFE workload identity (see that function's doc comment and this
/// module's top-level doc comment — no SPIRE is deployed in this sandbox),
/// so the ingest-token path is the only credential a caller here can
/// present. Bounded by [`OTLP_SEND_TIMEOUT`].
///
/// # Errors
/// Returns an error if the channel cannot connect, the metadata value
/// cannot be built, or `export()` returns a non-OK gRPC status, within
/// [`OTLP_SEND_TIMEOUT`].
pub async fn send_otlp_grpc(
    receiver: &ReceiverProcess,
    token: &str,
    request: ExportLogsServiceRequest,
) -> Result<()> {
    bounded(
        OTLP_SEND_TIMEOUT,
        "send OTLP gRPC LogsService.Export",
        async {
            let endpoint = format!("http://127.0.0.1:{}", receiver.otlp_grpc_port);
            let mut client = LogsServiceClient::connect(endpoint.clone())
                .await
                .with_context(|| format!("connect OTLP gRPC channel to {endpoint}"))?;
            let mut req = tonic::Request::new(request);
            let auth_value = format!("Bearer {token}")
                .parse()
                .context("build authorization metadata value")?;
            req.metadata_mut().insert("authorization", auth_value);
            client.export(req).await.context("LogsService.Export")?;
            Ok(())
        },
    )
    .await
}

// ---------------------------------------------------------------------
// Durability test helpers: raw JetStream producer, DLQ inspection, and
// exact-count OpenSearch polling (`tests/e2e_durability.rs`).
// ---------------------------------------------------------------------

/// Mirrors `crate::config::DEFAULT_NATS_JETSTREAM_SUBJECT_PREFIX` (private
/// to the service binary; this harness runs as a separate crate/process and
/// cannot reference it directly). Every [`spawn_receiver`]/[`spawn_writer`]
/// call in this harness leaves `NATS_JETSTREAM_SUBJECT_PREFIX` unset, so both
/// always resolve to this same default — a [`RawEventProducer`] publishing
/// under it lands on the exact stream/subject the real receiver and writer
/// use.
const INGEST_SUBJECT_PREFIX: &str = "svc-ingest.logs";

/// Header name carrying the server-validated tenant on a published message —
/// mirrors `crate::buffer::jetstream::JetStreamBuffer`'s private
/// `TENANT_HEADER` constant (`"Skauswatch-Tenant"`), duplicated here for the
/// same reason [`hash_ingest_token`] duplicates `crate::auth::hash_token`
/// above: this harness is a separate crate/process and cannot reference the
/// service binary's private items directly.
const RAW_TENANT_HEADER: &str = "Skauswatch-Tenant";

/// Subject prefix for `skauswatch-svc-ingest`'s dead-letter sink — mirrors
/// `crate::writer::DLQ_SUBJECT_PREFIX` (private to the service binary;
/// duplicated here for the same reason as [`INGEST_SUBJECT_PREFIX`] above).
/// Contains no `.`, so the derived JetStream stream name
/// (`crate::buffer::jetstream::JetStreamBuffer::stream_name`'s
/// dot-to-underscore substitution) is this exact string, unchanged.
const DLQ_STREAM_NAME: &str = "svc-ingest-dlq";

/// Publishes events directly onto `skauswatch-svc-ingest`'s durable
/// JetStream buffer, bypassing every protocol listener (syslog/OTLP/HTTPS)
/// entirely — the "direct buffer push" seeding path
/// `tests/e2e_durability.rs` uses so it can control exactly which events
/// land on the stream, and when, independent of any receiver process's
/// lifecycle. Reproduces `crate::buffer::jetstream::JetStreamBuffer::push`'s
/// exact wire contract (same subject scheme, header names, and an awaited
/// `PublishAck`) rather than reusing that type directly: this service crate
/// has no `[lib]` target (see `src/buffer/mod.rs`'s own doc comment), so
/// nothing outside `main.rs`'s module tree can import it.
pub struct RawEventProducer {
    context: async_nats::jetstream::Context,
}

impl RawEventProducer {
    /// Connects to `nats` and ensures the main ingest stream exists
    /// (idempotent `get_or_create_stream`, the identical config
    /// `JetStreamBuffer::stream_config` builds) — required before the first
    /// publish, for exactly the reason `crate::writer::build_dlq_buffer`'s
    /// doc comment documents for the push-only DLQ sink: a stream that has
    /// never been bound by a consumer (i.e. no writer has ever run yet)
    /// does not exist, and JetStream rejects a publish to a subject with no
    /// backing stream ("no stream found for given subject") rather than
    /// creating one on the fly.
    ///
    /// # Errors
    /// Returns an error if the NATS connection or stream provisioning
    /// fails, within [`CONTAINER_STARTUP_TIMEOUT`].
    pub async fn connect(nats: &NatsHandle) -> Result<Self> {
        bounded(
            CONTAINER_STARTUP_TIMEOUT,
            "raw event producer nats connect + ensure_stream",
            async {
                let client = async_nats::connect(&nats.url)
                    .await
                    .context("connect raw event producer to nats")?;
                let context = async_nats::jetstream::new(client);
                let stream_name = INGEST_SUBJECT_PREFIX.replace('.', "_");
                context
                    .get_or_create_stream(async_nats::jetstream::stream::Config {
                        name: stream_name,
                        subjects: vec![format!("{INGEST_SUBJECT_PREFIX}.>")],
                        ..Default::default()
                    })
                    .await
                    .context("ensure main ingest stream exists")?;
                Ok(Self { context })
            },
        )
        .await
    }

    /// Publishes one event under `tenant`, with `dedup_key` as the
    /// `Nats-Msg-Id` header (JetStream's server-side dedup key — see
    /// `crate::buffer::jetstream::JetStreamBuffer::push`'s doc comment) and
    /// `doc` as the JSON body. Does not return until the `PublishAck`
    /// resolves — mirrors the production durability contract documented on
    /// `crate::buffer` (module-level doc comment): never fire-and-forget.
    /// Bounded by [`HTTP_CALL_TIMEOUT`].
    ///
    /// # Errors
    /// Returns an error if the publish or its ack fails, within
    /// [`HTTP_CALL_TIMEOUT`].
    pub async fn publish(
        &self,
        tenant: &str,
        dedup_key: &str,
        doc: &serde_json::Value,
    ) -> Result<()> {
        bounded(HTTP_CALL_TIMEOUT, "raw event producer publish", async {
            let subject = format!("{INGEST_SUBJECT_PREFIX}.{tenant}");
            let mut headers = async_nats::HeaderMap::new();
            headers.insert("Nats-Msg-Id", dedup_key);
            headers.insert(RAW_TENANT_HEADER, tenant);
            let payload =
                bytes::Bytes::from(serde_json::to_vec(doc).context("serialize event doc")?);
            self.context
                .publish_with_headers(subject, headers, payload)
                .await
                .context("publish event")?
                .await
                .context("await publish ack")?;
            Ok(())
        })
        .await
    }
}

/// Reads the dead-letter sink's current message count directly from
/// JetStream (`Stream::get_info`'s `state.messages`) — `None` when the
/// stream does not exist yet (e.g. no writer process has ever started, or
/// the production "no stream found for given subject" regression this
/// durability suite guards against — see `crate::writer::build_dlq_buffer`'s
/// doc comment). Bounded by [`HTTP_CALL_TIMEOUT`].
///
/// # Errors
/// Returns an error if the NATS connection itself fails, within
/// [`HTTP_CALL_TIMEOUT`].
pub async fn count_dlq_messages(nats_url: &str) -> Result<Option<u64>> {
    bounded(HTTP_CALL_TIMEOUT, "read dlq stream message count", async {
        let client = async_nats::connect(nats_url)
            .await
            .context("connect to nats to read dlq stream")?;
        let context = async_nats::jetstream::new(client);
        match context.get_stream(DLQ_STREAM_NAME).await {
            Ok(stream) => {
                let info = stream.get_info().await.context("read dlq stream info")?;
                Ok(Some(info.state.messages))
            }
            Err(_) => Ok(None),
        }
    })
    .await
}

/// Polls [`count_dlq_messages`] (bounded by `timeout`) until it reports at
/// least `expected` messages — the assertion `tests/e2e_durability.rs`'s
/// OpenSearch-down scenario uses to prove permanently-failing events are
/// routed to the dead-letter sink rather than silently dropped, and that
/// the sink's stream genuinely exists (a `None` result the whole time, at
/// timeout, is exactly the "no stream found for given subject" regression
/// this suite guards against).
///
/// # Errors
/// Returns an error (via [`bounded`]'s timeout message) if `expected` is
/// not reached within `timeout`.
pub async fn wait_for_dlq_count(nats_url: &str, expected: u64, timeout: Duration) -> Result<u64> {
    bounded(
        timeout,
        &format!("dlq stream to report >= {expected} messages"),
        async {
            loop {
                if let Ok(Some(n)) = count_dlq_messages(nats_url).await
                    && n >= expected
                {
                    return Ok(n);
                }
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        },
    )
    .await
}

/// Polls `{tenant}`-scoped `skauswatch-logs-*` documents until at least
/// `expected` are searchable, bounded by `timeout`, then returns every
/// matching hit's `_source` — the general-purpose "how many (and which)
/// documents landed for this tenant" helper `tests/e2e_durability.rs`'s
/// crash-recovery and dedup scenarios use instead of [`wait_for_message`]'s
/// single-marker match. Unlike [`wait_for_document`] (first-hit-only), this
/// returns the full matching set so a caller can assert exact counts (zero
/// loss, zero duplicates) and inspect every document's content.
///
/// # Errors
/// Returns an error if fewer than `expected` documents become searchable
/// within `timeout`.
pub async fn wait_for_tenant_hit_count(
    opensearch_url: &str,
    tenant: &str,
    expected: usize,
    timeout: Duration,
) -> Result<Vec<serde_json::Value>> {
    let query = serde_json::json!({
        "size": (expected * 2).max(10),
        "query": { "term": { "tenant_id.keyword": tenant } }
    });
    bounded(
        timeout,
        &format!("{expected} documents with tenant_id={tenant} to become searchable"),
        async {
            loop {
                if let Ok(body) =
                    search_opensearch(opensearch_url, "skauswatch-logs-*", &query).await
                    && let Some(hits) = body["hits"]["hits"].as_array()
                    && hits.len() >= expected
                {
                    return Ok(hits.iter().map(|h| h["_source"].clone()).collect());
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        },
    )
    .await
}

// ---------------------------------------------------------------------
// Deterministic mid-flight writer-crash simulation (fix round 1).
//
// A fixed sleep-then-kill delay is a race: on a fast local NATS +
// OpenSearch, a small batch can fully drain (bulk write + every per-event
// ack) well inside that delay, so the SIGKILL always lands on an already-
// idle writer and the durable-consumer redelivery/resume path is never
// exercised — a false green (`writer_crash_and_restart_causes_zero_loss`
// would pass on writer1's own work alone). [`StallingOpenSearch`] removes
// the race entirely: a writer pointed at it can never complete a
// bulk-write call (it never receives a response), so the moment its
// durable consumer shows a nonzero `num_ack_pending`, the ENTIRE fetched
// batch is deterministically stuck in flight, unacked, for as long as the
// test wants — no timing luck involved.
// ---------------------------------------------------------------------

/// A TCP listener that accepts connections and never responds to them —
/// see this section's module comment. Any HTTP client (e.g. the writer's
/// `reqwest::Client`, which carries no request timeout — see
/// `bootstrap::run_writer`) that sends a request to [`Self::url`] blocks
/// on `.send().await` forever. Dropping this stops the accept loop; a
/// connection already accepted before the drop is only released when its
/// peer (the writer process) itself exits or is killed.
pub struct StallingOpenSearch {
    /// `http://127.0.0.1:{port}` — pass to [`spawn_writer_with_opensearch_url`]
    /// to guarantee that writer's bulk-write call blocks forever.
    pub url: String,
    _shutdown: tokio::sync::oneshot::Sender<()>,
}

/// Starts a [`StallingOpenSearch`] black hole on an ephemeral loopback
/// port.
///
/// # Errors
/// Returns an error if the listener cannot be bound.
pub async fn start_stalling_opensearch() -> Result<StallingOpenSearch> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind stalling opensearch listener")?;
    let port = listener
        .local_addr()
        .context("read stalling opensearch listener addr")?
        .port();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accepted = listener.accept() => {
                    let Ok((mut socket, _)) = accepted else { break; };
                    // Hold the connection open forever, never writing a
                    // response back — the peer's HTTP client blocks
                    // indefinitely waiting for one. Still drains incoming
                    // bytes so the writer's own request write doesn't
                    // itself stall on a full socket receive buffer.
                    tokio::spawn(async move {
                        use tokio::io::AsyncReadExt as _;
                        let mut buf = [0_u8; 4096];
                        loop {
                            match socket.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                    });
                }
            }
        }
    });
    Ok(StallingOpenSearch {
        url: format!("http://127.0.0.1:{port}"),
        _shutdown: shutdown_tx,
    })
}

/// Name of the main ingest durable, explicit-ack pull consumer
/// `JetStreamBuffer::consumer` binds — deterministic
/// (`{stream_name}-consumer`, `stream_name` being [`INGEST_SUBJECT_PREFIX`]
/// with `.` replaced by `_`; see `JetStreamBuffer::stream_name`/
/// `consumer`). Duplicated here for the same reason as
/// [`INGEST_SUBJECT_PREFIX`] above.
const INGEST_CONSUMER_NAME: &str = "svc-ingest_logs-consumer";

/// Reads the main ingest durable consumer's current `num_ack_pending` —
/// the count of messages JetStream has delivered to a puller but not yet
/// received an ack/nack for (a **live** server-side read — `Consumer::
/// get_info` — not a locally cached value). This is the anti-false-green
/// guard `tests/e2e_durability.rs`'s crash-recovery scenario requires: if
/// a just-killed writer left zero messages ack-pending, the kill did not
/// land mid-flight and the durable-consumer redelivery/resume path this
/// suite exists to prove was never exercised.
///
/// # Errors
/// Returns an error if the NATS connection, or the stream/consumer lookup,
/// fails (e.g. called before any writer has ever bound the consumer) —
/// within [`HTTP_CALL_TIMEOUT`].
pub async fn ingest_consumer_ack_pending(nats_url: &str) -> Result<usize> {
    bounded(
        HTTP_CALL_TIMEOUT,
        "read ingest consumer ack-pending count",
        async {
            let client = async_nats::connect(nats_url)
                .await
                .context("connect to nats to read consumer info")?;
            let context = async_nats::jetstream::new(client);
            let stream_name = INGEST_SUBJECT_PREFIX.replace('.', "_");
            let stream = context
                .get_stream(&stream_name)
                .await
                .context("get main ingest stream")?;
            let consumer: async_nats::jetstream::consumer::PullConsumer = stream
                .get_consumer(INGEST_CONSUMER_NAME)
                .await
                .map_err(|e| anyhow::anyhow!("get main ingest durable consumer: {e}"))?;
            let info = consumer.get_info().await.context("read consumer info")?;
            Ok(info.num_ack_pending)
        },
    )
    .await
}

/// Polls [`ingest_consumer_ack_pending`] (bounded by `timeout`) until it
/// reports at least `min` — the wait `tests/e2e_durability.rs`'s
/// crash-recovery scenario uses to confirm a writer has actually fetched a
/// batch (and, against a [`StallingOpenSearch`], is now genuinely and
/// permanently stuck on it) before killing that writer.
///
/// # Errors
/// Returns an error (via [`bounded`]'s timeout message) if `min` is not
/// reached within `timeout`.
pub async fn wait_for_ack_pending_at_least(
    nats_url: &str,
    min: usize,
    timeout: Duration,
) -> Result<usize> {
    bounded(
        timeout,
        &format!("ingest consumer to report >= {min} ack-pending messages"),
        async {
            loop {
                if let Ok(n) = ingest_consumer_ack_pending(nats_url).await
                    && n >= min
                {
                    return Ok(n);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        },
    )
    .await
}
