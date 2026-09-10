# svc-ingest — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development — fan out each wave's tasks to concurrent subagents against disjoint files, gate on the Integration checkpoint before starting the next wave, never skip a gate to save time.

**Goal:** Ship `svc-ingest`, a net-new multi-protocol SIEM log-ingest service (syslog UDP/TCP/TLS + OTLP gRPC/HTTP + HTTPS OCSF/JSON) that normalizes everything to OCSF through an extracted `skauswatch-ocsf` crate, buffers durably through NATS JetStream, and writes to the unified `skauswatch-logs-*` OpenSearch lake — absorbing `services/logs`' HTTP ingest and retiring `services/monitor`'s syslog collector.

**Architecture:** One binary, two run modes (`serve --mode receiver` / `serve --mode writer`), selected by K8s Deployment args so each scales independently. Receiver mode terminates syslog/OTLP/HTTPS, authenticates via mTLS SPIFFE ID (primary) or a Vault-issued ingest token (fallback), normalizes to OCSF, and awaits a synchronous JetStream `PublishAck` before acking the source. Writer mode drains the JetStream consumer in batches, bulk-writes to OpenSearch, and only acks JetStream after a successful write (at-least-once, DLQ on repeated failure).

**Tech Stack:** Rust 1.97 (edition 2024), Axum 0.8.9 (HTTPS), Tonic 0.14.6 (OTLP gRPC), raw Tokio UDP/TCP + `tokio-rustls` (syslog), `async-nats` 0.50.0 (JetStream), `sqlx` 0.9.0/Postgres (SPIFFE-ID/ingest-token lookup tables via `skauswatch-db`), `rustls` (all TLS), `spiffe`/`skauswatch-identity` (mTLS), `skauswatch-auth` (JWT/tenant), reqwest (OpenSearch `_bulk` + Vault secret fetch), `skauswatch-telemetry` (tracing/metrics/health), Helm v4.

**Spec:** `docs/v2-port/ingest-module-spec.md` (branch `docs/ingest-module-spec`, commit `d71c199`) — this plan implements that document section-by-section; cite it as "the Spec" below.

## Global Constraints (verbatim from the Spec + house rules — apply to every task)

- **Toolchain**: Rust 1.97.x, `edition = "2024"`, workspace `resolver = "3"` (`Cargo.toml:2-8`). `unsafe_code = "deny"`, `clippy::unwrap_used = "deny"`, `clippy::expect_used = "warn"`, `clippy::panic = "warn"` at the workspace level (`Cargo.toml:243-249`) — every non-test `.unwrap()`/`.expect()`/`panic!()` is a defect; test modules need their own `#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]` (not blanket-exempted).
- **`Result<T, E>` everywhere** — no `.unwrap()`/`.expect()` outside `#[cfg(test)]` without an inline-documented infallibility invariant.
- **Exact-pin dependencies, no bare ranges.** New pin required by the Spec, verbatim: `async-nats = { version = "=0.50.0", default-features = false, features = ["jetstream"] }` (Spec §7b, §14c2) — "Do NOT allow cargo to bump to a newer 0.y.z or 1.x without explicit review and smoke test re-run."
- **rustls only, never OpenSSL bindings** — "All TLS ports use rustls only (no OpenSSL C bindings)" (Spec §3b).
- **NATS production-hardening is mandatory, not optional** (Spec §7a, verbatim requirements):
  1. NATS server version ≥2.14 (Jepsen-reported message-loss bug on older async-flush).
  2. `sync_always: true` on the JetStream file store.
  3. Receiver **awaits `PublishAck` synchronously before returning 2xx** — "the receiver does not return 2xx or send an ack until JetStream PublishAck arrives. Never fire-and-forget a publish."
  4. Server-side dedup via a `Nats-Msg-Id` header on every publish.
  5. **Do NOT wrap `async-nats::jetstream::publish()` in `tokio::time::timeout()`** — use MsgId dedup + connection-level timeout config instead.
- **Server-side tenant stamping only** (Spec §6d): "the service NEVER reads a tenant ID from the event payload, request parameters, or any untrusted source. Tenant is ALWAYS extracted from the authenticated identity... and stamped onto the document by the handler before enqueueing."
- **Secrets from Vault, never hardcoded** (Spec §9b): mTLS certs, ingest tokens, OpenSearch credentials, and JetStream credentials all come from `svc-vault`/K8s Secrets — "no secrets in the image, `Dockerfile`, or config files."
- **Feature flag `skauswatch.log-ingest`** (Professional tier, default OFF) gates the entire service — already declared in `services/manager/src/flags.rs:26`'s `CORE_FLAGS`, "svc-ingest enforces it from day one" (Spec §10).
- **OSI-license dependencies only** — `cargo deny check` clean (advisories + license + source policy) before every commit; no PRC-based/sanctioned-entity dependencies.
- **90%+ coverage** (lines+branches, `cargo llvm-cov`), `cargo clippy --all-targets -- -D warnings` and `cargo fmt --check` clean, `Cargo.lock` committed, rootless containers (`USER` UID 1000, `capabilities.drop: [ALL]`), OTel logs+metrics+traces via env-configurable OTLP endpoint, native-binary `healthcheck` subcommand (never curl).

---

## File Structure Map

| Path | New/Modified | Responsibility |
|---|---|---|
| `crates/skauswatch-ocsf/{Cargo.toml,src/lib.rs,src/jsonord.rs,src/schema.rs,src/mappings/{mod,syslog,otlp,generic}.rs,tests/fixtures/*}` | **New** | Extracted OCSF normalizer + order-preserving `JsonVal` (moved verbatim from `services/logs`), per-format mapping hints |
| `services/logs/src/{main.rs,ingest.rs,opensearch.rs}` | Modified; `ocsf.rs`+`jsonord.rs` deleted | Delegates to `skauswatch-ocsf` instead of inlining it |
| `services/svc-ingest/{Cargo.toml,Dockerfile,src/main.rs,src/config.rs}` | **New** | Binary entrypoint, clap `serve --mode {receiver,writer}`/`healthcheck`/`openapi`/`migrate` |
| `services/svc-ingest/src/buffer/{mod.rs,jetstream.rs,inmemory.rs}` | **New** | `EventBuffer` trait + JetStream/in-memory impls |
| `services/svc-ingest/src/listeners/syslog/{mod.rs,parser.rs}` | **New** | RFC 3164/5424 UDP/TCP/TLS listener |
| `services/svc-ingest/src/listeners/otlp/mod.rs` | **New** | OTLP gRPC (:4317) + HTTP (:4318) listener |
| `services/svc-ingest/src/listeners/http.rs` | **New** | HTTPS OCSF/JSON listener (:8443), Axum |
| `services/svc-ingest/src/auth.rs`, `src/identity_store.rs`, `migrations/0001_ingest_identity.sql` | **New** | mTLS SPIFFE→tenant + ingest-token→tenant resolution, UDP CIDR mapping |
| `services/svc-ingest/src/writer.rs`, `src/opensearch/{mod.rs,ism.rs}`, `src/admin.rs` | **New** | JetStream consumer→bulk writer→DLQ; ISM hot/warm/cold policy; admin settings endpoint |
| `crates/skauswatch-proto/{build.rs,src/lib.rs}`, `proto/otel/opentelemetry/proto/{common,resource,logs}/v1/*.proto` | Modified/New | Vendored OTLP `.proto` (Apache-2.0) compiled via existing protox/tonic-prost-build pipeline |
| `services/monitor/src/collectors/syslog.rs` (removed), `services/monitor/src/main.rs`/`collectors/mod.rs` | Modified | UDP syslog collector retired; monitor's other collectors repoint to `/ingest` |
| `services/svc-ingest/backfill/` (or a `migrate`-sibling subcommand) + `k8s/helm/svc-ingest/templates/backfill-job.yaml` | **New** | One-time `aaa-events-*` → `skauswatch-logs-*` reindex Job |
| `k8s/helm/svc-ingest/{Chart.yaml,values.yaml,alpha.yml,beta.yml,gamma.yml,production.yml,templates/*}` | **New** | Dual Deployments (receiver/writer), receiver Service (multi-port incl. UDP), CiliumNetworkPolicy ×2, TracingPolicy, HPA, backfill Job |
| `services/manager/src/routes/siem.rs`, `k8s/helm/manager/values.yaml` (`LOGS_URL`) | Modified | Repoint the SIEM ingest proxy at `svc-ingest-receiver:8443` |
| Root `Cargo.toml` | Modified | Add `services/svc-ingest` to `members`; add `skauswatch-ocsf`, `async-nats` to `[workspace.dependencies]` |

---

## Wave 0 — Foundations

**Note on Cargo.toml collisions:** Task 0.2 front-loads *every* dependency `services/svc-ingest` will ever need (including `async-nats`, `tonic`, `spiffe`, `sqlx` via `skauswatch-db`, etc.) so that every Wave 1+ task only ever edits `.rs`/`.sql`/`.yaml` files, never `services/svc-ingest/Cargo.toml` again. Task 0.1 and 0.2 both touch root `Cargo.toml`, but on disjoint sections (`[workspace.dependencies]` vs `members` array) — low collision risk, resolve trivially if both land in the same pass.

### Task 0.1 — Extract `skauswatch-ocsf` crate + refactor `services/logs` onto it

- **Files:**
  - Create: `crates/skauswatch-ocsf/Cargo.toml`, `src/lib.rs`, `src/jsonord.rs`, `src/schema.rs`, `src/mappings/mod.rs` + 3 stub files `src/mappings/{syslog,otlp,generic}.rs` (each a doc comment + `#[cfg(test)] mod tests {}` only — Wave 1 tasks fill in bodies, never touching `mappings/mod.rs` again), `tests/fixtures/{batch.json,bulk_reference.ndjson}` (moved from `services/logs/tests/fixtures/`)
  - Modify: root `Cargo.toml` (`[workspace.dependencies]`: add `skauswatch-ocsf = { path = "crates/skauswatch-ocsf" }`)
  - Modify: `services/logs/Cargo.toml` (add `skauswatch-ocsf = { workspace = true }`, drop nothing else yet), `services/logs/src/main.rs` (remove `mod ocsf; mod jsonord;`), `services/logs/src/ingest.rs`, `services/logs/src/opensearch.rs` (import `skauswatch_ocsf::{normalize, JsonVal, jsonord}` instead of `crate::{ocsf::normalize, jsonord::...}`)
  - Delete: `services/logs/src/ocsf.rs`, `services/logs/src/jsonord.rs`
- **Interfaces:**
  - Produces (crate root `lib.rs`): `pub mod jsonord; pub mod schema; pub mod mappings; pub use jsonord::JsonVal; pub fn normalize(record: &JsonVal, source: &str, now: chrono::DateTime<chrono::Utc>) -> Result<JsonVal, NormalizeError>;` — byte-for-byte identical signature/behavior to the current `services/logs/src/ocsf.rs::normalize`.
  - `skauswatch-ocsf`'s Cargo.toml dependencies: `chrono`, `serde_json`, `thiserror`, `skauswatch-streams` (for `skauswatch_streams::py_isoformat`, used by `EventTime::render`'s naive-datetime branch — verified call site in the current `ocsf.rs`), all `{ workspace = true }`.
- **Acceptance criteria:**
  - `cargo test -p skauswatch-ocsf` passes every test currently in `services/logs/src/{ocsf.rs,jsonord.rs}` unchanged (move the `#[cfg(test)] mod tests` blocks verbatim), including `document_key_order_and_metadata_match_v1`, `timestamp_rendering_matches_python_isoformat`, `numeric_timestamp_out_of_chrono_range_is_an_error`.
  - `cargo test -p skauswatch-logs` still passes `ingest_bulk_body_matches_v1_reference` and `build_bulk_body_reproduces_reference_bytes` (services/logs/src/ingest.rs) using the *new* crate's `normalize`/`JsonVal` — proves the extraction is a true no-op for `services/logs`.
  - `cargo build -p skauswatch-ocsf` succeeds with the 3 mapping stub files present but empty of real logic.
- **Suggested executor:** `penguin-rust-dev`, **model:** sonnet (byte-parity extraction, easy to silently break v1 fixture matching).
- **Dependencies:** none (can start immediately).

### Task 0.2 — Scaffold `svc-ingest` skeleton (all deps, all module stubs, Dockerfile, migrate subcommand)

- **Files:**
  - Create: `services/svc-ingest/Cargo.toml` (package `skauswatch-svc-ingest`, `[[bin]] name = "skauswatch-svc-ingest"`, deps: `axum`, `tokio`, `tower`, `tower-http`, `clap`, `thiserror`, `anyhow`, `tracing`, `metrics`, `chrono`, `serde`, `serde_json`, `uuid`, `regex`, `reqwest`, `rustls`, `tokio-rustls`, `spiffe`, `jsonwebtoken`, `penguin-licensing` (features `["axum"]`), `skauswatch-auth`, `skauswatch-identity`, `skauswatch-telemetry`, `skauswatch-db`, `skauswatch-ocsf`, `skauswatch-proto`, `tonic`, `tonic-prost`, `prost`, `prost-types`, `utoipa` (features `["yaml"]`), **`async-nats = { version = "=0.50.0", default-features = false, features = ["jetstream"] }`** exactly as pinned in the Spec, all others `{ workspace = true }`; `[dev-dependencies]`: `axum-test`, `wiremock`, `skauswatch-testkit`, `mockall`)
  - Create: `services/svc-ingest/Dockerfile` (multi-stage `rust:1.97-slim-bookworm` → `debian:bookworm-slim`, `USER appuser` UID 1000, `HEALTHCHECK CMD ["/app/skauswatch-svc-ingest", "healthcheck"]`)
  - Create: `services/svc-ingest/src/main.rs` — clap `Cli { command: Option<Command> }`, `Command::{Serve{ #[arg(long, value_enum, default_value_t = RunMode::Receiver)] mode: RunMode }, Healthcheck, Openapi, Migrate}`, `enum RunMode { Receiver, Writer }` (`#[derive(clap::ValueEnum, Clone, Copy)]`); `mod config; mod buffer; mod listeners; mod auth; mod identity_store; mod writer; mod opensearch; mod admin; mod openapi;` — every one of these points at a file/dir this task ALSO creates as a compiling stub (empty struct/fn bodies, no `todo!()`/`unimplemented!()` — a `pub async fn run(..) -> anyhow::Result<()> { std::future::pending().await }` shape where a long-running task is expected, so `cargo build`/`cargo clippy -D warnings` are clean from this task onward)
  - Create: `services/svc-ingest/src/config.rs` — real implementation (not a stub): env-var loading for `HTTP_PORT`(8443)/`SYSLOG_PORT`(5140)/`SYSLOG_TLS_PORT`(6514)/`OTLP_GRPC_PORT`(4317)/`OTLP_HTTP_PORT`(4318)/`OPENSEARCH_URL`/`NATS_URL`/`NATS_JETSTREAM_SUBJECT_PREFIX`/`SYSLOG_UDP_ENABLED`/`SYSLOG_TRUSTED_CIDRS`, mirroring `services/logs/src/config.rs`'s `from_env()`/`from_values()`/`ConfigError` pattern for unit-testability.
  - Create: `services/svc-ingest/migrations/` (empty dir, so `sqlx::migrate!()` compiles with zero migrations until Task 1.4 adds one)
  - Modify: root `Cargo.toml` `members` array — add `"services/svc-ingest"`.
- **Interfaces:**
  - Produces: `RunMode` enum and `Config` struct that every Wave 1 task's `run(cfg: &Config, mode: RunMode, ...)`-shaped entry points consume.
  - Produces: `static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();` in `main.rs`, plus a `migrate()` async fn calling `skauswatch_db::run_migrations(&pool, &MIGRATOR)` (exact helper per `crates/skauswatch-db/src/lib.rs`) — same pattern as the other 9 services (see prior `migrate`-subcommand rollout).
- **Acceptance criteria:**
  - `cargo build -p skauswatch-svc-ingest` succeeds (all stub modules compile).
  - `cargo clippy -p skauswatch-svc-ingest --all-targets -- -D warnings` clean on the stub tree.
  - `Config::from_values(...)` unit tests: defaults match the Spec's port table (§3b); `SYSLOG_UDP_ENABLED` defaults `false`; invalid `SYSLOG_TRUSTED_CIDRS` entry is a `ConfigError`, not a panic.
  - `cargo test -p skauswatch-svc-ingest migrate_tests` — `MIGRATOR.iter().count()` equals on-disk `.sql` count (0 at this point).
- **Suggested executor:** `penguin-rust-dev`, **model:** sonnet (many moving parts, wrong stub shape here blocks 5 downstream tasks).
- **Dependencies:** none; should land before Task 0.3 (needs the crate + Cargo.toml to exist) and before every Wave 1 task.

### Task 0.3 — `EventBuffer` trait + JetStream + in-memory implementations

- **Files:**
  - Create: `services/svc-ingest/src/buffer/mod.rs` (trait + shared types, replacing the 0.2 stub), `src/buffer/jetstream.rs`, `src/buffer/inmemory.rs`
- **Interfaces:**
  - Produces (`buffer/mod.rs`):
    ```rust
    #[async_trait::async_trait]
    pub trait EventBuffer: Send + Sync {
        async fn push(&self, event: NormalizedEvent) -> Result<(), BufferError>;
        async fn consume(&self, batch_size: usize) -> Result<Vec<DeliveredEvent>, BufferError>;
        async fn ack(&self, handle: AckHandle) -> Result<(), BufferError>;
        async fn nack(&self, handle: AckHandle) -> Result<(), BufferError>;
    }
    pub struct NormalizedEvent { pub tenant: skauswatch_auth::Tenant, pub doc: skauswatch_ocsf::JsonVal, pub dedup_key: String }
    pub struct DeliveredEvent { pub event: NormalizedEvent, pub handle: AckHandle }
    pub struct AckHandle(/* opaque, jetstream::Message or in-memory index */);
    pub enum BufferError { Full, Transport(String), Serialize(String) }
    ```
  - `JetStreamBuffer::new(client: async_nats::jetstream::Context, subject_prefix: &str) -> Result<Self, BufferError>`; `push` computes `dedup_key` → `Nats-Msg-Id` header, calls `context.publish_with_headers(subject, headers, bytes).await?.await?` (async-nats 0.50 returns a `PublishAckFuture` that must itself be awaited — **both awaits are mandatory**, matching Global Constraint #3) with **no** `tokio::time::timeout()` wrapper (Global Constraint #5).
  - `InMemoryBuffer::new(capacity: usize) -> Self` — bounded `VecDeque<NormalizedEvent>` + `HashSet<String>` (dedup_key) dropping oldest on overflow, test-only (`#[cfg(any(test, feature = "testutil"))]`).
- **Acceptance criteria + key tests:**
  - `push_awaits_publish_ack_before_returning` — mock/fake JetStream context that delays ack resolution; assert `push()` does not return until the ack future resolves (regression for Spec §14b's "PublishAck synchronous blocking" durability test).
  - `push_sets_nats_msg_id_header_deterministically` — same `NormalizedEvent` content twice → identical `Nats-Msg-Id`; different content → different id.
  - `inmemory_buffer_drops_oldest_on_overflow` — push capacity+1 events, assert the buffer's length caps at capacity and the retained events are the newest N.
  - `inmemory_buffer_dedup_key_collision_rejected` — pushing two events with the same `dedup_key` is a no-op on the second (simulates JetStream server-side dedup for tests that use the in-memory fallback).
- **Suggested executor:** `penguin-rust-dev`, **model:** sonnet (the PublishAck-blocking + no-timeout constraint is the single most safety-critical piece of the whole service — Global Constraints #3/#5).
- **Dependencies:** Task 0.2 (needs the crate + `async-nats` dependency to exist).

**Integration + Gate 0→1:** Orchestrator runs `cargo build --workspace`, `cargo test -p skauswatch-ocsf -p skauswatch-logs -p skauswatch-svc-ingest`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --check`. All must be green (real denominators reported, e.g. "N tests passed") before dispatching Wave 1.

---

## Wave 1 — Listeners, Auth/Tenancy, Writer (5 parallel tasks)

All five tasks below only ever create/modify files already stubbed by Task 0.2 (or genuinely new leaf files under their own subdirectory) — no task in this wave touches `services/svc-ingest/Cargo.toml` or `src/main.rs` again.

### Task 1.1 — Syslog UDP/TCP/TLS listener (RFC 3164 + RFC 5424)

- **Files:**
  - Modify (fill stub): `services/svc-ingest/src/listeners/mod.rs` (add `pub mod syslog;` only — this line is pre-declared as a comment by 0.2 to avoid edit collision with 1.2/1.3, or each of 1.1/1.2/1.3 owns one line in a `mod.rs` that 0.2 leaves as three `// pub mod X;` comments to uncomment — executor uncomments only its own line)
  - Create: `services/svc-ingest/src/listeners/syslog/mod.rs`, `src/listeners/syslog/parser.rs`
  - Modify (fill stub): `crates/skauswatch-ocsf/src/mappings/syslog.rs`
- **Interfaces:**
  - Consumes: `skauswatch_ocsf::mappings::syslog::to_ocsf_fields(parsed: &ParsedSyslog) -> skauswatch_ocsf::JsonVal` (new, defined by this task inside the crate's stub file — safe since no other task touches that file); `crate::auth::resolve_via_mtls`/`resolve_via_udp_cidr` (Consumes from Task 1.4 — see its Produces; code against the documented signature even if 1.4 hasn't landed in this pass, verified at the Wave gate); `crate::buffer::EventBuffer::push` (Task 0.3).
  - Produces: `pub fn detect_and_parse(raw: &str) -> Option<ParsedSyslog>` (auto-detects `<` → RFC 5424 else RFC 3164, per Spec §4a); `pub async fn run_udp(cfg: &Config, buffer: Arc<dyn EventBuffer>) -> anyhow::Result<()>`, `run_tcp`, `run_tls` (mirrors `services/monitor/src/collectors/syslog.rs`'s `consume_socket`/`run` shape but targets `EventBuffer` instead of monitor's `IngestHandle`, and adds RFC 5424 + TCP/TLS + mTLS auth on top of monitor's UDP-only RFC-3164-only original).
- **Acceptance criteria + key tests:**
  - `rfc3164_and_rfc5424_auto_detected_by_leading_angle_bracket` — `<34>Oct 11 22:14:15 host msg` → RFC3164 branch; `<34>1 2025-01-15T12:30:00Z host app - - - msg` → RFC5424 branch (both produce the same normalized tuple shape per Spec §4a).
  - `year_wrap_timestamp_documented_limitation` — RFC 3164 message with no year assumes current year (reuse `services/monitor/src/collectors/syslog.rs`'s `parse_rfc3164_timestamp` test pattern), documented as acceptable per Spec §4a table.
  - `udp_packet_from_untrusted_cidr_is_silently_dropped_no_error` (Spec §14b) — packet from an IP outside `SYSLOG_TRUSTED_CIDRS` never reaches `EventBuffer::push` (assert push call count is 0 via a mock buffer).
  - `tcp_backpressure_closes_connection_on_buffer_full` — mock `EventBuffer::push` returning `BufferError::Full`; assert the TCP connection is closed (Spec §7c row 2).
  - `malformed_datagram_does_not_crash_the_listener` (mirrors monitor's `consume_socket_ignores_malformed_datagrams_without_crashing`).
- **Suggested executor:** `penguin-rust-dev`, **model:** sonnet (dual-protocol auto-detect + 3 transports is the most novel parsing surface).
- **Dependencies:** Wave 0 complete; soft-depends on Task 1.4's signatures (documented above, code-against-contract).

### Task 1.2 — OTLP gRPC (:4317) + HTTP (:4318) listener

- **Files:**
  - Create: `proto/otel/opentelemetry/proto/{common,resource,logs}/v1/*.proto` (vendored from the upstream `open-telemetry/opentelemetry-proto` repo, Apache-2.0, pinned at a specific tagged commit — record the exact commit SHA in a header comment for reproducibility, per Dependency Pinning discipline even though this isn't a Cargo dependency)
  - Modify: `crates/skauswatch-proto/build.rs` (add the three vendored files to the `files` array), `crates/skauswatch-proto/src/lib.rs` (re-export the generated `opentelemetry::proto::collector::logs::v1::{LogsServiceServer, ExportLogsServiceRequest, ...}` module)
  - Modify (uncomment its own line): `services/svc-ingest/src/listeners/mod.rs`
  - Create: `services/svc-ingest/src/listeners/otlp/mod.rs`
  - Modify (fill stub): `crates/skauswatch-ocsf/src/mappings/otlp.rs`
- **Interfaces:**
  - Produces (`mappings/otlp.rs`): `pub fn log_record_to_ocsf(record: &LogRecordFields, resource_attrs: &[(String, String)]) -> skauswatch_ocsf::JsonVal` — `body`→message, `severity_number`→OCSF severity id, `time_unix_nano`→timestamp, security-relevant attribute aliasing (`user_id`/`user`→`user_name`, `src_ip`→`src_ip_addr`) per Spec §4b/§5, unknown attrs → `metadata.custom_attributes`. `LogRecordFields` is a plain struct this task defines to decouple the mapping fn from the generated prost type (so `skauswatch-ocsf` doesn't need a `skauswatch-proto` dependency).
  - Produces: `pub struct LogsGrpc { .. }` implementing the generated `LogsService` trait (mirrors `services/manager/src/grpc/mod.rs`'s `mtls_incoming`/`TlsAcceptor` pattern verbatim for :4317's mTLS termination — reuse `skauswatch_identity::IdentityProvider::server_tls_config` + a local `mtls_incoming` helper); `pub async fn run_http(cfg: &Config, buffer: Arc<dyn EventBuffer>) -> anyhow::Result<()>` for :4318 (Axum, JSON-or-protobuf body per `Content-Type`).
  - Consumes: `crate::auth::resolve_via_mtls`/`resolve_via_token` (Task 1.4); `EventBuffer::push` (Task 0.3).
- **Acceptance criteria + key tests:**
  - `native_ocsf_shaped_otlp_attributes_pass_through_unmodified` (Spec §4b "Native OTLP passthrough").
  - `otlp_attribute_collision_user_id_wins_over_user` (Spec §15 open question #8's recommended resolution — log a warning, `user_id` takes precedence).
  - `otlp_grpc_full_buffer_returns_resource_exhausted` (Spec §7c row 4 — assert `tonic::Code::ResourceExhausted`).
  - `otlp_http_json_and_protobuf_variants_both_parse_to_the_same_ocsf_doc` (Spec §14b "OTLP HTTP: send JSON + protobuf variants, verify parsed correctly").
- **Suggested executor:** `penguin-rust-dev`, **model:** sonnet (new proto-vendoring pattern + mTLS-terminated tonic server + dual-encoding HTTP).
- **Dependencies:** Wave 0 complete; soft-depends on Task 1.4.

### Task 1.3 — HTTPS OCSF/JSON listener (:8443)

- **Files:**
  - Modify (uncomment its own line): `services/svc-ingest/src/listeners/mod.rs`
  - Create: `services/svc-ingest/src/listeners/http.rs`, `services/svc-ingest/src/openapi.rs` (fills the 0.2 stub — utoipa `ApiDoc` aggregator, mirrors `services/logs/src/openapi.rs`)
  - Modify (fill stub): `crates/skauswatch-ocsf/src/mappings/generic.rs`
- **Interfaces:**
  - Consumes: `skauswatch_ocsf::normalize` (native OCSF schema-validate-or-reject path uses `skauswatch_ocsf::schema` for field/type checks, generic JSON path calls `normalize` directly — same as `services/logs/src/ingest.rs::handle_ingest` today); `skauswatch_auth::tenant_middleware` + `penguin_licensing::axum::{FlagGate, flag_gate}` with `crate::auth::LOG_INGEST_FLAG = "skauswatch.log-ingest"` (same constant name/value as `services/logs/src/ingest.rs::LOG_INGEST_FLAG` — must match exactly, it's the same PostHog flag).
  - Produces: `pub fn router(state: AppState) -> axum::Router` exposing `POST /ingest` (byte-compatible request/response contract with `services/logs`' current `/ingest` — `{"ingested": N}` on 202, same 400/401/403/413/500 shape) plus `GET /healthz`/`GET /readyz` (mounted outside both gates, per `skauswatch-telemetry::health_router` convention).
- **Acceptance criteria + key tests:**
  - Port the exact existing `services/logs/src/ingest.rs` test suite (12 tests: `non_object_record_in_batch_returns_internal_error`, `oversized_batch_is_413`, `body_supplied_tenant_id_does_not_override_jwt_tenant`, `ingest_bulk_body_matches_v1_reference`, etc.) verbatim against the new router — this IS the "inherited contract" the Spec (§4c) requires, and doubles as the parity gate for Task 3.3's later cutover.
  - `native_ocsf_document_with_missing_required_field_is_400` (Spec §15 open question #4's recommended strict-required/permissive-optional resolution).
  - `json_array_of_ocsf_and_generic_docs_are_both_indexed` (Spec §14c smoke test #5).
- **Suggested executor:** `penguin-rust-dev`, **model:** haiku (this is a near-direct port of already-read, well-tested `services/logs/src/ingest.rs` — low novelty).
- **Dependencies:** Wave 0 complete; soft-depends on Task 1.4 only for the mTLS-optional-server-to-server path (Spec §3b row 6 "mTLS optional"), not for the primary bearer-JWT path.

### Task 1.4 — Auth/tenancy resolution (mTLS SPIFFE, ingest token, UDP CIDR) + identity store

- **Files:**
  - Create: `services/svc-ingest/migrations/0001_ingest_identity.sql` (two tables: `ingest_identities(spiffe_path TEXT PRIMARY KEY, tenant_id TEXT NOT NULL)`; `ingest_tokens(token_hash TEXT PRIMARY KEY, tenant_id TEXT NOT NULL, revoked_at TIMESTAMPTZ, expires_at TIMESTAMPTZ NOT NULL)`)
  - Modify (fill stub): `services/svc-ingest/src/identity_store.rs`, `services/svc-ingest/src/auth.rs`
- **Interfaces:**
  - Produces (`auth.rs`):
    ```rust
    pub const LOG_INGEST_FLAG: &str = "skauswatch.log-ingest";
    pub enum AuthError { NoCredential, InvalidCert, UnknownIdentity, TokenRevoked, TokenExpired }
    pub async fn resolve_via_mtls(peer: &spiffe::SpiffeId, store: &IdentityStore) -> Result<skauswatch_auth::Tenant, AuthError>;
    pub async fn resolve_via_token(raw_token: &str, store: &IdentityStore, cache: &TokenCache) -> Result<skauswatch_auth::Tenant, AuthError>;
    pub fn resolve_via_udp_cidr(peer_ip: std::net::IpAddr, cfg: &crate::config::Config) -> Option<skauswatch_auth::Tenant>;
    ```
    `TokenCache` is a `moka`-free hand-rolled `Arc<Mutex<HashMap<String, (Tenant, Instant)>>>` with a 5-minute TTL per Spec §9b ("5 min cache, validate on every request" — cache hit skips the DB round-trip, cache miss/expiry re-queries `identity_store`).
  - Produces (`identity_store.rs`): `IdentityStore::tenant_for_spiffe_path(&self, path: &str) -> sqlx::Result<Option<Tenant>>`, `IdentityStore::tenant_for_token_hash(&self, hash: &str) -> sqlx::Result<Option<TokenRecord>>` (`TokenRecord { tenant: Tenant, revoked_at: Option<DateTime<Utc>>, expires_at: DateTime<Utc> }`).
  - Consumes: `spiffe::cert::spiffe_id_from_der` (already the exact function `crates/skauswatch-identity/src/tls.rs::peer_spiffe_id` calls internally — call it directly here too, no change needed to `skauswatch-identity`) to extract the peer SPIFFE ID's `.path()` segment after a completed mTLS handshake; `skauswatch_db::{DbConfig, run_migrations}`.
  - Token hashing: SHA-256 (`sha2` crate, already workspace-pinned) of the raw bearer token before any DB lookup/storage — never store or log a plaintext ingest token.
- **Acceptance criteria + key tests (Spec §14b Auth tests, verbatim list):**
  - `mtls_cert_valid_ingests_and_stamps_tenant_from_spiffe_id`
  - `mtls_cert_invalid_is_rejected_403`
  - `mtls_cert_with_mismatched_spiffe_tenant_is_403` (SPIFFE ID has no row in `ingest_identities`)
  - `ingest_token_valid_ingests_and_stamps_tenant_from_lookup`
  - `ingest_token_revoked_is_401`
  - `bearer_token_absent_and_no_mtls_is_401`
  - `udp_packet_from_trusted_cidr_stamps_configured_tenant`
  - `udp_packet_from_untrusted_cidr_dropped_no_error` (also covered in 1.1, re-asserted here at the `resolve_via_udp_cidr` unit level)
  - `token_cache_hit_skips_db_lookup_within_ttl` / `token_cache_expires_after_five_minutes` (use `skauswatch_testkit::db` for a real Postgres/SQLite pool per `implementing-database-patterns` skill).
- **Suggested executor:** `penguin-rust-dev`, **model:** sonnet (security-critical tenant boundary — highest scrutiny task in the plan).
- **Dependencies:** Wave 0 complete. No other Wave 1 task depends on this landing first to *compile* against its own files, but 1.1/1.2/1.3's auth-path tests need this task's real implementation to pass (not just the stub) before the Wave 1 gate closes.

### Task 1.5 — Writer mode: JetStream consumer → OCSF passthrough validation → OpenSearch bulk + DLQ

- **Files:**
  - Modify (fill stub): `services/svc-ingest/src/writer.rs`
  - Create: `services/svc-ingest/src/opensearch/mod.rs` (daily index naming + `_bulk` body builder + `write_bulk`, ported from `services/logs/src/opensearch.rs`'s `daily_index`/`build_bulk_body`/`write_bulk` — same byte-for-byte NDJSON framing, now operating on `skauswatch_ocsf::JsonVal`)
- **Interfaces:**
  - Consumes: `crate::buffer::EventBuffer::{consume, ack, nack}` (Task 0.3); `skauswatch_ocsf::JsonVal` (Task 0.1).
  - Produces: `pub async fn run(cfg: &Config, buffer: Arc<dyn EventBuffer>, http: reqwest::Client) -> anyhow::Result<()>` — loop: `consume(NATS_CONSUMER_PREFETCH)` → build `_bulk` body per-tenant-daily-index → `write_bulk` → on success `ack` every delivered handle; on failure, `nack` (JetStream at-least-once redelivery) and after N consecutive failures for the same `dedup_key`, route to `svc-ingest.logs.dlq` (Spec §7c "Dead-letter queue") instead of endlessly nacking.
  - `pub fn daily_index(tenant: &str, now: DateTime<Utc>) -> String` — `skauswatch-logs-{tenant}?` — **decision needed here, not deferred**: the Spec's unified index scheme (§8a) is `skauswatch-logs-*-YYYY.MM.DD` with no explicit tenant segment in the index name (tenant isolation is via the `tenant_id` field + query-time filtering, matching how `services/logs` already does it — see `stamp_tenant`/`ingested_document_is_stamped_with_caller_tenant`). This task keeps the existing `skauswatch-logs-YYYY.MM.DD` naming (no per-tenant index split) to stay Spec-compliant; do not invent per-tenant indices.
- **Acceptance criteria + key tests (Spec §14b Durability tests, verbatim list):**
  - `writer_crash_mid_batch_causes_at_least_once_redelivery` — kill the writer loop mid-batch (drop the future), restart consumption, assert the same batch is redelivered (JetStream explicit-ack semantics) and OpenSearch's own `_id` dedup (or a dedup_key-derived deterministic `_id`) prevents duplicate documents.
  - `opensearch_down_for_ten_minutes_then_recovers_no_loss` — mock OpenSearch returning 503 for N calls then 200; assert every buffered event is eventually written, zero drops.
  - `repeated_bulk_failure_routes_to_dlq_not_silent_drop` (Spec §7c) — assert a DLQ-buffer push happens with a timestamp + error reason after the failure threshold.
  - `bulk_body_frames_action_and_document_lines_matches_v1_framing` (parity with `services/logs/src/opensearch.rs`'s existing test).
- **Suggested executor:** `penguin-rust-dev`, **model:** sonnet (at-least-once + DLQ correctness is durability-critical).
- **Dependencies:** Task 0.3 (EventBuffer trait must exist).

**Integration + Gate 1→2:** Orchestrator wires all five Wave 1 modules together in `main.rs`'s `serve()` (a small, non-conflicting final edit the orchestrator itself makes, not a subagent task, since every module it references now exists) — `cargo build --workspace`, full `cargo nextest run -p skauswatch-svc-ingest` (report exact pass count), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo llvm-cov -p skauswatch-svc-ingest --fail-under-lines 90`. Manually smoke-test one syslog UDP packet → OpenSearch round trip locally (testcontainers NATS+OpenSearch) before Wave 2.

---

## Wave 2 — Lifecycle, Lake Unification, K8s Chart (4 parallel tasks)

### Task 2.1 — ISM hot/warm/cold tiering + snapshot repo + admin settings endpoint

- **Files:**
  - Create: `services/svc-ingest/src/opensearch/ism.rs` (new file, disjoint from 1.5's `opensearch/mod.rs`), `services/svc-ingest/src/admin.rs` (fills 0.2 stub)
  - Modify: `services/svc-ingest/src/openapi.rs` (add the admin settings route's utoipa annotation — sequential after 1.3, safe since Wave 2 starts after the Wave 1 gate)
- **Interfaces:**
  - Produces: `pub fn build_ism_policy(hot_to_warm_days: i64, warm_to_cold_days: i64, cold_to_delete_days: i64, snapshot_repo: &str) -> serde_json::Value` — extends `services/logs/src/opensearch.rs::build_ism_policy`'s 2-state (hot/warm/delete) shape to 4 states (hot/warm/cold/delete) per Spec §8a1's table (defaults 30d/90d/370d); `pub fn validate_monotonic_ages(hot_to_warm: i64, warm_to_cold: i64, cold_to_delete: i64) -> Result<(), IsmConfigError>` (Spec: "All three ages are strictly increasing (validated at policy creation/update; reject non-monotonic configs)").
  - Produces (`admin.rs`): `PUT /api/v1/admin/ingest/lifecycle` (platform/super-admin scope only, per Spec §8a1 "Operators configure these globally... via an admin settings endpoint") — request body `{hot_to_warm_days, warm_to_cold_days, cold_to_delete_days}`, calls `validate_monotonic_ages` then `ensure_ism_policy` (reused from `services/logs/src/opensearch.rs::ensure_ism_policy` pattern, PUT to `_plugins/_ism/policies/{id}`). `POST /api/v1/admin/ingest/restore` — SIEM-admin-scoped, audited, triggers a COLD-tier restore per Spec §8a1.
- **Acceptance criteria + key tests (Spec §8a1 Testing, verbatim):**
  - `ism_policy_validation_rejects_non_monotonic_config` (hot_to_warm=90, warm_to_cold=30 → error, not applied).
  - `warm_tier_searchable_snapshot_roundtrip` — ingest 100 events (testcontainers OpenSearch), force a WARM transition, query, assert results match original.
  - `cold_tier_restore_triggers_audit_log_and_becomes_queryable` — move to COLD, call the restore endpoint, assert an audit-log entry is written and the restored data becomes queryable.
  - `admin_endpoint_requires_super_admin_scope` — a token with only `*:read` gets 403.
- **Suggested executor:** `penguin-rust-dev`, **model:** sonnet (multi-tier ISM + restore-audit correctness).
- **Dependencies:** Wave 1 complete (needs `opensearch/mod.rs` and `openapi.rs` to exist).

### Task 2.2 — Monitor collector retirement

- **Files:**
  - Delete: `services/monitor/src/collectors/syslog.rs`
  - Modify: `services/monitor/src/collectors/mod.rs` (remove the syslog module reference), `services/monitor/src/main.rs` (remove syslog collector wiring, if any), `services/monitor/src/es.rs` (per Spec §8d: refactor to read-only over the unified `skauswatch-logs-*` — the TAXII IOC matcher keeps running but queries the unified lake instead of `aaa-events-*`)
- **Interfaces:**
  - Consumes: nothing new from svc-ingest at the code level — collectors that still exist (auditd/file/journald/kubernetes/lxc/database) are updated to POST to `svc-ingest`'s HTTPS `/ingest` (reusing monitor's existing `reqwest::Client` + a new ingest-token env var) instead of writing directly to monitor's `ElasticsearchStore`.
- **Acceptance criteria + key tests:**
  - `services/monitor` builds and its existing non-syslog collector tests still pass with the direct-write path replaced by an HTTP POST to a mocked `/ingest` (wiremock).
  - `syslog_collector_module_is_removed` — a compile-time check (the module simply doesn't exist); any test previously targeting `services/monitor/src/collectors/syslog.rs` is deleted, not disabled.
  - `taxii_ioc_matcher_queries_unified_index_pattern` — assert the query target is `skauswatch-logs-*`, not `aaa-events-*`.
- **Suggested executor:** `penguin-rust-dev`, **model:** haiku (mechanical removal + a config-only redirect).
- **Dependencies:** Wave 1 complete (Task 1.3's `/ingest` contract must be stable).

### Task 2.3 — `aaa-events-*` → unified lake backfill Job

- **Files:**
  - Create: `services/svc-ingest/src/bin/backfill.rs` (or a `Backfill` clap subcommand on the main binary, per house convention of one binary per service — prefer extending `main.rs`'s `Command` enum with `Command::Backfill { start_date, end_date, batch_size, dry_run }` over a separate `[[bin]]`, since `services/svc-ingest/src/main.rs` module wiring already exists and this avoids a second binary artifact)
  - Create: `crates/skauswatch-ocsf/src/mappings/legacy_aaa_events.rs` (BaseEvent → OCSF field mapping — facility/severity integers, source enum→string — per Spec §8c)
  - Modify: `services/svc-ingest/src/main.rs` (add the `Backfill` variant to the pre-existing `Command` enum — sequential after Wave 1, safe)
- **Interfaces:**
  - Produces: `pub fn legacy_aaa_event_to_ocsf(raw: &JsonVal) -> Result<JsonVal, NormalizeError>` in the new mappings file.
  - Consumes: `services/logs/src/opensearch.rs`-style scroll-cursor pagination against `aaa-events-*` (reqwest, same OpenSearch REST pattern already established), `skauswatch_ocsf::normalize`-adjacent bulk-write helper from `opensearch/mod.rs` (Task 1.5).
- **Acceptance criteria + key tests:**
  - `backfill_dry_run_maps_without_writing` — `DRY_RUN=true` produces the mapped documents (assert count + shape) but issues zero `_bulk` POSTs (wiremock assert 0 received requests).
  - `backfill_batches_by_start_end_date_and_batch_size` — three date-range batches produce three separate scroll queries.
  - `legacy_event_facility_severity_integers_map_to_ocsf_severity_id` — a `BaseEvent`-shaped fixture with `Severity::Critical` maps to OCSF severity_id 5, matching the syslog mapping's own severity scale for consistency.
- **Suggested executor:** `penguin-rust-dev`, **model:** haiku (one-time batch job, well-bounded scope, reuses existing bulk-write plumbing).
- **Dependencies:** Wave 1 complete (Task 1.5's OpenSearch bulk-write helper).

### Task 2.4 — K8s Helm chart `k8s/helm/svc-ingest`

- **Files:**
  - Create: `k8s/helm/svc-ingest/{Chart.yaml,values.yaml,alpha.yml,beta.yml,gamma.yml,production.yml}`, `templates/{_helpers.tpl,configmap.yaml,secret.yaml,deployment-receiver.yaml,deployment-writer.yaml,service-receiver.yaml,ciliumnetworkpolicy-receiver.yaml,ciliumnetworkpolicy-writer.yaml,tracingpolicy.yaml,hpa-receiver.yaml,hpa-writer.yaml,backfill-job.yaml}`
- **Interfaces:**
  - Consumes: the exact CiliumNetworkPolicy YAML shape from Spec §9a (two policies: `svc-ingest-receiver` allowing ingress on 5140/UDP+TCP, 6514/TCP, 4317/TCP, 4318/TCP, 8443/TCP from same-namespace + egress to `nats-jetstream:4222` and `opensearch:9200`; `svc-ingest-writer` with no inbound service port, egress to `opensearch:9200`, `nats-jetstream:4222`, `svc-vault:8200`); the Service table from Spec §9a (`svc-ingest-receiver` ClusterIP multi-port; `svc-ingest-writer` — **no Service at all**, since it has "None (internal, reads JetStream only)" per the Spec's own table — do not create a writer Service).
  - Produces: two Deployments differing only in `args: ["serve", "--mode", "receiver"]` vs `["serve", "--mode", "writer"]` and their probe/port wiring (receiver has `livenessProbe`/`readinessProbe` on `:8443/healthz`; writer, having no HTTP surface at all in the Spec's design, gets an exec-based or gRPC-based probe instead — decide and document which; recommend a lightweight internal `:9091` HTTP healthz the writer binds purely for probes, not part of the Spec's public listener table, analogous to `:9090` metrics already being a private surface).
  - `values.yaml` follows the exact `k8s/helm/logs/values.yaml` shape (`podSecurityContext.runAsUser: 1000`, `securityContext.capabilities.drop: [ALL]`, `readOnlyRootFilesystem: true`, `tetragon.enabled: true`) plus new env: `NATS_URL`, `NATS_JETSTREAM_SYNC_ALWAYS=true` (Global Constraint — bake this in as a non-overridable default, not just a suggested value), `SYSLOG_UDP_ENABLED` (default `"false"`), `OPENSEARCH_URL`, `JWT_VERIFY_KEY` (secretKeyRef, same as `k8s/helm/logs`).
- **Acceptance criteria + key tests:**
  - `helm lint k8s/helm/svc-ingest` clean.
  - `helm template svc-ingest k8s/helm/svc-ingest --values k8s/helm/svc-ingest/alpha.yml` renders without error; assert (via `yq`/grep in the test script) that `svc-ingest-writer` has **no** `Service` object, `capabilities.drop: [ALL]` appears on every container, and the two CiliumNetworkPolicies match the Spec's port list exactly (5140 UDP+TCP, 6514, 4317, 4318, 8443 for receiver; no receiver-facing ports for writer).
  - `securitycontext_never_grants_net_admin_by_default` — UDP :514 special case (Spec §9c) requires an explicit, separately-documented `NET_BIND_SERVICE`/`NET_ADMIN` exception comment if a values override ever sets the real privileged port; default values must NOT grant it (default port is 5140, unprivileged).
- **Suggested executor:** `k8s-manifest-builder`, **model:** sonnet (dual-Deployment, dual-CNP chart with a genuinely novel "no Service for one mode" shape).
- **Dependencies:** Wave 1 complete (needs the real port/health-endpoint contract finalized).

**Integration + Gate 2→3:** `helm lint` + `helm template` for every values file (alpha/beta/gamma/production), `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`. Deploy to a local MicroK8s cluster and confirm both Deployments reach `Running` with `readyz` green before Wave 3.

---

## Wave 3 — Tests, OTel, Cutover (3 tasks)

### Task 3.1 — Durability + per-protocol e2e integration test suite

- **Files:**
  - Create: `services/svc-ingest/tests/durability.rs`, `services/svc-ingest/tests/per_protocol_e2e.rs` (integration tests dir, `testcontainers` for real NATS JetStream 2.14+ and OpenSearch)
- **Interfaces:**
  - Consumes: the full assembled `svc-ingest` binary/router surfaces from Waves 0-2 (black-box HTTP/gRPC/UDP/TCP clients against a locally-spawned instance, `skauswatch_testkit::jwt`/`license` for auth fixtures).
- **Acceptance criteria + key tests (Spec §14b, verbatim, the ones not already covered at the unit level in Waves 0-2):**
  - `jetstream_crash_and_restart_zero_loss_no_duplication` — ingest 100 events with MsgId dedup, force-kill the JetStream container mid-batch, restart with the same volume, assert exactly 100 events present (Spec's exact "100 events... exactly once" test).
  - `syslog_udp_100_events_all_reach_opensearch`, `syslog_tcp_backpressure_and_eventual_delivery_when_opensearch_degraded`, `syslog_tls_mtls_handshake_and_ingestion`, `otlp_grpc_50_logrecords_all_indexed`, `https_ocsf_and_generic_json_both_indexed` (Spec §14b "Per-protocol e2e" list, all six).
  - `smoke_test_matches_spec_14c_script` — a single test asserting the exact sequence: build image, start JetStream+OpenSearch, 100 syslog UDP, 10 OTLP gRPC, 5+5 HTTPS docs, all indexed, telemetry emitted, cleanup — under 2 minutes wall clock.
- **Suggested executor:** `test-runner`, **model:** sonnet (testcontainers orchestration + timing-sensitive crash/restart scenario).
- **Dependencies:** Wave 2 complete.

### Task 3.2 — OTel traces instrumentation end-to-end

- **Files:**
  - Modify: `services/svc-ingest/src/{listeners/**,writer.rs,buffer/jetstream.rs}` (add `tracing::instrument` spans, not new files — narrow, additive edits across already-final files)
- **Interfaces:**
  - Produces: a span per Spec §11a "Traces" list — end-to-end parse→normalize→enqueue→ack, and writer-side consume→bulk-write spans; metrics per Spec §11a "Metrics" list (`svc_ingest_receiver_events_total`, `svc_ingest_receiver_parse_duration_ms`, `svc_ingest_receiver_queue_depth`, `svc_ingest_writer_bulk_write_duration_ms`, `svc_ingest_writer_opensearch_errors_total`, `svc_ingest_buffer_full_rejections_total`) via the workspace `metrics` crate.
  - Self-exclusion (Spec §11b): confirm `OTEL_EXPORTER_OTLP_ENDPOINT` routes to the metrics/trace collector only, never svc-ingest's own `/ingest` — add a startup assertion/log if the configured OTLP endpoint host matches svc-ingest's own service DNS name (defense-in-depth, not just documentation).
- **Acceptance criteria + key tests:**
  - `telemetry_gate_smoke_test` (Spec §11c, exact denominators): ≥1 log record, ≥1 metric data point, ≥1 span received by a local OTLP test sink — report the actual counts, never a bare pass.
  - `every_metric_in_spec_11a_is_registered` — a test enumerating the six named metrics and asserting each has been recorded at least once during a smoke run.
- **Suggested executor:** `penguin-rust-dev`, **model:** haiku (mechanical instrumentation of already-final code).
- **Dependencies:** Wave 2 complete (all instrumented code paths must be final).

### Task 3.3 — Cutover: manager `/siem/ingest` repoint + `services/logs` deprecation

- **Files:**
  - Modify: `k8s/helm/manager/values.yaml` (repoint `LOGS_URL` to `http://svc-ingest-receiver:8443`) for beta/gamma/production values files only, **not** `services/manager/src/routes/siem.rs` code (no code change needed — `proxy_ingest` already forwards to whatever `LOGS_URL` resolves to)
  - Modify: `k8s/helm/logs/values.yaml` (`replicaCount: 0` and `autoscaling.enabled: false` — deprecate without deleting, one release for rollback safety) + a doc comment explaining why
- **Interfaces:**
  - Consumes: Task 1.3's byte-compatible `/ingest` contract (already verified by the ported test suite in Wave 1) as the proof this repoint is safe.
- **Acceptance criteria + key tests:**
  - `helm template manager --values k8s/helm/manager/beta.yml` renders `LOGS_URL=http://svc-ingest-receiver:8443`.
  - A live-cluster smoke test (via `test-runner`/`k8s-ops`, not a unit test): POST through the manager's `/api/v1/siem/ingest` proxy and confirm the document lands in `skauswatch-logs-*` — end-to-end proof the cutover works, not just that the config changed.
  - `services/logs` chart still renders cleanly at `replicaCount: 0` (no broken template references).
- **Suggested executor:** `penguin-rust-dev`, **model:** haiku (config-only change plus a live verification step).
- **Dependencies:** Wave 2 complete; Task 3.1's e2e suite green (do not cut over on unverified durability).

**Final Gate:** Full `make pre-commit` (lint → security scans → secrets → build → smoke tests incl. telemetry validation → full test suite → Dockerfile check) clean, `cargo deny check` clean, coverage ≥90% via `cargo llvm-cov` for every touched crate, screenshots N/A (no UI), OpenAPI spec regenerated (`skauswatch-svc-ingest openapi > openapi/v1.yaml`) and `spectral lint` clean.

---

## Deferred / Out of Scope (Spec §15 Open Questions, not mapped to a task in this plan)

- Durable-consumer-per-pod-lease design for writer replicas (Spec open question #1) — P1 ships a single-consumer assumption; multi-writer-replica lease coordination is a follow-up spike, not blocking P1.
- Dynamic (Vault/manager-API-queried) UDP CIDR provisioning (Spec open question #2) — static env-var CIDR list only, per the Spec's own P1 recommendation.
- Splunk HEC compatibility / additional appliance-forwarded syslog variants (Spec §13 Phase P4) — explicitly a later phase.
- DLQ retention/alerting policy tuning (Spec open question #6) — this plan's Task 1.5 implements the DLQ stream itself; the 30-day-retention/alert-on-any-event policy is a follow-up ops configuration, not new code.
