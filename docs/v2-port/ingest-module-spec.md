# svc-ingest — Multi-Protocol SIEM Log Ingest Service

**Status:** Design spec · **Target:** v2.1 (ingest plane separation) · **Flag:** `skauswatch.log-ingest` (default OFF, Professional tier)

Net-new dedicated ingest service absorbing direct-push HTTP ingest (`services/logs`), syslog collection (`services/monitor`'s RFC 3164 UDP), and OTLP logs pull — unified OCSF normalization + durable buffer (NATS JetStream) + runnable in two modes (receiver/writer for independent scaling). Closes the single-biggest fragmentation vector: today, log ingest is embedded in `services/logs` (HTTP only), syslog is a monitor collector (UDP-only, writes directly to `aaa-events-*` not OCSF), and there is no OTLP surface at all. Extracting the ingest plane as a separate service unlocks: protocol diversity without scope-bloating the original service; independent buffer/scaling; unified OCSF normalization pipeline; groundwork for the lake-unification P1 (monitor's collectors will route to svc-ingest's `/ingest` instead of direct-write).

## 1. Positioning

| | v1 `ingest/http_handler.py` | `services/monitor::collectors::syslog` | **svc-ingest** |
|---|---|---|---|
| Transport | HTTP `POST /ingest` | UDP socket binding, inline parse | **HTTP/HTTPS + syslog UDP/TCP/TLS + OTLP gRPC/HTTP** |
| Parser | OCSF normalizer | RFC 3164 only, single-pass | **RFC 3164 + RFC 5424 (syslog); OTLP proto; OCSF passthrough; generic JSON heuristic** |
| Storage | Immediate bulk-index to OpenSearch | Direct ElasticsearchStore write to `aaa-events-*` | **NATS JetStream stream → async writer drains to OpenSearch** |
| Auth | JWT `skauswatch_auth::tenant_middleware` | None (trusted CIDR or implicit tenant from monitor's own context) | **mTLS cert→SPIFFE ID→tenant primary; ingest-token fallback for non-mTLS sources; UDP trusted-CIDR-only** |
| Normalization | Byte-for-byte v1 OCSF port | BaseEvent struct (different schema) | **All → OCSF via extracted `skauswatch-ocsf` crate** |
| Tenant isolation | Stamped server-side | None (monitor's implicit context) | **Always server-side, never from event payload** |

**Core principle:** one ingest service, one OCSF schema, one unified OpenSearch lake. Today the platform has two (logs' `skauswatch-logs-*`, monitor's `aaa-events-*`) wearing one name. This service is both the enabler and the proof of lake unification.

## 2. Non-Goals

- No on-ingest detection, response, or enrichment (those belong in the SIEM correlation/AI layer, reading from the unified lake)
- No transformer plugins or custom DSL (protocols are native, parsing is fixed)
- No schema evolution beyond OCSF 1.3.0 (new class/activity additions are OCSF upstream, not driver-specific inventions)
- No cross-tenant aggregation or billing logic (that's manager-side, this is the plumbing)

## 3. Architecture Overview

### 3a. Component diagram (ASCII)

```
┌─────────────────────────────────────────────────────────────────┐
│                         svc-ingest                               │
│                                                                  │
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────┐  │
│  │  RECEIVER MODE   │  │   WRITER MODE    │  │  SHARED LIBS │  │
│  │                  │  │                  │  │              │  │
│  │ ┌──────────────┐ │  │ ┌──────────────┐ │  │ EventBuffer  │  │
│  │ │ syslog       │ │  │ │ JetStream    │ │  │ trait        │  │
│  │ │ listeners:   │ │  │ │ consumer:    │ │  │              │  │
│  │ │ UDP/TCP/TLS  │ │  │ │ drain        │ │  │ OCSF crate   │  │
│  │ │ :514/:6514   │ │  │ │ stream +ack  │ │  │ normalize()  │  │
│  │ └──────────────┘ │  │ └──────────────┘ │  │              │  │
│  │                  │  │                  │  │ Observability│  │
│  │ ┌──────────────┐ │  │ ┌──────────────┐ │  │ (logs/metrics│  │
│  │ │ OTLP         │ │  │ │ OpenSearch   │ │  │  /traces)    │  │
│  │ │ listeners:   │ │  │ │ bulk write   │ │  │              │  │
│  │ │ gRPC :4317   │ │  │ │ retry+DLQ    │ │  │ Auth:        │  │
│  │ │ HTTP :4318   │ │  │ └──────────────┘ │  │ mTLS + token │  │
│  │ └──────────────┘ │  │                  │  │              │  │
│  │                  │  │                  │  │ Secrets:     │  │
│  │ ┌──────────────┐ │  │                  │  │ svc-vault    │  │
│  │ │ HTTPS        │ │  │                  │  │              │  │
│  │ │ (OCSF/JSON)  │ │  │                  │  │              │  │
│  │ │ :8443        │ │  │                  │  │              │  │
│  │ └──────────────┘ │  │                  │  │              │  │
│  │                  │  │                  │  │              │  │
│  │ ┌──────────────┐ │  │                  │  │              │  │
│  │ │ Parse+       │ │  │                  │  │              │  │
│  │ │ Normalize    │ │  │                  │  │              │  │
│  │ │ (OCSF crate) │ │  │                  │  │              │  │
│  │ └──────────────┘ │  │                  │  │              │  │
│  │                  │  │                  │  │              │  │
│  │ ┌──────────────┐ │  │                  │  │              │  │
│  │ │ Enqueue      │──┼──│ NATS JetStream   │  │              │  │
│  │ │ (backpressure│ │  │ durable stream   │  │              │  │
│  │ │  429 on full)│ │  │ (disk-backed)    │  │              │  │
│  │ └──────────────┘ │  │                  │  │              │  │
│  └──────────────────┘  └──────────────────┘  └──────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
              │                               │
              ▼                               ▼
        NATS JetStream                  OpenSearch
        (tenant-scoped streams)         (skauswatch-logs-*)
```

### 3b. Listener & port table

| Transport | Port | Parser | Auth | Backpressure |
|-----------|------|--------|------|--------------|
| **Syslog UDP** | 514 (`:5140` unprivileged by default, override + `NET_BIND_SERVICE` capability for production 514) | RFC 3164 + RFC 5424 (auto-detect) | Trusted CIDR list only, OFF by default | UDP inherently lossy (documented) |
| **Syslog TCP** | 514 (`:5140` unprivileged) | RFC 3164 + RFC 5424 (auto-detect) | mTLS cert (primary) or ingest-token (header) | `NACK` on JetStream full, close conn |
| **Syslog TLS** | 6514 (standard, `:6514` unprivileged) | RFC 3164 + RFC 5424 (auto-detect) | mTLS cert (primary, client-cert + SNI validation) or ingest-token as TLS fallback | `NACK` on JetStream full, close conn |
| **OTLP gRPC** | 4317 | OpenTelemetry logs proto (v1) | mTLS cert (primary) or ingest-token (gRPC metadata header) | gRPC `RESOURCE_EXHAUSTED` (429 equivalent) |
| **OTLP HTTP** | 4318 | OpenTelemetry logs proto (v1, JSON or protobuf) | mTLS cert (primary) or ingest-token (HTTP Authorization header) | HTTP 429 |
| **HTTPS (OCSF/JSON)** | 8443 | OCSF schema validation (native) or generic JSON heuristic-normalized | Bearer JWT (stamped by handler); mTLS optional for server-to-server | HTTP 429 (same as logs v1 contract) |

All TLS ports use **rustls** only (no OpenSSL C bindings). mTLS certificate validation extracts SPIFFE ID from SAN or CN; tenant is resolved server-side from the ID (never from event payload). TCP/TLS backpressure drops the connection gracefully on buffer saturation; UDP is documented as lossy by design.

## 4. Ingest Formats & Parsers

### 4a. Syslog (RFC 3164 + RFC 5424, UDP/TCP/TLS)

**Parser logic:** detect on first character — `<` (angle bracket) → try RFC 5424; else → RFC 3164. Both emit a normalized tuple: `(severity, facility, hostname, message, timestamp)`.

| Standard | Format | Timestamp handling | Notes |
|----------|--------|-------------------|-------|
| **RFC 3164** | `<PRI>MMM DD HH:MM:SS HOSTNAME MESSAGE` | Year inferred (Jan 1 assumed if date crosses year boundary) | v1 `collectors/syslog_collector.py`'s UDP parser, known limitation (year wrap edge cases); acceptable for P1 |
| **RFC 5424** | `<PRI>VERSION ISOTIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MESSAGE` | Full ISO 8601 with timezone | Higher fidelity; both must be supported simultaneously in one listener |

**Severity/Facility mapping:** `PRI = facility × 8 + severity`; both are extracted and emitted as integers (match OCSF severity IDs and the `detect_severity` mapping in the existing normalizer). If an incoming syslog already carries a severity/facility, it is used; if missing, fallthrough to heuristic normalization (same as `detect_severity` in current `ocsf.rs`).

**Hostname extraction:** used as `src_hostname` or `host` in the OCSF document. If the source is a trusted syslog server (a forwarder), the original hostname is lost unless the syslog MESSAGE itself carries it (e.g., Rsyslog's `tag` prefix) — known limitation, acceptable for P1.

### 4b. OTLP Logs (gRPC :4317 + HTTP :4318)

OpenTelemetry Protocol, v1 spec (`opentelemetry-proto` crate, Apache-2.0). Ingest `LogRecord` messages:

```protobuf
message LogRecord {
  fixed64 time_unix_nano = 1;
  fixed64 observe_time_unix_nano = 2;
  string body = 5;                      // message text
  int32 severity_number = 6;            // maps to OCSF severity
  string severity_text = 7;
  map<string,AnyValue> attributes = 8;  // arbitrary labels → OCSF metadata
}
```

**Mapping to OCSF:** `body` → message, `severity_number` → OCSF severity ID (0-5 range, same as RFC 5424 levels), `time_unix_nano` → timestamp. Resource/span attributes (service name, version, environment) → OCSF `resource` / `metadata` fields. Attribute keys carrying security-relevant data (e.g., `user_id`, `src_ip`, `dst_ip`, `action`) are aliased to their OCSF counterparts automatically; unknown attributes land in `metadata.custom_attributes` (a map, no schema enforcement — OCSF is permissive).

**Native OTLP passthrough:** if the LogRecord already carries a complete OCSF-shaped attribute dict (which some instrumentations do), skip normalization and pass it through validated. This is the "OCSF as the unifying schema" principle — sources that already speak OCSF never get re-wrapped.

### 4c. OCSF + Generic JSON over HTTPS (:8443)

**Native OCSF:** request body is a single OCSF document or a JSON array of documents. Schema-validated against OCSF 1.3.0 (field names, required fields, type constraints). Valid documents are indexed directly; schema errors return HTTP 400.

**Generic JSON heuristic normalization:** if the body is valid JSON but not OCSF-shaped (e.g., a custom app log format: `{"timestamp": "...", "level": "...", "message": "...", "user": "..."}`), apply the existing `detect_class`/`detect_severity` heuristics from `ocsf.rs` to infer missing OCSF fields. This enables "push any JSON" use cases without breaking the pipeline; fidelity degrades gracefully (generic finding instead of a specific class).

Both paths are wrapped in the same tenant middleware + flag gate as the current logs service (inherited contract).

## 5. OCSF Normalization (`skauswatch-ocsf` Crate)

Extract the existing `services/logs/src/ocsf.rs` logic (class/severity/status detection heuristics, timestamp parsing, field mapping) into a shared **`crates/skauswatch-ocsf`** crate, published to the internal registry or committed as a workspace member. Consumed by:

1. `svc-ingest` — normalizing syslog, OTLP, and generic JSON
2. `services/logs` (refactored) — same normalization, now delegating to the crate instead of inlining it
3. Connector adapters (in v2.1, pulling CloudTrail/GuardDuty/etc.) — each adapter uses the same crate's `normalize()` entry point

**Crate structure:**

```
crates/skauswatch-ocsf/
  src/
    lib.rs              # normalize() → JsonVal; class/severity/status detection
    schema.rs           # OCSF 1.3.0 class registry, field name constants
    mappings/           # per-format mapping hints (RFC3164_FIELD_MAP, OTLP_ATTRIBUTE_MAP, etc.)
    tests/
      fixtures/         # RFC3164/5424/OTLP/generic JSON sample inputs + expected OCSF outputs
```

**Entry point:** `pub fn normalize(record: &JsonVal, source: &str) -> Result<JsonVal, NormalizeError>` — same signature as the current function, reusing its byte-for-byte-identical output for v1 parity.

**Per-format mapping notes:**

- **Syslog:** facility + severity integers → OCSF `process.name` / `severity_id` heuristic; MESSAGE → `message`; hostname → `src_hostname` or inferred from context.
- **OTLP:** attribute keys are case-insensitive aliases (`user_id` / `user` → OCSF `user_name`; `src_ip` → `src_ip_addr`); unknown attributes → metadata blob, no rejection.
- **OCSF passthrough:** no heuristics, schema-validated only.
- **Generic JSON:** fallback to existing `detect_*` functions if not OCSF-shaped.

## 6. Auth & Tenancy

### 6a. Primary: mTLS Client Certificate → SPIFFE ID → Tenant

Incoming mTLS connection presents a client certificate. Extract the SPIFFE ID from the Subject Alternative Name (SAN) or Common Name (CN) — format is `spiffe://penguintech.io/<env>/{identity}`. The `{identity}` part (e.g., `endpoint-agent`, `s3scan`, a custom source name) is resolved to a tenant via a **lookup table** (database or in-memory config). If the certificate is missing, invalid, or the SPIFFE ID does not map to a tenant, the connection is rejected with a 403 (HTTP) / UNAUTHENTICATED (gRPC) error.

**Why primary:** SPIFFE is the mesh identity standard; every ingest source that is part of the platform's infrastructure (agents, collectors, connectors) can hold a SPIFFE credential. Client certificates are cryptographic (no shared secrets), short-lived (issued/rotated by svc-vault), and carry no PII.

### 6b. Fallback: Per-Source Ingest Token

For sources that cannot do mTLS (e.g., third-party appliances, external monitoring agents, one-time manual log pushes), a pre-provisioned **ingest token** is accepted in place of the certificate. The token is a short-lived, bearer-style credential:

- **OTLP:** `Authorization: Bearer {token}` (HTTP headers or gRPC metadata)
- **Syslog:** TLS SNI or a custom `X-Ingest-Token` header (syslog-TLS mode), or an SNI value that maps to a token (not a hostname)
- **HTTPS:** `Authorization: Bearer {token}` (HTTP Authorization header)

Token validation: lookup the token in a Vault/IceBox secret backend (or a local revocation list cached from there) to resolve the tenant and verify the token has not expired or been revoked. Tokens are **never hard-coded** in the service or in configs; they are issued out-of-band (via the manager's provisioning API) and rotated on a fixed cadence or on revocation.

**Why fallback:** third-party integrations and legacy agents often cannot be modified to use mTLS; the fallback keeps the service usable without blocking on infrastructure upgrades.

### 6c. UDP Syslog: Trusted CIDR Only

UDP syslog (`:514` or `:5140`) is **OFF by default** and requires explicit operator opt-in (`SYSLOG_UDP_ENABLED=true` + `SYSLOG_TRUSTED_CIDRS=10.0.0.0/8,172.16.0.0/12`). A packet arriving from an untrusted IP is silently dropped (UDP has no connection state to reject gracefully). When enabled, the CIDR list is checked before parsing; if the source IP is outside the list, the packet is discarded, no error raised.

**Why restricted:** UDP has no authentication; trusting any UDP packet from any source would allow tenant-impersonation attacks (a malicious actor sends events claiming to be tenant A). Restricting to an operator-controlled CIDR (e.g., a syslog forwarder on the operator's network) mitigates this. Events arriving via UDP are **not** stamped with a tenant from the payload — the operator must configure svc-ingest to assign a fixed tenant ID to all UDP packets from a given CIDR, and the service hard-codes that mapping server-side.

### 6d. Server-Side Tenant Stamping (Mandatory)

**Rule:** the service NEVER reads a tenant ID from the event payload, request parameters, or any untrusted source. Tenant is ALWAYS extracted from the authenticated identity (mTLS SPIFFE ID, token lookup, UDP source CIDR mapping) and stamped onto the document by the handler before enqueueing. If the event payload happens to include a `tenant_id` field, it is either:

1. Ignored (dropped, never indexed)
2. Validated against the authenticated tenant and rejected if mismatched

This is the fundamental security principle (`security.md` Tenant Isolation) applied to ingest.

## 7. Durability & Backpressure

### 7a. NATS JetStream Buffer (Durable, File-Backed, Synchronous PublishAck)

**Why JetStream over Valkey:** syslog + OTLP + HTTP can arrive at ~10k events per second (EPS). At 2.5 KB/event (typical), that's ~25 MB/s, or ~8 GB/minute. An in-memory buffer (Valkey) fills in ~5 minutes during an OpenSearch outage and then drops events silently or crashes. JetStream is disk-backed by design: consumers pull from the stream at their own pace, the disk buffers backlog, and older events age off (configurable retention) without crashing the receiver.

**Production-hardening mandatory (security-evidence data):**

1. **NATS server version ≥2.14** — older versions have a message-loss bug under coordinated power-cut with async flush (Jepsen report, Dec 2025). Require 2.14+ in the deployment manifest.
2. **`sync_always: true` on the JetStream file store** — all published messages are synchronously flushed to disk before the server returns PublishAck to the client. Never rely on async flush for evidence data.
3. **Receiver awaits `PublishAck` synchronously before returning 2xx to the source** — the enqueue operation MUST block until the broker acknowledges the write to disk. For retryable transports (TCP/TLS/OTLP/HTTPS), the receiver does not return 2xx or send an ack until JetStream PublishAck arrives. Never fire-and-forget a publish. This is the load-bearing guarantee that enables idempotent retries without loss.
4. **Server-side deduplication via Nats-Msg-Id headers** — every event carries a unique `Nats-Msg-Id` header set by the receiver (e.g., a UUID or a deterministic hash of the event + timestamp). The NATS server performs server-side deduplication: if the same ID is published twice, the second is ignored. This handles client-side timeout + retry scenarios gracefully.
5. **Critical warning: Do NOT wrap `async-nats::jetstream::publish()` in `tokio::time::timeout()`** — a client timeout can fire while the TCP write persists on the broker's kernel buffer, causing the client to retry while the original write is still in flight. The result is silent duplication despite server-side dedup being disabled. Instead, use MsgId dedup + client-side timeout configuration on the NATS connection itself (`tokio_connector_config.timeout`), or accept that evidence ingest is one operation that does not have a strict timeout (re-raise on a background monitor if needed).

**Config:**

```toml
# NATS server version (K8s StatefulSet, helm chart)
NATS_SERVER_VERSION=2.14.0  # minimum

# JetStream file store sync
NATS_JETSTREAM_STORAGE=FILE
NATS_JETSTREAM_SYNC_ALWAYS=true

# Stream config
# Base subject for ingest streams (e.g., "svc-ingest.logs")
NATS_JETSTREAM_SUBJECT_PREFIX=svc-ingest.logs

# Max age: 7 days (events older than 7 days are deleted regardless of max_bytes)
NATS_MAX_AGE_SECONDS=604800

# Max bytes: 100 GB (ingest stream rolls when it hits this, deletes oldest messages)
NATS_MAX_BYTES=107374182400

# Consumer prefetch: writer drains in batches (e.g., 100 msgs at a time, then acks)
# Higher prefetch = faster drain but requires more memory; 100 is a reasonable default
NATS_CONSUMER_PREFETCH=100

# Acknowledgment mode: explicit (ack after OpenSearch write succeeds) — at-least-once delivery
NATS_EXPLICIT_ACK=true
```

### 7b. EventBuffer Trait (Pluggable) & Idempotent PublishAck

Behind a **`EventBuffer` trait**, the actual queue implementation is swappable. Receiver enqueues to `EventBuffer::push(event: NormalizedEvent)`, waiting for the PublishAck to return; writer consumes via `EventBuffer::consume(batch_size: usize) -> Vec<(event, ack_handle)>`.

**JetStream implementation** (P1) — Synadia `async-nats` client (Tier 1 support, feature-complete, production-proven in Vector):

```rust
pub struct JetStreamBuffer {
    client: nats::jetstream::Context,
    msg_id_counter: AtomicU64,  // or use UUID; must be deterministic per event for idempotency
}

impl EventBuffer for JetStreamBuffer {
    async fn push(&mut self, event: NormalizedEvent) -> Result<(), BufferError> {
        // Generate or derive a unique message ID for this event
        let msg_id = self.compute_msg_id(&event);

        // Publish SYNCHRONOUSLY — await PublishAck before returning
        // Never fire-and-forget or wrap in tokio::time::timeout()
        let ack = self.client.publish_with_headers(
            "svc-ingest.logs.ingest",
            &event.to_bytes(),
            &[("Nats-Msg-Id", &msg_id)],
        ).await?;

        // ack is a PublishAck — the server has synced to disk (sync_always: true)
        // Return error or RESOURCE_EXHAUSTED if the stream is full
        Ok(())
    }

    async fn consume(&mut self, batch_size: usize) -> Result<Vec<(Event, AckHandle)>> {
        // Fetch next batch from durable consumer, return without acking (caller acks)
        // Ack only after OpenSearch write succeeds
    }
}

// Dependency: pinned to exact version, minimal features
// Cargo.toml:
// async-nats = { version = "=0.50.0", default-features = false, features = ["jetstream"] }
// Note: 0.x is Synadia's intentional versioning indicating Tier 1 stability, not pre-release immaturity
```

**In-memory fallback** (testing only): a bounded `VecDeque<Event>` that drops oldest on overflow, with a Vec of seen MsgIds for dedup simulation.

### 7c. Backpressure Per Transport

| Transport | Full Buffer Behavior |
|-----------|---------------------|
| **UDP** | Drop packet (inherent to UDP, no feedback) |
| **TCP syslog** | Send TCP RST (close connection gracefully) or TCP NACK if a protocol-level ack exists; source must reconnect + retry |
| **TLS syslog** | Same as TCP — graceful close |
| **OTLP gRPC** | Send gRPC `RESOURCE_EXHAUSTED` status (HTTP 2 stream reset, equivalent to 429); client should retry with backoff |
| **OTLP HTTP** | HTTP 429 (too many requests) response; client should retry with backoff |
| **HTTPS (OCSF/JSON)** | HTTP 429; inherited from logs v1 contract |

**Dead-letter queue (DLQ):** if OpenSearch bulk-write fails repeatedly (e.g., cluster down for >10 min), events that have been acked off the JetStream stream are moved to a separate `svc-ingest.logs.dlq` stream for operator review. Events in the DLQ are **never** silently discarded; they are flagged with a timestamp and the error reason, and an alert is raised (observable via logs/metrics, not buried).

### 7d. RAM Bound by Design (JetStream Rationale)

**The math:**

| Scenario | EPS | Avg size | Rate | Saturation |
|----------|-----|----------|------|------------|
| Syslog peak | 10k | 2.5 KB | 25 MB/s | 8 GB/min |
| OTLP peak (with attrs) | 5k | 3 KB | 15 MB/s | ~5 GB/min |
| OpenSearch down (recovery time) | — | — | — | 1-10 min typical |
| JetStream total disk budget | — | — | — | 100 GB (configurable) |

In-memory queue filled in <1 min during sustained peak + outage → crash or silent loss. JetStream disk absorbs ~80 min of peak traffic at 100 GB config, giving an operator time to notice and respond.

## 8. Lake Unification & Migration

### 8a. Unified Index Scheme

Both the existing `skauswatch-logs-*` (v2 OCSF) and monitor's `aaa-events-*` (v1 BaseEvent) consolidate into a single **`skauswatch-logs-*-YYYY.MM.DD`** daily index pattern (same as today's logs service). All OCSF normalization targets this lake; monitor's collectors are retired from writing directly to `aaa-events-*`.

**ISM lifecycle policy:** managed via a new Data Lifecycle section (§8a1) below; replaces the existing `skauswatch-logs-policy`.

### 8a1. Data Lifecycle — Hot/Warm/Cold Tiering

Index State Management (ISM) policy orchestrates multi-tier archival: indices roll over by size/age, then transition through tiers based on age.

**Tier definitions:**

| Tier | Storage | Indexing | Query | Cost |
|------|---------|----------|-------|------|
| **HOT** | In-cluster hot nodes / local SSD | Full indexing, analyzers | Immediate, sub-second latency | High |
| **WARM** | Searchable snapshots (S3-compatible backend, MinIO default) | Read-only, snapshot-searchable via repository-s3 plugin | On-demand with local cache; queryable without restore | Medium |
| **COLD** | Compressed snapshots (cheapest backend — MinIO lifecycle rule or S3 Glacier) | Compressed, offloaded | Explicit restore-on-demand (slow, ~minutes) | Low |
| **DELETE** | — | — | — | — |

**Transition ages (ADMIN-CONFIGURABLE, not license-tier-driven):**

| Transition | Default | Notes |
|---|---|---|
| HOT → WARM | 30 days | Full indexing retention; after 30 days, move to searchable snapshots |
| WARM → COLD | 90 days | Compressed snapshots; still queryable but slower/with restore |
| COLD → DELETE | 370 days (~1 year) | Final retention boundary; older data purged |

All three ages are **strictly increasing** (validated at policy creation/update; reject non-monotonic configs). Operators configure these globally (platform/super-admin scope, cluster-wide) via an admin settings endpoint that writes/updates the ISM policy; changes apply to new indices immediately, existing indices re-evaluated on next state transition.

**Snapshot repository:**

- Endpoint: S3-compatible (MinIO, AWS S3, Wasabi, etc.) — MinIO is the default for self-hosted deployments
- Configuration: `SNAPSHOT_REPO_ENDPOINT` env var (defaults to MinIO internal address)
- Credentials: from `svc-vault` Secrets engine (no hardcoded S3 keys in config/code)
- Bucket: dedicated, versioning optional (ISM snapshots are immutable once created)

**Query across tiers:**

- **HOT + WARM transparent:** a search query returns results from both tiers seamlessly (searchable snapshots are queryable in-place)
- **COLD requires explicit restore:** responses indicate which tiers were searched; if COLD data matches, alert the user that a restore is pending (manual or auto-triggered via an admin flag)
- **Restore-on-demand:** restore API call (gated by SIEM admin role, audited) triggers a background restore job; restores data to WARM tier temporarily, then automatic re-archive after a TTL (e.g., 7 days)

**Ownership & maintenance:**

- `svc-ingest` (writer mode) creates and maintains the ISM policy and the index scheme (`skauswatch-logs-*-YYYY.MM.DD`)
- OpenSearch cluster roles and snapshot-repository registration are cluster infrastructure (managed separately, referenced here)
- Index rollover/state transitions are automatic (ISM handles it); svc-ingest publishes metrics tracking policy application and errors

**Testing:**

- ISM policy validation: reject non-monotonic age transitions (test with invalid config, assert error)
- WARM tier searchable snapshot: ingest 100 events, force transition to WARM, query and verify results match original
- COLD tier restore: move events to COLD, trigger restore API, verify data becomes queryable (slow), verify audit log records the restore request

### 8b. Monitor Collector Retirement

`services/monitor`'s collectors (auditd, file, journald, **syslog**, kubernetes, lxc, database) migrate from writing directly to monitor's own `ElasticsearchStore` to calling `svc-ingest`'s `/ingest` HTTP endpoint (or using a JetStream shared stream if co-located). Collectors become producers into the unified lake, same as a syslog appliance or an OTLP app would.

- **Syslog collector specifically:** the UDP listener and v1 RFC 3164 parser in `services/monitor/src/collectors/syslog.rs` are removed; sources that use monitor's syslog collector repoint to `svc-ingest`'s `localhost:5140` (or the production UDP/TCP/TLS listeners). Tenant ID (previously implicit in monitor's own context) is now provisioned via ingest token or mTLS SPIFFE ID.

- **Delivery:** collectors use the same EventBuffer interface, queueing to the unified JetStream stream. If monitor and svc-ingest are in the same pod/container, they can share the same JetStream connection (a local trait implementation, not over network). If separate, collectors push over HTTP to svc-ingest's `/ingest`.

### 8c. One-Time Backfill/Reindex Job

A **K8s Job** migrates existing events from `aaa-events-*` into the unified lake (optional but recommended for historical continuity):

1. Query all documents in `aaa-events-*` indices (ordered by timestamp)
2. For each document, map BaseEvent schema → OCSF via a legacy-adapter mapping (facility/severity integers, source enum → string, etc.)
3. Bulk-index into the daily `skauswatch-logs-*` index for that event's timestamp
4. Optional: delete `aaa-events-*` indices after verification (or keep read-only for audit)

**Job parameters:** `START_DATE` / `END_DATE` (in case the reindex needs to be parallelized across time ranges), `BATCH_SIZE` (number of documents per OpenSearch scroll cursor), `DRY_RUN=true` (validate mapping without writing).

The reindex runs once at lake-unification go-live; the mapping is documented in `skauswatch-ocsf` crate (a legacy adapter module, not a permanent feature).

### 8d. Monitor → Query-Only

Post-unification, monitor's `es.rs` module (`ElasticsearchStore`) is refactored to **read-only** over the unified lake. Collectors no longer write; the TAXII IOC matcher continues to run, but it now queries the unified `skauswatch-logs-*` instead of `aaa-events-*`. The monitor's own database `endpoint_events`/`endpoint_agents` tables remain for fleet-ops (agent list, telemetry) — only the event storage layer unifies.

## 9. Security & Kubernetes

### 9a. Per-Protocol Service + CiliumNetworkPolicy

Two K8s Services:

| Service | Port(s) | Selector | External |
|---------|---------|----------|----------|
| `svc-ingest-receiver` | 514 (UDP+TCP), 6514 (TLS), 4317 (gRPC), 4318 (HTTP), 8443 (HTTPS) | `app: svc-ingest, mode: receiver` | ClusterIP (pod-to-pod, no external access by default) |
| `svc-ingest-writer` | None (internal, reads JetStream only) | `app: svc-ingest, mode: writer` | ClusterIP (internal pod-to-pod) |

Both services behind a `CiliumNetworkPolicy` (not `NetworkPolicy`):

```yaml
# svc-ingest-receiver: allow inbound from trusted sources
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: svc-ingest-receiver
spec:
  endpointSelector:
    matchLabels:
      app: svc-ingest
      mode: receiver
  ingress:
  - fromEndpoints:
    - matchLabels:
        io/kubernetes.pod.namespace: skauswatch  # in-cluster sources only
    toPorts:
    - ports:
      - port: "5140"  # syslog
        protocol: UDP
      - port: "5140"
        protocol: TCP
      - port: "6514"
        protocol: TCP
      - port: "4317"
        protocol: TCP
      - port: "4318"
        protocol: TCP
      - port: "8443"
        protocol: TCP
  egress:
  - toEndpoints:
    - matchLabels:
        app: nats-jetstream  # JetStream service
    toPorts:
    - ports:
      - port: "4222"  # NATS client port
        protocol: TCP
  - toEndpoints:
    - matchLabels:
        app: opensearch
    toPorts:
    - ports:
      - port: "9200"
        protocol: TCP

# svc-ingest-writer: allow egress to OpenSearch + JetStream, ingress from receiver (if separate)
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: svc-ingest-writer
spec:
  endpointSelector:
    matchLabels:
      app: svc-ingest
      mode: writer
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: nats-jetstream  # JetStream drain -> reader notified
    toPorts:
    - ports:
      - port: "50051"  # gRPC (if used for inter-pod sync, not a P1 requirement)
        protocol: TCP
  egress:
  - toEndpoints:
    - matchLabels:
        app: opensearch
    toPorts:
    - ports:
      - port: "9200"
        protocol: TCP
  - toEndpoints:
    - matchLabels:
        app: nats-jetstream
    toPorts:
    - ports:
      - port: "4222"
        protocol: TCP
  - toEndpoints:
    - matchLabels:
        app: svc-vault
    toPorts:
    - ports:
      - port: "8200"
        protocol: TCP
```

### 9b. TLS & Secret Provisioning

- **Certificates:** mTLS cert/key for the receiver (accepted from clients); server cert for HTTPS/TLS ports. Issued by `svc-vault` PKI backend, stored as K8s Secrets, mounted read-only into pod.
- **Ingest tokens:** stored in `svc-vault` Secrets engine, cached locally in the receiver with TTL (e.g., 5 min cache, validate on every request).
- **OpenSearch credentials:** service-specific DB account (e.g., `svc-ingest-writer`, write-only on `skauswatch-logs-*`), managed by operator provisioning, stored as Secret.
- **JetStream credentials:** NATS user/password or token, stored as Secret.
- **NEVER hardcoded:** no secrets in the image, `Dockerfile`, or config files.

### 9c. Rootless Containers & Pod Security

- **Container `USER appuser` (UID 1000)** — no root, no privileged capabilities, exceptions documented.
- **Pod Security Admission (PSA) `restricted` baseline** — enforced via namespace label.
- **Tetragon `TracingPolicy`** — allowlist of expected runtime binaries (the Rust binary, dynamically-linked libraries, system tools if any). Violations logged; enforced (not observe-only).
- **No `hostNetwork`, `hostPID`, `privileged: true`** — all inbound traffic comes through ClusterIP Service.
- **UDP :514 special case:** if operator opts into UDP syslog with `SYSLOG_UDP_ENABLED=true`, that is a deliberate operator choice to accept syslog from a trusted CIDR; it does not require additional capabilities (UDP binding on unprivileged ports >1024, or :514 if `NET_BIND_SERVICE` capability is granted per `devops-containers.md`'s exception process).

### 9d. SPIFFE Identity

The receiver pod reserves **`spiffe://penguintech.io/<env>/svc-ingest-receiver`** and the writer reserves **`spiffe://penguintech.io/<env>/svc-ingest-writer`** (separate identities so writer can be revoked without affecting receiver if needed). Both are auto-enrolled in the SPIRE chart's `autoEnroll.services` list. When accepting mTLS connections, the receiver validates the client's SPIFFE ID against a list of known sources (e.g., `spiffe://penguintech.io/<env>/endpoint-agent`, `spiffe://penguintech.io/<env>/s3scan`, etc.), mapping each to a tenant.

## 10. Feature Flag & Tiering

`skauswatch.log-ingest` (Professional tier, default OFF) — gates the entire ingest service. Inherited from the existing `services/logs` flag (`skauswatch.log-ingest` already declared in `services/manager/src/flags.rs` but unenforced in logs; svc-ingest enforces it from day one).

No per-protocol flags (all four transports ship together) — tiering is a future concern if a specific protocol (e.g., OTLP gRPC) becomes Enterprise-exclusive, but that is not the current plan.

## 11. Observability

### 11a. OTel Logs + Metrics + Traces

Emits via OTLP to `OTEL_EXPORTER_OTLP_ENDPOINT` (env-configurable, never hardcoded). Mandatory signals:

**Logs:**
- INFO on startup (version, config summary, NATS/OpenSearch connections established)
- WARN on token lookup failure, certificate validation rejection, JetStream backpressure
- ERROR on OpenSearch write failure, NATS stream full, persistent connection failures
- DEBUG on per-event validation, parsing results (development/explicit debug mode only)

**Metrics:**
- `svc_ingest_receiver_events_total` (counter, per-transport label)
- `svc_ingest_receiver_parse_duration_ms` (histogram, per-parser label)
- `svc_ingest_receiver_queue_depth` (gauge, current JetStream stream size in bytes/events)
- `svc_ingest_writer_bulk_write_duration_ms` (histogram)
- `svc_ingest_writer_opensearch_errors_total` (counter, per-error-code label)
- `svc_ingest_buffer_full_rejections_total` (counter, per-transport)

**Traces:**
- End-to-end span from ingest (parse start) to OpenSearch index (write end)
- per-event processing: parse, normalize, enqueue, ack
- per-batch: JetStream consume, OpenSearch _bulk request

### 11b. Self-Exclusion

**CRITICAL:** svc-ingest MUST NOT ingest its own telemetry into the lake (infinite loop). OTEL exports go to the central collector; events from the ingest service's own code are filtered out server-side (OTEL sink checks the `service.name` attribute and discards `svc-ingest` internally) or never sent (e.g., configured endpoint is a metrics sink, not the logs ingest lake).

### 11c. Telemetry Gate (Testing)

Per `testing.md` Telemetry Validation: smoke tests assert:
- ≥1 log record received (DEBUG logs don't count; INFO/WARN/ERROR minimum)
- ≥1 metric data point received
- ≥1 span received (if the app makes inter-service calls — in this case, JetStream + OpenSearch reads count)

Denominator reported (e.g., "3 log records, 5 metrics, 2 spans"), never a bare "pass".

## 12. Consolidation Impact (v2.1 Service Consolidation Addendum)

The current `docs/v2-port/v2.1-backlog.md` and any future consolidation document should reflect:

- `svc-ingest` is the **dedicated ingest plane**, absorbing `services/logs`' HTTP `/ingest` surface and monitor's syslog collector.
- `services/logs` refactored to: (a) delegate OCSF normalization to the extracted `skauswatch-ocsf` crate, (b) expose the same `/ingest` HTTP endpoint (delegated to svc-ingest or a shared path, to-be-decided in implementation), (c) become a read-only query surface for backward compatibility if any existing clients directly call logs' routes (unlikely; manager proxies).
- `services/monitor` no longer writes to `aaa-events-*`; collectors push to svc-ingest's `/ingest`. The TAXII IOC matcher reads from the unified lake (`skauswatch-logs-*`). Monitor's own Postgres tables (`endpoint_events`, etc.) remain as fleet-ops storage.

**Net delta from the backlog:** what was described as separate modules (logs ingest, monitor collection, SIEM connectors) is now a single svc-ingest service with two run modes. The backlog's focus on "lake unification" is concretized here as: one ingest service, one OCSF schema, one OpenSearch lake.

## 13. Rollout Phases

| Phase | Ships | Value |
|---|---|---|
| **P1** | Receiver (HTTP/syslog/OTLP) + writer (JetStream→OpenSearch); extracted `skauswatch-ocsf` crate | Unified ingest surface; monitor syslog collector deprecated |
| **P2** | Run-mode separation deployable independently (separate Helm values for receiver/writer); NATS JetStream auth hardening | Scaling flexibility; operational separation |
| **P3** | Monitor collectors fully migrated to use `/ingest` endpoint; `aaa-events-*` backfill Job; `aaa-events-*` indices deprecated | Historic data unified; new events all in one lake |
| **P4** | (Optional) In-memory EventBuffer implementation for testing; additional protocol transports (e.g., generic syslog-forwarded-from-appliance variants, Splunk HEC compatibility) | Easier testing; broader appliance support |

## 14. Testing Matrix

### 14a. Unit Tests (Per-Parser Fixtures)

| Parser | Test vectors | Notes |
|--------|--------------|-------|
| **RFC 3164** | Valid msg, malformed PRI, missing hostname, year-wrap timestamp, multiline msg (dropped), msg with embedded newlines | Reuse v1 `collectors/syslog.py`'s test cases for parity |
| **RFC 5424** | Valid ISO 8601, missing version, invalid severity, SD (structured data) with special chars, empty MESSAGE | RFC 5424 test vectors from IETF 5424 spec examples |
| **OTLP** | Valid LogRecord proto, missing required fields (body, timestamp), attribute types (string/int/bool), resource attributes | Fuzz with opentelemetry-proto test data |
| **OCSF validation** | Valid OCSF doc, extra fields (accepted), missing required (rejected), class_uid mismatch | Validate against OCSF 1.3.0 schema |
| **Generic JSON heuristic** | Heuristic detects class correctly (auth msg vs. file msg vs. network msg), fallback to 2001, timestamp parsing edge cases | Reuse v1 `ocsf.rs`'s detect_* test cases |

### 14b. Integration Tests

**Auth tests:**
- mTLS cert valid → events ingested, tenant stamped from SPIFFE ID
- mTLS cert invalid → connection rejected, 403 error
- mTLS cert + mismatched SPIFFE tenant → 403 forbidden
- Ingest token valid → events ingested, tenant stamped from token lookup
- Ingest token revoked → 401 unauthorized
- Bearer token absent + no mTLS → 401 unauthorized
- UDP packet from trusted CIDR → events ingested, tenant stamped from config
- UDP packet from untrusted CIDR → packet dropped, no error sent

**Durability tests (production-hardening mandatory):**
- **PublishAck synchronous blocking:** Send 10 events via HTTP, mock JetStream to delay PublishAck, verify receiver blocks (waits for ack before returning 2xx). Assert that the receiver does NOT fire-and-forget or return success before JetStream ack arrives.
- **JetStream crash + restart with zero loss and no duplication:** (a) Ingest 100 events into JetStream stream with MsgId dedup enabled; (b) Force-kill JetStream container mid-batch (simulated crash); (c) Restart JetStream container with the same storage volume; (d) Verify all 100 events are in the stream exactly once (no loss, no duplication via MsgId replay). Assert that the receiver's next batch fetch (post-restart) yields no new duplicates.
- OpenSearch down for 10 min → receiver continues accepting events, JetStream buffers; on OpenSearch recovery, buffered events written (no loss)
- JetStream stream full → receiver sends 429 (HTTP) / RESOURCE_EXHAUSTED (gRPC) / RST (TCP); client can retry
- Writer crash mid-batch → events not acked; on restart, JetStream re-delivers same batch (at-least-once, idempotent bulk writes in OpenSearch ensure no duplicates via OpenSearch `_id` dedup or the EventBuffer's MsgId mapping)

**Per-protocol e2e:**
- Syslog UDP: send 100 events, verify all reach OpenSearch
- Syslog TCP: send events while OpenSearch is degraded, verify backpressure and eventual delivery
- Syslog TLS: mTLS handshake + event ingestion
- OTLP gRPC: send `ExportLogsServiceRequest` with 50 LogRecords, verify indexed
- OTLP HTTP: send JSON + protobuf variants, verify parsed correctly
- HTTPS OCSF: send native OCSF doc + generic JSON, verify both indexed

### 14c. Smoke Tests

```bash
# Pre-commit (every commit)
1. Build docker image (Rust release build, ~3 min)
2. Start JetStream + OpenSearch (testcontainers)
3. Send 100 syslog events via UDP to :5140 → verify all reach OpenSearch index
4. Send 10 OTLP LogRecords via gRPC → verify indexed
5. Send 5 OCSF + 5 generic JSON docs via HTTPS → verify all indexed
6. Verify OTel logs/metrics/traces emitted (≥1 record, ≥1 metric, ≥1 span)
7. Cleanup (delete testcontainers)
```

Expected duration: <2 min.

### 14c2. Dependency Pinning (async-nats)

**Mandatory for production security-evidence ingest:**

```toml
# Cargo.toml
[dependencies]
async-nats = { version = "=0.50.0", default-features = false, features = ["jetstream"] }
# Pin to exact version (=, not ~); remove default features (object-store, service, etc. are not needed here)
# Only enable jetstream (and tls, nkeys if required for NATS auth)

# Note: 0.x version scheme is Synadia's intentional versioning.
# 0.50.x is Tier 1 stability, not pre-release — this is the production-grade async NATS client used in Vector.
# Do NOT allow cargo to bump to a newer 0.y.z or 1.x without explicit review and smoke test re-run.
```

**Rationale:** JetStream + PublishAck synchronous blocking + MsgId dedup are load-bearing for evidence data. Uncontrolled dependency updates could introduce breaking changes (e.g., async-nats 0.51+ changes PublishAck semantics, or a transitive dependency adds a GPL license). Exact pinning ensures reproducible deployments and controlled upgrades.

### 14d. Coverage Requirement

90% lines + branches via `cargo llvm-cov`. Dead code (error paths that never fire in tests) is acceptable but must be documented.

## 15. Open Questions & Risks

1. **EventBuffer trait implementation details** — should the NATS JetStream implementation use a durable consumer per writer pod (so replicas don't duplicate-process messages) or a shared consumer (simpler, but requires careful locking)? Recommend durable consumer per pod ID with a lease to prevent rebalancing chaos during pod churn. Open decision pending implementation spike.

2. **UDP trusted CIDR provisioning** — operator configs `SYSLOG_TRUSTED_CIDRS` at deployment time (static). Should this be dynamic (queryable from Vault/manager config API on every packet) for flexibility? Recommend static for P1 (simpler); dynamic as a P2 enhancement if the CIDR list changes frequently in practice.

3. **Syslog tenant ID mapping** — a UDP source CIDR (e.g., `10.0.0.5`) is mapped to a fixed tenant ID at deployment time. What if one syslog forwarder handles events from multiple tenants? Recommend: operator provisions a separate UDP listener per tenant (separate port + CIDR), or uses TCP/TLS with per-message authentication instead. UDP's lack of per-message auth is a fundamental constraint; P1 does not solve this.

4. **OCSF native vs. JSON passthrough validation** — how strict is schema validation for native OCSF docs? Reject on any missing required field, or accept and fill defaults? Recommend: strict validation (reject malformed), log a warning but accept missing optional fields (OCSF is permissive on unknowns, but required fields must be present).

5. **Monitor collector migration timeline** — can collectors be migrated gradually (some use old direct-write, some use new `/ingest` endpoint) or must all migrate at once for coherency? Recommend: gradual, with a final cutover date (e.g., "by end of v2.1") — the unified lake is the end state, but intermediate states are supported for operational flexibility.

6. **DLQ retention & alerting** — how long should events remain in the DLQ before being purged? What alert fires when the DLQ fills? Recommend: 30-day retention (same as the main lake), manual operator intervention to drain (events are precious; auto-delete defeats the purpose). Alert fires on any event landing in the DLQ (not just after a threshold).

7. **Receiver + Writer scaling independently** — do we need a 3rd mode (manager that orchestrates both) or can they share the same Deployment with independent replicas? Recommend: separate Deployments (one for receiver, one for writer) so the operator can scale them independently (e.g., "5 receiver replicas, 2 writer replicas" if ingest is the bottleneck). Helm chart provides both; operator selects which mode to deploy.

8. **OTLP attribute aliasing** — what happens if an OTLP LogRecord includes both `user_id` and `user` attributes with different values? Recommend: log a warning, use `user_id` (explicit OCSF field name takes precedence over generic `user`). Open decision pending community feedback on real-world collisions.

---

## See Also

- `docs/v2-port/siem-module-spec.md` — ingest → SIEM lake (this spec details the ingest + lake-unification sections that SIEM references as P1)
- `docs/v2-port/logs-contract.md` — v1/v2 logs HTTP contract; svc-ingest inherits this for the HTTPS path
- `docs/v2-port/service-auth-model.md` — mTLS, SPIFFE, OIDC scopes; svc-ingest implements the same auth patterns
- `crates/skauswatch-ocsf/` (new) — extracted OCSF normalizer, shared by svc-ingest, logs, and future connectors
- `backend-rust.md` — Rust/Axum/Tonic standards (svc-ingest is all Rust)
- `critical-rules.md` — Dependency Pinning, Observability (OTel), Verification Integrity, Rootless Containers, PII Tokenization
- `security.md` — Tenant Isolation, Service-to-Service Auth, Encryption
