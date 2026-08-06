# Phase 12 Scope — Scanner ASM & Monitor Subsystem Parity

Read-only scoping pass over the two remaining large v1→v2 gaps in the
scan/detect surface: the scanner's Attack-Surface-Management (ASM) pipeline
and the `monitor` service's log-collector / threat-intel / alerting / AI
stack. v1 source recovered via `git show origin/release/v1.0.x:<path>` (the
Python tree was deleted from the working branch; never checked out).
Cross-references `docs/v2-port/v2.1-backlog.md` (§"scanner ASM subsystem",
already tracked at a summary level — this doc drills into what's actually
inside it) and `services/monitor/src/main.rs`'s own "Tracked follow-ups"
module doc (already itemizes the monitor gaps with LOC counts — this doc
verifies those claims against the underlying files and adds the
working-vs-dead-code split and restore plan). Follows the format of
`docs/v2-port/phase12-scope-infra.md`.

## Summary table

| Subsystem | v1 working? | v2 state today | Restore plan | Effort | Deps |
|---|---|---|---|---|---|
| Scanner: ASM pipeline (masscan→banner→screenshot→cert→diff) | **Yes, full** — real subprocess/socket/API code, wired to Celery, proxied through manager, reachable from webui | `services/scanner/src/asm.rs` is a 39-line placeholder struct; `scan.rs` returns `"nuclei/zap/openvas scanning not yet implemented"` for those scan types | Re-architect (not line-port): manager owns `asm_*` tables + publishes to a stream (mirror `s3_scan.rs`/`STREAM_S3_SCAN_TASKS` pattern), scanner worker consumes and runs masscan/banner/screenshot/cert/diff, writes results | **XL** | New scanner binaries (masscan, gowitness/xfreerdp/vncsnapshot) in container image, NET_RAW capability, 7-table migration, manager route rewrite |
| Scanner: manager `asm.rs` proxy | N/A (v1 had a working upstream to proxy to) | Proxies to `http://scanner:5001/api/v1/asm/*` — **scanner has no HTTP server at all** (only a telemetry health router); every call 503s | Same re-architecture as above — this router's proxy shape is itself wrong for v2's stream-worker model, not just missing an upstream | (bundled above) | (bundled above) |
| Scanner: generic vuln-scan jobs/targets/schedules/findings (nuclei/zap/openvas as ad-hoc + scheduled jobs) | **Yes, full** — real `NucleiScanner`/`ZapScanner`/`OpenvasScanner` (subprocess/REST/GMP clients), Celery `execute_scan` + `scheduler_worker.py` (croniter beat) | Not started; `scan.rs` stub covers only the ASM-embedded masscan use of these tools, not standalone scan_jobs | Lower priority than ASM: v1 never exposed this via manager or webui (no proxy route, no frontend reference found) — backend-only surface with no confirmed client | **L** | 4-table migration (`scan_targets/scan_jobs/scan_findings/scan_schedules`), nuclei/zap/openvas binaries+configs, cron scheduling loop |
| Scanner: `scanner:tasks` stream has no producer | N/A (v1 had no stream — used Celery `.delay()`) | Even the **already-ported** YARA/ClamAV path is unreachable end-to-end: zero code anywhere publishes to `STREAM_SCANNER_TASKS` | Manager needs a scan-trigger route that publishes to `scanner:tasks` (today none exists for malware/file scans either) | **S/M** | Blocks all scanner functionality, not just ASM — highest-leverage fix |
| Monitor: log collectors (k8s/lxc/auditd/syslog/journald/file/database, ~6,566 LOC) | **Yes, working** — real subprocess/socket/inotify/file-tail code in all 7, non-trivial (600–1,300 LOC each) | Not ported (documented gap in `main.rs`); event store has no producer | Port collectors as a new binary/set of tasks feeding `EventStore::index` (unimplemented write path already scaffolded) | **XL** | K8s API access, host log mounts, `NET_ADMIN`-free syslog UDP bind, 7 subsystems |
| Monitor: `log_processor.py` + `buffer_manager.py` (~2,562 LOC) | **Yes, working** — real ES/Mongo write pipeline with batching | Only the ES/OpenSearch read+write half is ported (`es.rs`); ingest orchestration (enrich→classify→buffer→flush) not ported | Port as the glue between collectors and `EventStore` | **M** | Needs collectors landed first (nothing to buffer otherwise) |
| Monitor: threat intel — TAXII engine (`taxii_client.py` 2,845 + `stix_parser.py` 1,037 + `indicator_matcher.py` 657 + `threat_database.py` 1,288 LOC) | **Yes, working engine** — real TAXII 2.x polling, circuit breakers, SQLite-backed IOC store/match. **But** ~15 of `main.py`'s REST routes on top of it call methods (`get_iocs_advanced`, `add_ioc`, …) that don't exist anywhere in v1 → 500 always | Not ported. `manager`'s separate `threat_intel.rs` (2,206 lines, IOC CRUD + static feed catalog) is a **different, already-ported subsystem** — do not conflate | Port the engine (feed polling + IOC store + matcher) for real; do **not** restore the ~15 broken REST routes as-is — redesign the API surface against what the engine actually exposes | **XL** | aaa-monitor's TAXII feeds are a separate concern from manager's IOC CRUD; needs its own Postgres/SQLite-equivalent schema |
| Monitor: alerting (`alert_manager.py`, `escalation.py`) | **No — confirmed dead code.** `search_alerts` always returns empty, `get_alert_by_id` always `None`, `start_processing` is an infinite no-op sleep loop, `escalation.handle_status_change` only logs | v2's `alerts.rs` is a faithful, documented port of this non-functional stub | **Not parity work** — nothing to restore. Real alerting is net-new functionality if wanted | N/A (or **L** if building real alerting from scratch) | — |
| Monitor: core analysis (`pattern_detector.py` 28 LOC, `anomaly_detector.py` 31 LOC, `event_classifier.py` 39 LOC, top-level `analysis_engine.py` 73 LOC) | **No — confirmed dead code.** Every one is an `__init__`-only skeleton; `classify_event` always returns `{"category":"unknown","confidence":0.0}`; `AnalysisEngine.__init__` even references an undefined `ai_provider` global (latent `NameError`, silently swallowed by a blanket `except Exception` in `main.py` startup) | v2's `dashboard.rs` faithfully ports the always-zero metrics | **Not parity work** — nothing real to restore | N/A | — |
| Monitor: AI integration (`ai_integration/*`, ~3,957 LOC: real OpenAI/Anthropic/Ollama clients + `ai_integration/analysis_engine.py` 949 LOC) | **Yes, working code**, but inert without operator-supplied API keys (each provider `enabled=False` by default; needs config to do anything) | Not ported; `/ai/*` routes not present | Port only if AI-assisted analysis is still wanted — real clients, not stubs, but never exercised without secrets configured | **L** | Requires OpenAI/Anthropic/Ollama credentials to be meaningful; depends on collectors+log_processor for real input |

---

## 1. Scanner ASM subsystem

### v1 behavior (confirmed working, not aspirational)

Pipeline (`services/worker-scanner/scanners/asm_scanner.py::ASMScanner`):
`MasscanScanner` (real `masscan` subprocess, port discovery) →
`grab_banners_batch` (async banner grab) → `ScreenshotScanner`
(gowitness for HTTP/HTTPS, xfreerdp for RDP, vncsnapshot for VNC, uploads to
S3) → `inspect_cert` (TLS cert parsing on 443/465/636/993/995/8443/9443,
expiry findings) → diff against the previous completed scan for the same
target (new/removed services, expired certs).

Triggered via `POST /scans` → DB row in `asm_scans` (mode
internal/external/both, `ports_config` json) → Celery
`execute_asm_scan.delay(scan_id)` (`services/worker-scanner/workers/
scan_worker.py`) → persists into `asm_hosts`, `asm_services`,
`asm_screenshots`, `asm_certs`, `asm_diffs`, plus a settings table
`asm_settings` (extra ports, masscan rate). Full REST surface
(`services/worker-scanner/api/routes/asm.py`, 10 endpoints: scans CRUD,
hosts, screenshots, certs, diff, report, port settings GET/PUT) is proxied
verbatim by `services/manager/api/v1/asm.py` — this is the one
customer-facing scan surface (reachable from the webui through manager).

A separate, parallel Celery task `execute_scan` (same file) drives
`NucleiScanner`/`ZapScanner`/`OpenvasScanner` — all three are real,
working clients (nuclei: subprocess + JSON parse; ZAP: REST API polling
client; OpenVAS: GMP protocol client with real scan-config UUIDs) — against
`scan_targets`/`scan_jobs`/`scan_findings`, on a cron schedule via
`scheduler_worker.py` (`croniter`, Celery Beat). **This half has no manager
proxy and no webui reference anywhere in v1** (`git grep` across
`services/webui/src` found zero hits) — it is backend-only, code-complete,
but with no confirmed v1 client. Schema: `scan_targets`, `scan_jobs`,
`scan_findings`, `scan_schedules` (4 tables) + the 7 ASM tables above = 11
tables total in v1's alembic history vs v2's single `scanner_scan_results`.

### v2 state

`services/scanner/src/asm.rs` is a 39-line placeholder (`AsmOrchestrator`
with no fields or methods beyond `new()`). `scan.rs::execute_scan` returns
a scan-level error string for `"nuclei" | "zap" | "openvas"`
("not yet implemented"). `services/manager/src/routes/asm.rs` (844 lines,
well-tested) is a faithful **shape** port of v1's proxy — but it points at
`SCANNER_URL` (default `http://scanner:5001`), and `services/scanner` never
binds an HTTP server for anything but the shared telemetry health router
(`skauswatch_telemetry::health_router`). Every ASM call from the webui
today fails with a 503 ("Cannot connect to scanner").

**Architectural finding, not just a missing feature**: v1's model was
"REST API + Celery" (manager proxies HTTP to worker-scanner's own Flask
app). v2's established worker pattern (confirmed against
`services/manager/src/routes/s3_scan.rs`, which owns its Postgres tables
directly and publishes `STREAM_S3_SCAN_TASKS` for `worker-s3` to consume)
is "manager owns tables + Redis Streams to a stateless worker" — `scanner`
is already built this way for YARA/ClamAV (`services/scanner/src/handler.rs`
consumes `scanner:tasks`, writes `scanner_scan_results` directly). Porting
ASM by writing an HTTP server into `scanner` and keeping `manager/asm.rs`
as an HTTP proxy would be replicating the *wrong* v1 shape. The consistent
restore path is: manager gets `asm_*` tables (mirroring the 7-table v1
schema, tenant-scoped per `docs/v2-port/tenancy-model.md`), `POST /asm/scans`
inserts a row and publishes to `scanner:tasks` (or a new `asm:tasks` stream)
with `scan_type=asm`, scanner's `asm.rs` gets the real masscan→banner→
screenshot→cert→diff pipeline and writes results back (either directly, or
via a results stream scanner already has for yara/clamav), and manager's
GET routes query Postgres directly instead of proxying HTTP — same
division of labor as `s3_scan.rs`/`worker-s3`.

**Precondition, independent of ASM**: `scanner:tasks` currently has **zero
publishers** anywhere in the codebase — even the YARA/ClamAV path that's
genuinely fully ported (`scan.rs`, EICAR-tested) is unreachable from any
client today because nothing ever calls `StreamProducer::publish(
STREAM_SCANNER_TASKS, ...)`. This is a smaller, higher-leverage fix that
unblocks more than just ASM and should land first or alongside it.

**Effort**: XL for the full ASM pipeline (external binaries: masscan
needs `NET_RAW`; gowitness/xfreerdp/vncsnapshot need to be in the
container image; S3 presigned URLs for screenshots/reports already exist
as a pattern via `skauswatch-s3`/vault crates elsewhere in the workspace).
L for the standalone nuclei/zap/openvas job surface, and it's lower
priority given no confirmed v1 caller. S/M for the stream-producer fix.

---

## 2. Monitor — log collectors, threat intel, alerting, AI

### Log collectors — confirmed working in v1

All 7 (`kubernetes_collector.py` 1,206 LOC, `auditd_collector.py` 1,192,
`lxc_collector.py` 1,308, `syslog_collector.py` 849, `journald_collector.py`
609, `file_collector.py` 618, `database_collector.py` 565 — 6,566 total,
matching `main.rs`'s own count) contain real OS-integration code, not
scaffolding: `auditd_collector` shells `tail -n 100 /var/log/audit/
audit.log` / `journalctl -n 100 --no-pager -o json` and opens a UDP socket
for live audit events; `syslog_collector` binds a real UDP socket;
`lxc_collector` shells `journalctl` and `subprocess`; `file_collector` uses
`aiofiles` + inotify. These feed `LogProcessor.process_event()`
(`log_processor.py`, 1,847 LOC) which enriches (classify, threat-match,
geolocate), batches via `BufferManager` (715 LOC), and flushes to
Elasticsearch/MongoDB — the exact write path `services/monitor/src/es.rs`
already ports on the read+write-method side. **These are the only event
producers in v1 or v2** — without them, v2's `GET /events/stream` (real
infra, per `routes/events.rs`) has nothing to stream and the ES-backed
store starts and stays empty.

### Threat intelligence — mixed picture, two unrelated subsystems

**aaa-monitor's TAXII engine** (`threat_intel/taxii_client.py` 2,845 LOC,
`stix_parser.py` 1,037, `indicator_matcher.py` 657, `threat_database.py`
1,288 — 5,827 total): the *engine* is real, working code — TAXII 2.x
server/collection discovery, OAuth2 auth, circuit breakers, per-feed
quality scoring, an aiosqlite-backed `ThreatDatabase` with working
`store_indicator`/`search_indicators`/`get_iocs`/`record_match`/
`get_feed_status`. `TAXIIConfig.enabled=True` by default (though the feed
list is empty until an operator configures one). **But** the ~15 REST
routes in `main.py` sitting on top of it call methods that exist nowhere
in the codebase (`get_iocs_advanced`, `add_ioc`, `get_ioc_by_id`,
`search_iocs_advanced`, `bulk_add_iocs`, `get_matches_by_event`,
`get_feed_status_enhanced`, `add_feed`, `get_feed_by_id`, `update_feed`,
`get_health_status` — zero matches anywhere, verified by full-tree grep) —
every one of those routes 500s unconditionally in v1. This is the same
"engine works, API layer on top was never actually run against it" pattern
as the ASM Celery-vs-REST split, and matches `main.rs`'s own note verbatim.

**`services/manager`'s threat intel is a completely different, already-
ported subsystem** — `threat_intel.rs` (2,206 lines) is IOC CRUD +
bulk-upsert + search + a *static* feed catalog, backed by Postgres
`threat_indicators`, faithfully matching v1's `services/manager/api/v1/
threat_intel.py` (whose `GET /feeds` also just returns a hardcoded list —
confirmed correct parity, not a gap). **Adjacent v1 dead code, no action
needed**: `services/manager/services/threat_intel/{feeds.py,sources/
{otx,virustotal,dns_blacklist,ip_blacklist,openioc,yara_rules,
stix_taxii}.py}` (~1,700 LOC of real external-API client code — OTX,
VirusTotal, etc.) implements a `FeedAggregator` that is imported by
`__init__.py` but **never instantiated anywhere** in v1 — orphaned, not a
regression to restore.

### Alerting and core analysis — confirmed dead code, do not restore

`alert_manager.py`: `search_alerts` always returns `AlertSearchResponse(
alerts=[], total=0, ...)`; `get_alert_by_id` always returns `None`;
`start_processing` is `while True: await asyncio.sleep(1)` — no queue, no
storage, no delivery of any kind. `escalation.py::handle_status_change`
only logs. `pattern_detector.py`/`anomaly_detector.py`/`event_classifier.py`
are each `__init__`-only skeletons (28/31/39 lines); `classify_event`
hardcodes `{"category": "unknown", "confidence": 0.0}`. Top-level
`analysis_engine.py` (73 lines, distinct from the real
`ai_integration/analysis_engine.py`) wires these together and its own
constructor call in `main.py` passes an **undefined name `ai_provider`**
(should be `ai_provider_manager`) — a latent `NameError` on every startup,
silently caught by `main.py`'s blanket `except Exception: logger.warning
(...)`. v2's `alerts.rs` and `dashboard.rs` already document and faithfully
preserve this non-functional behavior. **This confirms the task's
framing**: restoring "parity" here would mean re-implementing something
that never worked — out of scope.

### AI integration — real but inert without configuration

`ai_integration/openai_client.py` (432 LOC), `anthropic_client.py` (471),
`ollama_client.py` (531) are genuine API clients (`AsyncOpenAI`,
provider-specific error handling for rate limits/auth/timeouts).
`ai_integration/analysis_engine.py` (949 LOC — not to be confused with the
dead top-level `analysis_engine.py`) is real orchestration code. All three
provider configs default `enabled=False` (need an API key); `AIConfig.
enabled=True` overall but `default_provider="openai"`, which is itself
disabled by default — so in an unconfigured deployment this subsystem does
literally nothing, distinct from the alerting stubs which do nothing *even
when configured*. Only worth porting if AI-assisted analysis is still a
wanted feature, and only after collectors + log_processor exist to feed it
real events.

---

## Biggest risks

- **Manager's `asm.rs` is proxying to an endpoint that structurally cannot
  exist in v2's architecture** — the fix isn't "add the missing route to
  scanner," it's rearchitecting from HTTP-proxy to stream-publish +
  direct-Postgres-read, matching `s3_scan.rs`. Porting ASM without first
  making this call risks building the wrong shape twice.
- **`scanner:tasks` has no producer at all**, so even declaring the
  YARA/ClamAV path "fully ported" is aspirational from an end-to-end
  reachability standpoint — flag this as a P0 alongside or ahead of ASM.
- **Threat intel is two unrelated subsystems with the same name** — a
  restore effort that conflates aaa-monitor's TAXII engine with manager's
  already-complete `threat_intel.rs` risks either duplicating working code
  or scoping the wrong one. Confirm which surface a "threat intel" ask is
  actually about before estimating.
- **Monitor's dead-code stubs (alerting, pattern/anomaly/classification)
  should not be restored as "parity"** — v1 never had working versions;
  treating them as regressions would mean building new functionality under
  the guise of a port, and the `ai_provider` NameError shows this code path
  never even ran cleanly in v1.
