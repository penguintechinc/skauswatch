# SIEM + AI Investigator/Auditor — cloud-agnostic security-event platform

**Status:** Draft design spec · **Target:** v2.1+ (this module *completes* an already-partially-shipped SIEM; do not read "net-new" below as "nothing exists") · **Flag:** `skauswatch.siem` (already exists, `CORE_FLAGS`, default OFF) + new granular sub-flags (§11)

A cloud-agnostic security-event platform on **OpenSearch**, with an **AI Investigator** (reactive incident triage) and an **AI Auditor** (proactive continuous reasoning), running two ways simultaneously: **standalone** (own OpenSearch lake, direct HTTP ingest, AI reasoning over that lake — this half already ships) and **federated** (pull external providers — AWS/Azure/GCP/Datadog/SigNoz/external OpenSearch-or-Elastic — as read-only sources, normalize to OCSF, land in the same lake). Sibling to CodeScan Sentinel (code arm), DepGate (dependency-ingress arm), and EDR (endpoint arm) — this module is the **event/telemetry + detection + investigation arm**, and the aggregation point where every other module's findings converge for AI-assisted cross-signal reasoning.

## 1. Premise — one lake, two ingestion directions, two AI roles

```
DIRECT PUSH (have)          PULL CONNECTORS (net-new)         EDR BRIDGE (net-new, reconciled w/ EDR spec)
app/service → /ingest       AWS/Azure/GCP/Datadog/SigNoz/      manager → Redis Stream → forwarder
(services/logs, OCSF)       external-ES/OpenSearch pollers     → /ingest (X-Log-Source: endpoint-agent-*)
        │                            │                                  │
        └────────────────────────────┼──────────────────────────────────┘
                                      ▼
                    OpenSearch lake (skauswatch-logs-* daily index, OCSF documents)
                                      │
                     ┌────────────────┴────────────────┐
                     ▼                                  ▼
        Sigma correlation engine (net-new)      WaddleAI (tools-first → AI reasons)
                     │                                  │
                     ▼                          ┌────────┴────────┐
            siem_correlation_matches             ▼                 ▼
                     │              AI Investigator (reactive)  AI Auditor (proactive)
                     └──────────────►  incident + entity graph   continuous lake reasoning
                                        + timeline (Detective-    → siem_audit_findings
                                        style)
```

**Non-negotiable licensing constraint:** the STORE is **OpenSearch (Apache-2.0)**, never Elasticsearch (SSPL — forbidden as a shipped/deployed dependency, per `security.md`/`general.md` Supply Chain rules). Reading FROM a customer's external Elastic cluster **as a pull-connector source** is fine — client-side REST access to a customer-controlled system is not "shipping" Elastic, and the wire protocol is compatible enough that the same REST-client code already in this repo works against either backend. This distinction is currently blurred in code (§4) and must be made structurally explicit, not just documented.

**AI split (WaddleAI, tools-first → AI-reasons — same pattern already proven in Sentinel, §8):**
- **AI Investigator** — reactive. Given an incident (a correlation match, an alert, a manual trigger), builds an entity graph + timeline from the OCSF lake (Detective-style "what else did this IP/user/host touch").
- **AI Auditor** — proactive. Runs continuously/on-schedule over the lake, reasoning across everything ingested (own events + connector-pulled provider data + other modules' findings) to surface things no single deterministic rule would catch.
- Both degrade gracefully when WaddleAI is unreachable — deterministic detection (Sigma rules, IOC matching) never depends on AI availability; only the reasoning/narrative/graph-building layer does.

## 2. Positioning vs SigNoz — security vs observability, not two of the same thing

SigNoz is the platform's **observability** product — operational logs/metrics/traces (request latency, error rates, resource utilization, distributed tracing). That's a different lake, a different consumer (SREs/on-call, not security analysts), and a different question ("is the system healthy" vs "is the system under attack" / "did something bad happen"). SIEM does not re-implement observability, and observability data is not blindly duplicated into the security lake.

- **SIEM owns:** security telemetry (auth events, network/file/process activity, cloud-provider audit trails, IDS/malware verdicts, other modules' findings) + detection (Sigma/correlation/IOC matching) + investigation (AI Investigator/Auditor).
- **SigNoz owns:** ops logs/metrics/traces — stays SigNoz's problem, not rebuilt here.
- **The boundary is a read, not a merge:** SigNoz is one of the pull-connector sources (§6, P3) — SIEM reads *security-relevant* signals out of SigNoz (anomalous error-rate spikes correlated with an auth event, a trace showing an exploited endpoint) as OCSF-normalized events, the same as any other external provider. It never becomes SigNoz's storage backend or duplicates its full telemetry volume.
- No SigNoz integration exists in this repo today (grep-verified) — this is a forward-looking connector, not a retrofit of something already wired.

## 3. Separate module, own coordinator — suite boundaries

Mirrors the Sentinel/DepGate/EDR precedent: security capability areas get their own module with their own coordinator, reusing shared platform primitives rather than forking them.

| | Sentinel | DepGate | EDR | **SIEM** |
|---|---|---|---|---|
| Watches | code you have | deps entering the env | hosts already running | **events already happening, everywhere** |
| Coordinator | `worker-codescan` (worker only; `codescan-backend` fronts the API) | `services/depgate` (full standalone service) | `services/endpoint-agent` (client) + manager routes | **`services/siem`** (API/connector-config/findings surface, mirrors `codescan-backend`) + **`worker-siem`** (async connector-pull + correlation engine, mirrors `worker-codescan`) |
| AI | WaddleAI, tools-first triage | WaddleAI (optional, Enterprise) | — (not yet AI-assisted) | **WaddleAI, two roles (§8)** |
| Feeds SIEM? | via findings (§9) | via findings (§9) | **primary feed** (§5) | is the SIEM |

**What already exists and is reused, not rebuilt:**
- `services/logs` — the OCSF-normalizing HTTP ingest pipeline + OpenSearch bulk writer + ISM lifecycle policy. This *is* the platform's SIEM ingest engine already. `services/siem`/`worker-siem` are additive on top of it, not a replacement.
- `services/manager/src/routes/siem.rs` — the existing gateway (`/siem/health`, `/siem/ingest` proxy, `/siem/search`, `/siem/stats`, `/siem/config`), already gated on `skauswatch.siem`. This stays the client-facing surface; `services/siem` is a new backend service the manager can proxy to for connector config / correlation rules / AI investigation triggers, the same relationship `codescan-backend` has to the manager's `/api/v1/codescan/*` router.
- `services/monitor` — collectors (auditd/file/journald/syslog/kubernetes/lxc/database), TAXII/STIX threat-intel IOC matching. Reused as **producers into the unified lake** (§4), not replaced; the TAXII engine (`threat_intel/matcher.rs`) is real, working IOC-vs-event matching that the correlation engine (§7) builds on rather than duplicates.
- `skauswatch-ai` (WaddleAI `CompletionProvider`), `skauswatch-streams` (Redis Stream job model), `skauswatch-identity` (SPIFFE), `skauswatch-scan-core` (shared malware scan primitives, relevant if a connector or correlation rule needs to re-verify a file hash) — all reused as-is per house `penguin-libs`-first convention (no local shared/ forks).

## 4. Current state vs net-new — the fragmentation this spec must fix

**This is not a greenfield build.** A real, tested, house-standard SIEM ingest pipeline already ships. What's missing is connectors, detection beyond IOC matching, AI reasoning, and — most urgently — **the platform currently has two disconnected event lakes wearing one name.**

| Capability | Today | Gap |
|---|---|---|
| **OCSF-normalizing HTTP ingest** | ✅ `services/logs` (`ingest.rs`/`ocsf.rs`/`opensearch.rs`) — `POST /ingest`, tenant-JWT + `skauswatch.log-ingest` flag gated, bulk-writes OCSF docs to `skauswatch-logs-{date}`, ISM lifecycle (30d hot → warm → delete at retention) | None for the direct-push path itself — production-hardened, byte-for-byte parity tested (`docs/v2-port/logs-contract.md`) |
| **Manager SIEM gateway** | ✅ `services/manager/src/routes/siem.rs` — `/siem/health` (public), `/siem/ingest` (auth-forwarding proxy to `services/logs`), `/siem/search`/`/siem/stats` (query `skauswatch-logs-*`, i.e. the OCSF lake), `/siem/config`. Gated `skauswatch.siem` | Read surface only queries **one** of the two lakes (see fragmentation below); no connector/correlation/AI endpoints yet |
| **A second, disconnected event lake** | `services/monitor`'s `es.rs::ElasticsearchStore` writes/reads a **separate** index pattern (`aaa-events-*`, v1 default) with a **separate schema** (`BaseEvent` — `source`/`event_type`/`severity` as its own enums, not OCSF `class_uid`/`severity_id`). Its 7 log collectors (auditd/file/journald/syslog/kubernetes/lxc/database) and its TAXII/STIX IOC matcher (`threat_intel/matcher.rs`) all write/read *this* lake — never `skauswatch-logs-*` | **P1-priority fix.** Two lakes, two schemas, two query surfaces (`manager::siem::search_logs` vs `monitor`'s own `/events` route), zero cross-lake correlation possible today. An analyst asking "did this IOC match also show up in a CloudTrail-sourced event" gets a wrong answer split across two systems that don't know about each other |
| **Elastic/OpenSearch naming ambiguity** | `services/monitor/Cargo.toml`'s crate description literally reads *"REST event/alert API over Elasticsearch/OpenSearch + MongoDB"*; its config/struct names (`config.elasticsearch`, `ElasticsearchStore`) are generic REST-wire-protocol names that happen to work against either backend (`state.rs`'s own comment: *"OpenSearch preferred… MongoDB fallback dropped in v2 — MongoDB's server is SSPL, OpenSearch was already preferred"*) | **Must become structurally explicit, not just documented**: monitor's own event store must point at OpenSearch only (never a customer/self-hosted Elastic cluster) as the platform's store; an Elastic *cluster* is admissible **only** as a §6 pull-connector source (client-side read, customer's system, never this platform's deployed backend). Rename/re-scope in the P1 unification work (§12) so the Cargo.toml description and the config surface stop implying Elastic is a supported deployment target for the store itself |
| **IOC matching** | ✅ real, working — `monitor/threat_intel`'s TAXII 2.x poller + STIX parser + exact `(kind, value)` matcher against extracted event candidates (IP/domain/username) | Runs only against `aaa-events-*` today (the fragmentation above); needs to run against the unified OCSF lake once unified (§12 P1) |
| **Detection beyond IOC matching** | ❌ none | Sigma-compatible rules engine + multi-event correlation — §7, net-new |
| **Connectors (pull sources)** | ❌ none | AWS/Azure/GCP/DigitalOcean/Datadog/SigNoz/external-OpenSearch-or-Elastic-read — §6, net-new |
| **AI Investigator/Auditor** | ❌ none (WaddleAI provider abstraction exists in `skauswatch-ai`, proven pattern in Sentinel's `worker-codescan/triage.rs`, but nothing SIEM-side calls it) | §8, net-new |
| **EDR bridge** | ❌ endpoint events terminate in manager's own Postgres (`endpoint_events`); never reach the OCSF lake. `skauswatch-streams::STREAM_ENDPOINT_EVENTS` (`endpoint:events`) is **already reserved and already produced** by `manager/src/routes/endpoint.rs` — but today it carries only a per-batch `{agent_id, stored_count, timestamp}` **summary**, not the actual events, and **has zero consumers**. Don't assume it's ready to carry full event payloads as-is | §5, net-new — reconciled with the EDR spec's own §3/§7 design |

**Reuse-vs-build summary:** the direct-push ingest engine, the OCSF normalizer, the manager gateway shell, one working collector fleet, and one working IOC matcher all exist. What's net-new: lake unification, every pull connector, the correlation engine, both AI roles, and the EDR bridge.

## 5. Ingest architecture — three modes

### 5a. Direct push (have)
`services/logs` `POST /ingest` (§4) — any service or agent that can reach it and hold a tenant-JWT can push OCSF-normalizable records today. This is the substrate everything else in this section builds on top of; no changes required to accept it.

### 5b. EDR bridge (net-new — reconciles with `edr-module-spec.md` §3/§7)
The EDR spec's own design (independently derived from this same `services/logs` contract, since this SIEM spec didn't exist yet when it was written) is **adopted as-is**, with one correction from the recon above:

1. Agent → manager: unchanged (`POST /api/v1/endpoint/events`, HMAC/JWT + resolved tenant → `endpoint_events` Postgres, fleet-ops system of record).
2. Manager, same write path, enqueues onto a Redis Stream carrying `{tenant_id, agent_id, event_type, severity, details}` — **do not silently repurpose `STREAM_ENDPOINT_EVENTS` for this without confirming intent**: today it carries only a summary and has no consumer, so widening its payload is a compatible change *in isolation*, but a second, purpose-named stream (e.g. `endpoint:events:siem-bridge`, following the existing `{service}:{queue}` convention in `skauswatch-streams`) is the safer default unless the summary stream was always meant to grow into this — flagged as an open decision (§14).
3. `worker-siem` (not "a small worker or the manager itself" as the EDR spec left open — this SIEM spec's coordinator is the natural owner) drains the stream and calls `services/logs` `POST /ingest` with `X-Log-Source: endpoint-agent-{event_type}`.
4. `services/logs`'s existing `detect_class` already routes `-network`→4001 and `-file`→4003 correctly with zero changes; process events fall through to the generic `2001 security_finding` bucket — P1-stretch: add a real OCSF process-activity class rather than long-term overloading the generic bucket (same recommendation the EDR spec made).
5. Severity mapping needs zero code — `detect_severity`'s exact string set (`critical`/`high`/`medium`/`low`/`info`) already matches the agent's `Severity::as_str()`.
6. At-least-once delivery, retry/backoff, bounded dead-letter — a forward failure must be observable (Postgres stays authoritative), never silently swallowed, per `critical-rules.md` Verification Integrity.

### 5c. Pull connectors (net-new — §6)
Scheduled polling of external provider APIs, each normalized by a provider-specific adapter into OCSF, landing in the same `skauswatch-logs-*` lake via the same `services/logs` `/ingest` path (connectors are just another authenticated caller of the existing ingest surface — no second write path into OpenSearch).

## 6. Connector registry — pluggable, per-provider adapters (mirrors Sentinel's scanner-tool registry / DepGate's ecosystem front-ends)

Same shape as Sentinel §3 and DepGate §4: a registry of provider adapters, each independently toggled (§11), each responsible only for **provider schema → OCSF**, never touching OpenSearch or tenancy logic directly — that stays centralized in `services/logs`.

```
worker-siem scheduler (mirrors worker-codescan::scheduler + lease.rs)
  │  per-tenant siem_connectors row due for poll (interval elapsed / never polled)
  │  Valkey lease (per-connector, prevents double-poll across replicas — same pattern as codescan's per-repo lease)
  ▼
connector adapter (provider API call, credentials resolved from Vault/IceBox — never inline)
  │  raw provider event(s)
  ▼
provider → OCSF mapping (adapter-owned; e.g. CloudTrail eventName/eventSource → OCSF class/activity)
  │
  ▼
services/logs POST /ingest  (X-Log-Source: connector-{provider}, tenant stamped from siem_connectors.tenant_id)
```

| Connector | Provider surface | Mode | Phase |
|---|---|---|---|
| AWS CloudTrail | Management/data-event API or S3-delivered logs | Pull | P1 |
| AWS GuardDuty | Findings API | Pull | P1 |
| AWS Security Hub | Findings API (aggregates GuardDuty + other AWS security services) | Pull | P2 |
| AWS CloudWatch (Logs/Metrics-as-events) | Logs API | Pull | P2 |
| Datadog | Logs/Events API | Pull | P3 |
| SigNoz | Logs/traces API (security-relevant subset only, §2) | Pull | P3 |
| External OpenSearch or Elasticsearch (customer-hosted) | `_search` REST (read-only) | Pull | P3 |
| Azure Monitor / Activity Log | Azure Monitor REST API | Pull | P4 |
| Azure Defender (Microsoft Defender for Cloud) | Defender REST API | Pull | P4 |
| GCP Cloud Logging | Cloud Logging API | Pull | P4 |
| GCP Security Command Center | SCC API | Pull | P4 |
| DigitalOcean | Monitoring/audit API (narrower surface than the hyperscalers) | Pull | P4 |

**Credential handling (per connector):** read-only API credentials only, stored in Vault/IceBox (same pattern as Sentinel's git creds and DepGate's upstream registry creds — `docs/v2-port/v2.1-codescan-sentinel.md` §2, `v2.1-depgate.md` §4), never inline in `siem_connectors` config, never logged. A connector adapter that can *write* to the source provider is out of scope by design — SIEM reads, it does not manage cloud posture (that's CSPM's job — §9).

**The Elastic-source special case:** the "external OpenSearch or Elastic" connector is the one place this platform's code legitimately talks to an Elasticsearch cluster — and only as a read-only client against a customer-owned, customer-hosted system. This is exactly the "driver crate can be OSI even if the server isn't" principle (`license-safe-dependencies` house convention) — the REST client code is protocol-neutral, the licensing constraint is about what SkausWatch *ships and runs as its own store*, never about what it's permitted to read from.

## 7. Detection & correlation — Sigma-compatible rules engine (net-new)

Beyond `monitor`'s existing IOC matching (real, reused — §4), the lake needs rule-based and multi-event detection:

- **Sigma-compatible rule engine**: ingest [Sigma](https://github.com/SigmaHQ/sigma) YAML rules (an open, vendor-neutral detection-rule format the security community already publishes against), translate to OpenSearch query DSL, evaluate against incoming/recent OCSF documents. Build-vs-adapt an existing OSS Sigma-to-OpenSearch converter is an open decision (§14) — house convention (Sentinel §3, DepGate §5) strongly favors adopting proven OSS over hand-rolling a rule DSL from scratch, provided license is OSI/non-restrictive.
- **Multi-event correlation**: rules that fire on a *pattern across events* within a time window (e.g. "failed auth ×5 from one IP, then a success, then an outbound connection to a rare destination, within 10 minutes") — not expressible as a single-document Sigma match. This is the genuinely new detection primitive this module adds; Sigma rules alone only match single events.
- **Output**: `siem_correlation_matches` rows (§10) — deterministic, auditable, tool-is-ground-truth exactly like Sentinel's tool-hit-is-ground-truth principle (§1 of the Sentinel spec) — the AI Investigator narrates/expands a match, it never originates one.
- **Threat-intel integration**: the unified matcher (post-lake-unification, §4/§12) runs both IOC lookups (existing TAXII engine) and Sigma/correlation rules over the same OCSF stream — one detection pipeline, not two.

## 8. AI layer — Investigator (reactive) + Auditor (proactive), via WaddleAI

Same tools-first → AI-reasons contract already proven in Sentinel (`docs/v2-port/v2.1-codescan-sentinel.md` §4, implemented in `worker-codescan/src/triage.rs` against `skauswatch-ai::waddleai::WaddleAiProvider`): deterministic detection (Sigma/correlation/IOC) is ground truth; the LLM never does raw detection, it reasons on top of what the deterministic layer already found (plus ad-hoc lake queries it can issue as tools).

| Concern | Owner |
|---|---|
| Model hosting/routing (bulk/reason/hard tiers) | WaddleAI |
| Guardrails (ShieldGemma + prompt-injection defense on untrusted event content — event `message`/`raw_data` fields can contain attacker-controlled strings) | WaddleAI |
| Prompt construction — event/log content as **data, never instructions**, same `<untrusted_repo_content>`-style wrapping pattern `triage.rs` already uses | SIEM |
| Strict output schema (structured verdict/graph objects, not free-form prose/actions) | SIEM |
| Detection = ground truth; AI can annotate/narrate, never erase a Sigma/correlation/IOC match | SIEM |
| Human-gate on any action beyond read/annotate (this module has no auto-response — that's EDR's P3 concern, not SIEM's) | SIEM |

**AI Investigator (reactive):**
- Trigger: a `siem_correlation_matches` row, a manually-flagged event, or an operator request.
- Behavior: given a seed entity (IP/user/host/hash) and a time window, issues bounded OpenSearch queries (as tool calls) to pull related events across every source (own ingest, EDR-bridged, connector-pulled, other modules' findings), builds an entity graph (who/what touched what) and a timeline, and produces a narrative summary — a Detective-style "here's what happened" writeup, stored as a `siem_incidents` row.
- Never auto-remediates; it hands an analyst (or, cross-module, EDR's P3 response layer under its own separate approval gate) a structured incident, not an action.

**AI Auditor (proactive):**
- Trigger: scheduled (e.g. daily) sweep, or continuous low-rate background reasoning over new lake content.
- Behavior: reasons across the accumulated lake — patterns a single Sigma rule wouldn't catch (slow drift, cross-source correlation a human wouldn't think to write a rule for), and surfaces candidate findings for human review.
- Output: `siem_audit_findings` rows — same ground-truth-preserving shape as Sentinel's `ai_verdict` columns (additive annotation, never a destructive overwrite).

**Graceful degradation (mandatory, both roles):** WaddleAI unreachable/erroring → the specific investigation/audit run logs once and is skipped; Sigma/correlation/IOC detection continues unaffected; no incident/finding is ever fabricated from a failed AI call. Matches `triage.rs`'s existing "any transport/provider/schema failure returns `None`, caller continues with the deterministic verdict" contract exactly.

## 9. Suite integration — the cross-module hub

SIEM is where every other module's output becomes queryable, correlatable OCSF data, and where the AI reasons across all of it together — not a fifth independent module, but the aggregation point the others were always going to need.

| Source | What lands in the lake | Mechanism |
|---|---|---|
| CSPM (posture) | posture *findings* (misconfigurations, drift) — not raw cloud-provider events, that's the connectors' job (§6) | CSPM findings pushed to `services/logs` `/ingest`, `X-Log-Source: cspm-finding` |
| Sentinel (code) | SCA/CVE/SAST/secret findings | Same pattern, `X-Log-Source: codescan-finding` |
| DepGate (dependency ingress) | malware/quarantine verdicts | Same pattern, `X-Log-Source: depgate-verdict` |
| EDR (endpoint) | process/file/network telemetry | §5b bridge |
| External (GuardDuty/Security Hub/Defender/SCC) | provider-native findings, already a *finding* not a raw event | §6 connectors, normalized like everything else |

**Boundary vs CSPM, stated precisely (per this spec's brief — no CSPM spec exists yet to reconcile against, per the EDR spec's own note that it didn't exist either):** CSPM **computes** posture — it queries cloud-provider APIs, evaluates configuration against policy, and produces a posture score/drift finding. SIEM **ingests** events and other modules' findings, including CSPM's — it does not re-implement posture scanning, does not call cloud config APIs to compute compliance itself, and does not own remediation. The relationship is the same shape as CSPM→SIEM that GuardDuty/Security-Hub→SIEM already has via §6: CSPM produces, SIEM ingests + correlates + lets the AI reason across it alongside everything else.

**Unified exec report:** same aggregator gap the EDR spec already flagged (§8 there) — a cross-module executive report depending on findings from CSPM/Sentinel/DepGate/EDR/SIEM all landing somewhere central. This spec doesn't build that aggregator either; it strengthens the case for building it once given SIEM is now the natural landing zone for exactly the data that report would read.

## 10. Data model (new tables, `siem_` prefix — mirrors Sentinel's `codescan_*`/DepGate's `depgate_*` convention)

- **`siem_connectors`** — per-tenant connector config: `id, tenant_id, connector_type (cloudtrail|guardduty|securityhub|cloudwatch|datadog|signoz|external-opensearch|external-elastic|azure-monitor|azure-defender|gcp-logging|gcp-scc|digitalocean), credential_ref (Vault/IceBox pointer, never a raw secret), enabled, poll_interval_minutes, last_poll_at, last_poll_status` — mirrors `codescan_repo_configs`' `polling_*` columns, wired from day one this time (not left dead like that table was pre-Sentinel).
- **`siem_connector_runs`** — poll history/audit, mirrors `codescan_scan_runs`.
- **`siem_correlation_rules`** — `id, tenant_id, name, sigma_yaml, enabled, severity, mitre_attack_tags, created_at, updated_at`.
- **`siem_correlation_matches`** — `id, rule_id, tenant_id, matched_doc_ids[], window_start, window_end, severity, status (new|ack|resolved), created_at` — deterministic, ground truth.
- **`siem_incidents`** — AI Investigator output: `id, tenant_id, title, status, severity, source (correlation_match|manual|auditor), entity_graph (jsonb), timeline_ref, ai_summary, created_by, created_at`.
- **`siem_audit_findings`** — AI Auditor output: `id, tenant_id, finding_type, description, evidence_doc_ids[], severity, status, ai_rationale, created_at` — additive-only, never overwrites a deterministic match.

Per-tenant isolation: every table carries `tenant_id` and is filtered at the query layer (`security.md` Tenant Isolation), consistent with every other v2 table. The OpenSearch side of tenant isolation (index-per-tenant vs. a `tenant_id` term filter on shared daily indices, which is what `services/logs`/`manager::siem::build_os_query` already do) is an **open decision**, not settled here — §14.

## 11. Feature flag hierarchy (granular — `backend.md`/`critical-rules.md` convention)

`{product}.{feature}` keys, PostHog-gated, default OFF, Enterprise-gated capabilities additionally require `license.penguintech.io` entitlement on top (domain-bypass rule applies as usual). Master flag already exists in `services/manager/src/flags.rs`'s `CORE_FLAGS`; every sub-flag below is net-new and must be added to that registry (and `docs/v2-port/feature-flags.md`'s inventory) before use, per that doc's own runbook.

| Flag | Default | Tier | Gates |
|---|---|---|---|
| `skauswatch.siem` | OFF | Professional | Master switch — already exists, currently gates the manager's `/siem/{ingest,search,stats,config}` router. Every sub-flag below is inert if this is off |
| `skauswatch.siem.edr-ingest` | OFF | Professional | §5b bridge — deterministic forwarding, no AI |
| `skauswatch.siem.correlation-rules` | OFF | Professional | §7 Sigma/correlation engine — deterministic, same tier logic as Sentinel's deterministic floor |
| `skauswatch.siem.ai-investigator` | OFF | **Enterprise** | §8 reactive incident investigation — routes through WaddleAI (itself `skauswatch.waddleai`, Enterprise `TIER_FLAGS`) |
| `skauswatch.siem.ai-auditor` | OFF | **Enterprise** | §8 proactive continuous reasoning — same WaddleAI gate |
| `skauswatch.siem.connector.cloudtrail` | OFF | Professional | AWS CloudTrail pull connector |
| `skauswatch.siem.connector.guardduty` | OFF | Professional | AWS GuardDuty pull connector |
| `skauswatch.siem.connector.securityhub` | OFF | Professional | AWS Security Hub pull connector |
| `skauswatch.siem.connector.cloudwatch` | OFF | Professional | AWS CloudWatch pull connector |
| `skauswatch.siem.connector.datadog` | OFF | Professional | Datadog pull connector |
| `skauswatch.siem.connector.signoz` | OFF | Professional | SigNoz pull connector (security-relevant subset, §2) |
| `skauswatch.siem.connector.elastic` | OFF | Professional | External OpenSearch/Elasticsearch read-source connector (§6 special case) |
| `skauswatch.siem.connector.azure` | OFF | Professional | Azure Monitor/Activity + Defender pull connectors |
| `skauswatch.siem.connector.gcp` | OFF | Professional | GCP Cloud Logging + Security Command Center pull connectors |
| `skauswatch.siem.connector.digitalocean` | OFF | Professional | DigitalOcean monitoring/audit pull connector |

Per-connector flags gate rollout risk (ship CloudTrail without exposing half-built Azure/GCP), not pricing — every connector is deterministic ingestion at the same Professional tier as the base module, matching Sentinel/DepGate's "deterministic floor stands alone; AI-assisted capabilities gate at Enterprise" precedent exactly.

## 12. Phasing P1→P4 (each shippable, mirrors Sentinel/DepGate/EDR discipline)

| Phase | Ships | Value |
|---|---|---|
| **P1** | **Lake unification** (§4 — point `monitor`'s event store, collectors, and IOC matcher at the OCSF `skauswatch-logs-*` lake instead of `aaa-events-*`; fix the Cargo.toml/config naming ambiguity so Elastic-as-store is structurally impossible, not just discouraged) + EDR bridge (§5b) + AI Investigator/Auditor operating over the now-unified existing OCSF lake (§8, no connectors needed yet) + CloudTrail + GuardDuty connectors (§6) | Closes the two-lakes gap (the single biggest correctness problem this spec found); ships the AI roles immediately against real, already-flowing data; the two AWS connectors most customers ask for first |
| **P2** | Security Hub + CloudWatch connectors + Sigma/correlation rules engine (§7) | Detection beyond IOC matching; AWS coverage rounds out |
| **P3** | Datadog + SigNoz + external-OpenSearch/Elastic-read connectors | Cross-tool visibility without re-implementing any of them (§2's boundary made real) |
| **P4** | Azure (Monitor/Activity + Defender) + GCP (Cloud Logging + SCC) + DigitalOcean connectors + real entity-graph storage (promote `siem_incidents.entity_graph` from a JSONB blob to first-class graph tables if usage justifies it, §14) | Full multi-cloud coverage; graph queries beyond what a JSONB blob can efficiently answer |

P1 is unusually front-loaded on *fixing existing fragmentation* rather than pure net-new — deliberate: every later phase (connectors, correlation, AI) is worthless if it's reasoning over half the data.

## 13. Security, non-goals, risks

- **Connector credentials**: read-only API keys/roles only, Vault/IceBox-stored, never inline config, never logged (§6). A connector that could *write* to the source provider is explicitly out of scope.
- **Per-tenant lake isolation**: every OCSF document carries `tenant_id` (already true — `services/logs::stamp_tenant`); whether that's enough (shared daily index + term filter, today's model) or needs per-tenant index separation at higher tenant-count/compliance tiers is unresolved — §14.
- **The SSPL/Elastic constraint (§1, §6)** is the single most important invariant in this spec: OpenSearch is the only store this platform ever deploys; Elastic is admissible only as a read-only external connector source, and that boundary must be enforced structurally (config/type-level), not left as a comment.
- **WaddleAI degradation** (§8): both AI roles must be fully optional at runtime — a WaddleAI outage degrades to "no new incidents/audit findings generated", never a crash, never a fabricated result, never a block on deterministic detection.
- **OCSF as the stable contract**: every connector adapter's job ends at "provider schema → OCSF"; nothing downstream (correlation, AI, cross-module reads) should ever need to know a document originated from CloudTrail vs. the EDR bridge vs. a direct push. Losing this discipline is how the platform ends up with a third disconnected lake.
- **Non-goals**: SIEM does not compute cloud posture (CSPM's job, §9); does not perform endpoint response actions (EDR's P3, its own approval gate); does not re-implement observability (SigNoz's job, §2); does not manage/write to any connected external provider.
- **Not addressed here**: the cross-module executive-report aggregator (§9, flagged by both this spec and the EDR spec — build once, centrally); the exact entity-graph storage model beyond P1's JSONB (§14); Sigma-engine build-vs-adapt (§14).

## 14. Open decisions (need explicit confirmation before P2+)

1. **Lake-unification mechanics (P1, highest priority).** Does `monitor` migrate its event store wholesale onto `services/logs`'s ingest path (collectors call `/ingest` instead of writing `ElasticsearchStore` directly), or does `monitor` keep its own write path but both write into the *same* index/schema? Recommend the former — one ingest path, one OCSF contract, `monitor`'s collectors become producers exactly like a connector adapter is, rather than a second writer needing its own parity guarantees.
2. **EDR bridge stream naming (§5b).** Reuse/widen `STREAM_ENDPOINT_EVENTS` (already reserved, already produced, currently summary-only, zero consumers today) vs. add a new stream name. Recommend confirming with whoever reserved it before deciding — widening is technically free (no consumer to break) but may collide with unstated intent.
3. **Sigma engine: build vs. adapt an existing OSS Sigma-to-OpenSearch converter.** House convention (Sentinel/DepGate) strongly favors adopting proven OSS; needs a license check (OSI, non-PRC) before selection.
4. **Per-tenant index strategy (§13).** Shared daily index + `tenant_id` term filter (today's model, simplest, matches DepGate's "shared cache + per-tenant policy" reasoning) vs. per-tenant index/alias (stronger isolation, more operational overhead, no source in the repo has done this yet). Recommend starting with the shared-index model and revisiting only if a specific compliance requirement demands physical separation.
5. **Entity-graph storage (P4).** JSONB blob on `siem_incidents` (P1-P3, simple) vs. first-class graph tables/a graph-capable store (P4, only if usage justifies the complexity).
