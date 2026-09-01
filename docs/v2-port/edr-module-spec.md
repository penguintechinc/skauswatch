# EDR — Endpoint Detection & Response

**Status:** Draft design spec · **Target:** v2.1+ (telemetry hardening + SIEM bridge can ride v2.0 cutover as a fast-follow; detection/response are net-new) · **Flag:** `skauswatch.edr` (default OFF)

> **Sibling-spec note:** this doc was asked to cross-reference `scratchpad/specs/siem-module-spec.md` and `scratchpad/specs/cspm-module-spec.md` (SIEM's connector/EDR-bridge section + its open question about the endpoint agent). Neither file exists at that path in this session's scratchpad as of writing — only `docs/v2-port/v2.1-codescan-sentinel.md` and `docs/v2-port/v2.1-depgate.md` were available for house tone/structure. **The OCSF-bridge design in §3/§7 below is instead derived directly from the real `services/logs` ingest contract (`docs/v2-port/logs-contract.md`, `services/logs/src/ocsf.rs`) and the manager's actual `endpoint.rs` routes — grounded in shipped code, not the SIEM spec's assumptions.** Whoever finishes the SIEM spec should reconcile its EDR-bridge section against §3/§7 here rather than the reverse.

Endpoint Detection & Response: the host-telemetry arm of the SkausWatch security platform, sibling to Sentinel (code arm) and DepGate (dependency-ingress arm). Two agent form factors — an in-repo server/workload sensor and a laptop/desktop sensor shipped inside `penguin` (§1) — each collect process/file/network activity from a monitored host, an eventual on-host detection layer flags malicious activity, and a configurable response layer (§6) can act on it (isolate, kill, quarantine); both report through the same manager hub-API ingest path, tenant-scoped, audited, and feeding both the manager's fleet-ops view and the SIEM's OCSF lake.

## 1. Positioning

| | Sentinel | DepGate | **EDR** |
|---|---|---|---|
| Watches | code you already have (repos) | dependencies *entering* the environment | hosts/endpoints already running |
| Signal | SCA/CVE/SAST findings | malware verdict on an artifact | process/file/network/registry activity |
| Consumes | WaddleAI (triage) | scan-core (ClamAV+YARA-X), OSV/deps.dev | threat-intel feeds (P2), scan-core (P3, quarantine) |
| Feeds | reports, fix-PRs | cache + reports | **SIEM OCSF lake (primary)**, manager fleet-ops Postgres |

EDR is a **primary SIEM source**, not a bolt-on. Sentinel/DepGate findings are periodic/event-triggered (a scan run, an artifact pull); EDR is the platform's only continuous, host-level telemetry stream — the thing a SIEM correlates *against*. Today that stream terminates in the manager's own Postgres (`endpoint_agents`/`endpoint_events`) and never reaches the OCSF/OpenSearch lake (`services/logs`) that `services/manager/src/routes/siem.rs` fronts. Closing that gap (§3, §7) is this spec's highest-priority net-new item — every phase below is secondary to it.

**Positioning — RESOLVED: split by host form factor.** `client.md` mandates that desktop clients — software deployed outside the K8s server cluster — consolidate into the single Go `penguin` repo, one app per user, never per-product. That rule targets genuine end-user desktop/laptop clients; EDR's two deployment modes turn out to serve two different host populations, not one ambiguous "outside K8s" bucket:

- **Server / workload EDR agent (non-laptop hosts) — confirmed in-repo.** `services/endpoint-agent` (this repo, Rust) covers both its K8s DaemonSet mode and its bare-host systemd mode (`deployments/systemd/`, `scripts/install-linux.sh`) for Linux servers/VMs that are server-role hosts even when never in a K8s cluster — not end-user devices, so `client.md`'s consolidation rule doesn't actually reach this mode (see §2 Deployment).
- **Endpoint / laptop EDR (end-user devices) — owned by `penguin`, not this repo.** This is the case `client.md`'s rule actually targets: an engineer's EDR telemetry should come from the same `penguin` install already on their laptop, not a second product-specific agent.
- **Shared hub-API ingest.** Both form factors report into the same manager-side ingest endpoint — `POST /api/v1/endpoint/events` (§3) — so tenant resolution, the SIEM/OCSF bridge, and fleet-ops storage are shared infrastructure regardless of which agent produced the event. One server-side API, two agent form factors.

The original reasoning for keeping the sensor in-repo Rust still holds, now correctly scoped to the **server** agent only:

1. **Analogous to skauswatch's own approved all-Rust exception.** SkausWatch already deviates from `general.md`'s Python-default via an approved platform-wide decision to build the entire API/service tier in Rust for a security-sensitive, systems-programming product. A server EDR sensor — kernel-adjacent process/file/network introspection, eventually eBPF hooks, tamper-resistance requirements, running unattended on production infrastructure — is the same category of justified exception.
2. **A hard language-rule conflict if it were forced into `penguin`.** `penguin` is Go (`client.md`); `general.md`'s Language Selection is unconditional: *"Security-sensitive projects — Rust or Python3 only, never Go."* A server sensor doing raw process introspection (`SYS_PTRACE`), packet/connection enumeration (`NET_ADMIN`), and (P3) host-isolation/process-kill actions is squarely security-sensitive — exactly why it stays a Rust module here rather than joining `penguin`.

**New open sub-decision this split surfaces (unresolved — §10): what language the `penguin`-side laptop sensor should be built in.** A laptop EDR sensor is arguably just as security-sensitive as the server one, which puts it in the same tension with `general.md`'s Rust/Python-only rule that motivated keeping the server agent out of Go `penguin` in the first place. Three options, presented without a decision:

  (a) **A Rust module inside `penguin`** — consistent with `penguin` being "the single modular desktop client," a security-sensitive module in Rust vendored into an otherwise-Go app.
  (b) **A documented Go security exception** for the laptop sensor specifically, following the same explicit-approval pattern used elsewhere for justified deviations.
  (c) **Telemetry-only laptop agent** — collection/forwarding only; all response actions (isolate/kill/quarantine) stay server-side, sidestepping the language question for the highest-risk code path.

The reviewer leans toward (a), but this is **unconfirmed** — this spec has no standing to choose `penguin`'s implementation language; flagged for explicit user decision in §10.

## 2. Current state vs. net-new

`services/endpoint-agent` (Rust; a faithful port of a prior Go binary — CLI flags, config YAML shape, and severity/HMAC wire contract are preserved byte-for-byte per the crate's own doc comments) already ships a working, if narrow, agent:

| Capability | Today | Gap |
|---|---|---|
| **Collectors** | Process (`sysinfo`), file integrity (SHA-256 diff via `walkdir`), network connections (`netstat2`) — all fixed-interval **pollers** (1s/30s/5s defaults), not event-driven | No eBPF (Linux), EndpointSecurity (macOS), or ETW/minifilter (Windows) hooks — a fast process/connection can be missed between polls; §4 |
| **Registry monitoring** | Config shape (`RegistryCollectorConfig`) accepted, **fully inert** — no collector implementation exists (Windows-only, honestly documented as deferred in `config.rs`) | Real net-new build |
| **Detection** | Hardcoded name/port/path allow-lists (`BUILTIN_SUSPICIOUS_NAMES`, `BUILTIN_SUSPICIOUS_PORTS`, `BUILTIN_CRITICAL_PATHS`), config can only *union*-extend them, never narrow | This is severity **tagging**, not a rules/IOC-matching engine — §4 P2 |
| **Response** | None — agent is read-only telemetry | Full net-new build — §4 P3 |
| **Transport/auth** | HMAC: `X-API-Key = hex(HMAC-SHA256(shared_secret, agent_id))`, static per-agent secret, no rotation | Move to short-lived signed machine JWT or SPIFFE/mTLS — §4 P1, §5 |
| **Tenant scoping** | **Already implemented and tested** — `endpoint_enrollment_tokens` table (migration `0005`), `POST /endpoint/register` resolves `tenant_id` from a hashed, expiring, use-capped enrollment token instead of `default_tenant_uuid()`; re-registration keeps the stored tenant. This is *ahead* of where `docs/v2-port/service-auth-model.md` §5 describes it (already built, not just recommended) | None for P1 — reused as-is |
| **Storage** | `POST /endpoint/events` → manager Postgres `endpoint_events`/`endpoint_agents` only | **Never reaches the OCSF lake** (`services/logs`) — §3, §7 |
| **Deployment** | Two modes, both Linux, both **server form factor** per §1's resolved split: (a) K8s DaemonSet (`k8s/helm/endpoint-agent`, privileged/hostPID/hostNetwork, documented ROOT EXCEPTION for `SYS_PTRACE`+`NET_ADMIN`, Tetragon exec-allowlist as primary control since CNP can't scope hostNetwork traffic); (b) standalone systemd install (`scripts/install-linux.sh`, `deployments/systemd/endpoint-agent.service`) for bare Linux **servers/VMs**, never in a K8s cluster but still server-role hosts — not laptops, so `client.md`'s desktop-consolidation rule doesn't apply here; see §1 | macOS/Windows config-shape hints (`#[cfg(windows)]` default watch paths, Windows tool names in the suspicious-process list) predate the §1 split; laptop/desktop macOS+Windows is now `penguin`'s scope, not this crate's — the one remaining gap here is **Windows Server** as a server-form-factor target, unverified — §4 P4, §5 |
| **SPIFFE identity** | `spiffe://penguintech.io/<env>/endpoint-agent` reserved and registered in the SPIRE chart's `autoEnroll.services` for the in-cluster DaemonSet variant, but **not consumed as an auth mechanism today** — `service-auth-model.md` §1 lists it "out of scope for R2c/R3, listed for completeness." The bare-host variant is deliberately *not* SPIFFE-federated (customer laptops/servers aren't in skauswatch's trust domain) — enrollment tokens are its permanent auth model, SPIFFE only ever applies to the in-cluster mode | §5 |

**Bottom line:** today's agent — the **server** form factor per §1 — is a solid, tenant-aware telemetry collector wired only to fleet-ops Postgres. "Real EDR" — detection and response — does not exist yet.

## 3. OCSF bridge — resolving the SIEM's open question

`services/logs` already runs the platform's only OCSF pipeline: `POST /ingest` (port 5010) accepts an `X-Log-Source`-tagged record or batch, OCSF-normalizes it (`services/logs/src/ocsf.rs`), and bulk-indexes into the daily OpenSearch index `skauswatch-logs-{date}`; the manager's `siem.rs` router fronts read access (`/siem/search`, `/siem/stats`). `services/logs` itself has no auth — it trusts the manager's network position (`logs-contract.md`: "No auth on either endpoint — the manager fronts auth").

**Design: the manager is the bridge, not the agent.** The endpoint-agent binary never talks to `services/logs` directly — it would otherwise need a second, separately-authenticated egress path from arbitrary (including untrusted, customer-owned) hosts straight into the SIEM ingest surface, bypassing the tenant resolution the manager already performs on every event. Instead:

1. Agent → manager: unchanged. `POST /api/v1/endpoint/events` (HMAC + resolved tenant), persisted to `endpoint_events` as today — Postgres stays the fleet-ops system of record (agent list, per-agent history, `/statistics`). This is the shared hub-API ingest point referenced in §1 — the same endpoint both the in-repo server agent and, once built, `penguin`'s laptop agent report through.
2. Manager, on the same write path, also enqueues each event onto a Redis Stream (new, house pattern — mirrors `codescan:tasks`/`skauswatch:scan-jobs`, not a synchronous blocking call on the agent's hot report path) carrying `{tenant_id, agent_id, event_type, severity, details}`.
3. A small worker (or the manager itself, off the request path) drains the stream and calls `services/logs` `POST /ingest` with `X-Log-Source: endpoint-agent-{event_type}` (`endpoint-agent-process` / `-file` / `-network`), body = the event's raw `details` plus `agent_id`/`tenant_id`.
4. `services/logs`'s existing `detect_class`/`class_name` (`ocsf.rs`) already routes on source-substring: `-network` → `class_uid 4001` (network_activity), `-file` → `4003` (file_activity) — **zero changes needed on the logs side for those two**. Process events have no dedicated class today and fall through to the default `2001` (security_finding) — acceptable for P1, but recommended as a small additive P1-stretch change: add a genuine OCSF process-activity class entry to `class_name`/`detect_class` rather than overloading the generic finding bucket long-term.
5. `detect_severity` already matches on a `level`/`severity` string of exactly `critical`/`high`/`medium`/`low`/`info` — **identical to `Severity::as_str()` in `collectors/mod.rs`** — no severity-mapping code needed either.
6. Delivery is at-least-once via the stream with retry/backoff and a bounded dead-letter path (never silent-drop — Postgres remains authoritative if the SIEM forward fails, but a failure must be observable, not swallowed, per house Verification Integrity rules).

Net result: an additive manager-side forwarder + one small logs-service class addition, reusing every existing wire contract. No agent changes, no new agent auth surface, no new `services/logs` auth model.

## 4. Capabilities & phasing (P1→P4, each shippable — mirrors Sentinel/DepGate)

| Phase | Ships | Value |
|---|---|---|
| **P1** | Harden current telemetry (fix polling gaps where cheap — e.g. shorten default intervals, add drop-counters/backpressure metrics on the event channel) + **OCSF bridge into the SIEM lake** (§3) + auth upgrade: HMAC → SPIFFE/mTLS for the in-cluster DaemonSet mode, short-lived signed machine JWT (**ES256**, matching the mesh's landing asymmetric-signing work) for the bare-host/enrollment-token mode, since a customer endpoint can never hold a SPIFFE SVID | Closes the SIEM gap; stops relying on a single static shared HMAC secret per agent forever |
| **P2** | On-endpoint detection rules: process/file/network anomaly rules beyond the current hardcoded allow-lists; IOC match against the platform's existing threat-intel feeds (the VirusTotal/AlienVault OTX enrichment path s3scan already uses) | Real detection, not just severity tagging |
| **P3** | Response actions — isolate host (network-cut via the agent's own `NET_ADMIN` capability or a manager-issued Cilium host-firewall rule), kill process, quarantine file (reusing DepGate/Sentinel's shared **scan-core** quarantine primitive where the artifact is a file, not a stream) — gated by explicit scope + audited (§5) | The "R" in EDR |
| **P4** | Cross-platform for the **server** form factor only (§1): Windows Server (ETW + minifilter) sensor and installer where a genuine Windows Server telemetry gap exists; macOS server/workload coverage only if a real use case emerges (rare — macOS is overwhelmingly laptop/desktop, `penguin`'s scope per §1); tamper-resistance hardening (binary integrity attestation, self-tamper detection — see §5 gap) | Full server-fleet coverage — laptop/desktop macOS+Windows coverage is `penguin`'s responsibility, not tracked here |

P1 needs no new detection/response logic and is pure plumbing + auth hardening — it should ship first and independently of P2–P4, same shippable-phase discipline as Sentinel/DepGate.

## 5. Platform targets

Per §1's resolved split, `client.md` Platform Targets & Multi-Arch (**Linux amd64+arm64 minimum, macOS, Windows**) is the bar `penguin` — not this repo — must clear for the laptop form factor. This repo's in-repo **server** agent has a narrower, server-shaped target list: Linux (server distros, amd64+arm64) mandatory; Windows Server an open P4 candidate (§4); macOS out of scope here (macOS server/workload deployments are rare enough not to justify a dedicated in-repo sensor — §4 P4). Current state (§2) covers Linux only, both amd64/arm64 unverified (no CI cross-arch build evidence found for this crate specifically — flag for P1 verification, not just P4).

A server EDR sensor's telemetry ceiling is bounded by how deep it can see into the OS, and each server-relevant target OS demands **privileged host access** by a different mechanism:

| OS | Deep-telemetry mechanism | Current state |
|---|---|---|
| Linux (server) | eBPF (kprobes/tracepoints) for real-time process/file/network events, replacing today's pollers | Pollers only; ROOT EXCEPTION already granted (`SYS_PTRACE`+`NET_ADMIN`, `privileged: true`, `hostPID`/`hostNetwork` — `k8s/helm/endpoint-agent/values.yaml`) |
| Windows Server | ETW (Event Tracing for Windows) + a minifilter driver for file events | Not started; config shape hints exist (`#[cfg(windows)]` paths) but no collection code; scope is Windows Server specifically — desktop Windows is `penguin`'s target per §1 |

macOS is dropped from this repo's platform table per §1 — any macOS EDR coverage (overwhelmingly laptop/desktop) belongs to `penguin`.

The remaining server target requires the same class of privileged/root access `client.md`'s Build & Distribution and Rootless Containers (`critical-rules.md`) rules would otherwise forbid by default — the existing DaemonSet ROOT EXCEPTION is the precedent; a Windows Server equivalent (admin install, signed driver where required) needs the same explicit-approval treatment before P4, not a silent assumption.

## 6. Auth & security

- **SPIFFE-ready, dual auth model by deployment mode** (not a contradiction — two legitimately different trust boundaries, per `service-auth-model.md` §5's own reasoning): in-cluster DaemonSet → SPIFFE/mTLS using the already-reserved `spiffe://penguintech.io/<env>/endpoint-agent` ID; bare customer-host agent → short-lived signed machine JWT (ES256, asymmetric — the manager holds only a public key, so no single leaked agent secret compromises the fleet), issued at enrollment and renewed on heartbeat, replacing the current static per-agent HMAC secret. Enrollment-token tenant resolution (already built, §2) is unchanged by this — the JWT replaces the *transport* auth, not the tenant-provisioning flow.
- **Tamper resistance is currently weak and worth calling out explicitly.** The agent runs with `SYS_PTRACE`+`NET_ADMIN`+`privileged: true` — if an attacker compromises the agent process itself, they inherit ptrace-over-everything and raw network access on the host: this makes the sensor a **lateral-movement force-multiplier**, not just a monitoring gap, if compromised. Today's process collector explicitly *excludes* the agent's own process name from monitoring (a deliberate v1 self-noise fix) — the side effect is that tampering with the agent's own process/binary produces **zero self-alert**. P1/P4 should add a narrow, explicit self-integrity check (binary hash pinning, process-still-running heartbeat correlation on the manager side) that is *not* the same code path as the general self-exclusion, so fixing the noise bug didn't also blind the platform to its own compromise.
- Tetragon exec-allowlist (`templates/tracingpolicy.yaml`, already shipped) is the **primary** control for the in-cluster mode since a standard CiliumNetworkPolicy can't scope hostNetwork traffic — any exec other than the agent binary is SIGKILLed. The bare-host mode has no equivalent today; P4 should specify an analogous control (e.g. systemd hardening directives, currently mostly commented out/disabled in `deployments/systemd/endpoint-agent.service` — "Security hardening (comment out if causing issues)" with every directive set to non-hardened defaults, a gap worth closing independent of P4).
- **Detect-only vs. detect+respond is a per-agent/per-policy posture, not a global on/off.** Applies to both form factors but matters most for the server agent given its outage blast radius (below): a false-positive isolate/kill on a production server is a self-inflicted outage, so some customers will mandate detect-only regardless of what the platform supports elsewhere in their fleet. Each enrolled agent (or the tenant-level policy it inherits) carries a `response_mode` of `detect-only` (default) or `detect+respond` (opt-in), enforced by the manager at the point a response action would be dispatched — independent of whether the tenant is even licensed for response at all (§7). Two gates, not one: `skauswatch.edr.response` must be ON for the tenant *and* the specific agent/policy must be `detect+respond` before any isolate/kill/quarantine action reaches a host. `detect-only` telemetry+detection is available to any tenant with `skauswatch.edr.detection` on, independent of response tier.
- **Response actions (P3) are the highest-blast-radius surface in this module** — gated behind a dedicated scope (e.g. `edr:response:execute`, OIDC-scope pattern per `security.md`, never a role-name check), full audit log (who, when, target host/process/file, action, result, reversibility), and — given host isolation/process-kill can itself cause an outage — should default to requiring explicit confirmation (P3 open question: single-approver vs. two-person control, §10) — and, per the detect-only/detect+respond posture above, is only reachable at all for agents/policies explicitly opted into `detect+respond`.

## 7. Feature flag hierarchy

`{product}.{feature}` convention (`backend.md`), master flag default OFF, PostHog-gated (`critical-rules.md` Feature Flags), Enterprise-gated capabilities additionally require `license.penguintech.io` entitlement on top — domain-bypass rule applies as usual.

| Flag | Default | Tier | Gates |
|---|---|---|---|
| `skauswatch.edr` | OFF | Professional | Master switch — agent enrollment, fleet dashboard, all sub-flags below inert if this is off |
| `skauswatch.edr.telemetry` | OFF | Professional | Process/file/network collectors + reporting to manager Postgres (today's shipped capability) |
| `skauswatch.edr.siem-bridge` | OFF | Professional | Manager → `services/logs` OCSF forwarding (§3) |
| `skauswatch.edr.detection` | OFF | Professional | On-endpoint rule engine + IOC matching (P2) — deterministic, no AI, same tier logic as Sentinel/DepGate's deterministic floor |
| `skauswatch.edr.response` | OFF | **Enterprise** | Isolate/kill/quarantine actions (P3) — audit-and-compliance-class capability, matches the Enterprise tier's existing audit/compliance bucket (`critical-rules.md`); necessary but not sufficient — an agent/policy set to `detect-only` (§6) never receives dispatched actions even with this flag ON |
| `skauswatch.edr.linux` | OFF | Professional | Linux sensor build (current) |
| `skauswatch.edr.macos` | OFF | Professional | macOS EndpointSecurity sensor (P4) |
| `skauswatch.edr.windows` | OFF | Professional | Windows ETW/minifilter sensor (P4) |

Per-platform flags gate rollout risk (ship Linux without exposing half-built macOS/Windows sensors), not pricing — all three sit at the same tier as the base capability. Response stays Enterprise-only across all platforms once P4 lands. Response is a two-layer gate (§6): `skauswatch.edr.response` controls whether the tenant has the capability at all; the per-agent/per-policy `detect-only`/`detect+respond` setting controls whether a specific host can receive dispatched actions — a tenant fully licensed for response can still run every server in `detect-only` by choice.

## 8. Suite integration

- **→ SIEM**: primary feed via the OCSF bridge (§3) — every process/file/network event becomes a searchable OCSF document in the same lake Sentinel/DepGate/other sources eventually write to, enabling cross-signal correlation (e.g. a DepGate-quarantined artifact's hash later observed by an EDR file-integrity event on a monitored host).
- **← Threat intel**: P2 detection consumes the same TI feeds (VirusTotal/AlienVault OTX) s3scan already enriches against — no new TI integration needed, just a new consumer.
- **→ Unified exec report**: EDR findings (detections, response actions taken) should surface in the same cross-module executive report the CSPM spec flagged as missing an aggregator. This spec does not build that aggregator — it's called out here as a second module depending on the same missing piece, strengthening the case for building it once, centrally, rather than per-module.
- **↔ Sentinel/DepGate shared primitives**: P3 file quarantine should reuse DepGate's shared **scan-core** crate (ClamAV+YARA-X, `Verdict` enum) rather than a third bespoke scanning path, per the "DRY — shared scan-core" precedent DepGate's spec already established for its own and Sentinel's use.

## 9. Non-goals / risks

- **Response-action blast radius** is the single biggest operational risk this module introduces — a false-positive "isolate host" on a production server is a self-inflicted outage. P3 must ship confirmation/audit before any auto-response mode, and auto-response (vs. human-confirmed) is explicitly **out of scope** until P3 has a track record. The `detect-only` default (§6) is the primary mitigation available from day one — a customer can adopt EDR detection fleet-wide without ever enabling response.
- **Agent auto-update safety.** `client.md`'s Update Checks rules apply in full: silent/non-blocking update checks, never require manual download, never crash on network error. Given the agent runs privileged, an update mechanism is itself a high-value attack target (a malicious "update" would inherit `SYS_PTRACE`+`NET_ADMIN`/root) — update payloads must be signed and verified before install, out of scope for P1 but a hard P4 (or earlier) prerequisite before wide bare-host distribution.
- **No secrets in the distributed binary** (`client.md`) — the current design already satisfies this (enrollment token / JWT obtained at install/enrollment time, never baked into the binary); stays true as auth moves to signed JWTs.
- **PII/host-data handling.** File paths, usernames, and command lines collected today can contain PII (home directory names, usernames in `cmdline`). No tokenization currently applied before these reach Postgres or (once §3 ships) the OCSF lake — needs an explicit decision on whether host telemetry is exempt from the platform's UUID-only PII rule (`critical-rules.md` PII Tokenization) or needs scrubbing/tokenization at ingest. Flagged, not resolved, here.
- **Not in scope for this spec**: building the cross-module exec-report aggregator (§8); the response-action approval workflow's exact UI; macOS/Windows kernel-driver signing logistics (P4 implementation detail, not a design decision).

## 10. Open decisions (need explicit user confirmation)

1. **In-repo vs. `penguin` (§1) — RESOLVED.** Split by host form factor: server/workload EDR agent stays in-repo (`services/endpoint-agent`, Rust); laptop/endpoint EDR is `penguin`'s responsibility; both share the same manager hub-API ingest path (§1, §3). No further confirmation needed on the split itself.
2. **Laptop sensor implementation language inside `penguin` (new, raised by the §1 split).** Three options, undecided: (a) a Rust module inside `penguin` — reviewer's inclination, unconfirmed; (b) a documented Go security exception for the laptop sensor; (c) telemetry-only laptop agent, all response actions kept server-side. Determines whether `penguin`-side EDR work ships as Rust, an approved Go exception, or telemetry-only — should be resolved before that work begins.
3. **eBPF vs. continued userland polling for Linux (P1/P4).** eBPF gives real-time, no-gap telemetry and is the natural next step given the existing `SYS_PTRACE`/`privileged` posture already assumes deep host access; userland polling is simpler and what's shipped today. Recommend eBPF as the P4 target, revisit sooner if P1's "harden current telemetry" work exposes polling-gap false-negatives in practice.
4. **Response-action authorization model (P3).** Single-approver (scoped RBAC only) vs. two-person control (a second admin must confirm host isolation/process-kill) given the outage risk in §9; composes with, but is orthogonal to, the detect-only/detect+respond posture in §6 — this decision governs *who* approves a response once an agent is already in `detect+respond` mode, it doesn't replace the `detect-only` escape hatch. Recommend starting single-approver + full audit + a fast "undo isolation" path, escalate to two-person control only if incident review shows false-positive isolations happening in practice.
5. **Manager-side OCSF forward transport (§3).** Redis Stream (recommended, matches house job-queue convention) vs. a simpler synchronous best-effort HTTP call inline in `report_events` (simpler, but couples the agent's hot report path to `services/logs`/OpenSearch availability). Recommend the stream.
