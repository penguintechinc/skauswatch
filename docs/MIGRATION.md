# Migration Guide — v1 → v2

This is the human-readable guide to the SkausWatch **v2.0** platform migration,
for anyone tracking the project. The terse release record lives in
[`CHANGELOG.md`](../CHANGELOG.md); deep per-service contracts live under
[`docs/v2-port/`](v2-port/).

> **Status:** v2.0 is in active development on `release/v2.0.x` (not yet shipped).
> SkausWatch has **never been deployed to production**, so v2 is free to change
> wire contracts, schemas, routes, and module names without a data migration.

## What changed at a glance

- **All backend services rewritten in Rust** (from Python Quart/Flask/FastAPI +
  a Go endpoint agent) as a single Cargo workspace — axum REST, tonic gRPC,
  sqlx (PostgreSQL), and a Redis/Valkey Streams worker harness replacing Celery.
- **One React frontend** — the separate core, Vault, and CodeScan UIs are merged
  into `services/webui` as entitlement-gated, lazy-loaded modules.
- **Feature-flag + license gating** on every feature area via the
  `penguin-licensing` Rust crate (PostHog-compatible flags + license
  entitlement), default-OFF, fail-safe.
- **Module rename** to descriptive names (below).

## Module rename map

Modules are renamed to say what they do. The new name is canonical; where an
old name was externally visible (REST paths), the old form is kept as a
**deprecated alias** during the transition and removed in a later release.

| Old name | New name | Service / dir | REST base (old → new, old kept as deprecated alias) | Feature flag |
|----------|----------|---------------|------------------------------------------------------|--------------|
| edr | **endpoint** | `services/endpoint-agent` | `/api/v1/edr/*` → `/api/v1/endpoint/*` | `skauswatch.endpoint` |
| icebox | **vault** | `services/vault` (+ sync worker) | `/api/v1/icebox/*` → `/api/v1/vault/*` | `skauswatch.vault` |
| darwin | **codescan** | `services/codescan-backend` | `/api/v1/darwin/*` → `/api/v1/codescan/*` | `skauswatch.codescan` |
| worker-s3 | **s3scan** | `services/s3scan` | (worker; no public REST) | `skauswatch.s3-scan` |
| worker-scanner | **scanner** | `services/scanner` | proxied via manager `/api/v1/asm/*` | `skauswatch.asm` |
| aaa-monitor | **monitor** | `services/monitor` | `/api/v1/aaa/*` → `/api/v1/monitor/*` | `skauswatch.aaa-monitor` → `skauswatch.monitor` |
| pki-server | **pki** | `services/pki` | `/api/v1/certificates/*`, `/api/v1/ssh/*` | `skauswatch.pki` |
| ssh-ca | **sshca** | `services/sshca` | `/api/v1/ssh/*` | `skauswatch.pki` |
| log-receiver | **logs** | `services/logs` | `/ingest`, `/healthz` | `skauswatch.log-ingest` |

## Deprecation & compatibility policy

- **REST paths:** old `/api/v1/{edr,icebox,darwin,aaa}/*` paths remain mounted as
  aliases that return `Deprecation` + `Sunset` response headers, and are removed
  in a future minor release. Update clients to the new paths.
- **Feature-flag keys:** renamed keys are re-registered in the license server;
  the old keys are read as fallbacks during transition.
- **Redis Streams topics** (`edr:events`, `darwin:tasks`, …) and **DB tables**
  (`edr_agents`, `darwin_git_credentials`, …) are renamed outright — every
  producer/consumer is in this repo and updated atomically, and there is no
  production data to migrate.
- **gRPC** proto packages (`skauswatch.manager` / `.s3scan` / `.pki`) are
  unaffected by the rename.

## Endpoint agent direction

The **endpoint** agent (formerly EDR) is a thin client by design —
server-intensive, endpoint-light — and is planned to ship as a module of the
shared `penguin` modular desktop agent rather than a standalone binary. The
current standalone Rust port is the reusable core for that module.

## Not in v2.0 (tracked)

Deferred, flag-gated follow-ups are tracked in
[`docs/v2-port/v2.1-backlog.md`](v2-port/v2.1-backlog.md) — e.g. the scanner
ASM subsystem (Nuclei/ZAP/masscan/OpenVAS), the monitor log collectors +
threat-intel + AI route groups, and per-repo CodeScan git credentials.
