# SkausWatch v2 PostHog Feature Flag Inventory (R4)

Complete inventory of every PostHog flag key introduced by the v2 Rust port,
for creation in the centralized PenguinTech License Server admin. Source of
truth for the canonical set is `services/manager/src/flags.rs` (doc comment:
"Canonical skauswatch feature-flag inventory... Keep in sync with
docs/feature-flags.md" — this file is that doc, relocated under
`docs/v2-port/` alongside the rest of the v2 port documentation set).

All flags below **must be created OFF by default** in PostHog
(`license.penguintech.io`) — no exceptions, per `general.md` Feature
Toggling & License Enforcement.

## Flag Table

| Flag key | Defined in registry? | Service(s) | What it gates | Default | Tier |
|---|---|---|---|---|---|
| `skauswatch.vault` | Yes (`MODULE_FLAGS`) | vault | Every Vault route (secrets, JIT, sync, audit, MEK rotate) via `require_license` middleware; 402 `Vault license required` when off. `/healthz`, `/readyz`, `/api/v1/admin/license`, `/api/v1/openapi.json` bypass. | OFF | Licensed module (Professional/Enterprise — not tier-checked in code yet, flag-only) |
| `skauswatch.codescan` | Yes (`MODULE_FLAGS`) | manager, codescan-backend | manager: `/api/v1/codescan/*` + deprecated `/api/v1/darwin/*` alias (in-handler `license_denied` check, not a router layer). codescan-backend: its own `/api/v1/codescan/*` surface. Same key, two independent enforcement points. | OFF | Licensed module (flag-only) |
| `skauswatch.s3-scan` | Yes (`CORE_FLAGS`) | manager | `s3_scan::router()` — `/api/v1/s3-scan/*` | OFF | — |
| `skauswatch.threat-intel` | Yes (`CORE_FLAGS`) | manager | `threat_intel::router()` — `/api/v1/threat-intel/*` | OFF | — |
| `skauswatch.siem` | Yes (`CORE_FLAGS`) | manager | `siem::router()` — `/api/v1/siem/*` | OFF | — |
| `skauswatch.alerts` | Yes (`CORE_FLAGS`) | manager | `alerts::router()` — `/api/v1/alerts/*` (including `/ai-review` sub-route — see gap below) | OFF | — |
| `skauswatch.approvals` | Yes (`CORE_FLAGS`) | manager | `approvals::router()` — `/api/v1/approvals/*` | OFF | — |
| `skauswatch.asm` | Yes (`CORE_FLAGS`) | manager | `asm::router()` — `/api/v1/asm/*` | OFF | — |
| `skauswatch.endpoint` | Yes (`CORE_FLAGS`) | manager | Both `endpoint::agent_router()` (HMAC agent tier, e.g. `/api/v1/endpoint/heartbeat`) and `endpoint::operator_router()` (`/api/v1/endpoint/agents` etc.) — one flag covers both tiers | OFF | — |
| `skauswatch.research` | Yes (`CORE_FLAGS`) | manager | `research::router()` — `/api/v1/research/*` | OFF | — |
| `skauswatch.users` | Yes (`CORE_FLAGS`) | manager | `users::router()` — `/api/v1/users/*` | OFF | — |
| `skauswatch.ai-review` | Yes (`CORE_FLAGS`) | manager (declared only) | **Nothing.** `POST /api/v1/alerts/{id}/ai-review` (`request_ai_review` in `routes/alerts.rs`) checks only the `AI_ENABLED` env var and role, never `state.license.flag_enabled("skauswatch.ai-review")`. See gap below. | OFF (declared; unenforced) | — |
| `skauswatch.monitor` | Yes (`CORE_FLAGS`) | monitor | Every business route via `flags::flag_denied()` called explicitly in `routes/alerts.rs`, `routes/events.rs`, `routes/dashboard.rs` (function-call pattern, not an axum layer) | OFF | — |
| `skauswatch.log-ingest` | Yes (`CORE_FLAGS`) | manager (declared only) | **Nothing.** `services/logs` has no `flags.rs`, no `penguin_licensing`/`LicenseClient` reference anywhere, and its router (`ingest.rs`) mounts `POST /ingest` + `GET /healthz` completely unguarded. See gap below. | OFF (declared; unenforced) | — |
| `skauswatch.pki` | Yes (`CORE_FLAGS`) | pki | `ISSUANCE_FLAG` — gates only `POST /certificates` and `POST /ssh/certificates` (issuance sub-router, via `FlagGate`/`flag_gate`). Read/list/revoke/CRL/OCSP/CA-info routes are intentionally ungated (documented design in `routes/mod.rs`) | OFF | — |
| `skauswatch.whitelabel` | Yes (`TIER_FLAGS`) | manager (declared only) | No feature code exists yet — declared for the frontend `/api/v1/license/features` contract only | OFF | Professional |
| `skauswatch.google-sso` | Yes (`TIER_FLAGS`) | manager (declared only) | No feature code exists yet | OFF | Professional |
| `skauswatch.saml-sso` | Yes (`TIER_FLAGS`) | manager (declared only) | No feature code exists yet | OFF | Enterprise |
| `skauswatch.oidc-sso` | Yes (`TIER_FLAGS`) | manager (declared only) | No feature code exists yet | OFF | Enterprise |
| `skauswatch.audit-compliance` | Yes (`TIER_FLAGS`) | manager (declared only) | No feature code exists yet | OFF | Enterprise |
| `skauswatch.waddleai` | Yes (`TIER_FLAGS`) | manager (declared only) | No feature code exists yet | OFF | Enterprise |
| `skauswatch.advanced-analytics` | Yes (`TIER_FLAGS`) | manager (declared only) | No feature code exists yet | OFF | Enterprise |
| `skauswatch.sshca` | **No — missing from registry** | sshca | `ISSUANCE_FLAG` — gates only `POST /api/v1/ssh/certificates` (issuance sub-router), mirrors pki's pattern exactly. Read/list/revoke/KRL routes ungated by design. | OFF | — |
| `skauswatch.openapi-docs` | **No — missing from registry** | manager, pki, sshca, vault, monitor, codescan-backend (6 services) | The live authenticated `/api/v1/openapi.json` doc route in each service (public login-only spec is separate and unguarded per `backend.md` OpenAPI rule) | OFF | — |

**Total: 24 distinct flag keys** (22 in the canonical `flags.rs` registry: 2
module + 13 core + 7 tier; 2 more — `skauswatch.sshca`,
`skauswatch.openapi-docs` — used in code but absent from that registry).

## Gaps Found

1. **`services/logs` has zero flag/license enforcement.** No `flags.rs`, no
   `penguin_licensing`/`LicenseClient` import anywhere in the crate.
   `POST /ingest` (the SIEM log-ingest surface `skauswatch.log-ingest` was
   evidently reserved for) is reachable unconditionally. This is the one
   `/api/v1`-equivalent router in the v2 port that should be gated and isn't
   — flag it to the team before R4 sign-off.
2. **`skauswatch.ai-review` is declared but never checked.**
   `request_ai_review` in `services/manager/src/routes/alerts.rs` only
   consults `AI_ENABLED` (an env var, not a PostHog flag) plus role. Either
   wire `state.license.flag_enabled("skauswatch.ai-review")` into that
   handler, or drop the key from `CORE_FLAGS`/`/license/features` if it's
   superseded by the env var — as shipped, a PostHog toggle for it would be
   silently inert.
3. **`skauswatch.sshca` and `skauswatch.openapi-docs` are real, enforced
   flags missing from `services/manager/src/flags.rs`.** Both work correctly
   at their enforcement point but are invisible to `/api/v1/license/features`
   (frontend nav gating) and to anyone using `flags.rs` as the single
   inventory source — which is exactly how this doc was assembled, so they
   were only caught by a raw string-literal grep across all six-plus REST
   services. Add both to the registry (`sshca` alongside `pki` in
   `CORE_FLAGS`; `openapi-docs` as its own list or a documented exception)
   so the registry's own "canonical" claim holds.
4. **Not gaps:** `s3scan`, `scanner`, `worker-codescan`, `worker-vault-sync`
   (stream-consumer workers, `/healthz`+metrics only, no `/api/v1` REST
   surface) and `endpoint-agent` (a client binary, not a server) correctly
   have no flag code — their trigger paths are gated upstream by the
   manager's `skauswatch.s3-scan`/`skauswatch.endpoint` routers that enqueue
   their work. `TIER_FLAGS` having no enforcement code is also not a gap —
   no Professional/Enterprise feature exists yet to enforce; they're
   declared ahead of the feature landing so the frontend contract is stable.

## Runbook: Creating These Flags in PostHog

Per the `integrating-license-server` skill conventions
(`license.penguintech.io`, self-hosted PostHog Community Edition):

1. For each of the 24 keys above (add `skauswatch.sshca` and
   `skauswatch.openapi-docs` to `services/manager/src/flags.rs` first so the
   registry stays the single source before creating flags from it).
2. In the PostHog admin for the `skauswatch` project, create a feature flag
   named exactly the key (e.g. `skauswatch.vault`) — boolean, release
   condition **0% rollout / OFF for all** at creation time. Never create a
   flag pre-enabled.
3. No `distinct_id` targeting rules needed at creation — `LicenseClient`
   evaluates these as project-wide boolean flags, not per-user experiments.
4. Verify each new flag evaluates OFF end-to-end: call
   `GET /api/v1/license/features` against a non-dev-bypass deployment and
   confirm every key in the `flags` map reads `false`.
5. Flip a flag ON only after its feature has been validated in that
   environment (per `general.md`: "new flags default OFF; flip on after
   validation"). Do this per-environment (alpha → beta → gamma → prod), not
   globally in one step.
6. Domain-based `--dev` bypass (`with_bypass_domain("skauswatch.app")`,
   present in every service's `state.rs`) evaluates all flags `true`
   regardless of PostHog state — expected for local/dev evaluation, not a
   substitute for creating the real flags before beta/prod rollout.
7. Once a flag's feature is fully rolled out and stable, remove the flag
   gate from code and delete the PostHog flag — flags are not permanent
   config (`general.md`).
