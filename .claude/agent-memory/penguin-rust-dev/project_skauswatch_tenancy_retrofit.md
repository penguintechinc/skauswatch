---
name: project-skauswatch-tenancy-retrofit
description: skauswatch v2 org-wide multi-tenant isolation retrofit (R2 wave) — per-service pattern, shared conventions, and where the design doc lives
metadata:
  type: project
---

skauswatch v2 (Rust rewrite, `release/v2.0.x`) is retrofitting tenant
isolation service-by-service. Authoritative design doc:
`docs/v2-port/tenancy-model.md` — read it in full before touching any
service's auth/query layer, it has the exact per-service provenance table,
migration ordering, and sqlx patterns.

**Why:** several services had a live IDOR — `tenant_id` read from the
client-supplied request body/local claims shape instead of the validated
JWT. codescan-backend was one concrete instance (fixed 2026-07-31); the doc
lists manager, vault, monitor, pki, sshca, s3scan, scanner,
worker-codescan, worker-vault-sync as the full fan-out, each getting its own
R2 pass by a separate agent/session, landing concurrently on the same
branch.

**How to apply — the pattern every service follows:**
1. House `Claims` model lives in `crates/skauswatch-auth` (`sub/iss/aud/iat/
   exp/scope/tenant/teams/roles`). Add `skauswatch-auth = { workspace = true }`
   to the service's `Cargo.toml` if not already present.
2. Replace any local tenant-free `AccessClaims`-shaped struct with
   `skauswatch_auth::Claims` + `skauswatch_auth::decode_claims` +
   `Claims::require_tenant()`.
3. `CurrentUser` (or equivalent) gains a `tenant_id: uuid::Uuid` field parsed
   from `Claims.tenant` — decode independently in the extractor itself
   (don't rely solely on `TenantContext` request-extension state), because
   per-module test routers in this codebase never mount the outer
   `tenant_middleware` layer.
4. Layer `skauswatch_auth::tenant_middleware::<AppState>` as the OUTERMOST
   `.layer()` on the service's real router (defense in depth, not a
   replacement for #3). Needs `impl skauswatch_auth::JwtSecretSource for
   AppStateInner`.
5. Replace ad-hoc `JWT_SECRET_KEY` loading (random/pid-derived dev fallback)
   with `skauswatch_auth::load_jwt_secret()` — fails closed in prod
   (`RELEASE_MODE != "false"`), warns+random only outside prod.
6. Every owned table gets `tenant_id UUID NOT NULL` (logical reference to
   manager's `tenants.id` — no real FK, services don't share a database).
   Bootstrap/backfill literal: `00000000-0000-0000-0000-000000000001`
   (must match manager's seeded tenant exactly, since v2 has never hit prod
   — every existing row in every environment gets backfilled to it).
7. Every `sqlx::query`/`query_as` touching an owned table gets a
   `tenant_id = $N` predicate (SELECT/UPDATE/DELETE) or bind (INSERT),
   sourced only from `CurrentUser.tenant_id`/`TenantContext` — never
   path/body/query params. Cross-service Redis Stream `tenant_id` fields
   also need the same treatment on the producer side (test with the
   consumer's own R2 pass in mind — see `[[feedback-cross-service-stream-tenant-break]]`).

See also `crates/skauswatch-testkit/src/jwt.rs::mint_claims_token` — shared
test helper for minting `Claims`-shaped tokens with a given tenant, already
used by manager/monitor/vault/codescan-backend's test suites.

**Stream-consumer variant (s3scan/scanner/worker-codescan/worker-vault-sync):**
steps 1-5 above are JWT/REST-specific and don't apply — these services have
no JWT, no `Claims`, no `tenant_middleware`. Instead: `tenant_id` (stringified
UUID) is a field on every Redis Stream entry, stamped by the producer
(manager) from *its* authenticated caller. The consumer's job is narrower:
add a required-field parse (`ParseError::MissingField`/`InvalidUuid` on
missing/malformed — never default), thread the resulting `tenant_id` through
every task-variant struct, and use it as a `WHERE tenant_id = $N` predicate
on every DB call *including calls keyed by an internal serial primary key*
(e.g. `job_pk`) — defense in depth per §4 of the design doc, even though that
pk itself was already resolved through a tenant-scoped lookup. Watch for a
job-level task that **re-dispatches child tasks onto the same stream**
(s3scan's `enumerate` → per-object re-publish): the re-dispatch fields
function needs the tenant threaded through too, or the worker's own
fail-closed parser will reject the message it just published to itself.
Confirmed s3scan's R2 pass (2026-07-31) landed cleanly this way, concurrent
with manager's producer-side stamping on the same three task shapes
(`scan_task_fields`/`submit_task_fields`/`adhoc_task_fields`).
