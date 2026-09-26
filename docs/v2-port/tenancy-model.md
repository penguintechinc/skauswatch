# Tenancy model — retrofit spec (cutover-blocking)

Canonical design for multi-tenant isolation across skauswatch v2. R2
implementation agents follow this doc exactly; deviations require a spec
update here first, not a silent per-service choice.

**Current state confirmed by inspection: there is no `tenants` table
anywhere in the codebase today.** `skauswatch-auth::Claims` (the shared
JWT model with `tenant`) and `tenant_middleware`/`TenantContext` exist
(`crates/skauswatch-auth/src/lib.rs`) but are adopted by **zero** services
— every service still runs its own local `AccessClaims`/`Claims` shape
with no tenant enforcement, or (monitor) decodes `Claims` directly without
ever calling `tenant_middleware`. `codescan-backend` is the one partial
exception: its schema and queries already carry `tenant_id`, but it is
read from the **client-supplied request body** (`repos.rs`/`reviews.rs`,
`body.tenant_id`) — a direct violation of "client cannot set tenant" and
must be fixed, not treated as done.

## 1. `tenants` table

Owned by **manager** (the auth root — it's the only service that mints
JWTs). New migration `services/manager/migrations/0002_tenancy.sql`:

```sql
CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        VARCHAR(63) UNIQUE NOT NULL,   -- URL/subdomain-safe, immutable
    name        VARCHAR(255) NOT NULL,
    status      VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    created_at  TIMESTAMP NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP
);
```

`id` (UUID) is what travels in `Claims.tenant` — matches
`skauswatch-auth::Tenant(pub String)`'s `String` shape (stringified UUID),
and every downstream `tenant_id` column below is `UUID`, not the service's
native PK type (`INTEGER`/`BIGINT`), since tenant identity is
manager-issued and global, not local to any one service's ID space.

## 2. `users.tenant_id` + login/refresh

- `ALTER TABLE users ADD COLUMN tenant_id UUID NOT NULL REFERENCES tenants(id);` in the same migration. No default — every existing/seeded user row must be backfilled to the bootstrap tenant (see §8) before this constraint is added, or the migration fails closed (correct behavior, not a bug to work around).
- `services/manager/src/auth/mod.rs`'s `AccessClaims`/`RefreshClaims` are **replaced** by `skauswatch_auth::Claims` for the access token (keeps `sub`, drops the ad-hoc `role`/`type` shape, adds `iss`/`aud`/`scope`/`tenant`/`teams`/`roles`). This is a wire-contract break for any v1 ENDPOINT/webui client still expecting the old shape — flag to user (§8).
- `routes/auth.rs::login` — after password verification, `SELECT tenant_id FROM users WHERE id = $1` (already have the row; add `tenant_id` to `LoginRow`) and stamp it into the minted `Claims.tenant`. `role` collapses into `Claims.scope` via a role→scope bundle expansion (per `security.md`'s bundles: admin/maintainer/viewer) — a new helper in `skauswatch-auth`, not hand-rolled per call site.
- Refresh flow (`issue_token_pair`/`refresh`): `refresh_tokens` gains `tenant_id UUID NOT NULL` (denormalized from `users`, stamped at issuance) so rotation never has to re-derive tenant from a second `users` join before re-minting — read it straight off the row alongside `role`.
- `ServiceClaims` (machine/service tokens for pki/sshca gate) stays tenant-free by design — those are *caller-identity* tokens for service-to-service auth, not user-scoped resource access; see §3 for how tenant travels to those services instead.

## 3. Tenant provenance per service

| Service | Surface | Tenant source | Enforcement |
|---|---|---|---|
| manager | REST (`/api/v1/*`) | JWT via `tenant_middleware` → `TenantContext` | Reject (403) if absent |
| vault | REST | JWT via `tenant_middleware` (already decodes `tenant`→`CurrentUser.tenant_id`, currently unused — wire it up) | Reject (403) if absent |
| codescan-backend | REST | JWT via `tenant_middleware` — **replaces** client-body `tenant_id` in `repos.rs`/`reviews.rs` | Reject (403); body `tenant_id` field removed from `CreateRepoConfig`/request DTOs |
| monitor | REST | JWT via `tenant_middleware` (currently decodes `Claims` ad hoc — switch to the shared middleware for consistency) | Reject (403) if absent |
| pki | gRPC (`PKIService`) + REST (`AuthenticatedCaller`, no local user DB) | gRPC metadata key **`x-tenant-id`**; REST header **`X-Tenant-ID`** stamped by the calling service (manager), never the end client | Reject (`UNAUTHENTICATED`/403) if absent or empty |
| sshca | Same shape as pki (`AuthenticatedCaller`, no local user DB) | Same as pki: `x-tenant-id` gRPC metadata / `X-Tenant-ID` REST header | Reject if absent |
| s3scan | Redis Streams (`s3scan:tasks`) — gRPC `S3ScanService` surface exists but has no in-repo caller today (confirmed: manager dispatches via streams, not gRPC) | Stream field **`tenant_id`** on every entry (job-level and gRPC-shaped variants alike) | Reject/drop-with-error if absent — mirror `worker-codescan`'s existing `missing_tenant_id_is_an_error` pattern |
| scanner | Redis Streams (`scanner:tasks`) | Stream field **`tenant_id`** | Reject/drop-with-error if absent |
| worker-codescan | Redis Streams (`codescan:tasks`) | Stream field **`tenant_id`** — **already present**, just prefixed `_tenant_id`/unused; wire it into every query in this migration | Already validated at parse (`missing_tenant_id_is_an_error`) — just needs to be *used*, not just carried |
| worker-vault-sync | Consumes vault's sync stream | Stream field `tenant_id` (add — not present today) | Reject if absent |
| endpoint-agent-facing ingestion (manager `endpoint_events`/`endpoint_agents`) | REST (agent HMAC auth, not JWT) | Agent's `tenant_id` resolved server-side from `endpoint_agents.tenant_id` (looked up by `agent_id`, never trusted from the request payload) | Reject if agent has no tenant on file |

**Rule for every row in this table:** the tenant value is never accepted
from a field the remote party fully controls without a trust boundary
(client JSON body, unauthenticated header) — it is always either (a)
decoded from a signed JWT, (b) stamped by the *upstream* trusted service
(manager) into gRPC metadata / a stream field it produced, or (c) resolved
server-side from an already-authenticated identity (agent_id → tenant_id
lookup). A receiver missing (a)/(b)/(c) rejects the request/message; it
never falls back to a default tenant in production.

## 4. Canonical sqlx patterns (supersedes the SeaORM example in `skauswatch-auth`)

The doc comment on `TenantContext` in `crates/skauswatch-auth/src/lib.rs`
(lines ~219–230) shows a SeaORM `Entity::find().filter(...)` example —
**wrong for this codebase**, which uses sqlx exclusively. Correct during
R2a (the auth-crate touch-up); until then, treat the block below as
authoritative.

```rust
// Extractor order: TenantContext runs via tenant_middleware ahead of the
// handler; pull it in as a normal axum extractor.
async fn list_widgets(
    tenant: TenantContext,
    State(state): State<AppState>,
) -> Result<Json<Vec<Widget>>, ApiError> {
    let rows = sqlx::query_as::<_, Widget>(
        "SELECT id, name, created_at FROM widgets WHERE tenant_id = $1 ORDER BY id",
    )
    .bind(tenant.tenant.as_str().parse::<uuid::Uuid>().map_err(|_| ApiError::Unauthorized("invalid tenant".into()))?)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

// UPDATE/DELETE: tenant_id in the WHERE clause is mandatory even when
// filtering by primary key — never trust the path id alone.
sqlx::query("UPDATE widgets SET name = $1 WHERE id = $2 AND tenant_id = $3")
    .bind(&body.name).bind(widget_id).bind(tenant_uuid)
    .execute(&state.db).await?;

// INSERT: tenant_id is stamped from TenantContext, never from the request body.
sqlx::query("INSERT INTO widgets (id, tenant_id, name) VALUES ($1, $2, $3)")
    .bind(uuid::Uuid::new_v4()).bind(tenant_uuid).bind(&body.name)
    .execute(&state.db).await?;
```

One-liner for the report: **`WHERE tenant_id = $N` (bound from
`TenantContext`/stream field, never from path/body) on every SELECT,
UPDATE, and DELETE; every INSERT stamps `tenant_id` the same way.**

A `uuid::Uuid` parse helper (`TenantContext::tenant_uuid() -> Result<Uuid,
ApiError>`) belongs in `skauswatch-auth` itself, added alongside the R2a
doc fix — every service needs the same parse-or-403 step, don't repeat it
seven times.

## 5. Full table inventory + migration order

Owner = the service whose migration adds/alters the table. Consumer =
service that queries it but doesn't own its schema (must wait for the
owner's migration to land first — **owners before consumers**, this is
the apply-order rule).

| Service | Owner tables needing `tenant_id` | Consumer tables (already tenant-scoped by owner) |
|---|---|---|
| **manager** | `users`* , `refresh_tokens`, `threat_indicators`, `alerts`, `approval_requests`, `audit_logs`, `endpoint_agents`, `endpoint_events`, `s3_scan_schedules` (9) | — |
| **vault** | `vault_secrets`, `vault_secret_versions`, `vault_secret_owners`, `vault_jit_requests`, `vault_jit_grants`, `vault_one_time_secrets`, `vault_cloud_integrations`, `vault_audit_log` (8) | — |
| **worker-vault-sync** | `vault_cloud_sync_state` (1) | `vault_cloud_integrations` (vault-owned) |
| **pki** | `x509_certificates`, `ssh_certificates`, `crl_entries`, `pki_audit_log` (4) | — |
| **s3scan** | `s3_bucket_configs`, `s3_scan_jobs`, `s3_scan_results`, `adhoc_scan_results` (4) | `s3_scan_schedules` (manager-owned) |
| **scanner** | `scanner_scan_results` (1) | — |
| **codescan-backend** | `codescan_repo_configs`*, `codescan_reviews`*, `codescan_git_credentials`, `codescan_review_comments`, `codescan_review_detections`, `codescan_issue_plans`*, `codescan_provider_usage`, `codescan_license_policies`, `codescan_license_detections`, `codescan_license_violations` (10 — 3 marked `*` already have a `tenant_id BIGINT` column, unenforced/client-supplied; **change type to UUID + enforce from JWT**, don't just leave as-is) | — |

Total: **~37 tables** (9+8+1+4+4+1+10) need a `tenant_id UUID NOT NULL`
column (or type-fix + enforcement for the 3 codescan tables that already
have one), each with a composite index `(tenant_id, <hot lookup column>)`
— e.g. `(tenant_id, status)` on `alerts`/`x509_certificates`,
`(tenant_id, id)` everywhere else as the base case. Query-site count
(every `sqlx::query`/`query_as` call needing a `tenant_id` predicate
added) is larger than the table count — expect on the order of 100–150
call sites workspace-wide based on the auth/routes files read for this
spec; each R2 service agent should grep its own `src/` for
`sqlx::query` and treat every hit as a checklist item, not estimate from
this number.

`codescan_git_credentials` is keyed by `user_id`, not directly by tenant —
add `tenant_id` denormalized from the owning user anyway (needed for
tenant-scoped listing/audit without a join on every query) but the
authoritative uniqueness/ownership boundary stays `user_id`.

**Migration apply order (R2 sequencing):**
1. **Keystone**: manager's `0002_tenancy.sql` (`tenants` table + `users.tenant_id` + `refresh_tokens.tenant_id`) — everything else is a consumer of `tenants.id` even without an FK (cross-database, no real FK possible; treat as a logical reference, enforced by application-level validation, not `REFERENCES`).
2. **Fan-out (parallel, independent of each other, all depend on step 1 only for the *value*, not a schema FK)**: vault, pki, s3scan (+ worker-vault-sync's `vault_cloud_sync_state` right after vault), scanner, codescan-backend, monitor (no schema of its own — just needs its query layer switched to filter on `TenantContext`, plus `Claims`/`tenant_middleware` adoption).
3. **Auth-crate touch-up (can run anytime after step 1, does not block fan-out)**: fix the SeaORM doc-comment example in `skauswatch-auth` per §4; add the `tenant_uuid()` helper; add the role→scope bundle-expansion helper for manager's login flow.

## 6. Legitimate cross-tenant operations

Per `security.md`: only a separately-issued, short-lived, audit-logged
super-admin token may cross tenants; every other endpoint filters. Known
cross-tenant-shaped endpoints in the current code, and what to do with
each — **do not "fix" these into per-tenant filtering without reading
this row first**:

| Endpoint | Current behavior | Disposition |
|---|---|---|
| pki `GET /api/v1/expiring`, `POST /api/v1/cleanup` (`routes/common.rs`) | Scans all `x509_certificates`/`ssh_certificates` with no tenant filter | **Superseded during the R2 pki/sshca pass — left cross-tenant by design**, not filtered. Revisited as operator/maintenance sweeps (an expiry-warning or expired-cleanup job spanning every tenant), authorized in principle by a `super-admin`-scoped caller per `security.md`. pki's `ServiceClaims` carries no scope claim today (see that type's docs), so this is currently enforced only by deployment-level access control (which services can reach pki's REST port) — a real gap, called out in both handlers' doc comments, to close once pki's auth model grows a scope claim. |
| pki `GET /api/v1/audit`, `GET /api/v1/statistics`, `GET /api/v1/ca/info` (`routes/common.rs`) | All-tenant aggregate today | **Add `tenant_id` filter** to `audit`/`statistics` (per-tenant views). `ca/info` (CA metadata, not certificate data) may legitimately stay global — the CA itself isn't tenant-scoped, only the certificates it issues are; confirm with user if a future multi-CA-per-tenant model is planned (out of scope for v2.0). |
| manager audit/compliance review surfaces (`audit_logs`, if/when an admin UI queries across tenants) | Not yet built | Gate behind a `super-admin` scope per `security.md`, never the default `admin` role/scope — implement as an explicit `audit:cross_tenant` scope, separately issued, not inferred from `role=admin`. |
| `--dev` single-user flag | Unlocks premium features, not tenant scoping | Orthogonal — `--dev` mode still operates within exactly one tenant (the bootstrap tenant, §8); it never grants cross-tenant visibility. |

Anything not listed above and not carrying an explicit
`super-admin`/`*_cross_tenant` scope check gets the standard `WHERE
tenant_id = $N` filter, no exceptions.

## 7. Per-service R2 implementation checklist

1. Wait for owner migration (manager's `0002_tenancy.sql` first; then this service's own migration, see §5 order).
2. Add `tenant_id UUID NOT NULL` to every owned table (§5); composite index per hot query path.
3. Add/switch to `tenant_middleware` (REST) or the `x-tenant-id`/stream-field contract (gRPC/stream, §3); delete any local ad-hoc `Claims`/`AccessClaims` tenant handling that duplicates it.
4. Grep `src/` for every `sqlx::query`/`query_as` touching an owned table; add `tenant_id = $N` to every SELECT/UPDATE/DELETE `WHERE`, and a `tenant_id` bind to every INSERT (§4 pattern).
5. Remove any client-supplied `tenant_id` request-body/query-param field (codescan-backend: `repos.rs`, `reviews.rs` DTOs) — replace with the middleware-derived value.
6. Update/add tests: one regression per removed trust boundary (mirrors `worker-codescan`'s `missing_tenant_id_is_an_error` pattern) plus a cross-tenant-isolation test (tenant A's token can't read/write tenant B's row) per table.
7. Re-run `cargo llvm-cov` — tenant filtering must not drop the workspace below the 90% floor; new branches (missing-tenant rejection paths) need their own test coverage, not just the happy path.

## 8. Decisions needing user confirmation

- **Tenant provisioning model**: recommend **admin-provisioned only for v2.0** (no self-serve signup endpoint exposed) + seed exactly one default/bootstrap tenant at first migration so existing `/auth/register` (currently open, viewer-role self-service) keeps working by attaching new registrants to that bootstrap tenant. Self-serve multi-tenant signup → defer to v2.1 backlog (`docs/v2-port/v2.1-backlog.md`). **Needs user sign-off**: does `/auth/register` stay open at all in v2.0, or become admin-only now that tenancy exists?
- **Bootstrap tenant + first admin**: recommend a migration-time seed (fixed slug e.g. `default`, fixed UUID for reproducibility across environments) rather than a runtime bootstrap script — simpler, idempotent via `INSERT ... ON CONFLICT DO NOTHING`. **Needs user sign-off** on the fixed UUID/slug values and whether alpha/beta/prod each get their own bootstrap tenant or share the seed.
- **`--dev` flag interaction**: confirmed compatible as designed (§6) — `--dev`'s "≤1 user" cap composes naturally with "exactly 1 bootstrap tenant" (single-user + single-tenant is the same constraint from two angles). No open question here, noted for completeness only.
- **`Claims`/`AccessClaims` wire-break**: replacing manager's `AccessClaims` with the house `Claims` shape changes the JWT payload shape (adds `iss`/`aud`/`scope`/`tenant`/`teams`, drops the old flat `role`). Per the v2 program's "never hit prod" invariant this should be a non-issue, but **confirm no external fielded client (ENDPOINT agents, webui) hardcodes the old claim shape** before R2 lands this — the manager's own `services/manager/grpc/mod.rs` doc comment already asserts ENDPOINT agents use REST HMAC (not JWT) for their own auth, which supports "safe to change," but this should be explicitly confirmed, not assumed from one comment.
