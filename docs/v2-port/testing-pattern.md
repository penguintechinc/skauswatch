# Testing pattern — the shared harness, and how to use it per service

Foundation for the workspace-wide coverage push (target: `cargo llvm-cov
--workspace --fail-under-lines 90`, currently ~51%). This doc is the spec
for fanning the pattern proven on `codescan-backend` out to every other
service. It covers: the harness API, how to write an authed/unauthed
handler test, a DB test, the coverage-exclusion policy, and how to run
coverage locally with real databases.

## Why a real Postgres, not a mock

Every service's `AppStateInner.db` field is a concrete `sqlx::PgPool`, not
a trait object — handlers call `sqlx::query(...).fetch_one(&state.db)`
directly. Trait-abstracting the DB layer purely to make it mockable would
be a real (and risky) refactor of production code across every service, so
this harness does not do that. Instead, `skauswatch-testkit` gives every
DB-backed test a real, isolated Postgres schema. This is deliberate per the
task brief: **do not mock the DB layer — test against real Postgres.**

## The harness: `crates/skauswatch-testkit`

Added as a `[dev-dependencies]` entry (`skauswatch-testkit = { workspace =
true }`) in each service's `Cargo.toml`. Three modules:

### `skauswatch_testkit::db::test_pool`

```rust
pub async fn test_pool(migrations_dir: impl AsRef<Path>) -> sqlx::PgPool
```

Provisions a **fresh, uniquely-named Postgres schema** (`test_<uuid>`) on
the ambient Postgres instance, applies the caller's sqlx migrations into
it via a runtime `sqlx::migrate::Migrator`, and returns a pool whose
pooled connections all pin their `search_path` to that schema via
`PgPoolOptions::after_connect`. Call it once per test:

```rust
let pool = skauswatch_testkit::db::test_pool(
    concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")
).await;
```

This gives full isolation between parallel `cargo nextest`/`cargo test`
tests **without** the usual transaction-per-test-rollback trick — that
trick would require every handler to take a `Transaction` as its executor
instead of `&PgPool`, which is not the shape `AppStateInner.db` has today
in any service. Schema-per-test works with the pool shape services already
have, at the cost of one migration run per test (cheap: these are small
per-service schemas, tens of milliseconds).

Connection parameters come from `DB_HOST`/`DB_PORT`/`DB_NAME`/`DB_USER`/
`DB_PASS` env vars (same names `skauswatch_db::DbConfig` reads in
production), with test-friendly defaults (`localhost:5432`,
`postgres`/`postgres`/`postgres`) matching the CI service container and a
plain local `docker run postgres:17-bookworm`. **Panics loudly** (not a
silent skip) if Postgres is unreachable or migrations fail — a test-infra
fault should fail the build, not quietly report 0% DB coverage.

No automatic schema cleanup — CI's Postgres container is destroyed after
the job, and local dev is expected to be a throwaway container too (see
`make db-test-up`/`db-test-down` below). Orphaned schemas in a long-lived
local Postgres are harmless; drop them manually or recreate the container
if it matters.

### `skauswatch_testkit::jwt`

```rust
pub fn mint_access_token(secret: &str, sub: &str, role: &str) -> String
pub fn mint_expired_access_token(secret: &str, sub: &str, role: &str) -> String
```

Thin wrappers over `skauswatch_auth::issue_service_token` — mints the
shared manager-issued access-token shape (`{sub, role, type: "access",
exp, iat}`, HS256). This is the **same wire shape** consumed by both
patterns in the codebase (see "Router-wide vs per-handler auth" below), so
one minting helper covers every service.

### `skauswatch_testkit::license`

```rust
pub fn dev_license(product: &str) -> Arc<LicenseClient>   // flags/features pass
pub fn gated_license(product: &str) -> Arc<LicenseClient> // flags/features denied (release_mode)
```

Replaces the `dev_license()`/`gated_license()` closures that were
hand-copied into every `codescan-backend` route test module. New test
modules should call `skauswatch_testkit::license::dev_license("skauswatch")`
directly instead of redefining a local copy; existing duplicated copies
can be migrated opportunistically, not as a blocking prerequisite.

## Per-service wiring: `for_tests_with_db`

Every service already has an `AppStateInner::for_tests(license: ...) ->
AppState` constructor (manager, pki, monitor, vault, codescan-backend all
follow this exact pattern) that builds a **lazy, unconnected** pool via
`PgPoolOptions::connect_lazy(...)` — fine for auth/license/validation-gate
tests that never reach a query, useless for anything that does.

The fan-out pattern: add a sibling constructor that takes a real pool,
and have `for_tests` delegate to it so there is one source of truth for
the rest of the fixed test config (JWT secret, crypto keys, etc.):

```rust
// for_tests keeps its existing signature and callers unchanged:
pub fn for_tests(license: Arc<LicenseClient>) -> AppState {
    let db = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://test:test@127.0.0.1:1/test")
        .unwrap_or_else(|e| panic!("lazy test pool: {e}"));
    Self::for_tests_with_db(license, db)
}

// New: same fixed test config, real pool.
pub fn for_tests_with_db(license: Arc<LicenseClient>, db: PgPool) -> AppState {
    Arc::new(Self {
        license,
        db,
        auth: AuthSettings { jwt_secret: "test-secret".to_owned() },
        // ...whatever other fixed test fields the service has...
    })
}
```

Then a small per-service test helper (`codescan-backend` puts this in
`src/routes/test_support.rs`, already `#[cfg(test)]`-gated) ties the two
together:

```rust
pub(crate) async fn db_state(license: Arc<LicenseClient>) -> AppState {
    let pool = skauswatch_testkit::db::test_pool(
        concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")
    ).await;
    AppStateInner::for_tests_with_db(license, pool)
}
```

Services without their own `migrations/` directory (none currently in
scope; check `find services/<name> -iname migrations`) have no DB-backed
tests to write via this path — skip `db_state`/`for_tests_with_db`
entirely for them.

## Writing a handler test

### Unauthed (401) — already the established pattern, keep doing this

```rust
#[tokio::test]
async fn status_requires_auth() {
    let server = test_server(AppStateInner::for_tests(dev_license()));
    let resp = server.get("/api/v1/codescan/status").await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}
```

### Authed, DB-backed (the new part)

```rust
#[tokio::test]
async fn status_reports_zero_queue_depth_against_an_empty_db() {
    let state = crate::routes::test_support::db_state(dev_license()).await;
    let token = crate::routes::test_support::sign_token(&state, "1", "viewer");
    let server = test_server(state);
    let resp = server.get("/api/v1/codescan/status")
        .authorization_bearer(token)
        .await;
    resp.assert_status_ok();
}
```

### DB test with seed data + FK dependency

Insert prerequisite rows directly via `sqlx::query` against `state.db`
(bypassing the REST surface) so each test stays focused on the table it's
actually exercising — see `seed_repo_config` in
`services/codescan-backend/src/routes/reviews.rs` for the pattern (a
`codescan_reviews` row needs a valid `repo_config_id` FK).

### License-gate 403 path

```rust
let state = AppStateInner::for_tests(gated_license());   // release_mode = true
let token = test_support::sign_token(&state, "1", "admin");
// ... expect 403 with the fixed license-required message
```

## Router-wide vs per-handler auth — divergence the fan-out must handle

Two different auth wiring patterns exist across services, both consuming
the *same* JWT shape, so `skauswatch_testkit::jwt` works for either — but
the router construction in tests differs:

| Pattern | Services | Test router shape |
|---|---|---|
| **Per-handler extractor** | codescan-backend (`CurrentUser`/`AdminOnly`/`MaintainerOnly`), manager | Each handler declares the extractor as a function parameter; a route with no auth requirement simply omits it. Build the test router the same way production does (`routes::router(state)` or a per-module `router()` merged in) — no extra layer needed in tests. |
| **Router-wide middleware** | pki, sshca (`.layer(axum::middleware::from_extractor_with_state::<skauswatch_auth::AuthenticatedCaller, _>(state.clone()))`) | The *entire* router requires a valid token — there is no route-by-route opt-out. Test routers must apply the same `.layer(...)` the production router does, or every request (including ones that "shouldn't" need auth) will 401. Don't hand-build a bare `Router::new().route(...)` without the layer — it won't match production behavior. |

Both patterns decode with `skauswatch_auth::verify_service_token` /
`AuthenticatedCaller`, so `skauswatch_testkit::jwt::mint_access_token(secret,
sub, role)` mints a token either pattern accepts — only the router
assembly in the test differs.

## gRPC services (pki, manager)

`PKIService`/`ManagerService`/`S3ScanService` (tonic) are plain
`#[tonic::async_trait] impl ... for ...Impl` blocks — no network required
to test them. Construct the service struct directly (same `AppState`
wiring as above — `for_tests_with_db` if the RPC touches the DB) and call
its trait methods with `tonic::Request::new(...)`:

```rust
let svc = PKIServiceImpl { state: AppStateInner::for_tests_with_db(...) };
let resp = svc.issue_cert(tonic::Request::new(IssueCertRequest { .. })).await;
```

Auth is via `skauswatch_auth::verify_grpc_bearer(metadata, secret)` reading
the `authorization` gRPC metadata entry — mint a token with
`skauswatch_testkit::jwt::mint_access_token` and attach it as metadata:

```rust
let mut req = tonic::Request::new(..);
req.metadata_mut().insert("authorization",
    format!("Bearer {token}").parse().unwrap_or_else(|e| panic!("metadata: {e}")));
```

No harness changes needed for gRPC specifically — the same `db::test_pool`
and `jwt::mint_access_token` cover it; only the "router" being tested is a
direct trait-method call instead of an HTTP request.

## Coverage exclusion policy

`--ignore-filename-regex '(^|/)src/main\.rs$|(^|/)src/bin/'` (CI: both the
`test` inputs are unaffected, only `coverage` job; local: `make coverage`).

Excludes **only**: each service's `src/main.rs` (CLI parsing, `serve()`
wiring, the `healthcheck` subcommand — exercised by the container
HEALTHCHECK / smoke-test path, not unit tests) and anything under a
`src/bin/` directory (one-off utility binaries, e.g. `pki`'s
`src/bin/x509_parity.rs`).

**Nothing else is excluded.** Every handler, route, DB-layer function,
service/business-logic module, and crypto routine must be covered by real
tests — do not add files to this regex to hit the number faster. If a
file seems architecturally untestable, that's a design smell to flag, not
a reason to exclude it.

## Running coverage locally with a database

```bash
make db-test-up          # throwaway Postgres:17-bookworm + Valkey:8-bookworm containers
export DB_HOST=localhost DB_PORT=5432 DB_USER=postgres DB_PASS=postgres DB_NAME=postgres
export REDIS_URL=redis://localhost:6379/0
make coverage             # or: make test / make smoke-test
make db-test-down         # tear down when finished
```

`make db-test-up` blocks until Postgres reports ready (`pg_isready`) before
returning. CI wires the identical images via GitHub Actions `services:` in
`.github/workflows/rust.yml` (`test` and `coverage` jobs) — same digests,
same default credentials, so a green local run and a green CI run mean the
same thing.

## `codescan-backend` — the proof

Before this pass: DB-touching handlers (repos/reviews/plans/credentials
CRUD, `status`) were covered only on their pre-DB paths (401 unauthenticated,
403 wrong-role, 403 license-gated) — the actual query code was
0%-exercised. `error.rs` had no tests at all. Crypto (`crypto.rs`) was
already fully covered and untouched here.

After this pass: every REST handler has an authed-success path exercising
real Postgres (list/create/get/update/delete round trips, conflict/404
branches, FK-dependent seed data for reviews), `error.rs` has full
`ApiError`/`ApiJson`/fallback coverage, and the service reaches ≥90% lines
excluding `src/main.rs`. See the PR/report for the exact before → after
percentages from `cargo llvm-cov -p skauswatch-codescan-backend`.

## What the fan-out does per service

1. Confirm the service has a `migrations/` dir (skip DB-backed tests
   entirely if not — some services may be logs-only/no-DB).
2. Add `skauswatch-testkit = { workspace = true }` to `[dev-dependencies]`.
3. Add `for_tests_with_db` next to the existing `for_tests` in `state.rs`,
   have `for_tests` delegate to it.
4. Add a `db_state(license) -> AppState` helper (wherever the service's
   test-support code already lives, or a new `#[cfg(test)]` module).
5. Identify the auth pattern (per-handler extractor vs router-wide layer —
   see table above) and build the test router accordingly.
6. Write authed-success + error-branch tests for every handler that
   currently only has 401/403 coverage.
7. Add tests for any currently-untested `error.rs`/`ApiError` module.
8. Run `make db-test-up`, then `cargo llvm-cov -p <service> --locked
   --ignore-filename-regex '(^|/)src/main\.rs$|(^|/)src/bin/'
   --summary-only` and confirm ≥90%.
