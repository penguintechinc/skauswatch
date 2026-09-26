# OpenAPI Generation Pattern (utoipa) — v2 Rust Services

Established end-to-end on `services/codescan-backend` (2026-07-28) per
`backend.md`'s OpenAPI standard: every REST service MUST publish a
generated (not hand-written) `openapi/v{major}.yaml`, and the live spec/docs
route must sit behind the same auth as the rest of the API, with the login
endpoint as the sole unauthenticated exception. This doc is the pattern
every other v2 service replicates; deviations should be a deliberate,
documented choice, not an oversight.

`utoipa = "=5.5.0"` (features `axum_extras`, `chrono`, `uuid`) is already a
`[workspace.dependencies]` entry — add it to a service's own `Cargo.toml`
with `utoipa = { workspace = true }`. If the service needs the `openapi`
CLI subcommand to emit true YAML (see below), add the `yaml` feature on top
in the *service's* `Cargo.toml` only: `utoipa = { workspace = true,
features = ["yaml"] }`. This is a normal additive-feature Cargo pattern and
does not touch the root `Cargo.toml`; it does add new transitive lock
entries (`serde_yaml` and friends) to the shared `Cargo.lock`, which is
expected — regenerate via a plain `cargo check -p <crate>` (no `--locked`)
before running `--locked` tests/clippy.

## 1. Annotate DTOs with `#[derive(utoipa::ToSchema)]`

Add `utoipa::ToSchema` alongside the existing derives on every request body
struct and every `sqlx::FromRow, Serialize` response-row struct:

```rust
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct RepoConfig { /* ... */ }

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateRepoRequest { /* ... */ }
```

`chrono::DateTime<Utc>`, `chrono::NaiveDateTime`, `Option<serde_json::Value>`
(arbitrary/open object schema), and all primitive/`Option`/`Vec` field types
already used in this codebase are supported by utoipa out of the box with
the `chrono` feature already enabled workspace-wide — no extra work needed
per field.

**Handlers that build their response with `serde_json::json!(...)` instead
of serializing a typed struct** (the majority in this codebase — the house
convention is bare `{"error": msg}` / `{"message": ..., "config": ...}`
envelopes assembled ad hoc) need a **documentation-only mirror struct**:
deriving both `Serialize` (so `dead_code` doesn't flag its fields as
"never read" — the struct is never actually constructed at runtime, but the
generated `Serialize::serialize` body reads every field, which is enough to
satisfy the lint) and `utoipa::ToSchema`, named for what it documents and
referenced only from the `#[utoipa::path(responses(...))]` clause:

```rust
/// Documentation-only mirror of `create_repo`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RepoCreateResponse {
    message: String,
    config: RepoConfig,
}
```

For a genuinely merged/hand-built body (e.g. `get_review` flattens a row
plus a `comments` array via `serde_json::Value` manipulation), use
`#[serde(flatten)]` on the doc-only struct — utoipa's derive honors it and
produces an `allOf` composition:

```rust
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewDetailResponse {
    #[serde(flatten)]
    review: ReviewRow,
    comments: Vec<ReviewComment>,
}
```

**Shared error shapes** live once in `error.rs`, not duplicated per route
file — `ApiError`'s bare `{"error": msg}` variants (`BadRequest`,
`Unauthorized`, `Forbidden`, `NotFound`, `Conflict` when its body happens to
be bare) all map to one `ErrorResponse { error: String }`; the
`Validation` variant maps to `ValidationErrorResponse { error: String,
details: Vec<serde_json::Value> }`. Import these into every route file that
needs them rather than redefining locally.

Axum `Query<T>` extractor structs get `#[derive(utoipa::IntoParams)]`
alongside `Deserialize` — referenced as `params(ListQuery)` in the path
macro rather than listed in `components(schemas(...))`:

```rust
#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    page: Option<i64>,
    per_page: Option<i64>,
}
```

**Visibility:** any type or handler function referenced from the crate-wide
`ApiDoc` aggregation (below) must be at least `pub(crate)` — plain private
items in a route submodule aren't reachable from `routes::openapi`. Elevate
handler `async fn`s from private to `pub(crate) async fn`, and DTO/response
structs from private to `pub(crate)`. Don't use plain `pub` — that would
make them part of the crate's external API surface and trip the
workspace's `missing_docs = "warn"` lint (which becomes a hard error under
`-D warnings`); `pub(crate)` is invisible outside the crate so `missing_docs`
doesn't apply. A `Query`/`IntoParams` struct used only within its own file's
handlers can stay module-private *unless* that handler itself is
`pub(crate)`, in which case the query type must match (Rust's
`private_interfaces` lint — `-D warnings` — fires otherwise: a `pub(crate)`
fn cannot take a private type in its signature).

## 2. Annotate every handler with `#[utoipa::path(...)]`

```rust
#[utoipa::path(
    get,
    path = "/api/v1/codescan/repos/{repo_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("repo_id" = i64, Path, description = "Repository configuration id")),
    responses(
        (status = 200, description = "Repository configuration", body = RepoConfig),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 404, description = "Configuration not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_repo(/* ... */) -> Result<Response, ApiError> { /* ... */ }
```

- `path` must exactly match the full mounted path (including the `/api/v1`
  prefix applied by the router's `.nest("/api/v1", ...)`), not just the
  route-local suffix passed to `.route(...)`.
- `security(("bearer_jwt" = []))` on **every** handler — see the security
  scheme registration in step 3. Every route in every v2 service to date
  requires a bearer JWT; there's no scoped-OAuth2 flow variant needed yet.
- List every status code the handler can actually return, each pointing at
  the real (or documentation-only mirror) response type. Include the
  license-gate 403 wherever `license_denied()` gates the route, the 401 on
  every authenticated route, and 409/404/400 wherever the handler's own
  logic produces them. It's fine — and expected — for one status code
  (typically 400) to be documented with only one of two possible real
  shapes when a handler can produce either a bare validation error and a
  business-rule error with the same status; pick the more specific one and
  note the simplification rather than modeling `oneOf`.
- Query-extractor handlers: `params(ListQuery)` (the `IntoParams` type from
  step 1) instead of hand-listing each field.
- Mutating handlers: `request_body = CreateRepoRequest`.

## 3. Aggregate into `ApiDoc` + register the bearer scheme

Put this in its own `routes/openapi.rs` submodule (not directly in
`routes/mod.rs`) — it's a distinct concern from route assembly and the file
gets long:

```rust
#[derive(utoipa::OpenApi)]
#[openapi(
    info(title = "...", version = "1", description = "..."),
    paths(
        status::codescan_status,
        repos::list_repos, repos::create_repo, /* ...every handler... */
    ),
    components(schemas(
        ErrorResponse, ValidationErrorResponse,
        repos::RepoConfig, repos::RepoListResponse, /* ...every DTO/response type... */
    )),
    tags(
        (name = "codescan", description = "..."),
        (name = "credentials", description = "..."),
    ),
    modifiers(&SecurityAddon),
)]
pub(crate) struct ApiDoc;

struct SecurityAddon;
impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_jwt",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );
        }
    }
}
```

`IntoParams` types (the `ListQuery` structs) are **not** listed in
`components(schemas(...))` — they're inlined as path/query parameters, not
referenced as a body schema.

Declare the submodule `pub(crate) mod openapi;` in `routes/mod.rs` (not
plain `mod openapi;`) so `main.rs` can reach `routes::openapi::ApiDoc` for
the emit subcommand in step 4.

## 4. Emit subcommand — generate, never hand-write `openapi/v{major}.yaml`

Add an `Openapi` variant to the service's clap `Command` enum and print the
YAML:

```rust
#[derive(Subcommand)]
enum Command {
    Serve,
    Healthcheck,
    /// Print the generated OpenAPI 3.x spec (YAML) to stdout and exit.
    Openapi,
}

fn print_openapi() -> anyhow::Result<()> {
    use utoipa::OpenApi;
    let yaml = routes::openapi::ApiDoc::openapi()
        .to_yaml()
        .map_err(|e| anyhow::anyhow!("serialize openapi spec: {e}"))?;
    print!("{yaml}");
    Ok(())
}
```

`to_yaml()` requires the `yaml` utoipa feature (see the intro) — without it
only `to_json()`/`to_pretty_json()` are available. Regenerate and commit:

```bash
cargo run -p <crate> --locked -- openapi > services/<service>/openapi/v1.yaml
```

Validate with `openapi-spec-validator` (Python, `pip install
openapi-spec-validator`) before committing — it accepts YAML or JSON
input and confirms the document is structurally valid OpenAPI 3.x.

## 5. Live serving — flag-gated, authenticated, killable

```rust
pub(crate) const OPENAPI_FLAG: &str = "skauswatch.openapi-docs";

pub(crate) fn router() -> Router<AppState> {
    Router::new().route("/openapi.json", get(openapi_spec))
}

async fn openapi_spec(
    State(state): State<AppState>,
    _user: CurrentUser,          // <- see "auth wiring varies" below
) -> Result<Response, ApiError> {
    if !state.license.flag_enabled(OPENAPI_FLAG).await {
        return Err(ApiError::NotFound("Not Found".to_owned()));
    }
    Ok((StatusCode::OK, Json(ApiDoc::openapi())).into_response())
}
```

Merge this router into the service's main `/api/v1` nest alongside the
business routes (same file, same `.merge(...)` chain in `routes::router()`).
`utoipa::openapi::OpenApi` implements `Serialize` directly — `Json(...)`
just works.

**Don't** add the live `/openapi.json` route itself to `ApiDoc`'s `paths(...)`
— referencing the doc-generation type from within its own generated
document is a needless self-reference; the standard only requires the spec
describe the *business* API.

**Don't** add `utoipa-swagger-ui` — its default mount is unauthenticated by
design and violates the "docs behind auth" requirement outright. Serve the
raw JSON document behind auth (above); if a human-browsable UI is wanted
later, it needs its own explicit auth wrapping, not the crate's default.

### Auth wiring varies by service — check which pattern applies

| Pattern | Services | What the openapi route needs |
|---|---|---|
| **Per-handler auth** — every handler takes its own `CurrentUser`/`AuthedUser` extractor param | manager, vault, monitor, codescan-backend | Give `openapi_spec` the same extractor param as every other handler in the service (`_user: CurrentUser` above) — that's what produces 401 on a missing/invalid token, exactly like every other route |
| **Router-wide auth** — a single `.layer(axum::middleware::from_extractor_with_state::<AuthenticatedCaller, AppState>(...))` (or equivalent) wraps the whole `/api/v1` nest | pki, sshca | Don't add an extractor param to `openapi_spec` — the layer already covers it before the handler runs. The route only needs the flag check (`if !state.license.flag_enabled(...) { return 404 }`); merge it into the router the same way as every other route so it's inside the `.layer(...)` scope, not appended after |

Get this wrong and you either add a redundant/no-op extractor param on a
router-wide service, or ship an actually-unauthenticated `/openapi.json` on
a per-handler service — verify by grepping the service's
`routes/mod.rs`/`routes.rs` for `.layer(` before writing the handler.

## 6. The manager's login-split (services that own a login endpoint)

codescan-backend has **no** login endpoint (tokens are issued by the
manager and only verified here — see `src/auth.rs`), so the entire spec can
sit behind auth with no exception, matching `backend.md`'s general case.

**The manager is different**: it owns `POST /api/v1/auth/login`
(`services/manager/src/routes/auth.rs`). Per `backend.md`'s OpenAPI
section, an unauthenticated caller legitimately needs to discover *that one
endpoint* before it has a token — so the manager needs **two** documents,
not one gated-or-not toggle:

- **`PublicApiDoc`** — `paths(auth::login)` only, `components(schemas(...))`
  scoped to just the login request/response types. Served **unauthenticated**
  (no `CurrentUser` param) at a separate route, e.g.
  `GET /api/v1/openapi/login.json` — still flag-gated
  (`OPENAPI_FLAG`/`flag_enabled`), since an operator should still be able to
  kill live doc serving entirely, but never behind the `CurrentUser`
  extractor.
- **`ApiDoc`** — every other endpoint (users, alerts, threat-intel,
  approvals, endpoint, s3-scan, siem, asm, codescan proxy, research —
  everything except login), served at `GET /api/v1/openapi.json` behind
  the normal per-handler `CurrentUser` extractor, same as codescan-backend.

Two separate `#[derive(utoipa::OpenApi)]` structs, two separate routes, two
separate `SecurityAddon`-equivalents (the public one doesn't need a
security scheme registered at all, since it has no `security(...)` clause
on its one path). Do **not** try to build one `OpenApi` document and
conditionally strip paths at serve time — generating two real documents
from two real `#[derive(OpenApi)]` blocks keeps `openapi/v1.yaml` (the
committed, full, auth-required document) and the public login-only doc from
ever silently drifting apart.

Services with no login endpoint of their own (pki, sshca, vault, monitor,
codescan-backend) gate the whole spec and need no public doc — this is the
common case; the manager's split is the exception, not the template.

## 7. Tests to add per service

Mirror `services/codescan-backend/src/routes/openapi.rs`'s test module:

1. **Unauthenticated → 401** (per-handler-auth services only; router-wide
   services get this for free from the existing layer and don't need a
   duplicate test here).
2. **Authenticated + flag disabled (`release_mode = true`, no refresh) →
   404**.
3. **Authenticated + flag enabled (dev-bypass license) → 200**, body is a
   real OpenAPI document: assert `body["openapi"]` starts with `"3."`,
   assert at least one known path key exists in `body["paths"]`, and assert
   `body["components"]["securitySchemes"]["bearer_jwt"]` is present.

For the manager's public login doc, add a fourth case: **no token at all →
200** (proving the public route really is unauthenticated), plus asserting
its `paths` contains *only* the login path.

## Reference implementation

`services/codescan-backend/src/routes/{status,repos,reviews,plans,
credentials,openapi}.rs`, `services/codescan-backend/src/error.rs`
(`ErrorResponse`/`ValidationErrorResponse`), `services/codescan-backend/
src/main.rs` (`Openapi` subcommand), `services/codescan-backend/
openapi/v1.yaml` (generated output).
