# Service auth model — SPIFFE mTLS + scope retrofit (R2c/R3 spec)

Canonical design for service-to-service authentication/authorization across
skauswatch v2, built on the already-DONE `skauswatch-identity` crate
(`IdentityProvider`, `SpiffeIdMatcher`, `server_tls_config`/
`client_tls_config`). R2c/R3 implementation agents follow this doc exactly;
deviations require a spec update here first, not a silent per-service
choice. Mirrors the retrofit pattern of `docs/v2-port/tenancy-model.md` —
read that doc's §3/§6 conventions if anything here seems to duplicate it;
tenancy and service-auth are deliberately orthogonal (a request can be
tenant-valid and caller-unauthenticated, or vice versa).

**Current state confirmed by inspection:** `skauswatch-identity` has zero
consumers anywhere in the workspace (`grep -rl skauswatch_identity` across
`services/`/`crates/` hits only its own `Cargo.toml`). Every gRPC server
(manager's `ManagerService`+`S3ScanService`, pki's `PkiService`) runs on
plaintext TCP gated by a single shared HS256 secret (`JWT_SECRET_KEY`, via
`skauswatch_auth::verify_grpc_bearer`/`ServiceClaims`) — anyone who can
read that one env var, on any service, can mint a token accepted by every
other service. `ServiceClaims` carries no scope/audience claim at all, so
pki's `expiring`/`cleanup` maintenance endpoints (`routes/common.rs`) are
cross-tenant-by-design but enforced only by "which services can reach
pki's REST port" — a network-topology assumption, not a cryptographic one,
already flagged in that file's own doc comments. Every gRPC surface in the
repo has **zero in-repo callers today** (each `grpc/mod.rs` says so) — this
is the shape of "no live caller yet" the task description referred to.
sshca has no gRPC surface at all (REST-only, same `AuthenticatedCaller` +
`X-Tenant-ID` header pattern as pki via its own `tenant.rs`). s3scan the
*binary* has no gRPC of its own either — `S3ScanService` is served by the
**manager** binary (`services/manager/src/grpc/s3_scan_service.rs`); s3scan
the worker only ever talks Redis Streams.

---

## 1. SPIFFE ID scheme

Base per `penguintech.md`: `spiffe://penguintech.io/<env>/<service>`.
`<env>` is the deployment context (`alpha`/`beta`/`gamma`/prod — prod has
no literal env segment beyond the product's own trust domain policy; see
Decisions §7 on whether prod gets a single shared trust domain or a
per-tenant/customer federated one — out of scope for this doc, flagged).
`<service>` is the binary name, matching the `services/*` directory:

| SPIFFE ID | Binary | gRPC / mTLS role |
|---|---|---|
| `spiffe://penguintech.io/<env>/manager` | `services/manager` | gRPC **server** (`ManagerService`, `S3ScanService`) + gRPC **client** of pki (X.509/SSH issuance on behalf of users) |
| `spiffe://penguintech.io/<env>/pki` | `services/pki` | gRPC **server** (`PkiService`) |
| `spiffe://penguintech.io/<env>/sshca` | `services/sshca` | REST only today — no gRPC server; gets an SVID anyway for §4's JWT-SVID→STS path if/when it needs S3-adjacent AWS calls, and to be mTLS-ready if it grows a gRPC surface later |
| `spiffe://penguintech.io/<env>/s3scan` | `services/s3scan` (worker) | JWT-SVID→STS client only (§4) — no gRPC server or client role; talks to manager's `S3ScanService` today with zero in-repo callers (dead code), and to Redis Streams for real work |
| `spiffe://penguintech.io/<env>/worker-vault-sync` | `services/worker-vault-sync` | JWT-SVID→STS client (cloud KMS federation, same shape as §4) |
| `spiffe://penguintech.io/<env>/worker-codescan` | `services/worker-codescan` | No SPIFFE role identified yet — Redis Streams only, no outbound AWS/gRPC call in the current codebase; skip in R2c/R3, revisit if it grows one |
| `spiffe://penguintech.io/<env>/scanner` | `services/scanner` | Same as worker-codescan — no SPIFFE role yet |
| `spiffe://penguintech.io/<env>/vault` | `services/vault` | No gRPC client/server role found; candidate for JWT-SVID→cloud-KMS federation in a later round (external KMS encryption is an Enterprise-tier feature per `general.md` — not in R2c/R3 scope) |
| `spiffe://penguintech.io/<env>/monitor` | `services/monitor` | REST only, no gRPC/AWS client role identified — out of scope |
| `spiffe://penguintech.io/<env>/codescan-backend` | `services/codescan-backend` | REST only, no gRPC/AWS client role identified — out of scope |
| `spiffe://penguintech.io/<env>/logs` | `services/logs` | No role identified — out of scope |
| `spiffe://penguintech.io/<env>/endpoint-agent-maintenance` | N/A (operator/CLI identity, not a long-running service) | The maintenance/super-admin identity for pki's `expiring`/`cleanup` — see §3. Not tied to the ENDPOINT fleet-agent binary; the name is deliberately distinct from `endpoint-agent` (§5) to avoid confusion between "a customer's EDR sensor" and "an internal ops identity" |

**Who-calls-whom allowlist** (the `SpiffeIdMatcher` each server builds):

| Server | `SpiffeIdMatcher` allows | Rationale |
|---|---|---|
| pki's `PkiService` (gRPC) | `allow_exact(spiffe://penguintech.io/<env>/manager)` only | Manager is pki's sole in-repo caller-to-be (issuance on behalf of authenticated users); no other service issues certificates |
| manager's `ManagerService`+`S3ScanService` (gRPC) | `allow_path_prefix(penguintech.io, "/<env>")` — any workload in this env's trust domain — **not** narrowed further in R2c | These RPCs have zero real callers today (confirmed); a broad same-trust-domain allow avoids over-fitting a matcher to callers that don't exist yet. Narrow to specific identities (e.g. `s3scan`, `worker-vault-sync`) once a real caller is implemented — tracked as an R3-follow-up, not blocking |
| pki's `expiring`/`cleanup` maintenance ops | `allow_exact(spiffe://penguintech.io/<env>/endpoint-agent-maintenance)` (REST — see §3, not a gRPC matcher) | The one deliberate cross-tenant surface; §3 below |

No service today calls sshca, s3scan, or worker-vault-sync's identity as a
*peer to authenticate against* (they're callers, not gRPC servers), so
those three have no inbound `SpiffeIdMatcher` to define in R2c/R3 — only
outbound client configs.

---

## 2. mTLS on gRPC — replacing the shared HS256 secret

### Current mechanism being replaced

`skauswatch_auth::verify_grpc_bearer`/`ServiceClaims`/`issue_service_token`
— a single shared `JWT_SECRET_KEY` HS256 secret, no per-caller identity,
no scope. Every gRPC server (`manager/src/grpc/mod.rs`'s `require_jwt`,
`pki/src/grpc/mod.rs`'s `auth_interceptor`) calls this today.

### Target mechanism

Full mutual TLS via `IdentityProvider::server_tls_config`/
`client_tls_config`, exactly as already implemented and tested in
`crates/skauswatch-identity/src/tls.rs`:

- **pki** (`services/pki/src/grpc/mod.rs::serve`): build the tonic
  `Server` with `.tls_config(...)` derived from
  `identity_provider.server_tls_config(&manager_only_matcher)?` instead of
  plain HTTP/2. `IdentityProvider` is held in `AppState` (constructed once
  at startup via `IdentityProvider::connect_with_domain`, refreshed
  periodically — see "TLS configs are snapshots" caveat in the crate's own
  docs: a background `tokio::spawn` loop calling `.refresh()` +
  rebuilding the `ServerConfig` on a cadence shorter than SPIRE's SVID
  TTL, typically every 20–30 min against a 1h default TTL).
- **manager** (`services/manager/src/grpc/mod.rs::serve`): same pattern —
  `server_tls_config` with the broad same-trust-domain matcher from §1.
  Manager is *also* a gRPC **client** of pki once issuance-on-behalf-of-
  users is wired up: build its pki client channel with
  `client_tls_config(&pki_only_matcher)` where `pki_only_matcher =
  SpiffeIdMatcher::new().allow_exact(pki's SPIFFE ID)`.
- **sshca**: no gRPC server exists to convert; skip in this round. If a
  future PR adds one, follow the pki pattern exactly (this doc's §1 table
  already reserves its SPIFFE ID).

### What mTLS replaces vs. keeps

mTLS replaces the *authentication* layer (`verify_grpc_bearer`/HS256) —
the SPIFFE ID *is* the caller's cryptographic identity, no bearer token
needed. It does **not** replace tenant propagation (`x-tenant-id` gRPC
metadata, `require_tenant_metadata` — tenancy-model.md §3 stays exactly as
designed, orthogonal to caller auth) or the `api_version` field/handler
routing (`check_api_version` — API versioning is a wire-contract concern,
unrelated to transport security). Both stay as-is; only the "is this
caller who it claims to be" check moves from a shared-secret bearer token
to a certificate.

### Transition plan — **recommend: parallel-listener dual-accept, then hard cutover**

Hard-cutover-only is risky because SPIRE/agent rollout in a real cluster
(server registration, workload attestation, trust bundle propagation) can
lag behind a code deploy — a service that flips straight to mTLS-only
before its SPIRE agent is healthy goes instantly unreachable, and every
gRPC surface here currently has **zero real callers**, so there is no
"existing traffic" to preserve, but there *is* a startup-ordering risk
(pki's SPIRE agent socket not yet warm when manager's channel tries to
connect).

**Recommended shape, in order:**

1. **R2c**: Wire `IdentityProvider` into pki and manager's gRPC `serve()`
   functions, building the mTLS `ServerConfig`/`ClientConfig` from it.
   Keep the existing `require_jwt`/`auth_interceptor` HS256 check **also**
   present on the same listener as a secondary gate for one release cycle
   — i.e., the transport is mTLS (so a non-attested peer can't even
   complete the handshake), *and* the RPC-level bearer-token interceptor
   still runs on top for one release, so a caller that has valid mTLS but
   somehow no token (a bug, not a supported combination) still gets a
   clean `UNAUTHENTICATED` from the existing interceptor rather than a
   confusing TLS-layer error. This is not "accept either" — it's "require
   both, temporarily" — the safer direction to err on for a CA service.
2. **R3**: Once mTLS is confirmed healthy in beta (SPIRE agents attesting,
   `has_identity()` true, real handshakes succeeding), **drop the HS256
   interceptor entirely** — hard cutover, not indefinite dual-accept.
   `skauswatch_auth::verify_grpc_bearer`/`ServiceClaims`/
   `issue_service_token`/`AuthenticatedCaller` stay in the crate (pki/
   sshca's **REST** surfaces still use `AuthenticatedCaller` for the
   HMAC-adjacent machine-token pattern — that's unrelated to gRPC and is
   not being replaced by this doc), but the gRPC-specific
   `verify_grpc_bearer`/`require_jwt`/`auth_interceptor` call sites are
   deleted.
3. Because every gRPC surface has zero real callers today, there is no
   "existing agent breaks" risk analogous to the tenancy retrofit's
   `AccessClaims` wire-break (tenancy-model.md §8) — this is the one place
   where a hard cutover is *safer* than dual-accept-forever, since
   dual-accept-forever just means "the weaker of two auth mechanisms is
   still the real gate," which defeats the point of adding mTLS.

**Decision needing user confirmation**: is R2c→R3 (dual-accept-one-cycle
→ hard cutover) an acceptable pace, or does the user want R2c to hard-cut
immediately given there are no real callers to protect? Recommendation:
keep the one-cycle dual-accept anyway, purely as a rollback safety valve
for the *implementer's own* R2c testing (not for any real external
caller) — costs one extra release, buys a fallback if SPIRE rollout in
beta has infra problems unrelated to the code.

---

## 3. Service authorization / scope — closing the pki maintenance gap

**Problem restated**: `pki::routes::common::expiring`/`cleanup`
(`services/pki/src/routes/common.rs`) are REST endpoints, deliberately
cross-tenant (tenancy-model.md §6), currently gated by nothing but network
reachability — `AuthenticatedCaller`/`ServiceClaims` has no scope claim to
check.

**Chosen approach: dedicated SPIFFE ID, not a `ServiceClaims` scope
field.**

Rationale for SPIFFE-ID-as-authorization over adding a `scope` field to
`ServiceClaims`:

- `ServiceClaims` is HS256/shared-secret today; adding a scope field to it
  doesn't fix the underlying problem (anyone with `JWT_SECRET_KEY` can
  still mint `scope: "pki:maintenance"` themselves — a scope claim is only
  as trustworthy as the key signing it, and that key is shared across
  every service).
- Once §2's mTLS lands, the SPIFFE ID is already a cryptographically
  strong, non-forgeable caller identity — reusing it for this one
  authorization decision avoids introducing a second, weaker claims
  system in parallel with the first.
- A dedicated identity (`spiffe://penguintech.io/<env>/endpoint-agent-maintenance`
  — see §1's naming note) makes the audit trail self-describing: pki's
  access log shows literally which SPIFFE ID hit `/expiring`/`/cleanup`,
  no need to cross-reference a scope bundle to a role to a user.

**Implementation** (`services/pki/src/routes/common.rs`):

- `expiring`/`cleanup` move from plain axum handlers to handlers wrapped
  by a new extractor, `MaintenanceCaller`, analogous to `TenantId` in
  `services/pki/src/tenant.rs` but sourced from the **mTLS peer identity**
  of the underlying connection, not a header. Concretely: pki's REST
  listener also needs to run behind `IdentityProvider::server_tls_config`
  (mTLS on REST, not just gRPC — a new requirement this doc introduces;
  today pki's REST surface is plain HTTPS/TLS with server-only certs) with
  a matcher of `allow_exact(spiffe://penguintech.io/<env>/endpoint-agent-maintenance)`
  applied **only to the `/api/v1/expiring` and `/api/v1/cleanup` routes**
  (a per-route mTLS requirement — axum/tonic support per-route TLS configs
  via separate listeners/ports, not a single shared listener config; see
  Decisions §7 for the operational cost of this).
- Every other pki REST route keeps its current TLS posture (server-only
  cert, `AuthenticatedCaller` bearer-token check) — this is a narrow,
  surgical change to two routes, not a wholesale pki-REST-goes-mTLS
  migration.
- Update both handlers' doc comments to drop the "currently enforced only
  by deployment-level access control" caveat once landed, and add a
  regression test asserting a non-`endpoint-agent-maintenance` SPIFFE ID
  is rejected (mirrors `tls.rs`'s existing
  `mtls_rejects_peer_outside_matcher_allowlist` pattern, one layer up at
  the route level).

**Decision needing user confirmation**: this requires giving pki's REST
listener a *second* bound port/listener (mTLS-required, maintenance-only)
alongside its existing REST port — is that operationally acceptable, or
would the user prefer a same-port compromise (e.g. keep `expiring`/
`cleanup` on the standard listener but require an *additional* explicit
`X-Maintenance-Token` bearer, a second HS256 secret dedicated to just
these two routes, issued only to an ops/cron identity)? The second option
is weaker (back to a shared secret) but avoids a second listener/port.
**Recommendation: dedicated mTLS-required port**, consistent with "the
SPIFFE ID is the strong identity, don't reintroduce a shared secret to
avoid infra work."

---

## 4. JWT-SVID → AWS STS (`AssumeRoleWithWebIdentity`)

**Current state**: `crates/skauswatch-s3/src/credentials.rs::assume_role_credentials`
already implements the `sts:AssumeRole` exchange (customer `role_arn` +
optional `external_id`) but its **base caller identity** — the credentials
used to make that STS call in the first place — is "this service's own
ambient AWS identity (default credential-provider chain — IRSA/instance-
profile/env)" per the module doc comment. On dal2 (on-prem, no EKS/IRSA,
no instance-profile metadata service), that chain has nothing to resolve
to in production — this is exactly the on-prem rationale the task
description flagged: **IRSA is an AWS-EKS-only mechanism and simply
doesn't exist on dal2's bare-metal/on-prem Kubernetes.** JWT-SVID→STS
federation is dal2's IRSA equivalent: SPIRE issues a JWT-SVID as this
service's federated OIDC-shaped identity token, and AWS STS trusts it via
a pre-registered OIDC identity provider pointing at the SPIRE server's
JWT-SVID issuer endpoint (SPIRE can serve as an OIDC-discovery-compatible
issuer for this exact purpose — this is the standard SPIFFE/SPIRE↔AWS
federation pattern, not a skauswatch-specific invention).

**Plug-in point**: `assume_role_credentials`'s `base_credentials_override:
Option<Credentials>` parameter already exists as a test-only seam
(wiremock STS + hermetic caller identity). The production wiring is: stop
leaving this `None` in production and instead resolve a real `Credentials`
value from a JWT-SVID via `sts:AssumeRoleWithWebIdentity` (a **different**
STS API call than the `AssumeRole` this function already makes — see
below), then pass *that* result in as `base_credentials_override`. This
reuses the existing function signature/seam rather than adding a new
parameter.

**Concrete flow**:

1. At the point `resolve_client`/`resolve_client_inner` is invoked for an
   `assume_role`-mode bucket, first resolve the service's own base
   identity:
   ```rust
   let jwt_svid = identity_provider
       .fetch_jwt_svid("sts.amazonaws.com")   // audience — see below
       .await?;
   let base_creds = aws_sdk_sts::Client::new(&shared_config)
       .assume_role_with_web_identity()
       .role_arn(&this_services_own_federation_role_arn)   // NOT the customer's role_arn
       .role_session_name(ROLE_SESSION_NAME)
       .web_identity_token(jwt_svid.token())
       .send()
       .await?;
   ```
   `this_services_own_federation_role_arn` is a **new**, service-owned IAM
   role (one per service that needs S3/STS access — s3scan and
   worker-vault-sync per §1), pre-configured in AWS IAM with a trust
   policy that trusts the SPIRE JWT-SVID issuer as an OIDC provider. This
   is infrastructure setup (IAM role + OIDC provider registration),
   **not** something this crate can self-configure — flagged for the
   user/ops as a one-time AWS-side setup per environment.
2. **Audience value**: `"sts.amazonaws.com"` is the AWS-documented
   required audience for `AssumeRoleWithWebIdentity`-compatible OIDC
   tokens (matches the convention EKS/IRSA itself uses for its projected
   service-account tokens) — use this exact string, not a
   skauswatch-specific one, since AWS's own STS validation checks it.
3. Feed the resulting `Credentials` into `resolve_client_inner`'s existing
   `base_credentials_override` parameter — this becomes the identity used
   for the **customer's** `sts:AssumeRole` call
   (`assume_role_credentials`'s existing logic, unchanged), which then
   chains into the customer's own cross-account role + `external_id` as
   already implemented. Two STS hops total: JWT-SVID → service's own AWS
   role (new) → customer's role (existing).
4. Caching: unlike the customer-facing `AssumeRole` result (deliberately
   uncached, fresh per client build — see that function's doc comment),
   the JWT-SVID→own-role credentials **should** be cached and refreshed
   on a timer (typically ~1h AWS STS session duration), since this is the
   service's own identity, reused across every customer bucket the
   service touches — a fresh STS round-trip per job would be wasteful.
   Recommend a `tokio::sync::RwLock<Option<(Credentials, Instant)>>` in
   `AppState`, refreshed lazily when expired, populated by the flow above.

**Where this plugs into `skauswatch-s3`**: a new function alongside
`assume_role_credentials`, e.g. `federated_base_credentials(identity:
&IdentityProvider, own_role_arn: &str) -> Result<Credentials,
CredentialError>`, called by s3scan/worker-vault-sync's call sites before
they invoke `resolve_client`, not by `skauswatch-s3` itself (the crate
stays free of a hard `skauswatch-identity` dependency unless it already
needs one elsewhere — keep the SPIFFE-specific glue in the calling
service, matching the "credentials.rs is a hybrid resolver, not an
identity provider" framing already in that module's own doc comment).

**Decision needing user confirmation**: this needs one AWS IAM role +
OIDC-provider registration per service-per-environment
(s3scan/alpha, s3scan/beta, ..., worker-vault-sync/alpha, ...) as one-time
AWS-side infra setup, plus SPIRE server configured to expose a
JWT-SVID-compatible OIDC discovery document. Confirm this AWS/SPIRE-side
setup is in scope for R2c/R3 (infra work, not code) before an
implementation agent blocks on it — if the AWS IAM side isn't ready yet,
`federated_base_credentials` can be written and unit-tested (wiremock STS,
same pattern as the existing `assume_role_credentials` tests) without a
live environment, but production cutover waits on the IAM setup.

---

## 5. EDR agent tenant-scoped enrollment

**Problem restated** (tenancy-model.md §8, restated here since it's this
doc's job to resolve it): `register_agent`
(`services/manager/src/routes/endpoint.rs`) stamps every *newly created*
agent to `default_tenant_uuid()` because the HMAC-authenticated
enrollment request (`X-API-Key`/`X-Agent-ID`, `EndpointAgent` extractor in
that same file) carries no tenant information at all — there's no JWT, no
`x-tenant-id` header, nothing. Re-registration of an *existing* agent
correctly preserves its stored tenant (never re-derives), so this is
strictly a new-agent-provisioning gap, not a per-request leak.

**Two options considered:**

| Option | Shape | Pros | Cons |
|---|---|---|---|
| **A: Per-tenant enrollment token** | Manager REST endpoint `POST /api/v1/tenants/{id}/enrollment-tokens` (super_admin/tenant-admin-issued, short-lived, single- or multi-use) mints a token; the agent's install/config carries this token; `register_agent` looks up the token → resolves tenant → consumes/validates it, replacing (or supplementing) the current HMAC `X-API-Key`/`X-Agent-ID` scheme | Matches how most EDR/fleet products actually provision (a customer downloads an installer pre-baked with, or prompted for, an enrollment token); no SPIRE/SPIFFE dependency on end-customer infrastructure the agent runs on (customer laptops/servers are **not** part of skauswatch's own SPIFFE trust domain — federating them would mean trusting arbitrary customer infra as a SPIFFE peer, a much bigger security surface) | New DB table + endpoint + token lifecycle (issuance, expiry, revocation) to build |
| **B: Federated SPIFFE ID** | Each customer runs their own SPIRE deployment; skauswatch federates trust with it (exactly the pattern `SpiffeIdMatcher::allow_trust_domain` / the existing `mtls_succeeds_across_federated_trust_domains` test already demonstrates for `customer.example`); the agent's SPIFFE ID path segment encodes tenant | Reuses `skauswatch-identity` machinery already built and tested; strong crypto identity | **Requires every customer to run their own SPIRE server** and establish a federation trust relationship with skauswatch's SPIRE — completely unrealistic for an EDR agent meant to be a lightweight, easily-deployed sensor on arbitrary customer endpoints (workstations, servers) that will never run a SPIRE agent of their own |

**Recommended for v2.0: Option A — per-tenant enrollment token.**
Option B's dependency ("customer runs SPIRE") is a non-starter for a
fleet-deployed endpoint sensor; the federated-trust-domain capability
`skauswatch-identity` already has is the right tool for *service-to-
service* federation with a customer's *own backend infrastructure*
(hypothetically, if a customer ran a service that needed to call
skauswatch's APIs directly), not for a mass-deployed lightweight agent
binary.

**Contract-level design (Option A):**

*Manager-side (new):*
- New table `endpoint_enrollment_tokens` (`id`, `tenant_id UUID NOT NULL`,
  `token_hash` (never store the raw token, same principle as password
  hashing), `expires_at`, `max_uses` / `use_count`, `created_by`,
  `created_at`, `revoked_at NULL`).
- New endpoint `POST /api/v1/tenants/{tenant_id}/enrollment-tokens`
  (JWT-authenticated, `super_admin` or a new `tenant_admin`-shaped role —
  reuse `tenants.rs`'s existing `require_role(&["super_admin"])` pattern
  as the starting gate; a narrower per-tenant-admin role is a nice-to-have,
  not a blocker) — returns the raw token once, never retrievable again.
- `register_agent` gains a required `enrollment_token` field in
  `RegisterBody` (**new** requests only — re-registration of an existing
  `agent_id` keeps working with the current HMAC-only flow, since the
  agent already has a tenant on file). Validates: token exists, unexpired,
  unrevoked, under `max_uses`; resolves `tenant_id` from the token row
  instead of `default_tenant_uuid()`; increments `use_count`.
- `X-API-Key`/`X-Agent-ID` HMAC auth is **unchanged** — the enrollment
  token is an *additional* required field in the register body, not a
  replacement transport-auth mechanism. This keeps `EndpointAgent`'s
  extractor and `expected_api_key`/`ct_eq` exactly as-is.

*Agent-side (`services/endpoint-agent`):*
- `config.rs`/agent config file gains an `enrollment_token` field (empty
  string acceptable for a re-registering agent that already has a stored
  `agent_id`+`api_key`, per v1/current behavior); `transport.rs`'s
  `RegisterRequest` gains the field, sent verbatim on first registration.
- No change to `compute_api_key`/`Reporter::api_key()` — the HMAC scheme
  is untouched.

**Decision needing user confirmation**: exact role for issuing enrollment
tokens (`super_admin` only, vs. a new narrower `tenant_admin` role scoped
to that tenant) — recommend starting with `super_admin`-only for v2.0
(matches `tenants.rs`'s existing provisioning-is-admin-only posture per
tenancy-model.md §8) and revisiting a delegated `tenant_admin` role as a
v2.1-backlog item if customer self-service enrollment becomes a real
requirement.

---

## 6. Rollout order + per-piece R2c/R3 checklist

Owner = the piece an implementation agent should be dispatched against.
Pieces are independent of each other except where noted — dispatch in
parallel unless a dependency arrow says otherwise.

```
§2 mTLS (pki server + manager server/client)  ─┐
                                                 ├──► §3 pki maintenance SPIFFE gate
                                                 │    (needs pki's REST listener already
                                                 │     mTLS-capable from §2's plumbing)
§4 JWT-SVID→STS (s3scan, worker-vault-sync)    ─┘    (independent of §2/§3 — no gRPC
                                                       or REST-listener dependency)
§5 EDR enrollment tokens (manager + agent)           (fully independent — no SPIFFE/
                                                       mTLS dependency at all; Option A
                                                       deliberately avoids SPIFFE)
```

| Piece | Scope | Files (non-exhaustive, greps required) | Depends on |
|---|---|---|---|
| **R2c-1: pki gRPC mTLS** | Wire `IdentityProvider` into pki's `serve()`; build/hold `ServerConfig`; dual-accept HS256 for one cycle (§2) | `services/pki/src/grpc/mod.rs`, `services/pki/src/state.rs` (hold `IdentityProvider`), config/startup wiring | — |
| **R2c-2: manager gRPC mTLS (server)** | Same as R2c-1 for manager's `ManagerService`/`S3ScanService` | `services/manager/src/grpc/mod.rs`, `services/manager/src/state.rs` | — (parallel with R2c-1) |
| **R2c-3: manager→pki gRPC mTLS (client)** | Manager's pki client channel gets `client_tls_config` | Wherever manager's pki gRPC client is/will be constructed (no such client exists in-repo yet per the task's "no live caller" note — this may be building the client for the first time, not just retrofitting one) | R2c-1 (pki must be mTLS-capable as a server first) |
| **R3-1: pki maintenance SPIFFE gate** | Second mTLS-required listener for `/expiring`+`/cleanup`; `MaintenanceCaller` extractor; drop the "network topology only" doc-comment caveat | `services/pki/src/routes/common.rs`, `services/pki/src/tenant.rs` (sibling extractor), `services/pki/src/main.rs`/`state.rs` (second listener) | R2c-1 (needs pki's `IdentityProvider` already wired) |
| **R3-2: gRPC hard cutover** | Delete `verify_grpc_bearer`/`require_jwt`/`auth_interceptor` call sites from both gRPC servers once beta-confirmed | `services/manager/src/grpc/mod.rs`, `services/pki/src/grpc/mod.rs` | R2c-1, R2c-2 confirmed healthy in beta |
| **R2c-4: JWT-SVID→STS for s3scan** | `federated_base_credentials` helper; wire into s3scan's `resolve_client` call sites; cached/refreshed base credentials in `AppState` | `crates/skauswatch-s3/src/credentials.rs` (new fn), `services/s3scan/src/*` call sites | AWS IAM role + OIDC provider registered (ops precondition, §4 Decision) |
| **R2c-5: JWT-SVID→STS for worker-vault-sync** | Same pattern as R2c-4, different service/role | `services/worker-vault-sync/src/*` | Same AWS precondition, independent of R2c-4 |
| **R2c-6: EDR enrollment tokens (manager)** | New table/migration, new endpoint, `register_agent` validation | `services/manager/migrations/000X_enrollment_tokens.sql`, `services/manager/src/routes/tenants.rs` or new `routes/enrollment.rs`, `services/manager/src/routes/endpoint.rs` | — (fully independent) |
| **R2c-7: EDR enrollment tokens (agent)** | Config field + `RegisterRequest` field | `services/endpoint-agent/src/config.rs`, `services/endpoint-agent/src/transport.rs` | R2c-6 (wire shape must match manager's new field) |

**Non-goals for R2c/R3** (explicitly out of scope, don't let an
implementation agent scope-creep into these): sshca gaining a gRPC
surface; vault/monitor/codescan-backend/logs/scanner/worker-codescan
gaining any SPIFFE role (§1 — no identified need today); a delegated
`tenant_admin` role for enrollment-token issuance (§5 decision, v2.1
candidate); prod trust-domain topology (single vs. per-customer-federated
— §1 note, needs a separate decision before prod cutover, not blocking
alpha/beta).

---

## 7. Decisions needing user confirmation (collected)

1. **§2 — dual-accept pace**: keep the recommended one-release-cycle
   dual-accept (mTLS + HS256 both required) before hard-cutting to
   mTLS-only, or hard-cut immediately in R2c since there are no real
   callers to protect today? *Recommendation: keep the one-cycle
   dual-accept as an implementer safety valve.*
2. **§3 — pki maintenance gate mechanism**: dedicated second mTLS-required
   listener/port for `expiring`/`cleanup` (recommended) vs. a second
   shared-secret bearer token on the existing listener (weaker, no new
   port)? *Recommendation: dedicated mTLS port.*
3. **§4 — AWS/SPIRE infra readiness**: is per-service-per-environment AWS
   IAM role + OIDC-provider registration (plus SPIRE JWT-SVID OIDC
   discovery) in scope for R2c/R3 as infra work, or should the code land
   now (tested against wiremock STS) with production cutover deferred
   until that AWS-side setup exists? *Recommendation: land the code now,
   flag production cutover as gated on ops completing the AWS/SPIRE
   setup.*
4. **§5 — enrollment token issuance role**: `super_admin`-only for v2.0
   (recommended, matches existing tenant-provisioning posture) vs. a new
   delegated `tenant_admin` role now? *Recommendation: `super_admin`-only
   now, `tenant_admin` as a v2.1-backlog candidate.*
5. **§1 — prod trust-domain topology**: single shared `penguintech.io`
   trust domain across all prod tenants (simpler, matches today's
   single-tenant-per-deployment assumption elsewhere in the v2 program) vs.
   a per-customer federated trust domain (stronger isolation, much more
   SPIRE-federation complexity)? Not blocking R2c/R3 (alpha/beta can use
   a single trust domain regardless), but needs a decision before prod
   cutover. *No recommendation offered here — this is a genuine
   architecture fork the user should decide, not a default-and-flag
   item.*
