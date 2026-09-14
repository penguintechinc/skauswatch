# skauswatch-spire

Nested SPIFFE/SPIRE trust authority for the `penguintech.io` trust domain,
as deployed for skauswatch. Single trust domain, one root SPIRE server +
one child SPIRE server per cluster — never per-cluster federated trust
domains (that's a separate, unrelated `federation` block in `values.yaml`
for cross-trust-domain peering, e.g. a customer's own SPIRE).

```
                         penguintech.io (one trust domain)

                    ┌───────────────────────────────┐
                    │   ROOT SPIRE server            │
                    │   (root.example.yml — org-wide,│
                    │    NOT a skauswatch env)        │
                    │   + OIDC Discovery Provider     │
                    │   spire-oidc.dal2.penguintech.  │
                    │   cloud (JWT-SVID → AWS STS)    │
                    └───────────────┬─────────────────┘
                     UpstreamAuthority "spire"
                (child's downstream-agent bootstraps here,
                 join_token attestation, one-time per child)
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
 ┌─────────────┐      ┌─────────────┐      ┌─────────────────┐
 │ dal2-beta    │      │ dal2-gamma   │      │ skauswatch-prod  │
 │ child server │      │ child server │      │ child server      │
 │ (beta.yml)   │      │ (gamma.yml)  │      │ (production.yml)  │
 └──────┬───────┘      └──────┬───────┘      └────────┬─────────┘
        │ k8s_psat               │ k8s_psat               │ k8s_psat
        ▼                        ▼                        ▼
  spire-agent DaemonSet    spire-agent DaemonSet     spire-agent DaemonSet
  (per node)                (per node)                 (per node)
        │                        │                        │
        ▼                        ▼                        ▼
   skauswatch service pods  skauswatch service pods   skauswatch service pods
   (manager, pki, sshca,    (same)                     (same)
    s3scan, worker-*, ...)

 alpha.yml → topology.role: standalone (no nesting, self-signed, local dev only)
```

## Values files

| File | Role | Notes |
|---|---|---|
| `values.yaml` | defaults | `enabled: false`; every toggle documented inline |
| `alpha.yml` | `standalone` | Single self-contained server, local MicroK8s/Docker Desktop |
| `beta.yml` | `child` | Points at root once `topology.upstreamRoot.enabled: true` (live-ops) |
| `gamma.yml` | `child` | Same shape as beta |
| `production.yml` | `child` | Same shape, 3 replicas, PostgreSQL datastore |
| `root.example.yml` | `root` | **Reference only** — not one of the four mandated env files. The root is an org-wide, single deployment outside skauswatch's own product namespace footprint; copy it into wherever k8s-ops designates as the shared root cluster/namespace |

## Node attestation by environment

| Env | Fleet workload attestor (agent → local child server) | Why |
|---|---|---|
| alpha | `k8s_psat` | Local MicroK8s/Docker Desktop, on-prem-equivalent |
| beta / gamma / production | `k8s_psat` | dal2 is on-prem bare metal — no IRSA/instance-profile chain, no IMDS |
| any future AWS-resident node pool | `aws_iid` (toggle, `server.nodeAttestation.awsIid.enabled`) | Only for nodes that actually run in AWS EC2/EKS; never toggle globally |

`k8s_sat` (the deprecated service-account-token attestor) has been fully
removed from this chart — `k8s_psat` (projected, audience-bound,
short-lived tokens) is the only k8s-native attestor wired.

**Nested-upstream bootstrap attestation is a separate, third mechanism**
(`topology.upstreamRoot.nodeAttestor`, default `join_token`) — it is how
a *child server itself* proves its identity to *root*, not how fleet
agents attest to their local child server. It defaults to `join_token`
because root cannot reach into a child cluster's TokenReview API to
validate a `k8s_psat` token across cluster boundaries.

## Registration entries (child-local, chart-authored)

The `auto-enroll` post-install/post-upgrade Job (`autoEnroll.enabled`,
default `true`) runs against **the local child server only** and:

1. Creates one **node alias** entry (`-node`, selector
   `k8s_psat:cluster:<cluster>`) mapping every attested agent in the
   cluster to a single stable parent ID
   (`spiffe://penguintech.io/spire/agent/<cluster>`) — required because
   `k8s_psat`'s real per-node SPIFFE ID changes every time a node is
   replaced.
2. Registers one workload entry per service in `autoEnroll.services` /
   `suiteServices`, parented to that alias, selected by
   `k8s:ns:<namespace>` + `k8s:sa:<serviceAccount>` —
   `spiffe://penguintech.io/<env>/<service>`.

Best-effort and idempotent (`entry show` before `entry create`);
`suiteServices` entries skip silently if the target namespace doesn't
exist yet.

## Service-pod SVID pattern (apply to each service's own chart — NOT done by this chart)

Every skauswatch service pod that needs an SVID adds this to its own
`templates/deployment.yaml` (hostPath — CSI variant below once approved):

```yaml
        volumeMounts:
        - name: spiffe-workload-api
          mountPath: /run/spire/sockets
          readOnly: true
      volumes:
      - name: spiffe-workload-api
        hostPath:
          path: /run/spire/sockets
          type: Directory
```

and set `SPIFFE_ENDPOINT_SOCKET=unix:///run/spire/sockets/agent.sock` in
the container's env — this is the standard SPIFFE Workload API
environment variable every SPIFFE client library (including
`skauswatch-identity`) checks by default, so no per-service code change
is required beyond mounting the socket.

**Status:** wired behind a `spire.enabled` values toggle in each of
`k8s/helm/{pki,manager,s3scan,worker-vault-sync}` — `beta.yml`,
`gamma.yml`, and `production.yml` all set `spire.enabled: true`
(`pki` hard-requires a live SVID whenever `RELEASE_MODE=true`, which is
production-only today); `alpha.yml` leaves it at the chart default
(`false`), since local MicroK8s has no SPIRE agent DaemonSet.

**Mounting the socket is necessary but not sufficient.** The hostPath
directory is only ever populated with `agent.sock` while a `spire-agent`
DaemonSet is actually running on that node and writing to
`agent.socketDir` — bringing that DaemonSet up in a given cluster is
live cutover ops (this chart authors the DaemonSet manifest; it does not
by itself make `spire.enabled: true` on a consuming chart produce a
working socket until the agent is deployed and healthy there). Enabling
the toggle on a node with no running agent yields an empty/absent mount,
not a working SVID.

**CSI driver variant (recommended, disabled by default, needs approval
— see below):** once `spire.csiDriver.enabled: true` is approved and
live, replace the hostPath volume above with:

```yaml
        volumeMounts:
        - name: spiffe-workload-api
          mountPath: /run/spire/sockets
      volumes:
      - name: spiffe-workload-api
        csi:
          driver: csi.spiffe.io
          readOnly: true
```

`SPIFFE_ENDPOINT_SOCKET` stays identical either way.

## CSI driver (recommended, requires approval before enabling)

`spire.csiDriver.enabled` is `false` in `values.yaml` and every env file
in this chart. The SPIFFE CSI Driver DaemonSet
(`templates/csi-driver-daemonset.yaml`) runs `securityContext.privileged:
true` — it must bind-mount the agent's Workload API socket into other
pods' mount namespaces via the kubelet plugin registry, which is the
standard upstream `spiffe-csi-driver` posture, not a PenguinTech-specific
relaxation. Per `devops-containers.md` "Rootless Containers", this is a
**ROOT EXCEPTION requiring explicit user approval** before any live
environment flips it on. Until approved, hostPath delivery (already
wired via `agent.socketDir`) is the only active mechanism.

## OIDC discovery provider (AWS JWT-SVID → STS federation)

`spire.oidcProvider` is enabled **only on root** (`root.example.yml`) —
in a nested topology the trust-domain bundle (both X.509 and JWT signing
authorities) is aggregated at root across every child, so one root-hosted
discovery provider is authoritative for JWT-SVIDs issued by *any* child.
Do not enable it per-child; `beta.yml`/`gamma.yml`/`production.yml` all
leave it `false`.

Exposed via `oidcProvider.httproute` (Gateway API, matches this repo's
other services) or `oidcProvider.ingress` (classic Ingress) — pick
whichever the target cluster's ingress mechanism supports. Both default
off.

**What AWS needs** (full detail: `docs/v2-port/aws-identity-runbook.md`,
executed as Terraform by whoever owns the AWS account — not this chart):

- HTTPS reachable at `oidcProvider.issuerHost` (e.g.
  `spire-oidc.dal2.penguintech.cloud`) serving
  `/.well-known/openid-configuration` + JWKS.
- **TLS from a real CA, not self-signed** — AWS OIDC federation pins a
  certificate thumbprint; a self-signed cert works technically but
  breaks on every rotation unless the thumbprint is kept in perfect sync.
- `aws_iam_openid_connect_provider` registered once per AWS account,
  `client_id_list = ["sts.amazonaws.com"]` (the fixed audience
  `fetch_jwt_svid` requests).
- One IAM role trust-policy `sub` condition line per environment/service
  SPIFFE ID that needs AWS access (e.g.
  `spiffe://penguintech.io/beta/s3scan`) — never shared across
  environments.

## Admin-adjustable SVID TTL

**Deploy-time default: 5 minutes, both X.509-SVID and JWT-SVID**
(`spire.svidTtl.x509` / `spire.svidTtl.jwt` in `values.yaml`, per-env
overridable). Wired to two places:

1. `default_x509_svid_ttl`/`default_jwt_svid_ttl` in `server.conf`
   (`server-configmap.yaml`) — the server-wide fallback.
2. `-x509SVIDTTL`/`-jwtSVIDTTL` on every `spire-server entry create` the
   auto-enroll Job runs (`auto-enroll-configmap.yaml`) — the per-entry
   value, which is what actually governs each service's issued SVIDs.

`crates/skauswatch-identity` refreshes at ~half-life, so a 5m TTL means
each workload's SVID is re-issued roughly every ~2.5m — short-lived by
design, not a symptom of misconfiguration.

**Runtime admin adjustment (no `helm upgrade` required):** `manager`'s
registration entry is the sole one in this chart with `admin: true`
(`values.yaml` → `autoEnroll.services[].admin`, applied via `-admin` on
`entry create`). SPIRE's Server API (the gRPC `entry.v1.Entry` service,
including `UpdateEntry`) is served on the **same network listener already
used for node/agent traffic** — `spire.server.ports.grpc` (8081),
exposed today by `server-service.yaml`. No extra port or Service is
needed for this chart to support admin access.

To move a running SVID TTL, `manager` (using the X.509-SVID minted from
its own admin-flagged entry, fetched over its local SPIRE agent Workload
API socket — see "Service-pod SVID pattern" above) opens an mTLS
connection to `<spire-server-service>:8081` and calls `UpdateEntry` with
`x509_svid_ttl`/`jwt_svid_ttl` set on the target entry. Bounded **1m–24h**
by manager's own application-level policy (Rust code, out of scope for
this chart) — SPIRE itself does not enforce that specific range, only the
`ca_ttl`-derived clamp below.

**Why `ca_ttl` must stay >= 48h:** SPIRE clamps any issued SVID TTL to
`<= ca_ttl / 2`. Since the admin-adjustable ceiling above is 24h,
`spire.server.caTtl` (default `168h`, i.e. 7d — see `values.yaml` for the
full comment) must never drop below 48h, or a legitimate 24h
`UpdateEntry` would get silently clamped down by SPIRE before it takes
effect. This applies identically to a root server's self-signed CA and a
child server's upstream-issued intermediate CA — both use the same
`spire.server.caTtl` value in this chart.

**Live-ops note:** issuing the actual `UpdateEntry` call against a live
cluster is a runtime operation performed by the `manager` service itself,
not something this chart executes — the chart's job ends at granting the
`admin: true` entry and exposing the reachable port.

## Live-Ops (executed later by k8s-ops during cutover — NOT done by this chart)

This chart only renders manifests; the following require a live cluster
and are explicitly out of scope for chart authoring:

1. **Deciding where root physically lives** (which cluster/namespace) —
   an architecture decision, not encoded in any of the four mandated env
   files.
2. **Bootstrapping a child** (beta/gamma/production), per child:
   - `kubectl exec` into the live root server pod:
     `spire-server token generate -spiffeID <downstreamSpiffeID>`
     (one-time-use join token).
   - Create the `Secret` (`topology.upstreamRoot.joinTokenSecret.name`,
     key `token`) and `ConfigMap` (`trustBundleConfigMap.name`, key
     `bundle.pem`, from `spire-server bundle show` on root) in the
     child's namespace.
   - Flip `topology.upstreamRoot.enabled: true` + fill in
     `serverAddress`/`serverPort` in that env's values file, `helm
     upgrade`.
   - Once the child's `downstream-agent` sidecar shows healthy and root
     shows a new agent entry for it, run on root:
     `spire-server entry create -downstream -spiffeID
     <downstreamSpiffeID> -parentID <the new agent's SPIFFE ID>
     -selector <whatever selector the join_token attestation produced>`.
   - This registration step is a one-time, per-child action — it is
     deliberately not automated as a chart-rendered Job, since it
     requires a live join-token round-trip this chart cannot perform at
     render time.
3. **AWS IAM/OIDC provider setup** — `docs/v2-port/aws-identity-runbook.md`,
   Terraform apply against skauswatch's AWS account (root-hosted OIDC
   endpoint must be live and TLS-valid first).
4. **CSI driver approval + enablement** — see above; requires explicit
   user sign-off, not a chart default.
5. **Wiring `SPIFFE_ENDPOINT_SOCKET` + the volume/mount snippet above
   into each service's own Helm chart** (`k8s/helm/manager`,
   `k8s/helm/pki`, etc.) — deliberately not done by this chart per the
   task scope; each service chart gets it in a later coordinated pass.

## Validation

```bash
helm lint k8s/helm/spire
helm template spire k8s/helm/spire --values k8s/helm/spire/alpha.yml
helm template spire k8s/helm/spire --values k8s/helm/spire/beta.yml
helm template spire k8s/helm/spire --values k8s/helm/spire/gamma.yml
helm template spire k8s/helm/spire --values k8s/helm/spire/production.yml
```
