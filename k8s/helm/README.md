# k8s/helm — cluster security baseline

Chart-authoring reference for the security controls added across every
skauswatch chart (phase12 cluster-security-mesh pass). Everything here is
**chart content + operator documentation only** — live enforcement
(namespace labels, Tetragon/Cilium cluster add-ons, StorageClass
provisioning) is cutover ops, not something a `helm install` of these
charts does by itself.

## Cluster security baseline

### CiliumNetworkPolicy (`templates/ciliumnetworkpolicy.yaml`, every chart)

Each service chart ships **one CiliumNetworkPolicy scoped to its own pods**
(`endpointSelector` = the chart's `selectorLabels`), not a separate
namespace-wide default-deny object. This is intentional, not a shortcut:
Cilium's per-endpoint model means **selecting a pod with any
CiliumNetworkPolicy makes every ingress/egress path not explicitly listed
default-deny** for that pod — a second blanket "default-deny-all" CNP
alongside it would be redundant, and worse, would collide by *name* across
independently-`helm install`ed charts sharing the `skauswatch` namespace
(two charts creating an identically-named cluster-namespaced resource is a
real Helm ownership conflict — this repo intentionally avoids that pattern
here for the same reason it doesn't create `kind: Namespace` objects; see
below).

Every policy:
- Restricts `toPorts`/ingress ports to the **actual numeric serving port**
  from that chart's `values.yaml` (Cilium's CNP does not resolve k8s named
  container ports the way plain `NetworkPolicy` does — every port below is
  a literal number, not a name).
- Allows `kubelet` liveness/readiness probes via `fromEntities: [host,
  remote-node]` — a common Cilium gotcha: enabling any CNP on a pod without
  this breaks health checks, since probe traffic arrives from the node, not
  a pod identity.
- Allows DNS resolution (`kube-dns`, port 53) as a baseline egress rule,
  required for every `toFQDNs` rule below it to resolve.
- Gates the cross-namespace "gateway" ingress rule behind
  `{{ or .Values.ingress.enabled .Values.httproute.enabled }}` — only
  present when that chart is actually externally exposed for the target
  environment.

**Dependency label assumption (verify before relying on it in a live
cluster):** Postgres and Valkey/Redis are external dependencies this chart
set does not own or deploy (no `postgres`/`valkey` chart exists under
`k8s/helm/`) — resolved via short in-namespace DNS names (`postgres`,
`redis`) per each chart's `configMapData`. The generated CNP egress rules
match `app.kubernetes.io/name: postgresql` / `app.kubernetes.io/name:
valkey`, the standard Bitnami-postgresql / valkey/valkey chart label
convention (per `devops-kubernetes.md`). **Confirm these match the actual
deployed Postgres/Valkey pod labels before treating the egress rule as
correct** — a label mismatch here silently blocks DB/cache access once the
CNP goes live, since Cilium's `toEndpoints` matches by pod identity, not by
Service name.

**Service-call graph provenance:** every ingress/egress peer rule is
commented either `CONFIRMED (<source file/values.yaml key>)` — verified
against actual Rust source (`grpc/pki_client.rs`, `Command::new` call
sites) or a chart's `configMapData`/`secretData` — or left as a plain
comment describing a reasonable but unverified assumption (external API
egress inferred from `secretData` keys like `virustotal-api-key`,
`anthropic-api-key`, etc.). No edge was invented without at least one of
these two forms of evidence; anything not found in either was **left out**
rather than guessed (e.g. `sshca` and `logs` have no confirmed in-cluster
caller — only gateway/httproute + Prometheus ingress rules are present for
them).

**`endpoint-agent`: CNP does not apply to ingress.** It runs
`hostNetwork: true` (pre-existing, documented ROOT EXCEPTION). A standard
`endpointSelector` CiliumNetworkPolicy attributes traffic to pod identity,
which doesn't exist the same way for a host-networked pod's *inbound*
traffic. The correct primitive is Cilium's host firewall
(`CiliumClusterwideNetworkPolicy` + `nodeSelector`), but that governs ALL
host traffic on selected nodes — a cluster-wide, cutover-ops decision this
chart does not make unilaterally. Its chart only scopes *egress* (which
Cilium can still attribute to the process even under `hostNetwork`) —
manager + license server, both port-scoped.

### Tetragon exec-allowlist (`templates/tracingpolicy.yaml`, every chart)

Per-service `TracingPolicyNamespaced` (namespaced Tetragon CRD, scoped via
`podSelector` to the chart's own pods — not a cluster-wide
`TracingPolicy`). A `sys_execve` kprobe with `operator: "NotEqual"` against
the pod's known-legitimate binaries + `matchActions: [{action: Sigkill}]`:
any exec that is NOT one of the listed binaries is killed. This is the
standard Tetragon allowlist-enforcement pattern — `NotEqual` against a
multi-value list matches (and kills) only when the executed path differs
from *every* listed value.

Binaries allowlisted per chart, from actual `Command::new`/Dockerfile
`ENTRYPOINT` evidence (grepped across `services/*/src`, not guessed):

| Chart | Own binary | Subprocess(es) | Why |
|---|---|---|---|
| pki | `/usr/local/bin/skauswatch-pki` | `/usr/bin/ssh-keygen` | `services/pki/src/ca/ssh.rs` — SSH CA absorbed into pki |
| monitor | `/usr/local/bin/skauswatch-monitor` | `/usr/bin/journalctl`, `/usr/bin/tail` | `services/monitor/src/collectors/{journald,auditd,lxc}.rs` |
| scanner | `/usr/local/bin/skauswatch-scanner` | `/usr/bin/masscan` | `services/scanner/src/asm.rs` — needs `CAP_NET_RAW`, see values.yaml |
| webui | `/usr/local/bin/node` | — | Dockerfile `CMD ["node", "dist/server/index.js"]` |
| spire-agent | `/opt/spire/bin/spire-agent` | `/bin/sh`, `/bin/busybox`, `/bin/wget` | busybox init container + nested-topology sidecar share the pod |
| spire-server | `/opt/spire/bin/spire-server` | — | official image ENTRYPOINT |
| spire-oidc-provider | `/opt/spire/bin/oidc-discovery-provider` | — | official image ENTRYPOINT |
| everything else | its own `ENTRYPOINT` binary only | — | no `Command::new`/subprocess found in source |

**Tetragon prerequisite:** every `TracingPolicyNamespaced` requires the
Tetragon agent DaemonSet running on the node — a cluster add-on, **not
part of this chart set**. `helm install` succeeds without it (the CRD
object is created either way), but enforcement is inert until Tetragon is
actually running. Each chart exposes `tetragon.enabled` (default `true`) to
render without the policy in a cluster that hasn't rolled Tetragon out yet.

## PSA namespace baseline

Native Pod Security Admission enforces at the **namespace** level only —
there is no per-pod exemption. This chart set does **not** create
`kind: Namespace` objects (there is no existing precedent for it here, and
doing so from 12+ independently-installed charts sharing one namespace
would create Helm ownership collisions on the *same* object name). Applying
these labels is a one-time, pre-`helm install` **live-ops step**:

```bash
kubectl label namespace skauswatch pod-security.kubernetes.io/enforce=baseline \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted --overwrite
kubectl label namespace vault pod-security.kubernetes.io/enforce=restricted \
  --overwrite
```

**Why `skauswatch` is `baseline`, not `restricted`, today:**

| Chart | Blocks `restricted` because | PSA tier needed |
|---|---|---|
| scanner | `capabilities.add: [NET_RAW]` for masscan (`restricted` only permits adding `NET_BIND_SERVICE`) | `baseline` |
| monitor | Prospective `hostPath` volumes for `journalctl`/`tail`'s host log paths (`restricted` forbids `hostPath`) — **not yet wired in this chart** (flagged in `services/monitor/src/collectors/mod.rs`, out of scope for this pass), but the namespace floor accounts for it now so wiring it later isn't also a PSA fire drill | `baseline` |
| endpoint-agent | `privileged: true`, `hostPID`, `hostNetwork` (pre-existing ROOT EXCEPTION) | `privileged` — see below, not compatible with `baseline` either |
| spire-agent | Runs as root (`runAsUser: 0`) to manage the SPIFFE Workload API socket directory — common, documented SPIRE requirement | `baseline` |

`audit=restricted` / `warn=restricted` are set alongside `enforce=baseline`
as the standard PSA "ratchet" pattern — every `restricted` violation is
still visible (audit log + `kubectl` warning) without blocking anything,
so the gap to full `restricted` stays measured rather than silent.
Everything else in `skauswatch` (manager, s3scan, pki, sshca, logs,
codescan-backend, worker-codescan, webui) is already fully
`restricted`-compliant (`runAsNonRoot`, `drop: [ALL]`, no added
capabilities, `seccompProfile: RuntimeDefault` — added by this pass to
every chart's `podSecurityContext`).

**`vault` namespace is `restricted`** — both `vault` and
`worker-vault-sync` are fully compliant already (no special capabilities,
no host access).

**Recommended follow-up (not applied here — a deployment-topology decision
outside chart-authoring scope):** split `endpoint-agent` into its own
namespace (e.g. `skauswatch-agents`) labeled `enforce=privileged`, so
`skauswatch` itself can eventually drop to `restricted` once scanner's
NET_RAW and monitor's prospective hostPath are the *only* remaining gaps
(both stay at `baseline` regardless — neither is compatible with
`restricted`). Flagging this for the user/k8s-ops rather than moving
endpoint-agent unilaterally, since namespace topology affects RBAC and
deploy tooling beyond this chart.

**spire csi-driver: privileged, no CNP/Tetragon policy applied.**
`spire.csiDriver.enabled` defaults `false` (already documented in
`manager/values.yaml` and `spire/values.yaml` as requiring explicit user
approval before enabling — `privileged: true` to bind-mount the kubelet
plugin socket). Left out of this pass's enforcement since it's disabled by
default; add both when/if it's approved and turned on.

## At-rest encryption baseline

This chart set owns almost no storage directly — Postgres, Valkey, and S3
buckets are external dependencies (managed service or a StorageClass this
repo doesn't define), so at-rest encryption is primarily a **provider/
StorageClass configuration requirement**, not something rendered into a
Deployment manifest. No env var was invented here that the Rust services
don't already read (checked: no `DB_SSLMODE`/`S3_SSE`-style config exists
in `services/*/src` today — adding an unused ConfigMap key would be a
values.yaml lie, not a control).

| Layer | Requirement | Where it's enforced |
|---|---|---|
| Postgres | Storage/volume encryption enabled at the managed-DB or StorageClass layer | Provider config — not a K8s manifest in this repo |
| pki's PVC (`k8s/helm/pki/values.yaml persistence.storageClassName`) | **The only Kubernetes-native volume in the whole product** (holds the CA root private key) — MUST point at an encryption-at-rest-capable StorageClass in beta/gamma/production | Set per-environment values file; left `""` (cluster default) in the base chart since the real class name is cluster-specific |
| S3/object storage (manager, s3scan, worker-vault-sync buckets) | Default bucket encryption (SSE-S3/SSE-KMS) enabled at the bucket/provider level | Provider config — bucket credentials are operator-supplied at runtime (`S3_CRED_ENCRYPTION_KEY`-style app-layer encryption already covers credentials-at-rest; bucket *contents* encryption is the provider's setting, independent of this chart) |
| Backups (`pg_dump` targets, Vault sync targets) | Land in a volume/bucket with equivalent encryption to the primary store | Provider config |
| Enterprise customer-managed KMS (AWS KMS / GCP Cloud KMS / Azure Key Vault) | Additive on top of the platform-managed-key baseline above — license-gated (Enterprise tier, per `general.md`) | Not implemented in this pass — documented hook only; wire through `license_client.get_tier()` when a customer-KMS feature is built |

## Live-ops checklist (before first deploy of this pass)

- [ ] `kubectl label namespace skauswatch/vault ...` (PSA labels above)
- [ ] Confirm the actual Postgres/Valkey Service pod labels match
      `app.kubernetes.io/name: postgresql` / `valkey` in every chart's CNP,
      or update the generated egress `matchLabels`
- [ ] Install the Tetragon agent DaemonSet cluster-wide (or set
      `tetragon.enabled: false` per chart until it is)
- [ ] Set `pki.persistence.storageClassName` to a real encrypted
      StorageClass name in beta/gamma/production values
- [ ] Confirm Postgres/S3 storage-encryption flags are on at the provider
      before first write of real data
