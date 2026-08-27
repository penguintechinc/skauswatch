# Phase 11 R3/R4 — cluster cutover checklist (dal2/AWS/human required)

Everything in this doc **requires dal2 cluster access, an AWS account, or a
human decision** — none of it can be done by editing chart/values files in
this repo. Chart authoring, render-verification, and code work for Phase 11
R3 are complete; this is the remaining live-ops sequence for k8s-ops (or
whoever holds dal2/AWS credentials) to execute in order. Each step has a
concrete command/action, the expected result, and how to verify before
moving to the next step. Steps within a numbered section are ordered;
sections are ordered top-to-bottom except where marked independent.

## Already done — do not redo

| Item | Evidence |
|---|---|
| SPIRE chart authored (server, agent, auto-enroll Job, federation, OIDC provider, CSI driver, nested-topology wiring) | `k8s/helm/spire/` — `helm lint` + `helm template` clean across alpha/beta/gamma/production × {defaults, nested-child, federation, oidc+csi, all-combined} = 20/20 combinations, 0 render errors |
| Image-ref double-suffix bug (`@sha256:...` + trailing `:tag`) | Checked every `image:` line across all 20 rendered combinations — none found; chart already carries the preventive comment in `templates/oidc-provider-deployment.yaml` |
| **SPIRE workload-attestation selector bug** (`autoEnroll.services[].serviceAccount` used the bare service name, e.g. `manager`, instead of the actual rendered ServiceAccount name, e.g. `manager-skauswatch-manager` — every chart leaves `fullnameOverride` empty and is deployed via `helm upgrade --install <svc> ./k8s/helm/<svc>`, so `<chart>.fullname` always produces `<svc>-skauswatch-<svc>`) | Fixed in `k8s/helm/spire/values.yaml` for all 14 in-repo services (13 pre-existing + `depgate`). **This bug would have silently broken SVID issuance for every skauswatch workload** — the SPIRE entry's `k8s:sa:<name>` selector never matched a real pod, so workload attestation would fail for 100% of services on first live cutover. Caught by render-diffing this file against each service chart's actual `helm template` output, not by lint/schema validation (kubeconform/helm lint have no way to know what a *different* chart's fullname helper produces) |
| `depgate` registered in SPIRE auto-enroll (`k8s/helm/spire/values.yaml`) | New `autoEnroll.services` entry, namespace `skauswatch`, serviceAccount `depgate-skauswatch-depgate` |
| `depgate` SPIFFE ID + mesh-admin listener documented | `docs/v2-port/service-auth-model.md` §1 table + who-calls-whom table |
| `endpoint-agent` base SPIFFE ID documented (was missing — only `endpoint-agent-maintenance` was listed) | `docs/v2-port/service-auth-model.md` §1 table |
| Both AWS STS exchanges (`sts:AssumeRole`, `sts:AssumeRoleWithWebIdentity` via a throwaway self-hosted OIDC issuer) validated against a **real AWS account** | `services/scanner/tests/aws_live.rs`, `tests/smoke/aws_identity/run.sh`; see `docs/v2-port/aws-identity-runbook.md` "Validated (this session)" |
| PSA namespace-label commands, Cilium pod-label dependency-assumption caveat, at-rest-encryption-is-a-StorageClass-concern note | Already documented in `k8s/helm/README.md` ("PSA namespace baseline", "Dependency label assumption", "At-rest encryption baseline") — this checklist executes them, does not re-derive them |

## Flagged during this audit — needs a decision before beta soak (not fixed here)

**SPIRE child server CA/datastore is not persisted across pod restarts on
beta and gamma.** `beta.yml`/`gamma.yml` both set `spire.server.dataStore.type:
sqlite`, and the sqlite path (`/run/spire/data`) is mounted from an
`emptyDir` (`k8s/helm/spire/templates/server-deployment.yaml`) — the
`KeyManager "disk"` plugin's signing keys live in that same directory. A
pod restart (rollout, eviction, crash, node drain) wipes both, so the
child server generates a **new** self-signed/upstream-requested CA on
every restart: every previously-issued SVID stops validating, and the
child must re-run the join-token bootstrap against root from scratch
(§2 below) if nested. This is not a rendering bug (it renders and lints
clean) and not one of this pass's four scoped tasks — it's a design
tradeoff (sqlite was chosen as "zero-dependency bootstrap" per
`values.yaml`'s own comment) that has an operational consequence nobody
has weighed in on yet. **Options, in order of effort:** (a) accept the
risk for beta/gamma pre-GA (they're not customer-facing), (b) add a small
PVC for `/run/spire/data` instead of `emptyDir` (keeps sqlite, needs a
StorageClass decision — see §4), (c) point beta/gamma at NEST-hosted
PostgreSQL now instead of waiting, matching what `production.yml` and
`root.example.yml` already do. **Raise with the user before the beta soak
window (§7) — a mid-soak spire-server pod restart with option (a) accepted
will silently break every service's mTLS until agents re-attest, which
looks like a mesh outage, not a known tradeoff, if nobody remembers this
was accepted.**

---

## 1. Nested SPIRE bring-up — root

1. **Decide where root physically lives** (cluster/namespace) — architecture
   decision, not encoded in any chart file. `root.example.yml` assumes a
   dedicated `spire-root` namespace on some cluster, not necessarily dal2
   itself. **Blocks everything below.**
2. Install root:
   ```bash
   helm upgrade --install spire-root ./k8s/helm/spire \
     --kube-context <root-cluster-context> \
     --namespace spire-root --create-namespace \
     --values ./k8s/helm/spire/root.example.yml
   ```
   Expected: `spire-root-server` pod `Running`/`Ready`; `kubectl exec` into
   it and run `spire-server healthcheck` returns healthy.
3. Verify OIDC discovery is live (root.example.yml sets `oidcProvider.enabled:
   true`, `issuerHost: spire-oidc.dal2.penguintech.cloud`):
   ```bash
   curl -fsS https://spire-oidc.dal2.penguintech.cloud/.well-known/openid-configuration
   curl -fsS https://spire-oidc.dal2.penguintech.cloud/.well-known/jwks.json
   ```
   Expected: both return valid JSON (200). **TLS must terminate with a
   real (non-self-signed) CA cert** — verify with `openssl s_client
   -connect spire-oidc.dal2.penguintech.cloud:443 -showcerts` and confirm
   the chain doesn't terminate in a self-signed root.

## 2. Nested SPIRE bring-up — per child (beta, then gamma, then prod)

Repeat once per child. Do beta first; do not proceed to gamma/prod until
beta's join has been confirmed healthy for at least a few hours (this
validates the join-token/trust-bundle mechanics work before repeating them
against gamma/prod).

1. Generate a one-time join token on root:
   ```bash
   kubectl exec -n spire-root deploy/spire-root-skauswatch-spire-server -- \
     /opt/spire/bin/spire-server token generate \
     -spiffeID spiffe://penguintech.io/spire/server/dal2-beta \
     -socketPath /tmp/spire-server/private/api.sock
   ```
   Expected: a token string printed. **One-time use — minting a second
   token invalidates the first if unused.**
2. Get root's trust bundle:
   ```bash
   kubectl exec -n spire-root deploy/spire-root-skauswatch-spire-server -- \
     /opt/spire/bin/spire-server bundle show \
     -socketPath /tmp/spire-server/private/api.sock > /tmp/root-bundle.pem
   ```
3. Create the child-side Secret + ConfigMap the chart expects
   (`topology.upstreamRoot.joinTokenSecret`/`trustBundleConfigMap` in
   `values.yaml`):
   ```bash
   kubectl create secret generic spire-upstream-join-token \
     --context dal2-beta --namespace skauswatch \
     --from-literal=token='<token from step 1>'
   kubectl create configmap spire-upstream-root-bundle \
     --context dal2-beta --namespace skauswatch \
     --from-file=bundle.pem=/tmp/root-bundle.pem
   ```
4. Flip `beta.yml`: set `spire.topology.upstreamRoot.enabled: true` and
   `serverAddress` to root's reachable address, then:
   ```bash
   helm upgrade --install spire ./k8s/helm/spire \
     --kube-context dal2-beta --namespace skauswatch \
     --values ./k8s/helm/spire/beta.yml
   ```
   Expected: `spire-server` pod restarts with the downstream-agent sidecar;
   `kubectl logs -n skauswatch deploy/spire-skauswatch-spire-server -c
   downstream-agent` shows a successful attestation to root, no
   `insecure_bootstrap` errors.
5. On root, register the child as a downstream authority once its agent
   entry appears:
   ```bash
   kubectl exec -n spire-root deploy/spire-root-skauswatch-spire-server -- \
     /opt/spire/bin/spire-server entry create -downstream \
     -spiffeID spiffe://penguintech.io/spire/server/dal2-beta \
     -parentID <the new agent's SPIFFE ID from step 4's logs> \
     -selector <the join_token attestation selector from step 4's logs> \
     -socketPath /tmp/spire-server/private/api.sock
   ```
6. Verify: `kubectl exec` into the child's `spire-server` and run
   `spire-server healthcheck -socketPath /tmp/spire-server/private/api.sock`
   — expect healthy, and `spire-server bundle show` on the child should now
   return a bundle chaining to root's, not a fresh self-signed one.
7. Repeat for gamma (`downstreamSpiffeID: spiffe://penguintech.io/spire/server/dal2-gamma`)
   and prod (`spiffe://penguintech.io/spire/server/skauswatch-prod`).

## 3. AWS IAM OIDC provider + role trust policies (per customer external-id)

Depends on §1 step 3 (root's OIDC discovery must be live and TLS-valid
first). Full Terraform templates: `docs/v2-port/aws-identity-runbook.md`
§1/§2 — this is the execution order, not new Terraform.

1. Compute the TLS thumbprint of `spire-oidc.dal2.penguintech.cloud`'s
   certificate chain and register the OIDC provider (one-time per AWS
   account):
   ```bash
   terraform apply -target=aws_iam_openid_connect_provider.spire
   ```
   Expected: `aws iam list-open-id-connect-providers` shows the new
   provider ARN.
   **Note (proven this session, see aws-identity-runbook.md "Validated"):**
   AWS does not actually enforce the thumbprint match for issuers whose
   TLS cert chains to a publicly trusted CA — re-derive on rotation anyway
   as defense-in-depth, but a transient mismatch during a cert rotation
   window will not itself break the exchange for a public-CA-issued cert.
2. Apply `skauswatch_base`'s trust policy (`aws-identity-runbook.md` §1
   Step B) with one `sub` condition line per environment/service SPIFFE ID
   that needs AWS access — start with `s3scan` and `worker-vault-sync` per
   `service-auth-model.md` §4/§1.
3. Verify with a real exchange (reuse, don't reinvent):
   ```bash
   ./tests/smoke/aws_identity/run.sh
   ```
   This proves the mechanism generically (throwaway resources); it does
   **not** exercise the real `skauswatch_base` role from step 2 — follow
   with a manual `aws sts assume-role-with-web-identity` using a real
   JWT-SVID fetched from a live beta pod's SPIRE agent socket once step 2
   is applied, to confirm the *actual* production role trust policy (not
   just the mechanism) is correct.
4. Per customer: hand them `aws-identity-runbook.md` §2's Terraform
   template + `skauswatch_base`'s ARN; they apply it in their own account
   and paste the resulting role ARN + confirm their generated
   `external_id` into skauswatch's bucket-config UI. Repeat per customer —
   never share a trust/external-id pair across customers.

## 4. Namespace/cluster hardening on beta (independent of §1-3, do in parallel)

1. **Apply PSA labels** (exact commands already decided in
   `k8s/helm/README.md` "PSA namespace baseline" — do not deviate without
   updating that doc first):
   ```bash
   kubectl --context dal2-beta label namespace skauswatch \
     pod-security.kubernetes.io/enforce=baseline \
     pod-security.kubernetes.io/audit=restricted \
     pod-security.kubernetes.io/warn=restricted --overwrite
   kubectl --context dal2-beta label namespace vault \
     pod-security.kubernetes.io/enforce=restricted --overwrite
   ```
   Verify: `kubectl get ns skauswatch vault --show-labels`; then `helm
   upgrade` every chart in `skauswatch` and confirm no pod is rejected at
   admission (a `baseline` violation shows as `audit`/`warn` only, not a
   block — a real block means something regressed below `baseline`, e.g. a
   chart accidentally gained a new required capability).
2. **Verify the Cilium pod-label dependency assumption** (`k8s/helm/README.md`
   "Dependency label assumption") — the generated CiliumNetworkPolicy
   egress rules for Postgres/Valkey match `app.kubernetes.io/name:
   postgresql` / `app.kubernetes.io/name: valkey`:
   ```bash
   kubectl --context dal2-beta -n skauswatch get pods --show-labels | grep -E 'postgres|valkey|redis'
   ```
   Confirm the actual deployed pods carry those exact labels. **A mismatch
   here silently blocks DB/cache access once the CNP is enforced** — Cilium
   matches by pod identity, not Service name, so this doesn't show up as a
   Helm/render error, only as a live connection timeout.
3. **Verify at-rest StorageClass assumptions** (`k8s/helm/README.md`
   "At-rest encryption baseline") — confirm whatever StorageClass backs
   beta's Postgres/Valkey PVCs has encryption-at-rest enabled at the
   provisioner level (this chart set has no PVC of its own to configure —
   it's a provider-side setting):
   ```bash
   kubectl --context dal2-beta get pvc -n skauswatch -o custom-columns=NAME:.metadata.name,STORAGECLASS:.spec.storageClassName
   kubectl --context dal2-beta get storageclass <name> -o yaml
   ```
   Confirm the StorageClass's provisioner parameters include at-rest
   encryption (exact field is provisioner-specific — e.g. `encrypted:
   "true"` for an EBS-backed class). If not, this is a `security.md`
   compliance gap independent of SPIRE — flag to whoever owns beta's
   storage provisioning, not something a values.yaml change can fix.
4. **Decide the SPIRE sqlite-persistence question** flagged above before
   proceeding to §7 (beta soak) — whichever option is chosen, confirm
   it's applied on beta before starting the soak clock, since a pod
   restart mid-soak is otherwise expected to happen and will invalidate
   the results.

## 5. `ASM_SCREENSHOT_BUCKET` config (scanner ASM screenshot capture)

Independent of SPIRE/AWS-identity work above; bundled here because it's
another "needs a real bucket + cluster access" item discovered in the same
audit pass.

1. Provision (or designate an existing) S3/MinIO bucket for ASM screenshot
   artifacts (`services/scanner/src/asm.rs` — `asm/{tenant_id}/{scan_id}/{service_id}.png`
   keying, uses the standard AWS-provider-chain client, not per-tenant STS).
2. Set `ASM_SCREENSHOT_BUCKET` (and confirm `ASM_SCREENSHOT_ENABLED` is the
   intended value — defaults `true`) in `k8s/helm/scanner`'s beta/gamma/
   production values — **not this chart's concern** (`k8s/helm/spire` has
   no scanner config), flag to whoever owns `k8s/helm/scanner`.
3. **Two prerequisites already flagged in `services/scanner/src/asm.rs`'s
   own doc comment, unresolved as of this audit — confirm before enabling
   in a live cluster, not just before merging code:**
   - `chromium`/`chromium-browser` binary is not yet installed in
     `services/scanner/Dockerfile` — screenshot capture will fail-safe
     (logged, scan continues) but silently produce zero screenshots until
     this is added.
   - Any Tetragon `TracingPolicy` gating the scanner pod must additionally
     allow `chromium` spawning `--type=renderer`/`--type=zygote`/
     `--type=gpu-process` child processes, or the eBPF layer kills them
     before `asm.rs`'s own error handling ever sees a failure — check
     `k8s/helm/scanner/templates/tracingpolicy.yaml` allowlist before
     relying on screenshots being captured, not after noticing they're
     always empty.
4. Verify: run a scan against a target with at least one HTTP(S) service,
   confirm rows appear in `asm_screenshots` and the referenced S3 keys are
   fetchable.

## 6. Smoke tests

1. Chart-level (already passing, re-run post-cutover to confirm the live
   values match what was verified statically):
   ```bash
   helm lint ./k8s/helm/spire --values ./k8s/helm/spire/beta.yml
   helm template spire ./k8s/helm/spire --values ./k8s/helm/spire/beta.yml | kubectl --context dal2-beta apply --dry-run=server -f -
   ```
2. Mesh smoke test — confirm a real workload actually gets an SVID:
   ```bash
   kubectl --context dal2-beta exec -n skauswatch deploy/manager-skauswatch-manager -- \
     /opt/spire/bin/spire-agent api fetch x509 -socketPath /run/spire/sockets/agent.sock
   ```
   (Requires manager's chart to already mount the Workload API socket per
   `k8s/helm/spire/README.md` "Service-pod SVID pattern" — if not yet
   wired for a given service, this step blocks on that chart's own
   deferred-items list, not on this chart.) Expected: a valid X.509-SVID
   printed with SPIFFE ID `spiffe://penguintech.io/beta/manager`.
3. `make test-integration` / `make smoke-test` per the repo's standard
   pre-deploy gate — run against a freshly-deployed beta, not a
   long-running one (see `testing.md` "delete cluster before smoke/e2e
   tests").
4. AWS identity — `./tests/smoke/aws_identity/run.sh` (already run this
   session with throwaway resources; re-run against beta's actual pod
   environment once §3 step 2's real role trust policy is applied, per §3
   step 3 above).

## 7. Beta soak window

1. Leave beta running with real traffic/synthetic load for a defined
   window (recommend **≥72h**, matching the shortest SVID rotation cycle
   many times over — 5m TTL means ~800+ rotations in 72h, enough to catch
   a rotation-edge bug that a single manual fetch in §6 step 2 would miss).
2. Monitor for: SVID rotation failures (agent logs), any `spire-server`
   pod restart (see the flagged sqlite-persistence risk above — a restart
   during soak is itself a signal, not just noise), mTLS handshake
   failures once §2's mTLS wiring (service-auth-model.md §2) lands on
   pki/manager.
3. Exit criteria: zero unplanned `spire-server`/`spire-agent` restarts, zero
   SVID-fetch failures logged by any service that mounts the Workload API
   socket, OIDC discovery endpoint uptime 100% over the window (external
   dependency for AWS — a gap here doesn't break the mesh itself but does
   break AWS federation silently).

## 8. Rollback rehearsal

Do this **before** gamma/prod bring-up (§2 step 7), not after — the whole
point is proving the rollback path works before you need it for real.

1. On beta, simulate a bad `helm upgrade` (e.g. deploy with
   `topology.upstreamRoot.enabled: true` but a wrong `serverAddress`) and
   confirm:
   ```bash
   helm rollback spire <previous-revision> --kube-context dal2-beta --namespace skauswatch
   ```
   restores the prior working state. Expected: `spire-server` returns to
   standalone/previously-nested mode, agents re-attest, no manual
   intervention beyond the rollback command needed.
2. Rehearse the **join-token re-bootstrap** path specifically (§2 steps
   1-5) — since this is the step most likely to need repeating if a child
   ever needs to re-join root (e.g. after an accepted sqlite-persistence
   CA loss per the flagged risk above): mint a fresh token, re-run steps
   3-5, confirm the child recovers without a full chart reinstall.
3. Document actual elapsed time for both rehearsals — this becomes the
   basis for an incident-response time estimate if either needs to happen
   for real during gamma/prod cutover.

## SPIRE datastore provisioning (NEW — blocks beta soak)

Decided 2026-08-22: beta/gamma SPIRE moved off ephemeral sqlite-on-emptyDir (a
server pod restart wiped the CA and silently broke mesh mTLS for every workload)
onto PostgreSQL, matching production.

- [ ] **Create the `spire` database + a per-service account** on the beta
      in-cluster PostgreSQL (`postgres` service, the host every other chart's
      `beta.yml` uses). Grants: full DDL+DML on the `spire` database only —
      SPIRE manages its own schema. Per `backend.md`, this is its own account,
      not a shared one.
- [ ] **Create the `spire-db-credentials` Secret** in the `skauswatch` namespace
      (key names per the chart's server ConfigMap/Deployment). Verify with
      `kubectl get secret spire-db-credentials -n skauswatch`.
- [ ] Repeat both for gamma.
- [ ] **Verify CA survives a restart** (this is the whole point):
      `kubectl rollout restart deploy/spire-server -n skauswatch`, wait Ready,
      then confirm an existing workload's SVID still validates and that
      `spire-server entry show` still lists the auto-enrolled entries. A wiped
      CA shows up as every workload failing mTLS at once.
- [ ] **Provision & confirm the production PostgreSQL datastore.**
      `production.yml` now points SPIRE's datastore at the in-cluster
      `postgres` Service (this repo's convention, matching beta/gamma), so it
      no longer references the retired `marchproxy` product. Before cutover:
      (a) confirm that database exists in the prod cluster — or, if prod uses a
      managed/external DB (e.g. DigitalOcean Managed PostgreSQL), set `host` to
      that endpoint (the single value to change); (b) create the `spire`
      database and the `spire-db-credentials` secret. Production keeps
      `sslMode: verify-full` (do NOT downgrade); if the server cert is from a
      private CA, mount the CA bundle and set `sslRootCert`.
