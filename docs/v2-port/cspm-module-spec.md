# CSPM — Cloud Security Posture Management

**Status:** Draft design spec · **Target:** v2.1+ (net-new) · **Flag:** `skauswatch.cspm` (default OFF)

> **Sibling-spec note:** this doc cross-references `/home/penguin/.cache/sw-specs/edr-module-spec.md` (exists, read for cross-module consistency — §1/§7/§8 below build directly on its findings) and was asked to reconcile against a SIEM module spec that does not exist at any known path in this session — same situation EDR's own doc flagged for its SIEM sibling. House-tone/structure grounding otherwise comes from `docs/v2-port/v2.1-codescan-sentinel.md` and `docs/v2-port/v2.1-depgate.md`, both read in full.

Cloud Security Posture Management: periodic, read-only auditing of a customer's cloud **control plane** — the provider API/IAM layer that decides *who can do what to what*, as opposed to the workloads or data running inside it. Canonical example checks: public S3 buckets, wildcard IAM policies, security groups open to `0.0.0.0/0`, unencrypted EBS/RDS, disabled CloudTrail/VPC flow logs, root account without MFA. AWS first; Azure/GCP/DigitalOcean later (§3, §6).

**Concept reference, clean-room:** NCC Group's [ScoutSuite](https://github.com/nccgroup/ScoutSuite) is used here only as *prior art for the problem shape* (multi-cloud config audit, ruleset-per-resource-type, severity-tagged findings). ScoutSuite is **GPL-2.0**. This spec, and any implementation of it, contains **zero ScoutSuite code, zero copied rule text, zero copied check descriptions**. `deny.toml`'s `[licenses].allow` list (root of this repo) is permissive-only — `MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Unicode-3.0, Zlib, MPL-2.0, CDLA-Permissive-2.0, OpenSSL`, plus the workspace's own `AGPL-3.0-only` for internal `crates/*`/`services/*` only (`private = { ignore = true }`). GPL-2.0/AGPL from any third-party dependency is **not** in that list — `cargo deny check` fails closed on it. That is the enforcement mechanism this spec relies on, not a policy statement alone (§7).

## 1. Positioning

| | `services/scanner` (ASM) | `services/s3scan` | **CSPM** |
|---|---|---|---|
| Watches | the network-facing perimeter (masscan/banner/cert/screenshot) | objects already inside a customer S3 bucket | the cloud **provider API** itself — IAM, EC2, CloudTrail, Config, RDS |
| Signal | open ports, service banners, TLS cert posture, exposed HTTP surfaces | malware/PUP verdict on object bytes (ClamAV+YARA-X) | resource **configuration** vs. a declarative rule (public/private, encrypted/not, logged/not) |
| Consumes | `masscan`/headless-chromium subprocesses | shared scan-core (ClamAV+YARA-X), threat-intel enrichment | AWS control-plane SDK clients (§3), SPIFFE→STS federation |
| Feeds | `asm_*` tables, manager's own per-scan `/report` aggregate | `s3_scan_results`, object tags (verdict-as-tag) | new `cspm_findings` (§4), a findings REST surface |

**Naming collision worth calling out explicitly:** `services/scanner`'s own internal module is literally named `asm` (Attack Surface Management — masscan/banner/cert/screenshot). CSPM is a **different, unrelated axis** despite the industry term "ASM" sometimes overlapping in vendor marketing with "cloud posture." A public S3 bucket with a permissive ACL may present nothing interesting to a port scan at all — the misconfiguration is only visible by calling the AWS API, never by touching the network. Scanner/ASM and CSPM are complementary, not redundant: one asks "what does an outside attacker see," the other asks "what did we configure wrong that they'd exploit once they're in, or that leaks data with no exploit at all."

**Exec-report co-surfacing — grep-confirmed, does not exist today.** The task framing for this module (and EDR's spec before it, §8/§9 there) assumes findings from Sentinel/DepGate/EDR/CSPM eventually roll into one executive report. Searched the whole tree for an aggregator: every hit is a **per-module** aggregate —
- `services/manager/src/routes/asm.rs` — one service's own `/report` endpoint aggregating its own hosts/certs/screenshots.
- `services/manager/src/routes/siem.rs` — OpenSearch terms-aggregation for that one service's own `/siem/stats`.
- `services/depgate/src/mesh_admin.rs` — its own docstring says a cross-tenant caller "doing cross-tenant aggregation/reporting" is a *future* consumer, not a built one.
- `docs/v2-port/service-auth-model.md` §depgate mesh listener: "narrow to a specific identity once a real caller (e.g. a cross-tenant reporting aggregator) is implemented" — explicitly not implemented.

**No server-side cross-module exec-report aggregator exists anywhere in this codebase.** `services/codescan-backend/src/routes/findings.rs` is Sentinel's own findings REST surface — not a generic "exec-report pipeline"; no such generic pipeline exists to plug into. What CSPM can honestly claim today is **shape compatibility**: `cspm_findings` follows the same DTO/tenant/kind/severity/status vocabulary as `codescan_findings` (§4), so a *future* aggregator could `UNION`/fan-out across both tables cheaply — but nothing does that union today. CSPM is the **third** module (after Sentinel/DepGate's own report surfaces and EDR's spec) to independently arrive at "we need this and it isn't built" — see §8 Open Decision 1.

## 2. Separate independent module

`worker-cspm` — a new, standalone Rust/Axum service (`services/worker-cspm`), reserving `spiffe://penguintech.io/<env>/worker-cspm` on the mesh per `docs/v2-port/service-auth-model.md`'s service roster convention. Whole-platform-Rust is already the settled house direction for skauswatch (its own approved all-Rust exception, same one EDR's spec leans on for staying in-repo) — no Python/Go considered.

**Architectural precedent chosen: DepGate's single-binary shape, not Sentinel's two-binary split.** The workspace has two live patterns for a scan module:

| | `worker-codescan` + `codescan-backend` (Sentinel) | `services/depgate` |
|---|---|---|
| Deployables | 2 (stream-consumer worker; separate REST backend) | 1 |
| Findings REST auth | proxied through `services/manager`'s `codescan.rs` pure-proxy (`WORKER_CODESCAN_URL`), an **old v1-carryover pattern** | the service's **own** `tenant_middleware` + `FlagGate`-gated `/api/v1/depgate/*`, no manager hop — webui talks to it directly |
| Manager proxy route? | Yes (`services/manager/src/routes/codescan.rs`) | **No** — grepped `services/manager/src/routes/`, only `codescan.rs` exists; DepGate has none |

DepGate is the newer, net-new-in-v2 module and deliberately skipped the manager-proxy hop. `worker-cspm` follows DepGate: one deployable, its own JWT/tenant-scoped `/api/v1/cspm/*` admin+findings surface (mirroring `findings.rs`'s DTO/pagination/flag-gate shape, not proxied through manager), plus a separate mesh-only mTLS admin listener on its own port (DepGate's `mesh_admin.rs` precedent) for any future cross-tenant fleet summary a central aggregator might call (§8 Decision 1) — reachable only by a same-trust-domain SPIFFE peer, never client-facing.

**Scheduler + lease + scan-core + findings-pipeline, mirrored from worker-codescan's shape (pattern, not literal crate reuse):**

| Layer | Mirrors | Notes |
|---|---|---|
| `scheduler.rs` | `worker-codescan/src/scheduler.rs` | `due_accounts()` query (elapsed `polling_interval_minutes` or never-scanned) → enqueue onto a new `cspm:tasks` Redis Stream → stamp `last_scan_at`. Default interval 1440 min (daily), per-account overridable, same column shape as `codescan_repo_configs`. |
| `lease.rs` | `worker-codescan/src/lease.rs` | Same Valkey `SET NX PX` acquire/release primitive so multiple `worker-cspm` scheduler replicas never double-enqueue one cloud account in the same tick. **This is the pattern's second consumer** (worker-codescan is the first) — worth extracting to a shared crate once a third need arises, not before; noted, not acted on here. |
| `cspm_scan.rs` (new) | `worker-codescan/src/sentinel.rs` | Pure-compute layer: takes a resolved AWS client + account, calls control-plane APIs, evaluates the declarative rule set (§4), returns `Vec<CspmFinding>`. Never touches the DB directly — a `handler.rs` orchestrator persists, same split as Sentinel's `sentinel.rs`/`handler.rs`. |
| findings-pipeline | `codescan-backend/src/routes/findings.rs` | `Finding` DTO shape (explicit struct, not raw row passthrough), pagination, `?kind=`/`?severity=`/`?status=` filters, flag-gate helper — reused as a **pattern**, implemented as `worker-cspm`'s own route module per the DepGate single-binary decision above. |

**Explicitly NOT reused:** `crates/skauswatch-scan-core` (the ClamAV+YARA-X byte-scanning engine DepGate P0 extracted for s3scan/scanner/DepGate) has no application here — CSPM never scans bytes, it evaluates structured API responses. Naming a CSPM module "scan-core" anywhere in implementation would be misleading; call it `cspm_scan.rs`/`rules.rs` instead.

## 3. Cloud coverage & auth

**AWS first.** Grepped the workspace's AWS SDK footprint:

| Crate | Status | Plane |
|---|---|---|
| `aws-config` (`=1.9.0`), `aws-sdk-s3` (`=1.138.0`), `aws-sdk-sts` (`=1.108.0`), `aws-sdk-secretsmanager` (`=1.90.0`) | **Already pinned**, workspace-level exact versions, consumed by `manager`/`s3scan`/`worker-vault-sync`/`scanner`/`depgate`/`crates/skauswatch-s3` | Data-plane (objects, secrets, STS token exchange) |
| `aws-sdk-iam`, `aws-sdk-ec2`, `aws-sdk-cloudtrail`, `aws-sdk-config`, `aws-sdk-rds` | **New — zero hits anywhere in the tree** | Control-plane (exactly what CSPM needs) |

All five new crates are the official `aws-sdk-rust` generated clients, dual `Apache-2.0`/`MIT` — same licensing family as the four already-pinned SDK crates, `cargo-deny`-clean against the existing permissive allow list with **no `deny.toml` changes required**. Pin exact versions from the same `aws-sdk-rust` release train already resolved in `Cargo.lock` (the `aws-config =1.9.0` generation) to avoid duplicate transitive `aws-smithy-runtime`/`aws-smithy-types` versions — verify with `cargo tree -d` at implementation time rather than assuming; don't invent version numbers ahead of that check. Follow root `Cargo.toml`'s established pattern of `default-features = false` + an explicit trimmed feature list (the existing comments there explain why: avoiding the legacy `tls-rustls`/`rustls 0.21` stack pulled in by SDK crates' own `"rustls"` default feature, in favor of the modern `rustls-aws-lc` client already standardized on).

**Auth — reuse the SPIFFE→AssumeRoleWithWebIdentity chain end-to-end** (`docs/v2-port/aws-identity-runbook.md`, validated live against real AWS in that doc's own session):

```
worker-cspm pod SPIFFE X.509-SVID
  → fetch_jwt_svid("sts.amazonaws.com")                    [skauswatch-identity, unchanged]
  → sts:AssumeRoleWithWebIdentity → skauswatch_base          [same base role s3scan already uses]
  → sts:AssumeRole(cspm_role_arn, external_id) → customer's dedicated CSPM audit role
  → iam:List*/Get*, ec2:Describe*, cloudtrail:*, config:*, rds:Describe*, s3:GetBucket*/GetPublicAccessBlock
```

**Deliberately a separate customer-side role from s3scan's**, not a shared one — even though both ultimately trust the same `skauswatch_base` principal. s3scan's `skauswatch-scan` role is scoped to `s3:GetObject`/`s3:ListBucket` on one bucket; CSPM needs account-wide **read** across IAM/EC2/CloudTrail/Config/RDS — a materially larger blast radius if `skauswatch_base` or `worker-cspm` were ever compromised (read-only IAM/CloudTrail enumeration is itself high-value recon). Splitting the role lets a customer revoke CSPM access without touching S3-scan access, and vice versa. Recommend the customer attach AWS's own managed `arn:aws:iam::aws:policy/SecurityAudit` policy as the P1 baseline (purpose-built, AWS-authored, exactly this read-only-audit shape) rather than hand-rolling an equivalent — open decision, §8. Onboarding mirrors the runbook's §4 flow: skauswatch generates a per-customer `external_id`, customer applies a Terraform template creating `skauswatch-cspm` (not `skauswatch-scan`) trusting `skauswatch_base`'s ARN + that `external_id`, pastes the resulting role ARN into a new `cspm_cloud_accounts.role_arn` column (same shape as `s3_bucket_configs`' existing `role_arn`/`external_id` pair).

**Azure/GCP/DigitalOcean (later, §6):** none of the three have an AWS-OIDC-federation equivalent this clean. Azure Workload Identity Federation and GCP Workload Identity Federation are both real and SPIFFE-JWT-compatible in principle, but neither is proven against this codebase the way §1/§2 of the AWS runbook now is — real research needed, not assumed here. DigitalOcean has no workload-identity federation product at all; a DO API token is a genuine stored secret (§7).

## 4. Check/rule model

Declarative shape: `resource_type → condition → severity → remediation`, each check tagged with a CIS AWS Foundations Benchmark / AWS Foundational Security Best Practices (FSBP) control ID **as a reference pointer only** — no benchmark text copied into this codebase, consistent with the clean-room requirement (§ above). Exact current control numbers are populated at implementation time against the live benchmark version, not fabricated in this design doc.

P1 implementation is **hardcoded Rust match arms** per check (mirrors Sentinel/DepGate's own P1 precedent of shipping a hardcoded policy before any rules-engine investment) — the rule-DSL question is deliberately deferred, §8 Decision 2.

Findings map into a **new** `cspm_findings` table, shape-compatible with `codescan_findings` but not the same table — `codescan_findings.repo_config_id` is a hard `NOT NULL` FK to a code repo, semantically wrong for a cloud resource. `cspm_findings` mirrors the pattern instead: `tenant_id`, `cloud_account_id` (FK to new `cspm_cloud_accounts`), `kind`, `severity` (`critical|high|medium|low|unknown`), `status`, `first_seen`/`last_seen`, `source`. Same `kind`/`severity`/`status` vocabulary as Sentinel's table is the actual "maps into the schema" contract — a future aggregator unions on that shared vocabulary, not on a shared table.

**New `kind` values (as specified): `cspm`, `iam`, `network`, `storage`.**

| Kind | Example P1 checks |
|---|---|
| `iam` | Wildcard (`"Action":"*","Resource":"*"`) managed/inline policies; root account without MFA; root account with active access keys; IAM users with console access and no MFA |
| `network` | Security groups allowing `0.0.0.0/0` on 22/3389/all-ports; default VPC security group overly permissive; VPC flow logs disabled |
| `storage` | S3 buckets with public ACL/policy; S3 buckets without default (SSE) encryption; EBS volumes unencrypted; RDS instances unencrypted |
| `cspm` | Account-wide governance controls that aren't tied to one resource type — disabled/partial CloudTrail (no active multi-region trail) is the canonical P1 example |

**Graceful degradation is a first-class status, never a panic and never a false "clean."** `cspm_scan_runs` mirrors `codescan_scan_runs`'s `status`/`error` shape, plus a `partial_errors` JSON column recording which specific checks failed to evaluate (e.g. `AccessDenied` on one Describe call because the customer's role is narrower than `SecurityAudit`) without failing the whole run. A check that could not be evaluated persists as `cspm_findings.status = 'unavailable'` (new third status value, alongside `open`/`resolved`) — the UI must show "could not evaluate — see partial_errors," never silently omit the row as if it passed.

## 5. Feature flag hierarchy

`{product}.{feature}` convention (`backend.md`), master flag default OFF, PostHog-gated, Enterprise entitlement on top via `license.penguintech.io` (domain-bypass rule applies as usual). Modeled directly on DepGate's master+`.socket` precedent — `skauswatch.depgate` gates the whole surface, `skauswatch.depgate.socket` gates one optional integration with a documented "silent, zero-request path" when off (`services/depgate/src/socket.rs`). CSPM's per-provider sub-flags follow the identical silent-no-op contract: with `.azure` off, the scheduler simply never enqueues an Azure-tagged account — not an error, not a partial scan, just nothing enqueued.

| Flag | Default | Tier | Gates |
|---|---|---|---|
| `skauswatch.cspm` | OFF | Enterprise | Master — cloud-account enrollment, `worker-cspm` scheduler, all sub-flags below inert if this is off |
| `skauswatch.cspm.aws` | OFF | Enterprise | AWS provider checks (P1) |
| `skauswatch.cspm.azure` | OFF | Enterprise | Azure provider checks (P3) |
| `skauswatch.cspm.gcp` | OFF | Enterprise | GCP provider checks (P3) |
| `skauswatch.cspm.digitalocean` | OFF | Enterprise | DigitalOcean provider checks (P4) |
| `skauswatch.cspm.remediation` | OFF | Enterprise | Remediation-guidance surface on each finding (P2) — human-readable fix steps, not auto-remediation |
| `skauswatch.cspm.drift-detection` | OFF | Enterprise | Event-driven drift detection beyond the daily full scan (P4) |
| `skauswatch.cspm.custom-rules` | OFF | Enterprise | Admin-authored checks beyond the built-in library (P4) — the point at which §8 Decision 2's DSL question becomes load-bearing |

Master flag sits at Enterprise across the whole hierarchy (unlike EDR, whose base telemetry is Professional with only `.response` at Enterprise) — CSPM's entire value proposition is compliance/audit posture, which is squarely the Enterprise "audit & compliance" bucket per `critical-rules.md`'s tier table, not a capability with a meaningful lower-tier floor the way Sentinel's deterministic scans or DepGate's base proxy have.

**Registry note:** `services/manager/src/flags.rs`'s `MODULE_FLAGS` const currently lists only `["skauswatch.vault", "skauswatch.codescan"]` — `skauswatch.depgate` is enforced in code (`services/depgate/src/routes/mod.rs`) but **is not** in that registry, a pre-existing gap `docs/v2-port/feature-flags.md` doesn't yet call out for depgate specifically. `skauswatch.cspm` should join `MODULE_FLAGS` as a third licensed sub-product at implementation time — don't repeat depgate's registration miss.

## 6. Phasing P1→P4

| Phase | Ships | Value |
|---|---|---|
| **P1** | AWS read-only, ~12 highest-value checks (§4 table) → `cspm_cloud_accounts`/`cspm_scan_runs`/`cspm_findings` (new tables) + `worker-cspm`'s own findings REST surface, report-only | CIS-baseline visibility into a customer's AWS account, no remediation |
| **P2** | AWS Security Hub / AWS Config **import** (ingest findings the customer's account already has, rather than re-describing every resource daily — also the direct answer to §7's API-cost risk) + remediation guidance text per finding | Cheaper steady-state posture data + actionable fixes; gated `.remediation` |
| **P3** | Azure + GCP provider support — new SDK crates, and a **new, unproven** auth model (Workload Identity Federation for both, real research needed per §3) | Multi-cloud coverage for the two next-largest providers; gated `.azure`/`.gcp` |
| **P4** | DigitalOcean support (stored API token, no federation available) + drift detection (event-driven, likely CloudTrail/EventBridge-sourced rather than polling) + custom rules (resolves §8 Decision 2 for real) | Full provider coverage + near-real-time posture + customer-extensible rules; gated `.digitalocean`/`.drift-detection`/`.custom-rules` |

Each phase independently shippable, same discipline as Sentinel/DepGate/EDR's own phasing tables. P1 needs no AI, no cross-account write access, and no rules engine — closest analog is Sentinel's own P1 ("report-only Dependabot replacement, no AI").

## 7. Security / non-goals / risks

- **Clean-room enforcement is structural, not a promise.** `deny.toml`'s permissive-only allow list (§ above) means any accidentally-introduced GPL/AGPL third-party dependency — a copied ScoutSuite helper, a GPL'd cloud-config-parsing crate — fails `cargo deny check` in CI before merge. The workspace's own `AGPL-3.0-only` license only ever applies to internal path-crates (`private = { ignore = true }`), never to a pulled-in dependency.
- **No customer secret storage for the AWS path.** `cspm_cloud_accounts.role_arn`/`external_id` are routing metadata, not credentials — the actual short-lived STS credentials are never persisted (same non-persistence guarantee as s3scan's `assume_role_credentials`). Vault (`services/vault`, this platform's own JIT/secrets service) and IceBox (the cross-product secrets-escrow system referenced elsewhere in this codebase, e.g. WaddleAI's own-secrets custody) are **not needed for AWS** — the SPIFFE federation path is keyless end-to-end. They become load-bearing at P3/P4: Azure/GCP *should* also go keyless via their own workload-identity federation (unproven here, §3/§6), but DigitalOcean has no federation option — a DO API token is a genuine secret that must live in Vault/IceBox custody, referenced from `cspm_cloud_accounts` by an opaque secret-ref ID, never inline.
- **Cloud-API rate and cost for daily full-account scans.** IAM/EC2/Config/CloudTrail Describe/List APIs carry low default AWS rate limits and, at scale (thousands of resources, CloudTrail LookupEvents), real per-request cost. Needs exponential backoff + per-account/per-region pacing in P1; P2's Security Hub/Config-import phase exists specifically to reduce this by consuming pre-aggregated provider data instead of re-describing every resource on every run.
- **SPIFFE-readiness.** `worker-cspm` needs an entry added to `docs/v2-port/service-auth-model.md`'s service roster (`spiffe://penguintech.io/<env>/worker-cspm`), classified the same way as s3scan's row there — "JWT-SVID→STS client only, no gRPC server/client role."
- **Elevated read-scope risk vs. s3scan.** A compromised `skauswatch_base` role or `worker-cspm` process inherits account-wide IAM/EC2/CloudTrail *read* — itself valuable attacker recon even without any write permission. This is why §3 recommends a role **separate** from s3scan's bucket-scoped one, not a shared one.
- **Non-goals (explicit):** not a runtime/workload scanner (EDR's job); not a network/DAST perimeter scanner (`services/scanner`'s job); no auto-remediation in P1/P2 — human-in-the-loop guidance only, mirroring EDR's own caution about high-blast-radius automated actions; not a SIEM — CSPM is a periodic snapshot audit, not a continuous telemetry stream, so it is a SIEM *source* (findings can forward into the OCSF lake the same way EDR's spec designed for host events) rather than a SIEM itself.
- **Not in scope for this spec:** the cross-module exec-report aggregator (§1, §8); the Azure/GCP/DigitalOcean auth research (§3); the rule-DSL implementation itself (§8).

## 8. Open decisions (need explicit user confirmation)

1. **The cross-module exec-report aggregator — build server-side vs. client-side merge.** Grep-confirmed absent (§1). Server-side (a new aggregation route/service unioning `codescan_findings` + `cspm_findings` + eventual EDR detections by tenant) centralizes authz/tenant-scoping once and gives PDF/CSV export (already promised in Sentinel's own report spec) a real server-side rendering point. Client-side merge (webui fetches each module's findings separately, combines at render time) is simpler to ship per-module but pushes tenant-scoping correctness onto every frontend consumer and blocks server-rendered export formats. **Recommend server-side** — this is now the third module spec (Sentinel's own reports, EDR §8/§9, this one) independently needing it; building it once centrally is cheaper than three modules improvising their own partial version.
2. **Rule-DSL format.** P1 ships hardcoded Rust match arms (§4) — fast, no injection surface, but a code change + deploy per new check. A declarative config format (YAML/JSON interpreted at runtime) is what `.custom-rules` (P4) actually needs, but requires real design work of its own — a safe condition-expression mini-language, no `eval`, bounded evaluation cost. **Recommend deferring the DSL design until P4 is actually scheduled** — building a rules engine for 12 checks nobody can customize yet is exactly the kind of premature engine Sentinel/DepGate's own P1→P3 phasing discipline avoided.
3. **Customer role policy: AWS-managed `SecurityAudit` vs. a hand-rolled narrower policy.** `SecurityAudit` is AWS-authored, broad, and exactly the right shape, but broader than the ~12 P1 checks strictly need (e.g. it covers services CSPM won't touch until P2+). A hand-rolled minimal policy is tighter but is now skauswatch's own security-relevant artifact to maintain and gets a permissions-scope check wrong more easily than reusing AWS's own policy. **Recommend `SecurityAudit` for P1** (lower initial risk of accidental `AccessDenied` false-`unavailable` findings, §4), revisit narrowing once the P1 check list is stable.
