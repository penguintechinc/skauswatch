# AWS identity runbook — SPIFFE-federated + cross-account roles

Retires static AWS keys as the primary credential path for `s3scan`,
`worker-vault-sync`, and `manager` (`crates/skauswatch-s3/src/credentials.rs`,
`services/worker-vault-sync/src/providers/aws.rs`,
`services/manager/src/state.rs`). Neither mechanism below ever uses a
static AWS access key — the deployment picks which keyless mechanism
fits its cluster; see §0. This is documentation + Terraform snippets
only for the SPIRE/OIDC path — nothing there has been applied, and no
Rust code in this repo changes. The Helm-side toggle (§0) is applied —
`awsIdentity.mode` exists today in all three services' charts.

See `docs/v2-port/tenancy-model.md` for the tenant model this sits above,
and `crates/skauswatch-identity/src/lib.rs` (`IdentityProvider::fetch_jwt_svid`)
for the JWT-SVID primitive the SPIRE path federates into AWS.

## Validated (this session) — both STS exchanges proven against real AWS

Both keyless exchanges this runbook describes have been run end-to-end
against a real AWS account, not just documented/wiremocked:

- **`sts:AssumeRole`** (§2's customer cross-account hop) — an IAM role
  trusting the test caller's own ambient identity, gated by `ExternalId`,
  successfully assumed.
- **`sts:AssumeRoleWithWebIdentity`** (§1's SPIFFE-federation hop) — a
  hand-minted RS256 JWT (`sub=spiffe://penguintech.io/test/awslive`,
  `aud=sts.amazonaws.com`, the exact shape `fetch_jwt_svid` produces)
  successfully exchanged for AWS credentials via a **throwaway,
  self-hosted OIDC issuer** (a public S3 bucket serving
  `.well-known/openid-configuration` + `jwks.json`), registered as a real
  `aws_iam_openid_connect_provider` and trusted by a real IAM role with
  the exact `aud`/`sub` `StringEquals` trust-policy shape §1 Step B
  documents.

Test coverage: `services/scanner/tests/aws_live.rs` (gated on
`SKAUSWATCH_AWS_LIVE=1`, proves the S3 client + production YARA-X engine
against a real bucket) and `tests/smoke/aws_identity/run.sh` (gated,
requires AWS credentials in the environment — owns all AWS setup/teardown,
self-sweeping via a `${PREFIX}-*` naming convention, drives
`crates/skauswatch-s3/tests/aws_live_identity.rs` against the two roles it
provisions). Neither test is part of the default `cargo test`/CI run —
both no-op without explicit opt-in env vars and real AWS credentials; run
manually per the doc comment in `aws_live.rs`.

**What this does and does not prove:** the AWS-side trust-policy shape and
the Rust-side credential-exchange code path are now proven correct
end-to-end. It does **not** mean §5's live-ops checklist is done — the
smoke test's OIDC issuer, IAM roles, and bucket are throwaway
(`skauswatch-awslive-*`, torn down on exit every run), not the permanent
`skauswatch_base`/`skauswatch_scan` roles or a real SPIRE
`oidc-discovery-provider` deployment this runbook's §1/§2 Terraform
describes. §5 remains outstanding; see
`docs/v2-port/phase11-r3-r4-cutover-checklist.md` for the ordered
remaining steps.

**One thing the validation corrected**: §5's checklist bullet about
thumbprint rotation. AWS does **not** actually validate the
`thumbprint_list` value for an OIDC issuer whose TLS certificate chains to
a CA already in AWS's trusted root store (confirmed live — the smoke
test's S3-hosted issuer uses an AWS-issued cert, and `aws iam
create-open-id-connect-provider` accepted an arbitrary computed thumbprint
without rejecting a mismatch). This is documented AWS behavior for
well-known CAs, not a skauswatch-specific finding, but it changes the
checklist: thumbprint-rotation-tracking is only load-bearing if the SPIRE
OIDC endpoint's TLS cert comes from a private/self-signed CA. If it's
issued by a public CA (Let's Encrypt, AWS ACM, etc. — the "real CA"
requirement already recommended below), the thumbprint is a required
field on the API call but not an enforced trust check on AWS's side, so
the "re-derive on every cert rotation" step is a defense-in-depth nicety
rather than a hard requirement. §5's bullet is left as the safer default
(re-derive anyway — it's cheap and doesn't rely on this AWS behavior
staying the same), but this nuance was previously undocumented and is now
called out explicitly.

## 0. SPIRE vs Pod-Identity/IRSA — and/or, not either/or

skauswatch supports **two keyless AWS identity mechanisms side by side**.
Which one a given deployment uses is a Helm values choice
(`awsIdentity.mode: "spire" | "irsa" | "static"`), not a global
architecture decision — pick per-cluster:

| Cluster type | Mechanism | Why |
|---|---|---|
| **EKS** | `awsIdentity.mode: "irsa"` | EKS Pod Identity / IRSA is native: the ServiceAccount gets annotated `eks.amazonaws.com/role-arn: <arn>`, and the AWS SDK's default credential provider chain (`aws-sdk-s3`/`aws-config` in `s3scan`, `worker-vault-sync`, `manager`) discovers the projected service-account token and assumes the role with **zero application code change and no SPIRE dependency**. Skip §§1–3 entirely on EKS. |
| **On-prem / non-EKS** (skauswatch's actual `dal2` clusters today — alpha/beta/gamma, and prod unless/until it moves to EKS) | `awsIdentity.mode: "spire"` | No IRSA control plane exists, so §§1–3's SPIRE-OIDC-federation chain is the substitute: SPIRE issues a JWT-SVID, AWS IAM trusts SPIRE's OIDC discovery endpoint as an external IdP, `sts:AssumeRoleWithWebIdentity` exchanges the SVID for AWS credentials. |
| S3-compatible only (MinIO, Wasabi, B2 — no STS) | `awsIdentity.mode: "static"` | Neither mechanism applies; falls back to the existing envelope-encrypted `static_credentials` path (§3 below). Not a real-AWS option. |

Implementation: `k8s/helm/{s3scan,worker-vault-sync,manager}/templates/serviceaccount.yaml`
renders the `eks.amazonaws.com/role-arn` annotation only when
`awsIdentity.mode == "irsa"` and `awsIdentity.irsa.roleArn` is set;
`spire` mode renders no annotation and relies on the pod's
`SPIFFE_ENDPOINT_SOCKET` (see `k8s/helm/spire/README.md`'s "Service-pod
SVID pattern" — wiring that socket mount into each service's own chart
is a separate, not-yet-done pass, tracked in that README's deferred-items
list). Base `values.yaml` in all three charts defaults to `mode: "spire"`,
matching skauswatch's current on-prem clusters; `production.yml` in each
chart carries a commented example for flipping to `irsa` if a future prod
cluster is EKS.

**SPIRE server chaining note:** `k8s/helm/spire`'s `topology.upstreamRoot`
block is SPIRE's generic `UpstreamAuthority "spire"` plugin — it points a
child server at any reachable SPIRE server address, root or otherwise —
so the mechanism is not depth-limited to root → child: a child server can
itself be configured as the upstream for a deeper grandchild, chaining
root → child → grandchild, all under the single trust domain
`penguintech.io`. Today's shipped values files (`beta.yml`/`gamma.yml`/
`production.yml`) only define the two-level root → child topology shown
in that README's diagram; going deeper is a matter of pointing a further
child's `topology.upstreamRoot.serverAddress` at an existing child rather
than at root, no new chart mechanism required. See
`k8s/helm/spire/README.md`'s topology section for the join-token
bootstrap procedure per child.

## 1. Own-AWS federation (skauswatch's own S3/MinIO/Secrets Manager)

Prerequisite: SPIRE server runs the [`oidc-discovery-provider`
plugin](https://github.com/spiffe/spire/blob/main/support/oidc-discovery-provider),
publishing `https://spire-oidc.dal2.penguintech.cloud/.well-known/openid-configuration`
+ JWKS for trust domain `penguintech.io` (see `crates/skauswatch-identity`
doc comments for the trust-domain/SPIFFE-ID format already in use:
`spiffe://penguintech.io/<env>/<service>`, e.g.
`spiffe://penguintech.io/beta/s3scan`).

**Step A — register the OIDC provider in AWS IAM** (one-time per AWS
account):

```hcl
resource "aws_iam_openid_connect_provider" "spire" {
  url             = "https://spire-oidc.dal2.penguintech.cloud"
  client_id_list  = ["sts.amazonaws.com"]          # audience skauswatch requests via fetch_jwt_svid
  thumbprint_list = [var.spire_oidc_tls_thumbprint] # SHA1 of the TLS cert chain's root CA
}
```

**Step B — skauswatch's base IAM role**, trusted only for its own
service SPIFFE ID + the fixed audience:

```hcl
data "aws_iam_policy_document" "skauswatch_base_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.spire.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "spire-oidc.dal2.penguintech.cloud:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "spire-oidc.dal2.penguintech.cloud:sub"
      values   = ["spiffe://penguintech.io/beta/s3scan"] # one line per env/service that needs AWS
    }
  }
}

resource "aws_iam_role" "skauswatch_base" {
  name               = "skauswatch-base"
  assume_role_policy = data.aws_iam_policy_document.skauswatch_base_trust.json
}
```

`skauswatch_base`'s own permission policy should be minimal — its only
job is `sts:AssumeRole` into customer roles (§2) plus whatever
skauswatch-owned buckets/Secrets Manager entries it directly needs. It is
**not** granted broad S3 access itself.

## 2. Customer cross-account access (scanning customer S3)

Customer creates a role in **their** account trusting `skauswatch_base`'s
ARN, gated by a per-customer `external_id` (confused-deputy protection —
the same `external_id` column already modeled in
`BucketCredentialConfig::external_id`):

```hcl
# Customer-side Terraform — provided to the customer as a template, not
# applied by skauswatch.
data "aws_iam_policy_document" "skauswatch_scan_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::<SKAUSWATCH_ACCOUNT_ID>:role/skauswatch-base"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.skauswatch_external_id] # unique per customer, generated by skauswatch
    }
  }
}

resource "aws_iam_role" "skauswatch_scan" {
  name               = "skauswatch-scan"
  assume_role_policy = data.aws_iam_policy_document.skauswatch_scan_trust.json
}

resource "aws_iam_role_policy" "skauswatch_scan_perms" {
  role   = aws_iam_role.skauswatch_scan.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        "arn:aws:s3:::${var.customer_bucket}",
        "arn:aws:s3:::${var.customer_bucket}/*",
      ]
    }]
  })
}
```

No write/delete permissions — scanning is read-only (`GetObject` +
`ListBucket`), scoped to exactly the one bucket the customer registers.

## 3. Full chain

```
pod SPIFFE X.509-SVID (SPIRE agent)
  → fetch_jwt_svid("sts.amazonaws.com")                 [skauswatch-identity]
  → sts:AssumeRoleWithWebIdentity → skauswatch_base       [§1 trust policy, sub+aud conditions]
  → sts:AssumeRole(role_arn, external_id) → customer role [§2, credentials.rs::assume_role_credentials]
  → s3:GetObject / s3:ListBucket on the customer bucket
```

Zero static secrets anywhere in this chain for real-AWS buckets. This
replaces the "ambient AWS identity" placeholder already called out in
`credentials.rs`'s module doc comment ("a later round swaps the base
identity to a JWT-SVID") — `assume_role_credentials`'s
`base_credentials_override` seam is exactly where the JWT-SVID-derived
`Credentials` provider plugs in; no signature change needed, only the
production (non-test) caller wiring in `resolve_client`.

**S3-compatible fallback (MinIO, Wasabi, Backblaze B2, ...):** these
endpoints have no STS, so `is_aws_endpoint()` already rejects
`assume_role` against them (`CredentialError::AssumeRoleRequiresAwsEndpoint`).
They keep using `credential_mode = "static"` — envelope-encrypted
access-key/secret pairs at rest, per the existing `static_credentials`
path. This runbook does not change that fallback.

## 4. Customer onboarding flow

| Step | Who | Action |
|---|---|---|
| 1 | skauswatch | Generate a unique `external_id` (UUID) for the customer; surface it + `skauswatch_base`'s ARN in the bucket-config UI/API. |
| 2 | Customer | Apply the §2 Terraform (or console equivalent): create `skauswatch-scan` role, trust `skauswatch_base`'s ARN + their `external_id`, attach the read-only bucket policy. |
| 3 | Customer | Paste the resulting role ARN into skauswatch's bucket-config form (`role_arn` field on `s3_bucket_configs`). |
| 4 | skauswatch | Store `role_arn` + `external_id` only (`credential_mode = "assume_role"`); `credential_enc` stays `NULL`. No customer secret is ever transmitted or stored. |
| 5 | skauswatch | First scan job calls `resolve_client` → chain in §3; failure surfaces as `CredentialError::AssumeRole` (permanent=false, retryable) if the trust policy isn't live yet. |

## 5. Live-ops checklist (needs AWS-account access / Terraform apply — not in this repo)

- [ ] Deploy/confirm SPIRE `oidc-discovery-provider` plugin is running and reachable at the chosen public HTTPS hostname (TLS cert from a real CA — AWS OIDC federation does not accept self-signed without the exact thumbprint kept in sync).
- [ ] Compute and record the OIDC TLS thumbprint (`var.spire_oidc_tls_thumbprint`) for the `aws_iam_openid_connect_provider` resource; re-derive on every cert rotation.
- [ ] `terraform apply` §1 (OIDC provider + `skauswatch_base` role) in skauswatch's own AWS account — requires IAM admin access.
- [ ] Add one `sub` condition value per environment/service SPIFFE ID that needs AWS access (beta/gamma/prod each get their own line — never share a role trust across environments).
- [ ] Hand the §2 Terraform template (or equivalent console steps) to each customer; this is applied in **their** AWS account, not skauswatch's.
- [ ] Confirm `fetch_jwt_svid` audience string (`"sts.amazonaws.com"`) matches the `client_id_list` configured on the OIDC provider — a mismatch fails `AssumeRoleWithWebIdentity` with `InvalidIdentityToken`.
- [ ] Wire the production (non-override) branch of `resolve_client_inner` in `credentials.rs` to call `fetch_jwt_svid` + `sts:AssumeRoleWithWebIdentity` for the base identity, replacing today's default-credential-provider-chain fallback — **code change, tracked separately, not part of this doc.**
- [ ] Decommission any long-lived static AWS keys held for skauswatch's own account once §1 is live and verified.
