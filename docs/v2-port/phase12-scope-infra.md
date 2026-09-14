# Phase 12 Scope — Infra/Storage Subsystem Parity

Read-only scoping pass over three infra/storage gaps carried from the v2 port:
`worker-vault-sync` multi-cloud providers, `sshca` cert storage/revocation, and
`logs` mirror sinks. Cross-references `docs/v2-port/sshca-contract.md`,
`docs/v2-port/logs-contract.md`, and `docs/v2-port/v2.1-backlog.md` (all three
already tracked pieces of this before this pass; this doc reconciles and
extends them into a single restore plan with effort/dependency estimates).

## Summary table

| Subsystem | v1 working? | v2 state today | Restore plan | Effort | Deps |
|---|---|---|---|---|---|
| vault-sync: Azure | Yes, full | `NotImplementedProvider` stub | Port via `azure_security_keyvault` crate; SP or MSI credential | M | new crate + SP/MSI plumbing |
| vault-sync: GCP | Yes, full | `NotImplementedProvider` stub | Port via `google-cloud-secretmanager-v1`; SA JSON or ADC/Workload Identity | M | new crate + SA/ADC plumbing |
| vault-sync: OCI | Yes, full | `NotImplementedProvider` stub | No mature Rust SDK — `reqwest` + manual OCI request signing (RSA-SHA256) | L | bespoke signing code, highest-risk item |
| vault-sync: Kubernetes | Yes, full | `NotImplementedProvider` stub | Port via `kube` crate; in-cluster SA or kubeconfig | S/M | `kube` crate (mature) |
| vault-sync: payload plumbing | No (pre-existing v1 defect) | Preserved as-is | Fix `_publish_sync_event`/trigger route to send real `secret_id`/`encrypted_value` payload | S/M | touches `services/vault` trigger route, not just the worker |
| sshca: durable storage | **Never existed in v1** | In-memory (`store.rs`), matches v1's behavior class | Not a restoration — net-new. Two options below | M (consolidate) / M-L (standalone) | see sshca section |
| sshca: revocation/KRL | Real logic, non-durable in both v1 and v2 | Same as v1 (not a regression) | Same schema work as storage — revocation persistence rides along | (bundled above) | (bundled above) |
| logs: S3/Parquet mirror | Yes, written on every ingest — but **zero verified readers ever** | Env vars not even parsed (see correction below) | Recommend **skip** — write-only sink nothing reads | L if restored | `arrow`/`parquet` crates, absent from workspace |
| logs: Redis-stream consumer | **No — dead on arrival in v1**, zero producers ever existed | Env var not parsed | Recommend **skip entirely**, not defer | N/A | — |
| logs: syslog UDP listener | Yes, as a listener; no in-repo evidence of a real sender | Env var not parsed | Restore only if an external syslog source is a live requirement | S if restored | none beyond tokio (reuses existing OCSF path) |

---

## 1. worker-vault-sync — multi-cloud secret providers

**v1 source**: `icebox/services/sync-worker/providers/{aws,azure,gcp,oracle,kubernetes}.py`,
found at `git show ef82cb1:...` (parent of `de47166`, the commit that ported to
Rust and deliberately deleted the Python — already cross-referenced in
`docs/v2-port/v2.1-backlog.md`). **All five v1 providers were fully working,
symmetric implementations** — not aspirational code.

| Provider | v1 SDK / auth model | v2 file | Notes |
|---|---|---|---|
| AWS | `boto3` Secrets Manager | `aws-sdk-secretsmanager` — **already ported, real** | Reference implementation for the other four |
| Azure | `azure-keyvault-secrets` + `azure-identity`; `ClientSecretCredential` (service principal) or `DefaultAzureCredential` (managed identity) fallback | `services/worker-vault-sync/src/providers/not_implemented.rs` | Port target: `azure_security_keyvault` crate, same tag-filter list pattern |
| GCP | `google-cloud-secret-manager`; SA JSON key or ADC/Workload Identity | same stub | Port target: `google-cloud-secretmanager-v1`; preserve create_secret + add_version two-step |
| OCI | `oci` SDK; API-key signing (user/tenancy/fingerprint OCID + PEM key) | same stub | **No mature OCI Rust SDK exists.** Needs hand-rolled `reqwest` + RSA-SHA256 request signing — the one provider that isn't a crate swap |
| Kubernetes | `kubernetes` client lib; in-cluster ServiceAccount or kubeconfig, optional bearer/API-URL override | same stub | Port target: `kube` crate (mature, well-supported), same label-selector list + patch-or-create pattern |

**Cross-cutting defect, preserved in both v1 and v2 (already tracked in
`v2.1-backlog.md`)**: no caller — v1 or v2 — ever publishes a real secret
payload. `POST /sync/integrations/{id}/trigger` sends only
`{integration_id, event_type, timestamp}`, but `_do_push`/`_do_delete` (and
their Rust equivalents in `services/worker-vault-sync/src/handler.rs`) expect
`secret_id`/`secret_name`/`encrypted_value`/`encrypted_dek`/`dek_version`/
`external_ref`. Every trigger has always silently no-op'd on decrypt failure.
**This means restoring all four providers alone does not restore working
cloud sync** — the trigger route in `services/vault` needs a real payload
too. Recommend scoping this as a required companion item, not an optional
follow-up, since "full v1 parity" for vault-sync means secrets actually
syncing, and today none do (including AWS).

`pull_secret`/`list_secrets` (cloud→vault direction) were never wired to a
poll loop in either version — confirmed dead code path in v2's `mod.rs` doc
comment, not a v2 regression.

**Risk**: OCI is the one provider that is really **L**, not M — it needs
bespoke signature/canonicalization code with no existing crate to lean on,
the highest chance of subtle security-relevant bugs among the four.

---

## 2. sshca — cert storage and revocation

**Correcting the task's framing**: git archaeology found **no evidence v1
ever had durable SSH-cert storage**, contradicting the assumption that this
is a restoration.

- v1 shim (`services/ssh-ca/async_ssh_processor.py`, pre-`c904441`): pure
  aiohttp proxy, no storage of its own.
- v1 real engine (`icebox/services/ssh-ca/async_ssh_processor.py`,
  `AsyncSSHProcessor`, deleted in `f818041`): `self.certificates: Dict` and
  `self.revoked_certificates: Dict` — pure in-process dicts.
  `_load_existing_data()` contains the literal comment
  `# In production, this would load from database` — never implemented.
  KRL generation (`_generate_krl_sync`) is real and reflects in-memory
  revocations, but nothing survives a restart.
- `icebox/services/pki-server/ca/ssh_authority.py` (v1 sibling, also deleted
  in `f818041`): no DB/SQLAlchemy references either.

**Verdict: confirmed absent.** Treat durable storage as net-new work, not a
port. (This matches `sshca-contract.md`'s existing claim and
`v2.1-backlog.md`'s "v1 kept issued certs in memory (no table)" note — this
pass independently reconfirms both via fresh git archaeology, closing the
discrepancy with the task's initial framing.)

**Key finding — a durable schema already exists in a sibling v2 service.**
`services/pki` (current Rust, on disk) has a complete tenant-scoped Postgres
schema (`migrations/0001_pki_schema.sql`, `0002_tenancy.sql`):
`ssh_certificates`, `x509_certificates`, `crl_entries` (revocation ledger,
shared across both CA types), `pki_audit_log` — all `tenant_id`-scoped.
`services/pki/src/routes/ssh.rs` + `ca/ssh.rs` (959 lines) is a fully
functional, DB-backed, tenant-isolated SSH CA with real tests
(`revoke_succeeds_on_a_real_row_and_reflects_in_status`,
`tenant_b_cannot_get_list_or_revoke_tenant_as_certificate`). It even reads
`SSHCA_KEY_PATH`/`SSHCA_PUBLIC_KEY_PATH` — the same env var names
`services/sshca` uses. Per its own schema header this is a fresh v2 design
("v2 platform never shipped to prod... not a port of a legacy v1 table
layout"), not itself a v1 port.

**This surfaces an unresolved architecture split, not a simple parity gap**:
two v2 services (`sshca` and `pki`) both implement SSH CA signing against the
same key-path convention, one durable and one not. Flag to the user before
picking a restore path:

1. **Consolidate** — retire `services/sshca`'s standalone signing, route SSH
   cert issuance through `services/pki` (schema, tenancy, tests already
   built). Effort **M** — mostly manager routing changes + deprecating the
   sshca surface; the DB work is done.
2. **Give sshca its own durable storage** — copy pki's
   `ssh_certificates`/`crl_entries` migration pattern into
   `services/sshca/migrations/`, add `tenant_id`, wire `store.rs` to
   Postgres. Effort **M/L** — schema copy is cheap, but perpetuates two
   services owning the same CA-key path.

**Severity of the current in-memory-only state**: moderate-high for a CA
specifically — issuance records and revocation state both vanish on pod
restart, so a revoked cert reads as valid again after any redeploy or crash
(KRL resets empty), and there is no audit trail of what was ever issued. Not
rated "high" in isolation only because `services/pki` already offers a
durable, tenant-safe alternative path for the same operations — the acute
risk is architectural ambiguity (which service is authoritative for SSH
certs), not a missing capability org-wide.

RSA CA-key support and the ssh-keygen CI interop test remain separately
tracked in `v2.1-backlog.md` (unaffected by this finding).

---

## 3. logs — mirror sinks (S3/Parquet, Redis-stream, syslog)

**Correction to `logs-contract.md`**: current-tree grep shows the S3/Redis/
syslog env vars aren't "accepted but ignored" — `Config::from_env()`
(`services/logs/src/config.rs:38-42`) only reads `OPENSEARCH_URL`,
`LOG_RETENTION_DAYS`, `HTTP_PORT`. The other vars appear solely in doc
comments (`main.rs`, `config.rs`, `ingest.rs`), never parsed at all.

v1 source (`services/log-receiver`, introduced `70378f4`, deleted at
`e262f6c^`):

| Sink | v1 file | Format | Real traffic in v1? |
|---|---|---|---|
| S3/Parquet | `writers/parquet_writer.py` | pyarrow, Hive-partitioned (`ocsf_class=/year=/month=/day=/hour=`), Snappy; schema `class_uid(i32), class_name, time(us,UTC), severity_id(i8), status_id(i8), message, raw_data(JSON str)` | Written unconditionally on every ingest, but **no evidence anything ever read it back** — manager never queries S3; even v1's own test mocks the S3 client |
| Redis-stream | `ingest/redis_consumer.py` | consumer-group `log-receiver`, batch 500, `XREADGROUP`/`XACK` on `skauswatch:logs:ingest` | **Dead on arrival** — pickaxe search of the full v1 tree at deletion time found zero producers ever, in v1 or v2 |
| Syslog UDP | `ingest/syslog_handler.py` | RFC5424-ish regex (`<pri>ver ts host app procid msgid sd msg`, falls back to raw-message dict) | Listener was live and fed the same OCSF pipeline; no in-repo evidence of any component ever sending syslog to it (would be an external-only use case, unverifiable from this repo) |

**Recommendations**:
- **S3/Parquet**: skip. Real writes happened in v1, but restoring needs
  `arrow`/`parquet` crates absent from the workspace for a sink with zero
  confirmed readers. Effort if pursued anyway: **L**.
- **Redis-stream**: skip entirely, not defer. This was never live — nothing
  to restore parity *with*.
- **Syslog UDP**: only worth restoring if an external syslog source is a
  current, real requirement — the repo has no internal evidence either way;
  ask before committing effort. If yes: effort **S**, reuses the existing
  OCSF normalize path already in v2, no new dependency beyond tokio's UDP
  socket + a regex.

---

## Biggest risks

- **sshca**: in-memory storage means a revoked SSH cert becomes valid again
  after any pod restart/redeploy — a real security gap for a CA, not a
  cosmetic parity miss. Compounded by an unresolved two-service split
  (`sshca` vs `pki`) that should be decided before either gets a schema.
- **vault-sync**: porting all four remaining cloud providers is necessary
  but **not sufficient** — the trigger-route payload defect means secrets
  don't actually sync end-to-end for *any* provider today, including AWS.
  "Full v1 parity" here requires fixing that plumbing too.
- **OCI provider**: the only vault-sync gap requiring bespoke crypto/signing
  code instead of an existing crate — treat as L effort and highest
  code-review scrutiny, not a routine SDK port.
