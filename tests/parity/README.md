# Golden parity harness — manager v1 (Quart) vs v2 (Rust)

Runs the v1 Python manager (`services/manager`) and the v2 Rust manager
(`services/manager-rs`) side by side against identical seeded state,
replays a corpus covering **every REST endpoint of all 11 routers**, and
structurally diffs status + JSON body. The contract of record is
`docs/v2-port/manager-contract.md`; diffs that match a documented defect
DECISION are expected and live in `expected_diffs.json`.

## How to run

```bash
tests/parity/run.sh          # up + replay + teardown (default)
tests/parity/run.sh up       # boot infra + both managers, leave running
tests/parity/run.sh replay   # replay corpus against running managers
tests/parity/run.sh down     # remove every harness container + network
```

Requirements: docker, python3 + `requests` on the host. Reports land in
`tests/parity/reports/` (`report.md` human, `report.json` full). Exit code
is non-zero when any **finding** (non-allowlisted diff) remains.

`replay` is only valid once per fresh `up` — the corpus mutates state, and
both sides must start from the seeded snapshot to stay in lockstep.

## Topology

| container    | role |
|--------------|------|
| `parity-pg`  | postgres:17-bookworm, two identically seeded databases (`skauswatch_v1`, `skauswatch_v2`) |
| `parity-redis` | valkey/valkey:8-bookworm; v1 uses DB index 0, v2 uses DB index 1 |
| `parity-stub`  | one shared deterministic echo upstream (`stub_upstream.py`) standing in for worker-scanner (ASM), worker-darwin, log-receiver (SIEM), and the S3 endpoint for bucket tests. Both managers proxy to the same stub so forwarded method/path/query/body parity is directly observable |
| `parity-v1`  | python:3.13-slim-bookworm, pip-installs `services/manager/requirements.txt` (hash-verified), runs `main.py` on :5000 → host :15001. `GRPC_ENABLED=false` |
| `parity-v2`  | debug binary built via rust:1.97-slim-bookworm (cargo cache in the session scratchpad), runs on :5000 → host :15002. `GRPC_ENABLED=false` |

Both managers get the same `JWT_SECRET_KEY` and `EDR_API_SECRET`, so JWTs
and EDR HMAC keys are cross-valid; each gets its **own identical database**
and its own Redis DB index. OpenSearch is intentionally absent (both sides
must fail identically on SIEM search/stats).

## Licensing posture (important)

`RELEASE_MODE` is unset for v2 → penguin-licensing dev mode → every
feature/flag gate evaluates **enabled** (darwin gate open). v1's
penguin-licensing 0.1.0 has **no `has_feature` method** — every v1 license
check takes its exception path: darwin fails **open** (allowed, matching
v2), the users free-tier cap fails **closed** (`has_premium = False`).
Consequently:

- The darwin router is comparable (both sides open).
- The free-tier user-cap path (5+ users) is **not comparable** under this
  posture (v1 would cap, v2's dev bypass would not); the corpus therefore
  keeps the user count under 5 whenever `POST /api/v1/users` runs. The cap
  itself is covered by v2 unit tests, not by this harness.

## Seed data

`seed.sql` creates the contract's 13-table schema (derived from
`services/manager/models/db.py`, the authoritative source) and seeds 3–4
deterministic rows per feature: users for each role (admin/maintainer/
viewer + one deactivated; password `Password123!` for all), IOCs (incl. one
expired), alerts, approvals (incl. approved + expired), EDR agents/events,
S3 buckets/jobs/results/adhoc results/schedule. All IDs are explicit with
sequences reset (`setval`) so rows created during replay get identical IDs
on both sides. All seeded timestamps are fixed literals so deterministic
fields byte-compare.

v1's startup `create_all()` is idempotent by table name and leaves the
pre-created schema untouched.

## Diff & normalization rules

1. Compare HTTP status, then the JSON body **structurally** (object key
   order ignored — not semantic in JSON; v1 sets `JSON_SORT_KEYS=False`).
2. Every leaf is **byte-compared**, with one exception: when a leaf differs
   between sides AND both sides match the **same** nondeterminism class,
   the difference is accepted:
   - `TS` — strict Python `datetime.isoformat()`:
     `YYYY-MM-DDTHH:MM:SS` or `...SS.ffffff` (exactly 6 fraction digits).
   - `JWT` — three base64url segments starting `eyJ`.
   - `UUID` — RFC-4122 lowercase hex form.
   - `BCRYPT` — `$2a/b/y$NN$...` (53-char payload).
   A value matching a class on one side only **stays a diff** — that is the
   "assert the format" rule (e.g. a v2 timestamp with `+00:00`, a space
   separator, or 3 fraction digits is a finding, not noise).
3. Non-JSON bodies are compared as raw text (wrapped as `{"$raw": ...}`).
4. Corpus order is part of the fixture: mutations run identically on both
   sides so DB state (including sequences) stays in lockstep. Known
   asymmetric mutations are deliberately bounded and documented in
   `expected_diffs.json` (defect #7 status write targets a no-op value;
   the v2-only adhoc delete and bucket-4 lifecycle touch rows no later
   case reads on the v1 side).
5. `sleep_before` on a few cases works around two v1 realities: (a) two
   refresh tokens minted for one user within the same second are an
   identical JWT (second-granularity iat/exp) → `token_hash` UNIQUE
   violation (contract defect #9); (b) PyDAL writes second-precision
   timestamps, so v1 `ORDER BY last_heartbeat/created_at DESC` ties are
   nondeterministic — the sleeps keep mutation timestamps ≥1s apart.
6. v1 auto-recovery: v1 serves every request over ONE shared PyDAL
   connection and never rolls back on error (contract defect #9) — the
   first SQL error leaves the transaction aborted and all later DB
   requests 500 until restart. After any v1 500 the runner restarts the
   `parity-v1` container (fast: dependencies live in a persistent
   PYTHONUSERBASE volume) so each case observes v1's real per-endpoint
   behavior instead of the poison cascade.

## Expected-diff allowlist (`expected_diffs.json`)

Each entry names the corpus case (exact `case` or `case_glob`), optionally
pins the exact `[v1, v2]` status pair (`expect_status`), optionally
restricts which diff `paths` it excuses, and always carries a `ref` into
`docs/v2-port/manager-contract.md` plus a `reason`. A case counts as
ALLOWLISTED only if **every** diff (including a status mismatch, modeled as
path `$status`) is excused; anything left over is a FINDING and fails the
run. Rationale per family:

- **defect #1** (s3-scan schema drift): v1's jobs/results/statistics/
  schedule-get/upload/create-indicator/ti-enrichment routes were
  runtime-broken (500) against the real schema; v2 ports against the
  schema. All `*-defect1` cases.
- **defect #2** (research): v1 reads nonexistent `config.research.*` — 500
  on every research route; v2 implements ResearchConfig. `*decision2*` +
  shodan/maltego-disabled cases.
- **defect #3** (IOC type `file_hash`): v1 hash-lookup/create-indicator
  target the impossible `file_hash` type; v2 uses `hash`. The seeded hash
  IOC makes the divergence visible (v1 `found:false`, v2 `found:true`).
- **defect #7** (alerts status role gate): viewer 200→403.
- **defect #8** (filtered lists — found by this harness): v1 renders
  `WHERE <table> AND (...)` for every filtered list/search → 500; v2
  implements the documented filters. All `defect8-*` entries.
- **defect #10** (custom-validator 500s): v1's ValueError-raising
  validators crash `jsonify(e.errors())` → 500 instead of 400.
- **defect #11** (bucket create omits NOT NULL `created_by`): v1 500 on
  create; follow-on update/get/delete of the new bucket 404 on v1.
- **defect #12** (bucket test imports boto3, not installed): v1 500.
- **validation-details decision** (contract "Error body shapes"): v1 emits
  raw pydantic-v2 `e.errors()` dicts (incl. `input`/`url`/`ctx` keys that
  leak pydantic internals); v2 emits the same envelope
  `{error: "Validation error", details: [...]}` with simplified
  `{loc,msg,type}` entries. The allowlist excuses only the `details`
  payload (and EDR batch `errors[].error` strings) — the 400/202 status
  and envelope keys must still match.

## Coverage notes / honest gaps

- corpus: 282 cases across the 11 routers + root health endpoints
  (happy path, auth failure, validation failure, role gates, filters,
  pagination, EDR HMAC positive/negative, proxy forwarding).
- gRPC surface is out of scope here (covered by `grpc` module tests).
- The free-tier user cap and SSO-402 paths are not comparable under the
  dev licensing posture (see above).
- v1 boots with `GRPC_ENABLED=false`; its gRPC blueprint import path is
  otherwise untouched by the REST corpus.
