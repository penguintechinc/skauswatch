# Phase 12 Scope — CodeScan License/Credentials + AI/SIEM/Approvals Parity

Read-only scoping pass. v1 source was deleted from the working tree during the
v2 migration; all v1 findings below come from `git show <ref>:<path>` /
`git log --oneline --all -- <path>` against `origin/release/v1.0.x` and
pre-deletion commits on the current history line (primarily
`9466b34^` — the darwin module tip just before removal — and manager-side
commits `aad5b4c`, `5ca2052`, `cc9d6bd`). No branch was checked out; no files
outside this doc were modified.

**Framing that shapes every row below:** "v1 parity" is not one thing here.
Some items are a straight port (working v1 code, just disconnected in v2).
Others are v1 code that was *itself* never wired end-to-end — restoring
"parity" for those means designing the missing glue fresh, because there is
no working v1 behavior to copy. A few have no v1 precedent at all and would
be net-new features dressed up as a port. Each row says which case it is.

## Summary

| # | Subsystem | v1 working? | v2 state | Restore plan | Effort | Deps |
|---|---|---|---|---|---|---|
| 1 | `codescan_provider_usage` (AI cost/token tracking) | **Yes** — wired into real review flow | Table exists, no writer/reader | Port write-path (insert after each AI call in worker-codescan) + a read endpoint | S | none |
| 2 | `codescan_review_detections` (language/framework per review) | **Partial** — writer (`create_detection`) defined but never called; reader wired to a GET endpoint that therefore always returned empty | Table exists, fully unwired | Net-new detection logic required (v1 never had a real writer either) | M | none |
| 3 | `codescan_license_policies/_detections/_violations` | **Partial** — scanner (`CycloneDXScanner`) and policy CRUD both work standalone; never linked to each other or the review pipeline | Tables exist, fully unwired | Port scanner + CRUD (straightforward); design new glue: run scanner post-clone, evaluate vs. policy, insert detections/violations | M | git creds (row 4) first, for correct private-repo dependency resolution |
| 4 | worker-codescan per-repo git credentials | **Yes** — Fernet-encrypted, glob-matched credential genuinely injected into clone step | Schema/CRUD/crypto exist (v2 design is arguably better: tenant-scoped FK vs. v1 glob match); worker reads single `GIT_TOKEN` env var only | Wire `handler.rs`/`git_provider.rs` to query `codescan_git_credentials` instead of env var — no design work, v2 schema already correct | S | none — do this first, rows 3 and (indirectly) real diff-fetching depend on it |
| 5 | `request_ai_review` / `get_ai_review_result` gRPC + `ai:tasks` consumer (alert AI-triage) | **No** — pure scaffolding: REST publish existed (202 + queue), a full `AlertReviewer`/`AIProviderFactory` engine existed, but it had **zero callers**; the `manager-ai` consumer group was created and never consumed; webui never surfaced a result | 2 dead gRPC RPCs; `ai:tasks` constant defined; no consumer anywhere | Net-new: real `ai:tasks` consumer, gRPC RPCs as publish/query, results storage, webui surface. v1's `alert_reviewer.py`/`provider.py` are a strong design reference (map onto WaddleAI as the v2 provider) | M | sequence after row 6's gRPC wiring (same service struct); no hard blocker |
| 6 | `create_approval_request`/`process_approval`/`get_approval_status` gRPC | **Yes (REST)** — full working ticket workflow (CRUD + multi-approval decision state machine), already ported wire-for-wire to v2 REST (`services/manager/src/routes/approvals.rs`). gRPC itself was never implemented in v1 either — pure proto declaration in both versions | REST fully working in v2; gRPC = dead duplicate surface | Thin gRPC→REST-logic proxy for the 3 RPCs — trivial, business logic already ported and tested | S | none |
| 7 | `query_io_cs` gRPC | **Yes (REST)** — v1's IOC lookup/search is real and already ported (`services/manager/src/routes/threat_intel.rs`) | REST working; gRPC = dead duplicate | Thin gRPC→REST-logic proxy | S | none |
| 8 | `enrich_indicator` gRPC (live OTX/VirusTotal enrichment) | **No** — v1's "feeds" endpoint only reported whether `OTX_API_KEY`/`VIRUSTOTAL_API_KEY` env vars were *set*; no live external HTTP call ever existed anywhere in v1 | Dead RPC, no precedent | Net-new external API integration; no port target exists | L | none, but confirm product need before building — this was never a real feature |
| 9 | `stream_alerts` gRPC | **No** — no consumer (webui websocket, SIEM forwarder, anything) ever existed in v1 or v2; v1's own gRPC server commit (`5ca2052`) explicitly left this `UNIMPLEMENTED` as intentional v1 parity | Dead stub, deliberately matching v1's own dead stub — **not a v2 regression** | Only build if a real consumer is scoped (SOC dashboard, external forwarder) | L if pursued | needs a consumer use case first; otherwise leave documented as intentionally unimplemented |

`approvals:pending` Redis stream: defined (`STREAM_APPROVALS`) but never
published or consumed in v1 or v2 — a dead constant, not a gap, since the
approval workflow that matters (REST CRUD) doesn't need it.

## Detail — row 1/2/3: CodeScan license-compliance & detections

- `darwin/services/flask-backend/app/linters/license_scanner.py`
  (`CycloneDXScanner`, at `9466b34^`) is a real implementation: parses
  `requirements.txt`/`package.json`/`go.mod`, shells to `cyclonedx`/ScanCode
  CLI. It is **never instantiated outside its own file** — not registered in
  `app/core/linter.py`'s registry, never called from `app/core/reviewer.py`
  or `app/tasks/review_worker.py`.
- `app/api/v1/licenses.py` + `models.py` give full CRUD on license policies
  and a violations reader (`get_review_license_violations`) — but nothing
  ever calls the writer; the violations table was always empty in v1.
- `codescan_provider_usage` is the one genuinely-working piece:
  `models.py:795` inserts on every real AI review call, and
  `app/api/v1/providers.py` reads it back for cost/token stats. This should
  be the first of the three ported — it's a straight port, not a design
  problem.
- `codescan_review_detections` ("detected languages/frameworks per review"):
  `create_detection()`/`get_detections_by_review()` exist in `models.py`;
  the reader is wired into `app/api/v1/reviews.py` (GET review, GET review
  list) but `create_detection` has **zero callers anywhere in the darwin
  tree** — same orphaned pattern as license detections, just for a
  different detection type.

## Detail — row 4: worker-codescan git credentials

- `darwin/services/flask-backend/app/git/credentials.py`
  (`CredentialManager`/`GitCredential`): Fernet-encrypted at rest, matched to
  a repo by **URL glob pattern** (`fnmatch`), not a strict per-repo FK.
- `app/git/clone.py`'s `GitCloner.clone()` takes a resolved `GitCredential`
  and injects it (`clone_with_token()` for HTTPS, key file for SSH) before
  shelling to `git clone`. This is real, working, sandboxed.
- v2's `services/codescan-backend/src/routes/credentials.rs` (CRUD) +
  `src/crypto.rs` (decrypt) already exist and are tenant-scoped — a cleaner
  design than v1's glob match. `services/worker-codescan/src/handler.rs`
  (~line 205) builds `GitCredentials` from a single `GIT_TOKEN` env var
  instead of querying `codescan_git_credentials`; `git_provider.rs` fetches
  GitHub/GitLab diffs with that one token. This is pure wiring debt, not a
  design gap — already flagged in `docs/v2-port/v2.1-backlog.md` ("v1 itself
  never fetched PR files — passed `pr_files=[]` — so v2 is already ahead").

## Detail — rows 5–9: AI/SIEM/approvals gRPC cluster

All 8 dead RPCs live on the same `ManagerService` gRPC struct
(`services/manager/src/grpc/manager_service.rs` ~818–899); they split into
two very different buckets:

**Real logic to proxy (rows 6, 7 — cheap):**
- Approvals: `POST/GET /api/v1/approvals/*` is a genuine, tested,
  already-ported v2 REST implementation (list/pending/get/create/decide/
  cancel/statistics, 403-on-own-request, multi-approval counting). v1 never
  implemented the gRPC surface either — it's a pure proto declaration in
  both versions. Nothing in v1 or v2 ever auto-creates an approval
  (no cert-issuance gate, no user-creation gate) — it's an operator-driven
  ticket tracker, not a workflow engine other subsystems call into.
- IOC query: `query_io_cs` has a working REST equivalent already ported
  (`threat_intel.rs` lookup/search).
- For both: the gRPC handler bodies just need to call the existing REST
  route logic. No new business logic, no v1 archaeology needed beyond what's
  already confirmed.

**No v1 precedent — net-new work (rows 5, 8, 9 — expensive):**
- AI alert-review: v1 published a queue message and built a genuinely
  complete-looking analysis engine (`services/ai/provider.py` with real
  Ollama/Anthropic/OpenAI calls, `AlertReviewer` class) — but **nothing ever
  connected them**. The `manager-ai` consumer group was created at startup
  and abandoned; `alerts.ai_review` is a real DB column that was always
  null; webui has zero references to it. This is Darwin's AI *code* review
  — a separate, unrelated pipeline — don't conflate the two.
- IOC enrichment: v1's threat-intel "feeds" list (`otx`, `virustotal`, ...)
  only ever reported API-key-presence, never made a live external call.
- `stream_alerts`: no consumer ever existed; v1's own gRPC server commit
  message confirms leaving it `UNIMPLEMENTED` was itself v1-exact behavior,
  not a v2 regression.

## Recommended sequencing

1. Git credentials (row 4, S) — unblocks correct private-repo access for
   everything else in codescan.
2. Provider usage (row 1, S) and approvals/query_io_cs gRPC proxies
   (rows 6–7, S each) — cheap, real logic already exists, just needs wiring.
3. License scanning glue + review-detections logic (rows 2–3, M each) —
   genuine design work since v1 never finished either.
4. AI alert-review (row 5, M) — build against v1's engine as a reference,
   using WaddleAI as the v2 provider.
5. Enrichment / stream_alerts (rows 8–9, L) — only after product confirms
   the need; these were never real v1 features.

## Biggest risks

- **Conflating "proxy existing REST" with "build the feature."** Rows 6–7
  are cheap because the hard part already shipped in REST; rows 5/8/9 look
  the same shape (add a gRPC handler) but have no logic to proxy — treating
  them as equal-effort is the most likely planning mistake for Phase 12.
- **License-compliance and review-detections have no working v1 reference**
  for the part that actually matters (the glue). Estimates here carry more
  uncertainty than a normal port — they're closer to net-new feature design
  with recycled components.
- **The AI/SIEM/approvals gRPC mesh is not, overall, "a real v1 feature
  waiting to be restored."** Only the approvals ticket workflow and IOC
  lookup were real in v1 (and both are already ported to REST — gRPC there
  is a thin duplicate surface, not new capability). AI-review, live
  enrichment, and alert streaming were aspirational in v1 too: declared,
  partially built, never wired. Building those now is new product work, not
  parity restoration — worth flagging before Phase 12 is scoped as "finish
  the port."
