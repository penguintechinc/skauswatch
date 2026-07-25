# Log-Receiver Service — v1 Contract Spec (Rust port source of truth)

Derived from `services/log-receiver` (aiohttp + opensearch-py 2.7.1) on
`release/v2.0.x`, 2026-07-25. The Rust port (`services/log-receiver`, package
`skauswatch-log-receiver`) matches this contract; deviations are documented
below with a decision.

The log-receiver is the SIEM log-ingest endpoint the manager's siem router
proxies to via `LOG_RECEIVER_URL` (see `services/manager/src/routes/siem.rs`).
Only two surfaces are on that contract: `GET /healthz` (liveness probe) and
`POST /ingest` (ingest proxy). Both are ported byte-for-byte, along with the
OCSF document the manager's `/siem/search` + `/siem/stats` read back out of
OpenSearch.

## Bootstrap facts

- HTTP ingest port **5010** (env `HTTP_PORT`). Prometheus metrics on **:9090**
  (house telemetry standard; additive to v1). No auth on either endpoint (v1
  parity — the manager fronts auth).
- Startup applies the OpenSearch ISM lifecycle policy (best-effort; see below),
  then serves `/ingest` + `/healthz`.
- `serve` (default) / `healthcheck` subcommands (house pattern; `healthcheck`
  probes the local `/healthz`). No Dockerfile — deferred to Phase 10.

## Endpoints

### `GET /healthz`
- **200** `application/json`, body **`{"status":"ok","service":"log-receiver"}`**
  (insertion order preserved). The manager only checks `status_code == 200`.

### `POST /ingest`
- Body: a single JSON object **or** a JSON array of log records. A non-array
  body is wrapped into a one-element list (`records = body if isinstance(body,
  list) else [body]`).
- Header **`X-Log-Source`** (default `"http"`) selects the OCSF source label.
- Batch cap **10,000** records.
- Each record is OCSF-normalized and bulk-indexed into the daily OpenSearch
  index; the response is **202** `{"ingested": <record count>}`.

| Condition | Status | Body (`Content-Type`) |
|---|---|---|
| Success | **202** | `{"ingested":N}` (`application/json`) — N = record count |
| Body not valid JSON | **400** | `Invalid JSON` (`text/plain`) |
| Batch > 10,000 | **413** | `Batch too large (max 10,000)` (`text/plain`) |
| Non-object record / bad numeric timestamp / OpenSearch failure | **500** | see defect #6 |

`ingested` is the **record count**, not the OpenSearch success count — v1
ignores `write_batch`'s return value (defect #1). An empty array `[]` returns
`{"ingested":0}` and makes no OpenSearch request.

## OpenSearch write path (parity-critical)

- Daily index: **`skauswatch-logs-{now:%Y.%m.%d}`** (v1 `INDEX_PATTERN =
  "skauswatch-logs"`), e.g. `skauswatch-logs-2026.07.25`. `now` is UTC at write
  time. The manager searches `skauswatch-logs-*`.
- Wire call: **`POST {OPENSEARCH_URL}/_bulk`**, `Content-Type:
  application/x-ndjson`, reproducing opensearch-py `helpers.async_bulk` framing
  byte-for-byte — for each event two `\n`-terminated lines:
  ```
  {"index":{"_index":"skauswatch-logs-2026.07.25"}}
  {<compact OCSF document>}
  ```
  Compact JSON uses `(",", ":")` separators, `ensure_ascii=False`, and preserves
  key insertion order.
- Transport failure or non-2xx `_bulk` response → 500 (v1 `raise_on_error=False`
  ignores per-item errors but still raises on transport/HTTP errors). A 200 with
  `errors:true` is **not** an error (item errors ignored).

### OCSF document shape (exact key order + types)

```json
{
  "class_uid": 3002,
  "class_name": "authentication",
  "time": "2025-01-15T12:30:00+00:00",
  "severity_id": 1,
  "status_id": 1,
  "message": "user login",
  "metadata": {"version":"1.3.0","product":{"name":"SkausWatch","vendor_name":"PenguinTech"}},
  "raw_data": { <original record, key order preserved> }
}
```

- **class_uid / class_name** (`_detect_class`, checked in this order):
  `source` contains `"login"` OR `event_type == "auth"` → `3002 authentication`;
  `"network"` OR `src_ip` present → `4001 network_activity`; `"file"` OR
  `file_path` → `4003 file_activity`; `"api"` OR `endpoint` → `6003
  api_activity`; else `2001 security_finding`.
- **time** — `datetime.isoformat()` of the detected timestamp. First truthy of
  `timestamp` / `time` / `@timestamp`: a **string** is parsed with
  `fromisoformat(s.replace("Z","+00:00"))` (offset preserved; **naive input →
  no offset suffix**; fractional → 6 digits, omitted when zero); an
  **int/float** → `fromtimestamp(x, utc)` (always `+00:00`); missing/unparsable
  → `now` (aware `+00:00`). The naive case uses `skauswatch_streams::py_isoformat`.
- **severity_id** (`_detect_severity`): `str(level or severity or "").lower()`
  mapped — debug/info/informational→1, low/warning/warn→2, medium→3,
  error/high→4, critical/fatal→5, else 0.
- **status_id** (`_detect_status`): substring over `str(status or result or
  "")` — contains `success`/`ok`→1, else `fail`/`error`/`denied`→2, else 99.
  Substring semantics preserved verbatim (defect #2).
- **message**: `message` value, else `msg` value (used as-is, any JSON type),
  else `str(record)[:500]` (Python `repr`, incl. quote-switching).
- **metadata / raw_data**: fixed metadata; `raw_data` is the original record
  with key order preserved.

### ISM lifecycle policy (startup, best-effort)

- **`PUT {OPENSEARCH_URL}/_plugins/_ism/policies/skauswatch-logs-policy`** with
  the v1 `build_ism_policy` body: 30d hot (rollover 1d / 10M docs), warm
  (read_only + force_merge to 1 segment), delete at `LOG_RETENTION_DAYS`.
- Errors (e.g. OpenSearch unreachable) are logged and swallowed — startup
  continues (v1 `ensure_ism_policy` parity).

## Env vars

| Var | Default | Used | Notes |
|---|---|---|---|
| `OPENSEARCH_URL` | `http://localhost:9200` | yes | bulk + ISM target |
| `LOG_RETENTION_DAYS` | `90` | yes | ISM delete age; validated **1–400** (else startup fails, v1 `__post_init__`) |
| `HTTP_PORT` | `5010` | yes | ingest/healthz port |
| `S3_ENDPOINT_URL`, `S3_REGION`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, `S3_SIEM_BUCKET` | v1 defaults | no | Parquet sink (deferred) — accepted but ignored |
| `REDIS_URL` | `redis://localhost:6379` | no | Redis-stream consumer (deferred) |
| `SYSLOG_UDP_PORT` | `514` | no | syslog listener (deferred) |

Unparseable `LOG_RETENTION_DAYS`/`HTTP_PORT` fail startup (v1 `int(...)` raised).
Present-but-unused env vars do not affect startup.

## Scope: deferred v1 paths (documented decision)

v1 also mirrored every ingest to an **S3/Parquet** archive and accepted logs
from a **Redis stream** (`skauswatch:logs:ingest`) and a **syslog UDP** listener
(`SYSLOG_UDP_PORT`). This port covers the HTTP→OpenSearch path only; the three
secondary paths are **deferred**:

- **S3/Parquet mirror sink** — byte-parity of pyarrow's Parquet output is not
  reproducible by any Rust Parquet writer (differing row-group/metadata/
  compression framing), so there is no verifiable parity target; it needs heavy
  `arrow`/`parquet` crates absent from the workspace; and the manager never
  reads these objects.
- **Redis-stream consumer** and **syslog-UDP listener** — no v2 component
  produces to `skauswatch:logs:ingest` or sends syslog to this service
  (grep-verified across the repo), and both funnel through the deferred Parquet
  sink, so porting them now yields a lossy, traffic-less path.

All three are behind the same Parquet dependency and none are on the manager
contract. They are called out here for a follow-up (their v1 env vars remain
accepted so operator config stays valid).

## v1 defects / decisions (do not blindly replicate)

1. **`ingested` = record count, not indexed count** — `handle_ingest` returns
   `len(events)` and ignores `write_batch`'s success count. Replicated as-is.
2. **Substring status detection** — `"ok" in status` etc. means `"revoked"` →
   Success. Replicated verbatim.
3. **`level`/`severity` Python truthiness** — empty string / `0` / `null` fall
   through the `or` chain. Replicated (`JsonVal::py_truthy`).
4. **`str(record)[:500]` message fallback** — Python `repr(dict)` (single
   quotes, `True`/`False`/`None`, quote-switching for embedded quotes),
   truncated to 500 code points. Replicated; exotic float exponents /
   non-BMP-unprintable chars are a documented approximation (not hit by real
   log data).
5. **Timestamp offset variance** — naive ISO input yields a `time` with no
   offset; aware/numeric yields `+00:00` (or the parsed offset). Replicated
   exactly against captured `datetime.isoformat()` values.
6. **500 body divergence** — v1 uncaught exceptions (non-object record,
   out-of-range numeric timestamp, OpenSearch transport error) produced
   aiohttp's plain-text 500; v2 returns `{"error":"Internal Server Error"}`
   (house convention). The manager proxy maps either to its own 500, so the
   end-to-end shape is unchanged. Decision: keep the JSON body.
7. **Parquet-before-OpenSearch coupling** — v1 wrote Parquet *before*
   OpenSearch, so an S3 failure 500'd `/ingest` before any OpenSearch write.
   With Parquet deferred, v2's `/ingest` has no S3 dependency and writes only
   OpenSearch. Decision: acceptable — the response shape is identical and no v2
   consumer reads the S3 archive.
8. **serde_json key-order hazard** — serde_json's default `Value` sorts object
   keys; v1 preserves insertion order. Enabling serde_json `preserve_order`
   would flip ordering workspace-wide (feature unification) and silently break
   the manager's parity-verified responses. Decision: a self-contained ordered
   JSON type (`src/jsonord.rs`) preserves `raw_data` order and compact
   rendering without touching serde_json's features.

## Parity verification (synchronous, real)

**Reference capture** (`python:3.13-slim`): the **real v1 `ocsf/normalizer.py` +
`ocsf/schema.py`** (stdlib-only) build the OCSF documents for a fixed 7-record
batch, and the **real opensearch-py 2.7.1** (the version v1 pins) emits the
`_bulk` request against a stub HTTP server that captures the literal body. This
yields the exact OpenSearch wire bytes v1 would send, saved as
`tests/fixtures/bulk_reference.ndjson`. `datetime.isoformat()` outputs and
`str(dict)[:500]` message fallbacks were captured the same way
(`tests/fixtures/{isoformat_cases,pyrepr_cases,expected}.json`).

The **full aiohttp app was intentionally not run**: it requires the private
`penguin_utils` package plus `aiobotocore`/`pyarrow`, and its `/ingest` writes
Parquet to S3 *before* OpenSearch — unreachable without a live S3. Running the
identical v1 document code + the real opensearch-py serializer captures the same
OpenSearch bytes without those blockers.

The **7-record batch** (single `X-Log-Source: ingest-test`) exercises: all five
class detections (field-based), severity mapping incl. the empty-`level`
fallback and uppercase, status via `status`/`result`/substring, timestamps via
`Z`/offset/naive/unix-int/unix-float/microseconds, and message via
`message`/`msg`/`str(dict)` fallback.

**Rust side** (31 tests, all passing):
- Unit tests assert class/severity/status/timestamp/message and document key
  order against the captured Python values.
- `build_bulk_body_reproduces_reference_bytes` rebuilds the `_bulk` body
  in-process and asserts `== bulk_reference.ndjson`.
- `ingest_bulk_body_matches_v1_reference` POSTs the exact batch bytes to
  `/ingest` (axum-test) against a **wiremock** OpenSearch stub and asserts both
  the `202 {"ingested":7}` response **and** the captured outgoing `_bulk` body
  `== bulk_reference.ndjson` byte-for-byte.

**Outcome: byte-for-byte parity** on the OpenSearch `_bulk` request body and on
the `/ingest` + `/healthz` response shapes.

Regenerate the reference (if the batch/fixtures change):
```
docker run --rm -v <worktree>:/w:ro -v <scratch>/gen_reference.py:/gen_reference.py:ro \
  -v <scratch>/out:/out python:3.13-slim \
  sh -c "pip install 'opensearch-py[async]==2.7.1' && python3 /gen_reference.py"
```
(script preserved in the port session scratchpad).
