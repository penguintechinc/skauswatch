# Manager Service — v1 Contract Spec (Rust port source of truth)

Derived from `services/manager` (Quart) on `release/v2.0.x`, 2026-07-15.
The Rust port (`services/manager-rs`) MUST match this contract; deviations
require a documented decision in this file.

## Bootstrap facts

- REST port **5000** (env `API_PORT`), gRPC **50051** (env `GRPC_PORT`,
  `GRPC_ENABLED=true`). PKI gRPC client target `PKI_GRPC_ADDR=pki-server:50052`.
- CORS enabled by default: origins `*`; methods GET,POST,PUT,DELETE,OPTIONS;
  headers `Content-Type, Authorization, X-API-Key, X-Agent-ID`.
- Blueprints → prefixes: auth `/api/v1/auth`, users `/api/v1/users`, alerts
  `/api/v1/alerts`, threat_intel `/api/v1/threat-intel`, research
  `/api/v1/research`, approvals `/api/v1/approvals`, edr `/api/v1/edr`,
  s3_scan `/api/v1/s3-scan`, siem `/api/v1/siem`, asm `/api/v1/asm`, darwin
  `/api/v1/darwin`.
- Non-prefixed: `GET /healthz` → `{status,version,database,redis,timestamp}`
  (200 healthy / 503; checks DB SELECT 1 + Redis ping), `GET /readyz` →
  `{status:"ready"}`, `GET /version` → `{name,version,environment}`.
- Error envelope: 400 `{error:"Bad Request",detail}`, 401
  `{error:"Unauthorized",detail}`, 403 `{error:"Forbidden",detail}`, 404
  `{error:"Not Found",detail}`, 500 `{error:"Internal Server Error"}`.
- Pagination everywhere: `{items:[...], total, page, per_page, pages}`.
- Validation errors: `400 {error:"Validation error", details:[...]}`.

## Auth (parity-critical — webui + tests depend on the exact token shape)

- bcrypt password hashes (`users.password_hash`).
- JWT **HS256**, secret env `JWT_SECRET_KEY`. Access claims:
  `{sub: str(user_id), role, type:"access", exp: now+30min, iat}`.
  Refresh claims: `{sub, type:"refresh", exp: now+7d, iat}`; **sha256 of the
  refresh JWT** stored in `refresh_tokens.token_hash`; rotation on refresh
  (old token revoked); logout revokes all user's refresh tokens.
- `auth_required`: Bearer parse → decode → require `type=="access"` → load
  user by int(sub), reject inactive. 401 "Token expired"/"Invalid token".
- `role_required(*roles)`: `role in roles` else 403. Roles admin/maintainer/viewer.
- Login lockout: 5 failed attempts → `account_locked_until = now+15min`.
- Login response: `{access_token, refresh_token, token_type:"Bearer",
  expires_in, user:{id,email,full_name,role}}`.
- EDR agent auth (separate): headers `X-API-Key` + `X-Agent-ID`;
  `expected = hmac_sha256(EDR_API_SECRET, agent_id).hexdigest()`,
  constant-time compare.
- License gating: users create → `has_feature("premium")` else free-tier cap
  (`SIEM free_tier_user_cap`=5, exempt domains
  `skauswatch.penguintech.cloud`,`skauswatch.app`); darwin routes →
  `has_feature("darwin")` else 403; `_require_sso_license` → 402 (reserved).
  v1 fails OPEN on license-client exceptions. v2: use penguin-licensing
  crate (bypass domains give the same effect; fail-safe default OFF differs
  — v2 keeps v1 fail-open ONLY where parity requires, revisit at GA).

## Routers (full table)

See the detailed endpoint tables in the port tracker below. Summary counts:
auth 5, users 5, alerts 8, threat-intel 9, approvals 7, edr 9, s3-scan 22,
siem 6, asm 10 (pure proxy → worker-scanner:5001), darwin 12 (pure proxy →
worker-darwin:5005 behind `has_feature("darwin")`), research 7.

### auth `/api/v1/auth`
| M | Path | Auth | Notes |
|---|---|---|---|
| POST | /login | — | body {email:Email, password:min1}; 401 invalid/locked/deactivated |
| POST | /refresh | — | {refresh_token}; rotation; 401 expired/revoked/wrong-type |
| POST | /logout | JWT | revokes all refresh tokens; {message,tokens_revoked} |
| GET | /me | JWT | {id,email,full_name,role,is_active,mfa_enabled,created_at} |
| POST | /register | — | {email,password 8..128,full_name<=255}; 201 role=viewer; 409 exists |

### users `/api/v1/users`
list (admin/maintainer, paginated ≤100), get by id (self or admin/maint),
create (admin; 409 exists; free-tier cap 403), update (self: full_name+password
only; admin: all; 409 email), delete (admin; 400 self-delete; also deletes
refresh tokens).

### alerts `/api/v1/alerts`
list (filters severity[]/status[]/source), get, create (admin/maint; publishes
`alerts:pending` {alert_id,title,severity,source,created_at}), update, update
status (`/<id>/status`), ai-review (`/<id>/ai-review` → 202, publishes
`ai:tasks` {job_id,alert_id,provider,priority,task_type:"alert_review",
submitted_at}; 503 if AI disabled), search (POST /search), statistics
({total,by_severity,by_status,last_24_hours}).
Severity: critical/high/medium/low/info. Status: pending/in_progress/resolved/
false_positive/escalated. resolved sets resolved_at.

### threat-intel `/api/v1/threat-intel`
iocs list (per_page≤500, filters type[]/threat_level[]/source/include_expired),
get, create (409 + existing_id on dup type+value), bulk (≤1000, upsert,
{created_count,updated_count,error_count,errors[:10]}), delete (admin),
search (POST), lookup (POST {type,value} → {found,ioc?}), statistics
({total,by_type,by_threat_level,top_sources≤10,expired}), feeds (static list:
dns_blacklist, ip_blacklist, otx, virustotal, taxii).
IndicatorType: ip/domain/hash/url/email/file/registry.

### approvals `/api/v1/approvals`
list, pending (admin/maint; excludes own-decided, non-expired), get (full incl
approvers/approval_history), create ({request_type,resource_id,resource_type,
metadata,required_approvals 1-10,expires_hours 1-168}), decide
(`/<id>/decide` {approved,reason}; 403 own request; multi-approval counting),
cancel (requester or admin; sets rejected), statistics.
Types: certificate/user/service/configuration.

### edr `/api/v1/edr`
Agent (HMAC): register (201/200), heartbeat (404 unregistered), events
(single or ≤100 batch → 202 {events_received,events_stored,errors[:10]};
publishes `edr:events` summary), config (GET, X-Agent-ID header).
Operator (JWT): agents list (admin/maint), agent get, agent events
(per_page≤200), deactivate (admin), statistics (stale = active & no
heartbeat 5min).

### s3-scan `/api/v1/s3-scan` (22 routes)
buckets CRUD + test (boto3 head_bucket) + scan trigger; jobs list/get/cancel;
results list/get + statistics + create-indicator + ti-enrichment;
schedule GET/PUT/DELETE per bucket (cron 5-6 parts); upload (multipart,
≤100MB, md5+sha256) + upload get/history/delete (owner or admin);
hash-lookup (MD5-32/SHA256-64 hex). Credential masking: access `xxxx****`,
secret `xxxx...last4`.

### siem `/api/v1/siem`
health (no auth; probes log-receiver /healthz), ingest (proxy →
LOG_RECEIVER_URL /ingest), search (OpenSearch `skauswatch-logs-*`), stats
(aggs class_name.keyword/severity_id), config GET, config PUT (admin;
retention_days 1-400; v1 does NOT persist — validate-only no-op).

### asm — pure proxy to `WORKER_SCANNER_URL` (`worker-scanner:5001`)
/api/v1/asm/*: scans POST/GET/get + hosts/screenshots/certs/diff/report,
settings/ports GET/PUT (PUT admin). httpx timeout 120s, forwards
Authorization. Errors: 504 timeout, 503 connect, 500 other.

### darwin — pure proxy to `WORKER_DARWIN_URL` (`worker-darwin:5005`)
Every route gated by has_feature("darwin") → 403. status, repos CRUD
(POST/PUT/DELETE admin), reviews (POST maintainer), plans.

### research `/api/v1/research`
lookup (composite whois/dns/asn/shodan/maltego), whois, dns, asn, shodan
(503 if disabled), maltego (503 if disabled), config.
⚠ v1 code reads non-existent `config.research.*` — routes AttributeError at
runtime. v2 DECISION: implement against a proper ResearchConfig; shapes per
validators/research_models.py.

## DB schema (owned by manager; SQLAlchemy create_all at startup in v1)

Tables: users, refresh_tokens, threat_indicators, alerts, approval_requests,
audit_logs, edr_agents, edr_events, s3_bucket_configs, s3_scan_jobs,
s3_scan_results, adhoc_scan_results, s3_scan_schedules. Full column lists in
services/manager/models/db.py (treat as authoritative over handler code —
see drift below). v2: baseline into migrations/core via sqlx migrate
(Phase 10); manager-rs uses sqlx runtime queries, no create_all.

## Redis Streams (prefix `skauswatch`, maxlen ~10000)

Streams: edr:events, alerts:pending, ai:tasks, threatintel:updates,
approvals:pending, audit:log, s3scan:tasks, s3scan:results.
Groups (manager): manager-edr, manager-alerts, manager-ai, manager-s3scan,
manager-s3scan-results. Encoding: each field flattened — dict/list →
json.dumps, datetime → isoformat, else str (None→""). Consume:
xreadgroup(count=10, block=5000) + per-message xack.
Manager consumes edr:events (log/warn) and alerts:pending (high/critical →
republish ai:tasks). Producers/fields table in git history of this file's
source exploration; key ones:
- s3scan:tasks: {job_id,bucket_config_id,object_key,object_size,object_etag,
  scan_enabled,yara_enabled,submitted_at}
- audit:log: {event_type,action,success,user_id,resource_type,resource_id,
  details,severity,timestamp}

## gRPC

- Protos now canonical at proto/{manager,s3scan,pki}/v1/ (packages unchanged).
- v1 Python implements ONLY: HealthCheck, CreateAlert, GetAlert,
  UpdateAlertStatus, CreateIOC, LookupIndicator, LogAuditEvent.
  StreamAlerts/AI-review/QueryIOCs/EnrichIndicator/approval RPCs declared but
  NOT implemented; S3ScanService NOT registered at runtime.
- v2 scope decision: implement the 7 live RPCs + S3ScanService (workers need
  it), return UNIMPLEMENTED for the rest (matches v1 behavior).

## Env vars (full list in services/manager/config.py load_config)

Key ones: API_PORT(5000), GRPC_PORT(50051), DB_* (DB_PASS or DB_PASSWORD),
REDIS_URL/REDIS_PASSWORD/REDIS_KEY_PREFIX(skauswatch), SECRET_KEY,
JWT_SECRET_KEY, AI_ENABLED/OLLAMA_URL/ANTHROPIC_API_KEY/OPENAI_API_KEY,
OTX_API_KEY/VIRUSTOTAL_API_KEY, RESEARCH_*/SHODAN_*/MALTEGO_*,
OPENSEARCH_URL/LOG_RECEIVER_URL/LOG_RETENTION_DAYS, S3_SCAN_* (incl
S3_CRED_ENCRYPTION_KEY), WORKER_SCANNER_URL, WORKER_DARWIN_URL + DARWIN_*,
EDR_API_SECRET/EDR_*_INTERVAL/EDR_EVENT_BATCH_SIZE/EDR_SEVERITY_THRESHOLD.

## v1 defects found (port decisions — do NOT blindly replicate)

1. **s3_scan handlers ↔ schema drift**: handlers reference `db.adhoc_scans`,
   `files_scanned`, `file_key`, `scan_engine`, etc. that don't exist in the
   schema (`adhoc_scan_results`, `scanned_objects`, `object_key`,
   `detected_file_type`). DECISION: schema (§DB) is authoritative; port
   handlers against real columns. These v1 routes were runtime-broken.
2. **config.research missing** → research routes AttributeError. DECISION:
   proper ResearchConfig in v2.
3. **IOC type "file_hash"** written by s3_scan create-indicator is not in
   the allowed IS_IN_SET. DECISION: use `hash`.
4. **Job type "manual"** vs allowed full_scan/incremental_scan/prefix_scan.
   DECISION: keep writing what the DB allows; map manual→full_scan.
5. SIEM PUT /config is validate-only (not persisted) — replicate as-is.
6. License checks fail OPEN in v1 — replicate only where parity requires;
   flag for GA hardening.
7. **PUT /api/v1/alerts/{id}/status had NO role gate in v1** — any
   authenticated user (incl. read-only viewers) could mutate alert status,
   while every other alert mutation requires admin/maintainer. DECISION:
   v2 gates it with role(admin,maintainer). Golden harness will show a
   200→403 diff for viewer tokens on this route — intentional.
