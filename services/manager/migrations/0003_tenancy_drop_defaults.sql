-- R2a-2 follow-up to the 0002_tenancy.sql keystone. Design authority:
-- docs/v2-port/tenancy-model.md.
--
-- 0002 added `tenant_id` to threat_indicators/alerts/approval_requests/
-- audit_logs/endpoint_agents/endpoint_events/s3_scan_schedules WITH a
-- DEFAULT of the bootstrap tenant, explicitly so every existing INSERT
-- across this service kept compiling/working while the per-route tenant
-- sweep (R2a-2) landed. That sweep is now complete: every INSERT into these
-- 7 tables (REST handlers, the ManagerService gRPC surface, and test seed
-- helpers) explicitly supplies `tenant_id` from `CurrentUser`/gRPC
-- `x-tenant-id` metadata/the owning agent row — none of them rely on the
-- column default anymore. A live default from here on would mask a
-- forgotten stamp in future code instead of failing loudly, so it is
-- dropped.
--
-- This does NOT touch `users`/`refresh_tokens` (0002 already added those
-- with no default) or any s3scan-owned table (`s3_bucket_configs`,
-- `s3_scan_jobs`, `s3_scan_results`, `adhoc_scan_results`) — those are a
-- different service's migration (owners-before-consumers; see the design
-- doc's apply-order note). `routes/s3_scan.rs` still queries those tables
-- directly but cannot yet filter them by tenant until s3scan's own
-- migration lands.

ALTER TABLE threat_indicators ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE alerts ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE approval_requests ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE audit_logs ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE endpoint_agents ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE endpoint_events ALTER COLUMN tenant_id DROP DEFAULT;
ALTER TABLE s3_scan_schedules ALTER COLUMN tenant_id DROP DEFAULT;
