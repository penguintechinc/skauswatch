-- Tenancy retrofit keystone. Design authority: docs/v2-port/tenancy-model.md.
--
-- manager is the auth root (the only service that mints JWTs), so it owns
-- the `tenants` table itself. Every other manager-owned table gets a
-- `tenant_id UUID NOT NULL REFERENCES tenants(id)` column plus a composite
-- index on the hot lookup path. A single default/bootstrap tenant is seeded
-- so v1-parity self-service `/auth/register` keeps working (attaches new
-- registrants to this tenant — see routes/auth.rs::DEFAULT_TENANT_ID).
--
-- `gen_random_uuid()` is a PostgreSQL 13+ built-in (no pgcrypto extension
-- required) — matches the postgres:17-bookworm target everywhere in this repo.
--
-- Two treatments, by scope of this change (R2a-1 = manager auth/creation/
-- propagation keystone; see the R2a-1 task brief §"SCOPE BOUNDARY"):
--
--   * `users`/`refresh_tokens` — the auth/creation write paths THIS change
--     wires end to end (routes/auth.rs login/refresh/register,
--     routes/users.rs create_user). No column DEFAULT, matching the design
--     doc's explicit "no default — every row must be backfilled" guidance:
--     ADD COLUMN nullable -> UPDATE existing rows -> SET NOT NULL. Harmless
--     no-op today (0001 and 0002 apply back-to-back into a schema with no
--     pre-existing rows in every environment this has run in so far — v2
--     has never hit prod), but fails closed instead of silently accepting
--     an unbackfilled row in a long-lived environment.
--
--   * `threat_indicators`/`alerts`/`approval_requests`/`audit_logs`/
--     `endpoint_agents`/`endpoint_events`/`s3_scan_schedules` — write AND
--     read paths for these are explicitly deferred to R2a-2's per-route
--     sweep (~89 query sites, out of scope here). Column IS added NOT NULL
--     + FK'd now (so the schema is fully in place for R2a-2 to build on —
--     "keystone" per the apply-order note in the design doc), but WITH a
--     DEFAULT of the bootstrap tenant so every existing INSERT across this
--     service keeps compiling/working unchanged until R2a-2 lands real
--     per-route tenant stamping. R2a-2 should `ALTER COLUMN tenant_id DROP
--     DEFAULT` on these 7 tables once every INSERT site explicitly supplies
--     a value — a live default masks a forgotten stamp.

CREATE TABLE IF NOT EXISTS tenants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        VARCHAR(63) UNIQUE NOT NULL,
    name        VARCHAR(255) NOT NULL,
    status      VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
    created_at  TIMESTAMP NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP
);

-- Fixed, reproducible bootstrap tenant (same value across alpha/beta/prod —
-- see docs/v2-port/tenancy-model.md §8). Literal UUID must match
-- `skauswatch_manager::auth::DEFAULT_TENANT_ID` exactly.
INSERT INTO tenants (id, slug, name, status)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 'Default Tenant', 'active')
ON CONFLICT (id) DO NOTHING;

-- users (no default — write path fully wired in this change) -------------
ALTER TABLE users ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE users SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE users ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT fk_users_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users (tenant_id, id);

-- refresh_tokens (no default — write path fully wired in this change) ----
-- Denormalized from users at issuance (see routes/auth.rs::issue_token_pair)
-- so token rotation never needs a second users join to learn the tenant.
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE refresh_tokens SET tenant_id = '00000000-0000-0000-0000-000000000001' WHERE tenant_id IS NULL;
ALTER TABLE refresh_tokens ALTER COLUMN tenant_id SET NOT NULL;
ALTER TABLE refresh_tokens ADD CONSTRAINT fk_refresh_tokens_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_tenant_id ON refresh_tokens (tenant_id, id);

-- threat_indicators (defaulted — write/read paths deferred to R2a-2) -----
ALTER TABLE threat_indicators
    ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE threat_indicators ADD CONSTRAINT fk_threat_indicators_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_tenant_id ON threat_indicators (tenant_id, id);

-- alerts (defaulted — write/read paths deferred to R2a-2) ----------------
ALTER TABLE alerts
    ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE alerts ADD CONSTRAINT fk_alerts_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_status ON alerts (tenant_id, status);

-- approval_requests (defaulted — write/read paths deferred to R2a-2) -----
ALTER TABLE approval_requests
    ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE approval_requests ADD CONSTRAINT fk_approval_requests_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_tenant_status ON approval_requests (tenant_id, status);

-- audit_logs (defaulted — write/read paths deferred to R2a-2) ------------
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE audit_logs ADD CONSTRAINT fk_audit_logs_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_created ON audit_logs (tenant_id, created_at);

-- endpoint_agents (defaulted — write/read paths deferred to R2a-2) -------
ALTER TABLE endpoint_agents
    ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE endpoint_agents ADD CONSTRAINT fk_endpoint_agents_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_endpoint_agents_tenant_agent ON endpoint_agents (tenant_id, agent_id);

-- endpoint_events (defaulted — write/read paths deferred to R2a-2) -------
ALTER TABLE endpoint_events
    ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE endpoint_events ADD CONSTRAINT fk_endpoint_events_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_endpoint_events_tenant_agent ON endpoint_events (tenant_id, agent_id);

-- s3_scan_schedules (manager-owned per migrations/0001_manager_schema.sql;
-- defaulted — write/read paths deferred to R2a-2) -------------------------
ALTER TABLE s3_scan_schedules
    ADD COLUMN IF NOT EXISTS tenant_id UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000001';
ALTER TABLE s3_scan_schedules ADD CONSTRAINT fk_s3_scan_schedules_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
CREATE INDEX IF NOT EXISTS idx_s3_scan_schedules_tenant_id ON s3_scan_schedules (tenant_id, id);
