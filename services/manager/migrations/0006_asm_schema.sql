-- ASM (Attack Surface Management) schema — Phase 12 scan/monitor restore.
-- Design authority: docs/v2-port/phase12-scope-scan-monitor.md §1 "Scanner
-- ASM subsystem" restore plan, docs/v2-port/tenancy-model.md.
--
-- v1 (`services/worker-scanner/database/models.py::define_asm_tables`) had
-- 7 ASM tables plus a `target_id` FK into a separate `scan_targets` table
-- shared with the unrelated, out-of-scope nuclei/zap/openvas job schema
-- (`scan_targets`/`scan_jobs`/`scan_findings`/`scan_schedules` — see the
-- scope doc's summary table: "no confirmed v1 client", stretch-only here).
-- Pulling in that whole 4-table schema just to satisfy one FK would be scope
-- creep, so `asm_scans.target` is inlined as a plain host/CIDR/domain string
-- column instead of a `scan_targets` reference — a deliberate re-architecture
-- (see the scope doc's "Architectural finding" — this whole subsystem moves
-- from v1's REST+Celery/HTTP-proxy shape to manager-owns-tables +
-- Redis-Streams-to-worker, matching `s3_scan_jobs`/`s3_scan_results`).
--
-- manager owns these tables (creates the `asm_scans` row + publishes
-- `scanner:tasks`); the scanner worker (`services/scanner`) writes the
-- child rows directly against this same shared Postgres database — same
-- cross-service table-ownership pattern already established between
-- manager and s3scan (`services/s3scan/migrations` vs
-- `services/manager/src/routes/s3_scan.rs`).
--
-- Tenant isolation: NOT NULL + FK on `asm_scans` (new table, full write path
-- wired in this change — no default, per `0002_tenancy.sql`'s "no default"
-- treatment for freshly-wired tables). Child tables denormalize `tenant_id`
-- directly (no FK — matches `s3_scan_jobs`/`s3_scan_results`) so tenant-scoped
-- reads never need a join chain back to `asm_scans` to filter.

CREATE TABLE IF NOT EXISTS asm_scans (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    target          TEXT NOT NULL,
    mode            TEXT NOT NULL DEFAULT 'external' CHECK (mode IN ('internal', 'external', 'both')),
    status          TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    ports_config    JSONB,
    error_message   TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT now(),
    started_at      TIMESTAMP,
    completed_at    TIMESTAMP,
    created_by      INTEGER REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_asm_scans_tenant_id ON asm_scans (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_asm_scans_tenant_target ON asm_scans (tenant_id, target, status);

CREATE TABLE IF NOT EXISTS asm_hosts (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         BIGINT NOT NULL REFERENCES asm_scans(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL,
    ip_address      TEXT NOT NULL,
    hostname        TEXT,
    is_alive        BOOLEAN NOT NULL DEFAULT TRUE,
    latency_ms      DOUBLE PRECISION,
    os_guess        TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asm_hosts_tenant_scan ON asm_hosts (tenant_id, scan_id);

CREATE TABLE IF NOT EXISTS asm_services (
    id              BIGSERIAL PRIMARY KEY,
    host_id         BIGINT NOT NULL REFERENCES asm_hosts(id) ON DELETE CASCADE,
    tenant_id       UUID NOT NULL,
    port            INTEGER NOT NULL,
    protocol        TEXT NOT NULL DEFAULT 'tcp',
    state           TEXT NOT NULL DEFAULT 'open',
    service_name    TEXT,
    banner          TEXT,
    version         TEXT,
    created_at      TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asm_services_tenant_host ON asm_services (tenant_id, host_id);

CREATE TABLE IF NOT EXISTS asm_screenshots (
    id                  BIGSERIAL PRIMARY KEY,
    service_id          BIGINT NOT NULL REFERENCES asm_services(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    s3_key              TEXT NOT NULL,
    url                 TEXT,
    tool                TEXT NOT NULL,
    width               INTEGER,
    height              INTEGER,
    file_size_bytes     INTEGER,
    captured_at         TIMESTAMP,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asm_screenshots_tenant_service ON asm_screenshots (tenant_id, service_id);

CREATE TABLE IF NOT EXISTS asm_certs (
    id                  BIGSERIAL PRIMARY KEY,
    service_id          BIGINT NOT NULL REFERENCES asm_services(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    subject             TEXT,
    issuer              TEXT,
    not_before          TIMESTAMP,
    not_after           TIMESTAMP,
    is_expired          BOOLEAN NOT NULL DEFAULT FALSE,
    days_until_expiry   INTEGER,
    sans                JSONB,
    fingerprint_sha256  TEXT,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asm_certs_tenant_service ON asm_certs (tenant_id, service_id);

CREATE TABLE IF NOT EXISTS asm_diffs (
    id                  BIGSERIAL PRIMARY KEY,
    scan_id             BIGINT NOT NULL REFERENCES asm_scans(id) ON DELETE CASCADE,
    tenant_id           UUID NOT NULL,
    prev_scan_id        BIGINT REFERENCES asm_scans(id),
    new_services        JSONB,
    removed_services    JSONB,
    new_certs           JSONB,
    expired_certs       JSONB,
    created_at          TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asm_diffs_tenant_scan ON asm_diffs (tenant_id, scan_id);

-- Per-tenant ASM settings (v1: a single global `asm_settings` key/value
-- table; re-architected here as tenant-scoped since different tenants may
-- want different extra-port/masscan-rate defaults).
CREATE TABLE IF NOT EXISTS asm_settings (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    key             TEXT NOT NULL,
    value           JSONB,
    updated_at      TIMESTAMP NOT NULL DEFAULT now(),
    updated_by      INTEGER REFERENCES users(id),
    UNIQUE (tenant_id, key)
);
