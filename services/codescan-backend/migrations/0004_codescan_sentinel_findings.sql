-- CodeScan Sentinel P1 (docs/v2-port/v2.1-codescan-sentinel.md §9, §11 P1) —
-- the report-only Dependabot replacement: scheduled SCA/CVE scanning of each
-- repo's default + latest release branch via deps.dev, no AI, no policy
-- engine, no fix-PRs (those are P2/P3/P4). Additive only: 0001/0002/0003 are
-- untouched. This is also what finally *wires* the dead
-- `codescan_repo_configs.polling_enabled` / `polling_interval_minutes` /
-- `last_poll_at` columns that 0001 scaffolded but nothing ever queried —
-- see worker-codescan's new `scheduler` subcommand.
--
-- Tenant model matches 0002_codescan_tenancy.sql: tenant_id is UUID with no
-- real FK (manager owns `tenants`), enforced at the application layer from
-- the validated JWT `tenant` claim — never client-supplied.

-- One row per scheduled/triggered scan of a (repo, branch) — history +
-- in-flight status, surfaced by the report endpoints for "last scanned"
-- context and by the scheduler to avoid double-processing.
CREATE TABLE IF NOT EXISTS codescan_scan_runs (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    repo_config_id      BIGINT NOT NULL REFERENCES codescan_repo_configs (id) ON DELETE CASCADE,
    branch              VARCHAR(255) NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'running'
                            CHECK (status IN ('running', 'completed', 'failed')),
    findings_count      INTEGER NOT NULL DEFAULT 0,
    error               TEXT,
    started_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_codescan_scan_runs_tenant_repo
    ON codescan_scan_runs (tenant_id, repo_config_id, started_at DESC);

-- Unified SCA/CVE findings store. P1 only ever writes `kind IN ('sca',
-- 'cve')`; 'sast'/'license'/'secret'/'iac'/'sbom' arrive in P2 (spec §9/§11)
-- and are accepted by the CHECK constraint now so P2 doesn't need another
-- migration just to widen it.
--
-- `advisory_id` is NOT NULL DEFAULT '' (empty string) rather than nullable:
-- Postgres never considers two NULLs equal, which would silently defeat the
-- UNIQUE/upsert key below for every plain-outdated-package ('sca', no CVE)
-- finding — each scan would INSERT a fresh duplicate row instead of
-- updating the existing one. '' is reserved as the non-CVE sentinel value.
CREATE TABLE IF NOT EXISTS codescan_findings (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    repo_config_id      BIGINT NOT NULL REFERENCES codescan_repo_configs (id) ON DELETE CASCADE,
    branch              VARCHAR(255) NOT NULL,
    kind                VARCHAR(20) NOT NULL
                            CHECK (kind IN ('sca', 'cve', 'sast', 'license', 'secret', 'iac', 'sbom')),
    ecosystem           VARCHAR(20) NOT NULL,
    package_name        VARCHAR(255) NOT NULL,
    current_version     VARCHAR(128) NOT NULL,
    latest_version      VARCHAR(128),
    fixed_version       VARCHAR(128),
    advisory_id         VARCHAR(128) NOT NULL DEFAULT '',
    severity            VARCHAR(20) NOT NULL DEFAULT 'unknown'
                            CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    source              VARCHAR(32) NOT NULL DEFAULT 'deps_dev',
    status              VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    -- Set once an `alerts` row has been raised for this finding; cleared
    -- whenever a resolved finding reopens, so reopening can alert again
    -- without re-alerting on every unchanged scan in between (see
    -- worker-codescan's `db::upsert_finding`).
    alerted_at          TIMESTAMPTZ,
    first_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen           TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, repo_config_id, branch, package_name, advisory_id)
);

CREATE INDEX IF NOT EXISTS idx_codescan_findings_tenant_status
    ON codescan_findings (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_codescan_findings_tenant_repo_branch
    ON codescan_findings (tenant_id, repo_config_id, branch);
CREATE INDEX IF NOT EXISTS idx_codescan_findings_tenant_severity
    ON codescan_findings (tenant_id, severity);
