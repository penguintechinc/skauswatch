-- CodeScan Sentinel P2 (docs/v2-port/v2.1-codescan-sentinel.md §3, §9, P2) —
-- folds the pluggable scanner-tool registry (SAST/secrets/IaC/SBOM) into the
-- same `codescan_findings` table P1 created. Additive only: 0001-0004 are
-- untouched.
--
-- NOTE on `kind`: 0004's CHECK constraint already allows
-- ('sca','cve','sast','license','secret','iac','sbom') — it was written
-- widened up front so P2 would not need to touch that constraint at all.
-- This migration only adds the columns those new kinds actually need.

-- New tool-finding columns. All NOT NULL DEFAULT '' (matching 0004's
-- `advisory_id` convention) rather than nullable — a plain-outdated ('sca')
-- or CVE ('cve') row from P1 simply carries the empty-string sentinel for
-- every column below, and Postgres NULL!=NULL would otherwise silently
-- defeat the fingerprint-based UNIQUE index below the same way 0004's own
-- comment describes for `advisory_id`.
ALTER TABLE codescan_findings
    ADD COLUMN IF NOT EXISTS tool VARCHAR(32) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS rule_id VARCHAR(255) NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS file_path TEXT,
    ADD COLUMN IF NOT EXISTS line INTEGER,
    ADD COLUMN IF NOT EXISTS title TEXT NOT NULL DEFAULT '',
    -- sha256 hex digest (64 chars) of (tool, rule_id, file_path, line) —
    -- see worker-codescan's `scanner_tool::ToolFinding::fingerprint`. Left
    -- empty ('') for every P1 sca/cve row, which keeps using 0004's original
    -- `(tenant_id, repo_config_id, branch, package_name, advisory_id)`
    -- dedupe key unchanged below.
    ADD COLUMN IF NOT EXISTS fingerprint VARCHAR(64) NOT NULL DEFAULT '';

-- 0004's original UNIQUE constraint on (tenant_id, repo_config_id, branch,
-- package_name, advisory_id) is a *table-wide* constraint — it applies to
-- every row regardless of `kind`, not just sca/cve. Every tool finding
-- (sast/secret/iac) shares `package_name = ''` and `advisory_id = ''` (the
-- same non-applicable-column convention 0004 established), so a second tool
-- finding in the same (tenant, repo, branch) would collide on that
-- constraint before ever reaching the fingerprint index below. Replace it
-- with an equivalent *partial* unique index scoped to the kinds it was
-- actually written for — identical dedupe behavior for every existing
-- sca/cve row (P1 never wrote any other kind), now scoped so other kinds
-- don't collide with it.
ALTER TABLE codescan_findings
    DROP CONSTRAINT IF EXISTS codescan_findings_tenant_id_repo_config_id_branch_package_n_key;

CREATE UNIQUE INDEX IF NOT EXISTS idx_codescan_findings_sca_cve_dedupe
    ON codescan_findings (tenant_id, repo_config_id, branch, package_name, advisory_id)
    WHERE kind IN ('sca', 'cve');

-- Dedupe/upsert key for tool-produced findings (sast/secret/iac), scoped by
-- `WHERE fingerprint <> ''` so it never overlaps or interferes with the
-- sca/cve index above.
CREATE UNIQUE INDEX IF NOT EXISTS idx_codescan_findings_tool_fingerprint
    ON codescan_findings (tenant_id, repo_config_id, branch, kind, fingerprint)
    WHERE fingerprint <> '';

CREATE INDEX IF NOT EXISTS idx_codescan_findings_tenant_tool
    ON codescan_findings (tenant_id, tool)
    WHERE tool <> '';

-- One CycloneDX SBOM document per (repo, branch) scan run — produced by the
-- `syft`-backed `ScannerTool` impl (`kind = 'sbom'` never gets a
-- `codescan_findings` row; the document itself is the artifact). Compressed
-- at rest (gzip) since a CycloneDX document for a dependency-heavy repo can
-- run into several MB of JSON — see `security.md` Encryption (Storage):
-- Postgres's own at-rest encryption already covers this table, gzip here is
-- a size optimization, not a substitute for that baseline.
CREATE TABLE IF NOT EXISTS codescan_sbom_artifacts (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    repo_config_id      BIGINT NOT NULL REFERENCES codescan_repo_configs (id) ON DELETE CASCADE,
    branch              VARCHAR(255) NOT NULL,
    scan_run_id         BIGINT NOT NULL REFERENCES codescan_scan_runs (id) ON DELETE CASCADE,
    format              VARCHAR(32) NOT NULL DEFAULT 'cyclonedx-json',
    doc_gzip            BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- One SBOM per scan run — a re-run of the same (repo, branch) always
    -- starts a fresh `codescan_scan_runs` row (see `db::start_scan_run`), so
    -- there is never a legitimate reason for two SBOM rows to share one.
    UNIQUE (scan_run_id)
);

CREATE INDEX IF NOT EXISTS idx_codescan_sbom_artifacts_tenant_repo
    ON codescan_sbom_artifacts (tenant_id, repo_config_id, branch, created_at DESC);
