-- CodeScan Sentinel P4 (docs/v2-port/v2.1-codescan-sentinel.md §7, §9,
-- P4) — grouped auto-fix: one open PR/MR per (repo, target branch),
-- accumulating every approved dependency bump until it merges or closes,
-- at which point the next fix starts a fresh batch. Additive only:
-- 0001-0006 are untouched.
--
-- Tenant model matches every other Sentinel table (0004/0005/0006):
-- tenant_id is UUID with no real FK, enforced at the application layer
-- from the validated JWT `tenant` claim.

-- Per-repo opt-in for the git-write half of Sentinel. Default `false`
-- (report-only, spec §7: "opening PRs in a customer repo must be
-- opt-in") — deliberately the *opposite* polarity from `sentinel_exempt`'s
-- proposed opt-out blast radius (spec §6): watching/reporting is opt-out,
-- but writing to a customer's repo is always opt-in.
ALTER TABLE codescan_repo_configs
    ADD COLUMN IF NOT EXISTS sentinel_auto_fix BOOLEAN NOT NULL DEFAULT false;

-- One row per (repo, target branch) fix batch. `branch_name` is the
-- deterministic `codescan/sentinel-fixes-<target-branch>` head branch;
-- `pr_number`/`pr_url` identify the single open PR/MR this batch drives.
-- `status` transitions open -> merged|closed exactly once — a closed/merged
-- batch is historical, never reused (`worker-codescan::fix` always starts a
-- fresh row, and possibly a fresh branch, once the tracked PR stops being
-- open).
CREATE TABLE IF NOT EXISTS codescan_fix_batches (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    repo_config_id      BIGINT NOT NULL REFERENCES codescan_repo_configs (id) ON DELETE CASCADE,
    target_branch       VARCHAR(255) NOT NULL,
    branch_name         VARCHAR(255) NOT NULL,
    pr_number           BIGINT,
    pr_url              VARCHAR(512),
    status              VARCHAR(20) NOT NULL DEFAULT 'open'
                            CHECK (status IN ('open', 'merged', 'closed')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Anti-sprawl invariant (spec §7): exactly one OPEN batch per (repo, target
-- branch) — a partial unique index rather than a plain UNIQUE constraint
-- since many historical merged/closed rows for the same (repo, branch) are
-- expected and must NOT collide with each other.
CREATE UNIQUE INDEX IF NOT EXISTS uq_codescan_fix_batches_open
    ON codescan_fix_batches (tenant_id, repo_config_id, target_branch)
    WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_codescan_fix_batches_tenant_repo
    ON codescan_fix_batches (tenant_id, repo_config_id, target_branch);

-- Join: which findings a batch's PR itemizes, plus the version-bump detail
-- needed to regenerate the PR body without re-deriving it from
-- `codescan_findings` (which may have moved on to a later scan by the time
-- the body is rebuilt). `UNIQUE (batch_id, finding_id)` is this table's
-- idempotency key: `worker-codescan::fix` checks it before attempting a
-- git write for a given finding, so a re-run of an already-included fix
-- never re-commits or re-opens anything (spec's "update-until-merged", not
-- "recreate every run").
CREATE TABLE IF NOT EXISTS codescan_fix_batch_findings (
    id                      BIGSERIAL PRIMARY KEY,
    tenant_id               UUID NOT NULL,
    batch_id                BIGINT NOT NULL REFERENCES codescan_fix_batches (id) ON DELETE CASCADE,
    finding_id              BIGINT NOT NULL REFERENCES codescan_findings (id) ON DELETE CASCADE,
    package_name            VARCHAR(255) NOT NULL,
    ecosystem               VARCHAR(20) NOT NULL,
    old_version             VARCHAR(128) NOT NULL,
    new_version             VARCHAR(128) NOT NULL,
    advisory_id             VARCHAR(128) NOT NULL DEFAULT '',
    severity                VARCHAR(20) NOT NULL DEFAULT 'unknown',
    reachability_verdict    VARCHAR(32) NOT NULL DEFAULT '',
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (batch_id, finding_id)
);

CREATE INDEX IF NOT EXISTS idx_codescan_fix_batch_findings_tenant_batch
    ON codescan_fix_batch_findings (tenant_id, batch_id);
