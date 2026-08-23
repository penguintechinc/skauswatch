-- CodeScan Sentinel P3 (docs/v2-port/v2.1-codescan-sentinel.md §4, §6, §9,
-- P3) — AI reachability/exposure triage verdicts (`worker-codescan::triage`,
-- via WaddleAI) and the policy engine's rule store + audit trail
-- (`worker-codescan::policy`). Additive only: 0001-0005 are untouched.
--
-- Both the triage columns and the policy engine are Enterprise-gated (spec
-- §13) — deterministic P1/P2 scanning (sca/cve/sast/secret/iac/sbom
-- findings) continues to write every column it always has; every column
-- added here is simply left at its default/NULL for a tenant that never
-- reaches this pipeline (AI disabled, or below Enterprise tier).

-- Reachability triage verdict, additive onto the existing unified findings
-- table. `used`/`reachable` are nullable BOOLEANs (NULL = "no verdict yet",
-- distinct from `false`); `exposure`/`ai_severity` are nullable enums for
-- the same reason. `triage_source` records who last determined `used`
-- (`'prefilter'` when the static reachability check alone proved a package
-- unused and short-circuited before any AI spend, `'waddleai'` when a full
-- AI triage call produced a verdict) — '' means "never triaged".
ALTER TABLE codescan_findings
    ADD COLUMN IF NOT EXISTS used BOOLEAN,
    ADD COLUMN IF NOT EXISTS reachable BOOLEAN,
    ADD COLUMN IF NOT EXISTS exposure VARCHAR(20)
        CHECK (exposure IS NULL OR exposure IN ('internal', 'external', 'none')),
    ADD COLUMN IF NOT EXISTS ai_severity VARCHAR(20)
        CHECK (ai_severity IS NULL OR ai_severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    ADD COLUMN IF NOT EXISTS ai_rationale TEXT,
    ADD COLUMN IF NOT EXISTS triaged_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS triage_source VARCHAR(32) NOT NULL DEFAULT '',
    -- The policy engine's resolved action (spec §6). '' is the "never
    -- evaluated" sentinel — matches every other empty-string-sentinel
    -- convention already established in this table (0004/0005's
    -- `advisory_id`/`tool`/`rule_id`), so a plain NULL!=NULL Postgres
    -- footgun never applies here either.
    ADD COLUMN IF NOT EXISTS action VARCHAR(20) NOT NULL DEFAULT ''
        CHECK (action IN ('', 'ignore', 'document', 'alert', 'fix'));

CREATE INDEX IF NOT EXISTS idx_codescan_findings_tenant_action
    ON codescan_findings (tenant_id, action)
    WHERE action <> '';

-- Admin-defined, priority-ordered policy rules (spec §6). Every match-
-- criterion column is nullable TEXT — NULL is a wildcard ("matches
-- anything"), matching `worker-codescan::policy::PolicyRule`'s `Option<String>`
-- fields exactly. Lower `priority` evaluates first; first match wins (see
-- `worker-codescan::policy::evaluate`).
CREATE TABLE IF NOT EXISTS codescan_policy_rules (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    priority            INTEGER NOT NULL DEFAULT 100,
    repo                TEXT,
    ecosystem           TEXT,
    package             TEXT,
    cve                 TEXT,
    severity            TEXT,
    -- 'reachable' | 'unreachable' | 'unknown'.
    reachability        TEXT,
    -- 'internal' | 'external' | 'none'.
    exposure            TEXT,
    tool                TEXT,
    kind                TEXT,
    action              VARCHAR(20) NOT NULL CHECK (action IN ('ignore', 'document', 'alert', 'fix')),
    description         TEXT,
    -- Audit: who configured this rule and when/last-changed (spec §6 /
    -- `security.md`'s general audit-trail expectations for admin-controlled
    -- security suppression). `_by` columns are the JWT `sub` (user id) as a
    -- string, not a FK — this service has no local users table (see
    -- migrations/0001's header comment).
    created_by          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by          TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_codescan_policy_rules_tenant_priority
    ON codescan_policy_rules (tenant_id, priority);

-- Audit trail: every policy decision the engine ever makes for a finding,
-- whether an admin rule matched (`rule_id` set) or the default matrix
-- decided (`rule_id` NULL) — "a security team must be able to answer 'why
-- was this auto-suppressed?'" (spec §6). Append-only: a finding re-scanned
-- on a later run gets a new decision row, not an update, so the history is
-- never lost.
CREATE TABLE IF NOT EXISTS codescan_policy_decisions (
    id                  BIGSERIAL PRIMARY KEY,
    tenant_id           UUID NOT NULL,
    finding_id          BIGINT NOT NULL REFERENCES codescan_findings (id) ON DELETE CASCADE,
    rule_id             BIGINT REFERENCES codescan_policy_rules (id) ON DELETE SET NULL,
    action              VARCHAR(20) NOT NULL CHECK (action IN ('ignore', 'document', 'alert', 'fix')),
    reason              TEXT NOT NULL,
    decided_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_codescan_policy_decisions_tenant_finding
    ON codescan_policy_decisions (tenant_id, finding_id, decided_at DESC);
