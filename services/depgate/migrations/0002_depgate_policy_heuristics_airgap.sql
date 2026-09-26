-- DepGate P3 schema additions (docs/v2-port/v2.1-depgate.md §5/§6/§6b/§8):
-- package-risk heuristic findings, the policy/quarantine rules engine, and
-- air-gap bundle-import provenance. v2 has never shipped to prod (see
-- 0001's design note), so — like 0001 — this is additive with no backfill
-- concerns.
--
-- Tenant scoping follows 0001's precedent exactly: `tenant_id` here is
-- attribution/audit only (which tenant's ingest/import caused the row),
-- never a filter on the shared, content-addressed hot path. The one
-- exception is `depgate_policy_rules`, which IS filtered by tenant at query
-- time — policy is a per-tenant configuration surface, not shared cache
-- state (§11: "shared cache + per-tenant policy").

-- Per-tenant policy/quarantine rules engine (§6, §8) — same shape as
-- Sentinel's rules engine (priority, match, action, audit). NULL on any
-- match column means "any" for that dimension; the highest-`priority`
-- enabled row whose columns all match (or are NULL) wins.
CREATE TABLE IF NOT EXISTS depgate_policy_rules (
    id              UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 100,
    ecosystem       TEXT,
    name_glob       TEXT,
    version_glob    TEXT,
    verdict         TEXT,
    risk_check      TEXT,
    min_severity    TEXT CHECK (min_severity IS NULL OR min_severity IN ('info', 'low', 'medium', 'high', 'critical')),
    action          TEXT NOT NULL CHECK (action IN ('allow', 'warn', 'block', 'quarantine')),
    description     TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMP NOT NULL DEFAULT now(),
    updated_at      TIMESTAMP NOT NULL DEFAULT now(),
    created_by      TEXT
);

CREATE INDEX IF NOT EXISTS idx_depgate_policy_rules_tenant_priority
    ON depgate_policy_rules (tenant_id, priority DESC);

-- Quarantine gains a real disposition lifecycle (§6: pending -> confirmed /
-- false_positive -> released) in place of P1's single fixed 'blocked'
-- literal, plus the audit trail linking a quarantine event back to the
-- policy rule (if any) that produced it and to whoever resolved it.
ALTER TABLE depgate_quarantine ALTER COLUMN disposition SET DEFAULT 'pending';

ALTER TABLE depgate_quarantine
    ADD CONSTRAINT depgate_quarantine_disposition_check
    CHECK (disposition IN ('pending', 'confirmed', 'false_positive', 'released'));

ALTER TABLE depgate_quarantine
    ADD COLUMN IF NOT EXISTS policy_rule_id UUID REFERENCES depgate_policy_rules (id) ON DELETE SET NULL;
ALTER TABLE depgate_quarantine ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMP;
ALTER TABLE depgate_quarantine ADD COLUMN IF NOT EXISTS resolved_by TEXT;
ALTER TABLE depgate_quarantine ADD COLUMN IF NOT EXISTS resolution_note TEXT;

-- Package-risk heuristic signals (§5) — recorded per ingest, independent of
-- the scan verdict. These are signals for the policy engine to weigh, never
-- verdicts themselves: a row here does not imply the artifact was blocked.
CREATE TABLE IF NOT EXISTS depgate_risk_findings (
    id          UUID PRIMARY KEY,
    sha256      TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    reference   TEXT NOT NULL,
    check_name  TEXT NOT NULL,
    severity    TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    detail      TEXT NOT NULL,
    tenant_id   UUID NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_depgate_risk_findings_sha256 ON depgate_risk_findings (sha256);
CREATE INDEX IF NOT EXISTS idx_depgate_risk_findings_tenant ON depgate_risk_findings (tenant_id);

-- Every ingest-time policy evaluation, audit-logged regardless of outcome —
-- "why was this package blocked/allowed?" (§6).
CREATE TABLE IF NOT EXISTS depgate_policy_decisions (
    id              UUID PRIMARY KEY,
    sha256          TEXT NOT NULL,
    ecosystem       TEXT NOT NULL,
    name            TEXT NOT NULL,
    reference       TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    action          TEXT NOT NULL CHECK (action IN ('allow', 'warn', 'block', 'quarantine')),
    matched_rule_id UUID REFERENCES depgate_policy_rules (id) ON DELETE SET NULL,
    reason          TEXT NOT NULL,
    tenant_id       UUID NOT NULL,
    created_at      TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_depgate_policy_decisions_sha256 ON depgate_policy_decisions (sha256);
CREATE INDEX IF NOT EXISTS idx_depgate_policy_decisions_tenant ON depgate_policy_decisions (tenant_id, created_at DESC);

-- Air-gap bundle import provenance (§6b: "Records provenance (which
-- bundle, when)").
CREATE TABLE IF NOT EXISTS depgate_bundle_imports (
    id                  UUID PRIMARY KEY,
    bundle_name         TEXT NOT NULL,
    manifest_sha256     TEXT NOT NULL,
    signature_verified  BOOLEAN NOT NULL DEFAULT false,
    artifact_count      INTEGER NOT NULL,
    tenant_id           UUID NOT NULL,
    imported_at         TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_depgate_bundle_imports_tenant ON depgate_bundle_imports (tenant_id, imported_at DESC);
