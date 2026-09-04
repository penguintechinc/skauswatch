-- DepGate P4 schema additions (docs/v2-port/v2.1-depgate.md §5/§9/§10):
-- the provenance policy-match dimension (cosign signature verification,
-- src/provenance.rs) on top of 0002's policy/quarantine engine. v2 has
-- never shipped to prod (see 0001's design note), so this is additive with
-- no backfill concerns, same posture as 0002.

-- `NULL` matches any provenance disposition, same "NULL means any" contract
-- every other `depgate_policy_rules` match column already uses. Adding a
-- provenance-matching rule never changes the *default* decision for rows
-- that don't configure one (`crate::policy::default_decision` never
-- consults this column) — §9/§10's "default must not break existing
-- pulls".
ALTER TABLE depgate_policy_rules
    ADD COLUMN IF NOT EXISTS provenance TEXT
    CHECK (provenance IS NULL OR provenance IN ('unsigned', 'verified', 'invalid'));

-- Every policy decision now also records the provenance disposition it was
-- evaluated against, for the same audit reason 0001/0002 record verdict/
-- action ("answerable: why was this package blocked/allowed?"). Existing
-- decisions predate this column's existence entirely (fresh v2 schema, no
-- backfill), so a hard NOT NULL default is safe.
ALTER TABLE depgate_policy_decisions
    ADD COLUMN IF NOT EXISTS provenance TEXT NOT NULL DEFAULT 'unsigned';
