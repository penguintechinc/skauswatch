-- Hardening from the shared scan-core extraction — see
-- docs/v2-port/v2.1-depgate.md §3: promotes the loose `scan_status
-- VARCHAR(20)` string literal (enforced only in Rust today, via
-- `skauswatch_scan_core::Verdict`/`src/db.rs::scan_status_for`) to a real
-- database-level CHECK constraint, so a future writer (this worker, a
-- manual UPDATE, or a later DepGate/Sentinel consumer of this same schema
-- shape) cannot silently persist a typo'd or stale status value.
--
-- Additive only: no column type change, no data rewrite. The allowed set is
-- exactly `skauswatch_scan_core::Verdict::as_str()`'s six values — `clean`,
-- `infected`, `pup`, `error`, `skipped`, plus the new `quarantined` state
-- DepGate introduces (not yet written by this worker, but reserved so a
-- later writer sharing this table shape doesn't need a follow-up
-- migration). `NULL` remains valid (an `IN (...)` CHECK is satisfied for a
-- NULL operand), matching every existing row created before a scan
-- completes.

ALTER TABLE s3_scan_results
    ADD CONSTRAINT s3_scan_results_scan_status_check
    CHECK (scan_status IN ('clean', 'infected', 'pup', 'error', 'skipped', 'quarantined'));

ALTER TABLE adhoc_scan_results
    ADD CONSTRAINT adhoc_scan_results_scan_status_check
    CHECK (scan_status IN ('clean', 'infected', 'pup', 'error', 'skipped', 'quarantined'));
