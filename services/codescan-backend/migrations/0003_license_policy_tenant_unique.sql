-- Phase 12: codescan_license_policies gets a real CRUD surface for the
-- first time (services/codescan-backend/src/routes/license_policies.rs) —
-- surfacing the pre-existing global `UNIQUE (license_name)` constraint as an
-- actual cross-tenant bug: tenant A configuring a policy for "MIT" would
-- block tenant B from ever configuring their own "MIT" policy. That
-- constraint predates the tenancy retrofit (0002) and was never exercised by
-- any query path until now, so this is corrected before the surface goes
-- live rather than shipping the collision.
--
-- Bootstrap tenant literal matches the one used throughout this service's
-- prior migrations (docs/v2-port/tenancy-model.md §8); no data migration is
-- needed here since 0002 already backfilled every row's tenant_id.

ALTER TABLE codescan_license_policies
    DROP CONSTRAINT IF EXISTS codescan_license_policies_license_name_key;

ALTER TABLE codescan_license_policies
    ADD CONSTRAINT codescan_license_policies_tenant_license_key
    UNIQUE (tenant_id, license_name);
