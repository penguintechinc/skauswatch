-- Tenancy retrofit for codescan-backend. Design authority:
-- docs/v2-port/tenancy-model.md (§5 table inventory, §7 per-service
-- checklist). Fixes the live IDOR where `tenant_id` was read from the
-- client-supplied request body instead of the validated JWT — see
-- src/auth.rs and the per-route handlers for the corresponding query-layer
-- fix landing in this same change.
--
-- codescan-backend has no local `tenants` table (manager owns it — see
-- services/manager/migrations/0002_tenancy.sql) and no local `users` table
-- either, so every `tenant_id` column below is a *logical* reference to
-- manager's `tenants.id` (cross-database, no real FK possible — enforced at
-- the application layer via the validated JWT `tenant` claim, never a
-- client-supplied value) rather than a `REFERENCES` constraint.
--
-- Bootstrap tenant literal must match manager's
-- `services/manager/src/auth::DEFAULT_TENANT_ID` / migration seed exactly —
-- v2 has never hit prod, so every pre-existing row in every environment
-- this has run in gets backfilled to it.
--
-- Two treatments, by whether the column already existed:
--
--   * `codescan_repo_configs` / `codescan_reviews` / `codescan_issue_plans`
--     already carry a `tenant_id BIGINT`, unenforced and populated (if at
--     all) directly from the vulnerable client-supplied request body.
--     Those existing values are not trustworthy tenant identifiers (they
--     were never validated against anything), so this treats them the same
--     as "no value": drop the column and re-add it as UUID, backfilled to
--     the bootstrap tenant, then SET NOT NULL. There is no meaningful data
--     to preserve by attempting a BIGINT->UUID cast.
--
--   * The other 7 tables (`codescan_git_credentials`,
--     `codescan_review_comments`, `codescan_review_detections`,
--     `codescan_provider_usage`, `codescan_license_policies`,
--     `codescan_license_detections`, `codescan_license_violations`) never
--     had a tenant_id column at all: ADD COLUMN nullable -> UPDATE existing
--     rows -> SET NOT NULL, matching manager's "no default" treatment for
--     tables whose read/write paths are fully wired in the same change
--     (every query site touching these tables is updated in this pass,
--     including the 5 schema-only tables that currently have zero query
--     sites in this service's REST surface but still must not accept an
--     unenforced tenant boundary going forward).
--
-- `codescan_git_credentials` is keyed by `user_id`, not directly by tenant
-- (per the design doc) — `tenant_id` here is denormalized from the owning
-- user for tenant-scoped listing/audit without a join on every query; the
-- authoritative ownership boundary stays `user_id`.

-- codescan_repo_configs (type-fix BIGINT -> UUID + enforce) --------------
ALTER TABLE codescan_repo_configs DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE codescan_repo_configs ADD COLUMN tenant_id UUID;
UPDATE codescan_repo_configs SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_repo_configs ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_repo_configs_tenant_id ON codescan_repo_configs (tenant_id, id);

-- codescan_reviews (type-fix BIGINT -> UUID + enforce) -------------------
ALTER TABLE codescan_reviews DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE codescan_reviews ADD COLUMN tenant_id UUID;
UPDATE codescan_reviews SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_reviews ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_reviews_tenant_status ON codescan_reviews (tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_codescan_reviews_tenant_repo_config ON codescan_reviews (tenant_id, repo_config_id);

-- codescan_issue_plans (type-fix BIGINT -> UUID + enforce) ---------------
ALTER TABLE codescan_issue_plans DROP COLUMN IF EXISTS tenant_id;
ALTER TABLE codescan_issue_plans ADD COLUMN tenant_id UUID;
UPDATE codescan_issue_plans SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_issue_plans ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_issue_plans_tenant_repository ON codescan_issue_plans (tenant_id, repository);

-- codescan_git_credentials (new column) ----------------------------------
ALTER TABLE codescan_git_credentials ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE codescan_git_credentials SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_git_credentials ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_git_credentials_tenant_id ON codescan_git_credentials (tenant_id, id);

-- codescan_review_comments (new column) ----------------------------------
ALTER TABLE codescan_review_comments ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE codescan_review_comments SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_review_comments ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_review_comments_tenant_review ON codescan_review_comments (tenant_id, review_id);

-- codescan_review_detections (new column) --------------------------------
ALTER TABLE codescan_review_detections ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE codescan_review_detections SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_review_detections ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_review_detections_tenant_review ON codescan_review_detections (tenant_id, review_id);

-- codescan_provider_usage (new column) -----------------------------------
ALTER TABLE codescan_provider_usage ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE codescan_provider_usage SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_provider_usage ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_provider_usage_tenant_review ON codescan_provider_usage (tenant_id, review_id);

-- codescan_license_policies (new column) ---------------------------------
ALTER TABLE codescan_license_policies ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE codescan_license_policies SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_license_policies ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_license_policies_tenant_id ON codescan_license_policies (tenant_id, id);

-- codescan_license_detections (new column) -------------------------------
ALTER TABLE codescan_license_detections ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE codescan_license_detections SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_license_detections ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_license_detections_tenant_review ON codescan_license_detections (tenant_id, review_id);

-- codescan_license_violations (new column) -------------------------------
ALTER TABLE codescan_license_violations ADD COLUMN IF NOT EXISTS tenant_id UUID;
UPDATE codescan_license_violations SET tenant_id = '00000000-0000-0000-0000-000000000001'
    WHERE tenant_id IS NULL;
ALTER TABLE codescan_license_violations ALTER COLUMN tenant_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_codescan_license_violations_tenant_review ON codescan_license_violations (tenant_id, review_id);
