-- CodeScan AI Code Review — Database account provisioning
-- Run this after the initial Alembic migration: alembic upgrade head
-- Usage: psql -U <superuser> -d skauswatch -f scripts/db/init-codescan-db.sql
--
-- The CODESCAN_DB_PASS placeholder is replaced by the deploy script or run manually.
-- In production, substitute the actual password before executing.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'codescan') THEN
    CREATE USER codescan WITH PASSWORD 'changeme';
    RAISE NOTICE 'User codescan created.';
  ELSE
    RAISE NOTICE 'User codescan already exists, skipping creation.';
  END IF;
END
$$;

-- Grant on all codescan_* tables (idempotent)
GRANT SELECT, INSERT, UPDATE, DELETE ON
  codescan_tenants,
  codescan_users,
  codescan_repo_configs,
  codescan_git_credentials,
  codescan_reviews,
  codescan_review_comments,
  codescan_review_detections,
  codescan_issue_plans,
  codescan_provider_usage,
  codescan_license_policies,
  codescan_license_detections,
  codescan_license_violations
TO codescan;

-- Grant sequence access so PyDAL INSERT can fetch next IDs
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO codescan;

-- Ensure future sequences created by Alembic are also accessible
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO codescan;
