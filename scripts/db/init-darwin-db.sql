-- Darwin AI Code Review — Database account provisioning
-- Run this after the initial Alembic migration: alembic upgrade head
-- Usage: psql -U <superuser> -d skauswatch -f scripts/db/init-darwin-db.sql
--
-- The DARWIN_DB_PASS placeholder is replaced by the deploy script or run manually.
-- In production, substitute the actual password before executing.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'darwin') THEN
    CREATE USER darwin WITH PASSWORD 'changeme';
    RAISE NOTICE 'User darwin created.';
  ELSE
    RAISE NOTICE 'User darwin already exists, skipping creation.';
  END IF;
END
$$;

-- Grant on all darwin_* tables (idempotent)
GRANT SELECT, INSERT, UPDATE, DELETE ON
  darwin_tenants,
  darwin_users,
  darwin_repo_configs,
  darwin_git_credentials,
  darwin_reviews,
  darwin_review_comments,
  darwin_review_detections,
  darwin_issue_plans,
  darwin_provider_usage,
  darwin_license_policies,
  darwin_license_detections,
  darwin_license_violations
TO darwin;

-- Grant sequence access so PyDAL INSERT can fetch next IDs
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO darwin;

-- Ensure future sequences created by Alembic are also accessible
ALTER DEFAULT PRIVILEGES IN SCHEMA public
  GRANT USAGE, SELECT ON SEQUENCES TO darwin;
