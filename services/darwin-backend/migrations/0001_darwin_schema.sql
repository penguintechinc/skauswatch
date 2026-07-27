-- Darwin AI code-review schema (v2 Rust port).
--
-- Table names are `darwin_*`-prefixed to match the existing per-service DB
-- grant (scripts/db/init-darwin-db.sql) and the already-merged worker-darwin
-- consumer, which queries `darwin_reviews` / `darwin_repo_configs` /
-- `darwin_review_comments` directly (services/worker-darwin/src/db.rs).
-- Column names for those three tables are constrained by that existing
-- consumer contract; every other table is this service's own design,
-- carried over from the v1 Flask backend's SQLAlchemy schema
-- (darwin/services/flask-backend/app/db_schema.py) with the `darwin_`
-- prefix applied.
--
-- No local `darwin_users` / `darwin_tenants` identity tables: authentication
-- is centralized at the manager service (shared `users` table, HS256 JWT).
-- This service validates the same JWT and trusts its `sub`/`role` claims
-- directly; user-id columns below are plain integers (no FK) referencing
-- that external identity space.

CREATE TABLE IF NOT EXISTS darwin_repo_configs (
    id                          BIGSERIAL PRIMARY KEY,
    tenant_id                   BIGINT,
    team_id                     BIGINT,
    owner_id                    BIGINT,
    provider                    VARCHAR(32) NOT NULL CHECK (provider IN ('github', 'gitlab')),
    repo_url                    VARCHAR(512) NOT NULL,
    repo_name                   VARCHAR(255) NOT NULL,
    enabled                     BOOLEAN NOT NULL DEFAULT true,
    auto_review                 BOOLEAN NOT NULL DEFAULT true,
    review_on_open              BOOLEAN NOT NULL DEFAULT true,
    review_on_sync              BOOLEAN NOT NULL DEFAULT false,
    default_categories          JSONB,
    default_ai_provider         VARCHAR(64),
    ignored_paths               JSONB,
    custom_rules                JSONB,
    webhook_secret              VARCHAR(255),
    polling_enabled             BOOLEAN NOT NULL DEFAULT false,
    polling_interval_minutes    INTEGER NOT NULL DEFAULT 5,
    last_poll_at                TIMESTAMPTZ,
    display_name                VARCHAR(255),
    description                 TEXT,
    is_active                   BOOLEAN NOT NULL DEFAULT true,
    credential_id               BIGINT,
    max_review_age_hours        INTEGER NOT NULL DEFAULT 168,
    skip_patterns                JSONB,
    auto_plan_on_issue          BOOLEAN NOT NULL DEFAULT false,
    issue_plan_provider         VARCHAR(64),
    issue_plan_model            VARCHAR(128),
    issue_plan_daily_limit      INTEGER,
    issue_plan_cost_limit_usd   DOUBLE PRECISION,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, repo_name)
);

CREATE TABLE IF NOT EXISTS darwin_git_credentials (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             BIGINT NOT NULL,
    name                VARCHAR(128),
    platform            VARCHAR(32) NOT NULL CHECK (platform IN ('github', 'gitlab')),
    credential_type     VARCHAR(32) NOT NULL DEFAULT 'token' CHECK (credential_type IN ('token', 'ssh_key')),
    encrypted_token     BYTEA NOT NULL,
    token_expires_at    TIMESTAMPTZ,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE darwin_repo_configs
    ADD CONSTRAINT fk_darwin_repo_configs_credential
    FOREIGN KEY (credential_id) REFERENCES darwin_git_credentials (id) ON DELETE SET NULL;

CREATE TABLE IF NOT EXISTS darwin_reviews (
    id                  BIGSERIAL PRIMARY KEY,
    external_id         VARCHAR(128) UNIQUE,
    tenant_id           BIGINT,
    team_id             BIGINT,
    triggered_by        BIGINT,
    repo_config_id      BIGINT NOT NULL REFERENCES darwin_repo_configs (id) ON DELETE CASCADE,
    pr_number           INTEGER,
    pr_title            VARCHAR(512),
    pr_url              VARCHAR(512),
    base_sha            VARCHAR(64),
    head_sha            VARCHAR(64),
    commit_sha          VARCHAR(64),
    review_type         VARCHAR(32) NOT NULL DEFAULT 'differential' CHECK (review_type IN ('differential', 'whole')),
    categories          JSONB,
    ai_provider         VARCHAR(64),
    ai_model            VARCHAR(128),
    status              VARCHAR(32) NOT NULL DEFAULT 'queued',
    error_message       TEXT,
    files_reviewed      INTEGER NOT NULL DEFAULT 0,
    comments_count      INTEGER NOT NULL DEFAULT 0,
    started_at          TIMESTAMPTZ,
    completed_at        TIMESTAMPTZ,
    summary             TEXT,
    score               INTEGER,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_darwin_reviews_repo_config ON darwin_reviews (repo_config_id);
CREATE INDEX IF NOT EXISTS idx_darwin_reviews_status ON darwin_reviews (status);

-- Column shape (review_id, file_path, line_number, comment, severity,
-- created_at) is a hard contract with worker-darwin's INSERT statement.
CREATE TABLE IF NOT EXISTS darwin_review_comments (
    id                      BIGSERIAL PRIMARY KEY,
    review_id               BIGINT NOT NULL REFERENCES darwin_reviews (id) ON DELETE CASCADE,
    file_path               VARCHAR(512),
    line_number             INTEGER,
    comment                 TEXT,
    category                VARCHAR(50),
    severity                VARCHAR(20),
    suggestion              TEXT,
    source                  VARCHAR(64),
    linter_rule_id          VARCHAR(128),
    platform_comment_id     VARCHAR(128),
    status                  VARCHAR(20) NOT NULL DEFAULT 'open',
    posted_at               TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_darwin_review_comments_review ON darwin_review_comments (review_id);

CREATE TABLE IF NOT EXISTS darwin_review_detections (
    id                  BIGSERIAL PRIMARY KEY,
    review_id           BIGINT NOT NULL REFERENCES darwin_reviews (id) ON DELETE CASCADE,
    detection_type      VARCHAR(64),
    name                VARCHAR(128),
    confidence          DOUBLE PRECISION,
    file_count          INTEGER,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS darwin_issue_plans (
    id                      BIGSERIAL PRIMARY KEY,
    external_id             VARCHAR(128) UNIQUE NOT NULL,
    tenant_id               BIGINT,
    platform                VARCHAR(32) NOT NULL CHECK (platform IN ('github', 'gitlab')),
    repository              VARCHAR(255) NOT NULL,
    issue_number            INTEGER NOT NULL,
    issue_url               VARCHAR(512),
    issue_title             VARCHAR(512),
    issue_body              TEXT,
    plan_content            TEXT,
    plan_steps              JSONB,
    ai_provider             VARCHAR(64),
    ai_model                VARCHAR(128),
    status                  VARCHAR(32) NOT NULL DEFAULT 'queued',
    error_message           TEXT,
    comment_posted          BOOLEAN NOT NULL DEFAULT false,
    platform_comment_id     VARCHAR(128),
    token_usage             JSONB,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_darwin_issue_plans_repository ON darwin_issue_plans (repository);

CREATE TABLE IF NOT EXISTS darwin_provider_usage (
    id                  BIGSERIAL PRIMARY KEY,
    review_id           BIGINT REFERENCES darwin_reviews (id) ON DELETE SET NULL,
    provider            VARCHAR(64),
    model               VARCHAR(128),
    prompt_tokens       INTEGER,
    completion_tokens   INTEGER,
    total_tokens        INTEGER,
    latency_ms          INTEGER,
    cost_estimate       DOUBLE PRECISION,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- License-compliance-scanning tables (OSS license taint detection within
-- reviewed code) — schema only in this pass; see Cargo.toml/README deferral
-- note. Distinct from PenguinTech's own product-tier license entitlement.
CREATE TABLE IF NOT EXISTS darwin_license_policies (
    id              BIGSERIAL PRIMARY KEY,
    license_name    VARCHAR(128) UNIQUE NOT NULL,
    policy          VARCHAR(32) NOT NULL CHECK (policy IN ('allowed', 'review_required', 'blocked')),
    actions         JSONB,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS darwin_license_detections (
    id                  BIGSERIAL PRIMARY KEY,
    review_id           BIGINT NOT NULL REFERENCES darwin_reviews (id) ON DELETE CASCADE,
    package_name        VARCHAR(255),
    package_version     VARCHAR(64),
    license_name        VARCHAR(128),
    license_source      VARCHAR(64),
    file_path           VARCHAR(512),
    confidence          DOUBLE PRECISION,
    policy_violation    BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS darwin_license_violations (
    id                  BIGSERIAL PRIMARY KEY,
    review_id           BIGINT NOT NULL REFERENCES darwin_reviews (id) ON DELETE CASCADE,
    detection_id        BIGINT REFERENCES darwin_license_detections (id) ON DELETE SET NULL,
    license_name        VARCHAR(128),
    package_name        VARCHAR(255),
    policy              VARCHAR(32),
    severity            VARCHAR(20),
    actions_taken       JSONB,
    status              VARCHAR(20) NOT NULL DEFAULT 'open',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
