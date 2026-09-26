-- Per-tenant EDR enrollment tokens (docs/v2-port/service-auth-model.md §5
-- Option A): closes the "every new agent lands on the default tenant"
-- gap in `routes/endpoint.rs::register_agent` by giving a *new* agent an
-- explicit tenant to resolve, instead of always falling back to
-- `default_tenant_uuid()`. Re-registration of an existing agent is
-- unaffected — it keeps the tenant already on file and never consults this
-- table.
--
-- `token_hash` (never the raw token) mirrors the password-hashing
-- principle used elsewhere in this schema (`users.password_hash`,
-- `refresh_tokens.token_hash`) — the raw token is returned exactly once, at
-- issuance, and is never retrievable again.
CREATE TABLE IF NOT EXISTS endpoint_enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID NOT NULL REFERENCES tenants(id),
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    max_uses    INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    use_count   INTEGER NOT NULL DEFAULT 0 CHECK (use_count >= 0),
    expires_at  TIMESTAMP NOT NULL,
    created_by  INTEGER NOT NULL REFERENCES users(id),
    created_at  TIMESTAMP NOT NULL DEFAULT now(),
    revoked_at  TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_hash ON endpoint_enrollment_tokens (token_hash);
CREATE INDEX IF NOT EXISTS idx_enrollment_tokens_tenant ON endpoint_enrollment_tokens (tenant_id);
