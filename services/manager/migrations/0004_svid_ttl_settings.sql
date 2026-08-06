-- Persisted SPIFFE SVID TTL settings, super-admin-controlled
-- (docs/v2-port/service-auth-model.md; routes/admin.rs GET/PUT
-- /api/v1/admin/svid-ttl). Singleton row (fixed id = 1) — there is exactly
-- one SVID TTL policy per deployment, so GET/PUT never has to reason about
-- "which row"; a missing row means "never configured", and the handler
-- falls back to the documented defaults rather than requiring a seed.
CREATE TABLE IF NOT EXISTS svid_ttl_settings (
    id               SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    x509_ttl_seconds INTEGER NOT NULL DEFAULT 300 CHECK (x509_ttl_seconds BETWEEN 60 AND 86400),
    jwt_ttl_seconds  INTEGER NOT NULL DEFAULT 300 CHECK (jwt_ttl_seconds BETWEEN 60 AND 86400),
    updated_by       INTEGER REFERENCES users(id),
    updated_at       TIMESTAMP NOT NULL DEFAULT now()
);
