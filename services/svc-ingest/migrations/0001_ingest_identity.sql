-- Auth/tenancy identity tables for svc-ingest (Task 1.4,
-- docs/v2-port/ingest-module-spec.md §6): resolve an authenticated ingest
-- source (mTLS SPIFFE ID, or a bearer ingest token) to the tenant its
-- events are stamped with. These two tables are the ONLY source of truth
-- an authenticated identity maps to a tenant -- the service never trusts a
-- tenant id read from an event payload or request parameter (§6d).

-- mTLS: the peer's SPIFFE ID path segment (`spiffe::SpiffeId::path()`,
-- e.g. "/prod/endpoint-agent") -> tenant. One row per provisioned ingest
-- source; a path with no row is an unrecognized identity (403), never a
-- fallback tenant.
CREATE TABLE IF NOT EXISTS ingest_identities (
    spiffe_path TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL
);

-- Ingest-token fallback (§6b) for sources that cannot do mTLS. `token_hash`
-- is the hex-encoded SHA-256 digest of the raw bearer token -- the raw
-- token is never stored or logged (mirrors `endpoint_enrollment_tokens.
-- token_hash`/`refresh_tokens.token_hash` elsewhere in this workspace).
-- `revoked_at` NULL means still active; `expires_at` is mandatory --
-- ingest tokens are always short-lived, never non-expiring.
CREATE TABLE IF NOT EXISTS ingest_tokens (
    token_hash  TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL,
    revoked_at  TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ingest_tokens_expires_at ON ingest_tokens (expires_at);
