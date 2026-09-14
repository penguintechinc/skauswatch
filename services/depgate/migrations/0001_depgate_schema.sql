-- DepGate P1 schema (docs/v2-port/v2.1-depgate.md §8). v2 has never shipped
-- to prod, so this is a fresh schema, not a port of a legacy table layout.
--
-- Design note (tenant scoping — see src/scanpipe.rs module docs): the OCI
-- proxy's hot serve path deliberately does NOT filter cache-hit lookups by
-- tenant. Per §11 ("shared cache + per-tenant policy — dedup is the whole
-- point") the content-addressed cache is intentionally tenant-agnostic: a
-- vetted `nginx:latest` layer is the same clean bytes for every tenant, and
-- re-scanning it per tenant would defeat the entire dedup rationale in §2.
-- `tenant_id` on both tables below is attribution/audit only (which tenant's
-- request first caused ingestion) — the admin/report API IS tenant-scoped
-- (src/routes/admin.rs), consistent with `security.md`'s tenant-isolation
-- rule applying to customer-facing data surfaces.
--
-- `sha256` is the content-addressed cache key (`sha256/<hex>` in the S3
-- bucket) — it is deliberately NOT this table's primary key, because it is
-- not unique to one row: two different tags (`nginx:latest` and
-- `nginx:1.27`) can legitimately point at byte-identical content and
-- therefore the same `sha256`, while remaining two distinct
-- "thing a client asked for by name" rows. `(ecosystem, name, reference)` —
-- the actual lookup key the OCI proxy resolves a tag through — is the
-- unique/upsert key instead; `id` is a synthetic PK per this workspace's
-- convention of never using a natural key as PK.

CREATE TABLE IF NOT EXISTS depgate_artifacts (
    id              UUID PRIMARY KEY,
    ecosystem       TEXT NOT NULL DEFAULT 'oci',
    name            TEXT NOT NULL,
    reference       TEXT NOT NULL,
    sha256          TEXT NOT NULL,
    upstream        TEXT NOT NULL,
    content_type    TEXT,
    size_bytes      BIGINT NOT NULL DEFAULT 0,
    verdict         TEXT NOT NULL CHECK (verdict IN ('clean', 'infected', 'pup', 'error', 'skipped', 'quarantined')),
    verdict_at      TIMESTAMP NOT NULL DEFAULT now(),
    scanner_version TEXT NOT NULL,
    pinned          BOOLEAN NOT NULL DEFAULT false,
    tenant_id       UUID NOT NULL,
    first_seen      TIMESTAMP NOT NULL DEFAULT now(),
    last_seen       TIMESTAMP NOT NULL DEFAULT now(),
    UNIQUE (ecosystem, name, reference)
);

CREATE INDEX IF NOT EXISTS idx_depgate_artifacts_ecosystem_name ON depgate_artifacts (ecosystem, name);
CREATE INDEX IF NOT EXISTS idx_depgate_artifacts_verdict ON depgate_artifacts (verdict);
CREATE INDEX IF NOT EXISTS idx_depgate_artifacts_tenant ON depgate_artifacts (tenant_id);
CREATE INDEX IF NOT EXISTS idx_depgate_artifacts_pinned ON depgate_artifacts (pinned) WHERE pinned;
CREATE INDEX IF NOT EXISTS idx_depgate_artifacts_sha256 ON depgate_artifacts (sha256);

-- Flagged artifacts, held out of the servable cache namespace entirely
-- (stored, if at all, under the `quarantine/` S3 prefix — never `sha256/`).
-- No FK to depgate_artifacts: a quarantined artifact intentionally has no
-- corresponding "clean" cache row.
CREATE TABLE IF NOT EXISTS depgate_quarantine (
    id           UUID PRIMARY KEY,
    sha256       TEXT NOT NULL,
    ecosystem    TEXT NOT NULL DEFAULT 'oci',
    name         TEXT NOT NULL,
    reference    TEXT NOT NULL,
    reason       TEXT NOT NULL,
    threat       TEXT NOT NULL,
    disposition  TEXT NOT NULL DEFAULT 'blocked',
    tenant_id    UUID NOT NULL,
    created_at   TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_depgate_quarantine_sha256 ON depgate_quarantine (sha256);
CREATE INDEX IF NOT EXISTS idx_depgate_quarantine_tenant ON depgate_quarantine (tenant_id);
CREATE INDEX IF NOT EXISTS idx_depgate_quarantine_created_at ON depgate_quarantine (created_at DESC);
