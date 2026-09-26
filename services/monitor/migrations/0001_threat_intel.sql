-- Threat-intelligence engine schema (phase 12) — aaa-monitor's own TAXII
-- feed/IOC/match store. Rust port of v1 `threat_intel/threat_database.py`'s
-- aiosqlite-backed `ThreatDatabase` (`store_indicator`/`search_indicators`/
-- `get_iocs`/`record_match`/`get_feed_status`), moved to this codebase's
-- standard runtime database (Postgres — see backend-database.md) instead of
-- v1's embedded SQLite.
--
-- Deliberately a SEPARATE schema from services/manager's `threat_indicators`
-- table (migrations/0001_manager_schema.sql) — that table is manager's own
-- already-ported IOC-CRUD + static feed-catalog subsystem
-- (src/routes/threat_intel.rs), a different v1 subsystem entirely (v1
-- services/manager/api/v1/threat_intel.py) with no relationship to
-- aaa-monitor's TAXII polling engine beyond sharing the words "threat
-- intel" — see services/monitor/src/threat_intel/mod.rs module docs for the
-- full disambiguation. Conflating the two schemas would either duplicate
-- working code or corrupt the wrong one; keep them independent.
--
-- `threat_feeds`/`threat_iocs` are NOT tenant-scoped: like v1's engine and
-- manager's `threat_indicators`, a TAXII-sourced indicator ("203.0.113.5 is
-- malicious") is shared threat intelligence, not any one tenant's data.
-- `threat_matches` (an event ↔ IOC association) DOES carry `tenant_id`,
-- denormalized from the matched event at write time, so a tenant's match
-- history is queryable without ever exposing another tenant's — see
-- src/threat_intel/matcher.rs.

CREATE TABLE IF NOT EXISTS threat_feeds (
    id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                     VARCHAR(255) NOT NULL,
    url                      TEXT NOT NULL UNIQUE,
    feed_type                VARCHAR(20) NOT NULL DEFAULT 'taxii',
    enabled                  BOOLEAN NOT NULL DEFAULT true,
    update_frequency         BIGINT NOT NULL DEFAULT 3600,
    credentials              JSONB,
    headers                  JSONB,
    certificate_verification BOOLEAN NOT NULL DEFAULT true,
    proxy_url                TEXT,
    last_updated             TIMESTAMPTZ,
    ioc_count                BIGINT NOT NULL DEFAULT 0,
    status                   VARCHAR(20) NOT NULL DEFAULT 'unknown',
    metadata                 JSONB NOT NULL DEFAULT '{}',
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at               TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS threat_iocs (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    kind              VARCHAR(50) NOT NULL,
    value             TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    threat_level      VARCHAR(20) NOT NULL DEFAULT 'unknown',
    confidence        DOUBLE PRECISION NOT NULL DEFAULT 0,
    tags              JSONB NOT NULL DEFAULT '[]',
    malware_families  JSONB NOT NULL DEFAULT '[]',
    kill_chain_phases JSONB NOT NULL DEFAULT '[]',
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    expiration        TIMESTAMPTZ,
    source_feed       VARCHAR(255),
    metadata          JSONB NOT NULL DEFAULT '{}',
    UNIQUE (kind, value)
);
CREATE INDEX IF NOT EXISTS idx_threat_iocs_kind_value ON threat_iocs (kind, value);

CREATE TABLE IF NOT EXISTS threat_matches (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id      VARCHAR(255) NOT NULL,
    ioc_id        UUID NOT NULL REFERENCES threat_iocs(id),
    matched_value TEXT NOT NULL,
    field_name    VARCHAR(100) NOT NULL,
    confidence    DOUBLE PRECISION NOT NULL DEFAULT 0,
    threat_level  VARCHAR(20) NOT NULL DEFAULT 'unknown',
    tenant_id     VARCHAR(255) NOT NULL,
    matched_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    metadata      JSONB NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_threat_matches_tenant ON threat_matches (tenant_id);
CREATE INDEX IF NOT EXISTS idx_threat_matches_event ON threat_matches (event_id);
