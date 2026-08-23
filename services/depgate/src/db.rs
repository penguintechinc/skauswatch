//! DepGate's DB layer: `depgate_artifacts` (the tag/digest -> sha256 index,
//! plus verdict/audit metadata) and `depgate_quarantine` (flagged
//! artifacts). Runtime `sqlx::query`/`query_as` only — no compile-time
//! `query!` macro, per this crate's conventions (no `DATABASE_URL`/`.sqlx`
//! cache dependency at build time).
//!
//! Lookups by `(ecosystem, name, reference)` — the OCI tag-resolution path
//! — are deliberately NOT tenant-filtered; see the schema migration's
//! design note and `src/scanpipe.rs` module docs for why the shared,
//! content-addressed cache is tenant-agnostic by design. The admin/report
//! queries at the bottom of this file (list/stats) ARE tenant-scoped, since
//! those serve the per-tenant reporting surface (`src/routes/admin.rs`).

use chrono::NaiveDateTime;
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

/// One `depgate_artifacts` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ArtifactRow {
    /// Synthetic primary key.
    pub id: Uuid,
    /// Ecosystem discriminator (`"oci"` for P1).
    pub ecosystem: String,
    /// The repository/package name as requested (e.g. `library/nginx`).
    pub name: String,
    /// The tag or digest string the caller most recently requested.
    pub reference: String,
    /// Content-addressed digest hex (no `sha256:` prefix).
    pub sha256: String,
    /// Upstream registry base URL this was fetched from.
    pub upstream: String,
    /// Stored `Content-Type`.
    pub content_type: Option<String>,
    /// Size in bytes.
    pub size_bytes: i64,
    /// One of `clean`/`infected`/`pup`/`error`/`skipped`/`quarantined`.
    pub verdict: String,
    /// When the current verdict was recorded.
    pub verdict_at: NaiveDateTime,
    /// `skauswatch-scan-core`'s `SCANNER_VERSION` at scan time.
    pub scanner_version: String,
    /// Exempt from future TTL eviction (seed-warmed artifacts).
    pub pinned: bool,
    /// Tenant that first caused this row to be created (attribution only —
    /// see module docs).
    pub tenant_id: Uuid,
    /// First time this `(ecosystem, name, reference)` was resolved.
    pub first_seen: NaiveDateTime,
    /// Most recent resolution.
    pub last_seen: NaiveDateTime,
}

/// Fields needed to upsert one resolved artifact.
#[derive(Debug, Clone)]
pub struct UpsertArtifact<'a> {
    /// Ecosystem discriminator.
    pub ecosystem: &'a str,
    /// Repository/package name.
    pub name: &'a str,
    /// Tag or digest string requested.
    pub reference: &'a str,
    /// Content digest hex.
    pub sha256: &'a str,
    /// Upstream base URL.
    pub upstream: &'a str,
    /// `Content-Type` to store.
    pub content_type: Option<&'a str>,
    /// Size in bytes.
    pub size_bytes: i64,
    /// Verdict string (`Verdict::as_str()`).
    pub verdict: &'a str,
    /// Scanner version string.
    pub scanner_version: &'a str,
    /// Whether this resolution should be pinned (seed warm-start only —
    /// normal proxy traffic always passes `false`; see the `ON CONFLICT`
    /// clause below for why that never un-pins an already-pinned row).
    pub pinned: bool,
    /// Attribution tenant.
    pub tenant_id: Uuid,
}

/// Inserts or refreshes the `(ecosystem, name, reference)` row. On
/// conflict, `pinned` is OR'd with the existing value so a normal (never
/// pinned) proxy resolution can never un-pin a seed-warmed row.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn upsert_artifact(pool: &PgPool, a: &UpsertArtifact<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO depgate_artifacts \
            (id, ecosystem, name, reference, sha256, upstream, content_type, size_bytes, \
             verdict, verdict_at, scanner_version, pinned, tenant_id, first_seen, last_seen) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), $10, $11, $12, now(), now()) \
         ON CONFLICT (ecosystem, name, reference) DO UPDATE SET \
            sha256 = EXCLUDED.sha256, \
            upstream = EXCLUDED.upstream, \
            content_type = EXCLUDED.content_type, \
            size_bytes = EXCLUDED.size_bytes, \
            verdict = EXCLUDED.verdict, \
            verdict_at = now(), \
            scanner_version = EXCLUDED.scanner_version, \
            pinned = depgate_artifacts.pinned OR EXCLUDED.pinned, \
            last_seen = now()",
    )
    .bind(Uuid::new_v4())
    .bind(a.ecosystem)
    .bind(a.name)
    .bind(a.reference)
    .bind(a.sha256)
    .bind(a.upstream)
    .bind(a.content_type)
    .bind(a.size_bytes)
    .bind(a.verdict)
    .bind(a.scanner_version)
    .bind(a.pinned)
    .bind(a.tenant_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Resolves a previously-seen `(ecosystem, name, reference)` to its current
/// row — the tag-index lookup on the OCI serve path. Not tenant-filtered;
/// see module docs.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn find_by_reference(
    pool: &PgPool,
    ecosystem: &str,
    name: &str,
    reference: &str,
) -> Result<Option<ArtifactRow>, sqlx::Error> {
    sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, ecosystem, name, reference, sha256, upstream, content_type, size_bytes, \
                verdict, verdict_at, scanner_version, pinned, tenant_id, first_seen, last_seen \
         FROM depgate_artifacts WHERE ecosystem = $1 AND name = $2 AND reference = $3",
    )
    .bind(ecosystem)
    .bind(name)
    .bind(reference)
    .fetch_optional(pool)
    .await
}

/// One `depgate_quarantine` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct QuarantineRow {
    /// Primary key.
    pub id: Uuid,
    /// Content digest hex.
    pub sha256: String,
    /// Ecosystem discriminator.
    pub ecosystem: String,
    /// Repository/package name.
    pub name: String,
    /// Tag or digest string requested.
    pub reference: String,
    /// Human-readable reason (e.g. threat names).
    pub reason: String,
    /// `malware` or `pup`.
    pub threat: String,
    /// Disposition (`"blocked"` for P1 — no policy engine yet).
    pub disposition: String,
    /// Attribution tenant.
    pub tenant_id: Uuid,
    /// When this was recorded.
    pub created_at: NaiveDateTime,
}

/// Fields needed to record one quarantine event.
#[derive(Debug, Clone)]
pub struct QuarantineInsert<'a> {
    /// Content digest hex.
    pub sha256: &'a str,
    /// Ecosystem discriminator.
    pub ecosystem: &'a str,
    /// Repository/package name.
    pub name: &'a str,
    /// Tag or digest string requested.
    pub reference: &'a str,
    /// Human-readable reason.
    pub reason: &'a str,
    /// `malware` or `pup`.
    pub threat: &'a str,
    /// Attribution tenant.
    pub tenant_id: Uuid,
}

/// Records a quarantine event. Always inserts a new row — repeated pulls of
/// the same infected reference are each individually audit-logged.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn insert_quarantine(pool: &PgPool, q: &QuarantineInsert<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO depgate_quarantine \
            (id, sha256, ecosystem, name, reference, reason, threat, disposition, tenant_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'blocked', $8, now())",
    )
    .bind(Uuid::new_v4())
    .bind(q.sha256)
    .bind(q.ecosystem)
    .bind(q.name)
    .bind(q.reference)
    .bind(q.reason)
    .bind(q.threat)
    .bind(q.tenant_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Filters for the admin `GET /api/v1/depgate/artifacts` listing.
#[derive(Debug, Clone, Default)]
pub struct ArtifactFilters {
    /// Exact-match verdict filter.
    pub verdict: Option<String>,
    /// Exact-match ecosystem filter.
    pub ecosystem: Option<String>,
    /// Substring (`ILIKE %name%`) filter.
    pub name: Option<String>,
    /// Page size.
    pub limit: i64,
    /// Page offset.
    pub offset: i64,
}

/// Lists artifacts attributed to `tenant_id`, applying `filters`, and
/// returns the matching page plus the total (unpaginated) match count.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn list_artifacts(
    pool: &PgPool,
    tenant_id: Uuid,
    filters: &ArtifactFilters,
) -> Result<(Vec<ArtifactRow>, i64), sqlx::Error> {
    let mut count_qb: QueryBuilder<Postgres> =
        QueryBuilder::new("SELECT COUNT(*) FROM depgate_artifacts WHERE tenant_id = ");
    count_qb.push_bind(tenant_id);
    push_artifact_filters(&mut count_qb, filters);
    let total: i64 = count_qb.build_query_scalar().fetch_one(pool).await?;

    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "SELECT id, ecosystem, name, reference, sha256, upstream, content_type, size_bytes, \
                verdict, verdict_at, scanner_version, pinned, tenant_id, first_seen, last_seen \
         FROM depgate_artifacts WHERE tenant_id = ",
    );
    qb.push_bind(tenant_id);
    push_artifact_filters(&mut qb, filters);
    qb.push(" ORDER BY last_seen DESC LIMIT ");
    qb.push_bind(filters.limit);
    qb.push(" OFFSET ");
    qb.push_bind(filters.offset);

    let rows = qb.build_query_as::<ArtifactRow>().fetch_all(pool).await?;
    Ok((rows, total))
}

fn push_artifact_filters(qb: &mut QueryBuilder<Postgres>, filters: &ArtifactFilters) {
    if let Some(v) = &filters.verdict {
        qb.push(" AND verdict = ");
        qb.push_bind(v.clone());
    }
    if let Some(e) = &filters.ecosystem {
        qb.push(" AND ecosystem = ");
        qb.push_bind(e.clone());
    }
    if let Some(n) = &filters.name {
        qb.push(" AND name ILIKE ");
        qb.push_bind(format!("%{n}%"));
    }
}

/// Lists quarantine events for `tenant_id`, most recent first.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn list_quarantine(
    pool: &PgPool,
    tenant_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<(Vec<QuarantineRow>, i64), sqlx::Error> {
    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM depgate_quarantine WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(pool)
            .await?;

    let rows = sqlx::query_as::<_, QuarantineRow>(
        "SELECT id, sha256, ecosystem, name, reference, reason, threat, disposition, \
                tenant_id, created_at \
         FROM depgate_quarantine WHERE tenant_id = $1 \
         ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok((rows, total))
}

/// Per-verdict artifact counts for `tenant_id` — the `/stats` endpoint's
/// `by_verdict` breakdown.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn verdict_counts(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT verdict, COUNT(*) FROM depgate_artifacts WHERE tenant_id = $1 GROUP BY verdict",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Total quarantine event count for `tenant_id`.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn quarantine_count(pool: &PgPool, tenant_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM depgate_quarantine WHERE tenant_id = $1")
        .bind(tenant_id)
        .fetch_one(pool)
        .await
}

/// Fleet-wide (every tenant) per-verdict artifact counts — backs
/// `crate::mesh_admin`'s mTLS-only cross-tenant summary, analogous to
/// [`verdict_counts`] but deliberately unscoped. Reachable only via the
/// SPIFFE-authenticated mesh listener, never the JWT-gated admin API (see
/// `crate::mesh_admin` module docs) — a per-tenant caller must never be able
/// to trigger this query.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn verdict_counts_all_tenants(pool: &PgPool) -> Result<Vec<(String, i64)>, sqlx::Error> {
    let rows: Vec<(String, i64)> =
        sqlx::query_as("SELECT verdict, COUNT(*) FROM depgate_artifacts GROUP BY verdict")
            .fetch_all(pool)
            .await?;
    Ok(rows)
}

/// Fleet-wide (every tenant) total quarantine event count — see
/// [`verdict_counts_all_tenants`]'s docs for the reachability contract.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn quarantine_count_all_tenants(pool: &PgPool) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar("SELECT COUNT(*) FROM depgate_quarantine")
        .fetch_one(pool)
        .await
}
