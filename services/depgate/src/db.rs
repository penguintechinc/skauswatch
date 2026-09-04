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
    /// Lifecycle disposition: `pending`/`confirmed`/`false_positive`/`released`
    /// (`docs/v2-port/v2.1-depgate.md` §6).
    pub disposition: String,
    /// The policy rule that produced this quarantine event, if any (`None`
    /// for a default-policy quarantine with no matching rule).
    pub policy_rule_id: Option<Uuid>,
    /// When a human resolved this event (set the disposition away from
    /// `pending`).
    pub resolved_at: Option<NaiveDateTime>,
    /// Who resolved it (subject claim of the resolving JWT).
    pub resolved_by: Option<String>,
    /// Free-text resolution note (e.g. why this was a false positive).
    pub resolution_note: Option<String>,
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
    /// The policy rule that produced this event, if any.
    pub policy_rule_id: Option<Uuid>,
    /// Attribution tenant.
    pub tenant_id: Uuid,
}

/// Records a quarantine event with disposition `pending`. Always inserts a
/// new row — repeated pulls of the same infected reference are each
/// individually audit-logged.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn insert_quarantine(pool: &PgPool, q: &QuarantineInsert<'_>) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO depgate_quarantine \
            (id, sha256, ecosystem, name, reference, reason, threat, disposition, policy_rule_id, tenant_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, now())",
    )
    .bind(Uuid::new_v4())
    .bind(q.sha256)
    .bind(q.ecosystem)
    .bind(q.name)
    .bind(q.reference)
    .bind(q.reason)
    .bind(q.threat)
    .bind(q.policy_rule_id)
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
                policy_rule_id, resolved_at, resolved_by, resolution_note, \
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

// -- Policy rules engine (§6, §8) --------------------------------------

/// One `depgate_policy_rules` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PolicyRuleRow {
    /// Primary key.
    pub id: Uuid,
    /// Owning tenant — policy is per-tenant configuration, unlike the
    /// shared content-addressed cache (see this file's module docs).
    pub tenant_id: Uuid,
    /// Match priority — highest wins among all matching, enabled rules.
    pub priority: i32,
    /// `NULL` matches any ecosystem.
    pub ecosystem: Option<String>,
    /// Glob (`*`/`?`) against the package/repo name. `NULL` matches any.
    pub name_glob: Option<String>,
    /// Glob against the tag/version/reference string. `NULL` matches any.
    pub version_glob: Option<String>,
    /// Exact-match scan verdict (`Verdict::as_str()`). `NULL` matches any.
    pub verdict: Option<String>,
    /// Exact-match heuristic check name (`RiskFinding.check`). `NULL`
    /// matches any (or, combined with `min_severity`, "any finding at or
    /// above this severity").
    pub risk_check: Option<String>,
    /// Minimum heuristic severity required for a match, when `risk_check`
    /// or a bare severity gate is configured. `NULL` means no severity
    /// floor.
    pub min_severity: Option<String>,
    /// Exact-match provenance disposition (`unsigned`/`verified`/`invalid`,
    /// P4 §5/§9/§10). `NULL` matches any.
    pub provenance: Option<String>,
    /// `allow`/`warn`/`block`/`quarantine`.
    pub action: String,
    /// Human-readable purpose.
    pub description: Option<String>,
    /// Disabled rules are never matched.
    pub enabled: bool,
    /// Row creation time.
    pub created_at: NaiveDateTime,
    /// Last update time.
    pub updated_at: NaiveDateTime,
    /// Subject claim of whoever created/last modified this rule.
    pub created_by: Option<String>,
}

/// Fields accepted from a policy-rule create/update request.
#[derive(Debug, Clone)]
pub struct PolicyRuleInput<'a> {
    /// Match priority.
    pub priority: i32,
    /// Ecosystem filter.
    pub ecosystem: Option<&'a str>,
    /// Name glob filter.
    pub name_glob: Option<&'a str>,
    /// Version glob filter.
    pub version_glob: Option<&'a str>,
    /// Verdict filter.
    pub verdict: Option<&'a str>,
    /// Risk-check filter.
    pub risk_check: Option<&'a str>,
    /// Minimum severity filter.
    pub min_severity: Option<&'a str>,
    /// Provenance filter (`unsigned`/`verified`/`invalid`).
    pub provenance: Option<&'a str>,
    /// Resulting action.
    pub action: &'a str,
    /// Human-readable purpose.
    pub description: Option<&'a str>,
    /// Whether this rule is active.
    pub enabled: bool,
    /// Subject claim of the caller.
    pub created_by: Option<&'a str>,
}

/// Creates a policy rule for `tenant_id`.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn insert_policy_rule(
    pool: &PgPool,
    tenant_id: Uuid,
    input: &PolicyRuleInput<'_>,
) -> Result<PolicyRuleRow, sqlx::Error> {
    sqlx::query_as::<_, PolicyRuleRow>(
        "INSERT INTO depgate_policy_rules \
            (id, tenant_id, priority, ecosystem, name_glob, version_glob, verdict, risk_check, \
             min_severity, provenance, action, description, enabled, created_at, updated_at, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, now(), now(), $14) \
         RETURNING id, tenant_id, priority, ecosystem, name_glob, version_glob, verdict, \
                   risk_check, min_severity, provenance, action, description, enabled, created_at, \
                   updated_at, created_by",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(input.priority)
    .bind(input.ecosystem)
    .bind(input.name_glob)
    .bind(input.version_glob)
    .bind(input.verdict)
    .bind(input.risk_check)
    .bind(input.min_severity)
    .bind(input.provenance)
    .bind(input.action)
    .bind(input.description)
    .bind(input.enabled)
    .bind(input.created_by)
    .fetch_one(pool)
    .await
}

/// Lists every policy rule for `tenant_id`, highest priority first — the
/// same order [`crate::policy::evaluate`] uses to pick a winner.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn list_policy_rules(
    pool: &PgPool,
    tenant_id: Uuid,
) -> Result<Vec<PolicyRuleRow>, sqlx::Error> {
    sqlx::query_as::<_, PolicyRuleRow>(
        "SELECT id, tenant_id, priority, ecosystem, name_glob, version_glob, verdict, \
                risk_check, min_severity, provenance, action, description, enabled, created_at, \
                updated_at, created_by \
         FROM depgate_policy_rules WHERE tenant_id = $1 ORDER BY priority DESC, created_at ASC",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await
}

/// Fetches one policy rule, tenant-scoped.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn get_policy_rule(
    pool: &PgPool,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<PolicyRuleRow>, sqlx::Error> {
    sqlx::query_as::<_, PolicyRuleRow>(
        "SELECT id, tenant_id, priority, ecosystem, name_glob, version_glob, verdict, \
                risk_check, min_severity, provenance, action, description, enabled, created_at, \
                updated_at, created_by \
         FROM depgate_policy_rules WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Replaces every mutable field of a policy rule, tenant-scoped.
/// `Ok(None)` when no such rule exists for this tenant.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn update_policy_rule(
    pool: &PgPool,
    tenant_id: Uuid,
    id: Uuid,
    input: &PolicyRuleInput<'_>,
) -> Result<Option<PolicyRuleRow>, sqlx::Error> {
    sqlx::query_as::<_, PolicyRuleRow>(
        "UPDATE depgate_policy_rules SET \
            priority = $1, ecosystem = $2, name_glob = $3, version_glob = $4, verdict = $5, \
            risk_check = $6, min_severity = $7, provenance = $8, action = $9, description = $10, \
            enabled = $11, updated_at = now(), created_by = COALESCE($12, created_by) \
         WHERE tenant_id = $13 AND id = $14 \
         RETURNING id, tenant_id, priority, ecosystem, name_glob, version_glob, verdict, \
                   risk_check, min_severity, provenance, action, description, enabled, created_at, \
                   updated_at, created_by",
    )
    .bind(input.priority)
    .bind(input.ecosystem)
    .bind(input.name_glob)
    .bind(input.version_glob)
    .bind(input.verdict)
    .bind(input.risk_check)
    .bind(input.min_severity)
    .bind(input.provenance)
    .bind(input.action)
    .bind(input.description)
    .bind(input.enabled)
    .bind(input.created_by)
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Deletes a policy rule, tenant-scoped. Returns whether a row was deleted.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn delete_policy_rule(
    pool: &PgPool,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query("DELETE FROM depgate_policy_rules WHERE tenant_id = $1 AND id = $2")
        .bind(tenant_id)
        .bind(id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

// -- Risk findings (§5) -------------------------------------------------

/// One `depgate_risk_findings` row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct RiskFindingRow {
    /// Primary key.
    pub id: Uuid,
    /// Content digest hex of the artifact this finding is about.
    pub sha256: String,
    /// Ecosystem discriminator.
    pub ecosystem: String,
    /// Package/repo name.
    pub name: String,
    /// Tag/version/reference string.
    pub reference: String,
    /// Stable check identifier.
    pub check_name: String,
    /// Severity of this hit.
    pub severity: String,
    /// Human-readable explanation.
    pub detail: String,
    /// Attribution tenant.
    pub tenant_id: Uuid,
    /// When this was recorded.
    pub created_at: NaiveDateTime,
}

/// Bulk-inserts `findings` for one ingested artifact. A no-op (no query
/// sent) when `findings` is empty.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn insert_risk_findings(
    pool: &PgPool,
    sha256: &str,
    ecosystem: &str,
    name: &str,
    reference: &str,
    tenant_id: Uuid,
    findings: &[crate::heuristics::RiskFinding],
) -> Result<(), sqlx::Error> {
    if findings.is_empty() {
        return Ok(());
    }
    let mut qb: QueryBuilder<Postgres> = QueryBuilder::new(
        "INSERT INTO depgate_risk_findings \
            (id, sha256, ecosystem, name, reference, check_name, severity, detail, tenant_id, created_at) ",
    );
    qb.push_values(findings, |mut b, f| {
        b.push_bind(Uuid::new_v4())
            .push_bind(sha256)
            .push_bind(ecosystem)
            .push_bind(name)
            .push_bind(reference)
            .push_bind(f.check.clone())
            .push_bind(f.severity.as_str())
            .push_bind(f.detail.clone())
            .push_bind(tenant_id)
            .push("now()");
    });
    qb.build().execute(pool).await?;
    Ok(())
}

/// Lists every recorded risk finding for `sha256`, tenant-scoped.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn list_risk_findings(
    pool: &PgPool,
    tenant_id: Uuid,
    sha256: &str,
) -> Result<Vec<RiskFindingRow>, sqlx::Error> {
    sqlx::query_as::<_, RiskFindingRow>(
        "SELECT id, sha256, ecosystem, name, reference, check_name, severity, detail, \
                tenant_id, created_at \
         FROM depgate_risk_findings WHERE tenant_id = $1 AND sha256 = $2 \
         ORDER BY created_at ASC",
    )
    .bind(tenant_id)
    .bind(sha256)
    .fetch_all(pool)
    .await
}

// -- Policy decisions audit trail (§6) -----------------------------------

/// Fields needed to record one policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyDecisionInsert<'a> {
    /// Content digest hex.
    pub sha256: &'a str,
    /// Ecosystem discriminator.
    pub ecosystem: &'a str,
    /// Package/repo name.
    pub name: &'a str,
    /// Tag/version/reference string.
    pub reference: &'a str,
    /// The scan verdict this decision was made against.
    pub verdict: &'a str,
    /// The resulting action.
    pub action: &'a str,
    /// The rule that matched, if any.
    pub matched_rule_id: Option<Uuid>,
    /// Human-readable "why".
    pub reason: &'a str,
    /// Provenance disposition this decision was made against
    /// (`crate::provenance::ProvenanceStatus::as_str()`, P4 §5/§9).
    pub provenance: &'a str,
    /// Attribution tenant.
    pub tenant_id: Uuid,
}

/// Records one policy decision — every ingest-time evaluation, regardless
/// of the resulting action (§6: "answerable: why was this package
/// blocked?").
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn insert_policy_decision(
    pool: &PgPool,
    d: &PolicyDecisionInsert<'_>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO depgate_policy_decisions \
            (id, sha256, ecosystem, name, reference, verdict, action, matched_rule_id, reason, provenance, tenant_id, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())",
    )
    .bind(Uuid::new_v4())
    .bind(d.sha256)
    .bind(d.ecosystem)
    .bind(d.name)
    .bind(d.reference)
    .bind(d.verdict)
    .bind(d.action)
    .bind(d.matched_rule_id)
    .bind(d.reason)
    .bind(d.provenance)
    .bind(d.tenant_id)
    .execute(pool)
    .await?;
    Ok(())
}

// -- Quarantine disposition lifecycle (§6) -------------------------------

/// Fetches one quarantine event by id, tenant-scoped.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn get_quarantine(
    pool: &PgPool,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<QuarantineRow>, sqlx::Error> {
    sqlx::query_as::<_, QuarantineRow>(
        "SELECT id, sha256, ecosystem, name, reference, reason, threat, disposition, \
                policy_rule_id, resolved_at, resolved_by, resolution_note, tenant_id, created_at \
         FROM depgate_quarantine WHERE tenant_id = $1 AND id = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

/// Updates a quarantine event's disposition, tenant-scoped. `Ok(None)` when
/// no such event exists for this tenant.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn update_quarantine_disposition(
    pool: &PgPool,
    tenant_id: Uuid,
    id: Uuid,
    disposition: &str,
    resolved_by: &str,
    resolution_note: Option<&str>,
) -> Result<Option<QuarantineRow>, sqlx::Error> {
    sqlx::query_as::<_, QuarantineRow>(
        "UPDATE depgate_quarantine SET \
            disposition = $1, resolved_at = now(), resolved_by = $2, resolution_note = $3 \
         WHERE tenant_id = $4 AND id = $5 \
         RETURNING id, sha256, ecosystem, name, reference, reason, threat, disposition, \
                   policy_rule_id, resolved_at, resolved_by, resolution_note, tenant_id, created_at",
    )
    .bind(disposition)
    .bind(resolved_by)
    .bind(resolution_note)
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(pool)
    .await
}

// -- Air-gap bundle import provenance (§6b) ------------------------------

/// Records one bundle import event.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn insert_bundle_import(
    pool: &PgPool,
    tenant_id: Uuid,
    bundle_name: &str,
    manifest_sha256: &str,
    signature_verified: bool,
    artifact_count: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO depgate_bundle_imports \
            (id, bundle_name, manifest_sha256, signature_verified, artifact_count, tenant_id, imported_at) \
         VALUES ($1, $2, $3, $4, $5, $6, now())",
    )
    .bind(Uuid::new_v4())
    .bind(bundle_name)
    .bind(manifest_sha256)
    .bind(signature_verified)
    .bind(artifact_count)
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(())
}

// -- Re-scan sweep support (§6) -------------------------------------------

/// Lists every artifact whose recorded `scanner_version` differs from
/// `current_version` — the re-scan sweep's candidate set
/// (`crate::rescan::sweep`). Deliberately unscoped by tenant: a re-scan is
/// a maintenance operation over the whole shared cache, not a per-tenant
/// report.
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn artifacts_with_stale_scanner_version(
    pool: &PgPool,
    current_version: &str,
) -> Result<Vec<ArtifactRow>, sqlx::Error> {
    sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, ecosystem, name, reference, sha256, upstream, content_type, size_bytes, \
                verdict, verdict_at, scanner_version, pinned, tenant_id, first_seen, last_seen \
         FROM depgate_artifacts WHERE scanner_version <> $1",
    )
    .bind(current_version)
    .fetch_all(pool)
    .await
}

/// Fleet-wide (every tenant) list of `verdict = clean` artifacts — the
/// candidate set for `crate::bundle::export_bundle`. Export is a
/// connected-side maintenance operation over the whole shared cache, not a
/// per-tenant report, same reachability posture as
/// [`verdict_counts_all_tenants`].
///
/// # Errors
/// Propagates any `sqlx::Error`.
pub async fn list_clean_artifacts_all_tenants(
    pool: &PgPool,
) -> Result<Vec<ArtifactRow>, sqlx::Error> {
    sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, ecosystem, name, reference, sha256, upstream, content_type, size_bytes, \
                verdict, verdict_at, scanner_version, pinned, tenant_id, first_seen, last_seen \
         FROM depgate_artifacts WHERE verdict = 'clean' ORDER BY ecosystem, name, reference",
    )
    .fetch_all(pool)
    .await
}

impl PolicyRuleRow {
    /// Converts this row into the pure `crate::policy::PolicyRule` shape
    /// `crate::policy::evaluate` operates on. `None` only if the DB somehow
    /// holds an `action`/`min_severity` value outside the `CHECK`-
    /// constrained set — defensive, should never happen; such a row is
    /// simply skipped (never matched) rather than panicking the ingest
    /// path over one malformed rule.
    #[must_use]
    pub fn into_policy_rule(self) -> Option<crate::policy::PolicyRule> {
        let action = self.action.parse().ok()?;
        let min_severity = match self.min_severity {
            Some(s) => Some(s.parse().ok()?),
            None => None,
        };
        Some(crate::policy::PolicyRule {
            id: self.id,
            priority: self.priority,
            ecosystem: self.ecosystem,
            name_glob: self.name_glob,
            version_glob: self.version_glob,
            verdict: self.verdict,
            risk_check: self.risk_check,
            min_severity,
            provenance: self.provenance,
            action,
            enabled: self.enabled,
        })
    }
}
