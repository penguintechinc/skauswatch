//! Database operations for CodeScan review worker using sqlx 0.9.
//!
//! Every function here takes the caller-validated `tenant_id` from
//! [`crate::message::CodeScanReviewTask`] and applies it as a hard `WHERE`/
//! bind boundary — SELECT/UPDATE filter on it, INSERT stamps it. A row that
//! exists but belongs to a different tenant is indistinguishable from a
//! missing row (see docs/v2-port/tenancy-model.md §4/§6): callers get a
//! generic "not found" rather than any signal the row exists elsewhere.

use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Update review status in the database. Scoped to `tenant_id`; a review
/// owned by a different tenant matches zero rows rather than erroring —
/// the caller (`handler::handle`) always re-validates via [`get_review`]
/// immediately after, which does surface the tenant mismatch as an error.
pub async fn update_review_status(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    status: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_reviews SET status = $1, updated_at = NOW() \
         WHERE id = $2 AND tenant_id = $3",
    )
    .bind(status)
    .bind(review_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Mark review as completed with summary. Scoped to `tenant_id`.
pub async fn complete_review(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    summary: &str,
    comments_count: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_reviews SET status = 'completed', summary = $1, \
         comments_count = $2, completed_at = NOW(), updated_at = NOW() \
         WHERE id = $3 AND tenant_id = $4",
    )
    .bind(summary)
    .bind(comments_count)
    .bind(review_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Mark review as failed. Scoped to `tenant_id`.
pub async fn mark_review_failed(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    error: &str,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_reviews SET status = 'failed', error_message = $1, \
         updated_at = NOW() WHERE id = $2 AND tenant_id = $3",
    )
    .bind(error)
    .bind(review_id)
    .bind(tenant_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Insert a review comment finding, stamped with `tenant_id` (the column is
/// `NOT NULL` since `0002_codescan_tenancy.sql` — never omit it).
pub async fn insert_review_comment(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    file_path: &str,
    line_number: i64,
    comment: &str,
    severity: &str,
) -> anyhow::Result<i64> {
    let result = sqlx::query(
        "INSERT INTO codescan_review_comments \
         (review_id, tenant_id, file_path, line_number, comment, severity, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, NOW()) RETURNING id",
    )
    .bind(review_id)
    .bind(tenant_id)
    .bind(file_path)
    .bind(line_number)
    .bind(comment)
    .bind(severity)
    .fetch_one(pool)
    .await?;

    Ok(result.get::<i64, _>(0))
}

/// Fetch review details from database, scoped to `tenant_id`. A review that
/// exists under a different tenant returns the same generic not-found error
/// as a nonexistent id — never leaks cross-tenant existence.
pub async fn get_review(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
) -> anyhow::Result<ReviewRecord> {
    let row = sqlx::query(
        "SELECT id, repo_config_id, status, ai_provider, ai_model, tenant_id \
         FROM codescan_reviews WHERE id = $1 AND tenant_id = $2",
    )
    .bind(review_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("review {} not found", review_id))?;

    Ok(ReviewRecord {
        _id: row.get(0),
        repo_config_id: row.get(1),
        _status: row.get(2),
        _ai_provider: row.get(3),
        _ai_model: row.get(4),
        _tenant_id: row.get(5),
    })
}

/// Fetch repository configuration, scoped to `tenant_id`.
pub async fn get_repo_config(
    pool: &PgPool,
    repo_config_id: i64,
    tenant_id: Uuid,
) -> anyhow::Result<RepoConfigRecord> {
    let row = sqlx::query(
        "SELECT id, tenant_id, provider, repo_url, repo_name, credential_id \
         FROM codescan_repo_configs WHERE id = $1 AND tenant_id = $2",
    )
    .bind(repo_config_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("repo config {} not found", repo_config_id))?;

    Ok(RepoConfigRecord {
        _id: row.get(0),
        _tenant_id: row.get(1),
        _provider: row.get(2),
        _repo_url: row.get(3),
        _repo_name: row.get(4),
        credential_id: row.get(5),
    })
}

/// A resolved `codescan_git_credentials` row — decryption happens in the
/// caller (`handler::CodeScanReviewHandler`), this layer only fetches the
/// ciphertext + metadata needed to decide whether the credential is usable.
#[derive(Debug, Clone)]
pub struct GitCredentialRecord {
    pub platform: String,
    pub credential_type: String,
    pub encrypted_token: Vec<u8>,
    pub is_active: bool,
    pub token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Fetch a git credential by id, scoped to `tenant_id` — mirrors
/// codescan-backend's own tenant-scoped lookups
/// (`services/codescan-backend/src/routes/credentials.rs`). A credential
/// owned by a different tenant is indistinguishable from a missing one.
pub async fn get_git_credential(
    pool: &PgPool,
    credential_id: i64,
    tenant_id: Uuid,
) -> anyhow::Result<GitCredentialRecord> {
    let row = sqlx::query(
        "SELECT platform, credential_type, encrypted_token, is_active, token_expires_at \
         FROM codescan_git_credentials WHERE id = $1 AND tenant_id = $2",
    )
    .bind(credential_id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| anyhow::anyhow!("git credential {} not found", credential_id))?;

    Ok(GitCredentialRecord {
        platform: row.get(0),
        credential_type: row.get(1),
        encrypted_token: row.get(2),
        is_active: row.get(3),
        token_expires_at: row.get(4),
    })
}

/// Records one AI provider call's approximate token usage/cost against a
/// review, stamped with `tenant_id` (`NOT NULL` since
/// `0002_codescan_tenancy.sql`). Non-fatal by design — callers log and
/// continue on error rather than failing the review over a cost-tracking
/// write (see `handler::CodeScanReviewHandler::execute_pipeline`).
#[allow(clippy::too_many_arguments)]
pub async fn insert_provider_usage(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    provider: &str,
    model: &str,
    prompt_tokens: i32,
    completion_tokens: i32,
    latency_ms: i64,
    cost_estimate: Option<f64>,
) -> anyhow::Result<i64> {
    let total_tokens = prompt_tokens + completion_tokens;
    let latency_ms_i32 = i32::try_from(latency_ms).unwrap_or(i32::MAX);
    let result = sqlx::query(
        "INSERT INTO codescan_provider_usage \
         (review_id, tenant_id, provider, model, prompt_tokens, completion_tokens, \
          total_tokens, latency_ms, cost_estimate, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW()) RETURNING id",
    )
    .bind(review_id)
    .bind(tenant_id)
    .bind(provider)
    .bind(model)
    .bind(prompt_tokens)
    .bind(completion_tokens)
    .bind(total_tokens)
    .bind(latency_ms_i32)
    .bind(cost_estimate)
    .fetch_one(pool)
    .await?;

    Ok(result.get::<i64, _>(0))
}

/// Records one language/framework detection for a review, stamped with
/// `tenant_id`. Non-fatal by design — see `insert_provider_usage`.
pub async fn insert_review_detection(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    detection_type: &str,
    name: &str,
    confidence: f64,
    file_count: i32,
) -> anyhow::Result<i64> {
    let result = sqlx::query(
        "INSERT INTO codescan_review_detections \
         (review_id, tenant_id, detection_type, name, confidence, file_count, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,NOW()) RETURNING id",
    )
    .bind(review_id)
    .bind(tenant_id)
    .bind(detection_type)
    .bind(name)
    .bind(confidence)
    .bind(file_count)
    .fetch_one(pool)
    .await?;

    Ok(result.get::<i64, _>(0))
}

/// A tenant-scoped `codescan_license_policies` row, keyed by license name.
#[derive(Debug, Clone)]
pub struct LicensePolicyRecord {
    pub policy: String,
    pub actions: Option<serde_json::Value>,
}

/// Looks up the policy configured for a given SPDX/free-text license name,
/// scoped to `tenant_id`. `None` means the tenant has not configured a
/// policy for this license — callers treat that as "no violation" (an
/// admin has to opt a license into review/blocking, see
/// `services/codescan-backend/src/routes/license_policies.rs`), not as an
/// implicit deny.
pub async fn get_license_policy(
    pool: &PgPool,
    tenant_id: Uuid,
    license_name: &str,
) -> anyhow::Result<Option<LicensePolicyRecord>> {
    let row = sqlx::query(
        "SELECT policy, actions FROM codescan_license_policies \
         WHERE tenant_id = $1 AND license_name = $2",
    )
    .bind(tenant_id)
    .bind(license_name)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| LicensePolicyRecord {
        policy: r.get(0),
        actions: r.get(1),
    }))
}

/// Records one detected dependency license for a review, stamped with
/// `tenant_id`. Non-fatal by design — see `insert_provider_usage`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_license_detection(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    package_name: &str,
    package_version: &str,
    license_name: Option<&str>,
    license_source: &str,
    file_path: &str,
    confidence: f64,
    policy_violation: bool,
) -> anyhow::Result<i64> {
    let result = sqlx::query(
        "INSERT INTO codescan_license_detections \
         (review_id, tenant_id, package_name, package_version, license_name, license_source, \
          file_path, confidence, policy_violation, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW()) RETURNING id",
    )
    .bind(review_id)
    .bind(tenant_id)
    .bind(package_name)
    .bind(package_version)
    .bind(license_name)
    .bind(license_source)
    .bind(file_path)
    .bind(confidence)
    .bind(policy_violation)
    .fetch_one(pool)
    .await?;

    Ok(result.get::<i64, _>(0))
}

/// Records a policy violation for a previously-inserted license detection,
/// stamped with `tenant_id`. Non-fatal by design — see
/// `insert_provider_usage`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_license_violation(
    pool: &PgPool,
    review_id: i64,
    tenant_id: Uuid,
    detection_id: i64,
    license_name: &str,
    package_name: &str,
    policy: &str,
    severity: &str,
    actions_taken: Option<&serde_json::Value>,
) -> anyhow::Result<i64> {
    let result = sqlx::query(
        "INSERT INTO codescan_license_violations \
         (review_id, tenant_id, detection_id, license_name, package_name, policy, severity, \
          actions_taken, status, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open',NOW()) RETURNING id",
    )
    .bind(review_id)
    .bind(tenant_id)
    .bind(detection_id)
    .bind(license_name)
    .bind(package_name)
    .bind(policy)
    .bind(severity)
    .bind(actions_taken)
    .fetch_one(pool)
    .await?;

    Ok(result.get::<i64, _>(0))
}

/// Review record from database.
#[derive(Debug, Clone)]
pub struct ReviewRecord {
    pub _id: i64,
    pub repo_config_id: i64,
    pub _status: String,
    pub _ai_provider: Option<String>,
    pub _ai_model: Option<String>,
    pub _tenant_id: Uuid,
}

/// Repo configuration record from database.
#[derive(Debug, Clone)]
pub struct RepoConfigRecord {
    pub _id: i64,
    pub _tenant_id: Uuid,
    pub _provider: String,
    pub _repo_url: String,
    pub _repo_name: String,
    /// FK into `codescan_git_credentials`, `NULL` when the repo has no
    /// per-repo credential configured — see
    /// `handler::CodeScanReviewHandler::resolve_git_credentials`.
    pub credential_id: Option<i64>,
}

// ── CodeScan Sentinel (docs/v2-port/v2.1-codescan-sentinel.md §9/§10) ─────
// findings/scan-run persistence + the `alerts` bridge. Additive alongside
// the AI-review functions above; see migrations/0004_codescan_sentinel_findings.sql.

/// Post-upsert state of one `codescan_findings` row, used by the caller
/// (`handler::CodeScanReviewHandler::handle_sentinel_scan`) to decide
/// whether to bridge an `alerts` row.
#[derive(Debug, Clone, Copy)]
pub struct UpsertedFinding {
    pub id: i64,
    /// `true` when this finding has never been alerted during its current
    /// open lifetime — brand new, or freshly reopened from `resolved` (the
    /// upsert clears `alerted_at` on reopen so it can alert again).
    pub needs_alert: bool,
}

/// Inserts or refreshes one `codescan_findings` row for the
/// `(tenant_id, repo_config_id, branch, package_name, advisory_id)` dedupe
/// key — only ever called with `kind` `"sca"` or `"cve"` (see callers in
/// `sentinel.rs`); tool-registry findings go through
/// [`upsert_tool_finding`]'s separate fingerprint-based key instead. A
/// previously `resolved` finding that reappears is reopened and its
/// `alerted_at` cleared — see migrations/0004's column doc comment. The
/// `WHERE kind IN ('sca', 'cve')` on the `ON CONFLICT` target matches
/// migrations/0005's partial index of the same predicate (which replaced
/// 0004's original table-wide constraint so it no longer collides with
/// tool-registry rows that share the same `package_name = ''`/
/// `advisory_id = ''` convention — see that migration's comment).
#[allow(clippy::too_many_arguments)]
pub async fn upsert_finding(
    pool: &PgPool,
    tenant_id: Uuid,
    repo_config_id: i64,
    branch: &str,
    kind: &str,
    ecosystem: &str,
    package_name: &str,
    current_version: &str,
    latest_version: Option<&str>,
    advisory_id: &str,
    severity: &str,
) -> anyhow::Result<UpsertedFinding> {
    let row = sqlx::query(
        "INSERT INTO codescan_findings \
         (tenant_id, repo_config_id, branch, kind, ecosystem, package_name, \
          current_version, latest_version, advisory_id, severity, status, \
          first_seen, last_seen, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'open',now(),now(),now(),now()) \
         ON CONFLICT (tenant_id, repo_config_id, branch, package_name, advisory_id) \
         WHERE kind IN ('sca', 'cve') \
         DO UPDATE SET \
           kind = EXCLUDED.kind, \
           latest_version = EXCLUDED.latest_version, \
           severity = EXCLUDED.severity, \
           last_seen = now(), \
           updated_at = now(), \
           status = 'open', \
           alerted_at = CASE WHEN codescan_findings.status = 'resolved' \
                              THEN NULL ELSE codescan_findings.alerted_at END \
         RETURNING id, alerted_at",
    )
    .bind(tenant_id)
    .bind(repo_config_id)
    .bind(branch)
    .bind(kind)
    .bind(ecosystem)
    .bind(package_name)
    .bind(current_version)
    .bind(latest_version)
    .bind(advisory_id)
    .bind(severity)
    .fetch_one(pool)
    .await?;

    let id: i64 = row.get(0);
    let alerted_at: Option<chrono::DateTime<chrono::Utc>> = row.get(1);
    Ok(UpsertedFinding {
        id,
        needs_alert: alerted_at.is_none(),
    })
}

/// Marks a finding as alerted — called immediately after the `alerts` row
/// bridge succeeds, so a later scan of the same still-open finding does not
/// alert again on every run.
pub async fn mark_finding_alerted(pool: &PgPool, finding_id: i64) -> anyhow::Result<()> {
    sqlx::query("UPDATE codescan_findings SET alerted_at = now() WHERE id = $1")
        .bind(finding_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Marks every currently-`open` finding for `(tenant_id, repo_config_id,
/// branch)` whose `kind` is in `kinds` and whose id is NOT in `seen_ids` as
/// `resolved` — the dependency/rule hit was either removed or is no longer
/// flagged. Called once per *kind group* that was actually scanned this run
/// (P1's manifest-based `["sca", "cve"]` scan and P2's tool-based
/// `["sast", "secret", "iac"]` scan are independent passes — see
/// `handler::CodeScanReviewHandler::scan_and_persist_branch`), mirroring
/// how Dependabot auto-closes alerts for fixed dependencies.
///
/// The `kinds` filter matters: if the tool-based tree fetch fails for a
/// branch this run (`tree_fetch::fetch_branch_tree` error — network hiccup,
/// oversized archive), the caller simply skips calling this for
/// `["sast", "secret", "iac"]` that run rather than passing an empty
/// `seen_ids`, which would otherwise resolve every real, still-open
/// tool finding purely because this run never got far enough to re-see them.
pub async fn resolve_stale_findings(
    pool: &PgPool,
    tenant_id: Uuid,
    repo_config_id: i64,
    branch: &str,
    kinds: &[&str],
    seen_ids: &[i64],
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_findings SET status = 'resolved', updated_at = now() \
         WHERE tenant_id = $1 AND repo_config_id = $2 AND branch = $3 \
           AND kind = ANY($4) AND status = 'open' AND NOT (id = ANY($5))",
    )
    .bind(tenant_id)
    .bind(repo_config_id)
    .bind(branch)
    .bind(kinds)
    .bind(seen_ids)
    .execute(pool)
    .await?;
    Ok(())
}

/// Starts a `codescan_scan_runs` row, returning its id for
/// [`finish_scan_run`].
pub async fn start_scan_run(
    pool: &PgPool,
    tenant_id: Uuid,
    repo_config_id: i64,
    branch: &str,
) -> anyhow::Result<i64> {
    let row = sqlx::query(
        "INSERT INTO codescan_scan_runs (tenant_id, repo_config_id, branch, status, started_at) \
         VALUES ($1, $2, $3, 'running', now()) RETURNING id",
    )
    .bind(tenant_id)
    .bind(repo_config_id)
    .bind(branch)
    .fetch_one(pool)
    .await?;
    Ok(row.get::<i64, _>(0))
}

/// Closes out a `codescan_scan_runs` row with its final status.
pub async fn finish_scan_run(
    pool: &PgPool,
    run_id: i64,
    status: &str,
    findings_count: i64,
    error: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_scan_runs SET status = $1, findings_count = $2, error = $3, \
         finished_at = now() WHERE id = $4",
    )
    .bind(status)
    .bind(findings_count)
    .bind(error)
    .bind(run_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Writes one alert row directly into manager's shared `alerts` table
/// (docs/v2-port/v2.1-codescan-sentinel.md §9/§12) — the same
/// shared-database, per-service-grant pattern as every other cross-table
/// write in this stack (see `scripts/db/init-codescan-db.sql`'s `codescan`
/// grant). Manager owns the table's schema and REST surface; this worker
/// only ever inserts, matching its INSERT-only grant — it never reads back
/// or mutates a row once written.
pub async fn insert_sentinel_alert(
    pool: &PgPool,
    tenant_id: Uuid,
    title: &str,
    description: &str,
    severity: &str,
    indicators: &serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO alerts (title, description, severity, status, source, indicators, \
          tenant_id, created_at, updated_at) \
         VALUES ($1, $2, $3, 'pending', 'codescan_sentinel', $4, $5, now(), now())",
    )
    .bind(title)
    .bind(description)
    .bind(severity)
    .bind(indicators)
    .bind(tenant_id)
    .execute(pool)
    .await?;
    Ok(())
}

// ── CodeScan Sentinel P2 tool registry (docs/v2-port/v2.1-codescan-sentinel.md
// §3/§9) — SAST/secret/IaC findings + SBOM artifacts, additive alongside the
// P1 SCA/CVE functions above; see migrations/0005_codescan_sentinel_tool_findings.sql.

/// Inserts or refreshes one `codescan_findings` row for a tool-produced
/// (`sast`/`secret`/`iac`) finding, deduped/upserted on
/// `finding.fingerprint()` via the partial unique index migrations/0005
/// added (`(tenant_id, repo_config_id, branch, kind, fingerprint) WHERE
/// fingerprint <> ''`) — entirely independent of 0004's original
/// `package_name`/`advisory_id` dedupe key, which continues to govern P1's
/// sca/cve rows unchanged. Same reopen/re-alert semantics as
/// [`upsert_finding`]: a previously `resolved` finding that reappears is
/// reopened and its `alerted_at` cleared.
pub async fn upsert_tool_finding(
    pool: &PgPool,
    tenant_id: Uuid,
    repo_config_id: i64,
    branch: &str,
    finding: &crate::scanner_tool::ToolFinding,
) -> anyhow::Result<UpsertedFinding> {
    let fingerprint = finding.fingerprint();
    let row = sqlx::query(
        "INSERT INTO codescan_findings \
         (tenant_id, repo_config_id, branch, kind, ecosystem, package_name, \
          current_version, tool, rule_id, severity, file_path, line, title, \
          fingerprint, status, first_seen, last_seen, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,'','','',$5,$6,$7,$8,$9,$10,$11,'open',now(),now(),now(),now()) \
         ON CONFLICT (tenant_id, repo_config_id, branch, kind, fingerprint) \
         WHERE fingerprint <> '' \
         DO UPDATE SET \
           tool = EXCLUDED.tool, \
           severity = EXCLUDED.severity, \
           file_path = EXCLUDED.file_path, \
           line = EXCLUDED.line, \
           title = EXCLUDED.title, \
           last_seen = now(), \
           updated_at = now(), \
           status = 'open', \
           alerted_at = CASE WHEN codescan_findings.status = 'resolved' \
                              THEN NULL ELSE codescan_findings.alerted_at END \
         RETURNING id, alerted_at",
    )
    .bind(tenant_id)
    .bind(repo_config_id)
    .bind(branch)
    .bind(finding.kind)
    .bind(finding.tool)
    .bind(&finding.rule_id)
    .bind(&finding.severity)
    .bind(&finding.file_path)
    .bind(finding.line)
    .bind(&finding.title)
    .bind(&fingerprint)
    .fetch_one(pool)
    .await?;

    let id: i64 = row.get(0);
    let alerted_at: Option<chrono::DateTime<chrono::Utc>> = row.get(1);
    Ok(UpsertedFinding {
        id,
        needs_alert: alerted_at.is_none(),
    })
}

/// Stores one gzip-compressed CycloneDX SBOM document for a scan run — one
/// row per `codescan_scan_runs.id` (see migrations/0005's `UNIQUE
/// (scan_run_id)`), read back by codescan-backend's
/// `GET /codescan/findings/sbom/{scan_run_id}`.
pub async fn insert_sbom_artifact(
    pool: &PgPool,
    tenant_id: Uuid,
    repo_config_id: i64,
    branch: &str,
    scan_run_id: i64,
    format: &str,
    doc_gzip: &[u8],
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO codescan_sbom_artifacts \
         (tenant_id, repo_config_id, branch, scan_run_id, format, doc_gzip, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, now()) \
         ON CONFLICT (scan_run_id) DO UPDATE SET \
           format = EXCLUDED.format, doc_gzip = EXCLUDED.doc_gzip",
    )
    .bind(tenant_id)
    .bind(repo_config_id)
    .bind(branch)
    .bind(scan_run_id)
    .bind(format)
    .bind(doc_gzip)
    .execute(pool)
    .await?;
    Ok(())
}

// ── CodeScan Sentinel P3 (docs/v2-port/v2.1-codescan-sentinel.md §4/§6) —
// AI reachability/exposure triage verdicts + the policy engine's rule store
// and audit trail. Additive alongside every function above; see
// migrations/0006_codescan_sentinel_triage_policy.sql. Enterprise-gated —
// see `handler::CodeScanReviewHandler`'s license-tier check, which decides
// whether any of this is ever called for a given scan.

/// One WaddleAI triage verdict to persist onto an already-upserted finding.
#[derive(Debug, Clone)]
pub struct AiVerdict {
    pub used: bool,
    pub reachable: bool,
    pub exposure: &'static str,
    pub ai_severity: Option<String>,
    pub ai_rationale: String,
}

/// Persists a WaddleAI triage verdict. **Ground truth preserved**: this
/// `UPDATE` only ever touches the additive `used`/`reachable`/`exposure`/
/// `ai_severity`/`ai_rationale`/`triaged_at`/`triage_source` columns — it
/// has no `severity =` or `status =` clause, so a triage verdict can
/// re-rank severity (via `ai_severity`, a separate column) but can never
/// erase or downgrade the original scanner/CVE finding (spec §4: "tool
/// finding = ground truth (AI re-ranks, can't erase a scanner hit)"). See
/// `tests::upsert_ai_verdict_never_touches_the_original_severity_or_status`.
pub async fn upsert_ai_verdict(
    pool: &PgPool,
    finding_id: i64,
    verdict: &AiVerdict,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_findings SET \
           used = $1, reachable = $2, exposure = $3, ai_severity = $4, ai_rationale = $5, \
           triaged_at = now(), triage_source = 'waddleai' \
         WHERE id = $6",
    )
    .bind(verdict.used)
    .bind(verdict.reachable)
    .bind(verdict.exposure)
    .bind(&verdict.ai_severity)
    .bind(&verdict.ai_rationale)
    .bind(finding_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Records the static prefilter's own "not used" determination when it
/// alone proved a package unused and the scan short-circuited before any AI
/// spend (spec §5 point 1) — so `used`/`triage_source` reflect *some*
/// determination even when WaddleAI was never called for this finding.
/// Never called with `used = true` (a "used" verdict always proceeds to
/// full AI triage, see `handler::CodeScanReviewHandler`); the parameter
/// exists so the one call site reads naturally either way.
pub async fn upsert_prefilter_verdict(
    pool: &PgPool,
    finding_id: i64,
    used: bool,
) -> anyhow::Result<()> {
    sqlx::query(
        "UPDATE codescan_findings SET used = $1, triaged_at = now(), triage_source = 'prefilter' \
         WHERE id = $2",
    )
    .bind(used)
    .bind(finding_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Applies one policy-engine decision to a finding and writes its audit
/// row in the same call — always both together, per
/// `crate::policy::Decision`'s "always audit-logged" contract.
pub async fn apply_policy_decision(
    pool: &PgPool,
    tenant_id: Uuid,
    finding_id: i64,
    decision: &crate::policy::Decision,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE codescan_findings SET action = $1 WHERE id = $2")
        .bind(&decision.action)
        .bind(finding_id)
        .execute(pool)
        .await?;
    sqlx::query(
        "INSERT INTO codescan_policy_decisions \
         (tenant_id, finding_id, rule_id, action, reason, decided_at) \
         VALUES ($1, $2, $3, $4, $5, now())",
    )
    .bind(tenant_id)
    .bind(finding_id)
    .bind(decision.matched_rule_id)
    .bind(&decision.action)
    .bind(&decision.reason)
    .execute(pool)
    .await?;
    Ok(())
}

/// Loads every configured policy rule for `tenant_id`, for
/// `crate::policy::evaluate` (which re-sorts by priority itself, so
/// row order here is irrelevant).
pub async fn list_policy_rules(
    pool: &PgPool,
    tenant_id: Uuid,
) -> anyhow::Result<Vec<crate::policy::PolicyRule>> {
    let rows = sqlx::query(
        "SELECT id, priority, repo, ecosystem, package, cve, severity, reachability, exposure, \
                tool, kind, action \
         FROM codescan_policy_rules WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| crate::policy::PolicyRule {
            id: r.get(0),
            priority: r.get(1),
            repo: r.get(2),
            ecosystem: r.get(3),
            package: r.get(4),
            cve: r.get(5),
            severity: r.get(6),
            reachability: r.get(7),
            exposure: r.get(8),
            tool: r.get(9),
            kind: r.get(10),
            action: r.get(11),
        })
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Bootstrap tenant literal — matches manager's
    /// `crate::auth::DEFAULT_TENANT_ID` / codescan-backend's migration seed
    /// (see docs/v2-port/tenancy-model.md §8).
    const TEST_TENANT_ID: &str = "00000000-0000-0000-0000-000000000001";
    /// A second, distinct tenant used only to prove cross-tenant isolation —
    /// mirrors codescan-backend's own `TEST_TENANT_ID` convention of a
    /// `..aa`/`..bb`-style literal reserved for tests.
    const OTHER_TENANT_ID: &str = "00000000-0000-0000-0000-0000000000bb";

    fn test_tenant() -> Uuid {
        TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("test tenant uuid: {e}"))
    }

    fn other_tenant() -> Uuid {
        OTHER_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("other tenant uuid: {e}"))
    }

    /// These three tables (`codescan_repo_configs`, `codescan_reviews`,
    /// `codescan_review_comments`) are OWNED by codescan-backend; this
    /// worker only consumes them (see
    /// services/codescan-backend/migrations/0001_codescan_schema.sql header
    /// comment). worker-codescan ships no migrations of its own, so tests
    /// point the shared harness at codescan-backend's migrations dir.
    async fn test_pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../codescan-backend/migrations"
        ))
        .await
    }

    async fn seed_repo_config(pool: &PgPool) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(test_tenant())
        .bind("github")
        .bind("https://github.com/acme/widgets")
        .bind("acme/widgets")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo config: {e}"));
        row.get::<i64, _>(0)
    }

    async fn seed_review(pool: &PgPool, repo_config_id: i64) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_reviews \
             (repo_config_id, tenant_id, status, ai_provider, ai_model) \
             VALUES ($1, $2, 'queued', $3, $4) RETURNING id",
        )
        .bind(repo_config_id)
        .bind(test_tenant())
        .bind("ollama")
        .bind("test-model")
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed review: {e}"));
        row.get::<i64, _>(0)
    }

    #[tokio::test]
    async fn update_review_status_changes_status() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        update_review_status(&pool, review, test_tenant(), "processing")
            .await
            .unwrap_or_else(|e| panic!("update status: {e}"));

        let row = sqlx::query("SELECT status FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "processing");
    }

    #[tokio::test]
    async fn update_review_status_does_not_touch_a_different_tenants_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        // Same review id, wrong tenant: must match zero rows.
        update_review_status(&pool, review, other_tenant(), "processing")
            .await
            .unwrap_or_else(|e| panic!("update status: {e}"));

        let row = sqlx::query("SELECT status FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(
            row.get::<String, _>(0),
            "queued",
            "a cross-tenant update must never mutate another tenant's row"
        );
    }

    #[tokio::test]
    async fn complete_review_sets_summary_and_comment_count() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        complete_review(&pool, review, test_tenant(), "all clear", 3)
            .await
            .unwrap_or_else(|e| panic!("complete review: {e}"));

        let row = sqlx::query(
            "SELECT status, summary, comments_count, completed_at FROM codescan_reviews WHERE id = $1",
        )
        .bind(review)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "completed");
        assert_eq!(row.get::<String, _>(1), "all clear");
        assert_eq!(row.get::<i32, _>(2), 3);
        assert!(
            row.get::<Option<chrono::DateTime<chrono::Utc>>, _>(3)
                .is_some()
        );
    }

    #[tokio::test]
    async fn complete_review_does_not_touch_a_different_tenants_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        complete_review(&pool, review, other_tenant(), "all clear", 3)
            .await
            .unwrap_or_else(|e| panic!("complete review: {e}"));

        let row = sqlx::query("SELECT status FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "queued");
    }

    #[tokio::test]
    async fn mark_review_failed_sets_error_message() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        mark_review_failed(&pool, review, test_tenant(), "boom")
            .await
            .unwrap_or_else(|e| panic!("mark failed: {e}"));

        let row = sqlx::query("SELECT status, error_message FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "failed");
        assert_eq!(row.get::<String, _>(1), "boom");
    }

    #[tokio::test]
    async fn mark_review_failed_does_not_touch_a_different_tenants_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        mark_review_failed(&pool, review, other_tenant(), "boom")
            .await
            .unwrap_or_else(|e| panic!("mark failed: {e}"));

        let row = sqlx::query("SELECT status FROM codescan_reviews WHERE id = $1")
            .bind(review)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "queued");
    }

    #[tokio::test]
    async fn insert_review_comment_persists_a_finding_stamped_with_tenant() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        let comment_id = insert_review_comment(
            &pool,
            review,
            test_tenant(),
            "src/main.rs",
            42,
            "**Title**\n\nBody text",
            "critical",
        )
        .await
        .unwrap_or_else(|e| panic!("insert comment: {e}"));
        assert!(comment_id > 0);

        let row = sqlx::query(
            "SELECT file_path, line_number, comment, severity, tenant_id \
             FROM codescan_review_comments WHERE id = $1",
        )
        .bind(comment_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "src/main.rs");
        assert_eq!(row.get::<i32, _>(1), 42);
        assert_eq!(row.get::<String, _>(2), "**Title**\n\nBody text");
        assert_eq!(row.get::<String, _>(3), "critical");
        assert_eq!(row.get::<Uuid, _>(4), test_tenant());
    }

    #[tokio::test]
    async fn get_review_returns_the_seeded_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        let record = get_review(&pool, review, test_tenant())
            .await
            .unwrap_or_else(|e| panic!("get review: {e}"));
        assert_eq!(record._id, review);
        assert_eq!(record.repo_config_id, repo);
        assert_eq!(record._status, "queued");
        assert_eq!(record._ai_provider.as_deref(), Some("ollama"));
        assert_eq!(record._ai_model.as_deref(), Some("test-model"));
        assert_eq!(record._tenant_id, test_tenant());
    }

    #[tokio::test]
    async fn get_review_errors_when_missing() {
        let pool = test_pool().await;
        let result = get_review(&pool, 999_999_999, test_tenant()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_review_is_not_found_for_a_different_tenant() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        let result = get_review(&pool, review, other_tenant()).await;
        assert!(
            result.is_err(),
            "a review owned by another tenant must not be visible"
        );
    }

    #[tokio::test]
    async fn get_repo_config_returns_the_seeded_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let record = get_repo_config(&pool, repo, test_tenant())
            .await
            .unwrap_or_else(|e| panic!("get repo config: {e}"));
        assert_eq!(record._id, repo);
        assert_eq!(record._tenant_id, test_tenant());
        assert_eq!(record._provider, "github");
        assert_eq!(record._repo_url, "https://github.com/acme/widgets");
        assert_eq!(record._repo_name, "acme/widgets");
        assert_eq!(record.credential_id, None);
    }

    #[tokio::test]
    async fn get_repo_config_errors_when_missing() {
        let pool = test_pool().await;
        let result = get_repo_config(&pool, 999_999_999, test_tenant()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_repo_config_is_not_found_for_a_different_tenant() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let result = get_repo_config(&pool, repo, other_tenant()).await;
        assert!(
            result.is_err(),
            "a repo config owned by another tenant must not be visible"
        );
    }

    async fn seed_git_credential(pool: &PgPool, tenant: Uuid, platform: &str) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_git_credentials \
             (user_id, tenant_id, platform, credential_type, encrypted_token, is_active) \
             VALUES (1, $1, $2, 'token', $3, true) RETURNING id",
        )
        .bind(tenant)
        .bind(platform)
        .bind(b"fake-ciphertext".as_slice())
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed git credential: {e}"));
        row.get::<i64, _>(0)
    }

    #[tokio::test]
    async fn get_repo_config_includes_credential_id_when_set() {
        let pool = test_pool().await;
        let credential = seed_git_credential(&pool, test_tenant(), "github").await;
        let row = sqlx::query(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name, credential_id) \
             VALUES ($1, 'github', 'https://github.com/acme/widgets', 'acme/widgets', $2) RETURNING id",
        )
        .bind(test_tenant())
        .bind(credential)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo config: {e}"));
        let repo: i64 = row.get(0);

        let record = get_repo_config(&pool, repo, test_tenant())
            .await
            .unwrap_or_else(|e| panic!("get repo config: {e}"));
        assert_eq!(record.credential_id, Some(credential));
    }

    #[tokio::test]
    async fn get_git_credential_returns_the_seeded_row() {
        let pool = test_pool().await;
        let credential = seed_git_credential(&pool, test_tenant(), "gitlab").await;

        let record = get_git_credential(&pool, credential, test_tenant())
            .await
            .unwrap_or_else(|e| panic!("get git credential: {e}"));
        assert_eq!(record.platform, "gitlab");
        assert_eq!(record.credential_type, "token");
        assert!(record.is_active);
        assert_eq!(record.token_expires_at, None);
    }

    #[tokio::test]
    async fn get_git_credential_errors_when_missing() {
        let pool = test_pool().await;
        let result = get_git_credential(&pool, 999_999_999, test_tenant()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_git_credential_is_not_found_for_a_different_tenant() {
        let pool = test_pool().await;
        let credential = seed_git_credential(&pool, test_tenant(), "github").await;

        let result = get_git_credential(&pool, credential, other_tenant()).await;
        assert!(
            result.is_err(),
            "a credential owned by another tenant must not be visible"
        );
    }

    #[tokio::test]
    async fn insert_provider_usage_persists_a_row_stamped_with_tenant() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        let id = insert_provider_usage(
            &pool,
            review,
            test_tenant(),
            "anthropic",
            "claude-opus-4-5",
            100,
            50,
            1234,
            Some(0.0021),
        )
        .await
        .unwrap_or_else(|e| panic!("insert provider usage: {e}"));
        assert!(id > 0);

        let row = sqlx::query(
            "SELECT provider, model, prompt_tokens, completion_tokens, total_tokens, \
             latency_ms, cost_estimate, tenant_id FROM codescan_provider_usage WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "anthropic");
        assert_eq!(row.get::<String, _>(1), "claude-opus-4-5");
        assert_eq!(row.get::<i32, _>(2), 100);
        assert_eq!(row.get::<i32, _>(3), 50);
        assert_eq!(row.get::<i32, _>(4), 150);
        assert_eq!(row.get::<i32, _>(5), 1234);
        assert_eq!(row.get::<Option<f64>, _>(6), Some(0.0021));
        assert_eq!(row.get::<Uuid, _>(7), test_tenant());
    }

    #[tokio::test]
    async fn insert_review_detection_persists_a_row_stamped_with_tenant() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        let id = insert_review_detection(&pool, review, test_tenant(), "language", "Rust", 0.75, 3)
            .await
            .unwrap_or_else(|e| panic!("insert review detection: {e}"));
        assert!(id > 0);

        let row = sqlx::query(
            "SELECT detection_type, name, confidence, file_count, tenant_id \
             FROM codescan_review_detections WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "language");
        assert_eq!(row.get::<String, _>(1), "Rust");
        assert!((row.get::<f64, _>(2) - 0.75).abs() < f64::EPSILON);
        assert_eq!(row.get::<i32, _>(3), 3);
        assert_eq!(row.get::<Uuid, _>(4), test_tenant());
    }

    async fn seed_license_policy(pool: &PgPool, tenant: Uuid, license_name: &str, policy: &str) {
        sqlx::query(
            "INSERT INTO codescan_license_policies (tenant_id, license_name, policy) \
             VALUES ($1, $2, $3)",
        )
        .bind(tenant)
        .bind(license_name)
        .bind(policy)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed license policy: {e}"));
    }

    #[tokio::test]
    async fn get_license_policy_returns_none_when_unconfigured() {
        let pool = test_pool().await;
        let result = get_license_policy(&pool, test_tenant(), "GPL-3.0")
            .await
            .unwrap_or_else(|e| panic!("get license policy: {e}"));
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn get_license_policy_returns_a_configured_policy() {
        let pool = test_pool().await;
        seed_license_policy(&pool, test_tenant(), "GPL-3.0", "blocked").await;

        let result = get_license_policy(&pool, test_tenant(), "GPL-3.0")
            .await
            .unwrap_or_else(|e| panic!("get license policy: {e}"));
        let policy = result.unwrap_or_else(|| panic!("expected Some(policy)"));
        assert_eq!(policy.policy, "blocked");
    }

    #[tokio::test]
    async fn get_license_policy_is_tenant_scoped() {
        let pool = test_pool().await;
        seed_license_policy(&pool, other_tenant(), "GPL-3.0", "blocked").await;

        let result = get_license_policy(&pool, test_tenant(), "GPL-3.0")
            .await
            .unwrap_or_else(|e| panic!("get license policy: {e}"));
        assert!(
            result.is_none(),
            "a different tenant's policy row must not be visible"
        );
    }

    #[tokio::test]
    async fn insert_license_detection_and_violation_round_trip() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let review = seed_review(&pool, repo).await;

        let detection_id = insert_license_detection(
            &pool,
            review,
            test_tenant(),
            "left-pad",
            "1.3.0",
            Some("GPL-3.0"),
            "npm_registry",
            "package.json",
            0.9,
            true,
        )
        .await
        .unwrap_or_else(|e| panic!("insert license detection: {e}"));
        assert!(detection_id > 0);

        let violation_id = insert_license_violation(
            &pool,
            review,
            test_tenant(),
            detection_id,
            "GPL-3.0",
            "left-pad",
            "blocked",
            "critical",
            Some(&serde_json::json!(["block_merge"])),
        )
        .await
        .unwrap_or_else(|e| panic!("insert license violation: {e}"));
        assert!(violation_id > 0);

        let row = sqlx::query(
            "SELECT detection_id, license_name, package_name, policy, severity, status, tenant_id \
             FROM codescan_license_violations WHERE id = $1",
        )
        .bind(violation_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<i64, _>(0), detection_id);
        assert_eq!(row.get::<String, _>(1), "GPL-3.0");
        assert_eq!(row.get::<String, _>(2), "left-pad");
        assert_eq!(row.get::<String, _>(3), "blocked");
        assert_eq!(row.get::<String, _>(4), "critical");
        assert_eq!(row.get::<String, _>(5), "open");
        assert_eq!(row.get::<Uuid, _>(6), test_tenant());
    }

    // ── Sentinel: findings / scan runs / alerts bridge ────────────────────

    #[tokio::test]
    async fn upsert_finding_inserts_a_new_open_row_needing_alert() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let result = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "cve",
            "npm",
            "left-pad",
            "1.0.0",
            Some("1.3.0"),
            "GHSA-aaaa",
            "high",
        )
        .await
        .unwrap_or_else(|e| panic!("upsert: {e}"));
        assert!(result.id > 0);
        assert!(result.needs_alert, "a brand new finding must need an alert");

        let row = sqlx::query(
            "SELECT status, severity, latest_version FROM codescan_findings WHERE id = $1",
        )
        .bind(result.id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "open");
        assert_eq!(row.get::<String, _>(1), "high");
        assert_eq!(row.get::<Option<String>, _>(2).as_deref(), Some("1.3.0"));
    }

    #[tokio::test]
    async fn upsert_finding_is_idempotent_on_the_dedupe_key_and_does_not_re_alert() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let first = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "cve",
            "npm",
            "left-pad",
            "1.0.0",
            Some("1.3.0"),
            "GHSA-aaaa",
            "high",
        )
        .await
        .unwrap_or_else(|e| panic!("first upsert: {e}"));
        mark_finding_alerted(&pool, first.id)
            .await
            .unwrap_or_else(|e| panic!("mark alerted: {e}"));

        let second = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "cve",
            "npm",
            "left-pad",
            "1.0.0",
            Some("1.4.0"),
            "GHSA-aaaa",
            "critical",
        )
        .await
        .unwrap_or_else(|e| panic!("second upsert: {e}"));

        assert_eq!(
            second.id, first.id,
            "same dedupe key must update, not duplicate"
        );
        assert!(
            !second.needs_alert,
            "a finding already alerted this lifetime must not re-alert on every scan"
        );

        let row =
            sqlx::query("SELECT severity, latest_version FROM codescan_findings WHERE id = $1")
                .bind(first.id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "critical");
        assert_eq!(row.get::<Option<String>, _>(1).as_deref(), Some("1.4.0"));
    }

    #[tokio::test]
    async fn upsert_finding_reopens_a_resolved_finding_and_allows_re_alerting() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let first = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "cve",
            "npm",
            "left-pad",
            "1.0.0",
            Some("1.3.0"),
            "GHSA-aaaa",
            "high",
        )
        .await
        .unwrap_or_else(|e| panic!("upsert: {e}"));
        mark_finding_alerted(&pool, first.id)
            .await
            .unwrap_or_else(|e| panic!("mark alerted: {e}"));
        resolve_stale_findings(&pool, test_tenant(), repo, "main", &["sca", "cve"], &[])
            .await
            .unwrap_or_else(|e| panic!("resolve stale: {e}"));

        let row = sqlx::query("SELECT status FROM codescan_findings WHERE id = $1")
            .bind(first.id)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "resolved");

        let reopened = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "cve",
            "npm",
            "left-pad",
            "1.0.0",
            Some("1.5.0"),
            "GHSA-aaaa",
            "high",
        )
        .await
        .unwrap_or_else(|e| panic!("reopen upsert: {e}"));
        assert_eq!(reopened.id, first.id);
        assert!(
            reopened.needs_alert,
            "a reopened finding must be able to alert again"
        );
    }

    #[tokio::test]
    async fn resolve_stale_findings_only_touches_findings_missing_from_seen_ids() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let stale = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "sca",
            "npm",
            "stale-pkg",
            "1.0.0",
            Some("1.0.0"),
            "",
            "low",
        )
        .await
        .unwrap_or_else(|e| panic!("upsert stale: {e}"));
        let kept = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "sca",
            "npm",
            "kept-pkg",
            "1.0.0",
            Some("2.0.0"),
            "",
            "low",
        )
        .await
        .unwrap_or_else(|e| panic!("upsert kept: {e}"));

        resolve_stale_findings(
            &pool,
            test_tenant(),
            repo,
            "main",
            &["sca", "cve"],
            &[kept.id],
        )
        .await
        .unwrap_or_else(|e| panic!("resolve stale: {e}"));

        let stale_status: String =
            sqlx::query_scalar("SELECT status FROM codescan_findings WHERE id = $1")
                .bind(stale.id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("select stale: {e}"));
        let kept_status: String =
            sqlx::query_scalar("SELECT status FROM codescan_findings WHERE id = $1")
                .bind(kept.id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("select kept: {e}"));
        assert_eq!(stale_status, "resolved");
        assert_eq!(kept_status, "open");
    }

    #[tokio::test]
    async fn resolve_stale_findings_does_not_touch_a_different_tenants_or_branchs_rows() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let same_branch = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "sca",
            "npm",
            "pkg-a",
            "1.0.0",
            Some("1.0.0"),
            "",
            "low",
        )
        .await
        .unwrap_or_else(|e| panic!("upsert: {e}"));
        let other_branch = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "release/v1.0.x",
            "sca",
            "npm",
            "pkg-b",
            "1.0.0",
            Some("1.0.0"),
            "",
            "low",
        )
        .await
        .unwrap_or_else(|e| panic!("upsert other branch: {e}"));

        resolve_stale_findings(&pool, test_tenant(), repo, "main", &["sca", "cve"], &[])
            .await
            .unwrap_or_else(|e| panic!("resolve stale: {e}"));

        let same_branch_status: String =
            sqlx::query_scalar("SELECT status FROM codescan_findings WHERE id = $1")
                .bind(same_branch.id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("select: {e}"));
        let other_branch_status: String =
            sqlx::query_scalar("SELECT status FROM codescan_findings WHERE id = $1")
                .bind(other_branch.id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(same_branch_status, "resolved");
        assert_eq!(
            other_branch_status, "open",
            "resolving one branch's stale findings must never touch another branch's rows"
        );
    }

    #[tokio::test]
    async fn start_and_finish_scan_run_round_trip() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let run_id = start_scan_run(&pool, test_tenant(), repo, "main")
            .await
            .unwrap_or_else(|e| panic!("start: {e}"));
        assert!(run_id > 0);

        finish_scan_run(&pool, run_id, "completed", 3, None)
            .await
            .unwrap_or_else(|e| panic!("finish: {e}"));

        let row = sqlx::query(
            "SELECT status, findings_count, error, finished_at FROM codescan_scan_runs \
             WHERE id = $1",
        )
        .bind(run_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "completed");
        assert_eq!(row.get::<i32, _>(1), 3);
        assert_eq!(row.get::<Option<String>, _>(2), None);
        assert!(
            row.get::<Option<chrono::DateTime<chrono::Utc>>, _>(3)
                .is_some()
        );
    }

    #[tokio::test]
    async fn finish_scan_run_records_an_error_on_failure() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let run_id = start_scan_run(&pool, test_tenant(), repo, "main")
            .await
            .unwrap_or_else(|e| panic!("start: {e}"));

        finish_scan_run(&pool, run_id, "failed", 0, Some("git provider unreachable"))
            .await
            .unwrap_or_else(|e| panic!("finish: {e}"));

        let row = sqlx::query("SELECT status, error FROM codescan_scan_runs WHERE id = $1")
            .bind(run_id)
            .fetch_one(&pool)
            .await
            .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "failed");
        assert_eq!(
            row.get::<Option<String>, _>(1).as_deref(),
            Some("git provider unreachable")
        );
    }

    /// Mirrors manager's `alerts` table shape closely enough to exercise
    /// `insert_sentinel_alert`'s real INSERT statement, without pulling in
    /// manager's own (concurrently-evolving) migrations — this worker's
    /// tests only ever need to prove the INSERT is well-formed and scoped
    /// correctly, not manager's full schema.
    async fn seed_alerts_fixture_table(pool: &PgPool) {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alerts ( \
                id SERIAL PRIMARY KEY, \
                title VARCHAR(255) NOT NULL, \
                description TEXT, \
                severity VARCHAR(20) NOT NULL, \
                status VARCHAR(20) DEFAULT 'pending', \
                source VARCHAR(100), \
                indicators JSONB, \
                tenant_id UUID NOT NULL, \
                created_at TIMESTAMPTZ DEFAULT now(), \
                updated_at TIMESTAMPTZ \
            )",
        )
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("create alerts fixture table: {e}"));
    }

    #[tokio::test]
    async fn insert_sentinel_alert_writes_a_tenant_scoped_row() {
        let pool = test_pool().await;
        seed_alerts_fixture_table(&pool).await;

        insert_sentinel_alert(
            &pool,
            test_tenant(),
            "Critical CVE in left-pad",
            "GHSA-aaaa affecting left-pad@1.0.0 on acme/widgets:main",
            "critical",
            &serde_json::json!(["left-pad", "GHSA-aaaa"]),
        )
        .await
        .unwrap_or_else(|e| panic!("insert alert: {e}"));

        let row = sqlx::query(
            "SELECT title, severity, status, source, tenant_id FROM alerts WHERE title = $1",
        )
        .bind("Critical CVE in left-pad")
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "Critical CVE in left-pad");
        assert_eq!(row.get::<String, _>(1), "critical");
        assert_eq!(row.get::<String, _>(2), "pending");
        assert_eq!(row.get::<String, _>(3), "codescan_sentinel");
        assert_eq!(row.get::<Uuid, _>(4), test_tenant());
    }

    // ── CodeScan Sentinel P2 tool registry ─────────────────────────────────

    fn test_tool_finding(
        rule_id: &str,
        file_path: &str,
        line: i32,
    ) -> crate::scanner_tool::ToolFinding {
        crate::scanner_tool::ToolFinding {
            kind: "sast",
            tool: "semgrep",
            rule_id: rule_id.to_owned(),
            severity: "high".to_owned(),
            file_path: Some(file_path.to_owned()),
            line: Some(line),
            title: "Hardcoded secret".to_owned(),
        }
    }

    #[tokio::test]
    async fn upsert_tool_finding_inserts_a_new_open_row_needing_alert() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let finding = test_tool_finding("rule-a", "app.py", 10);

        let result = upsert_tool_finding(&pool, test_tenant(), repo, "main", &finding)
            .await
            .unwrap_or_else(|e| panic!("upsert: {e}"));
        assert!(result.needs_alert);

        let row = sqlx::query(
            "SELECT kind, tool, rule_id, severity, file_path, line, title, status, fingerprint \
             FROM codescan_findings WHERE id = $1",
        )
        .bind(result.id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<String, _>(0), "sast");
        assert_eq!(row.get::<String, _>(1), "semgrep");
        assert_eq!(row.get::<String, _>(2), "rule-a");
        assert_eq!(row.get::<String, _>(3), "high");
        assert_eq!(row.get::<Option<String>, _>(4).as_deref(), Some("app.py"));
        assert_eq!(row.get::<Option<i32>, _>(5), Some(10));
        assert_eq!(row.get::<String, _>(6), "Hardcoded secret");
        assert_eq!(row.get::<String, _>(7), "open");
        assert_eq!(row.get::<String, _>(8), finding.fingerprint());
    }

    #[tokio::test]
    async fn upsert_tool_finding_is_idempotent_on_the_fingerprint_and_does_not_re_alert() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let finding = test_tool_finding("rule-a", "app.py", 10);

        let first = upsert_tool_finding(&pool, test_tenant(), repo, "main", &finding)
            .await
            .unwrap_or_else(|e| panic!("first upsert: {e}"));
        mark_finding_alerted(&pool, first.id)
            .await
            .unwrap_or_else(|e| panic!("mark alerted: {e}"));

        let second = upsert_tool_finding(&pool, test_tenant(), repo, "main", &finding)
            .await
            .unwrap_or_else(|e| panic!("second upsert: {e}"));
        assert_eq!(
            second.id, first.id,
            "same fingerprint must update, not duplicate"
        );
        assert!(
            !second.needs_alert,
            "an already-alerted, still-open finding must not need re-alerting"
        );

        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM codescan_findings WHERE repo_config_id = $1 AND kind = 'sast'",
        )
        .bind(repo)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("count: {e}"));
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn upsert_tool_finding_never_collides_with_a_p1_sca_cve_row_in_the_same_branch() {
        // Both dedupe keys are scoped by kind and are otherwise disjoint
        // (package_name/advisory_id for sca/cve, fingerprint for
        // sast/secret/iac) — this proves inserting both kinds in the same
        // (tenant, repo, branch) never trips the other kind's unique index.
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "sca",
            "npm",
            "left-pad",
            "1.0.0",
            Some("1.3.0"),
            "",
            "low",
        )
        .await
        .unwrap_or_else(|e| panic!("upsert sca: {e}"));

        let tool_result = upsert_tool_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            &test_tool_finding("rule-a", "app.py", 10),
        )
        .await
        .unwrap_or_else(|e| panic!("upsert tool finding: {e}"));
        assert!(tool_result.id > 0);
    }

    #[tokio::test]
    async fn resolve_stale_findings_only_resolves_the_requested_kinds() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;

        let sca = upsert_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            "sca",
            "npm",
            "left-pad",
            "1.0.0",
            Some("1.0.0"),
            "",
            "low",
        )
        .await
        .unwrap_or_else(|e| panic!("upsert sca: {e}"));
        let sast = upsert_tool_finding(
            &pool,
            test_tenant(),
            repo,
            "main",
            &test_tool_finding("rule-a", "app.py", 10),
        )
        .await
        .unwrap_or_else(|e| panic!("upsert sast: {e}"));

        // Resolving only the "sast" kind group with an empty seen_ids must
        // leave the still-open "sca" finding untouched.
        resolve_stale_findings(&pool, test_tenant(), repo, "main", &["sast"], &[])
            .await
            .unwrap_or_else(|e| panic!("resolve: {e}"));

        let sca_status: String =
            sqlx::query_scalar("SELECT status FROM codescan_findings WHERE id = $1")
                .bind(sca.id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("select sca: {e}"));
        let sast_status: String =
            sqlx::query_scalar("SELECT status FROM codescan_findings WHERE id = $1")
                .bind(sast.id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("select sast: {e}"));
        assert_eq!(
            sca_status, "open",
            "sca must be untouched by a sast-only resolve pass"
        );
        assert_eq!(sast_status, "resolved");
    }

    #[tokio::test]
    async fn insert_sbom_artifact_stores_and_upserts_by_scan_run() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let run_id = start_scan_run(&pool, test_tenant(), repo, "main")
            .await
            .unwrap_or_else(|e| panic!("start run: {e}"));

        insert_sbom_artifact(
            &pool,
            test_tenant(),
            repo,
            "main",
            run_id,
            "cyclonedx-json",
            b"first-doc",
        )
        .await
        .unwrap_or_else(|e| panic!("insert sbom: {e}"));

        // A second call for the same scan_run_id must update in place, not
        // duplicate — mirrors the "one SBOM per scan run" invariant
        // migrations/0005's UNIQUE(scan_run_id) enforces.
        insert_sbom_artifact(
            &pool,
            test_tenant(),
            repo,
            "main",
            run_id,
            "cyclonedx-json",
            b"second-doc",
        )
        .await
        .unwrap_or_else(|e| panic!("upsert sbom: {e}"));

        let rows: Vec<(Vec<u8>,)> =
            sqlx::query_as("SELECT doc_gzip FROM codescan_sbom_artifacts WHERE scan_run_id = $1")
                .bind(run_id)
                .fetch_all(&pool)
                .await
                .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(rows.len(), 1, "must upsert, not duplicate");
        assert_eq!(rows[0].0, b"second-doc");
    }

    // ── CodeScan Sentinel P3: AI triage + policy engine ────────────────────

    async fn seed_cve_finding(pool: &PgPool, repo: i64, severity: &str) -> i64 {
        upsert_finding(
            pool,
            test_tenant(),
            repo,
            "main",
            "cve",
            "npm",
            "axios",
            "1.0.0",
            Some("1.7.0"),
            "GHSA-critical-axios",
            severity,
        )
        .await
        .unwrap_or_else(|e| panic!("seed finding: {e}"))
        .id
    }

    #[tokio::test]
    async fn upsert_ai_verdict_never_touches_the_original_severity_or_status() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let finding_id = seed_cve_finding(&pool, repo, "critical").await;

        upsert_ai_verdict(
            &pool,
            finding_id,
            &AiVerdict {
                used: true,
                reachable: false,
                exposure: "none",
                ai_severity: Some("low".to_owned()),
                ai_rationale: "dead code path".to_owned(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("upsert ai verdict: {e}"));

        let row = sqlx::query(
            "SELECT severity, status, used, reachable, exposure, ai_severity, ai_rationale, \
                    triage_source \
             FROM codescan_findings WHERE id = $1",
        )
        .bind(finding_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(
            row.get::<String, _>(0),
            "critical",
            "the AI verdict must never overwrite the scanner's original severity"
        );
        assert_eq!(row.get::<String, _>(1), "open");
        assert!(row.get::<Option<bool>, _>(2).unwrap_or_default());
        assert!(!row.get::<Option<bool>, _>(3).unwrap_or(true));
        assert_eq!(row.get::<Option<String>, _>(4).as_deref(), Some("none"));
        assert_eq!(row.get::<Option<String>, _>(5).as_deref(), Some("low"));
        assert_eq!(row.get::<String, _>(6), "dead code path");
        assert_eq!(row.get::<String, _>(7), "waddleai");
    }

    #[tokio::test]
    async fn upsert_prefilter_verdict_records_not_used_without_calling_ai() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let finding_id = seed_cve_finding(&pool, repo, "high").await;

        upsert_prefilter_verdict(&pool, finding_id, false)
            .await
            .unwrap_or_else(|e| panic!("upsert prefilter verdict: {e}"));

        let row = sqlx::query(
            "SELECT used, reachable, triage_source, severity FROM codescan_findings WHERE id = $1",
        )
        .bind(finding_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select: {e}"));
        assert_eq!(row.get::<Option<bool>, _>(0), Some(false));
        assert_eq!(
            row.get::<Option<bool>, _>(1),
            None,
            "reachable is never set by the prefilter alone"
        );
        assert_eq!(row.get::<String, _>(2), "prefilter");
        assert_eq!(row.get::<String, _>(3), "high", "severity is untouched");
    }

    #[tokio::test]
    async fn apply_policy_decision_sets_the_action_and_writes_an_audit_row() {
        let pool = test_pool().await;
        let repo = seed_repo_config(&pool).await;
        let finding_id = seed_cve_finding(&pool, repo, "critical").await;
        let decision = crate::policy::Decision {
            action: "alert".to_owned(),
            matched_rule_id: None,
            reason: "default action matrix: critical + reachable+external: alert".to_owned(),
        };

        apply_policy_decision(&pool, test_tenant(), finding_id, &decision)
            .await
            .unwrap_or_else(|e| panic!("apply decision: {e}"));

        let action: String =
            sqlx::query_scalar("SELECT action FROM codescan_findings WHERE id = $1")
                .bind(finding_id)
                .fetch_one(&pool)
                .await
                .unwrap_or_else(|e| panic!("select action: {e}"));
        assert_eq!(action, "alert");

        let row = sqlx::query(
            "SELECT tenant_id, finding_id, rule_id, action, reason FROM codescan_policy_decisions \
             WHERE finding_id = $1",
        )
        .bind(finding_id)
        .fetch_one(&pool)
        .await
        .unwrap_or_else(|e| panic!("select decision: {e}"));
        assert_eq!(row.get::<Uuid, _>(0), test_tenant());
        assert_eq!(row.get::<i64, _>(1), finding_id);
        assert_eq!(row.get::<Option<i64>, _>(2), None);
        assert_eq!(row.get::<String, _>(3), "alert");
        assert!(row.get::<String, _>(4).contains("default action matrix"));
    }

    async fn seed_policy_rule(
        pool: &PgPool,
        tenant: Uuid,
        priority: i32,
        package: Option<&str>,
        action: &str,
    ) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_policy_rules (tenant_id, priority, package, action) \
             VALUES ($1, $2, $3, $4) RETURNING id",
        )
        .bind(tenant)
        .bind(priority)
        .bind(package)
        .bind(action)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed policy rule: {e}"));
        row.get::<i64, _>(0)
    }

    #[tokio::test]
    async fn list_policy_rules_returns_only_the_requested_tenants_rules() {
        let pool = test_pool().await;
        seed_policy_rule(&pool, test_tenant(), 10, Some("axios"), "ignore").await;
        seed_policy_rule(&pool, other_tenant(), 5, None, "alert").await;

        let rules = list_policy_rules(&pool, test_tenant())
            .await
            .unwrap_or_else(|e| panic!("list rules: {e}"));
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].package.as_deref(), Some("axios"));
        assert_eq!(rules[0].action, "ignore");
        assert_eq!(rules[0].priority, 10);
    }

    #[tokio::test]
    async fn list_policy_rules_is_empty_for_a_tenant_with_no_rules_configured() {
        let pool = test_pool().await;
        let rules = list_policy_rules(&pool, test_tenant())
            .await
            .unwrap_or_else(|e| panic!("list rules: {e}"));
        assert!(rules.is_empty());
    }
}
