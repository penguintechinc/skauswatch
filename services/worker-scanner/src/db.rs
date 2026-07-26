//! Database operations for scanner results.

use chrono::Utc;
use sqlx::PgPool;

/// Inserts a scan result into the database.
#[allow(clippy::too_many_arguments)]
pub async fn insert_scan_result(
    pool: &PgPool,
    job_id: &str,
    scan_type: &str,
    target: &str,
    findings_count: i32,
    findings_json: &str,
    duration_sec: f64,
    status: &str,
    error_message: Option<&str>,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO adhoc_scan_results (job_id, scan_type, target, findings_count, findings, duration_sec, status, error_message, created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $9)"
    )
    .bind(job_id)
    .bind(scan_type)
    .bind(target)
    .bind(findings_count)
    .bind(findings_json)
    .bind(duration_sec)
    .bind(status)
    .bind(error_message)
    .bind(Utc::now())
    .execute(pool)
    .await?;
    Ok(())
}

/// Updates a scan result status.
#[allow(dead_code)] // Phase 3: used in future result updates
pub async fn update_scan_result_status(
    pool: &PgPool,
    job_id: &str,
    status: &str,
) -> anyhow::Result<()> {
    sqlx::query("UPDATE adhoc_scan_results SET status = $1, updated_at = $2 WHERE job_id = $3")
        .bind(status)
        .bind(Utc::now())
        .bind(job_id)
        .execute(pool)
        .await?;
    Ok(())
}
