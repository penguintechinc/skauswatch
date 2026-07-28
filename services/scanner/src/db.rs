//! Database operations for scanner results.
//!
//! Writes land in `scanner_scan_results` (see
//! `migrations/0001_scanner_schema.sql`) — deliberately NOT
//! `adhoc_scan_results`, which is a same-named but structurally unrelated
//! table already owned by the s3scan/manager ad-hoc file-upload-scan
//! feature. All services share one Postgres database in production, so the
//! two names must never collide.

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
        "INSERT INTO scanner_scan_results (job_id, scan_type, target, findings_count, findings, duration_sec, status, error_message, created_at, updated_at)
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
    sqlx::query("UPDATE scanner_scan_results SET status = $1, updated_at = $2 WHERE job_id = $3")
        .bind(status)
        .bind(Utc::now())
        .bind(job_id)
        .execute(pool)
        .await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;
    use sqlx::Row;

    async fn pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    #[tokio::test]
    async fn insert_scan_result_persists_success_row() {
        let pool = pool().await;
        insert_scan_result(
            &pool,
            "job-1",
            "yara",
            "/tmp/file.bin",
            2,
            r#"{"matches":["rule_a","rule_b"]}"#,
            1.5,
            "success",
            None,
        )
        .await
        .expect("insert succeeds");

        let row = sqlx::query(
            "SELECT job_id, scan_type, target, findings_count, findings, duration_sec, status, error_message \
             FROM scanner_scan_results WHERE job_id = $1",
        )
        .bind("job-1")
        .fetch_one(&pool)
        .await
        .expect("row exists");

        assert_eq!(row.get::<String, _>("job_id"), "job-1");
        assert_eq!(row.get::<String, _>("scan_type"), "yara");
        assert_eq!(row.get::<String, _>("target"), "/tmp/file.bin");
        assert_eq!(row.get::<i32, _>("findings_count"), 2);
        assert_eq!(row.get::<f64, _>("duration_sec"), 1.5);
        assert_eq!(row.get::<String, _>("status"), "success");
        assert_eq!(row.get::<Option<String>, _>("error_message"), None);
        let findings: serde_json::Value = row.get("findings");
        assert_eq!(findings["matches"][0], "rule_a");
    }

    #[tokio::test]
    async fn insert_scan_result_persists_error_row_with_message() {
        let pool = pool().await;
        insert_scan_result(
            &pool,
            "job-2",
            "clamav",
            "s3://bucket/key",
            0,
            "{}",
            0.0,
            "error",
            Some("clamd unreachable"),
        )
        .await
        .expect("insert succeeds");

        let row =
            sqlx::query("SELECT status, error_message FROM scanner_scan_results WHERE job_id = $1")
                .bind("job-2")
                .fetch_one(&pool)
                .await
                .expect("row exists");

        assert_eq!(row.get::<String, _>("status"), "error");
        assert_eq!(
            row.get::<Option<String>, _>("error_message"),
            Some("clamd unreachable".to_owned())
        );
    }

    #[tokio::test]
    async fn update_scan_result_status_changes_status_and_updated_at() {
        let pool = pool().await;
        insert_scan_result(
            &pool, "job-3", "yara", "target", 0, "{}", 0.1, "pending", None,
        )
        .await
        .expect("insert succeeds");

        let before = sqlx::query("SELECT updated_at FROM scanner_scan_results WHERE job_id = $1")
            .bind("job-3")
            .fetch_one(&pool)
            .await
            .expect("row exists")
            .get::<chrono::DateTime<Utc>, _>("updated_at");

        // Ensure the timestamp comparison below can't tie on clock resolution.
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;

        update_scan_result_status(&pool, "job-3", "success")
            .await
            .expect("update succeeds");

        let row =
            sqlx::query("SELECT status, updated_at FROM scanner_scan_results WHERE job_id = $1")
                .bind("job-3")
                .fetch_one(&pool)
                .await
                .expect("row exists");

        assert_eq!(row.get::<String, _>("status"), "success");
        assert!(row.get::<chrono::DateTime<Utc>, _>("updated_at") > before);
    }

    #[tokio::test]
    async fn update_scan_result_status_matches_no_rows_for_unknown_job_id() {
        let pool = pool().await;
        // Not an error — mirrors the handler's "don't fail the message"
        // semantics; a zero-row UPDATE is a successful no-op.
        update_scan_result_status(&pool, "does-not-exist", "success")
            .await
            .expect("update succeeds even with no matching row");
    }
}
