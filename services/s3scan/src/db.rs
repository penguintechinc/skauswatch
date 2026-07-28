//! Database access for the worker, written against the live schema
//! (`tests/parity/seed.sql`, the port's schema authority). All statements are
//! static `&str` bound with sqlx placeholders — no dynamic SQL. Timestamps are
//! `now()` server-side; wire-visible timestamps are not produced here (the
//! worker writes rows, the manager renders them).
//!
//! The result-write + job-counter path mirrors the manager's gRPC
//! `ReportScanResult` (`services/manager/src/grpc/s3_scan_service.rs`) so both
//! writers agree on columns and semantics; the worker owns writes on the scan
//! path.

use sqlx::PgPool;

/// Canonical `s3_scan_results.scan_status` value for a verdict — one of the
/// manager's result-filter enum values (`clean`/`infected`/`pup`).
pub fn scan_status_for(is_malware: bool, is_pup: bool) -> &'static str {
    if is_malware {
        "infected"
    } else if is_pup {
        "pup"
    } else {
        "clean"
    }
}

/// Resolved bucket configuration (credentials + enumeration filters).
#[derive(Debug, Clone)]
pub struct BucketConfig {
    /// Bucket config id.
    pub id: i32,
    /// S3 endpoint URL.
    pub endpoint_url: String,
    /// Bucket name.
    pub bucket_name: String,
    /// Access key id.
    pub access_key_id: String,
    /// Secret access key.
    pub secret_access_key: String,
    /// Region (defaults us-east-1 when NULL).
    pub region: String,
    /// Path-style addressing.
    pub path_style: bool,
    /// Configured key prefix filter.
    pub prefix_filter: Option<String>,
    /// Extension allow-list (from the `file_types_filter` jsonb array).
    pub file_types_filter: Vec<String>,
    /// Per-bucket max file size in MB.
    pub max_file_size_mb: i32,
    /// Whether scanning is enabled for the bucket.
    pub scan_enabled: bool,
    /// Whether YARA is requested for the bucket.
    pub yara_enabled: bool,
}

/// Raw bucket-config row.
#[derive(sqlx::FromRow)]
struct BucketRow {
    id: i32,
    endpoint_url: String,
    bucket_name: String,
    access_key_id: String,
    secret_access_key: String,
    region: Option<String>,
    path_style: Option<bool>,
    prefix_filter: Option<String>,
    file_types_filter: Option<serde_json::Value>,
    max_file_size_mb: Option<i32>,
    scan_enabled: Option<bool>,
    yara_enabled: Option<bool>,
}

/// Extracts a `Vec<String>` from a jsonb array of strings.
fn json_str_list(v: &Option<serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|i| i.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

impl From<BucketRow> for BucketConfig {
    fn from(r: BucketRow) -> Self {
        Self {
            id: r.id,
            endpoint_url: r.endpoint_url,
            bucket_name: r.bucket_name,
            access_key_id: r.access_key_id,
            secret_access_key: r.secret_access_key,
            region: r.region.unwrap_or_else(|| "us-east-1".to_owned()),
            path_style: r.path_style.unwrap_or(false),
            prefix_filter: r.prefix_filter,
            file_types_filter: json_str_list(&r.file_types_filter),
            max_file_size_mb: r.max_file_size_mb.unwrap_or(100),
            scan_enabled: r.scan_enabled.unwrap_or(true),
            yara_enabled: r.yara_enabled.unwrap_or(false),
        }
    }
}

/// Loads a bucket config by id.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn fetch_bucket_config(
    pool: &PgPool,
    id: i32,
) -> Result<Option<BucketConfig>, sqlx::Error> {
    let row = sqlx::query_as::<_, BucketRow>(
        "SELECT id, endpoint_url, bucket_name, access_key_id, secret_access_key, region, \
         path_style, prefix_filter, file_types_filter, max_file_size_mb, \
         scan_enabled, yara_enabled FROM s3_bucket_configs WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(Into::into))
}

/// Job reference resolved from the UUID carried on the wire.
#[derive(Debug, Clone)]
pub struct JobRef {
    /// Integer primary key (`s3_scan_results.job_id` FK target).
    pub pk: i32,
    /// Bucket config id the job targets.
    pub bucket_config_id: i32,
    /// Prefix override stored in the job `metadata` jsonb by the manager's
    /// trigger-scan, if any.
    pub prefix_override: Option<String>,
}

/// Resolves a job UUID to its primary key, bucket, and metadata prefix.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn fetch_job(pool: &PgPool, job_uuid: &str) -> Result<Option<JobRef>, sqlx::Error> {
    let row: Option<(i32, i32, Option<serde_json::Value>)> =
        sqlx::query_as("SELECT id, bucket_config_id, metadata FROM s3_scan_jobs WHERE job_id = $1")
            .bind(job_uuid)
            .fetch_optional(pool)
            .await?;
    Ok(row.map(|(pk, bucket_config_id, metadata)| JobRef {
        pk,
        bucket_config_id,
        prefix_override: metadata
            .as_ref()
            .and_then(|m| m.get("prefix_filter"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    }))
}

/// Transitions a job to `running`, stamping `started_at` and `total_objects`.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn set_job_running(
    pool: &PgPool,
    job_pk: i32,
    total_objects: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE s3_scan_jobs SET status = 'running', started_at = COALESCE(started_at, now()), \
         total_objects = $2 WHERE id = $1",
    )
    .bind(job_pk)
    .bind(total_objects)
    .execute(pool)
    .await?;
    Ok(())
}

/// Increments `skipped_objects` for objects filtered/too-large at enumeration.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn bump_job_skipped(pool: &PgPool, job_pk: i32, n: i32) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE s3_scan_jobs SET skipped_objects = COALESCE(skipped_objects, 0) + $2 WHERE id = $1",
    )
    .bind(job_pk)
    .bind(n)
    .execute(pool)
    .await?;
    Ok(())
}

/// A completed per-object result to persist.
#[derive(Debug, Clone)]
pub struct ResultRecord {
    /// Job primary key.
    pub job_pk: i32,
    /// Bucket config id.
    pub bucket_config_id: i32,
    /// Object key.
    pub object_key: String,
    /// Object size in bytes.
    pub object_size: i32,
    /// Object ETag, if known.
    pub object_etag: Option<String>,
    /// Detected MIME type.
    pub detected_file_type: String,
    /// Canonical scan status (`clean`/`infected`/`pup`/`error`).
    pub scan_status: String,
    /// Malware verdict.
    pub is_malware: bool,
    /// PUP verdict.
    pub is_pup: bool,
    /// Any-threat verdict.
    pub is_threat: bool,
    /// Threat names (jsonb array).
    pub threat_names: serde_json::Value,
    /// ClamAV result (jsonb) if scanned.
    pub clamav_result: Option<serde_json::Value>,
    /// TI enrichment (jsonb) if enriched.
    pub ti_enrichment: Option<serde_json::Value>,
    /// MD5 hex.
    pub file_md5: Option<String>,
    /// SHA1 hex.
    pub file_sha1: Option<String>,
    /// SHA256 hex.
    pub file_sha256: Option<String>,
    /// Applied S3 tags (jsonb).
    pub tags_applied: Option<serde_json::Value>,
    /// Scan duration in ms.
    pub scan_duration_ms: i32,
}

/// Inserts one scan result row.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn insert_result(pool: &PgPool, r: &ResultRecord) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO s3_scan_results (job_id, bucket_config_id, object_key, object_size, \
         object_etag, detected_file_type, scan_status, is_malware, is_pup, is_threat, \
         threat_names, clamav_result, ti_enrichment, file_md5, file_sha1, file_sha256, \
         tags_applied, scan_duration_ms, scanned_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, now())",
    )
    .bind(r.job_pk)
    .bind(r.bucket_config_id)
    .bind(&r.object_key)
    .bind(r.object_size)
    .bind(&r.object_etag)
    .bind(&r.detected_file_type)
    .bind(&r.scan_status)
    .bind(r.is_malware)
    .bind(r.is_pup)
    .bind(r.is_threat)
    .bind(&r.threat_names)
    .bind(&r.clamav_result)
    .bind(&r.ti_enrichment)
    .bind(&r.file_md5)
    .bind(&r.file_sha1)
    .bind(&r.file_sha256)
    .bind(&r.tags_applied)
    .bind(r.scan_duration_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Bumps job counters for a processed object: `scanned_objects` always +1,
/// `infected_objects`/`pup_objects`/`error_count` conditionally (manager
/// `ReportScanResult` parity).
///
/// # Errors
/// Propagates sqlx errors.
pub async fn bump_job_counters(
    pool: &PgPool,
    job_pk: i32,
    is_malware: bool,
    is_pup: bool,
    is_error: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE s3_scan_jobs SET \
         scanned_objects = COALESCE(scanned_objects, 0) + 1, \
         infected_objects = COALESCE(infected_objects, 0) + $2, \
         pup_objects = COALESCE(pup_objects, 0) + $3, \
         error_count = COALESCE(error_count, 0) + $4 WHERE id = $1",
    )
    .bind(job_pk)
    .bind(i32::from(is_malware))
    .bind(i32::from(is_pup))
    .bind(i32::from(is_error))
    .execute(pool)
    .await?;
    Ok(())
}

/// Marks a running job `completed` once every enumerated object has been
/// processed or skipped (`scanned_objects + skipped_objects >= total_objects`,
/// `total_objects > 0`). Idempotent — only transitions `running` jobs.
///
/// # Errors
/// Propagates sqlx errors.
pub async fn maybe_complete_job(pool: &PgPool, job_pk: i32) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE s3_scan_jobs SET status = 'completed', completed_at = now() \
         WHERE id = $1 AND status = 'running' AND total_objects > 0 \
         AND COALESCE(scanned_objects, 0) + COALESCE(skipped_objects, 0) >= total_objects",
    )
    .bind(job_pk)
    .execute(pool)
    .await?;
    Ok(())
}

/// Writes a terminal ad-hoc result (verdict + hashes + type).
///
/// # Errors
/// Propagates sqlx errors.
#[allow(clippy::too_many_arguments)]
pub async fn finish_adhoc(
    pool: &PgPool,
    scan_id: &str,
    scan_status: &str,
    is_malware: bool,
    is_pup: bool,
    is_threat: bool,
    detected_file_type: &str,
    threat_names: &serde_json::Value,
    clamav_result: Option<&serde_json::Value>,
    scan_duration_ms: i32,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE adhoc_scan_results SET scan_status = $2, is_malware = $3, is_pup = $4, \
         is_threat = $5, detected_file_type = $6, threat_names = $7, clamav_result = $8, \
         scan_duration_ms = $9, scanned_at = now() WHERE scan_id = $1",
    )
    .bind(scan_id)
    .bind(scan_status)
    .bind(is_malware)
    .bind(is_pup)
    .bind(is_threat)
    .bind(detected_file_type)
    .bind(threat_names)
    .bind(clamav_result)
    .bind(scan_duration_ms)
    .execute(pool)
    .await?;
    Ok(())
}

/// Marks an ad-hoc scan `error` (e.g. content not retrievable).
///
/// # Errors
/// Propagates sqlx errors.
pub async fn set_adhoc_error(pool: &PgPool, scan_id: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE adhoc_scan_results SET scan_status = 'error', scanned_at = now() \
         WHERE scan_id = $1",
    )
    .bind(scan_id)
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn status_mapping() {
        assert_eq!(scan_status_for(true, false), "infected");
        assert_eq!(scan_status_for(true, true), "infected");
        assert_eq!(scan_status_for(false, true), "pup");
        assert_eq!(scan_status_for(false, false), "clean");
    }

    #[test]
    fn json_list_extraction() {
        let v = Some(serde_json::json!([".exe", ".dll", 3]));
        assert_eq!(
            json_str_list(&v),
            vec![".exe".to_owned(), ".dll".to_owned()]
        );
        assert_eq!(json_str_list(&None), Vec::<String>::new());
        assert_eq!(
            json_str_list(&Some(serde_json::Value::Null)),
            Vec::<String>::new()
        );
    }

    #[test]
    fn bucket_config_defaults_from_nulls() {
        let cfg: BucketConfig = BucketRow {
            id: 1,
            endpoint_url: "https://s3".to_owned(),
            bucket_name: "b".to_owned(),
            access_key_id: "AK".to_owned(),
            secret_access_key: "SK".to_owned(),
            region: None,
            path_style: None,
            prefix_filter: None,
            file_types_filter: None,
            max_file_size_mb: None,
            scan_enabled: None,
            yara_enabled: None,
        }
        .into();
        assert_eq!(cfg.region, "us-east-1");
        assert!(!cfg.path_style);
        assert_eq!(cfg.max_file_size_mb, 100);
        assert!(cfg.scan_enabled);
    }

    // ── real-Postgres tests (see docs/v2-port/testing-pattern.md) ──────────

    async fn pool() -> PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    /// Seeds one `s3_bucket_configs` row, returning its primary key.
    async fn seed_bucket(pool: &PgPool, scan_enabled: bool, yara_enabled: bool) -> i32 {
        let row: (i32,) = sqlx::query_as(
            "INSERT INTO s3_bucket_configs \
             (name, endpoint_url, bucket_name, access_key_id, secret_access_key, region, \
              path_style, prefix_filter, file_types_filter, max_file_size_mb, scan_enabled, \
              yara_enabled, created_by) \
             VALUES ($1, 'https://s3.example', 'test-bucket', 'AK', 'SK', NULL, NULL, NULL, \
                     $2, NULL, $3, $4, 1) RETURNING id",
        )
        .bind(format!("bucket-{}", uuid::Uuid::new_v4()))
        .bind(serde_json::json!([".exe", ".dll"]))
        .bind(scan_enabled)
        .bind(yara_enabled)
        .fetch_one(pool)
        .await
        .expect("seed bucket");
        row.0
    }

    /// Seeds one `s3_scan_jobs` row, returning its primary key.
    async fn seed_job(
        pool: &PgPool,
        bucket_config_id: i32,
        job_uuid: &str,
        metadata: serde_json::Value,
    ) -> i32 {
        let row: (i32,) = sqlx::query_as(
            "INSERT INTO s3_scan_jobs (job_id, bucket_config_id, job_type, status, triggered_by, metadata) \
             VALUES ($1, $2, 'manual', 'pending', 1, $3) RETURNING id",
        )
        .bind(job_uuid)
        .bind(bucket_config_id)
        .bind(metadata)
        .fetch_one(pool)
        .await
        .expect("seed job");
        row.0
    }

    /// Seeds one `adhoc_scan_results` row.
    async fn seed_adhoc(pool: &PgPool, scan_id: &str) {
        sqlx::query(
            "INSERT INTO adhoc_scan_results (scan_id, uploaded_by, original_filename) \
             VALUES ($1, 1, 'upload.bin')",
        )
        .bind(scan_id)
        .execute(pool)
        .await
        .expect("seed adhoc");
    }

    fn sample_result(job_pk: i32, bucket_config_id: i32) -> ResultRecord {
        ResultRecord {
            job_pk,
            bucket_config_id,
            object_key: "uploads/a.bin".to_owned(),
            object_size: 1024,
            object_etag: Some("\"etag\"".to_owned()),
            detected_file_type: "application/octet-stream".to_owned(),
            scan_status: "clean".to_owned(),
            is_malware: false,
            is_pup: false,
            is_threat: false,
            threat_names: serde_json::Value::Array(vec![]),
            clamav_result: None,
            ti_enrichment: None,
            file_md5: Some("d41d8cd98f00b204e9800998ecf8427e".to_owned()),
            file_sha1: Some("da39a3ee5e6b4b0d3255bfef95601890afd80709".to_owned()),
            file_sha256: Some(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned(),
            ),
            tags_applied: None,
            scan_duration_ms: 42,
        }
    }

    #[tokio::test]
    async fn fetch_bucket_config_found_uses_explicit_values() {
        let pool = pool().await;
        let id = seed_bucket(&pool, true, true).await;
        let cfg = fetch_bucket_config(&pool, id)
            .await
            .expect("query")
            .expect("row present");
        assert_eq!(cfg.id, id);
        assert_eq!(cfg.bucket_name, "test-bucket");
        assert_eq!(
            cfg.file_types_filter,
            vec![".exe".to_owned(), ".dll".to_owned()]
        );
        assert!(cfg.scan_enabled);
        assert!(cfg.yara_enabled);
        // Nullable columns left NULL in the seed still resolve to defaults.
        assert_eq!(cfg.region, "us-east-1");
        assert_eq!(cfg.max_file_size_mb, 100);
    }

    #[tokio::test]
    async fn fetch_bucket_config_missing_is_none() {
        let pool = pool().await;
        assert!(
            fetch_bucket_config(&pool, 999_999)
                .await
                .expect("query")
                .is_none()
        );
    }

    #[tokio::test]
    async fn fetch_job_resolves_pk_bucket_and_prefix_override() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(
            &pool,
            bucket_id,
            &job_uuid,
            serde_json::json!({"prefix_filter": "uploads/"}),
        )
        .await;

        let job = fetch_job(&pool, &job_uuid)
            .await
            .expect("query")
            .expect("row present");
        assert_eq!(job.pk, pk);
        assert_eq!(job.bucket_config_id, bucket_id);
        assert_eq!(job.prefix_override, Some("uploads/".to_owned()));
    }

    #[tokio::test]
    async fn fetch_job_without_prefix_metadata_has_no_override() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        seed_job(&pool, bucket_id, &job_uuid, serde_json::json!({})).await;

        let job = fetch_job(&pool, &job_uuid)
            .await
            .expect("query")
            .expect("row present");
        assert_eq!(job.prefix_override, None);
    }

    #[tokio::test]
    async fn fetch_job_missing_is_none() {
        let pool = pool().await;
        assert!(
            fetch_job(&pool, "does-not-exist")
                .await
                .expect("query")
                .is_none()
        );
    }

    #[tokio::test]
    async fn set_job_running_stamps_status_and_total() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, bucket_id, &job_uuid, serde_json::json!({})).await;

        set_job_running(&pool, pk, 7).await.expect("update");

        let row: (String, i32, Option<chrono::NaiveDateTime>) = sqlx::query_as(
            "SELECT status, total_objects, started_at FROM s3_scan_jobs WHERE id = $1",
        )
        .bind(pk)
        .fetch_one(&pool)
        .await
        .expect("select");
        assert_eq!(row.0, "running");
        assert_eq!(row.1, 7);
        assert!(row.2.is_some());
    }

    #[tokio::test]
    async fn bump_job_skipped_increments_counter() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, bucket_id, &job_uuid, serde_json::json!({})).await;

        bump_job_skipped(&pool, pk, 2).await.expect("bump 1");
        bump_job_skipped(&pool, pk, 3).await.expect("bump 2");

        let row: (i32,) = sqlx::query_as("SELECT skipped_objects FROM s3_scan_jobs WHERE id = $1")
            .bind(pk)
            .fetch_one(&pool)
            .await
            .expect("select");
        assert_eq!(row.0, 5);
    }

    #[tokio::test]
    async fn insert_result_persists_all_fields() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, bucket_id, &job_uuid, serde_json::json!({})).await;
        let record = sample_result(pk, bucket_id);

        insert_result(&pool, &record).await.expect("insert");

        let row: (String, String, bool, Option<String>) = sqlx::query_as(
            "SELECT object_key, scan_status, is_malware, file_sha256 FROM s3_scan_results \
             WHERE job_id = $1",
        )
        .bind(pk)
        .fetch_one(&pool)
        .await
        .expect("select");
        assert_eq!(row.0, "uploads/a.bin");
        assert_eq!(row.1, "clean");
        assert!(!row.2);
        assert_eq!(row.3, record.file_sha256);
    }

    #[tokio::test]
    async fn bump_job_counters_increments_conditionally() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, bucket_id, &job_uuid, serde_json::json!({})).await;

        bump_job_counters(&pool, pk, true, false, false)
            .await
            .expect("malware bump");
        bump_job_counters(&pool, pk, false, true, false)
            .await
            .expect("pup bump");
        bump_job_counters(&pool, pk, false, false, true)
            .await
            .expect("error bump");

        let row: (i32, i32, i32, i32) = sqlx::query_as(
            "SELECT scanned_objects, infected_objects, pup_objects, error_count \
             FROM s3_scan_jobs WHERE id = $1",
        )
        .bind(pk)
        .fetch_one(&pool)
        .await
        .expect("select");
        assert_eq!(row, (3, 1, 1, 1));
    }

    #[tokio::test]
    async fn maybe_complete_job_transitions_when_threshold_met() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, bucket_id, &job_uuid, serde_json::json!({})).await;
        set_job_running(&pool, pk, 2).await.expect("running");
        bump_job_skipped(&pool, pk, 1).await.expect("skip 1");
        bump_job_counters(&pool, pk, false, false, false)
            .await
            .expect("scan 1"); // scanned=1 + skipped=1 == total=2

        maybe_complete_job(&pool, pk).await.expect("complete check");

        let row: (String, Option<chrono::NaiveDateTime>) =
            sqlx::query_as("SELECT status, completed_at FROM s3_scan_jobs WHERE id = $1")
                .bind(pk)
                .fetch_one(&pool)
                .await
                .expect("select");
        assert_eq!(row.0, "completed");
        assert!(row.1.is_some());
    }

    #[tokio::test]
    async fn maybe_complete_job_noop_below_threshold() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, bucket_id, &job_uuid, serde_json::json!({})).await;
        set_job_running(&pool, pk, 5).await.expect("running");
        bump_job_counters(&pool, pk, false, false, false)
            .await
            .expect("scan 1"); // scanned=1 + skipped=0 < total=5

        maybe_complete_job(&pool, pk).await.expect("complete check");

        let row: (String,) = sqlx::query_as("SELECT status FROM s3_scan_jobs WHERE id = $1")
            .bind(pk)
            .fetch_one(&pool)
            .await
            .expect("select");
        assert_eq!(row.0, "running");
    }

    #[tokio::test]
    async fn maybe_complete_job_noop_when_total_zero() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, bucket_id, &job_uuid, serde_json::json!({})).await;
        set_job_running(&pool, pk, 0).await.expect("running");

        maybe_complete_job(&pool, pk).await.expect("complete check");

        let row: (String,) = sqlx::query_as("SELECT status FROM s3_scan_jobs WHERE id = $1")
            .bind(pk)
            .fetch_one(&pool)
            .await
            .expect("select");
        // total_objects = 0 fails the `total_objects > 0` guard — stays running.
        assert_eq!(row.0, "running");
    }

    #[tokio::test]
    async fn maybe_complete_job_noop_when_not_running() {
        let pool = pool().await;
        let bucket_id = seed_bucket(&pool, true, false).await;
        let job_uuid = uuid::Uuid::new_v4().to_string();
        let pk = seed_job(&pool, bucket_id, &job_uuid, serde_json::json!({})).await;
        // Job is still 'pending' — never transitioned to 'running'.

        maybe_complete_job(&pool, pk).await.expect("complete check");

        let row: (String,) = sqlx::query_as("SELECT status FROM s3_scan_jobs WHERE id = $1")
            .bind(pk)
            .fetch_one(&pool)
            .await
            .expect("select");
        assert_eq!(row.0, "pending");
    }

    #[tokio::test]
    async fn finish_adhoc_writes_terminal_verdict() {
        let pool = pool().await;
        let scan_id = uuid::Uuid::new_v4().to_string();
        seed_adhoc(&pool, &scan_id).await;

        finish_adhoc(
            &pool,
            &scan_id,
            "infected",
            true,
            false,
            true,
            "application/x-msdownload",
            &serde_json::json!(["Win.Test.EICAR"]),
            Some(&serde_json::json!({"is_malware": true})),
            17,
        )
        .await
        .expect("finish");

        let row: (String, bool, Option<chrono::NaiveDateTime>) = sqlx::query_as(
            "SELECT scan_status, is_malware, scanned_at FROM adhoc_scan_results WHERE scan_id = $1",
        )
        .bind(&scan_id)
        .fetch_one(&pool)
        .await
        .expect("select");
        assert_eq!(row.0, "infected");
        assert!(row.1);
        assert!(row.2.is_some());
    }

    #[tokio::test]
    async fn set_adhoc_error_marks_row_error() {
        let pool = pool().await;
        let scan_id = uuid::Uuid::new_v4().to_string();
        seed_adhoc(&pool, &scan_id).await;

        set_adhoc_error(&pool, &scan_id).await.expect("set error");

        let row: (String,) =
            sqlx::query_as("SELECT scan_status FROM adhoc_scan_results WHERE scan_id = $1")
                .bind(&scan_id)
                .fetch_one(&pool)
                .await
                .expect("select");
        assert_eq!(row.0, "error");
    }

    #[tokio::test]
    async fn set_adhoc_error_on_missing_row_is_a_noop_not_an_error() {
        let pool = pool().await;
        // No matching scan_id row exists — UPDATE affects zero rows, which is
        // not itself an sqlx error.
        set_adhoc_error(&pool, "does-not-exist")
            .await
            .expect("noop update");
    }
}
