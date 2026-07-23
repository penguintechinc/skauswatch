//! /api/v1/s3-scan — bucket-config CRUD + connection test + scan trigger,
//! scan jobs, scan results + statistics + TI integration, per-bucket
//! schedules, ad-hoc upload scanning, and hash lookup. Contract:
//! docs/v2-port/manager-contract.md §s3-scan; Python source of truth:
//! services/manager/api/v1/s3_scan.py (+ validators/s3_scan_models.py).
//!
//! Contract-defect decisions applied here (do NOT "fix" back to v1):
//! - Defect #1 (schema authoritative): v1 handlers referenced columns/tables
//!   that don't exist (`db.adhoc_scans`, `files_scanned`, `file_key`,
//!   `scan_engine`, `confidence_score`, job `prefix_filter`/`force_rescan`,
//!   schedule `last_triggered_at`, …) and were runtime-broken. Queries here
//!   use the real columns; v1 JSON *field names* are preserved and mapped
//!   (files_scanned←scanned_objects, file_key←object_key,
//!   file_type←detected_file_type, sandbox_report←sandbox_result,
//!   last_triggered_at←last_run_at, …). Fields with no backing column
//!   (scan_engine, confidence_score, result error_message/metadata/
//!   created_at/updated_at, adhoc sandbox_status) are emitted as null/{}.
//!   Trigger-scan stores prefix_filter/force_rescan inside the job's
//!   `metadata` jsonb; inserts populate the NOT NULL `job_id`/`triggered_by`/
//!   `created_by`/`scan_id`/`uploaded_by` columns v1 omitted. Ad-hoc uploads
//!   are stored as `pending` (schema IS_IN_SET) instead of v1's fake
//!   instant-"clean", with scanned_at null until a worker scans them.
//! - Defect #3: TI indicators created from scan results use type `hash`
//!   (v1 wrote the disallowed `file_hash`); lookups use `hash` too so reads
//!   match writes.
//! - Defect #4: manual scan triggers write job_type `full_scan` (the DB's
//!   allowed set) instead of v1's disallowed `manual`.
//!
//! House conventions shared with routes/alerts.rs & routes/threat_intel.rs:
//! bare v1 `{"error": ...}` bodies map onto the ApiError envelope;
//! page/per_page floored at 1 where v1 would divide by zero; timestamps are
//! selected as chrono `NaiveDateTime` and rendered with
//! `skauswatch_streams::py_isoformat` (Python `datetime.isoformat()` parity).

use axum::body::Bytes;
use axum::extract::multipart::MultipartRejection;
use axum::extract::{DefaultBodyLimit, Multipart, Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::Deserialize;
use sqlx::{Postgres, QueryBuilder};

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::state::AppState;

/// v1 `S3ScanStatus` enum values (results/statistics filter surface).
const SCAN_STATUSES: [&str; 5] = ["clean", "infected", "pup", "error", "skipped"];
const SCAN_STATUS_MSG: &str = "Input should be 'clean', 'infected', 'pup', 'error' or 'skipped'";

/// Defect #3: the IOC type written/read for file hashes ("hash", not v1's
/// disallowed "file_hash").
const HASH_IOC_TYPE: &str = "hash";

/// List defaults: page size 50, hard cap 500 (v1 `min(per_page, 500)`).
const DEFAULT_PER_PAGE: i64 = 50;
const MAX_PER_PAGE: i64 = 500;

/// v1 ad-hoc upload cap (100MB) plus multipart-framing slack for the axum
/// body limit — the handler still enforces the exact 100MB contract check.
const MAX_UPLOAD_MB: usize = 100;
const UPLOAD_BODY_LIMIT: usize = (MAX_UPLOAD_MB + 2) * 1024 * 1024;

const BUCKET_COLUMNS: &str = "SELECT id, name, endpoint_url, bucket_name, access_key_id, \
     secret_access_key, region, use_ssl, path_style, prefix_filter, file_types_filter, \
     max_file_size_mb, scan_enabled, yara_enabled, created_at, updated_at \
     FROM s3_bucket_configs WHERE TRUE";

const JOB_COLUMNS: &str = "SELECT id, bucket_config_id, job_type, status, scanned_objects, \
     infected_objects, pup_objects, error_count, skipped_objects, started_at, \
     completed_at, error_message, metadata, created_at \
     FROM s3_scan_jobs WHERE TRUE";

const RESULT_COLUMNS: &str = "SELECT id, job_id, bucket_config_id, object_key, object_size, \
     detected_file_type, scan_status, is_malware, is_pup, is_threat, threat_names, \
     yara_matches, sandbox_status, sandbox_result, scanned_at \
     FROM s3_scan_results WHERE TRUE";

const ADHOC_COLUMNS: &str = "SELECT id, uploaded_by, original_filename, file_size, scan_status, \
     is_malware, is_pup, is_threat, threat_names, yara_matches, sandbox_result, file_md5, \
     file_sha256, scanned_at, uploaded_at FROM adhoc_scan_results WHERE TRUE";

/// Router for /api/v1/s3-scan — all 22 contract routes (23 method+path
/// pairs; the contract counts GET+DELETE /upload/{id} as one route).
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/s3-scan/buckets", get(list_buckets).post(create_bucket))
        .route(
            "/s3-scan/buckets/{bucket_id}",
            get(get_bucket).put(update_bucket).delete(delete_bucket),
        )
        .route(
            "/s3-scan/buckets/{bucket_id}/test",
            post(test_bucket_connection),
        )
        .route("/s3-scan/buckets/{bucket_id}/scan", post(trigger_scan))
        .route(
            "/s3-scan/buckets/{bucket_id}/schedule",
            get(get_schedule).put(set_schedule).delete(delete_schedule),
        )
        .route("/s3-scan/jobs", get(list_jobs))
        .route("/s3-scan/jobs/{job_id}", get(get_job))
        .route("/s3-scan/jobs/{job_id}/cancel", post(cancel_job))
        .route("/s3-scan/results", get(query_results))
        .route("/s3-scan/results/{result_id}", get(get_result))
        .route(
            "/s3-scan/results/{result_id}/create-indicator",
            post(create_ti_indicator),
        )
        .route(
            "/s3-scan/results/{result_id}/ti-enrichment",
            get(get_ti_enrichment),
        )
        .route("/s3-scan/statistics", get(get_statistics))
        .route(
            "/s3-scan/upload",
            post(upload_file).layer(DefaultBodyLimit::max(UPLOAD_BODY_LIMIT)),
        )
        .route("/s3-scan/upload/history", get(list_upload_history))
        .route(
            "/s3-scan/upload/{scan_id}",
            get(get_upload_result).delete(delete_upload_scan),
        )
        .route("/s3-scan/hash-lookup", post(hash_lookup))
}

/// Single-field `{error: "Validation error", details: [...]}` body builder.
fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// v1 pages math: `(total + per_page - 1) // per_page` (per_page >= 1).
fn total_pages(total: i64, per_page: i64) -> i64 {
    (total + per_page - 1) / per_page
}

/// pydantic-style string length check (character count, not bytes).
fn check_len(s: &str, field: &str, min: usize, max: usize) -> Result<(), ApiError> {
    let n = s.chars().count();
    if n < min {
        let unit = if min == 1 { "character" } else { "characters" };
        return Err(validation(
            field,
            &format!("String should have at least {min} {unit}"),
        ));
    }
    if n > max {
        return Err(validation(
            field,
            &format!("String should have at most {max} characters"),
        ));
    }
    Ok(())
}

fn required_str(
    v: &Option<String>,
    field: &str,
    min: usize,
    max: usize,
) -> Result<String, ApiError> {
    let Some(s) = v else {
        return Err(validation(field, "Field required"));
    };
    check_len(s, field, min, max)?;
    Ok(s.clone())
}

/// Lenient datetime parsing approximating Python's fromisoformat/pydantic:
/// RFC3339 (offset/Z), naive ISO with T or space, or bare date at midnight.
fn parse_datetime(s: &str) -> Option<NaiveDateTime> {
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.naive_utc());
    }
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%d %H:%M:%S%.f"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(dt);
        }
    }
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
}

/// v1 `mask_credentials` access-key half: `xxxx****` (<=4 chars → `****`).
fn mask_access_key(key: &str) -> String {
    let n = key.chars().count();
    if n <= 4 {
        return "****".to_owned();
    }
    let head: String = key.chars().take(4).collect();
    format!("{head}{}", "*".repeat(n - 4))
}

/// v1 `mask_credentials` secret half: `xxxx…last4` with `len-8` stars —
/// Python's negative-repeat quirk (5..=8 chars overlap head/tail) preserved.
fn mask_secret_key(key: &str) -> String {
    let n = key.chars().count();
    if n <= 4 {
        return "****".to_owned();
    }
    let head: String = key.chars().take(4).collect();
    let tail: String = key.chars().skip(n - 4).collect();
    format!("{head}{}{tail}", "*".repeat(n.saturating_sub(8)))
}

/// v1 parity: `row.field or []` — SQL NULL / jsonb null become `[]`.
fn jsonb_list(v: &Option<serde_json::Value>) -> serde_json::Value {
    match v {
        Some(val) if !val.is_null() => val.clone(),
        _ => serde_json::Value::Array(vec![]),
    }
}

/// v1 parity: `row.field or {}` — SQL NULL / jsonb null become `{}`.
fn jsonb_object(v: &Option<serde_json::Value>) -> serde_json::Value {
    match v {
        Some(val) if !val.is_null() => val.clone(),
        _ => serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// Quart request.args parity: first value wins for scalars, repeated keys
/// accumulate for lists.
fn first<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
}

fn collect(pairs: &[(String, String)], key: &str) -> Vec<String> {
    pairs
        .iter()
        .filter(|(k, _)| k == key)
        .map(|(_, v)| v.clone())
        .collect()
}

/// Shared page/per_page parsing (buckets/jobs/history): defaults 1 and 50,
/// per_page capped at 500. Deviation from v1 (house rule): floored at 1 —
/// v1 divides by zero / builds negative offsets on 0.
fn parse_page_params(pairs: &[(String, String)]) -> (i64, i64) {
    let page = first(pairs, "page")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1)
        .max(1);
    let per_page = first(pairs, "per_page")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_PER_PAGE)
        .clamp(1, MAX_PER_PAGE);
    (page, per_page)
}

// ============================================
// Bucket configuration endpoints
// ============================================

/// Full bucket-config row — timestamps as chrono `NaiveDateTime`, filter
/// list as jsonb.
#[derive(sqlx::FromRow)]
struct BucketRow {
    id: i32,
    name: String,
    endpoint_url: String,
    bucket_name: String,
    access_key_id: String,
    secret_access_key: String,
    region: Option<String>,
    use_ssl: Option<bool>,
    path_style: Option<bool>,
    prefix_filter: Option<String>,
    file_types_filter: Option<serde_json::Value>,
    max_file_size_mb: Option<i32>,
    scan_enabled: Option<bool>,
    yara_enabled: Option<bool>,
    created_at: Option<NaiveDateTime>,
    updated_at: Option<NaiveDateTime>,
}

/// v1 full bucket shape (list items + GET detail) with masked credentials.
fn bucket_json(b: &BucketRow) -> serde_json::Value {
    serde_json::json!({
        "id": b.id,
        "name": b.name,
        "endpoint_url": b.endpoint_url,
        "bucket_name": b.bucket_name,
        "access_key_id": mask_access_key(&b.access_key_id),
        "secret_access_key": mask_secret_key(&b.secret_access_key),
        "region": b.region,
        "use_ssl": b.use_ssl,
        "path_style": b.path_style,
        "prefix_filter": b.prefix_filter,
        "file_types_filter": jsonb_list(&b.file_types_filter),
        "max_file_size_mb": b.max_file_size_mb,
        "scan_enabled": b.scan_enabled,
        "yara_enabled": b.yara_enabled,
        "created_at": skauswatch_streams::py_isoformat_opt(b.created_at),
        "updated_at": skauswatch_streams::py_isoformat_opt(b.updated_at),
    })
}

async fn fetch_bucket(db: &sqlx::PgPool, bucket_id: i32) -> Result<Option<BucketRow>, ApiError> {
    let mut qb = QueryBuilder::new(BUCKET_COLUMNS);
    qb.push(" AND id = ").push_bind(bucket_id);
    Ok(qb.build_query_as::<BucketRow>().fetch_optional(db).await?)
}

/// True when the bucket-config id exists (cheap existence probe shared by
/// the schedule endpoints).
async fn bucket_exists(db: &sqlx::PgPool, bucket_id: i32) -> Result<bool, ApiError> {
    let row: Option<(i32,)> = sqlx::query_as("SELECT id FROM s3_bucket_configs WHERE id = $1")
        .bind(bucket_id)
        .fetch_optional(db)
        .await?;
    Ok(row.is_some())
}

/// GET /buckets — paginated bucket configs, newest first, creds masked.
async fn list_buckets(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (page, per_page) = parse_page_params(&params);
    let offset = (page - 1) * per_page;

    let mut qb = QueryBuilder::new(BUCKET_COLUMNS);
    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows = qb
        .build_query_as::<BucketRow>()
        .fetch_all(&state.db)
        .await?;
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM s3_bucket_configs")
        .fetch_one(&state.db)
        .await?;

    let items: Vec<serde_json::Value> = rows.iter().map(bucket_json).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": total_pages(total, per_page),
    })))
}

/// BucketConfigCreateRequest — fields optional so missing ones map to the
/// validation envelope instead of an axum extractor rejection.
#[derive(Deserialize)]
struct BucketCreateBody {
    name: Option<String>,
    endpoint_url: Option<String>,
    bucket_name: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    region: Option<String>,
    use_ssl: Option<bool>,
    path_style: Option<bool>,
    prefix_filter: Option<String>,
    file_types_filter: Option<Vec<String>>,
    max_file_size_mb: Option<i64>,
    scan_enabled: Option<bool>,
    yara_enabled: Option<bool>,
}

struct ValidBucketCreate {
    name: String,
    endpoint_url: String,
    bucket_name: String,
    access_key_id: String,
    secret_access_key: String,
    region: String,
    use_ssl: bool,
    path_style: bool,
    prefix_filter: Option<String>,
    file_types_filter: Option<Vec<String>>,
    max_file_size_mb: i64,
    scan_enabled: bool,
    yara_enabled: bool,
}

/// pydantic endpoint_url validator: max 500 chars, stripped, must carry an
/// http(s) scheme.
fn validate_endpoint_url(raw: &str) -> Result<String, ApiError> {
    check_len(raw, "endpoint_url", 0, 500)?;
    let v = raw.trim().to_owned();
    if !(v.starts_with("http://") || v.starts_with("https://")) {
        return Err(validation(
            "endpoint_url",
            "Value error, Endpoint URL must start with http:// or https://",
        ));
    }
    Ok(v)
}

/// pydantic file_types_filter validator: <=50 entries, each stripped,
/// lowercased, and dot-prefixed.
fn normalize_file_types(raw: &[String]) -> Result<Vec<String>, ApiError> {
    if raw.len() > 50 {
        return Err(validation(
            "file_types_filter",
            "List should have at most 50 items",
        ));
    }
    Ok(raw.iter().map(|s| normalize_file_type(s)).collect())
}

/// Strip + lowercase + ensure a leading dot ("EXE" → ".exe").
fn normalize_file_type(s: &str) -> String {
    let v = s.trim().to_lowercase();
    if v.starts_with('.') {
        v
    } else {
        format!(".{v}")
    }
}

fn check_max_file_size(v: i64, field: &str) -> Result<(), ApiError> {
    if v < 1 {
        return Err(validation(
            field,
            "Input should be greater than or equal to 1",
        ));
    }
    if v > 500 {
        return Err(validation(
            field,
            "Input should be less than or equal to 500",
        ));
    }
    Ok(())
}

/// Mirrors pydantic BucketConfigCreateRequest (field-definition order),
/// including its defaults: region us-east-1, use_ssl true, path_style true,
/// max_file_size_mb 100, scan_enabled true, yara_enabled false.
fn validate_bucket_create(b: &BucketCreateBody) -> Result<ValidBucketCreate, ApiError> {
    let name = required_str(&b.name, "name", 1, 255)?;
    let Some(raw_endpoint) = b.endpoint_url.as_deref() else {
        return Err(validation("endpoint_url", "Field required"));
    };
    let endpoint_url = validate_endpoint_url(raw_endpoint)?;
    let bucket_name = required_str(&b.bucket_name, "bucket_name", 1, 255)?;
    let access_key_id = required_str(&b.access_key_id, "access_key_id", 1, 255)?;
    let secret_access_key = required_str(&b.secret_access_key, "secret_access_key", 1, 500)?;
    let region = b.region.clone().unwrap_or_else(|| "us-east-1".to_owned());
    check_len(&region, "region", 0, 50)?;
    if let Some(p) = &b.prefix_filter {
        check_len(p, "prefix_filter", 0, 500)?;
    }
    let file_types_filter = match &b.file_types_filter {
        None => None,
        Some(list) => Some(normalize_file_types(list)?),
    };
    let max_file_size_mb = b.max_file_size_mb.unwrap_or(100);
    check_max_file_size(max_file_size_mb, "max_file_size_mb")?;
    Ok(ValidBucketCreate {
        name,
        endpoint_url,
        bucket_name,
        access_key_id,
        secret_access_key,
        region,
        use_ssl: b.use_ssl.unwrap_or(true),
        path_style: b.path_style.unwrap_or(true),
        prefix_filter: b.prefix_filter.clone(),
        file_types_filter,
        max_file_size_mb,
        scan_enabled: b.scan_enabled.unwrap_or(true),
        yara_enabled: b.yara_enabled.unwrap_or(false),
    })
}

#[derive(sqlx::FromRow)]
struct CreatedBucketRow {
    id: i32,
    name: String,
    bucket_name: String,
    access_key_id: String,
    created_at: Option<NaiveDateTime>,
}

/// POST /buckets — admin/maintainer. 409 on duplicate endpoint+bucket pair.
/// Defect #1: populates the NOT NULL created_by column v1 omitted.
async fn create_bucket(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(body): Json<BucketCreateBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let v = validate_bucket_create(&body)?;

    let existing: Option<(i32,)> = sqlx::query_as(
        "SELECT id FROM s3_bucket_configs WHERE endpoint_url = $1 AND bucket_name = $2",
    )
    .bind(&v.endpoint_url)
    .bind(&v.bucket_name)
    .fetch_optional(&state.db)
    .await?;
    if let Some((existing_id,)) = existing {
        return Err(ApiError::Conflict(serde_json::json!({
            "error": "Bucket configuration already exists",
            "existing_id": existing_id,
        })));
    }

    let row = sqlx::query_as::<_, CreatedBucketRow>(
        "INSERT INTO s3_bucket_configs (name, endpoint_url, bucket_name, access_key_id, \
         secret_access_key, region, use_ssl, path_style, prefix_filter, file_types_filter, \
         max_file_size_mb, scan_enabled, yara_enabled, created_by, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, now()) \
         RETURNING id, name, bucket_name, access_key_id, created_at",
    )
    .bind(&v.name)
    .bind(&v.endpoint_url)
    .bind(&v.bucket_name)
    .bind(&v.access_key_id)
    .bind(&v.secret_access_key)
    .bind(&v.region)
    .bind(v.use_ssl)
    .bind(v.path_style)
    .bind(&v.prefix_filter)
    .bind(v.file_types_filter.clone().map(serde_json::Value::from))
    .bind(v.max_file_size_mb)
    .bind(v.scan_enabled)
    .bind(v.yara_enabled)
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Bucket configuration created successfully",
            "bucket": {
                "id": row.id,
                "name": row.name,
                "bucket_name": row.bucket_name,
                "access_key_id": mask_access_key(&row.access_key_id),
                "created_at": skauswatch_streams::py_isoformat_opt(row.created_at),
            }
        })),
    ))
}

/// GET /buckets/{id} — full config with masked credentials.
async fn get_bucket(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(bucket_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let bucket = fetch_bucket(&state.db, bucket_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Bucket configuration not found".to_owned()))?;
    Ok(Json(bucket_json(&bucket)))
}

/// BucketConfigUpdateRequest — every field optional; absent fields untouched.
#[derive(Deserialize)]
struct BucketUpdateBody {
    name: Option<String>,
    endpoint_url: Option<String>,
    bucket_name: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    region: Option<String>,
    use_ssl: Option<bool>,
    path_style: Option<bool>,
    prefix_filter: Option<String>,
    file_types_filter: Option<Vec<String>>,
    max_file_size_mb: Option<i64>,
    scan_enabled: Option<bool>,
    yara_enabled: Option<bool>,
}

struct ValidBucketUpdate {
    name: Option<String>,
    endpoint_url: Option<String>,
    bucket_name: Option<String>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    region: Option<String>,
    use_ssl: Option<bool>,
    path_style: Option<bool>,
    prefix_filter: Option<String>,
    file_types_filter: Option<Vec<String>>,
    max_file_size_mb: Option<i64>,
    scan_enabled: Option<bool>,
    yara_enabled: Option<bool>,
}

impl ValidBucketUpdate {
    fn has_updates(&self) -> bool {
        self.name.is_some()
            || self.endpoint_url.is_some()
            || self.bucket_name.is_some()
            || self.access_key_id.is_some()
            || self.secret_access_key.is_some()
            || self.region.is_some()
            || self.use_ssl.is_some()
            || self.path_style.is_some()
            || self.prefix_filter.is_some()
            || self.file_types_filter.is_some()
            || self.max_file_size_mb.is_some()
            || self.scan_enabled.is_some()
            || self.yara_enabled.is_some()
    }
}

/// Mirrors pydantic BucketConfigUpdateRequest — per-field checks only when
/// the field is present.
fn validate_bucket_update(b: &BucketUpdateBody) -> Result<ValidBucketUpdate, ApiError> {
    if let Some(n) = &b.name {
        check_len(n, "name", 1, 255)?;
    }
    let endpoint_url = match b.endpoint_url.as_deref() {
        None => None,
        Some(raw) => Some(validate_endpoint_url(raw)?),
    };
    if let Some(n) = &b.bucket_name {
        check_len(n, "bucket_name", 1, 255)?;
    }
    if let Some(n) = &b.access_key_id {
        check_len(n, "access_key_id", 1, 255)?;
    }
    if let Some(n) = &b.secret_access_key {
        check_len(n, "secret_access_key", 1, 500)?;
    }
    if let Some(n) = &b.region {
        check_len(n, "region", 0, 50)?;
    }
    if let Some(p) = &b.prefix_filter {
        check_len(p, "prefix_filter", 0, 500)?;
    }
    let file_types_filter = match &b.file_types_filter {
        None => None,
        Some(list) => Some(normalize_file_types(list)?),
    };
    if let Some(m) = b.max_file_size_mb {
        check_max_file_size(m, "max_file_size_mb")?;
    }
    Ok(ValidBucketUpdate {
        name: b.name.clone(),
        endpoint_url,
        bucket_name: b.bucket_name.clone(),
        access_key_id: b.access_key_id.clone(),
        secret_access_key: b.secret_access_key.clone(),
        region: b.region.clone(),
        use_ssl: b.use_ssl,
        path_style: b.path_style,
        prefix_filter: b.prefix_filter.clone(),
        file_types_filter,
        max_file_size_mb: b.max_file_size_mb,
        scan_enabled: b.scan_enabled,
        yara_enabled: b.yara_enabled,
    })
}

#[derive(sqlx::FromRow)]
struct UpdatedBucketRow {
    id: i32,
    name: String,
    access_key_id: String,
    updated_at: Option<NaiveDateTime>,
}

/// PUT /buckets/{id} — admin/maintainer partial update; pyDAL parity sets
/// updated_at whenever any field changes.
async fn update_bucket(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(bucket_id): Path<i32>,
    Json(body): Json<BucketUpdateBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let v = validate_bucket_update(&body)?;

    if !bucket_exists(&state.db, bucket_id).await? {
        return Err(ApiError::NotFound(
            "Bucket configuration not found".to_owned(),
        ));
    }

    if v.has_updates() {
        let mut qb =
            QueryBuilder::<Postgres>::new("UPDATE s3_bucket_configs SET updated_at = now()");
        if let Some(x) = &v.name {
            qb.push(", name = ").push_bind(x.clone());
        }
        if let Some(x) = &v.endpoint_url {
            qb.push(", endpoint_url = ").push_bind(x.clone());
        }
        if let Some(x) = &v.bucket_name {
            qb.push(", bucket_name = ").push_bind(x.clone());
        }
        if let Some(x) = &v.access_key_id {
            qb.push(", access_key_id = ").push_bind(x.clone());
        }
        if let Some(x) = &v.secret_access_key {
            qb.push(", secret_access_key = ").push_bind(x.clone());
        }
        if let Some(x) = &v.region {
            qb.push(", region = ").push_bind(x.clone());
        }
        if let Some(x) = v.use_ssl {
            qb.push(", use_ssl = ").push_bind(x);
        }
        if let Some(x) = v.path_style {
            qb.push(", path_style = ").push_bind(x);
        }
        if let Some(x) = &v.prefix_filter {
            qb.push(", prefix_filter = ").push_bind(x.clone());
        }
        if let Some(x) = &v.file_types_filter {
            qb.push(", file_types_filter = ")
                .push_bind(serde_json::Value::from(x.clone()));
        }
        if let Some(x) = v.max_file_size_mb {
            qb.push(", max_file_size_mb = ").push_bind(x);
        }
        if let Some(x) = v.scan_enabled {
            qb.push(", scan_enabled = ").push_bind(x);
        }
        if let Some(x) = v.yara_enabled {
            qb.push(", yara_enabled = ").push_bind(x);
        }
        qb.push(" WHERE id = ").push_bind(bucket_id);
        qb.build().execute(&state.db).await?;
    }

    let row = sqlx::query_as::<_, UpdatedBucketRow>(
        "SELECT id, name, access_key_id, updated_at FROM s3_bucket_configs WHERE id = $1",
    )
    .bind(bucket_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Bucket configuration not found".to_owned()))?;

    Ok(Json(serde_json::json!({
        "message": "Bucket configuration updated successfully",
        "bucket": {
            "id": row.id,
            "name": row.name,
            "access_key_id": mask_access_key(&row.access_key_id),
            "updated_at": skauswatch_streams::py_isoformat_opt(row.updated_at),
        }
    })))
}

/// DELETE /buckets/{id} — admin only.
async fn delete_bucket(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(bucket_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin"])?;
    if !bucket_exists(&state.db, bucket_id).await? {
        return Err(ApiError::NotFound(
            "Bucket configuration not found".to_owned(),
        ));
    }
    sqlx::query("DELETE FROM s3_bucket_configs WHERE id = $1")
        .bind(bucket_id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Bucket configuration deleted successfully"
    })))
}

/// POST /buckets/{id}/test — admin/maintainer; performs a real head_bucket
/// (v1 used boto3). Bodies are v1's custom `{success, ...}` shapes, not the
/// error envelope: 200 ok, 400 service error (code+message), 500 transport.
async fn test_bucket_connection(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(bucket_id): Path<i32>,
) -> Result<Response, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let bucket = fetch_bucket(&state.db, bucket_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Bucket configuration not found".to_owned()))?;
    Ok(run_head_bucket(&bucket).await.into_response())
}

/// Builds a per-bucket S3 client from the stored credentials and issues
/// HeadBucket, mapping outcomes onto the v1 boto3 response shapes.
async fn run_head_bucket(b: &BucketRow) -> (StatusCode, Json<serde_json::Value>) {
    use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
    use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};

    let creds = Credentials::new(
        b.access_key_id.clone(),
        b.secret_access_key.clone(),
        None,
        None,
        "s3-bucket-config",
    );
    let region = Region::new(b.region.clone().unwrap_or_else(|| "us-east-1".to_owned()));
    let cfg = aws_sdk_s3::config::Builder::new()
        .behavior_version(BehaviorVersion::latest())
        .region(region)
        .endpoint_url(&b.endpoint_url)
        .force_path_style(b.path_style.unwrap_or(false))
        .credentials_provider(creds)
        .build();
    let client = aws_sdk_s3::Client::from_conf(cfg);

    match client.head_bucket().bucket(&b.bucket_name).send().await {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "success": true,
                "message": format!("Successfully connected to bucket '{}'", b.bucket_name),
            })),
        ),
        Err(SdkError::ServiceError(ctx)) => {
            let code = ctx.err().code().unwrap_or("Unknown").to_owned();
            let message = ctx.err().message().unwrap_or("").to_owned();
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "success": false,
                    "error": format!("Connection failed: {code}"),
                    "details": message,
                })),
            )
        }
        Err(other) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "success": false,
                "error": "Connection failed",
                "details": other.to_string(),
            })),
        ),
    }
}

// ============================================
// Scan job endpoints
// ============================================

/// One `s3scan:tasks` dispatch — v1 ScanJobManager task shape.
struct ScanTaskMsg<'a> {
    /// Scan-job UUID (v1 `job_id = str(uuid4())`), or the ad-hoc scan UUID.
    job_id: &'a str,
    /// Bucket config id; `None` for ad-hoc uploads (v1 None → "").
    bucket_config_id: Option<i32>,
    /// S3 object key; empty for a job-level dispatch (worker enumerates).
    object_key: &'a str,
    /// Object size in bytes (0 when unknown at dispatch time).
    object_size: i64,
    /// Object ETag; empty when unknown at dispatch time.
    object_etag: &'a str,
    /// v1 `config.get("scan_enabled", True)`.
    scan_enabled: bool,
    /// v1 `config.get("yara_enabled", False)`.
    yara_enabled: bool,
    /// Python `datetime.utcnow().isoformat()` publish stamp.
    submitted_at: &'a str,
}

/// v1 `s3scan:tasks` message — field names, order, and redis-py xadd
/// stringification (`{job_id,bucket_config_id,object_key,object_size,
/// object_etag,scan_enabled,yara_enabled,submitted_at}`; Python renders
/// bools as "True"/"False" and None as "").
fn scan_task_fields(msg: &ScanTaskMsg<'_>) -> skauswatch_streams::EntryFields {
    vec![
        ("job_id".to_owned(), msg.job_id.to_owned()),
        (
            "bucket_config_id".to_owned(),
            msg.bucket_config_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
        ),
        ("object_key".to_owned(), msg.object_key.to_owned()),
        ("object_size".to_owned(), msg.object_size.to_string()),
        ("object_etag".to_owned(), msg.object_etag.to_owned()),
        (
            "scan_enabled".to_owned(),
            skauswatch_streams::py_bool(msg.scan_enabled).to_owned(),
        ),
        (
            "yara_enabled".to_owned(),
            skauswatch_streams::py_bool(msg.yara_enabled).to_owned(),
        ),
        ("submitted_at".to_owned(), msg.submitted_at.to_owned()),
    ]
}

/// TriggerScanRequest — v1 tolerates a missing body entirely.
#[derive(Default, Deserialize)]
struct TriggerBody {
    prefix_filter: Option<String>,
    force_rescan: Option<bool>,
}

#[derive(sqlx::FromRow)]
struct CreatedJobRow {
    id: i32,
    bucket_config_id: i32,
    job_type: String,
    status: Option<String>,
    created_at: Option<NaiveDateTime>,
}

/// POST /buckets/{id}/scan — admin/maintainer. Defect #4: writes job_type
/// `full_scan` (DB-allowed) instead of v1's `manual`; defect #1: generates
/// the NOT NULL job_id, sets triggered_by, and stows
/// prefix_filter/force_rescan in metadata (no such job columns exist).
async fn trigger_scan(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(bucket_id): Path<i32>,
    body: Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let parsed: TriggerBody = if body.is_empty() {
        TriggerBody::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|_| ApiError::BadRequest("Invalid JSON body".to_owned()))?
    };
    if let Some(p) = &parsed.prefix_filter {
        check_len(p, "prefix_filter", 0, 500)?;
    }
    let force_rescan = parsed.force_rescan.unwrap_or(false);

    let bucket: Option<(Option<bool>, Option<bool>)> =
        sqlx::query_as("SELECT scan_enabled, yara_enabled FROM s3_bucket_configs WHERE id = $1")
            .bind(bucket_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((scan_enabled, yara_enabled)) = bucket else {
        return Err(ApiError::NotFound(
            "Bucket configuration not found".to_owned(),
        ));
    };
    if !scan_enabled.unwrap_or(false) {
        return Err(ApiError::BadRequest(
            "Scanning is disabled for this bucket".to_owned(),
        ));
    }

    let job_uuid = uuid::Uuid::new_v4().to_string();
    let metadata = serde_json::json!({
        "prefix_filter": parsed.prefix_filter,
        "force_rescan": force_rescan,
    });
    let row = sqlx::query_as::<_, CreatedJobRow>(
        "INSERT INTO s3_scan_jobs (job_id, bucket_config_id, job_type, status, triggered_by, \
         metadata, created_at) VALUES ($1, $2, 'full_scan', 'pending', $3, $4, now()) \
         RETURNING id, bucket_config_id, job_type, status, created_at",
    )
    .bind(&job_uuid)
    .bind(bucket_id)
    .bind(user.id)
    .bind(&metadata)
    .fetch_one(&state.db)
    .await?;

    // v2 dispatch decision: v1's HTTP trigger only inserted a pending row —
    // no runtime component ever picked it up (the ScanJobManager publisher
    // was reachable only via the never-registered gRPC S3ScanService), so
    // jobs stayed pending forever. v2 publishes one job-level s3scan:tasks
    // message using the v1 task field shape; empty object_key means "worker
    // enumerates the bucket". Failures are swallowed with a warning, matching
    // every v1 HTTP publish site.
    state
        .publish_stream(
            skauswatch_streams::STREAM_S3_SCAN_TASKS,
            scan_task_fields(&ScanTaskMsg {
                job_id: &job_uuid,
                bucket_config_id: Some(bucket_id),
                object_key: "",
                object_size: 0,
                object_etag: "",
                scan_enabled: true,
                yara_enabled: yara_enabled.unwrap_or(false),
                submitted_at: &skauswatch_streams::py_now_isoformat(),
            }),
        )
        .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Scan job created successfully",
            "job": {
                "id": row.id,
                "bucket_config_id": row.bucket_config_id,
                "job_type": row.job_type,
                "status": row.status,
                "created_at": skauswatch_streams::py_isoformat_opt(row.created_at),
            }
        })),
    ))
}

/// Scan-job row — schema columns; the v1 wire names are mapped in
/// `job_json` (files_scanned←scanned_objects, files_error←error_count, …).
#[derive(sqlx::FromRow)]
struct JobRow {
    id: i32,
    bucket_config_id: i32,
    job_type: String,
    status: Option<String>,
    scanned_objects: Option<i32>,
    infected_objects: Option<i32>,
    pup_objects: Option<i32>,
    error_count: Option<i32>,
    skipped_objects: Option<i32>,
    started_at: Option<NaiveDateTime>,
    completed_at: Option<NaiveDateTime>,
    error_message: Option<String>,
    metadata: Option<serde_json::Value>,
    created_at: Option<NaiveDateTime>,
}

/// prefix_filter for the wire — read back out of the job's metadata jsonb.
fn meta_prefix_filter(m: &Option<serde_json::Value>) -> serde_json::Value {
    m.as_ref()
        .and_then(|v| v.get("prefix_filter"))
        .cloned()
        .unwrap_or(serde_json::Value::Null)
}

/// force_rescan for the wire — read back out of metadata, default false.
fn meta_force_rescan(m: &Option<serde_json::Value>) -> bool {
    m.as_ref()
        .and_then(|v| v.get("force_rescan"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// v1 job list-item shape with schema→wire column mapping (defect #1).
fn job_json(j: &JobRow) -> serde_json::Value {
    serde_json::json!({
        "id": j.id,
        "bucket_config_id": j.bucket_config_id,
        "job_type": j.job_type,
        "status": j.status,
        "files_scanned": j.scanned_objects.unwrap_or(0),
        "files_infected": j.infected_objects.unwrap_or(0),
        "files_pup": j.pup_objects.unwrap_or(0),
        "files_error": j.error_count.unwrap_or(0),
        "files_skipped": j.skipped_objects.unwrap_or(0),
        "prefix_filter": meta_prefix_filter(&j.metadata),
        "force_rescan": meta_force_rescan(&j.metadata),
        "started_at": skauswatch_streams::py_isoformat_opt(j.started_at),
        "completed_at": skauswatch_streams::py_isoformat_opt(j.completed_at),
        "error_message": j.error_message,
        "created_at": skauswatch_streams::py_isoformat_opt(j.created_at),
    })
}

/// v1 progress math: scanned / (scanned+infected+pup+error+skipped) * 100,
/// rounded to 2 decimals, only while the job is running.
fn progress_percent(j: &JobRow) -> f64 {
    let scanned = i64::from(j.scanned_objects.unwrap_or(0));
    let total = scanned
        + i64::from(j.infected_objects.unwrap_or(0))
        + i64::from(j.pup_objects.unwrap_or(0))
        + i64::from(j.error_count.unwrap_or(0))
        + i64::from(j.skipped_objects.unwrap_or(0));
    if total > 0 && j.status.as_deref() == Some("running") {
        let pct = scanned as f64 / total as f64 * 100.0;
        (pct * 100.0).round() / 100.0
    } else {
        0.0
    }
}

/// Parsed GET /jobs query params (Quart request.args semantics).
struct JobsQuery {
    page: i64,
    per_page: i64,
    bucket_config_id: Option<i32>,
    job_type: Vec<String>,
    status: Vec<String>,
}

/// Quart parity: bucket_config_id=0 is falsy and applies no filter; repeated
/// job_type/status keys accumulate and pass through unvalidated.
fn parse_jobs_params(pairs: &[(String, String)]) -> JobsQuery {
    let (page, per_page) = parse_page_params(pairs);
    JobsQuery {
        page,
        per_page,
        bucket_config_id: first(pairs, "bucket_config_id")
            .and_then(|v| v.parse::<i32>().ok())
            .filter(|v| *v != 0),
        job_type: collect(pairs, "job_type"),
        status: collect(pairs, "status"),
    }
}

fn push_job_filters(qb: &mut QueryBuilder<Postgres>, q: &JobsQuery) {
    if let Some(b) = q.bucket_config_id {
        qb.push(" AND bucket_config_id = ").push_bind(b);
    }
    if !q.job_type.is_empty() {
        qb.push(" AND job_type = ANY(")
            .push_bind(q.job_type.clone())
            .push(")");
    }
    if !q.status.is_empty() {
        qb.push(" AND status = ANY(")
            .push_bind(q.status.clone())
            .push(")");
    }
}

/// GET /jobs — paginated scan jobs, newest first, with optional
/// bucket/job_type/status filters.
async fn list_jobs(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let q = parse_jobs_params(&params);
    let offset = (q.page - 1) * q.per_page;

    let mut qb = QueryBuilder::new(JOB_COLUMNS);
    push_job_filters(&mut qb, &q);
    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(q.per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows = qb.build_query_as::<JobRow>().fetch_all(&state.db).await?;

    let mut cq = QueryBuilder::new("SELECT COUNT(*) FROM s3_scan_jobs WHERE TRUE");
    push_job_filters(&mut cq, &q);
    let total: i64 = cq.build_query_scalar().fetch_one(&state.db).await?;

    let items: Vec<serde_json::Value> = rows.iter().map(job_json).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": q.page,
        "per_page": q.per_page,
        "pages": total_pages(total, q.per_page),
    })))
}

/// GET /jobs/{id} — list shape plus metadata, updated_at (null — no such
/// column, defect #1), and computed progress_percent.
async fn get_job(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(job_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut qb = QueryBuilder::new(JOB_COLUMNS);
    qb.push(" AND id = ").push_bind(job_id);
    let row = qb
        .build_query_as::<JobRow>()
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Scan job not found".to_owned()))?;

    let mut v = job_json(&row);
    if let Some(obj) = v.as_object_mut() {
        obj.insert("metadata".to_owned(), jsonb_object(&row.metadata));
        obj.insert("updated_at".to_owned(), serde_json::Value::Null);
        obj.insert(
            "progress_percent".to_owned(),
            serde_json::json!(progress_percent(&row)),
        );
    }
    Ok(Json(v))
}

/// POST /jobs/{id}/cancel — admin/maintainer; only pending/running jobs.
async fn cancel_job(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(job_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT status FROM s3_scan_jobs WHERE id = $1")
            .bind(job_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((status,)) = row else {
        return Err(ApiError::NotFound("Scan job not found".to_owned()));
    };
    let status = status.unwrap_or_else(|| "None".to_owned());
    if status != "pending" && status != "running" {
        return Err(ApiError::BadRequest(format!(
            "Cannot cancel job with status '{status}'"
        )));
    }
    sqlx::query("UPDATE s3_scan_jobs SET status = 'cancelled', completed_at = now() WHERE id = $1")
        .bind(job_id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Scan job cancelled successfully"
    })))
}

// ============================================
// Scan result endpoints
// ============================================

/// Scan-result row — schema columns; wire names mapped in `result_json`
/// (file_key←object_key, file_size←object_size, file_type←detected_file_type).
#[derive(sqlx::FromRow)]
struct ResultRow {
    id: i32,
    job_id: i32,
    bucket_config_id: i32,
    object_key: String,
    object_size: Option<i32>,
    detected_file_type: Option<String>,
    scan_status: Option<String>,
    is_malware: Option<bool>,
    is_pup: Option<bool>,
    is_threat: Option<bool>,
    threat_names: Option<serde_json::Value>,
    yara_matches: Option<serde_json::Value>,
    sandbox_status: Option<String>,
    sandbox_result: Option<serde_json::Value>,
    scanned_at: Option<NaiveDateTime>,
}

/// v1 result list-item shape. scan_engine/confidence_score have no backing
/// columns (defect #1) and are always null.
fn result_json(r: &ResultRow) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "scan_job_id": r.job_id,
        "bucket_config_id": r.bucket_config_id,
        "file_key": r.object_key,
        "file_size": r.object_size,
        "file_type": r.detected_file_type,
        "scan_status": r.scan_status,
        "is_malware": r.is_malware,
        "is_pup": r.is_pup,
        "is_threat": r.is_threat,
        "threat_names": jsonb_list(&r.threat_names),
        "yara_matches": jsonb_list(&r.yara_matches),
        "scan_engine": serde_json::Value::Null,
        "confidence_score": serde_json::Value::Null,
        "scanned_at": skauswatch_streams::py_isoformat_opt(r.scanned_at),
    })
}

/// v1 result detail shape — list shape plus sandbox fields and the
/// column-less error_message/metadata/created_at/updated_at (defect #1).
fn result_detail_json(r: &ResultRow) -> serde_json::Value {
    let mut v = result_json(r);
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "sandbox_status".to_owned(),
            serde_json::json!(r.sandbox_status),
        );
        obj.insert("sandbox_report".to_owned(), jsonb_object(&r.sandbox_result));
        obj.insert("error_message".to_owned(), serde_json::Value::Null);
        obj.insert(
            "metadata".to_owned(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
        obj.insert("created_at".to_owned(), serde_json::Value::Null);
        obj.insert("updated_at".to_owned(), serde_json::Value::Null);
    }
    v
}

/// WHERE-clause inputs for GET /results.
#[derive(Debug, Default)]
struct ResultFilters {
    bucket_config_id: Option<i32>,
    scan_status: Vec<String>,
    is_malware: Option<bool>,
    is_pup: Option<bool>,
    is_threat: Option<bool>,
    file_type: Option<String>,
    date_from: Option<NaiveDateTime>,
    date_to: Option<NaiveDateTime>,
}

fn push_result_filters(qb: &mut QueryBuilder<Postgres>, f: &ResultFilters) {
    if let Some(b) = f.bucket_config_id {
        qb.push(" AND bucket_config_id = ").push_bind(b);
    }
    if !f.scan_status.is_empty() {
        qb.push(" AND scan_status = ANY(")
            .push_bind(f.scan_status.clone())
            .push(")");
    }
    if let Some(x) = f.is_malware {
        qb.push(" AND is_malware = ").push_bind(x);
    }
    if let Some(x) = f.is_pup {
        qb.push(" AND is_pup = ").push_bind(x);
    }
    if let Some(x) = f.is_threat {
        qb.push(" AND is_threat = ").push_bind(x);
    }
    if let Some(t) = &f.file_type {
        qb.push(" AND detected_file_type = ").push_bind(t.clone());
    }
    if let Some(d) = f.date_from {
        qb.push(" AND scanned_at >= ").push_bind(d);
    }
    if let Some(d) = f.date_to {
        qb.push(" AND scanned_at <= ").push_bind(d);
    }
}

#[derive(Debug)]
struct ResultsQuery {
    filters: ResultFilters,
    page: i64,
    per_page: i64,
}

/// GET /results parse failures: pydantic-style validation errors, or the
/// distinct v1 `{"error": "Invalid date format", "details": ...}` 400 body
/// raised by datetime.fromisoformat before validation ran.
#[derive(Debug)]
enum ResultsQueryError {
    Api(ApiError),
    InvalidDate(String),
}

/// Mirrors the v1 GET /results parsing order: fromisoformat on the dates
/// first (custom 400 body), then pydantic ScanResultsQueryRequest checks —
/// scan_status enum, file_type <=50 + dot-normalization, page>=1,
/// per_page 1..=500 (after v1's pre-clamp min(per_page, 500)).
fn parse_results_params(pairs: &[(String, String)]) -> Result<ResultsQuery, ResultsQueryError> {
    let parse_date = |key: &str| -> Result<Option<NaiveDateTime>, ResultsQueryError> {
        match first(pairs, key).filter(|s| !s.is_empty()) {
            None => Ok(None),
            Some(s) => parse_datetime(s).map(Some).ok_or_else(|| {
                ResultsQueryError::InvalidDate(format!("Invalid isoformat string: '{s}'"))
            }),
        }
    };
    let date_from = parse_date("date_from")?;
    let date_to = parse_date("date_to")?;

    let scan_status = collect(pairs, "scan_status");
    if scan_status
        .iter()
        .any(|s| !SCAN_STATUSES.contains(&s.as_str()))
    {
        return Err(ResultsQueryError::Api(validation(
            "scan_status",
            SCAN_STATUS_MSG,
        )));
    }

    let file_type = match first(pairs, "file_type") {
        None => None,
        Some(raw) => {
            check_len(raw, "file_type", 0, 50).map_err(ResultsQueryError::Api)?;
            Some(normalize_file_type(raw))
        }
    };

    let page = first(pairs, "page")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1);
    if page < 1 {
        return Err(ResultsQueryError::Api(validation(
            "page",
            "Input should be greater than or equal to 1",
        )));
    }
    let per_page = first(pairs, "per_page")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(DEFAULT_PER_PAGE)
        .min(MAX_PER_PAGE);
    if per_page < 1 {
        return Err(ResultsQueryError::Api(validation(
            "per_page",
            "Input should be greater than or equal to 1",
        )));
    }

    let bool_arg = |key: &str| {
        first(pairs, key)
            .filter(|s| !s.is_empty())
            .map(|v| v.to_lowercase() == "true")
    };

    Ok(ResultsQuery {
        filters: ResultFilters {
            bucket_config_id: first(pairs, "bucket_config_id")
                .and_then(|v| v.parse::<i32>().ok())
                .filter(|v| *v != 0),
            scan_status,
            is_malware: bool_arg("is_malware"),
            is_pup: bool_arg("is_pup"),
            is_threat: bool_arg("is_threat"),
            file_type,
            date_from,
            date_to,
        },
        page,
        per_page,
    })
}

/// GET /results — filtered, paginated scan results, newest scan first.
async fn query_results(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Response, ApiError> {
    let q = match parse_results_params(&params) {
        Ok(q) => q,
        Err(ResultsQueryError::Api(e)) => return Err(e),
        Err(ResultsQueryError::InvalidDate(details)) => {
            return Ok((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "Invalid date format",
                    "details": details,
                })),
            )
                .into_response());
        }
    };
    let offset = (q.page - 1) * q.per_page;

    let mut qb = QueryBuilder::new(RESULT_COLUMNS);
    push_result_filters(&mut qb, &q.filters);
    qb.push(" ORDER BY scanned_at DESC LIMIT ")
        .push_bind(q.per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows = qb
        .build_query_as::<ResultRow>()
        .fetch_all(&state.db)
        .await?;

    let mut cq = QueryBuilder::new("SELECT COUNT(*) FROM s3_scan_results WHERE TRUE");
    push_result_filters(&mut cq, &q.filters);
    let total: i64 = cq.build_query_scalar().fetch_one(&state.db).await?;

    let items: Vec<serde_json::Value> = rows.iter().map(result_json).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": q.page,
        "per_page": q.per_page,
        "pages": total_pages(total, q.per_page),
    }))
    .into_response())
}

/// GET /results/{id} — single scan result detail.
async fn get_result(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(result_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut qb = QueryBuilder::new(RESULT_COLUMNS);
    qb.push(" AND id = ").push_bind(result_id);
    let row = qb
        .build_query_as::<ResultRow>()
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Scan result not found".to_owned()))?;
    Ok(Json(result_detail_json(&row)))
}

/// GET /statistics — aggregate counts over the last `period_days`
/// (default 30), optionally scoped to one bucket config.
async fn get_statistics(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let period_days = first(&params, "period_days")
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(30);
    let bucket_config_id = first(&params, "bucket_config_id")
        .and_then(|v| v.parse::<i32>().ok())
        .filter(|v| *v != 0);
    let from_date = Utc::now().naive_utc() - chrono::Duration::days(period_days);

    let push_scope = |qb: &mut QueryBuilder<Postgres>| {
        qb.push_bind(from_date);
        if let Some(b) = bucket_config_id {
            qb.push(" AND bucket_config_id = ").push_bind(b);
        }
    };

    let mut tq = QueryBuilder::new(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE is_malware), \
         COUNT(*) FILTER (WHERE is_pup), COUNT(*) FILTER (WHERE scan_status = 'clean'), \
         COUNT(*) FILTER (WHERE scan_status = 'error'), \
         COUNT(*) FILTER (WHERE scan_status = 'skipped') \
         FROM s3_scan_results WHERE scanned_at >= ",
    );
    push_scope(&mut tq);
    let (total_scanned, total_infected, total_pup, total_clean, total_error, total_skipped): (
        i64,
        i64,
        i64,
        i64,
        i64,
        i64,
    ) = tq.build_query_as().fetch_one(&state.db).await?;

    let mut fq = QueryBuilder::new(
        "SELECT detected_file_type, COUNT(*) FROM s3_scan_results WHERE scanned_at >= ",
    );
    push_scope(&mut fq);
    fq.push(" GROUP BY detected_file_type");
    let type_rows: Vec<(Option<String>, i64)> = fq.build_query_as().fetch_all(&state.db).await?;
    let mut by_file_type = serde_json::Map::new();
    for (file_type, count) in type_rows {
        // v1 truthiness: null AND empty-string file types are skipped.
        if let Some(t) = file_type.filter(|t| !t.is_empty()) {
            by_file_type.insert(t, serde_json::Value::from(count));
        }
    }

    let mut by_bucket = serde_json::Map::new();
    if bucket_config_id.is_none() {
        let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
            "SELECT b.name, COUNT(*), COUNT(*) FILTER (WHERE r.is_malware), \
             COUNT(*) FILTER (WHERE r.is_pup) FROM s3_scan_results r \
             JOIN s3_bucket_configs b ON b.id = r.bucket_config_id \
             WHERE r.scanned_at >= $1 GROUP BY b.name",
        )
        .bind(from_date)
        .fetch_all(&state.db)
        .await?;
        for (name, total, infected, pup) in rows {
            by_bucket.insert(
                name,
                serde_json::json!({"total": total, "infected": infected, "pup": pup}),
            );
        }
    }

    let mut lq =
        QueryBuilder::new("SELECT max(scanned_at) FROM s3_scan_results WHERE scanned_at >= ");
    push_scope(&mut lq);
    let last_scan_at: Option<NaiveDateTime> = lq.build_query_scalar().fetch_one(&state.db).await?;
    let last_scan_at = skauswatch_streams::py_isoformat_opt(last_scan_at);

    Ok(Json(serde_json::json!({
        "total_scanned": total_scanned,
        "total_infected": total_infected,
        "total_pup": total_pup,
        "total_clean": total_clean,
        "total_error": total_error,
        "total_skipped": total_skipped,
        "by_file_type": by_file_type,
        "by_bucket": by_bucket,
        "last_scan_at": last_scan_at,
        "scan_period_days": period_days,
    })))
}

// ============================================
// Schedule endpoints
// ============================================

/// Schedule row — schema columns; wire names last_triggered_at/
/// next_trigger_at map from last_run_at/next_run_at (defect #1).
#[derive(sqlx::FromRow)]
struct ScheduleRow {
    id: i32,
    bucket_config_id: i32,
    cron_expression: String,
    timezone: Option<String>,
    enabled: Option<bool>,
    last_run_at: Option<NaiveDateTime>,
    next_run_at: Option<NaiveDateTime>,
    created_at: Option<NaiveDateTime>,
    updated_at: Option<NaiveDateTime>,
}

/// GET /buckets/{id}/schedule — 404s for missing bucket, then missing
/// schedule. error_count/last_error_message have no columns → 0/null.
async fn get_schedule(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(bucket_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !bucket_exists(&state.db, bucket_id).await? {
        return Err(ApiError::NotFound(
            "Bucket configuration not found".to_owned(),
        ));
    }
    let row = sqlx::query_as::<_, ScheduleRow>(
        "SELECT id, bucket_config_id, cron_expression, timezone, enabled, last_run_at, \
         next_run_at, created_at, updated_at \
         FROM s3_scan_schedules WHERE bucket_config_id = $1",
    )
    .bind(bucket_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("No schedule configured for this bucket".to_owned()))?;

    Ok(Json(serde_json::json!({
        "id": row.id,
        "bucket_config_id": row.bucket_config_id,
        "cron_expression": row.cron_expression,
        "timezone": row.timezone,
        "enabled": row.enabled,
        "last_triggered_at": skauswatch_streams::py_isoformat_opt(row.last_run_at),
        "next_trigger_at": skauswatch_streams::py_isoformat_opt(row.next_run_at),
        "error_count": 0,
        "last_error_message": serde_json::Value::Null,
        "created_at": skauswatch_streams::py_isoformat_opt(row.created_at),
        "updated_at": skauswatch_streams::py_isoformat_opt(row.updated_at),
    })))
}

/// ScheduleSetRequest body.
#[derive(Deserialize)]
struct ScheduleBody {
    cron_expression: Option<String>,
    timezone: Option<String>,
    enabled: Option<bool>,
}

/// Mirrors pydantic ScheduleSetRequest: cron required <=255 chars, stripped,
/// 5-6 whitespace parts, restricted character set; timezone default UTC.
fn validate_schedule(b: &ScheduleBody) -> Result<(String, String, bool), ApiError> {
    let Some(raw) = b.cron_expression.as_deref() else {
        return Err(validation("cron_expression", "Field required"));
    };
    check_len(raw, "cron_expression", 0, 255)?;
    let cron = raw.trim().to_owned();
    let parts = cron.split_whitespace().count();
    if parts != 5 && parts != 6 {
        return Err(validation(
            "cron_expression",
            "Value error, Cron expression must have 5 or 6 parts (minute hour day month dow [year])",
        ));
    }
    const ALLOWED: &str = "0123456789,-/*L?WC# ";
    if !cron.chars().all(|c| ALLOWED.contains(c)) {
        return Err(validation(
            "cron_expression",
            "Value error, Cron expression contains invalid characters",
        ));
    }
    let timezone = b.timezone.clone().unwrap_or_else(|| "UTC".to_owned());
    check_len(&timezone, "timezone", 0, 50)?;
    Ok((cron, timezone, b.enabled.unwrap_or(true)))
}

#[derive(sqlx::FromRow)]
struct UpsertedScheduleRow {
    id: i32,
    bucket_config_id: i32,
    cron_expression: String,
    timezone: Option<String>,
    enabled: Option<bool>,
    created_at: Option<NaiveDateTime>,
    updated_at: Option<NaiveDateTime>,
}

/// PUT /buckets/{id}/schedule — admin/maintainer upsert keyed on the unique
/// bucket_config_id; updated_at set only on the update path (pyDAL parity).
async fn set_schedule(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(bucket_id): Path<i32>,
    Json(body): Json<ScheduleBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let (cron, timezone, enabled) = validate_schedule(&body)?;

    if !bucket_exists(&state.db, bucket_id).await? {
        return Err(ApiError::NotFound(
            "Bucket configuration not found".to_owned(),
        ));
    }

    let row = sqlx::query_as::<_, UpsertedScheduleRow>(
        "INSERT INTO s3_scan_schedules (bucket_config_id, cron_expression, timezone, enabled, \
         created_at) VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (bucket_config_id) DO UPDATE SET \
         cron_expression = EXCLUDED.cron_expression, timezone = EXCLUDED.timezone, \
         enabled = EXCLUDED.enabled, updated_at = now() \
         RETURNING id, bucket_config_id, cron_expression, timezone, enabled, \
         created_at, updated_at",
    )
    .bind(bucket_id)
    .bind(&cron)
    .bind(&timezone)
    .bind(enabled)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "message": "Schedule configured successfully",
        "schedule": {
            "id": row.id,
            "bucket_config_id": row.bucket_config_id,
            "cron_expression": row.cron_expression,
            "timezone": row.timezone,
            "enabled": row.enabled,
            "created_at": skauswatch_streams::py_isoformat_opt(row.created_at),
            "updated_at": skauswatch_streams::py_isoformat_opt(row.updated_at),
        }
    })))
}

/// DELETE /buckets/{id}/schedule — admin/maintainer.
async fn delete_schedule(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(bucket_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    if !bucket_exists(&state.db, bucket_id).await? {
        return Err(ApiError::NotFound(
            "Bucket configuration not found".to_owned(),
        ));
    }
    let existing: Option<(i32,)> =
        sqlx::query_as("SELECT id FROM s3_scan_schedules WHERE bucket_config_id = $1")
            .bind(bucket_id)
            .fetch_optional(&state.db)
            .await?;
    if existing.is_none() {
        return Err(ApiError::NotFound(
            "No schedule configured for this bucket".to_owned(),
        ));
    }
    sqlx::query("DELETE FROM s3_scan_schedules WHERE bucket_config_id = $1")
        .bind(bucket_id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Schedule removed successfully"
    })))
}

// ============================================
// Ad-hoc upload endpoints
// ============================================

/// lowercase hex of a digest output (md-5 0.11 and sha2 0.10 use different
/// `digest` trait generations, so a shared formatter beats trait imports).
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[derive(sqlx::FromRow)]
struct CreatedAdhocRow {
    id: i32,
    original_filename: String,
    file_size: Option<i32>,
    scan_status: Option<String>,
    file_sha256: Option<String>,
    scanned_at: Option<NaiveDateTime>,
}

/// POST /upload — multipart `file` field, <=100MB, md5+sha256 recorded.
/// Defect #1: rows land in adhoc_scan_results with a generated scan_id and
/// status `pending` (schema set) instead of v1's fake instant-"clean".
async fn upload_file(
    State(state): State<AppState>,
    user: CurrentUser,
    multipart: Result<Multipart, MultipartRejection>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    // Non-multipart request ≙ Quart's empty request.files dict.
    let Ok(mut multipart) = multipart else {
        return Err(ApiError::BadRequest(
            "No file provided in request".to_owned(),
        ));
    };

    let mut file: Option<(String, Bytes)> = None;
    loop {
        match multipart.next_field().await {
            Ok(Some(field)) => {
                if field.name() == Some("file") {
                    let filename = field.file_name().unwrap_or("").to_owned();
                    if filename.is_empty() {
                        return Err(ApiError::BadRequest("Empty filename".to_owned()));
                    }
                    let data = field
                        .bytes()
                        .await
                        .map_err(|e| ApiError::internal("upload read", e))?;
                    file = Some((filename, data));
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => return Err(ApiError::internal("multipart parse", e)),
        }
    }
    let Some((filename, data)) = file else {
        return Err(ApiError::BadRequest(
            "No file provided in request".to_owned(),
        ));
    };

    let file_size = data.len();
    if file_size > MAX_UPLOAD_MB * 1024 * 1024 {
        return Err(ApiError::BadRequest(format!(
            "File size exceeds {MAX_UPLOAD_MB}MB limit"
        )));
    }
    let size_i32 = i32::try_from(file_size).map_err(|e| ApiError::internal("upload size", e))?;
    let md5_hex = hex_lower(&<md5::Md5 as md5::Digest>::digest(&data));
    let sha256_hex = hex_lower(&<sha2::Sha256 as sha2::Digest>::digest(&data));
    let scan_uuid = uuid::Uuid::new_v4().to_string();

    let row = sqlx::query_as::<_, CreatedAdhocRow>(
        "INSERT INTO adhoc_scan_results (scan_id, uploaded_by, original_filename, file_size, \
         file_md5, file_sha256, scan_status, is_malware, is_pup, is_threat, uploaded_at) \
         VALUES ($1, $2, $3, $4, $5, $6, 'pending', FALSE, FALSE, FALSE, now()) \
         RETURNING id, original_filename, file_size, scan_status, file_sha256, scanned_at",
    )
    .bind(&scan_uuid)
    .bind(user.id)
    .bind(&filename)
    .bind(size_i32)
    .bind(&md5_hex)
    .bind(&sha256_hex)
    .fetch_one(&state.db)
    .await?;

    // v2 dispatch decision: v1's HTTP upload route was runtime-broken
    // (defect #1, `db.adhoc_scans`) and its service-layer sibling scanned
    // inline — nothing ever hit the stream. v2 dispatches the ad-hoc scan as
    // an s3scan:tasks message in the v1 task field shape: empty
    // bucket_config_id (no bucket config — the worker resolves the ad-hoc
    // bucket), object_key uses the v1 AdhocScanManager `{scan_id}/{filename}`
    // convention, and yara is on (ad-hoc results expose yara_matches).
    // Failures are swallowed with a warning, matching every v1 HTTP publish
    // site.
    let object_key = format!("{scan_uuid}/{filename}");
    state
        .publish_stream(
            skauswatch_streams::STREAM_S3_SCAN_TASKS,
            scan_task_fields(&ScanTaskMsg {
                job_id: &scan_uuid,
                bucket_config_id: None,
                object_key: &object_key,
                object_size: i64::from(size_i32),
                object_etag: "",
                scan_enabled: true,
                yara_enabled: true,
                submitted_at: &skauswatch_streams::py_now_isoformat(),
            }),
        )
        .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "File uploaded and scan initiated",
            "scan": {
                "id": row.id,
                "filename": row.original_filename,
                "file_size": row.file_size,
                "scan_status": row.scan_status,
                "file_hash_sha256": row.file_sha256,
                "scanned_at": skauswatch_streams::py_isoformat_opt(row.scanned_at),
            }
        })),
    ))
}

/// Ad-hoc scan row — schema columns; wire names filename/file_hash_*/
/// created_at map from original_filename/file_md5/file_sha256/uploaded_at.
#[derive(sqlx::FromRow)]
struct AdhocRow {
    id: i32,
    uploaded_by: i32,
    original_filename: String,
    file_size: Option<i32>,
    scan_status: Option<String>,
    is_malware: Option<bool>,
    is_pup: Option<bool>,
    is_threat: Option<bool>,
    threat_names: Option<serde_json::Value>,
    yara_matches: Option<serde_json::Value>,
    sandbox_result: Option<serde_json::Value>,
    file_md5: Option<String>,
    file_sha256: Option<String>,
    scanned_at: Option<NaiveDateTime>,
    uploaded_at: Option<NaiveDateTime>,
}

/// v1 owner gate: uploader or admin only (403 "Access denied").
fn check_upload_access(row: &AdhocRow, user: &CurrentUser) -> Result<(), ApiError> {
    if row.uploaded_by != user.id && user.role != "admin" {
        return Err(ApiError::Forbidden("Access denied".to_owned()));
    }
    Ok(())
}

async fn fetch_adhoc(db: &sqlx::PgPool, scan_id: i32) -> Result<Option<AdhocRow>, ApiError> {
    let mut qb = QueryBuilder::new(ADHOC_COLUMNS);
    qb.push(" AND id = ").push_bind(scan_id);
    Ok(qb.build_query_as::<AdhocRow>().fetch_optional(db).await?)
}

/// GET /upload/{id} — full ad-hoc result, owner or admin. Column-less
/// sandbox_status/scan_engine/confidence_score/error_message/metadata are
/// null/{} (defect #1).
async fn get_upload_result(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scan_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = fetch_adhoc(&state.db, scan_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Scan result not found".to_owned()))?;
    check_upload_access(&row, &user)?;

    Ok(Json(serde_json::json!({
        "id": row.id,
        "filename": row.original_filename,
        "file_size": row.file_size,
        "scan_status": row.scan_status,
        "is_malware": row.is_malware,
        "is_pup": row.is_pup,
        "is_threat": row.is_threat,
        "threat_names": jsonb_list(&row.threat_names),
        "yara_matches": jsonb_list(&row.yara_matches),
        "sandbox_status": serde_json::Value::Null,
        "sandbox_report": jsonb_object(&row.sandbox_result),
        "scan_engine": serde_json::Value::Null,
        "confidence_score": serde_json::Value::Null,
        "file_hash_md5": row.file_md5,
        "file_hash_sha256": row.file_sha256,
        "error_message": serde_json::Value::Null,
        "metadata": serde_json::Value::Object(serde_json::Map::new()),
        "scanned_at": skauswatch_streams::py_isoformat_opt(row.scanned_at),
        "created_at": skauswatch_streams::py_isoformat_opt(row.uploaded_at),
    })))
}

/// GET /upload/history — the caller's uploads (admins see everyone's),
/// newest upload first.
async fn list_upload_history(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (page, per_page) = parse_page_params(&params);
    let offset = (page - 1) * per_page;
    let scope_to_user = user.role != "admin";

    let mut qb = QueryBuilder::new(ADHOC_COLUMNS);
    if scope_to_user {
        qb.push(" AND uploaded_by = ").push_bind(user.id);
    }
    qb.push(" ORDER BY uploaded_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows = qb.build_query_as::<AdhocRow>().fetch_all(&state.db).await?;

    let mut cq = QueryBuilder::new("SELECT COUNT(*) FROM adhoc_scan_results WHERE TRUE");
    if scope_to_user {
        cq.push(" AND uploaded_by = ").push_bind(user.id);
    }
    let total: i64 = cq.build_query_scalar().fetch_one(&state.db).await?;

    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "filename": r.original_filename,
                "file_size": r.file_size,
                "scan_status": r.scan_status,
                "is_malware": r.is_malware,
                "is_pup": r.is_pup,
                "is_threat": r.is_threat,
                "file_hash_sha256": r.file_sha256,
                "scanned_at": skauswatch_streams::py_isoformat_opt(r.scanned_at),
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": total_pages(total, per_page),
    })))
}

/// DELETE /upload/{id} — owner or admin.
async fn delete_upload_scan(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scan_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row = fetch_adhoc(&state.db, scan_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Scan result not found".to_owned()))?;
    check_upload_access(&row, &user)?;
    sqlx::query("DELETE FROM adhoc_scan_results WHERE id = $1")
        .bind(scan_id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Ad-hoc scan deleted successfully"
    })))
}

// ============================================
// Threat-intelligence integration endpoints
// ============================================

/// v1 threat-level mapping for scan-result IOCs.
fn threat_level_for(is_malware: bool, is_pup: bool) -> &'static str {
    if is_malware {
        "high"
    } else if is_pup {
        "medium"
    } else {
        "low"
    }
}

/// Scan-result subset feeding the TI endpoints — the hash now comes from
/// the real file_sha256 column (defect #1; v1 read a non-existent metadata).
#[derive(sqlx::FromRow)]
struct TiSourceRow {
    bucket_config_id: i32,
    object_key: String,
    is_malware: Option<bool>,
    is_pup: Option<bool>,
    is_threat: Option<bool>,
    threat_names: Option<serde_json::Value>,
    file_sha256: Option<String>,
}

async fn fetch_ti_source(
    db: &sqlx::PgPool,
    result_id: i32,
) -> Result<Option<TiSourceRow>, ApiError> {
    Ok(sqlx::query_as::<_, TiSourceRow>(
        "SELECT bucket_config_id, object_key, is_malware, is_pup, is_threat, \
         threat_names, file_sha256 FROM s3_scan_results WHERE id = $1",
    )
    .bind(result_id)
    .fetch_optional(db)
    .await?)
}

/// Indicator row for the TI enrichment / hash lookup responses.
#[derive(sqlx::FromRow)]
struct IndicatorRow {
    id: i32,
    indicator_type: String,
    threat_level: Option<String>,
    confidence: Option<f64>,
    source: Option<String>,
    tags: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
    created_at: Option<NaiveDateTime>,
}

/// Fetches a live (non-expired) `hash` indicator for a value — defect #3
/// keeps reads and writes on the same type.
async fn fetch_hash_indicator(
    db: &sqlx::PgPool,
    value: &str,
) -> Result<Option<IndicatorRow>, ApiError> {
    Ok(sqlx::query_as::<_, IndicatorRow>(
        "SELECT id, indicator_type, threat_level, confidence, source, tags, metadata, \
         created_at FROM threat_indicators \
         WHERE indicator_type = $1 AND value = $2 \
         AND (expires_at IS NULL OR expires_at > $3) LIMIT 1",
    )
    .bind(HASH_IOC_TYPE)
    .bind(value)
    .bind(Utc::now().naive_utc())
    .fetch_optional(db)
    .await?)
}

/// POST /results/{id}/create-indicator — admin/maintainer; promotes a
/// threat-flagged scan result's sha256 into threat_indicators (type `hash`
/// per defect #3, confidence 50 since no confidence_score column exists).
async fn create_ti_indicator(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(result_id): Path<i32>,
) -> Result<Response, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let result = fetch_ti_source(&state.db, result_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Scan result not found".to_owned()))?;
    if !result.is_threat.unwrap_or(false) {
        return Err(ApiError::BadRequest(
            "Scan result is not marked as threat".to_owned(),
        ));
    }
    let Some(hash) = result.file_sha256.as_deref().filter(|h| !h.is_empty()) else {
        return Err(ApiError::BadRequest(
            "No file hash available in scan result".to_owned(),
        ));
    };

    let existing: Option<(i32,)> =
        sqlx::query_as("SELECT id FROM threat_indicators WHERE indicator_type = $1 AND value = $2")
            .bind(HASH_IOC_TYPE)
            .bind(hash)
            .fetch_optional(&state.db)
            .await?;
    if let Some((indicator_id,)) = existing {
        return Ok(Json(serde_json::json!({
            "message": "Threat indicator already exists",
            "indicator_id": indicator_id,
        }))
        .into_response());
    }

    let threat_level = threat_level_for(
        result.is_malware.unwrap_or(false),
        result.is_pup.unwrap_or(false),
    );
    // v1: int((confidence_score or 0.5) * 100) — no such column, so 50.
    let confidence = 50.0_f64;
    let metadata = serde_json::json!({
        "scan_result_id": result_id,
        "file_key": result.object_key,
        "bucket_config_id": result.bucket_config_id,
        "scan_engine": serde_json::Value::Null,
    });

    #[derive(sqlx::FromRow)]
    struct CreatedIocRow {
        id: i32,
        indicator_type: String,
        value: String,
        threat_level: Option<String>,
        created_at: Option<NaiveDateTime>,
    }
    let row = sqlx::query_as::<_, CreatedIocRow>(
        "INSERT INTO threat_indicators (indicator_type, value, threat_level, confidence, \
         source, tags, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now()) \
         RETURNING id, indicator_type, value, threat_level, created_at",
    )
    .bind(HASH_IOC_TYPE)
    .bind(hash)
    .bind(threat_level)
    .bind(confidence)
    .bind(format!("s3-scan-result-{result_id}"))
    .bind(jsonb_list(&result.threat_names))
    .bind(&metadata)
    .fetch_one(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Threat indicator created successfully",
            "indicator": {
                "id": row.id,
                "indicator_type": row.indicator_type,
                "value": row.value,
                "threat_level": row.threat_level,
                "created_at": skauswatch_streams::py_isoformat_opt(row.created_at),
            }
        })),
    )
        .into_response())
}

/// GET /results/{id}/ti-enrichment — live `hash` indicator for the result's
/// sha256; `{enrichment: null, found: false}` when hashless or unmatched.
async fn get_ti_enrichment(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(result_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let result = fetch_ti_source(&state.db, result_id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Scan result not found".to_owned()))?;
    let Some(hash) = result.file_sha256.as_deref().filter(|h| !h.is_empty()) else {
        return Ok(Json(
            serde_json::json!({"enrichment": serde_json::Value::Null, "found": false}),
        ));
    };

    let Some(ioc) = fetch_hash_indicator(&state.db, hash).await? else {
        return Ok(Json(
            serde_json::json!({"enrichment": serde_json::Value::Null, "found": false}),
        ));
    };
    Ok(Json(serde_json::json!({
        "found": true,
        "enrichment": {
            "indicator_id": ioc.id,
            "indicator_type": ioc.indicator_type,
            "value": hash,
            "threat_level": ioc.threat_level,
            "confidence": ioc.confidence,
            "source": ioc.source,
            "tags": jsonb_list(&ioc.tags),
            "metadata": jsonb_object(&ioc.metadata),
        }
    })))
}

/// HashLookupRequest body.
#[derive(Deserialize)]
struct HashLookupBody {
    hash_value: Option<String>,
}

/// Mirrors pydantic HashLookupRequest: raw length 32..=256, then stripped +
/// UPPERCASED (v1 quirk — lookups are case-sensitive against stored hashes),
/// hex-only, and exactly MD5 (32) or SHA256 (64) long.
fn validate_hash_value(b: &HashLookupBody) -> Result<String, ApiError> {
    let Some(raw) = b.hash_value.as_deref() else {
        return Err(validation("hash_value", "Field required"));
    };
    check_len(raw, "hash_value", 32, 256)?;
    let v = raw.trim().to_uppercase();
    if !v.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(validation(
            "hash_value",
            "Value error, Hash must be valid hexadecimal",
        ));
    }
    let n = v.chars().count();
    if n != 32 && n != 64 {
        return Err(validation(
            "hash_value",
            "Value error, Hash must be MD5 (32 chars) or SHA256 (64 chars)",
        ));
    }
    Ok(v)
}

/// POST /hash-lookup — checks a normalized hash against live `hash`
/// indicators (defect #3 type mapping).
async fn hash_lookup(
    State(state): State<AppState>,
    _user: CurrentUser,
    Json(body): Json<HashLookupBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let hash = validate_hash_value(&body)?;
    let Some(ioc) = fetch_hash_indicator(&state.db, &hash).await? else {
        return Ok(Json(serde_json::json!({"found": false, "hash": hash})));
    };
    Ok(Json(serde_json::json!({
        "found": true,
        "hash": hash,
        "indicator": {
            "id": ioc.id,
            "threat_level": ioc.threat_level,
            "confidence": ioc.confidence,
            "source": ioc.source,
            "tags": jsonb_list(&ioc.tags),
            "metadata": jsonb_object(&ioc.metadata),
            "created_at": skauswatch_streams::py_isoformat_opt(ioc.created_at),
        }
    })))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};

    /// Boots a TestServer with only the s3-scan router nested under /api/v1
    /// — self-contained regardless of routes/mod.rs wiring.
    fn test_server() -> axum_test::TestServer {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        let state = AppStateInner::for_tests(client);
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    fn user_with_role(role: &str) -> CurrentUser {
        CurrentUser {
            id: 1,
            email: "user@example.com".to_owned(),
            full_name: None,
            role: role.to_owned(),
            is_active: true,
            mfa_enabled: false,
            created_at: None,
        }
    }

    fn pairs(kv: &[(&str, &str)]) -> Vec<(String, String)> {
        kv.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn dt(s: &str) -> NaiveDateTime {
        match NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.f") {
            Ok(t) => t,
            Err(e) => panic!("bad test datetime {s}: {e}"),
        }
    }

    #[test]
    fn scan_task_fields_match_v1_names_order_and_encoding() {
        // Job-level dispatch (bucket scan trigger).
        let fields = scan_task_fields(&ScanTaskMsg {
            job_id: "6f9b7a1c-0000-0000-0000-000000000000",
            bucket_config_id: Some(3),
            object_key: "",
            object_size: 0,
            object_etag: "",
            scan_enabled: true,
            yara_enabled: false,
            submitted_at: "2026-07-22T09:30:00.000042",
        });
        assert_eq!(
            fields,
            pairs(&[
                ("job_id", "6f9b7a1c-0000-0000-0000-000000000000"),
                ("bucket_config_id", "3"),
                ("object_key", ""),
                ("object_size", "0"),
                ("object_etag", ""),
                // Python str(bool) capitalization, per redis-py xadd parity.
                ("scan_enabled", "True"),
                ("yara_enabled", "False"),
                ("submitted_at", "2026-07-22T09:30:00.000042"),
            ])
        );
    }

    #[test]
    fn scan_task_fields_adhoc_dispatch_encodes_none_as_empty() {
        let fields = scan_task_fields(&ScanTaskMsg {
            job_id: "adhoc-uuid",
            bucket_config_id: None,
            object_key: "adhoc-uuid/evil.exe",
            object_size: 1024,
            object_etag: "",
            scan_enabled: true,
            yara_enabled: true,
            submitted_at: "2026-07-22T09:30:00.000042",
        });
        assert_eq!(
            fields,
            pairs(&[
                ("job_id", "adhoc-uuid"),
                // v1 encoder: None → "".
                ("bucket_config_id", ""),
                ("object_key", "adhoc-uuid/evil.exe"),
                ("object_size", "1024"),
                ("object_etag", ""),
                ("scan_enabled", "True"),
                ("yara_enabled", "True"),
                ("submitted_at", "2026-07-22T09:30:00.000042"),
            ])
        );
    }

    #[tokio::test]
    async fn protected_endpoints_require_a_token() {
        let server = test_server();
        let responses = [
            server.get("/api/v1/s3-scan/buckets").await,
            server.post("/api/v1/s3-scan/buckets").await,
            server.get("/api/v1/s3-scan/buckets/1").await,
            server.put("/api/v1/s3-scan/buckets/1").await,
            server.delete("/api/v1/s3-scan/buckets/1").await,
            server.post("/api/v1/s3-scan/buckets/1/test").await,
            server.post("/api/v1/s3-scan/buckets/1/scan").await,
            server.get("/api/v1/s3-scan/buckets/1/schedule").await,
            server.put("/api/v1/s3-scan/buckets/1/schedule").await,
            server.delete("/api/v1/s3-scan/buckets/1/schedule").await,
            server.get("/api/v1/s3-scan/jobs").await,
            server.get("/api/v1/s3-scan/jobs/1").await,
            server.post("/api/v1/s3-scan/jobs/1/cancel").await,
            server.get("/api/v1/s3-scan/results").await,
            server.get("/api/v1/s3-scan/results/1").await,
            server
                .post("/api/v1/s3-scan/results/1/create-indicator")
                .await,
            server.get("/api/v1/s3-scan/results/1/ti-enrichment").await,
            server.get("/api/v1/s3-scan/statistics").await,
            server.post("/api/v1/s3-scan/upload").await,
            server.get("/api/v1/s3-scan/upload/history").await,
            server.get("/api/v1/s3-scan/upload/1").await,
            server.delete("/api/v1/s3-scan/upload/1").await,
            server.post("/api/v1/s3-scan/hash-lookup").await,
        ];
        for res in responses {
            res.assert_status(StatusCode::UNAUTHORIZED);
            let body: serde_json::Value = res.json();
            assert_eq!(body["error"], "Unauthorized");
            assert_eq!(body["detail"], "Missing authorization header");
        }
    }

    #[tokio::test]
    async fn garbage_bearer_token_is_rejected() {
        let server = test_server();
        let res = server
            .get("/api/v1/s3-scan/buckets")
            .authorization_bearer("not-a-jwt")
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Unauthorized");
        assert_eq!(body["detail"], "Invalid token");
    }

    #[test]
    fn role_gates_match_v1() {
        // admin/maintainer gates: create/update/test bucket, trigger scan,
        // cancel job, schedule put/delete, create-indicator.
        for role in ["admin", "maintainer"] {
            assert!(
                user_with_role(role)
                    .require_role(&["admin", "maintainer"])
                    .is_ok()
            );
        }
        match user_with_role("viewer").require_role(&["admin", "maintainer"]) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Insufficient permissions"),
            other => panic!("expected 403 for viewer, got {other:?}"),
        }
        // delete bucket is admin-only.
        assert!(user_with_role("admin").require_role(&["admin"]).is_ok());
        for role in ["maintainer", "viewer"] {
            assert!(matches!(
                user_with_role(role).require_role(&["admin"]),
                Err(ApiError::Forbidden(_))
            ));
        }
    }

    #[test]
    fn upload_owner_gate_allows_owner_and_admin_only() {
        let row = AdhocRow {
            id: 7,
            uploaded_by: 42,
            original_filename: "a.bin".to_owned(),
            file_size: Some(3),
            scan_status: Some("pending".to_owned()),
            is_malware: Some(false),
            is_pup: Some(false),
            is_threat: Some(false),
            threat_names: None,
            yara_matches: None,
            sandbox_result: None,
            file_md5: None,
            file_sha256: None,
            scanned_at: None,
            uploaded_at: None,
        };
        let mut owner = user_with_role("viewer");
        owner.id = 42;
        assert!(check_upload_access(&row, &owner).is_ok());
        assert!(check_upload_access(&row, &user_with_role("admin")).is_ok());
        match check_upload_access(&row, &user_with_role("maintainer")) {
            Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Access denied"),
            other => panic!("expected 403, got {other:?}"),
        }
    }

    #[test]
    fn mask_credentials_matches_python_semantics() {
        assert_eq!(mask_access_key("abcd"), "****");
        assert_eq!(mask_access_key("AKIA1234"), "AKIA****");
        assert_eq!(mask_secret_key("abcd"), "****");
        // Python quirk: 5..=8 chars → head4 + "" + last4 (overlap preserved).
        assert_eq!(mask_secret_key("abcdef"), "abcdcdef");
        assert_eq!(mask_secret_key("0123456789AB"), "0123****89AB");
    }

    #[test]
    fn bucket_create_validation_required_fields_and_defaults() {
        let full = BucketCreateBody {
            name: Some("minio".to_owned()),
            endpoint_url: Some(" https://minio.local:9000 ".to_owned()),
            bucket_name: Some("scans".to_owned()),
            access_key_id: Some("AKIA1234".to_owned()),
            secret_access_key: Some("secretsecret".to_owned()),
            region: None,
            use_ssl: None,
            path_style: None,
            prefix_filter: None,
            file_types_filter: Some(vec!["EXE".to_owned(), ".Dll".to_owned()]),
            max_file_size_mb: None,
            scan_enabled: None,
            yara_enabled: None,
        };
        match validate_bucket_create(&full) {
            Ok(v) => {
                assert_eq!(v.endpoint_url, "https://minio.local:9000");
                assert_eq!(v.region, "us-east-1");
                assert!(v.use_ssl);
                assert!(v.path_style); // pydantic default true, not the DB default
                assert_eq!(v.max_file_size_mb, 100);
                assert!(v.scan_enabled);
                assert!(!v.yara_enabled);
                assert_eq!(
                    v.file_types_filter,
                    Some(vec![".exe".to_owned(), ".dll".to_owned()])
                );
            }
            Err(e) => panic!("expected ok, got {e:?}"),
        }

        let missing_name = BucketCreateBody {
            name: None,
            ..clone_create(&full)
        };
        assert!(matches!(
            validate_bucket_create(&missing_name),
            Err(ApiError::Validation(_))
        ));

        let bad_scheme = BucketCreateBody {
            endpoint_url: Some("ftp://x".to_owned()),
            ..clone_create(&full)
        };
        assert!(matches!(
            validate_bucket_create(&bad_scheme),
            Err(ApiError::Validation(_))
        ));

        let too_big = BucketCreateBody {
            max_file_size_mb: Some(501),
            ..clone_create(&full)
        };
        assert!(matches!(
            validate_bucket_create(&too_big),
            Err(ApiError::Validation(_))
        ));
    }

    fn clone_create(b: &BucketCreateBody) -> BucketCreateBody {
        BucketCreateBody {
            name: b.name.clone(),
            endpoint_url: b.endpoint_url.clone(),
            bucket_name: b.bucket_name.clone(),
            access_key_id: b.access_key_id.clone(),
            secret_access_key: b.secret_access_key.clone(),
            region: b.region.clone(),
            use_ssl: b.use_ssl,
            path_style: b.path_style,
            prefix_filter: b.prefix_filter.clone(),
            file_types_filter: b.file_types_filter.clone(),
            max_file_size_mb: b.max_file_size_mb,
            scan_enabled: b.scan_enabled,
            yara_enabled: b.yara_enabled,
        }
    }

    #[test]
    fn bucket_update_validation_is_per_present_field() {
        let empty = BucketUpdateBody {
            name: None,
            endpoint_url: None,
            bucket_name: None,
            access_key_id: None,
            secret_access_key: None,
            region: None,
            use_ssl: None,
            path_style: None,
            prefix_filter: None,
            file_types_filter: None,
            max_file_size_mb: None,
            scan_enabled: None,
            yara_enabled: None,
        };
        match validate_bucket_update(&empty) {
            Ok(v) => assert!(!v.has_updates()),
            Err(e) => panic!("expected ok, got {e:?}"),
        }

        let bad_endpoint = BucketUpdateBody {
            endpoint_url: Some("minio.local".to_owned()),
            ..empty_update()
        };
        assert!(matches!(
            validate_bucket_update(&bad_endpoint),
            Err(ApiError::Validation(_))
        ));

        let normalized = BucketUpdateBody {
            file_types_filter: Some(vec![" ZIP ".to_owned()]),
            ..empty_update()
        };
        match validate_bucket_update(&normalized) {
            Ok(v) => {
                assert!(v.has_updates());
                assert_eq!(v.file_types_filter, Some(vec![".zip".to_owned()]));
            }
            Err(e) => panic!("expected ok, got {e:?}"),
        }
    }

    fn empty_update() -> BucketUpdateBody {
        BucketUpdateBody {
            name: None,
            endpoint_url: None,
            bucket_name: None,
            access_key_id: None,
            secret_access_key: None,
            region: None,
            use_ssl: None,
            path_style: None,
            prefix_filter: None,
            file_types_filter: None,
            max_file_size_mb: None,
            scan_enabled: None,
            yara_enabled: None,
        }
    }

    #[test]
    fn cron_validation_matches_v1() {
        let ok5 = ScheduleBody {
            cron_expression: Some(" 0 2 * * * ".to_owned()),
            timezone: None,
            enabled: None,
        };
        match validate_schedule(&ok5) {
            Ok((cron, tz, enabled)) => {
                assert_eq!(cron, "0 2 * * *");
                assert_eq!(tz, "UTC");
                assert!(enabled);
            }
            Err(e) => panic!("expected ok, got {e:?}"),
        }
        let ok6 = ScheduleBody {
            cron_expression: Some("0 2 * * 1-5 2026".to_owned()),
            timezone: Some("America/Chicago".to_owned()),
            enabled: Some(false),
        };
        assert!(validate_schedule(&ok6).is_ok());

        for bad in ["0 2 *", "0 2 * * * * *", "0 2 * * mon", "0 2 * * $"] {
            let body = ScheduleBody {
                cron_expression: Some(bad.to_owned()),
                timezone: None,
                enabled: None,
            };
            assert!(
                matches!(validate_schedule(&body), Err(ApiError::Validation(_))),
                "expected validation error for {bad:?}"
            );
        }
        let missing = ScheduleBody {
            cron_expression: None,
            timezone: None,
            enabled: None,
        };
        assert!(matches!(
            validate_schedule(&missing),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn hash_lookup_validation_normalizes_and_bounds() {
        let body = |v: &str| HashLookupBody {
            hash_value: Some(v.to_owned()),
        };
        match validate_hash_value(&body("d41d8cd98f00b204e9800998ecf8427e")) {
            Ok(v) => assert_eq!(v, "D41D8CD98F00B204E9800998ECF8427E"),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert!(validate_hash_value(&body(sha)).is_ok());

        // Too short overall (pydantic min_length=32 fires first).
        assert!(matches!(
            validate_hash_value(&body("abc123")),
            Err(ApiError::Validation(_))
        ));
        // Non-hex.
        assert!(matches!(
            validate_hash_value(&body("z41d8cd98f00b204e9800998ecf8427e")),
            Err(ApiError::Validation(_))
        ));
        // Hex but 40 chars (neither MD5 nor SHA256).
        assert!(matches!(
            validate_hash_value(&body("da39a3ee5e6b4b0d3255bfef95601890afd80709")),
            Err(ApiError::Validation(_))
        ));
        // Missing.
        assert!(matches!(
            validate_hash_value(&HashLookupBody { hash_value: None }),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn results_params_parse_booleans_dates_and_bounds() {
        let ok = parse_results_params(&pairs(&[
            ("is_malware", "TRUE"),
            ("is_pup", "1"),
            ("file_type", "EXE"),
            ("scan_status", "clean"),
            ("scan_status", "infected"),
            ("bucket_config_id", "0"),
            ("date_from", "2026-07-01T00:00:00"),
            ("per_page", "1000"),
        ]));
        match ok {
            Ok(q) => {
                assert_eq!(q.filters.is_malware, Some(true)); // lower()=="true"
                assert_eq!(q.filters.is_pup, Some(false)); // "1" is not "true"
                assert_eq!(q.filters.is_threat, None); // absent
                assert_eq!(q.filters.file_type.as_deref(), Some(".exe"));
                assert_eq!(q.filters.scan_status, vec!["clean", "infected"]);
                assert_eq!(q.filters.bucket_config_id, None); // 0 is falsy
                assert!(q.filters.date_from.is_some());
                assert_eq!((q.page, q.per_page), (1, 500)); // min(1000, 500)
            }
            Err(e) => panic!("expected ok, got {e:?}"),
        }

        assert!(matches!(
            parse_results_params(&pairs(&[("page", "0")])),
            Err(ResultsQueryError::Api(ApiError::Validation(_)))
        ));
        assert!(matches!(
            parse_results_params(&pairs(&[("per_page", "0")])),
            Err(ResultsQueryError::Api(ApiError::Validation(_)))
        ));
        assert!(matches!(
            parse_results_params(&pairs(&[("scan_status", "quarantined")])),
            Err(ResultsQueryError::Api(ApiError::Validation(_)))
        ));
        match parse_results_params(&pairs(&[("date_to", "yesterday")])) {
            Err(ResultsQueryError::InvalidDate(msg)) => {
                assert_eq!(msg, "Invalid isoformat string: 'yesterday'");
            }
            other => panic!("expected InvalidDate, got {other:?}"),
        }
    }

    #[test]
    fn jobs_params_accumulate_lists_and_skip_zero_bucket() {
        let q = parse_jobs_params(&pairs(&[
            ("page", "2"),
            ("per_page", "9999"),
            ("bucket_config_id", "0"),
            ("job_type", "full_scan"),
            ("job_type", "prefix_scan"),
            ("status", "running"),
        ]));
        assert_eq!((q.page, q.per_page), (2, 500));
        assert_eq!(q.bucket_config_id, None);
        assert_eq!(q.job_type, vec!["full_scan", "prefix_scan"]);
        assert_eq!(q.status, vec!["running"]);

        let defaults = parse_jobs_params(&pairs(&[("page", "abc")]));
        assert_eq!((defaults.page, defaults.per_page), (1, 50));
        assert!(defaults.job_type.is_empty());
    }

    #[test]
    fn total_pages_matches_python_ceiling_division() {
        assert_eq!(total_pages(0, 50), 0);
        assert_eq!(total_pages(1, 50), 1);
        assert_eq!(total_pages(500, 50), 10);
        assert_eq!(total_pages(501, 50), 11);
    }

    #[test]
    fn trigger_body_prefix_filter_bounded_at_500() {
        let long = "x".repeat(501);
        let err = check_len(&long, "prefix_filter", 0, 500);
        assert!(matches!(err, Err(ApiError::Validation(_))));
        assert!(check_len(&"x".repeat(500), "prefix_filter", 0, 500).is_ok());
    }

    #[test]
    fn threat_level_mapping_matches_v1() {
        assert_eq!(threat_level_for(true, true), "high");
        assert_eq!(threat_level_for(true, false), "high");
        assert_eq!(threat_level_for(false, true), "medium");
        assert_eq!(threat_level_for(false, false), "low");
    }

    fn job_row() -> JobRow {
        JobRow {
            id: 3,
            bucket_config_id: 9,
            job_type: "full_scan".to_owned(),
            status: Some("running".to_owned()),
            scanned_objects: Some(30),
            infected_objects: Some(5),
            pup_objects: Some(5),
            error_count: Some(5),
            skipped_objects: Some(5),
            started_at: Some(dt("2026-07-15T10:00:00")),
            completed_at: None,
            error_message: None,
            metadata: Some(serde_json::json!({
                "prefix_filter": "incoming/",
                "force_rescan": true,
            })),
            created_at: Some(dt("2026-07-15T09:59:00.000042")),
        }
    }

    #[test]
    fn job_json_maps_schema_columns_to_v1_field_names() {
        let v = job_json(&job_row());
        assert_eq!(v["files_scanned"], 30);
        assert_eq!(v["files_infected"], 5);
        assert_eq!(v["files_pup"], 5);
        assert_eq!(v["files_error"], 5);
        assert_eq!(v["files_skipped"], 5);
        assert_eq!(v["prefix_filter"], "incoming/");
        assert_eq!(v["force_rescan"], true);
        assert_eq!(v.get("metadata"), None); // list shape has no metadata
        // Python isoformat: fraction omitted at micros==0, six digits else.
        assert_eq!(v["started_at"], "2026-07-15T10:00:00");
        assert_eq!(v["completed_at"], serde_json::Value::Null);
        assert_eq!(v["created_at"], "2026-07-15T09:59:00.000042");

        let mut bare = job_row();
        bare.metadata = None;
        let v = job_json(&bare);
        assert_eq!(v["prefix_filter"], serde_json::Value::Null);
        assert_eq!(v["force_rescan"], false);
    }

    #[test]
    fn progress_percent_only_while_running() {
        let running = job_row(); // 30 of 50 total
        assert!((progress_percent(&running) - 60.0).abs() < f64::EPSILON);

        let mut done = job_row();
        done.status = Some("completed".to_owned());
        assert!((progress_percent(&done) - 0.0).abs() < f64::EPSILON);

        let mut empty = job_row();
        empty.scanned_objects = None;
        empty.infected_objects = None;
        empty.pup_objects = None;
        empty.error_count = None;
        empty.skipped_objects = None;
        assert!((progress_percent(&empty) - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn result_detail_json_nulls_columnless_v1_fields() {
        let row = ResultRow {
            id: 1,
            job_id: 2,
            bucket_config_id: 3,
            object_key: "a/b.exe".to_owned(),
            object_size: Some(1024),
            detected_file_type: Some(".exe".to_owned()),
            scan_status: Some("infected".to_owned()),
            is_malware: Some(true),
            is_pup: Some(false),
            is_threat: Some(true),
            threat_names: Some(serde_json::json!(["Eicar"])),
            yara_matches: None,
            sandbox_status: None,
            sandbox_result: None,
            scanned_at: Some(dt("2026-07-15T10:00:00")),
        };
        let v = result_detail_json(&row);
        assert_eq!(v["scanned_at"], "2026-07-15T10:00:00"); // isoformat, no fraction
        assert_eq!(v["scan_job_id"], 2);
        assert_eq!(v["file_key"], "a/b.exe");
        assert_eq!(v["file_size"], 1024);
        assert_eq!(v["file_type"], ".exe");
        assert_eq!(v["threat_names"], serde_json::json!(["Eicar"]));
        assert_eq!(v["yara_matches"], serde_json::json!([]));
        assert_eq!(v["scan_engine"], serde_json::Value::Null);
        assert_eq!(v["confidence_score"], serde_json::Value::Null);
        assert_eq!(v["sandbox_report"], serde_json::json!({}));
        assert_eq!(v["error_message"], serde_json::Value::Null);
        assert_eq!(v["metadata"], serde_json::json!({}));
        assert_eq!(v["created_at"], serde_json::Value::Null);
        assert_eq!(v["updated_at"], serde_json::Value::Null);
    }

    #[test]
    fn hex_lower_and_digests_are_stable() {
        assert_eq!(
            hex_lower(&<md5::Md5 as md5::Digest>::digest(b"abc")),
            "900150983cd24fb0d6963f7d28e17f72"
        );
        assert_eq!(
            hex_lower(&<sha2::Sha256 as sha2::Digest>::digest(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn file_type_normalization_matches_pydantic_validator() {
        assert_eq!(normalize_file_type("EXE"), ".exe");
        assert_eq!(normalize_file_type(" .Zip "), ".zip");
        assert_eq!(normalize_file_type(""), "."); // v1 quirk: empty → "."
    }
}
