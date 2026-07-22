//! /api/v1/threat-intel — IOC CRUD, bulk upsert, search, lookup, statistics,
//! and the static feed catalog. Contract: docs/v2-port/manager-contract.md
//! §threat-intel; Python source of truth:
//! services/manager/api/v1/threat_intel.py (+ validators/pydantic_models.py
//! IOCCreateRequest / IOCSearchRequest / IOCBulkCreateRequest).
//!
//! Port decisions (same conventions as routes/users.rs and routes/alerts.rs):
//! v1's bare `{"error": ...}` bodies map onto the `ApiError` envelope;
//! `page`/`per_page` on GET /iocs are clamped to ≥1 (v1 divides by zero on
//! per_page=0); v1 accepts `tags` in IOCSearchRequest but never applies it as
//! a filter — that behavior is preserved.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::Deserialize;
use sqlx::{Postgres, QueryBuilder};

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::state::AppState;

/// v1 `IndicatorType` enum values.
const INDICATOR_TYPES: [&str; 7] = ["ip", "domain", "hash", "url", "email", "file", "registry"];
/// v1 `ThreatLevel` enum values.
const THREAT_LEVELS: [&str; 5] = ["critical", "high", "medium", "low", "info"];
const TYPE_MSG: &str =
    "Input should be 'ip', 'domain', 'hash', 'url', 'email', 'file' or 'registry'";
const LEVEL_MSG: &str = "Input should be 'critical', 'high', 'medium', 'low' or 'info'";

/// GET /iocs defaults: page size 50, hard cap 500 (v1 `min(per_page, 500)`).
const DEFAULT_PER_PAGE: i64 = 50;
const MAX_PER_PAGE: i64 = 500;
/// Bulk create accepts at most 1000 indicators (pydantic `max_items=1000`).
const MAX_BULK_INDICATORS: usize = 1000;

const IOC_COLUMNS: &str = "SELECT id, indicator_type, value, threat_level, confidence, source, \
     tags, metadata, expires_at::text, created_at::text, updated_at::text \
     FROM threat_indicators WHERE TRUE";

/// Router for /api/v1/threat-intel.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/threat-intel/iocs", get(list_iocs).post(create_ioc))
        .route("/threat-intel/iocs/bulk", post(bulk_create_iocs))
        .route("/threat-intel/iocs/search", post(search_iocs))
        .route("/threat-intel/iocs/lookup", post(lookup_ioc))
        .route(
            "/threat-intel/iocs/{ioc_id}",
            get(get_ioc).delete(delete_ioc),
        )
        .route("/threat-intel/statistics", get(get_statistics))
        .route("/threat-intel/feeds", get(list_feeds))
}

/// Single-field `{error: "Validation error", details: [...]}` with a custom
/// `loc` — bulk items need `["indicators", idx, field]` locations.
fn validation_at(loc: serde_json::Value, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": loc, "msg": msg, "type": "value_error"
    })])
}

/// Builds the pydantic-style `loc` for a field, nested under
/// `indicators[idx]` when validating a bulk item.
fn field_loc(item: Option<usize>, field: &str) -> serde_json::Value {
    match item {
        Some(idx) => serde_json::json!(["indicators", idx, field]),
        None => serde_json::json!([field]),
    }
}

/// Full IOC row selected via `IOC_COLUMNS` — jsonb columns come back as
/// `serde_json::Value`, timestamps as Postgres text.
#[derive(sqlx::FromRow)]
struct IocRow {
    id: i32,
    indicator_type: String,
    value: String,
    threat_level: Option<String>,
    confidence: Option<f64>,
    source: Option<String>,
    tags: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
    expires_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// v1 parity: `ioc.tags or []` — SQL NULL / jsonb null become `[]`.
fn tags_json(v: &Option<serde_json::Value>) -> serde_json::Value {
    match v {
        Some(val) if !val.is_null() => val.clone(),
        _ => serde_json::Value::Array(vec![]),
    }
}

/// v1 parity: `ioc.metadata or {}` — SQL NULL / jsonb null become `{}`.
fn metadata_json(v: &Option<serde_json::Value>) -> serde_json::Value {
    match v {
        Some(val) if !val.is_null() => val.clone(),
        _ => serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// v1 list-item shape (GET /iocs) — no `updated_at`.
fn ioc_json(row: &IocRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "indicator_type": row.indicator_type,
        "value": row.value,
        "threat_level": row.threat_level,
        "confidence": row.confidence,
        "source": row.source,
        "tags": tags_json(&row.tags),
        "metadata": metadata_json(&row.metadata),
        "expires_at": row.expires_at,
        "created_at": row.created_at,
    })
}

/// v1 detail shape (GET /iocs/{id}) — list shape plus `updated_at`.
fn ioc_detail_json(row: &IocRow) -> serde_json::Value {
    let mut v = ioc_json(row);
    if let Some(obj) = v.as_object_mut() {
        obj.insert("updated_at".to_owned(), serde_json::json!(row.updated_at));
    }
    v
}

/// v1 search-item shape (POST /iocs/search) — no metadata/expires/updated.
fn search_json(row: &IocRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "indicator_type": row.indicator_type,
        "value": row.value,
        "threat_level": row.threat_level,
        "confidence": row.confidence,
        "source": row.source,
        "tags": tags_json(&row.tags),
        "created_at": row.created_at,
    })
}

/// v1 lookup match shape (POST /iocs/lookup) — no timestamps/metadata.
fn lookup_json(row: &IocRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "indicator_type": row.indicator_type,
        "value": row.value,
        "threat_level": row.threat_level,
        "confidence": row.confidence,
        "source": row.source,
        "tags": tags_json(&row.tags),
    })
}

/// Shared WHERE-clause inputs for the list and search endpoints. `like` is a
/// pre-escaped `%...%` ILIKE pattern applied to `value`. `now` is captured
/// once per request (v1 builds the query with a single `datetime.utcnow()`).
struct IocFilters {
    like: Option<String>,
    types: Vec<String>,
    levels: Vec<String>,
    source: Option<String>,
    confidence_min: Option<f64>,
    include_expired: bool,
    now: NaiveDateTime,
}

impl Default for IocFilters {
    fn default() -> Self {
        Self {
            like: None,
            types: Vec::new(),
            levels: Vec::new(),
            source: None,
            confidence_min: None,
            include_expired: false,
            now: Utc::now().naive_utc(),
        }
    }
}

fn push_filters(qb: &mut QueryBuilder<Postgres>, f: &IocFilters) {
    if let Some(p) = &f.like {
        qb.push(" AND value ILIKE ").push_bind(p.clone());
    }
    if !f.types.is_empty() {
        qb.push(" AND indicator_type = ANY(")
            .push_bind(f.types.clone())
            .push(")");
    }
    if !f.levels.is_empty() {
        qb.push(" AND threat_level = ANY(")
            .push_bind(f.levels.clone())
            .push(")");
    }
    if let Some(s) = &f.source {
        qb.push(" AND source = ").push_bind(s.clone());
    }
    if let Some(c) = f.confidence_min {
        qb.push(" AND confidence >= ").push_bind(c);
    }
    if !f.include_expired {
        qb.push(" AND (expires_at IS NULL OR expires_at > ")
            .push_bind(f.now)
            .push(")");
    }
}

/// Runs the filtered page query plus the matching COUNT(*) — v1 orders by
/// created_at DESC for both list and search.
async fn fetch_ioc_page(
    db: &sqlx::PgPool,
    filters: &IocFilters,
    page: i64,
    per_page: i64,
) -> Result<(Vec<IocRow>, i64), ApiError> {
    let offset = (page - 1) * per_page;
    let mut qb = QueryBuilder::new(IOC_COLUMNS);
    push_filters(&mut qb, filters);
    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows = qb.build_query_as::<IocRow>().fetch_all(db).await?;

    let mut cq = QueryBuilder::new("SELECT COUNT(*) FROM threat_indicators WHERE TRUE");
    push_filters(&mut cq, filters);
    let total: i64 = cq.build_query_scalar().fetch_one(db).await?;
    Ok((rows, total))
}

/// v1 pages math: `(total + per_page - 1) // per_page` (per_page >= 1).
fn total_pages(total: i64, per_page: i64) -> i64 {
    (total + per_page - 1) / per_page
}

/// Escapes LIKE wildcards so user search text matches literally (Postgres
/// default escape char is backslash).
fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

/// Lenient datetime parsing approximating pydantic v2: RFC3339 (offset/Z),
/// naive ISO with T or space, or bare date at midnight.
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

/// Parsed GET /iocs query params (Quart request.args semantics).
struct ListQuery {
    page: i64,
    per_page: i64,
    types: Vec<String>,
    levels: Vec<String>,
    source: Option<String>,
    include_expired: bool,
}

/// Quart parity: first value wins for scalars (unparsable ints fall back to
/// the default), repeated `type`/`threat_level` keys accumulate. Deviation:
/// page/per_page floored at 1 — v1 divides by zero on per_page=0. Filter
/// values are passed through unvalidated, exactly like v1's `belongs(...)`.
fn parse_list_params(pairs: &[(String, String)]) -> ListQuery {
    let first = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    };
    let collect = |key: &str| {
        pairs
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
            .collect::<Vec<_>>()
    };
    ListQuery {
        page: first("page")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(1)
            .max(1),
        per_page: first("per_page")
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(DEFAULT_PER_PAGE)
            .clamp(1, MAX_PER_PAGE),
        types: collect("type"),
        levels: collect("threat_level"),
        source: first("source").filter(|s| !s.is_empty()).map(str::to_owned),
        include_expired: first("include_expired")
            .unwrap_or("false")
            .eq_ignore_ascii_case("true"),
    }
}

async fn list_iocs(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let q = parse_list_params(&params);
    let filters = IocFilters {
        types: q.types,
        levels: q.levels,
        source: q.source,
        include_expired: q.include_expired,
        ..IocFilters::default()
    };
    let (rows, total) = fetch_ioc_page(&state.db, &filters, q.page, q.per_page).await?;
    let items: Vec<serde_json::Value> = rows.iter().map(ioc_json).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": q.page,
        "per_page": q.per_page,
        "pages": total_pages(total, q.per_page),
    })))
}

async fn get_ioc(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(ioc_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut qb = QueryBuilder::new(IOC_COLUMNS);
    qb.push(" AND id = ").push_bind(ioc_id);
    let row = qb
        .build_query_as::<IocRow>()
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("IOC not found".to_owned()))?;
    Ok(Json(ioc_detail_json(&row)))
}

/// IOCCreateRequest — fields optional here so missing ones map to the
/// validation envelope instead of an axum extractor rejection.
#[derive(Deserialize)]
struct IocBody {
    indicator_type: Option<String>,
    value: Option<String>,
    threat_level: Option<String>,
    confidence: Option<f64>,
    source: Option<String>,
    tags: Option<Vec<String>>,
    metadata: Option<serde_json::Map<String, serde_json::Value>>,
    expires_at: Option<String>,
}

/// A validated IOC ready for insert/update, mirroring what v1 stores.
struct ValidIoc {
    indicator_type: String,
    value: String,
    threat_level: String,
    confidence: f64,
    source: String,
    tags: Vec<String>,
    metadata: serde_json::Value,
    expires_at: Option<NaiveDateTime>,
}

/// True for what v1's IP validator accepts: four dotted decimal parts each in
/// 0..=255, or anything containing `:` (IPv6 passthrough).
fn valid_ip(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.len() == 4
        && parts
            .iter()
            .all(|p| p.parse::<i64>().is_ok_and(|n| (0..=255).contains(&n)))
    {
        return true;
    }
    v.contains(':')
}

/// Mirrors pydantic IOCCreateRequest: indicator_type enum, value 1-1000
/// (stripped, IP/email format-checked), threat_level default medium,
/// confidence 0-1 default 0.5, source ≤100, ≤20 tags each ≤50 chars
/// (stripped + lowercased), metadata dict default {}, optional expires_at.
/// `item` nests error locations under `indicators[idx]` for bulk bodies.
fn validate_ioc(b: &IocBody, item: Option<usize>) -> Result<ValidIoc, ApiError> {
    let loc = |field: &str| field_loc(item, field);

    let Some(indicator_type) = b.indicator_type.as_deref() else {
        return Err(validation_at(loc("indicator_type"), "Field required"));
    };
    if !INDICATOR_TYPES.contains(&indicator_type) {
        return Err(validation_at(loc("indicator_type"), TYPE_MSG));
    }

    let Some(raw_value) = b.value.as_deref() else {
        return Err(validation_at(loc("value"), "Field required"));
    };
    let n = raw_value.chars().count();
    if n < 1 {
        return Err(validation_at(
            loc("value"),
            "String should have at least 1 character",
        ));
    }
    if n > 1000 {
        return Err(validation_at(
            loc("value"),
            "String should have at most 1000 characters",
        ));
    }
    let value = raw_value.trim().to_owned();
    if indicator_type == "ip" && !valid_ip(&value) {
        return Err(validation_at(
            loc("value"),
            "Value error, Invalid IP address format",
        ));
    }
    if indicator_type == "email" && !(value.contains('@') && value.contains('.')) {
        return Err(validation_at(
            loc("value"),
            "Value error, Invalid email format",
        ));
    }

    let threat_level = match b.threat_level.as_deref() {
        None => "medium".to_owned(),
        Some(l) if THREAT_LEVELS.contains(&l) => l.to_owned(),
        Some(_) => return Err(validation_at(loc("threat_level"), LEVEL_MSG)),
    };

    let confidence = b.confidence.unwrap_or(0.5);
    if confidence < 0.0 {
        return Err(validation_at(
            loc("confidence"),
            "Input should be greater than or equal to 0",
        ));
    }
    if confidence > 1.0 {
        return Err(validation_at(
            loc("confidence"),
            "Input should be less than or equal to 1",
        ));
    }

    let Some(source) = b.source.as_deref() else {
        return Err(validation_at(loc("source"), "Field required"));
    };
    if source.chars().count() > 100 {
        return Err(validation_at(
            loc("source"),
            "String should have at most 100 characters",
        ));
    }

    let raw_tags = b.tags.clone().unwrap_or_default();
    if raw_tags.len() > 20 {
        return Err(validation_at(
            loc("tags"),
            "List should have at most 20 items",
        ));
    }
    let mut tags = Vec::with_capacity(raw_tags.len());
    for tag in &raw_tags {
        if tag.chars().count() > 50 {
            return Err(validation_at(
                loc("tags"),
                "Value error, Tag too long (max 50 chars)",
            ));
        }
        tags.push(tag.trim().to_lowercase());
    }

    let metadata = b
        .metadata
        .clone()
        .map(serde_json::Value::Object)
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

    let expires_at =
        match b.expires_at.as_deref() {
            None => None,
            Some(s) => Some(parse_datetime(s).ok_or_else(|| {
                validation_at(loc("expires_at"), "Input should be a valid datetime")
            })?),
        };

    Ok(ValidIoc {
        indicator_type: indicator_type.to_owned(),
        value,
        threat_level,
        confidence,
        source: source.to_owned(),
        tags,
        metadata,
        expires_at,
    })
}

#[derive(sqlx::FromRow)]
struct CreatedRow {
    id: i32,
    indicator_type: String,
    value: String,
    threat_level: Option<String>,
    created_at: Option<String>,
}

async fn create_ioc(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(body): Json<IocBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let v = validate_ioc(&body, None)?;

    let existing: Option<(i32,)> =
        sqlx::query_as("SELECT id FROM threat_indicators WHERE indicator_type = $1 AND value = $2")
            .bind(&v.indicator_type)
            .bind(&v.value)
            .fetch_optional(&state.db)
            .await?;
    if let Some((existing_id,)) = existing {
        return Err(ApiError::Conflict(serde_json::json!({
            "error": "IOC already exists",
            "existing_id": existing_id,
        })));
    }

    let row = sqlx::query_as::<_, CreatedRow>(
        "INSERT INTO threat_indicators \
         (indicator_type, value, threat_level, confidence, source, tags, metadata, \
          expires_at, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now()) \
         RETURNING id, indicator_type, value, threat_level, created_at::text",
    )
    .bind(&v.indicator_type)
    .bind(&v.value)
    .bind(&v.threat_level)
    .bind(v.confidence)
    .bind(&v.source)
    .bind(serde_json::Value::from(v.tags.clone()))
    .bind(&v.metadata)
    .bind(v.expires_at)
    .fetch_one(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "IOC created successfully",
            "ioc": {
                "id": row.id,
                "indicator_type": row.indicator_type,
                "value": row.value,
                "threat_level": row.threat_level,
                "created_at": row.created_at,
            }
        })),
    ))
}

/// IOCBulkCreateRequest — `indicators` optional so a missing field maps to
/// the validation envelope.
#[derive(Deserialize)]
struct BulkBody {
    indicators: Option<Vec<IocBody>>,
}

/// Upserts one validated IOC on (indicator_type, value); returns true when a
/// new row was inserted, false when an existing one was updated. pyDAL parity:
/// updates bump `updated_at`, inserts leave it NULL.
async fn upsert_ioc(db: &sqlx::PgPool, v: &ValidIoc) -> Result<bool, sqlx::Error> {
    let existing: Option<(i32,)> =
        sqlx::query_as("SELECT id FROM threat_indicators WHERE indicator_type = $1 AND value = $2")
            .bind(&v.indicator_type)
            .bind(&v.value)
            .fetch_optional(db)
            .await?;

    match existing {
        Some((id,)) => {
            sqlx::query(
                "UPDATE threat_indicators SET threat_level = $1, confidence = $2, \
                 source = $3, tags = $4, metadata = $5, expires_at = $6, \
                 updated_at = now() WHERE id = $7",
            )
            .bind(&v.threat_level)
            .bind(v.confidence)
            .bind(&v.source)
            .bind(serde_json::Value::from(v.tags.clone()))
            .bind(&v.metadata)
            .bind(v.expires_at)
            .bind(id)
            .execute(db)
            .await?;
            Ok(false)
        }
        None => {
            sqlx::query(
                "INSERT INTO threat_indicators \
                 (indicator_type, value, threat_level, confidence, source, tags, \
                  metadata, expires_at, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())",
            )
            .bind(&v.indicator_type)
            .bind(&v.value)
            .bind(&v.threat_level)
            .bind(v.confidence)
            .bind(&v.source)
            .bind(serde_json::Value::from(v.tags.clone()))
            .bind(&v.metadata)
            .bind(v.expires_at)
            .execute(db)
            .await?;
            Ok(true)
        }
    }
}

/// POST /iocs/bulk — v1 validates the entire batch up front (any invalid
/// item 400s the whole request); the per-item error list only collects DB
/// failures during the upsert loop. Always 201, first 10 errors returned.
async fn bulk_create_iocs(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(body): Json<BulkBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_role(&["admin", "maintainer"])?;

    let Some(raw) = body.indicators else {
        return Err(validation_at(
            field_loc(None, "indicators"),
            "Field required",
        ));
    };
    if raw.len() > MAX_BULK_INDICATORS {
        return Err(validation_at(
            field_loc(None, "indicators"),
            "List should have at most 1000 items",
        ));
    }
    let mut valid = Vec::with_capacity(raw.len());
    for (idx, item) in raw.iter().enumerate() {
        valid.push(validate_ioc(item, Some(idx))?);
    }

    let mut created_count = 0_i64;
    let mut updated_count = 0_i64;
    let mut errors: Vec<serde_json::Value> = Vec::new();
    for (idx, v) in valid.iter().enumerate() {
        match upsert_ioc(&state.db, v).await {
            Ok(true) => created_count += 1,
            Ok(false) => updated_count += 1,
            Err(e) => errors.push(serde_json::json!({
                "index": idx,
                "error": e.to_string(),
            })),
        }
    }

    let first_ten: Vec<serde_json::Value> = errors.iter().take(10).cloned().collect();
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "success": true,
            "created_count": created_count,
            "updated_count": updated_count,
            "error_count": errors.len(),
            "errors": first_ten,
        })),
    ))
}

async fn delete_ioc(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(ioc_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin"])?;

    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM threat_indicators WHERE id = $1")
        .bind(ioc_id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("IOC not found".to_owned()));
    }

    sqlx::query("DELETE FROM threat_indicators WHERE id = $1")
        .bind(ioc_id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({
        "message": "IOC deleted successfully"
    })))
}

/// IOCSearchRequest — `tags` is accepted for schema parity but v1 never
/// filters on it, and neither do we.
#[derive(Deserialize)]
struct SearchBody {
    query: Option<String>,
    indicator_type: Option<Vec<String>>,
    threat_level: Option<Vec<String>>,
    source: Option<String>,
    #[allow(dead_code)] // v1 parity: declared in the model, never used
    tags: Option<Vec<String>>,
    confidence_min: Option<f64>,
    include_expired: Option<bool>,
    page: Option<i64>,
    per_page: Option<i64>,
}

/// Validates IOCSearchRequest and builds SQL filters. Python truthiness is
/// preserved: empty query/source and confidence_min=0.0 apply no filter.
fn validate_search(b: &SearchBody) -> Result<(IocFilters, i64, i64), ApiError> {
    let page = b.page.unwrap_or(1);
    if page < 1 {
        return Err(validation_at(
            field_loc(None, "page"),
            "Input should be greater than or equal to 1",
        ));
    }
    let per_page = b.per_page.unwrap_or(DEFAULT_PER_PAGE);
    if per_page < 1 {
        return Err(validation_at(
            field_loc(None, "per_page"),
            "Input should be greater than or equal to 1",
        ));
    }
    if per_page > MAX_PER_PAGE {
        return Err(validation_at(
            field_loc(None, "per_page"),
            "Input should be less than or equal to 500",
        ));
    }
    if let Some(q) = &b.query
        && q.chars().count() > 500
    {
        return Err(validation_at(
            field_loc(None, "query"),
            "String should have at most 500 characters",
        ));
    }
    let types = b.indicator_type.clone().unwrap_or_default();
    if types.iter().any(|t| !INDICATOR_TYPES.contains(&t.as_str())) {
        return Err(validation_at(field_loc(None, "indicator_type"), TYPE_MSG));
    }
    let levels = b.threat_level.clone().unwrap_or_default();
    if levels.iter().any(|l| !THREAT_LEVELS.contains(&l.as_str())) {
        return Err(validation_at(field_loc(None, "threat_level"), LEVEL_MSG));
    }
    if let Some(c) = b.confidence_min {
        if c < 0.0 {
            return Err(validation_at(
                field_loc(None, "confidence_min"),
                "Input should be greater than or equal to 0",
            ));
        }
        if c > 1.0 {
            return Err(validation_at(
                field_loc(None, "confidence_min"),
                "Input should be less than or equal to 1",
            ));
        }
    }
    let filters = IocFilters {
        like: b
            .query
            .as_deref()
            .filter(|q| !q.is_empty())
            .map(|q| format!("%{}%", like_escape(q))),
        types,
        levels,
        source: b.source.clone().filter(|s| !s.is_empty()),
        confidence_min: b.confidence_min.filter(|c| *c != 0.0),
        include_expired: b.include_expired.unwrap_or(false),
        ..IocFilters::default()
    };
    Ok((filters, page, per_page))
}

async fn search_iocs(
    State(state): State<AppState>,
    _user: CurrentUser,
    Json(body): Json<SearchBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (filters, page, per_page) = validate_search(&body)?;
    let (rows, total) = fetch_ioc_page(&state.db, &filters, page, per_page).await?;
    let items: Vec<serde_json::Value> = rows.iter().map(search_json).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": total_pages(total, per_page),
    })))
}

/// POST /iocs/lookup body — `type` + `value`, both required (truthy in v1,
/// so empty strings also 400).
#[derive(Deserialize)]
struct LookupBody {
    #[serde(rename = "type")]
    indicator_type: Option<String>,
    value: Option<String>,
}

async fn lookup_ioc(
    State(state): State<AppState>,
    _user: CurrentUser,
    Json(body): Json<LookupBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let indicator_type = body.indicator_type.as_deref().filter(|s| !s.is_empty());
    let value = body.value.as_deref().filter(|s| !s.is_empty());
    let (Some(indicator_type), Some(value)) = (indicator_type, value) else {
        return Err(ApiError::BadRequest(
            "Both 'type' and 'value' are required".to_owned(),
        ));
    };

    let row: Option<IocRow> = sqlx::query_as(
        "SELECT id, indicator_type, value, threat_level, confidence, source, tags, \
         metadata, expires_at::text, created_at::text, updated_at::text \
         FROM threat_indicators \
         WHERE indicator_type = $1 AND value = $2 \
           AND (expires_at IS NULL OR expires_at > $3)",
    )
    .bind(indicator_type)
    .bind(value)
    .bind(Utc::now().naive_utc())
    .fetch_optional(&state.db)
    .await?;

    match row {
        Some(ioc) => Ok(Json(serde_json::json!({
            "found": true,
            "ioc": lookup_json(&ioc),
        }))),
        None => Ok(Json(serde_json::json!({
            "found": false,
            "indicator_type": indicator_type,
            "value": value,
        }))),
    }
}

/// Builds a `{value: count}` object covering every canonical key, zero-filled
/// — matches the v1 per-value COUNT loop (unknown values are ignored).
fn bucket_counts(keys: &[&str], rows: &[(Option<String>, i64)]) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    for k in keys {
        let n = rows
            .iter()
            .find(|(key, _)| key.as_deref() == Some(*k))
            .map_or(0, |(_, n)| *n);
        map.insert((*k).to_owned(), serde_json::Value::from(n));
    }
    serde_json::Value::Object(map)
}

/// GET /statistics — totals, zero-filled per-type/per-level buckets, top 10
/// sources, and expired count. v1 computed top_sources with N+1 client-side
/// counts over distinct sources, skipping falsy (NULL/empty) values; one
/// GROUP BY query yields the same map.
async fn get_statistics(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM threat_indicators")
        .fetch_one(&state.db)
        .await?;
    let type_rows: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT indicator_type, COUNT(*) FROM threat_indicators GROUP BY indicator_type",
    )
    .fetch_all(&state.db)
    .await?;
    let level_rows: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT threat_level, COUNT(*) FROM threat_indicators GROUP BY threat_level",
    )
    .fetch_all(&state.db)
    .await?;
    let source_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT source, COUNT(*) FROM threat_indicators \
         WHERE source IS NOT NULL AND source <> '' \
         GROUP BY source ORDER BY COUNT(*) DESC LIMIT 10",
    )
    .fetch_all(&state.db)
    .await?;
    let expired: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM threat_indicators \
         WHERE expires_at IS NOT NULL AND expires_at <= $1",
    )
    .bind(Utc::now().naive_utc())
    .fetch_one(&state.db)
    .await?;

    let mut top_sources = serde_json::Map::new();
    for (source, count) in &source_rows {
        top_sources.insert(source.clone(), serde_json::Value::from(*count));
    }

    Ok(Json(serde_json::json!({
        "total": total,
        "by_type": bucket_counts(&INDICATOR_TYPES, &type_rows),
        "by_threat_level": bucket_counts(&THREAT_LEVELS, &level_rows),
        "top_sources": top_sources,
        "expired": expired,
    })))
}

/// v1 feed catalog from `ThreatIntelConfig`: dns/ip blacklists default to
/// enabled=true and otx/virustotal/taxii to enabled=false — load_config never
/// overrides any of those flags, so only `configured` (API key presence) and
/// the static descriptions vary. `taxii_servers` is always empty in v1.
fn feeds_json(otx_key: Option<&str>, virustotal_key: Option<&str>) -> serde_json::Value {
    let configured = |key: Option<&str>| key.is_some_and(|k| !k.is_empty());
    serde_json::json!({
        "feeds": [
            {
                "id": "dns_blacklist",
                "name": "DNS Blacklists",
                "type": "dns",
                "enabled": true,
                "description": "SpamHaus, SpamCop, SORBS DNS blacklists",
            },
            {
                "id": "ip_blacklist",
                "name": "IP Blacklists",
                "type": "ip",
                "enabled": true,
                "description": "Known malicious IP address lists",
            },
            {
                "id": "otx",
                "name": "AlienVault OTX",
                "type": "api",
                "enabled": false,
                "configured": configured(otx_key),
                "description": "Open Threat Exchange threat intelligence",
            },
            {
                "id": "virustotal",
                "name": "VirusTotal",
                "type": "api",
                "enabled": false,
                "configured": configured(virustotal_key),
                "description": "VirusTotal file and URL analysis",
            },
            {
                "id": "taxii",
                "name": "STIX/TAXII",
                "type": "taxii",
                "enabled": false,
                "servers": 0,
                "description": "STIX/TAXII 2.1 threat feeds",
            },
        ]
    })
}

/// GET /feeds — env is read at request time (`OTX_API_KEY`,
/// `VIRUSTOTAL_API_KEY`), same pattern as alerts.rs `AI_ENABLED`.
async fn list_feeds(_user: CurrentUser) -> Result<Json<serde_json::Value>, ApiError> {
    let otx = std::env::var("OTX_API_KEY").ok();
    let virustotal = std::env::var("VIRUSTOTAL_API_KEY").ok();
    Ok(Json(feeds_json(otx.as_deref(), virustotal.as_deref())))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn base_body() -> IocBody {
        IocBody {
            indicator_type: Some("domain".to_owned()),
            value: Some("evil.example.com".to_owned()),
            threat_level: None,
            confidence: None,
            source: Some("unit-test".to_owned()),
            tags: None,
            metadata: None,
            expires_at: None,
        }
    }

    fn first_detail(err: ApiError) -> serde_json::Value {
        match err {
            ApiError::Validation(details) => {
                details.first().cloned().unwrap_or(serde_json::Value::Null)
            }
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn validate_ioc_applies_v1_defaults() {
        let v = match validate_ioc(&base_body(), None) {
            Ok(v) => v,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(v.threat_level, "medium");
        assert_eq!(v.confidence, 0.5);
        assert!(v.tags.is_empty());
        assert_eq!(v.metadata, serde_json::json!({}));
        assert_eq!(v.expires_at, None);
    }

    #[test]
    fn validate_ioc_requires_and_checks_enums() {
        let missing_type = IocBody {
            indicator_type: None,
            ..base_body()
        };
        let d = first_detail(match validate_ioc(&missing_type, None) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        });
        assert_eq!(d["loc"], serde_json::json!(["indicator_type"]));
        assert_eq!(d["msg"], "Field required");

        let bad_type = IocBody {
            indicator_type: Some("mac".to_owned()),
            ..base_body()
        };
        assert!(matches!(
            validate_ioc(&bad_type, None),
            Err(ApiError::Validation(_))
        ));

        let bad_level = IocBody {
            threat_level: Some("apocalyptic".to_owned()),
            ..base_body()
        };
        assert!(matches!(
            validate_ioc(&bad_level, None),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn validate_ioc_value_bounds_and_strip() {
        let empty = IocBody {
            value: Some(String::new()),
            ..base_body()
        };
        assert!(matches!(
            validate_ioc(&empty, None),
            Err(ApiError::Validation(_))
        ));

        let long = IocBody {
            value: Some("x".repeat(1001)),
            ..base_body()
        };
        assert!(matches!(
            validate_ioc(&long, None),
            Err(ApiError::Validation(_))
        ));

        let padded = IocBody {
            value: Some("  evil.example.com  ".to_owned()),
            ..base_body()
        };
        match validate_ioc(&padded, None) {
            Ok(v) => assert_eq!(v.value, "evil.example.com"),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
    }

    #[test]
    fn validate_ioc_ip_rules_match_v1() {
        let ip = |value: &str| IocBody {
            indicator_type: Some("ip".to_owned()),
            value: Some(value.to_owned()),
            ..base_body()
        };
        assert!(validate_ioc(&ip("10.0.0.1"), None).is_ok());
        assert!(validate_ioc(&ip(" 10.0.0.1 "), None).is_ok()); // stripped first
        assert!(validate_ioc(&ip("::1"), None).is_ok()); // IPv6 passthrough
        let d = first_detail(match validate_ioc(&ip("999.0.0.1"), None) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        });
        assert_eq!(d["msg"], "Value error, Invalid IP address format");
        assert!(validate_ioc(&ip("10.0.0"), None).is_err());
        assert!(validate_ioc(&ip("not-an-ip"), None).is_err());
    }

    #[test]
    fn validate_ioc_email_rules_match_v1() {
        let email = |value: &str| IocBody {
            indicator_type: Some("email".to_owned()),
            value: Some(value.to_owned()),
            ..base_body()
        };
        assert!(validate_ioc(&email("bad@guy.example"), None).is_ok());
        let d = first_detail(match validate_ioc(&email("no-at-sign.example"), None) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        });
        assert_eq!(d["msg"], "Value error, Invalid email format");
        assert!(validate_ioc(&email("no@dot"), None).is_err());
    }

    #[test]
    fn validate_ioc_confidence_and_source_bounds() {
        let low = IocBody {
            confidence: Some(-0.1),
            ..base_body()
        };
        assert!(matches!(
            validate_ioc(&low, None),
            Err(ApiError::Validation(_))
        ));
        let high = IocBody {
            confidence: Some(1.1),
            ..base_body()
        };
        assert!(matches!(
            validate_ioc(&high, None),
            Err(ApiError::Validation(_))
        ));

        let no_source = IocBody {
            source: None,
            ..base_body()
        };
        assert!(matches!(
            validate_ioc(&no_source, None),
            Err(ApiError::Validation(_))
        ));
        let long_source = IocBody {
            source: Some("s".repeat(101)),
            ..base_body()
        };
        assert!(matches!(
            validate_ioc(&long_source, None),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn validate_ioc_tags_are_stripped_lowercased_and_bounded() {
        let tagged = IocBody {
            tags: Some(vec!["  APT-29 ".to_owned(), "Phishing".to_owned()]),
            ..base_body()
        };
        match validate_ioc(&tagged, None) {
            Ok(v) => assert_eq!(v.tags, vec!["apt-29", "phishing"]),
            Err(e) => panic!("expected ok, got {e:?}"),
        }

        let too_many = IocBody {
            tags: Some(vec!["t".to_owned(); 21]),
            ..base_body()
        };
        let d = first_detail(match validate_ioc(&too_many, None) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        });
        assert_eq!(d["msg"], "List should have at most 20 items");

        let long_tag = IocBody {
            tags: Some(vec!["t".repeat(51)]),
            ..base_body()
        };
        let d = first_detail(match validate_ioc(&long_tag, None) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        });
        assert_eq!(d["msg"], "Value error, Tag too long (max 50 chars)");
    }

    #[test]
    fn validate_ioc_expires_at_is_lenient_then_strict() {
        let ok = IocBody {
            expires_at: Some("2026-08-01T00:00:00Z".to_owned()),
            ..base_body()
        };
        match validate_ioc(&ok, None) {
            Ok(v) => assert!(v.expires_at.is_some()),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
        let bare_date = IocBody {
            expires_at: Some("2026-08-01".to_owned()),
            ..base_body()
        };
        assert!(validate_ioc(&bare_date, None).is_ok());
        let bad = IocBody {
            expires_at: Some("next tuesday".to_owned()),
            ..base_body()
        };
        let d = first_detail(match validate_ioc(&bad, None) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        });
        assert_eq!(d["msg"], "Input should be a valid datetime");
    }

    #[test]
    fn bulk_item_errors_nest_loc_under_indicators() {
        let bad = IocBody {
            indicator_type: None,
            ..base_body()
        };
        let d = first_detail(match validate_ioc(&bad, Some(3)) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        });
        assert_eq!(
            d["loc"],
            serde_json::json!(["indicators", 3, "indicator_type"])
        );
    }

    #[test]
    fn list_params_accumulate_and_clamp_like_v1() {
        let pairs = vec![
            ("page".to_owned(), "2".to_owned()),
            ("per_page".to_owned(), "1000".to_owned()),
            ("type".to_owned(), "ip".to_owned()),
            ("type".to_owned(), "domain".to_owned()),
            ("threat_level".to_owned(), "high".to_owned()),
            ("source".to_owned(), "otx".to_owned()),
            ("include_expired".to_owned(), "TRUE".to_owned()),
        ];
        let q = parse_list_params(&pairs);
        assert_eq!(q.page, 2);
        assert_eq!(q.per_page, 500); // v1 min(per_page, 500)
        assert_eq!(q.types, vec!["ip", "domain"]);
        assert_eq!(q.levels, vec!["high"]);
        assert_eq!(q.source.as_deref(), Some("otx"));
        assert!(q.include_expired);
    }

    #[test]
    fn list_params_defaults_match_v1() {
        let q = parse_list_params(&[("page".to_owned(), "junk".to_owned())]);
        assert_eq!(q.page, 1);
        assert_eq!(q.per_page, 50);
        assert!(q.types.is_empty());
        assert!(q.levels.is_empty());
        assert_eq!(q.source, None);
        assert!(!q.include_expired); // default "false"
    }

    fn base_search() -> SearchBody {
        SearchBody {
            query: None,
            indicator_type: None,
            threat_level: None,
            source: None,
            tags: None,
            confidence_min: None,
            include_expired: None,
            page: None,
            per_page: None,
        }
    }

    #[test]
    fn search_defaults_and_truthiness_match_v1() {
        let body = SearchBody {
            query: Some("50%_evil".to_owned()),
            confidence_min: Some(0.0),
            source: Some(String::new()),
            ..base_search()
        };
        match validate_search(&body) {
            Ok((f, page, per_page)) => {
                assert_eq!((page, per_page), (1, 50));
                assert_eq!(f.like.as_deref(), Some("%50\\%\\_evil%"));
                assert_eq!(f.confidence_min, None); // 0.0 is falsy in v1
                assert_eq!(f.source, None); // "" is falsy in v1
                assert!(!f.include_expired);
            }
            Err(e) => panic!("expected ok, got {e:?}"),
        }

        let filtered = SearchBody {
            confidence_min: Some(0.7),
            include_expired: Some(true),
            ..base_search()
        };
        match validate_search(&filtered) {
            Ok((f, _, _)) => {
                assert_eq!(f.confidence_min, Some(0.7));
                assert!(f.include_expired);
                assert_eq!(f.like, None);
            }
            Err(e) => panic!("expected ok, got {e:?}"),
        }
    }

    #[test]
    fn search_rejects_out_of_range_and_bad_enums() {
        let big = SearchBody {
            per_page: Some(501),
            ..base_search()
        };
        assert!(matches!(
            validate_search(&big),
            Err(ApiError::Validation(_))
        ));
        let zero_page = SearchBody {
            page: Some(0),
            ..base_search()
        };
        assert!(matches!(
            validate_search(&zero_page),
            Err(ApiError::Validation(_))
        ));
        let bad_type = SearchBody {
            indicator_type: Some(vec!["mac".to_owned()]),
            ..base_search()
        };
        let d = first_detail(match validate_search(&bad_type) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        });
        assert_eq!(d["msg"], TYPE_MSG);
        let bad_level = SearchBody {
            threat_level: Some(vec!["extreme".to_owned()]),
            ..base_search()
        };
        assert!(matches!(
            validate_search(&bad_level),
            Err(ApiError::Validation(_))
        ));
        let bad_conf = SearchBody {
            confidence_min: Some(1.5),
            ..base_search()
        };
        assert!(matches!(
            validate_search(&bad_conf),
            Err(ApiError::Validation(_))
        ));
        let long_query = SearchBody {
            query: Some("q".repeat(501)),
            ..base_search()
        };
        assert!(matches!(
            validate_search(&long_query),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn filter_sql_includes_only_active_clauses() {
        let filters = IocFilters {
            like: Some("%evil%".to_owned()),
            types: vec!["ip".to_owned()],
            source: Some("otx".to_owned()),
            confidence_min: Some(0.7),
            ..IocFilters::default()
        };
        let mut qb = QueryBuilder::<Postgres>::new("SELECT 1 WHERE TRUE");
        push_filters(&mut qb, &filters);
        let sql = qb.sql();
        let sql = sql.as_str();
        assert!(sql.contains("value ILIKE"));
        assert!(sql.contains("indicator_type = ANY("));
        assert!(!sql.contains("threat_level = ANY(")); // empty list skipped
        assert!(sql.contains("source ="));
        assert!(sql.contains("confidence >="));
        assert!(sql.contains("expires_at IS NULL OR expires_at >"));

        let mut qb = QueryBuilder::<Postgres>::new("SELECT 1 WHERE TRUE");
        push_filters(
            &mut qb,
            &IocFilters {
                include_expired: true,
                ..IocFilters::default()
            },
        );
        assert_eq!(qb.sql().as_str(), "SELECT 1 WHERE TRUE");
    }

    #[test]
    fn total_pages_matches_python_ceiling_division() {
        assert_eq!(total_pages(0, 50), 0);
        assert_eq!(total_pages(1, 50), 1);
        assert_eq!(total_pages(500, 50), 10);
        assert_eq!(total_pages(501, 50), 11);
    }

    #[test]
    fn jsonb_null_normalization_matches_v1() {
        assert_eq!(tags_json(&None), serde_json::json!([]));
        assert_eq!(
            tags_json(&Some(serde_json::Value::Null)),
            serde_json::json!([])
        );
        assert_eq!(
            tags_json(&Some(serde_json::json!(["apt"]))),
            serde_json::json!(["apt"])
        );
        assert_eq!(metadata_json(&None), serde_json::json!({}));
        assert_eq!(
            metadata_json(&Some(serde_json::json!({"k": 1}))),
            serde_json::json!({"k": 1})
        );
    }

    #[test]
    fn bucket_counts_zero_fills_and_ignores_unknowns() {
        let rows = vec![
            (Some("ip".to_owned()), 4_i64),
            (Some("bogus".to_owned()), 9_i64),
            (None, 2_i64),
        ];
        let v = bucket_counts(&INDICATOR_TYPES, &rows);
        assert_eq!(v["ip"], 4);
        assert_eq!(v["domain"], 0);
        assert_eq!(v.get("bogus"), None);
    }

    #[test]
    fn feeds_reflect_api_key_presence_only() {
        let v = feeds_json(Some("key123"), None);
        let feeds = match v["feeds"].as_array() {
            Some(f) => f,
            None => panic!("feeds should be an array"),
        };
        assert_eq!(feeds.len(), 5);
        let ids: Vec<&str> = feeds.iter().filter_map(|f| f["id"].as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "dns_blacklist",
                "ip_blacklist",
                "otx",
                "virustotal",
                "taxii"
            ]
        );
        assert_eq!(feeds[0]["enabled"], true); // dns default-on in v1 config
        assert_eq!(feeds[2]["enabled"], false); // otx enabled never set in v1
        assert_eq!(feeds[2]["configured"], true);
        assert_eq!(feeds[3]["configured"], false);
        assert_eq!(feeds[4]["servers"], 0);

        let empty_key = feeds_json(Some(""), Some("vt"));
        assert_eq!(empty_key["feeds"][2]["configured"], false); // "" is falsy
        assert_eq!(empty_key["feeds"][3]["configured"], true);
    }

    #[test]
    fn valid_ip_edge_cases() {
        assert!(valid_ip("0.0.0.0"));
        assert!(valid_ip("255.255.255.255"));
        assert!(!valid_ip("256.1.1.1"));
        assert!(!valid_ip("1.2.3.4.5"));
        assert!(!valid_ip("-1.0.0.0"));
        assert!(valid_ip("fe80::1")); // colon passthrough, v1 parity
    }
}
