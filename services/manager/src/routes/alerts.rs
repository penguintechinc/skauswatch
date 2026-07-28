//! /api/v1/alerts — list/get/create/update, status transitions, AI-review
//! dispatch, search, and statistics. Contract: docs/v2-port/manager-contract.md
//! §alerts; Python source of truth: services/manager/api/v1/alerts.py.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::Deserialize;
use sqlx::{Postgres, QueryBuilder};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson};
use crate::state::AppState;

const SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "info"];
const STATUSES: [&str; 5] = [
    "pending",
    "in_progress",
    "resolved",
    "false_positive",
    "escalated",
];
const SEVERITY_MSG: &str = "Input should be 'critical', 'high', 'medium', 'low' or 'info'";
const STATUS_MSG: &str =
    "Input should be 'pending', 'in_progress', 'resolved', 'false_positive' or 'escalated'";
/// v1 `config.ai.default_provider` — a constant "ollama" (load_config never overrides it).
const DEFAULT_AI_PROVIDER: &str = "ollama";

const ALERT_COLUMNS: &str = "SELECT id, title, description, severity, status, source, \
     indicators, ai_review, assigned_to, resolved_at, resolution_notes, \
     created_at, updated_at FROM alerts WHERE TRUE";

/// Router for /api/v1/alerts.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/alerts", get(list_alerts).post(create_alert))
        .route("/alerts/search", post(search_alerts))
        .route("/alerts/statistics", get(alert_statistics))
        .route("/alerts/{alert_id}", get(get_alert).put(update_alert))
        .route("/alerts/{alert_id}/status", put(update_alert_status))
        .route("/alerts/{alert_id}/ai-review", post(request_ai_review))
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// Full alert row selected via `ALERT_COLUMNS` — jsonb columns come back as
/// `serde_json::Value`, timestamps as chrono `NaiveDateTime` (rendered with
/// `py_isoformat` for v1 wire parity).
#[derive(sqlx::FromRow)]
struct AlertRow {
    id: i32,
    title: String,
    description: Option<String>,
    severity: String,
    status: String,
    source: Option<String>,
    indicators: Option<serde_json::Value>,
    ai_review: Option<serde_json::Value>,
    assigned_to: Option<i32>,
    resolved_at: Option<NaiveDateTime>,
    resolution_notes: Option<String>,
    created_at: Option<NaiveDateTime>,
    updated_at: Option<NaiveDateTime>,
}

/// v1 full-alert response shape (list + get endpoints).
fn alert_json(row: &AlertRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "status": row.status,
        "source": row.source,
        "indicators": normalize_indicators(&row.indicators),
        "ai_review": row.ai_review,
        "assigned_to": row.assigned_to,
        "resolved_at": skauswatch_streams::py_isoformat_opt(row.resolved_at),
        "resolution_notes": row.resolution_notes,
        "created_at": skauswatch_streams::py_isoformat_opt(row.created_at),
        "updated_at": skauswatch_streams::py_isoformat_opt(row.updated_at),
    })
}

/// v1 search response subset (POST /alerts/search items).
fn search_json(row: &AlertRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "title": row.title,
        "description": row.description,
        "severity": row.severity,
        "status": row.status,
        "source": row.source,
        "created_at": skauswatch_streams::py_isoformat_opt(row.created_at),
    })
}

/// v1 parity: `alert.indicators or []` — SQL NULL / jsonb null become `[]`.
fn normalize_indicators(v: &Option<serde_json::Value>) -> serde_json::Value {
    match v {
        Some(val) if !val.is_null() => val.clone(),
        _ => serde_json::Value::Array(vec![]),
    }
}

/// Shared WHERE-clause inputs for the list and search endpoints. `like` is a
/// pre-escaped `%...%` ILIKE pattern applied to title OR description.
#[derive(Default)]
struct AlertFilters {
    like: Option<String>,
    severity: Vec<String>,
    status: Vec<String>,
    source: Option<String>,
    assigned_to: Option<i32>,
    created_after: Option<NaiveDateTime>,
    created_before: Option<NaiveDateTime>,
}

fn push_filters(qb: &mut QueryBuilder<Postgres>, f: &AlertFilters) {
    if let Some(p) = &f.like {
        qb.push(" AND (title ILIKE ")
            .push_bind(p.clone())
            .push(" OR description ILIKE ")
            .push_bind(p.clone())
            .push(")");
    }
    if !f.severity.is_empty() {
        qb.push(" AND severity = ANY(")
            .push_bind(f.severity.clone())
            .push(")");
    }
    if !f.status.is_empty() {
        qb.push(" AND status = ANY(")
            .push_bind(f.status.clone())
            .push(")");
    }
    if let Some(s) = &f.source {
        qb.push(" AND source = ").push_bind(s.clone());
    }
    if let Some(a) = f.assigned_to {
        qb.push(" AND assigned_to = ").push_bind(a);
    }
    if let Some(t) = f.created_after {
        qb.push(" AND created_at >= ").push_bind(t);
    }
    if let Some(t) = f.created_before {
        qb.push(" AND created_at <= ").push_bind(t);
    }
}

/// Runs the filtered page query plus the matching COUNT(*) — v1 orders by
/// created_at DESC for both list and search.
async fn fetch_alert_page(
    db: &sqlx::PgPool,
    filters: &AlertFilters,
    page: i64,
    per_page: i64,
) -> Result<(Vec<AlertRow>, i64), ApiError> {
    let offset = (page - 1) * per_page;
    let mut qb = QueryBuilder::new(ALERT_COLUMNS);
    push_filters(&mut qb, filters);
    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows = qb.build_query_as::<AlertRow>().fetch_all(db).await?;

    let mut cq = QueryBuilder::new("SELECT COUNT(*) FROM alerts WHERE TRUE");
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

/// Parsed GET /alerts query params (Quart request.args semantics).
struct ListQuery {
    page: i64,
    per_page: i64,
    severity: Vec<String>,
    status: Vec<String>,
    source: Option<String>,
}

/// Quart parity: first value wins for scalars (unparsable ints fall back to
/// the default), repeated keys accumulate for severity/status. Deviation:
/// page/per_page floored at 1 — v1 divides by zero on per_page=0.
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
            .unwrap_or(20)
            .clamp(1, 100),
        severity: collect("severity"),
        status: collect("status"),
        source: first("source").filter(|s| !s.is_empty()).map(str::to_owned),
    }
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

async fn list_alerts(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let q = parse_list_params(&params);
    let filters = AlertFilters {
        severity: q.severity,
        status: q.status,
        source: q.source,
        ..AlertFilters::default()
    };
    let (rows, total) = fetch_alert_page(&state.db, &filters, q.page, q.per_page).await?;
    let items: Vec<serde_json::Value> = rows.iter().map(alert_json).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": q.page,
        "per_page": q.per_page,
        "pages": total_pages(total, q.per_page),
    })))
}

async fn get_alert(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(alert_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let mut qb = QueryBuilder::new(ALERT_COLUMNS);
    qb.push(" AND id = ").push_bind(alert_id);
    let row = qb
        .build_query_as::<AlertRow>()
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Alert not found".to_owned()))?;
    Ok(Json(alert_json(&row)))
}

/// AlertCreateRequest — fields optional here so missing ones map to the
/// validation envelope instead of an axum extractor rejection.
#[derive(Deserialize)]
struct CreateBody {
    title: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    source: Option<String>,
    indicators: Option<Vec<String>>,
}

struct ValidCreate {
    title: String,
    description: String,
    severity: String,
    source: String,
    indicators: Vec<String>,
}

/// Mirrors pydantic AlertCreateRequest: title 1-255, description <=4000,
/// severity enum, source 1-100, <=100 indicators each <=500 chars (stripped).
fn validate_create(b: &CreateBody) -> Result<ValidCreate, ApiError> {
    let title = required_str(&b.title, "title", 1, 255)?;
    let description = required_str(&b.description, "description", 0, 4000)?;
    let Some(severity) = b.severity.as_deref() else {
        return Err(validation("severity", "Field required"));
    };
    if !SEVERITIES.contains(&severity) {
        return Err(validation("severity", SEVERITY_MSG));
    }
    let source = required_str(&b.source, "source", 1, 100)?;
    let raw = b.indicators.clone().unwrap_or_default();
    if raw.len() > 100 {
        return Err(validation(
            "indicators",
            "List should have at most 100 items",
        ));
    }
    let mut indicators = Vec::with_capacity(raw.len());
    for item in &raw {
        if item.chars().count() > 500 {
            return Err(validation("indicators", "Value error, Indicator too long"));
        }
        indicators.push(item.trim().to_owned());
    }
    Ok(ValidCreate {
        title,
        description,
        severity: severity.to_owned(),
        source,
        indicators,
    })
}

#[derive(sqlx::FromRow)]
struct CreatedRow {
    id: i32,
    title: String,
    severity: String,
    status: String,
    created_at: Option<NaiveDateTime>,
}

/// v1 `alerts:pending` message — field names, order, and redis-py xadd
/// stringification (`{alert_id,title,severity,source,created_at}`;
/// `source or ""`, `created_at.isoformat() if created_at else ""`).
fn alert_pending_fields(
    alert_id: i32,
    title: &str,
    severity: &str,
    source: &str,
    created_at: Option<NaiveDateTime>,
) -> skauswatch_streams::EntryFields {
    vec![
        ("alert_id".to_owned(), alert_id.to_string()),
        ("title".to_owned(), title.to_owned()),
        ("severity".to_owned(), severity.to_owned()),
        ("source".to_owned(), source.to_owned()),
        (
            "created_at".to_owned(),
            created_at
                .map(skauswatch_streams::py_isoformat)
                .unwrap_or_default(),
        ),
    ]
}

async fn create_alert(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiJson(body): ApiJson<CreateBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let v = validate_create(&body)?;

    let row = sqlx::query_as::<_, CreatedRow>(
        "INSERT INTO alerts (title, description, severity, status, source, indicators, created_at, \
          updated_at) \
         VALUES ($1, $2, $3, 'pending', $4, $5, now(), now()) \
         RETURNING id, title, severity, status, created_at",
    )
    .bind(&v.title)
    .bind(&v.description)
    .bind(&v.severity)
    .bind(&v.source)
    .bind(serde_json::Value::from(v.indicators))
    .fetch_one(&state.db)
    .await?;

    // v1 publishes alerts:pending after insert, swallowing failures
    // (try/except + warning) — publish errors never fail the request.
    state
        .publish_stream(
            skauswatch_streams::STREAM_ALERTS_PENDING,
            alert_pending_fields(row.id, &row.title, &row.severity, &v.source, row.created_at),
        )
        .await;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Alert created successfully",
            "alert": {
                "id": row.id,
                "title": row.title,
                "severity": row.severity,
                "status": row.status,
                "created_at": skauswatch_streams::py_isoformat_opt(row.created_at),
            }
        })),
    ))
}

/// AlertUpdateRequest — every field optional; absent fields are not touched.
#[derive(Deserialize)]
struct UpdateBody {
    title: Option<String>,
    description: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    assigned_to: Option<i32>,
    resolution_notes: Option<String>,
}

fn validate_update(b: &UpdateBody) -> Result<(), ApiError> {
    if let Some(t) = &b.title {
        check_len(t, "title", 1, 255)?;
    }
    if let Some(d) = &b.description {
        check_len(d, "description", 0, 4000)?;
    }
    if let Some(s) = b.severity.as_deref()
        && !SEVERITIES.contains(&s)
    {
        return Err(validation("severity", SEVERITY_MSG));
    }
    if let Some(s) = b.status.as_deref()
        && !STATUSES.contains(&s)
    {
        return Err(validation("status", STATUS_MSG));
    }
    if let Some(n) = &b.resolution_notes {
        check_len(n, "resolution_notes", 0, 2000)?;
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct UpdatedRow {
    id: i32,
    title: String,
    severity: String,
    status: String,
    updated_at: Option<NaiveDateTime>,
}

async fn update_alert(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(alert_id): Path<i32>,
    ApiJson(body): ApiJson<UpdateBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    validate_update(&body)?;

    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM alerts WHERE id = $1")
        .bind(alert_id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("Alert not found".to_owned()));
    }

    let has_updates = body.title.is_some()
        || body.description.is_some()
        || body.severity.is_some()
        || body.status.is_some()
        || body.assigned_to.is_some()
        || body.resolution_notes.is_some();
    if has_updates {
        // pyDAL sets updated_at automatically on every update (update=utcnow).
        let mut qb = QueryBuilder::<Postgres>::new("UPDATE alerts SET updated_at = now()");
        if let Some(v) = &body.title {
            qb.push(", title = ").push_bind(v.clone());
        }
        if let Some(v) = &body.description {
            qb.push(", description = ").push_bind(v.clone());
        }
        if let Some(v) = &body.severity {
            qb.push(", severity = ").push_bind(v.clone());
        }
        if let Some(v) = &body.status {
            qb.push(", status = ").push_bind(v.clone());
            if v == "resolved" {
                qb.push(", resolved_at = now()");
            }
        }
        if let Some(v) = body.assigned_to {
            qb.push(", assigned_to = ").push_bind(v);
        }
        if let Some(v) = &body.resolution_notes {
            qb.push(", resolution_notes = ").push_bind(v.clone());
        }
        qb.push(" WHERE id = ").push_bind(alert_id);
        qb.build().execute(&state.db).await?;
    }

    let row = sqlx::query_as::<_, UpdatedRow>(
        "SELECT id, title, severity, status, updated_at FROM alerts WHERE id = $1",
    )
    .bind(alert_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Alert not found".to_owned()))?;

    Ok(Json(serde_json::json!({
        "message": "Alert updated successfully",
        "alert": {
            "id": row.id,
            "title": row.title,
            "severity": row.severity,
            "status": row.status,
            "updated_at": skauswatch_streams::py_isoformat_opt(row.updated_at),
        }
    })))
}

#[derive(Deserialize)]
struct StatusBody {
    status: Option<String>,
}

async fn update_alert_status(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(alert_id): Path<i32>,
    ApiJson(body): ApiJson<StatusBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // Documented deviation from v1 (contract defect #7): v1 let ANY
    // authenticated role — including read-only viewers — mutate alert
    // status. That contradicts the role model; gate like the peer
    // alert mutations.
    user.require_role(&["admin", "maintainer"])?;
    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM alerts WHERE id = $1")
        .bind(alert_id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("Alert not found".to_owned()));
    }

    let Some(status) = body.status.as_deref().filter(|s| STATUSES.contains(s)) else {
        return Err(ApiError::BadRequest("Invalid status".to_owned()));
    };

    let sql = if status == "resolved" {
        "UPDATE alerts SET status = $1, resolved_at = now(), updated_at = now() WHERE id = $2"
    } else {
        "UPDATE alerts SET status = $1, updated_at = now() WHERE id = $2"
    };
    sqlx::query(sql)
        .bind(status)
        .bind(alert_id)
        .execute(&state.db)
        .await?;

    Ok(Json(serde_json::json!({
        "message": "Status updated",
        "alert_id": alert_id,
        "new_status": status,
    })))
}

/// Optional POST /{id}/ai-review body — v1 tolerates a missing body entirely.
#[derive(Default, Deserialize)]
struct AiReviewBody {
    provider: Option<String>,
    priority: Option<i64>,
}

/// v1 `ai:tasks` message — field names, order, and redis-py xadd
/// stringification (`{job_id,alert_id,provider,priority,task_type,
/// submitted_at}`; task_type fixed to "alert_review").
fn ai_task_fields(
    job_id: &str,
    alert_id: i32,
    provider: &str,
    priority: i64,
    submitted_at: String,
) -> skauswatch_streams::EntryFields {
    vec![
        ("job_id".to_owned(), job_id.to_owned()),
        ("alert_id".to_owned(), alert_id.to_string()),
        ("provider".to_owned(), provider.to_owned()),
        ("priority".to_owned(), priority.to_string()),
        ("task_type".to_owned(), "alert_review".to_owned()),
        ("submitted_at".to_owned(), submitted_at),
    ]
}

/// v1 parity: `AI_ENABLED` env var, default true; any value other than
/// "true" (case-insensitive) disables AI integration.
fn ai_enabled() -> bool {
    ai_enabled_value(std::env::var("AI_ENABLED").ok().as_deref())
}

fn ai_enabled_value(raw: Option<&str>) -> bool {
    raw.is_none_or(|v| v.eq_ignore_ascii_case("true"))
}

async fn request_ai_review(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(alert_id): Path<i32>,
    body: Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_role(&["admin", "maintainer"])?;

    if !ai_enabled() {
        // v1 returns this bare body; the shared envelope has no 503 variant.
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "AI integration is disabled"})),
        ));
    }

    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM alerts WHERE id = $1")
        .bind(alert_id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("Alert not found".to_owned()));
    }

    let parsed: AiReviewBody = if body.is_empty() {
        AiReviewBody::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|_| ApiError::BadRequest("Invalid JSON body".to_owned()))?
    };
    let provider = parsed
        .provider
        .unwrap_or_else(|| DEFAULT_AI_PROVIDER.to_owned());
    let priority = parsed.priority.unwrap_or(1);
    let job_id = uuid::Uuid::new_v4().to_string();
    // Python datetime.utcnow().isoformat() — v1 shape via the shared helper.
    let submitted_at = skauswatch_streams::py_now_isoformat();

    // v1 publishes ai:tasks before building the 202 response, swallowing
    // failures (try/except + warning) — the job_id is returned regardless.
    // v1 stamps a fresh utcnow() inside the publish dict, distinct from the
    // response's submitted_at.
    state
        .publish_stream(
            skauswatch_streams::STREAM_AI_TASKS,
            ai_task_fields(
                &job_id,
                alert_id,
                &provider,
                priority,
                skauswatch_streams::py_now_isoformat(),
            ),
        )
        .await;

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "message": "AI review requested",
            "job_id": job_id,
            "alert_id": alert_id,
            "provider": provider,
            "priority": priority,
            "submitted_at": submitted_at,
        })),
    ))
}

/// AlertSearchRequest — datetimes arrive as strings and are parsed leniently.
#[derive(Deserialize)]
struct SearchBody {
    query: Option<String>,
    severity: Option<Vec<String>>,
    status: Option<Vec<String>>,
    source: Option<String>,
    assigned_to: Option<i32>,
    created_after: Option<String>,
    created_before: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

fn parse_optional_datetime(
    v: &Option<String>,
    field: &str,
) -> Result<Option<NaiveDateTime>, ApiError> {
    match v {
        None => Ok(None),
        Some(s) => parse_datetime(s)
            .map(Some)
            .ok_or_else(|| validation(field, "Input should be a valid datetime")),
    }
}

/// Validates AlertSearchRequest and builds SQL filters. Python truthiness is
/// preserved: empty query/source and assigned_to=0 apply no filter.
fn validate_search(b: &SearchBody) -> Result<(AlertFilters, i64, i64), ApiError> {
    let page = b.page.unwrap_or(1);
    if page < 1 {
        return Err(validation(
            "page",
            "Input should be greater than or equal to 1",
        ));
    }
    let per_page = b.per_page.unwrap_or(20);
    if per_page < 1 {
        return Err(validation(
            "per_page",
            "Input should be greater than or equal to 1",
        ));
    }
    if per_page > 100 {
        return Err(validation(
            "per_page",
            "Input should be less than or equal to 100",
        ));
    }
    if let Some(q) = &b.query {
        check_len(q, "query", 0, 500)?;
    }
    let severity = b.severity.clone().unwrap_or_default();
    if severity.iter().any(|s| !SEVERITIES.contains(&s.as_str())) {
        return Err(validation("severity", SEVERITY_MSG));
    }
    let status = b.status.clone().unwrap_or_default();
    if status.iter().any(|s| !STATUSES.contains(&s.as_str())) {
        return Err(validation("status", STATUS_MSG));
    }
    let filters = AlertFilters {
        like: b
            .query
            .as_deref()
            .filter(|q| !q.is_empty())
            .map(|q| format!("%{}%", like_escape(q))),
        severity,
        status,
        source: b.source.clone().filter(|s| !s.is_empty()),
        assigned_to: b.assigned_to.filter(|a| *a != 0),
        created_after: parse_optional_datetime(&b.created_after, "created_after")?,
        created_before: parse_optional_datetime(&b.created_before, "created_before")?,
    };
    Ok((filters, page, per_page))
}

async fn search_alerts(
    State(state): State<AppState>,
    _user: CurrentUser,
    ApiJson(body): ApiJson<SearchBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (filters, page, per_page) = validate_search(&body)?;
    let (rows, total) = fetch_alert_page(&state.db, &filters, page, per_page).await?;
    let items: Vec<serde_json::Value> = rows.iter().map(search_json).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": total_pages(total, per_page),
    })))
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

async fn alert_statistics(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alerts")
        .fetch_one(&state.db)
        .await?;
    let sev_rows: Vec<(Option<String>, i64)> =
        sqlx::query_as("SELECT severity, COUNT(*) FROM alerts GROUP BY severity")
            .fetch_all(&state.db)
            .await?;
    let status_rows: Vec<(Option<String>, i64)> =
        sqlx::query_as("SELECT status, COUNT(*) FROM alerts GROUP BY status")
            .fetch_all(&state.db)
            .await?;
    let cutoff = Utc::now().naive_utc() - chrono::Duration::days(1);
    let last_24_hours: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE created_at >= $1")
            .bind(cutoff)
            .fetch_one(&state.db)
            .await?;

    Ok(Json(serde_json::json!({
        "total": total,
        "by_severity": bucket_counts(&SEVERITIES, &sev_rows),
        "by_status": bucket_counts(&STATUSES, &status_rows),
        "last_24_hours": last_24_hours,
    })))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn total_pages_matches_python_ceiling_division() {
        assert_eq!(total_pages(0, 20), 0);
        assert_eq!(total_pages(1, 20), 1);
        assert_eq!(total_pages(100, 20), 5);
        assert_eq!(total_pages(101, 20), 6);
    }

    #[test]
    fn like_escape_neutralizes_wildcards() {
        assert_eq!(like_escape("50%_a"), "50\\%\\_a");
        assert_eq!(like_escape("back\\slash"), "back\\\\slash");
        assert_eq!(like_escape("plain"), "plain");
    }

    #[test]
    fn parse_datetime_accepts_common_forms() {
        assert!(parse_datetime("2026-07-15T10:00:00Z").is_some());
        assert!(parse_datetime("2026-07-15T10:00:00+02:00").is_some());
        assert!(parse_datetime("2026-07-15T10:00:00.123456").is_some());
        assert!(parse_datetime("2026-07-15 10:00:00").is_some());
        let midnight =
            chrono::NaiveDate::from_ymd_opt(2026, 7, 15).and_then(|d| d.and_hms_opt(0, 0, 0));
        assert_eq!(parse_datetime("2026-07-15"), midnight);
        assert_eq!(parse_datetime("not-a-date"), None);
    }

    #[test]
    fn list_params_first_value_wins_and_lists_accumulate() {
        let pairs = vec![
            ("page".to_owned(), "3".to_owned()),
            ("page".to_owned(), "9".to_owned()),
            ("per_page".to_owned(), "500".to_owned()),
            ("severity".to_owned(), "high".to_owned()),
            ("severity".to_owned(), "critical".to_owned()),
            ("status".to_owned(), "pending".to_owned()),
            ("source".to_owned(), "endpoint".to_owned()),
        ];
        let q = parse_list_params(&pairs);
        assert_eq!(q.page, 3);
        assert_eq!(q.per_page, 100); // capped per v1 min(per_page, 100)
        assert_eq!(q.severity, vec!["high", "critical"]);
        assert_eq!(q.status, vec!["pending"]);
        assert_eq!(q.source.as_deref(), Some("endpoint"));
    }

    #[test]
    fn list_params_defaults_on_garbage() {
        let pairs = vec![("page".to_owned(), "abc".to_owned())];
        let q = parse_list_params(&pairs);
        assert_eq!(q.page, 1);
        assert_eq!(q.per_page, 20);
        assert!(q.severity.is_empty());
        assert_eq!(q.source, None);
    }

    #[test]
    fn alert_pending_fields_match_v1_names_order_and_encoding() {
        let created = chrono::NaiveDate::from_ymd_opt(2026, 7, 22)
            .and_then(|d| d.and_hms_micro_opt(9, 30, 0, 42));
        let fields = alert_pending_fields(7, "Suspicious login", "high", "endpoint", created);
        assert_eq!(
            fields,
            vec![
                ("alert_id".to_owned(), "7".to_owned()),
                ("title".to_owned(), "Suspicious login".to_owned()),
                ("severity".to_owned(), "high".to_owned()),
                ("source".to_owned(), "endpoint".to_owned()),
                (
                    "created_at".to_owned(),
                    "2026-07-22T09:30:00.000042".to_owned()
                ),
            ]
        );
        // v1: `created_at.isoformat() if created_at else ""`.
        let fields = alert_pending_fields(7, "t", "low", "", None);
        assert_eq!(fields[4], ("created_at".to_owned(), String::new()));
    }

    #[test]
    fn ai_task_fields_match_v1_names_order_and_encoding() {
        let fields = ai_task_fields(
            "6f9b7a1c-0000-0000-0000-000000000000",
            42,
            "ollama",
            2,
            "2026-07-22T09:30:00.000042".to_owned(),
        );
        assert_eq!(
            fields,
            vec![
                (
                    "job_id".to_owned(),
                    "6f9b7a1c-0000-0000-0000-000000000000".to_owned()
                ),
                ("alert_id".to_owned(), "42".to_owned()),
                ("provider".to_owned(), "ollama".to_owned()),
                ("priority".to_owned(), "2".to_owned()),
                ("task_type".to_owned(), "alert_review".to_owned()),
                (
                    "submitted_at".to_owned(),
                    "2026-07-22T09:30:00.000042".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn ai_enabled_matches_python_env_semantics() {
        assert!(ai_enabled_value(None)); // default true
        assert!(ai_enabled_value(Some("true")));
        assert!(ai_enabled_value(Some("TRUE")));
        assert!(!ai_enabled_value(Some("false")));
        assert!(!ai_enabled_value(Some("1"))); // v1: only "true" enables
    }

    #[test]
    fn create_validation_enforces_required_and_bounds() {
        let base = CreateBody {
            title: Some("t".to_owned()),
            description: Some("d".to_owned()),
            severity: Some("high".to_owned()),
            source: Some("endpoint".to_owned()),
            indicators: None,
        };
        assert!(validate_create(&base).is_ok());

        let missing = CreateBody {
            title: None,
            ..clone_create(&base)
        };
        assert!(matches!(
            validate_create(&missing),
            Err(ApiError::Validation(_))
        ));

        let bad_sev = CreateBody {
            severity: Some("apocalyptic".to_owned()),
            ..clone_create(&base)
        };
        assert!(matches!(
            validate_create(&bad_sev),
            Err(ApiError::Validation(_))
        ));

        let long_indicator = CreateBody {
            indicators: Some(vec!["x".repeat(501)]),
            ..clone_create(&base)
        };
        assert!(matches!(
            validate_create(&long_indicator),
            Err(ApiError::Validation(_))
        ));

        let stripped = CreateBody {
            indicators: Some(vec!["  1.2.3.4  ".to_owned()]),
            ..clone_create(&base)
        };
        match validate_create(&stripped) {
            Ok(v) => assert_eq!(v.indicators, vec!["1.2.3.4"]),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
    }

    fn clone_create(b: &CreateBody) -> CreateBody {
        CreateBody {
            title: b.title.clone(),
            description: b.description.clone(),
            severity: b.severity.clone(),
            source: b.source.clone(),
            indicators: b.indicators.clone(),
        }
    }

    #[test]
    fn search_validation_rejects_out_of_range_and_bad_enums() {
        let ok = SearchBody {
            query: Some("ransom".to_owned()),
            severity: Some(vec!["high".to_owned()]),
            status: None,
            source: None,
            assigned_to: Some(0),
            created_after: Some("2026-07-01".to_owned()),
            created_before: None,
            page: None,
            per_page: None,
        };
        match validate_search(&ok) {
            Ok((f, page, per_page)) => {
                assert_eq!((page, per_page), (1, 20));
                assert_eq!(f.like.as_deref(), Some("%ransom%"));
                assert_eq!(f.assigned_to, None); // Python truthiness: 0 skipped
                assert!(f.created_after.is_some());
            }
            Err(e) => panic!("expected ok, got {e:?}"),
        }

        let too_big = SearchBody {
            per_page: Some(101),
            ..clone_search(&ok)
        };
        assert!(matches!(
            validate_search(&too_big),
            Err(ApiError::Validation(_))
        ));

        let bad_status = SearchBody {
            status: Some(vec!["closed".to_owned()]),
            ..clone_search(&ok)
        };
        assert!(matches!(
            validate_search(&bad_status),
            Err(ApiError::Validation(_))
        ));

        let bad_date = SearchBody {
            created_after: Some("yesterday".to_owned()),
            ..clone_search(&ok)
        };
        assert!(matches!(
            validate_search(&bad_date),
            Err(ApiError::Validation(_))
        ));
    }

    fn clone_search(b: &SearchBody) -> SearchBody {
        SearchBody {
            query: b.query.clone(),
            severity: b.severity.clone(),
            status: b.status.clone(),
            source: b.source.clone(),
            assigned_to: b.assigned_to,
            created_after: b.created_after.clone(),
            created_before: b.created_before.clone(),
            page: b.page,
            per_page: b.per_page,
        }
    }

    #[test]
    fn indicators_normalize_null_to_empty_list() {
        assert_eq!(normalize_indicators(&None), serde_json::json!([]));
        assert_eq!(
            normalize_indicators(&Some(serde_json::Value::Null)),
            serde_json::json!([])
        );
        assert_eq!(
            normalize_indicators(&Some(serde_json::json!(["a"]))),
            serde_json::json!(["a"])
        );
    }

    #[test]
    fn bucket_counts_zero_fills_and_ignores_unknowns() {
        let rows = vec![
            (Some("high".to_owned()), 3_i64),
            (Some("bogus".to_owned()), 9_i64),
        ];
        let v = bucket_counts(&SEVERITIES, &rows);
        assert_eq!(v["high"], 3);
        assert_eq!(v["critical"], 0);
        assert_eq!(v.get("bogus"), None);
    }

    use crate::routes::test_support::{authed_user, db_state};

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    async fn server_for(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    async fn seed_alert(state: &AppState, title: &str, severity: &str, source: &str) -> i32 {
        let (id,): (i32,) = sqlx::query_as(
            "INSERT INTO alerts (title, description, severity, status, source, indicators, \
             created_at, updated_at) VALUES ($1, 'd', $2, 'pending', $3, '[]', now(), now()) \
             RETURNING id",
        )
        .bind(title)
        .bind(severity)
        .bind(source)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed_alert: {e}"));
        id
    }

    #[tokio::test]
    async fn list_and_get_alerts_round_trip_against_real_db() {
        let state = db_state(dev_license()).await;
        let id = seed_alert(&state, "C2 beacon", "critical", "endpoint").await;
        let (_, token) = authed_user(&state, "alerts-viewer@example.com", "viewer").await;
        let server = server_for(state).await;

        let list = server
            .get("/api/v1/alerts")
            .authorization_bearer(&token)
            .await;
        list.assert_status_ok();
        let body: serde_json::Value = list.json();
        assert!(body["total"].as_i64().unwrap_or(0) >= 1);
        assert!(body["items"].as_array().is_some_and(|a| !a.is_empty()));

        let get = server
            .get(&format!("/api/v1/alerts/{id}"))
            .authorization_bearer(&token)
            .await;
        get.assert_status_ok();
        let body: serde_json::Value = get.json();
        assert_eq!(body["title"], "C2 beacon");
        assert_eq!(body["indicators"], serde_json::json!([]));

        let missing = server
            .get("/api/v1/alerts/999999")
            .authorization_bearer(&token)
            .await;
        missing.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_alerts_filters_by_severity_and_status() {
        let state = db_state(dev_license()).await;
        seed_alert(&state, "Alpha", "critical", "endpoint").await;
        seed_alert(&state, "Bravo", "low", "siem").await;
        let (_, token) = authed_user(&state, "alerts-filter@example.com", "viewer").await;
        let server = server_for(state).await;

        let res = server
            .get("/api/v1/alerts?severity=critical")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        let items = body["items"].as_array().cloned().unwrap_or_default();
        assert!(items.iter().all(|i| i["severity"] == "critical"));
    }

    #[tokio::test]
    async fn create_alert_requires_role_and_validates_then_succeeds() {
        let state = db_state(dev_license()).await;
        let (_, viewer_tok) = authed_user(&state, "ca-viewer@example.com", "viewer").await;
        let (_, maint_tok) = authed_user(&state, "ca-maint@example.com", "maintainer").await;
        let server = server_for(state).await;

        let res = server
            .post("/api/v1/alerts")
            .authorization_bearer(&viewer_tok)
            .json(&serde_json::json!({
                "title": "t", "description": "d", "severity": "high", "source": "s"
            }))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);

        let res = server
            .post("/api/v1/alerts")
            .authorization_bearer(&maint_tok)
            .json(&serde_json::json!({
                "title": "", "description": "d", "severity": "high", "source": "s"
            }))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);

        let res = server
            .post("/api/v1/alerts")
            .authorization_bearer(&maint_tok)
            .json(&serde_json::json!({
                "title": "New alert", "description": "d", "severity": "medium",
                "source": "endpoint", "indicators": ["1.2.3.4"]
            }))
            .await;
        res.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["alert"]["title"], "New alert");
        assert_eq!(body["alert"]["status"], "pending");
    }

    #[tokio::test]
    async fn update_alert_validates_and_persists_changes() {
        let state = db_state(dev_license()).await;
        let id = seed_alert(&state, "Orig", "low", "manual").await;
        let (_, maint_tok) = authed_user(&state, "ua-maint@example.com", "maintainer").await;
        let server = server_for(state).await;

        let missing = server
            .put("/api/v1/alerts/999999")
            .authorization_bearer(&maint_tok)
            .json(&serde_json::json!({"title": "x"}))
            .await;
        missing.assert_status(StatusCode::NOT_FOUND);

        let bad = server
            .put(&format!("/api/v1/alerts/{id}"))
            .authorization_bearer(&maint_tok)
            .json(&serde_json::json!({"severity": "apocalyptic"}))
            .await;
        bad.assert_status(StatusCode::BAD_REQUEST);

        let res = server
            .put(&format!("/api/v1/alerts/{id}"))
            .authorization_bearer(&maint_tok)
            .json(&serde_json::json!({"status": "resolved", "resolution_notes": "fixed"}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["alert"]["status"], "resolved");
    }

    #[tokio::test]
    async fn update_alert_status_endpoint_gates_role_and_validates() {
        let state = db_state(dev_license()).await;
        let id = seed_alert(&state, "S", "low", "manual").await;
        let (_, viewer_tok) = authed_user(&state, "uas-viewer@example.com", "viewer").await;
        let (_, admin_tok) = authed_user(&state, "uas-admin@example.com", "admin").await;
        let server = server_for(state).await;

        let res = server
            .put(&format!("/api/v1/alerts/{id}/status"))
            .authorization_bearer(&viewer_tok)
            .json(&serde_json::json!({"status": "resolved"}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);

        let bad = server
            .put(&format!("/api/v1/alerts/{id}/status"))
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"status": "bogus"}))
            .await;
        bad.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = bad.json();
        assert_eq!(body["error"], "Invalid status");

        let missing = server
            .put("/api/v1/alerts/999999/status")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"status": "resolved"}))
            .await;
        missing.assert_status(StatusCode::NOT_FOUND);

        let res = server
            .put(&format!("/api/v1/alerts/{id}/status"))
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"status": "resolved"}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["new_status"], "resolved");
    }

    // Note: the AI_ENABLED=false 503 branch is exercised at the pure-function
    // level only (`ai_enabled_matches_python_env_semantics` above) — the
    // workspace forbids `unsafe`, so this crate cannot mutate a process-global
    // env var from a test to drive that branch through the HTTP surface.

    #[tokio::test]
    async fn request_ai_review_requires_role_404s_missing_then_accepts() {
        let state = db_state(dev_license()).await;
        let id = seed_alert(&state, "R", "high", "endpoint").await;
        let (_, viewer_tok) = authed_user(&state, "air-viewer@example.com", "viewer").await;
        let (_, maint_tok) = authed_user(&state, "air-maint@example.com", "maintainer").await;
        let server = server_for(state).await;

        let res = server
            .post(&format!("/api/v1/alerts/{id}/ai-review"))
            .authorization_bearer(&viewer_tok)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);

        let missing = server
            .post("/api/v1/alerts/999999/ai-review")
            .authorization_bearer(&maint_tok)
            .await;
        missing.assert_status(StatusCode::NOT_FOUND);

        let res = server
            .post(&format!("/api/v1/alerts/{id}/ai-review"))
            .authorization_bearer(&maint_tok)
            .json(&serde_json::json!({"provider": "ollama", "priority": 2}))
            .await;
        res.assert_status(StatusCode::ACCEPTED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["provider"], "ollama");
        assert_eq!(body["priority"], 2);
        assert!(body["job_id"].as_str().is_some_and(|s| !s.is_empty()));
    }

    #[tokio::test]
    async fn search_alerts_validates_and_filters() {
        let state = db_state(dev_license()).await;
        seed_alert(&state, "Ransomware hit", "critical", "endpoint").await;
        let (_, token) = authed_user(&state, "search@example.com", "viewer").await;
        let server = server_for(state).await;

        let bad = server
            .post("/api/v1/alerts/search")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"per_page": 0}))
            .await;
        bad.assert_status(StatusCode::BAD_REQUEST);

        let res = server
            .post("/api/v1/alerts/search")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"query": "Ransomware"}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["total"].as_i64().unwrap_or(0) >= 1);
    }

    #[tokio::test]
    async fn alert_statistics_returns_zero_filled_buckets() {
        let state = db_state(dev_license()).await;
        seed_alert(&state, "S1", "high", "endpoint").await;
        let (_, token) = authed_user(&state, "stats@example.com", "viewer").await;
        let server = server_for(state).await;
        let res = server
            .get("/api/v1/alerts/statistics")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["total"].as_i64().unwrap_or(0) >= 1);
        assert!(body["by_severity"]["high"].as_i64().unwrap_or(0) >= 1);
        assert_eq!(body["by_status"]["resolved"], 0);
        assert!(body["last_24_hours"].as_i64().unwrap_or(0) >= 1);
    }
}
