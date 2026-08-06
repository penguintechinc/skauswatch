//! /api/v1/approvals — approval-workflow CRUD, multi-approver decisions,
//! cancellation, and statistics. Contract: docs/v2-port/manager-contract.md
//! §approvals; Python source of truth: services/manager/api/v1/approvals.py.
//!
//! v1's bare `{"error": ...}` bodies map onto the `ApiError` envelope (same
//! convention as routes/users.rs). JSONB mutations are read-modify-write
//! inside a transaction, matching the v1 PyDAL read+update race semantics
//! (no row locking, no jsonb_set). Deviation (shared with the other ported
//! routers): explicit JSON `null` for defaulted body fields falls back to
//! the default instead of pydantic's "not a valid X" error.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::Deserialize;
use sqlx::{Postgres, QueryBuilder};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

/// v1 `ApprovalStatus` enum values (statistics buckets).
const STATUSES: [&str; 4] = ["pending", "approved", "rejected", "expired"];
/// v1 `ApprovalType` enum values (request_type buckets + create validation).
const TYPES: [&str; 4] = ["certificate", "user", "service", "configuration"];
const TYPE_MSG: &str = "Input should be 'certificate', 'user', 'service' or 'configuration'";

/// List-item projection: the GET /approvals response omits the jsonb columns.
const LIST_COLUMNS: &str = "SELECT id, request_type, resource_id, resource_type, requester_id, \
     status, required_approvals, current_approvals, expires_at, created_at \
     FROM approval_requests WHERE TRUE";

/// Router for /api/v1/approvals.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/approvals", get(list_approvals).post(create_approval))
        .route("/approvals/pending", get(list_pending_approvals))
        .route("/approvals/statistics", get(get_statistics))
        .route("/approvals/{approval_id}", get(get_approval))
        .route("/approvals/{approval_id}/decide", post(decide_approval))
        .route("/approvals/{approval_id}/cancel", post(cancel_approval))
}

/// Builds the v1 `{error: "Validation error", details: [...]}` body for a
/// single-field failure (same helper shape as routes/alerts.rs).
fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// pydantic-style max-length check (character count, not bytes).
fn check_max_len(s: &str, field: &str, max: usize) -> Result<(), ApiError> {
    if s.chars().count() > max {
        return Err(validation(
            field,
            &format!("String should have at most {max} characters"),
        ));
    }
    Ok(())
}

/// pydantic-style required string with a max-length bound.
fn required_str(v: &Option<String>, field: &str, max: usize) -> Result<String, ApiError> {
    let Some(s) = v else {
        return Err(validation(field, "Field required"));
    };
    check_max_len(s, field, max)?;
    Ok(s.clone())
}

/// pydantic-style `ge`/`le` integer bound check.
fn check_range(v: i64, field: &str, min: i64, max: i64) -> Result<(), ApiError> {
    if v < min {
        return Err(validation(
            field,
            &format!("Input should be greater than or equal to {min}"),
        ));
    }
    if v > max {
        return Err(validation(
            field,
            &format!("Input should be less than or equal to {max}"),
        ));
    }
    Ok(())
}

/// v1 parity: `value or []` — SQL NULL / jsonb null become `[]`.
fn normalize_array(v: &Option<serde_json::Value>) -> serde_json::Value {
    match v {
        Some(val) if !val.is_null() => val.clone(),
        _ => serde_json::Value::Array(vec![]),
    }
}

/// v1 parity: `value or {}` — SQL NULL / jsonb null become `{}`.
fn normalize_object(v: &Option<serde_json::Value>) -> serde_json::Value {
    match v {
        Some(val) if !val.is_null() => val.clone(),
        _ => serde_json::Value::Object(serde_json::Map::new()),
    }
}

/// True when `approval_history` already holds a decision by `user_id` — the
/// v1 `any(h.get("user_id") == g.current_user_id ...)` check used by both
/// the pending list (exclusion) and the decide endpoint (400).
fn has_decided(history: &serde_json::Value, user_id: i32) -> bool {
    history.as_array().is_some_and(|entries| {
        entries.iter().any(|h| {
            h.get("user_id").and_then(serde_json::Value::as_i64) == Some(i64::from(user_id))
        })
    })
}

/// v1 pages math: `(total + per_page - 1) // per_page` (per_page >= 1).
fn total_pages(total: i64, per_page: i64) -> i64 {
    (total + per_page - 1) / per_page
}

/// Parsed GET /approvals query params (Quart request.args semantics).
struct ListQuery {
    page: i64,
    per_page: i64,
    status: Vec<String>,
    request_type: Vec<String>,
    requester_id: Option<i32>,
}

/// Quart parity: first value wins for scalars (unparsable ints fall back to
/// the default), repeated `status`/`type` keys accumulate, and
/// `requester_id` follows Python truthiness (0 applies no filter).
/// Deviation: page/per_page floored at 1 — v1 divides by zero on per_page=0.
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
        status: collect("status"),
        request_type: collect("type"),
        requester_id: first("requester_id")
            .and_then(|v| v.parse::<i32>().ok())
            .filter(|v| *v != 0),
    }
}

/// WHERE-clause inputs shared by the list page and count queries.
struct ListFilters {
    status: Vec<String>,
    request_type: Vec<String>,
    requester_id: Option<i32>,
}

fn push_list_filters(qb: &mut QueryBuilder<Postgres>, f: &ListFilters) {
    if !f.status.is_empty() {
        qb.push(" AND status = ANY(")
            .push_bind(f.status.clone())
            .push(")");
    }
    if !f.request_type.is_empty() {
        qb.push(" AND request_type = ANY(")
            .push_bind(f.request_type.clone())
            .push(")");
    }
    if let Some(r) = f.requester_id {
        qb.push(" AND requester_id = ").push_bind(r);
    }
}

/// List-item row (`LIST_COLUMNS`) — timestamps as chrono `NaiveDateTime`
/// (rendered with `py_isoformat` for v1 wire parity).
#[derive(sqlx::FromRow)]
struct ApprovalListRow {
    id: i32,
    request_type: String,
    resource_id: Option<String>,
    resource_type: Option<String>,
    requester_id: i32,
    status: Option<String>,
    required_approvals: Option<i32>,
    current_approvals: Option<i32>,
    expires_at: Option<NaiveDateTime>,
    created_at: Option<NaiveDateTime>,
}

/// v1 list-item response shape (GET /approvals items).
fn list_item_json(r: &ApprovalListRow) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "request_type": r.request_type,
        "resource_id": r.resource_id,
        "resource_type": r.resource_type,
        "requester_id": r.requester_id,
        "status": r.status,
        "required_approvals": r.required_approvals,
        "current_approvals": r.current_approvals,
        "expires_at": skauswatch_streams::py_isoformat_opt(r.expires_at),
        "created_at": skauswatch_streams::py_isoformat_opt(r.created_at),
    })
}

/// Documentation-only mirror of `list_item_json`'s wire shape.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalListItem {
    id: i32,
    request_type: String,
    resource_id: Option<String>,
    resource_type: Option<String>,
    requester_id: i32,
    status: Option<String>,
    required_approvals: Option<i32>,
    current_approvals: Option<i32>,
    expires_at: Option<String>,
    created_at: Option<String>,
}

/// Documentation-only mirror of `list_approvals`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalListResponse {
    items: Vec<ApprovalListItem>,
    total: i64,
    page: i64,
    per_page: i64,
    pages: i64,
}

/// GET /approvals — any authenticated user; paginated with status[]/type[]
/// (repeated) and requester_id filters, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/approvals",
    tag = "approvals",
    security(("bearer_jwt" = [])),
    params(
        ("page" = Option<i64>, Query, description = "1-based page number (default 1)"),
        ("per_page" = Option<i64>, Query, description = "Page size, capped at 100 (default 20)"),
        ("status" = Option<Vec<String>>, Query, description = "Repeatable status filter"),
        ("type" = Option<Vec<String>>, Query, description = "Repeatable request_type filter"),
        ("requester_id" = Option<i32>, Query, description = "Exact requester filter (0 = no filter)"),
    ),
    responses(
        (status = 200, description = "Paginated approval list", body = ApprovalListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_approvals(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let q = parse_list_params(&params);
    let filters = ListFilters {
        status: q.status,
        request_type: q.request_type,
        requester_id: q.requester_id,
    };
    let offset = (q.page - 1) * q.per_page;

    let mut qb = QueryBuilder::new(LIST_COLUMNS);
    qb.push(" AND tenant_id = ").push_bind(user.tenant_id);
    push_list_filters(&mut qb, &filters);
    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(q.per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let rows = qb
        .build_query_as::<ApprovalListRow>()
        .fetch_all(&state.db)
        .await?;

    let mut cq = QueryBuilder::new("SELECT COUNT(*) FROM approval_requests WHERE TRUE");
    cq.push(" AND tenant_id = ").push_bind(user.tenant_id);
    push_list_filters(&mut cq, &filters);
    let total: i64 = cq.build_query_scalar().fetch_one(&state.db).await?;

    let items: Vec<serde_json::Value> = rows.iter().map(list_item_json).collect();
    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": q.page,
        "per_page": q.per_page,
        "pages": total_pages(total, q.per_page),
    })))
}

/// Pending-list row — list fields plus the jsonb needed for exclusion and
/// the metadata included in the pending item shape.
#[derive(sqlx::FromRow)]
struct PendingRow {
    id: i32,
    request_type: String,
    resource_id: Option<String>,
    resource_type: Option<String>,
    requester_id: i32,
    status: Option<String>,
    required_approvals: Option<i32>,
    current_approvals: Option<i32>,
    metadata: Option<serde_json::Value>,
    approval_history: Option<serde_json::Value>,
    expires_at: Option<NaiveDateTime>,
    created_at: Option<NaiveDateTime>,
}

/// Documentation-only mirror of one `list_pending_approvals` item.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalPendingItem {
    id: i32,
    request_type: String,
    resource_id: Option<String>,
    resource_type: Option<String>,
    requester_id: i32,
    status: Option<String>,
    required_approvals: Option<i32>,
    current_approvals: Option<i32>,
    metadata: serde_json::Value,
    expires_at: Option<String>,
    created_at: Option<String>,
}

/// Documentation-only mirror of `list_pending_approvals`'s
/// `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalPendingResponse {
    count: usize,
    items: Vec<ApprovalPendingItem>,
}

/// GET /approvals/pending — admin/maintainer; non-expired pending requests
/// excluding those the current user has already decided (derived from
/// `approval_history` user_id entries). Returns `{items, count}`.
#[utoipa::path(
    get,
    path = "/api/v1/approvals/pending",
    tag = "approvals",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Non-expired pending approvals awaiting the caller's decision", body = ApprovalPendingResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_pending_approvals(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let now = Utc::now().naive_utc();

    let rows = sqlx::query_as::<_, PendingRow>(
        "SELECT id, request_type, resource_id, resource_type, requester_id, status, \
                required_approvals, current_approvals, metadata, approval_history, \
                expires_at, created_at \
         FROM approval_requests \
         WHERE status = 'pending' AND (expires_at IS NULL OR expires_at > $1) \
           AND tenant_id = $2 \
         ORDER BY created_at DESC",
    )
    .bind(now)
    .bind(user.tenant_id)
    .fetch_all(&state.db)
    .await?;

    let items: Vec<serde_json::Value> = rows
        .iter()
        .filter(|r| !has_decided(&normalize_array(&r.approval_history), user.id))
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "request_type": r.request_type,
                "resource_id": r.resource_id,
                "resource_type": r.resource_type,
                "requester_id": r.requester_id,
                "status": r.status,
                "required_approvals": r.required_approvals,
                "current_approvals": r.current_approvals,
                "metadata": normalize_object(&r.metadata),
                "expires_at": skauswatch_streams::py_isoformat_opt(r.expires_at),
                "created_at": skauswatch_streams::py_isoformat_opt(r.created_at),
            })
        })
        .collect();

    Ok(Json(serde_json::json!({
        "count": items.len(),
        "items": items,
    })))
}

/// Full row for GET /approvals/{id} — all columns, jsonb as `Value`,
/// timestamps as chrono `NaiveDateTime`.
#[derive(sqlx::FromRow)]
struct ApprovalFullRow {
    id: i32,
    request_type: String,
    resource_id: Option<String>,
    resource_type: Option<String>,
    requester_id: i32,
    status: Option<String>,
    required_approvals: Option<i32>,
    current_approvals: Option<i32>,
    approvers: Option<serde_json::Value>,
    approval_history: Option<serde_json::Value>,
    metadata: Option<serde_json::Value>,
    expires_at: Option<NaiveDateTime>,
    completed_at: Option<NaiveDateTime>,
    created_at: Option<NaiveDateTime>,
    updated_at: Option<NaiveDateTime>,
}

/// Documentation-only mirror of `get_approval`'s wire shape.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalDetail {
    id: i32,
    request_type: String,
    resource_id: Option<String>,
    resource_type: Option<String>,
    requester_id: i32,
    status: Option<String>,
    required_approvals: Option<i32>,
    current_approvals: Option<i32>,
    approvers: serde_json::Value,
    approval_history: serde_json::Value,
    metadata: serde_json::Value,
    expires_at: Option<String>,
    completed_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// GET /approvals/{approval_id} — any authenticated user; full object.
#[utoipa::path(
    get,
    path = "/api/v1/approvals/{approval_id}",
    tag = "approvals",
    security(("bearer_jwt" = [])),
    params(("approval_id" = i32, Path, description = "Approval request id")),
    responses(
        (status = 200, description = "Approval request detail", body = ApprovalDetail),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Approval request not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_approval(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(approval_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let r = sqlx::query_as::<_, ApprovalFullRow>(
        "SELECT id, request_type, resource_id, resource_type, requester_id, status, \
                required_approvals, current_approvals, approvers, approval_history, \
                metadata, expires_at, completed_at, \
                created_at, updated_at \
         FROM approval_requests WHERE id = $1 AND tenant_id = $2",
    )
    .bind(approval_id)
    .bind(user.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Approval request not found".to_owned()))?;

    Ok(Json(serde_json::json!({
        "id": r.id,
        "request_type": r.request_type,
        "resource_id": r.resource_id,
        "resource_type": r.resource_type,
        "requester_id": r.requester_id,
        "status": r.status,
        "required_approvals": r.required_approvals,
        "current_approvals": r.current_approvals,
        "approvers": normalize_array(&r.approvers),
        "approval_history": normalize_array(&r.approval_history),
        "metadata": normalize_object(&r.metadata),
        "expires_at": skauswatch_streams::py_isoformat_opt(r.expires_at),
        "completed_at": skauswatch_streams::py_isoformat_opt(r.completed_at),
        "created_at": skauswatch_streams::py_isoformat_opt(r.created_at),
        "updated_at": skauswatch_streams::py_isoformat_opt(r.updated_at),
    })))
}

/// ApprovalCreateRequest — fields optional here so missing ones map to the
/// validation envelope instead of an axum extractor rejection.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateBody {
    request_type: Option<String>,
    resource_id: Option<String>,
    resource_type: Option<String>,
    metadata: Option<serde_json::Value>,
    required_approvals: Option<i64>,
    expires_hours: Option<i64>,
}

struct ValidCreate {
    request_type: String,
    resource_id: String,
    resource_type: String,
    metadata: serde_json::Value,
    required_approvals: i32,
    expires_hours: i64,
}

/// Mirrors pydantic ApprovalCreateRequest: request_type enum, resource_id
/// <=128, resource_type <=50, metadata dict (default {}),
/// required_approvals 1-10 (default 1), expires_hours 1-168 (default 24).
fn validate_create(b: &CreateBody) -> Result<ValidCreate, ApiError> {
    let Some(request_type) = b.request_type.as_deref() else {
        return Err(validation("request_type", "Field required"));
    };
    if !TYPES.contains(&request_type) {
        return Err(validation("request_type", TYPE_MSG));
    }
    let resource_id = required_str(&b.resource_id, "resource_id", 128)?;
    let resource_type = required_str(&b.resource_type, "resource_type", 50)?;
    let metadata = match &b.metadata {
        None => serde_json::Value::Object(serde_json::Map::new()),
        Some(v) if v.is_object() => v.clone(),
        Some(_) => {
            return Err(validation("metadata", "Input should be a valid dictionary"));
        }
    };
    let required_approvals = b.required_approvals.unwrap_or(1);
    check_range(required_approvals, "required_approvals", 1, 10)?;
    let expires_hours = b.expires_hours.unwrap_or(24);
    check_range(expires_hours, "expires_hours", 1, 168)?;
    Ok(ValidCreate {
        request_type: request_type.to_owned(),
        resource_id,
        resource_type,
        metadata,
        required_approvals: required_approvals as i32,
        expires_hours,
    })
}

#[derive(sqlx::FromRow)]
struct CreatedRow {
    id: i32,
    request_type: String,
    resource_id: String,
    status: String,
    expires_at: Option<NaiveDateTime>,
    created_at: Option<NaiveDateTime>,
}

/// Summary embedded in [`ApprovalCreateResponse`].
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalCreateSummary {
    id: i32,
    request_type: String,
    resource_id: String,
    status: String,
    expires_at: Option<String>,
    created_at: Option<String>,
}

/// Documentation-only mirror of `create_approval`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalCreateResponse {
    message: String,
    approval: ApprovalCreateSummary,
}

/// POST /approvals — any authenticated user; requester_id = current user,
/// expires_at = now + expires_hours; 201 `{message, approval}`.
#[utoipa::path(
    post,
    path = "/api/v1/approvals",
    tag = "approvals",
    security(("bearer_jwt" = [])),
    request_body = CreateBody,
    responses(
        (status = 201, description = "Approval request created", body = ApprovalCreateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_approval(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiJson(body): ApiJson<CreateBody>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    let v = validate_create(&body)?;
    let now = Utc::now().naive_utc();
    let expires_at = now + chrono::Duration::hours(v.expires_hours);

    let row = sqlx::query_as::<_, CreatedRow>(
        "INSERT INTO approval_requests \
             (request_type, resource_id, resource_type, requester_id, status, \
              required_approvals, current_approvals, approvers, approval_history, \
              metadata, expires_at, tenant_id, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'pending', $5, 0, '[]'::jsonb, '[]'::jsonb, $6, $7, $8, $9, $9) \
         RETURNING id, request_type, resource_id, status, expires_at, created_at",
    )
    .bind(&v.request_type)
    .bind(&v.resource_id)
    .bind(&v.resource_type)
    .bind(user.id)
    .bind(v.required_approvals)
    .bind(&v.metadata)
    .bind(expires_at)
    .bind(user.tenant_id)
    .bind(now)
    .fetch_one(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Approval request created",
            "approval": {
                "id": row.id,
                "request_type": row.request_type,
                "resource_id": row.resource_id,
                "status": row.status,
                "expires_at": skauswatch_streams::py_isoformat_opt(row.expires_at),
                "created_at": skauswatch_streams::py_isoformat_opt(row.created_at),
            }
        })),
    ))
}

/// ApprovalDecisionRequest — `approved` required, `reason` optional <=1000.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct DecideBody {
    approved: Option<bool>,
    reason: Option<String>,
}

/// Snapshot read for the decide/cancel state machine. Nullable count/status
/// columns are COALESCEd to their v1 defaults — rows created through the API
/// always populate them.
#[derive(sqlx::FromRow)]
struct DecisionRow {
    status: String,
    requester_id: i32,
    required_approvals: i32,
    current_approvals: i32,
    approvers: Option<serde_json::Value>,
    approval_history: Option<serde_json::Value>,
    expires_at: Option<NaiveDateTime>,
}

/// Pre-decision guard outcomes, in the exact v1 check order.
#[derive(Debug, PartialEq, Eq)]
enum DecisionGuard {
    /// status != pending → 400 "Approval request already {status}".
    AlreadyCompleted,
    /// expires_at <= now → persist status=expired, 400.
    Expired,
    /// requester decides own request → 403.
    OwnRequest,
    /// user already in approval_history → 400.
    AlreadyDecided,
    /// All checks passed.
    Proceed,
}

/// Runs the v1 decide guards in order: completed → expired → own request →
/// already decided. `history` must already be normalized to an array value.
fn check_decision_guards(
    status: &str,
    expires_at: Option<NaiveDateTime>,
    requester_id: i32,
    history: &serde_json::Value,
    user_id: i32,
    now: NaiveDateTime,
) -> DecisionGuard {
    if status != "pending" {
        return DecisionGuard::AlreadyCompleted;
    }
    if expires_at.is_some_and(|t| t <= now) {
        return DecisionGuard::Expired;
    }
    if requester_id == user_id {
        return DecisionGuard::OwnRequest;
    }
    if has_decided(history, user_id) {
        return DecisionGuard::AlreadyDecided;
    }
    DecisionGuard::Proceed
}

/// One reviewer's decision, ready to be appended to `approval_history`.
struct Decision<'a> {
    user_id: i32,
    user_email: &'a str,
    approved: bool,
    reason: Option<&'a str>,
    timestamp: &'a str,
}

/// Column changes computed by `apply_decision`.
#[derive(Debug, PartialEq, Eq)]
struct DecisionUpdate {
    /// New status, or `None` when the request stays pending.
    new_status: Option<&'static str>,
    /// Incremented approval count (approve path only).
    new_current_approvals: Option<i32>,
    /// Approvers array with the deciding user appended (approve path only).
    new_approvers: Option<serde_json::Value>,
    /// History with the decision record appended (always written).
    new_history: serde_json::Value,
    /// Whether completed_at is set to now.
    completed: bool,
}

/// v1 decision state machine: approve appends to approvers + history and
/// increments the count, flipping to approved when it reaches
/// required_approvals; any reject short-circuits to rejected + completed.
fn apply_decision(
    current_approvals: i32,
    required_approvals: i32,
    approvers: &serde_json::Value,
    history: &serde_json::Value,
    d: &Decision<'_>,
) -> DecisionUpdate {
    let mut new_history = history.as_array().cloned().unwrap_or_default();
    new_history.push(serde_json::json!({
        "user_id": d.user_id,
        "user_email": d.user_email,
        "approved": d.approved,
        "reason": d.reason,
        "timestamp": d.timestamp,
    }));
    let new_history = serde_json::Value::Array(new_history);

    if d.approved {
        let count = current_approvals + 1;
        let mut new_approvers = approvers.as_array().cloned().unwrap_or_default();
        new_approvers.push(serde_json::json!(d.user_id));
        let done = count >= required_approvals;
        DecisionUpdate {
            new_status: done.then_some("approved"),
            new_current_approvals: Some(count),
            new_approvers: Some(serde_json::Value::Array(new_approvers)),
            new_history,
            completed: done,
        }
    } else {
        DecisionUpdate {
            new_status: Some("rejected"),
            new_current_approvals: None,
            new_approvers: None,
            new_history,
            completed: true,
        }
    }
}

#[derive(sqlx::FromRow)]
struct DecidedRow {
    id: i32,
    status: Option<String>,
    current_approvals: Option<i32>,
    required_approvals: Option<i32>,
    completed_at: Option<NaiveDateTime>,
}

/// Summary embedded in [`ApprovalDecisionResponse`].
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalDecisionSummary {
    id: i32,
    status: Option<String>,
    current_approvals: Option<i32>,
    required_approvals: Option<i32>,
    completed_at: Option<String>,
}

/// Documentation-only mirror of `decide_approval`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalDecisionResponse {
    message: String,
    approval: ApprovalDecisionSummary,
}

/// POST /approvals/{approval_id}/decide — admin/maintainer; records an
/// approve/reject, enforcing the v1 guard order, and returns the updated
/// counters. Read-modify-write runs in one transaction (v1 race semantics).
#[utoipa::path(
    post,
    path = "/api/v1/approvals/{approval_id}/decide",
    tag = "approvals",
    security(("bearer_jwt" = [])),
    params(("approval_id" = i32, Path, description = "Approval request id")),
    request_body = DecideBody,
    responses(
        (status = 200, description = "Decision recorded", body = ApprovalDecisionResponse),
        (status = 400, description = "Validation error, already completed/decided, or expired", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions, or caller is the requester", body = ErrorResponse),
        (status = 404, description = "Approval request not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn decide_approval(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(approval_id): Path<i32>,
    ApiJson(body): ApiJson<DecideBody>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let Some(approved) = body.approved else {
        return Err(validation("approved", "Field required"));
    };
    if let Some(reason) = body.reason.as_deref() {
        check_max_len(reason, "reason", 1000)?;
    }

    let now = Utc::now().naive_utc();
    let mut tx = state.db.begin().await?;

    let row = sqlx::query_as::<_, DecisionRow>(
        "SELECT COALESCE(status, 'pending') AS status, requester_id, \
                COALESCE(required_approvals, 1) AS required_approvals, \
                COALESCE(current_approvals, 0) AS current_approvals, \
                approvers, approval_history, expires_at \
         FROM approval_requests WHERE id = $1 AND tenant_id = $2",
    )
    .bind(approval_id)
    .bind(user.tenant_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| ApiError::NotFound("Approval request not found".to_owned()))?;

    let history = normalize_array(&row.approval_history);
    match check_decision_guards(
        &row.status,
        row.expires_at,
        row.requester_id,
        &history,
        user.id,
        now,
    ) {
        DecisionGuard::AlreadyCompleted => {
            return Err(ApiError::BadRequest(format!(
                "Approval request already {}",
                row.status
            )));
        }
        DecisionGuard::Expired => {
            sqlx::query(
                "UPDATE approval_requests SET status = 'expired', updated_at = $2 \
                 WHERE id = $1 AND tenant_id = $3",
            )
            .bind(approval_id)
            .bind(now)
            .bind(user.tenant_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Err(ApiError::BadRequest(
                "Approval request has expired".to_owned(),
            ));
        }
        DecisionGuard::OwnRequest => {
            return Err(ApiError::Forbidden(
                "Cannot approve your own request".to_owned(),
            ));
        }
        DecisionGuard::AlreadyDecided => {
            return Err(ApiError::BadRequest(
                "You have already made a decision on this request".to_owned(),
            ));
        }
        DecisionGuard::Proceed => {}
    }

    let timestamp = skauswatch_streams::py_isoformat(now);
    let upd = apply_decision(
        row.current_approvals,
        row.required_approvals,
        &normalize_array(&row.approvers),
        &history,
        &Decision {
            user_id: user.id,
            user_email: &user.email,
            approved,
            reason: body.reason.as_deref(),
            timestamp: &timestamp,
        },
    );

    // PyDAL parity: `update=datetime.utcnow` bumps updated_at on every update.
    let mut qb = QueryBuilder::<Postgres>::new("UPDATE approval_requests SET updated_at = ");
    qb.push_bind(now);
    qb.push(", approval_history = ").push_bind(upd.new_history);
    if let Some(count) = upd.new_current_approvals {
        qb.push(", current_approvals = ").push_bind(count);
    }
    if let Some(approvers) = upd.new_approvers {
        qb.push(", approvers = ").push_bind(approvers);
    }
    if let Some(status) = upd.new_status {
        qb.push(", status = ").push_bind(status);
    }
    if upd.completed {
        qb.push(", completed_at = ").push_bind(now);
    }
    qb.push(" WHERE id = ")
        .push_bind(approval_id)
        .push(" AND tenant_id = ")
        .push_bind(user.tenant_id);
    qb.build().execute(&mut *tx).await?;
    tx.commit().await?;

    let out = sqlx::query_as::<_, DecidedRow>(
        "SELECT id, status, current_approvals, required_approvals, completed_at \
         FROM approval_requests WHERE id = $1 AND tenant_id = $2",
    )
    .bind(approval_id)
    .bind(user.tenant_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Approval request not found".to_owned()))?;

    Ok(Json(serde_json::json!({
        "message": "Decision recorded",
        "approval": {
            "id": out.id,
            "status": out.status,
            "current_approvals": out.current_approvals,
            "required_approvals": out.required_approvals,
            "completed_at": skauswatch_streams::py_isoformat_opt(out.completed_at),
        }
    })))
}

/// Documentation-only mirror of `cancel_approval`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalCancelResponse {
    message: String,
}

/// POST /approvals/{approval_id}/cancel — requester or admin; only pending
/// requests can be cancelled. v1 semantics: cancellation sets
/// status=rejected (there is no "cancelled" status) + completed_at.
#[utoipa::path(
    post,
    path = "/api/v1/approvals/{approval_id}/cancel",
    tag = "approvals",
    security(("bearer_jwt" = [])),
    params(("approval_id" = i32, Path, description = "Approval request id")),
    responses(
        (status = 200, description = "Approval request cancelled", body = ApprovalCancelResponse),
        (status = 400, description = "Request is not pending", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Caller is neither the requester nor an admin", body = ErrorResponse),
        (status = 404, description = "Approval request not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn cancel_approval(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(approval_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let row: Option<(i32, String)> = sqlx::query_as(
        "SELECT requester_id, COALESCE(status, 'pending') AS status \
         FROM approval_requests WHERE id = $1 AND tenant_id = $2",
    )
    .bind(approval_id)
    .bind(user.tenant_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((requester_id, status)) = row else {
        return Err(ApiError::NotFound("Approval request not found".to_owned()));
    };

    let is_requester = requester_id == user.id;
    let is_admin = user.role == "admin";
    if !is_requester && !is_admin {
        return Err(ApiError::Forbidden("Forbidden".to_owned()));
    }

    if status != "pending" {
        return Err(ApiError::BadRequest(format!(
            "Cannot cancel {status} request"
        )));
    }

    let now = Utc::now().naive_utc();
    sqlx::query(
        "UPDATE approval_requests \
         SET status = 'rejected', completed_at = $2, updated_at = $2 \
         WHERE id = $1 AND tenant_id = $3",
    )
    .bind(approval_id)
    .bind(now)
    .bind(user.tenant_id)
    .execute(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "message": "Approval request cancelled"
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

/// Documentation-only mirror of `get_statistics`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct ApprovalStatisticsResponse {
    total: i64,
    /// Zero-filled per-status counts, keyed by the four canonical values.
    by_status: std::collections::BTreeMap<String, i64>,
    /// Zero-filled per-type counts, keyed by the four canonical values.
    by_type: std::collections::BTreeMap<String, i64>,
    expired_pending: i64,
    last_7_days: i64,
}

/// GET /approvals/statistics — admin/maintainer;
/// `{total, by_status, by_type, expired_pending, last_7_days}`.
#[utoipa::path(
    get,
    path = "/api/v1/approvals/statistics",
    operation_id = "approvals_get_statistics",
    tag = "approvals",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Approval statistics", body = ApprovalStatisticsResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_statistics(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let now = Utc::now().naive_utc();

    let total: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM approval_requests WHERE tenant_id = $1")
            .bind(user.tenant_id)
            .fetch_one(&state.db)
            .await?;
    let status_rows: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT status, COUNT(*) FROM approval_requests WHERE tenant_id = $1 GROUP BY status",
    )
    .bind(user.tenant_id)
    .fetch_all(&state.db)
    .await?;
    let type_rows: Vec<(Option<String>, i64)> = sqlx::query_as(
        "SELECT request_type, COUNT(*) FROM approval_requests \
         WHERE tenant_id = $1 GROUP BY request_type",
    )
    .bind(user.tenant_id)
    .fetch_all(&state.db)
    .await?;
    let expired_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_requests \
         WHERE tenant_id = $1 AND status = 'pending' \
           AND expires_at IS NOT NULL AND expires_at <= $2",
    )
    .bind(user.tenant_id)
    .bind(now)
    .fetch_one(&state.db)
    .await?;
    let week_ago = now - chrono::Duration::days(7);
    let last_7_days: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM approval_requests WHERE tenant_id = $1 AND created_at >= $2",
    )
    .bind(user.tenant_id)
    .bind(week_ago)
    .fetch_one(&state.db)
    .await?;

    Ok(Json(serde_json::json!({
        "total": total,
        "by_status": bucket_counts(&STATUSES, &status_rows),
        "by_type": bucket_counts(&TYPES, &type_rows),
        "expired_pending": expired_pending,
        "last_7_days": last_7_days,
    })))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn dt(s: &str) -> NaiveDateTime {
        match NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
            Ok(t) => t,
            Err(e) => panic!("bad test datetime {s}: {e}"),
        }
    }

    fn history_with(user_ids: &[i32]) -> serde_json::Value {
        serde_json::Value::Array(
            user_ids
                .iter()
                .map(|id| serde_json::json!({"user_id": id, "approved": true}))
                .collect(),
        )
    }

    fn base_create() -> CreateBody {
        CreateBody {
            request_type: Some("certificate".to_owned()),
            resource_id: Some("cert-123".to_owned()),
            resource_type: Some("tls_cert".to_owned()),
            metadata: None,
            required_approvals: None,
            expires_hours: None,
        }
    }

    fn decision(user_id: i32, approved: bool) -> Decision<'static> {
        Decision {
            user_id,
            user_email: "reviewer@example.com",
            approved,
            reason: Some("looks fine"),
            timestamp: "2026-07-15T10:00:00.000042",
        }
    }

    #[test]
    fn total_pages_matches_python_ceiling_division() {
        assert_eq!(total_pages(0, 20), 0);
        assert_eq!(total_pages(1, 20), 1);
        assert_eq!(total_pages(100, 20), 5);
        assert_eq!(total_pages(101, 20), 6);
    }

    #[test]
    fn list_params_first_wins_lists_accumulate_and_type_maps() {
        let pairs = vec![
            ("page".to_owned(), "2".to_owned()),
            ("page".to_owned(), "9".to_owned()),
            ("per_page".to_owned(), "500".to_owned()),
            ("status".to_owned(), "pending".to_owned()),
            ("status".to_owned(), "approved".to_owned()),
            ("type".to_owned(), "certificate".to_owned()),
            ("requester_id".to_owned(), "7".to_owned()),
        ];
        let q = parse_list_params(&pairs);
        assert_eq!(q.page, 2);
        assert_eq!(q.per_page, 100); // capped per v1 min(per_page, 100)
        assert_eq!(q.status, vec!["pending", "approved"]);
        assert_eq!(q.request_type, vec!["certificate"]);
        assert_eq!(q.requester_id, Some(7));
    }

    #[test]
    fn list_params_defaults_and_python_truthiness() {
        let q = parse_list_params(&[
            ("page".to_owned(), "junk".to_owned()),
            ("requester_id".to_owned(), "0".to_owned()), // v1: falsy → no filter
        ]);
        assert_eq!(q.page, 1);
        assert_eq!(q.per_page, 20);
        assert!(q.status.is_empty());
        assert_eq!(q.requester_id, None);

        let q = parse_list_params(&[("requester_id".to_owned(), "abc".to_owned())]);
        assert_eq!(q.requester_id, None);
    }

    #[test]
    fn create_validation_applies_v1_defaults() {
        let v = match validate_create(&base_create()) {
            Ok(v) => v,
            Err(e) => panic!("expected ok, got {e:?}"),
        };
        assert_eq!(v.request_type, "certificate");
        assert_eq!(v.required_approvals, 1);
        assert_eq!(v.expires_hours, 24);
        assert_eq!(v.metadata, serde_json::json!({}));
    }

    #[test]
    fn create_validation_rejects_missing_and_invalid_fields() {
        let missing_type = CreateBody {
            request_type: None,
            ..base_create()
        };
        assert!(matches!(
            validate_create(&missing_type),
            Err(ApiError::Validation(_))
        ));

        let bad_type = CreateBody {
            request_type: Some("deployment".to_owned()),
            ..base_create()
        };
        assert!(matches!(
            validate_create(&bad_type),
            Err(ApiError::Validation(_))
        ));

        let long_resource = CreateBody {
            resource_id: Some("x".repeat(129)),
            ..base_create()
        };
        assert!(matches!(
            validate_create(&long_resource),
            Err(ApiError::Validation(_))
        ));

        let long_resource_type = CreateBody {
            resource_type: Some("x".repeat(51)),
            ..base_create()
        };
        assert!(matches!(
            validate_create(&long_resource_type),
            Err(ApiError::Validation(_))
        ));

        let bad_metadata = CreateBody {
            metadata: Some(serde_json::json!([1, 2])),
            ..base_create()
        };
        assert!(matches!(
            validate_create(&bad_metadata),
            Err(ApiError::Validation(_))
        ));
    }

    #[test]
    fn create_validation_enforces_integer_bounds() {
        for (required, hours) in [
            (Some(0), None),
            (Some(11), None),
            (None, Some(0)),
            (None, Some(169)),
        ] {
            let body = CreateBody {
                required_approvals: required,
                expires_hours: hours,
                ..base_create()
            };
            assert!(matches!(
                validate_create(&body),
                Err(ApiError::Validation(_))
            ));
        }
        let edges = CreateBody {
            required_approvals: Some(10),
            expires_hours: Some(168),
            ..base_create()
        };
        assert!(validate_create(&edges).is_ok());
    }

    #[test]
    fn guards_run_in_v1_order() {
        let now = dt("2026-07-15T12:00:00");
        let history = history_with(&[5]);
        // Completed wins over everything, including own-request + expiry.
        assert_eq!(
            check_decision_guards(
                "approved",
                Some(dt("2026-07-15T11:00:00")),
                5,
                &history,
                5,
                now
            ),
            DecisionGuard::AlreadyCompleted
        );
        // Expiry wins over own-request and already-decided.
        assert_eq!(
            check_decision_guards(
                "pending",
                Some(dt("2026-07-15T11:00:00")),
                5,
                &history,
                5,
                now
            ),
            DecisionGuard::Expired
        );
        // Own request wins over already-decided.
        assert_eq!(
            check_decision_guards("pending", None, 5, &history, 5, now),
            DecisionGuard::OwnRequest
        );
        assert_eq!(
            check_decision_guards("pending", None, 1, &history, 5, now),
            DecisionGuard::AlreadyDecided
        );
        assert_eq!(
            check_decision_guards("pending", None, 1, &history, 6, now),
            DecisionGuard::Proceed
        );
    }

    #[test]
    fn expiry_boundary_matches_python_lte() {
        let now = dt("2026-07-15T12:00:00");
        let empty = serde_json::json!([]);
        // v1: `expires_at <= utcnow()` — exactly-now counts as expired.
        assert_eq!(
            check_decision_guards("pending", Some(now), 1, &empty, 2, now),
            DecisionGuard::Expired
        );
        assert_eq!(
            check_decision_guards(
                "pending",
                Some(dt("2026-07-15T12:00:01")),
                1,
                &empty,
                2,
                now
            ),
            DecisionGuard::Proceed
        );
        // No expiry set → never expires.
        assert_eq!(
            check_decision_guards("pending", None, 1, &empty, 2, now),
            DecisionGuard::Proceed
        );
    }

    #[test]
    fn approve_below_required_stays_pending() {
        let upd = apply_decision(
            0,
            2,
            &serde_json::json!([]),
            &serde_json::json!([]),
            &decision(9, true),
        );
        assert_eq!(upd.new_status, None);
        assert_eq!(upd.new_current_approvals, Some(1));
        assert_eq!(upd.new_approvers, Some(serde_json::json!([9])));
        assert!(!upd.completed);
        let entry = &upd.new_history[0];
        assert_eq!(entry["user_id"], 9);
        assert_eq!(entry["user_email"], "reviewer@example.com");
        assert_eq!(entry["approved"], true);
        assert_eq!(entry["reason"], "looks fine");
        assert_eq!(entry["timestamp"], "2026-07-15T10:00:00.000042");
    }

    #[test]
    fn approve_reaching_required_completes() {
        let upd = apply_decision(
            1,
            2,
            &serde_json::json!([4]),
            &history_with(&[4]),
            &decision(9, true),
        );
        assert_eq!(upd.new_status, Some("approved"));
        assert_eq!(upd.new_current_approvals, Some(2));
        assert_eq!(upd.new_approvers, Some(serde_json::json!([4, 9])));
        assert!(upd.completed);
        // Existing history preserved, new record appended.
        match upd.new_history.as_array() {
            Some(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[1]["user_id"], 9);
            }
            None => panic!("history should be an array"),
        }
    }

    #[test]
    fn reject_short_circuits_regardless_of_counts() {
        let upd = apply_decision(
            5,
            10,
            &serde_json::json!([1, 2, 3, 4, 5]),
            &history_with(&[1, 2, 3, 4, 5]),
            &decision(9, false),
        );
        assert_eq!(upd.new_status, Some("rejected"));
        assert_eq!(upd.new_current_approvals, None); // count untouched
        assert_eq!(upd.new_approvers, None); // approvers untouched
        assert!(upd.completed);
        match upd.new_history.as_array() {
            Some(entries) => {
                assert_eq!(entries.len(), 6);
                assert_eq!(entries[5]["approved"], false);
            }
            None => panic!("history should be an array"),
        }
    }

    #[test]
    fn null_jsonb_treated_as_empty_like_python_or() {
        let upd = apply_decision(
            0,
            1,
            &serde_json::Value::Null,
            &serde_json::Value::Null,
            &decision(3, true),
        );
        assert_eq!(upd.new_status, Some("approved"));
        assert_eq!(upd.new_approvers, Some(serde_json::json!([3])));
        assert_eq!(upd.new_history.as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn has_decided_matches_on_history_user_id() {
        assert!(has_decided(&history_with(&[1, 2, 3]), 2));
        assert!(!has_decided(&history_with(&[1, 2, 3]), 9));
        assert!(!has_decided(&serde_json::json!([]), 1));
        assert!(!has_decided(&serde_json::Value::Null, 1));
        // Entries without user_id (or with non-numeric ids) never match.
        let odd = serde_json::json!([{"approved": true}, {"user_id": "2"}]);
        assert!(!has_decided(&odd, 2));
    }

    #[test]
    fn normalize_helpers_match_python_or_defaults() {
        assert_eq!(normalize_array(&None), serde_json::json!([]));
        assert_eq!(
            normalize_array(&Some(serde_json::Value::Null)),
            serde_json::json!([])
        );
        assert_eq!(
            normalize_array(&Some(serde_json::json!([1]))),
            serde_json::json!([1])
        );
        assert_eq!(normalize_object(&None), serde_json::json!({}));
        assert_eq!(
            normalize_object(&Some(serde_json::Value::Null)),
            serde_json::json!({})
        );
        assert_eq!(
            normalize_object(&Some(serde_json::json!({"k": 1}))),
            serde_json::json!({"k": 1})
        );
    }

    #[test]
    fn bucket_counts_zero_fills_and_ignores_unknowns() {
        let rows = vec![
            (Some("pending".to_owned()), 3_i64),
            (Some("bogus".to_owned()), 9_i64),
        ];
        let v = bucket_counts(&STATUSES, &rows);
        assert_eq!(v["pending"], 3);
        assert_eq!(v["approved"], 0);
        assert_eq!(v["rejected"], 0);
        assert_eq!(v["expired"], 0);
        assert_eq!(v.get("bogus"), None);
    }

    #[test]
    fn history_timestamp_uses_python_isoformat_shape() {
        // The decide path stamps history entries with the shared helper —
        // Python isoformat omits the fraction at microsecond == 0.
        let t = dt("2026-07-15T10:00:00");
        assert_eq!(skauswatch_streams::py_isoformat(t), "2026-07-15T10:00:00");
    }

    #[test]
    fn reason_bound_matches_pydantic() {
        assert!(check_max_len(&"x".repeat(1000), "reason", 1000).is_ok());
        assert!(matches!(
            check_max_len(&"x".repeat(1001), "reason", 1000),
            Err(ApiError::Validation(_))
        ));
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

    async fn seed_approval(
        state: &AppState,
        requester_id: i32,
        request_type: &str,
        required: i32,
    ) -> i32 {
        seed_approval_in_tenant(
            state,
            crate::routes::test_support::default_tenant_id(),
            requester_id,
            request_type,
            required,
        )
        .await
    }

    /// Like [`seed_approval`] but stamps an explicit `tenant_id` — used by
    /// the cross-tenant isolation tests below.
    async fn seed_approval_in_tenant(
        state: &AppState,
        tenant_id: uuid::Uuid,
        requester_id: i32,
        request_type: &str,
        required: i32,
    ) -> i32 {
        let (id,): (i32,) = sqlx::query_as(
            "INSERT INTO approval_requests \
             (request_type, resource_id, resource_type, requester_id, status, \
              required_approvals, current_approvals, approvers, approval_history, metadata, \
              expires_at, tenant_id, created_at, updated_at) \
             VALUES ($1, 'res-1', 'thing', $2, 'pending', $3, 0, '[]', '[]', '{}', \
                     now() + interval '1 day', $4, now(), now()) RETURNING id",
        )
        .bind(request_type)
        .bind(requester_id)
        .bind(required)
        .bind(tenant_id)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed_approval: {e}"));
        id
    }

    #[tokio::test]
    async fn list_and_get_approvals_round_trip() {
        let state = db_state(dev_license()).await;
        let (requester_id, _) = authed_user(&state, "appr-req@example.com", "maintainer").await;
        let id = seed_approval(&state, requester_id, "certificate", 1).await;
        let (_, token) = authed_user(&state, "appr-viewer@example.com", "viewer").await;
        let server = server_for(state).await;

        let list = server
            .get("/api/v1/approvals")
            .authorization_bearer(&token)
            .await;
        list.assert_status_ok();
        let body: serde_json::Value = list.json();
        assert!(body["total"].as_i64().unwrap_or(0) >= 1);

        let get = server
            .get(&format!("/api/v1/approvals/{id}"))
            .authorization_bearer(&token)
            .await;
        get.assert_status_ok();
        let body: serde_json::Value = get.json();
        assert_eq!(body["request_type"], "certificate");
        assert_eq!(body["approvers"], serde_json::json!([]));

        let missing = server
            .get("/api/v1/approvals/999999")
            .authorization_bearer(&token)
            .await;
        missing.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_pending_requires_role_and_excludes_decided() {
        let state = db_state(dev_license()).await;
        let (requester_id, _) = authed_user(&state, "pend-req@example.com", "maintainer").await;
        let id = seed_approval(&state, requester_id, "user", 2).await;
        let (viewer_id, viewer_tok) =
            authed_user(&state, "pend-viewer@example.com", "viewer").await;
        let (_, admin_tok) = authed_user(&state, "pend-admin@example.com", "admin").await;

        // Mark as already decided by the admin so it's excluded from the
        // admin's own pending list but still shows for a fresh reviewer.
        sqlx::query("UPDATE approval_requests SET approval_history = $2 WHERE id = $1")
            .bind(id)
            .bind(serde_json::json!([{"user_id": viewer_id, "approved": true}]))
            .execute(&state.db)
            .await
            .unwrap_or_else(|e| panic!("seed history: {e}"));

        let server = server_for(state).await;

        let forbidden = server
            .get("/api/v1/approvals/pending")
            .authorization_bearer(&viewer_tok)
            .await;
        forbidden.assert_status(StatusCode::FORBIDDEN);

        let res = server
            .get("/api/v1/approvals/pending")
            .authorization_bearer(&admin_tok)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        let items = body["items"].as_array().cloned().unwrap_or_default();
        assert!(items.iter().any(|i| i["id"] == id));
    }

    #[tokio::test]
    async fn create_approval_validates_then_succeeds() {
        let state = db_state(dev_license()).await;
        let (_, token) = authed_user(&state, "create-appr@example.com", "viewer").await;
        let server = server_for(state).await;

        let bad = server
            .post("/api/v1/approvals")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"request_type": "deployment"}))
            .await;
        bad.assert_status(StatusCode::BAD_REQUEST);

        let res = server
            .post("/api/v1/approvals")
            .authorization_bearer(&token)
            .json(&serde_json::json!({
                "request_type": "certificate",
                "resource_id": "cert-9",
                "resource_type": "tls_certificate",
            }))
            .await;
        res.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["approval"]["status"], "pending");
        assert_eq!(body["approval"]["request_type"], "certificate");
    }

    #[tokio::test]
    async fn decide_approval_enforces_guards_and_completes() {
        let state = db_state(dev_license()).await;
        let (requester_id, requester_tok) =
            authed_user(&state, "decide-req@example.com", "maintainer").await;
        let (reviewer_id, reviewer_tok) =
            authed_user(&state, "decide-rev@example.com", "admin").await;
        let (_, viewer_tok) = authed_user(&state, "decide-viewer@example.com", "viewer").await;
        let id = seed_approval(&state, requester_id, "user", 1).await;
        let server = server_for(state).await;

        // Role gate.
        let res = server
            .post(&format!("/api/v1/approvals/{id}/decide"))
            .authorization_bearer(&viewer_tok)
            .json(&serde_json::json!({"approved": true}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);

        // Own-request guard.
        let res = server
            .post(&format!("/api/v1/approvals/{id}/decide"))
            .authorization_bearer(&requester_tok)
            .json(&serde_json::json!({"approved": true}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Cannot approve your own request");

        // Missing `approved` field.
        let res = server
            .post(&format!("/api/v1/approvals/{id}/decide"))
            .authorization_bearer(&reviewer_tok)
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);

        // Successful approve reaches required_approvals=1 → approved.
        let res = server
            .post(&format!("/api/v1/approvals/{id}/decide"))
            .authorization_bearer(&reviewer_tok)
            .json(&serde_json::json!({"approved": true, "reason": "looks fine"}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["approval"]["status"], "approved");
        assert_eq!(body["approval"]["current_approvals"], 1);
        assert!(body["approval"]["completed_at"].is_string());

        // Already-decided by the same reviewer.
        let res = server
            .post(&format!("/api/v1/approvals/{id}/decide"))
            .authorization_bearer(&reviewer_tok)
            .json(&serde_json::json!({"approved": true}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Approval request already approved");

        // Missing target.
        let missing = server
            .post("/api/v1/approvals/999999/decide")
            .authorization_bearer(&reviewer_tok)
            .json(&serde_json::json!({"approved": true}))
            .await;
        missing.assert_status(StatusCode::NOT_FOUND);
        let _ = reviewer_id;
    }

    #[tokio::test]
    async fn decide_approval_expired_persists_status_and_400s() {
        let state = db_state(dev_license()).await;
        let (requester_id, _) = authed_user(&state, "exp-req@example.com", "maintainer").await;
        let (_, reviewer_tok) = authed_user(&state, "exp-rev@example.com", "admin").await;
        let id = seed_approval(&state, requester_id, "service", 1).await;
        sqlx::query(
            "UPDATE approval_requests SET expires_at = now() - interval '1 hour' WHERE id = $1",
        )
        .bind(id)
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("expire: {e}"));
        let server = server_for(state).await;

        let res = server
            .post(&format!("/api/v1/approvals/{id}/decide"))
            .authorization_bearer(&reviewer_tok)
            .json(&serde_json::json!({"approved": true}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Approval request has expired");

        let get = server
            .get(&format!("/api/v1/approvals/{id}"))
            .authorization_bearer(&reviewer_tok)
            .await;
        get.assert_status_ok();
        let body: serde_json::Value = get.json();
        assert_eq!(body["status"], "expired");
    }

    #[tokio::test]
    async fn cancel_approval_requester_or_admin_only_and_pending_only() {
        let state = db_state(dev_license()).await;
        let (requester_id, requester_tok) =
            authed_user(&state, "cancel-req@example.com", "maintainer").await;
        let (_, other_tok) = authed_user(&state, "cancel-other@example.com", "viewer").await;
        let id = seed_approval(&state, requester_id, "configuration", 1).await;
        let server = server_for(state).await;

        let forbidden = server
            .post(&format!("/api/v1/approvals/{id}/cancel"))
            .authorization_bearer(&other_tok)
            .await;
        forbidden.assert_status(StatusCode::FORBIDDEN);

        let missing = server
            .post("/api/v1/approvals/999999/cancel")
            .authorization_bearer(&requester_tok)
            .await;
        missing.assert_status(StatusCode::NOT_FOUND);

        let res = server
            .post(&format!("/api/v1/approvals/{id}/cancel"))
            .authorization_bearer(&requester_tok)
            .await;
        res.assert_status_ok();

        // Already cancelled (now rejected) — can't cancel twice.
        let again = server
            .post(&format!("/api/v1/approvals/{id}/cancel"))
            .authorization_bearer(&requester_tok)
            .await;
        again.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn approval_statistics_requires_role_and_reports_buckets() {
        let state = db_state(dev_license()).await;
        let (requester_id, _) = authed_user(&state, "stat-req@example.com", "maintainer").await;
        seed_approval(&state, requester_id, "certificate", 1).await;
        let (_, viewer_tok) = authed_user(&state, "stat-viewer@example.com", "viewer").await;
        let (_, admin_tok) = authed_user(&state, "stat-admin@example.com", "admin").await;
        let server = server_for(state).await;

        let forbidden = server
            .get("/api/v1/approvals/statistics")
            .authorization_bearer(&viewer_tok)
            .await;
        forbidden.assert_status(StatusCode::FORBIDDEN);

        let res = server
            .get("/api/v1/approvals/statistics")
            .authorization_bearer(&admin_tok)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["total"].as_i64().unwrap_or(0) >= 1);
        assert!(body["by_status"]["pending"].as_i64().unwrap_or(0) >= 1);
        assert!(body["by_type"]["certificate"].as_i64().unwrap_or(0) >= 1);
        assert!(body["last_7_days"].as_i64().unwrap_or(0) >= 1);
    }

    // -- tenant isolation (docs/v2-port/tenancy-model.md) -------------------

    use crate::routes::test_support::{authed_user_in_tenant, seed_tenant};

    #[tokio::test]
    async fn tenant_a_cannot_list_get_decide_or_cancel_tenant_bs_approval() {
        let state = db_state(dev_license()).await;
        let tenant_b = seed_tenant(&state.db, "appr-tenant-b").await;
        let (requester_b, _) =
            authed_user_in_tenant(&state, "appr-req-b@example.com", "maintainer", tenant_b).await;
        let id_b = seed_approval_in_tenant(&state, tenant_b, requester_b, "user", 1).await;
        let (_, admin_a) = authed_user(&state, "appr-admin-a@example.com", "admin").await;
        let server = server_for(state).await;

        let list = server
            .get("/api/v1/approvals")
            .authorization_bearer(&admin_a)
            .await;
        list.assert_status_ok();
        let body: serde_json::Value = list.json();
        let items = body["items"].as_array().cloned().unwrap_or_default();
        assert!(items.iter().all(|i| i["id"] != id_b));

        let get = server
            .get(&format!("/api/v1/approvals/{id_b}"))
            .authorization_bearer(&admin_a)
            .await;
        get.assert_status(StatusCode::NOT_FOUND);

        let decide = server
            .post(&format!("/api/v1/approvals/{id_b}/decide"))
            .authorization_bearer(&admin_a)
            .json(&serde_json::json!({"approved": true}))
            .await;
        decide.assert_status(StatusCode::NOT_FOUND);

        let cancel = server
            .post(&format!("/api/v1/approvals/{id_b}/cancel"))
            .authorization_bearer(&admin_a)
            .await;
        cancel.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn pending_list_and_statistics_are_scoped_to_the_caller_tenant() {
        let state = db_state(dev_license()).await;
        let tenant_b = seed_tenant(&state.db, "appr-tenant-b-2").await;
        let (requester_b, _) =
            authed_user_in_tenant(&state, "appr-req-b2@example.com", "maintainer", tenant_b).await;
        let id_b = seed_approval_in_tenant(&state, tenant_b, requester_b, "certificate", 1).await;
        let (requester_a, _) = authed_user(&state, "appr-req-a@example.com", "maintainer").await;
        seed_approval(&state, requester_a, "user", 1).await;
        let (_, admin_a) = authed_user(&state, "appr-admin-a2@example.com", "admin").await;
        let server = server_for(state).await;

        let pending = server
            .get("/api/v1/approvals/pending")
            .authorization_bearer(&admin_a)
            .await;
        pending.assert_status_ok();
        let body: serde_json::Value = pending.json();
        let items = body["items"].as_array().cloned().unwrap_or_default();
        assert!(items.iter().all(|i| i["id"] != id_b));

        let stats = server
            .get("/api/v1/approvals/statistics")
            .authorization_bearer(&admin_a)
            .await;
        stats.assert_status_ok();
        let body: serde_json::Value = stats.json();
        assert_eq!(body["by_type"]["certificate"], 0);
        assert!(body["by_type"]["user"].as_i64().unwrap_or(0) >= 1);
    }
}
