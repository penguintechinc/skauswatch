//! /api/v1/codescan — authenticated pure proxy to the CodeScan AI-code-review
//! worker (`WORKER_CODESCAN_URL`), gated on the `skauswatch.codescan` module
//! flag. Contract: docs/v2-port/manager-contract.md §codescan; Python source
//! of truth: services/manager/api/v1/codescan.py.

use std::sync::OnceLock;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse};
use crate::state::AppState;

/// PostHog module flag gating every codescan route (see `crate::flags`
/// `MODULE_FLAGS`) — the v2 equivalent of v1 `has_feature("codescan")`.
const CODESCAN_FLAG: &str = "skauswatch.codescan";
/// v1 bare 403 body text when the codescan feature is not licensed.
const LICENSE_MSG: &str = "CodeScan AI review requires a CodeScan license.";
/// v1 httpx client timeout (`httpx.AsyncClient(timeout=120.0)`).
const PROXY_TIMEOUT: Duration = Duration::from_secs(120);

/// Router for /api/v1/codescan — a pure proxy to the worker-codescan backend.
/// Also mounts the pre-rename `/darwin/*` paths as a deprecated alias to the
/// same handlers (see docs/MIGRATION.md) — old callers keep working and get
/// `Deprecation`/`Sunset` response headers via [`crate::deprecated`].
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(canonical_router())
        .merge(legacy_router())
}

/// The canonical `/codescan/*` routes.
fn canonical_router() -> Router<AppState> {
    Router::new()
        .route("/codescan/status", get(codescan_status))
        .route("/codescan/repos", get(list_repos).post(create_repo))
        .route(
            "/codescan/repos/{repo_id}",
            get(get_repo).put(update_repo).delete(delete_repo),
        )
        .route("/codescan/reviews", get(list_reviews).post(create_review))
        .route("/codescan/reviews/{review_id}", get(get_review))
        .route("/codescan/plans", get(list_plans).post(create_plan))
        .route("/codescan/plans/{plan_id}", get(get_plan))
}

/// The deprecated `/darwin/*` aliases — identical handlers, tagged deprecated.
fn legacy_router() -> Router<AppState> {
    Router::new()
        .route("/darwin/status", get(codescan_status))
        .route("/darwin/repos", get(list_repos).post(create_repo))
        .route(
            "/darwin/repos/{repo_id}",
            get(get_repo).put(update_repo).delete(delete_repo),
        )
        .route("/darwin/reviews", get(list_reviews).post(create_review))
        .route("/darwin/reviews/{review_id}", get(get_review))
        .route("/darwin/plans", get(list_plans).post(create_plan))
        .route("/darwin/plans/{plan_id}", get(get_plan))
        .layer(axum::middleware::from_fn(
            crate::deprecated::deprecated_alias,
        ))
}

/// Shared HTTP client for worker-codescan proxying — built once per process
/// (per-request timeouts keep the v1 client semantics).
fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(reqwest::Client::new)
}

/// v1 `CODESCAN_BASE`: `{WORKER_CODESCAN_URL}/api/v1/codescan`, default
/// `http://worker-codescan:5005`. Read per request (house pattern: siem.rs).
fn codescan_base() -> String {
    let url = std::env::var("WORKER_CODESCAN_URL")
        .unwrap_or_else(|_| "http://worker-codescan:5005".to_owned());
    format!("{url}/api/v1/codescan")
}

/// v1 `_check_codescan_license` equivalent: the bare v1 403 body when the
/// `skauswatch.codescan` flag is off. penguin-licensing is fail-safe and never
/// errors — dev builds and bypass domains evaluate enabled, replacing v1's
/// fail-open exception path (contract §Auth license gating, GA revisit note).
async fn license_denied(state: &AppState) -> Option<Response> {
    if state.license.flag_enabled(CODESCAN_FLAG).await {
        None
    } else {
        Some(
            (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "error": LICENSE_MSG })),
            )
                .into_response(),
        )
    }
}

/// The inbound Authorization header value, forwarded upstream verbatim when
/// present — the only header v1 forwards.
fn auth_value(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// v1 `dict(request.args)` semantics — first value wins per key, insertion
/// order preserved (werkzeug `MultiDict.__getitem__` returns first value).
fn dedupe_first(pairs: &[(String, String)]) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for (k, v) in pairs {
        if !out.iter().any(|(seen, _)| seen == k) {
            out.push((k.clone(), v.clone()));
        }
    }
    out
}

/// Python truthiness over JSON values — `None`, `False`, `0`, `""`, `[]`,
/// and `{}` are all falsy (drives the v1 `json=body or {}` fallback).
fn python_falsy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => true,
        serde_json::Value::Bool(b) => !*b,
        serde_json::Value::Number(n) => n.as_f64().is_some_and(|f| f == 0.0),
        serde_json::Value::String(s) => s.is_empty(),
        serde_json::Value::Array(a) => a.is_empty(),
        serde_json::Value::Object(o) => o.is_empty(),
    }
}

/// Quart `await request.get_json()` + v1 `json=body or {}`: empty bodies and
/// Python-falsy JSON values forward as `{}`; malformed JSON is the envelope
/// 400 (house pattern: alerts.rs ai-review body handling).
fn parse_body(bytes: &Bytes) -> Result<serde_json::Value, ApiError> {
    if bytes.is_empty() {
        return Ok(serde_json::json!({}));
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| ApiError::BadRequest("Invalid JSON body".to_owned()))?;
    Ok(if python_falsy(&value) {
        serde_json::json!({})
    } else {
        value
    })
}

/// Maps reqwest transport failures to the v1 error bodies. httpx handler
/// ordering is preserved: timeouts (including connect timeouts) → 504 before
/// the connect check → 503; anything else is the v1 catch-all 500 carrying
/// the error string.
fn transport_error(e: &reqwest::Error) -> Response {
    let (status, msg) = if e.is_timeout() {
        (
            StatusCode::GATEWAY_TIMEOUT,
            "worker-codescan timeout".to_owned(),
        )
    } else if e.is_connect() {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            "Cannot connect to worker-codescan".to_owned(),
        )
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    };
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// Forwards one request to worker-codescan and shapes the reply exactly like
/// v1 `_proxy`: upstream JSON and status pass through; non-JSON bodies wrap
/// as `{"raw": <text>}`; transport failures map via [`transport_error`].
async fn forward(
    base: &str,
    timeout: Duration,
    method: reqwest::Method,
    path: &str,
    auth: Option<String>,
    params: &[(String, String)],
    body: Option<&serde_json::Value>,
) -> Response {
    let full = format!("{base}{path}");
    let url = if params.is_empty() {
        reqwest::Url::parse(&full)
    } else {
        reqwest::Url::parse_with_params(&full, params)
    };
    let url = match url {
        Ok(u) => u,
        // v1: an invalid upstream URL fell to the generic except → 500 str.
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response();
        }
    };
    let mut req = http_client().request(method, url).timeout(timeout);
    if let Some(auth) = auth {
        req = req.header(reqwest::header::AUTHORIZATION, auth);
    }
    if let Some(b) = body {
        req = req.json(b);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => return transport_error(&e),
    };
    let status =
        StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let bytes = match resp.bytes().await {
        Ok(b) => b,
        Err(e) => return transport_error(&e),
    };
    let payload: serde_json::Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| serde_json::json!({ "raw": String::from_utf8_lossy(&bytes) }));
    (status, Json(payload)).into_response()
}

/// Proxies one manager route to `{WORKER_CODESCAN_URL}/api/v1/codescan{path}`
/// with the v1 120s timeout, forwarding only the Authorization header.
async fn proxy(
    headers: &HeaderMap,
    method: reqwest::Method,
    path: &str,
    params: &[(String, String)],
    body: Option<&serde_json::Value>,
) -> Response {
    forward(
        &codescan_base(),
        PROXY_TIMEOUT,
        method,
        path,
        auth_value(headers),
        params,
        body,
    )
    .await
}

/// Re-serializes a successful (`2xx`) proxied response through `T`, so any
/// upstream field not modeled by `T` is silently dropped before it reaches
/// the caller. Defense-in-depth: `codescan-backend` is audit-clean today, but
/// this proxy has no way to know if that stays true, so it only ever re-emits
/// the fields it explicitly models rather than forwarding whatever upstream
/// happens to return. Error/non-2xx bodies (`{"error": ...}` from upstream,
/// or the `{"raw": ...}` wrapper [`forward`] builds for non-JSON bodies) pass
/// through completely unchanged — only success bodies have a modeled shape,
/// matching each handler's documented `responses(...)` schema.
///
/// A `2xx` body that fails to deserialize as `T` (an upstream contract break
/// this proxy has never seen) fails closed as a `502` rather than forwarding
/// an unrecognized shape verbatim.
async fn allowlist<T>(resp: Response) -> Response
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let status = resp.status();
    if !status.is_success() {
        return resp;
    }
    let bytes = match axum::body::to_bytes(resp.into_body(), usize::MAX).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("worker-codescan response: {e}") })),
            )
                .into_response();
        }
    };
    match serde_json::from_slice::<T>(&bytes) {
        Ok(value) => (status, Json(value)).into_response(),
        Err(_) => (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": "Unexpected response shape from worker-codescan" })),
        )
            .into_response(),
    }
}

/// `{status, queue_depth}` — mirrors
/// `services/codescan-backend/src/routes/status.rs::StatusResponse`; also the
/// field allowlist [`allowlist`] enforces on the proxied response.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct StatusResponse {
    status: String,
    queue_depth: i64,
}

/// One `codescan_repo_configs` row — mirrors
/// `services/codescan-backend/src/routes/repos.rs::RepoConfig`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct RepoConfig {
    id: i64,
    tenant_id: uuid::Uuid,
    team_id: Option<i64>,
    owner_id: Option<i64>,
    provider: String,
    repo_url: String,
    repo_name: String,
    enabled: bool,
    auto_review: bool,
    review_on_open: bool,
    review_on_sync: bool,
    default_categories: Option<serde_json::Value>,
    default_ai_provider: Option<String>,
    ignored_paths: Option<serde_json::Value>,
    custom_rules: Option<serde_json::Value>,
    display_name: Option<String>,
    description: Option<String>,
    is_active: bool,
    credential_id: Option<i64>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// GET /codescan/repos — mirrors `repos.rs::RepoListResponse`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct RepoListResponse {
    data: Vec<RepoConfig>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// POST /codescan/repos — mirrors `repos.rs::RepoCreateResponse`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct RepoCreateResponse {
    message: String,
    config: RepoConfig,
}

/// PUT /codescan/repos/{repo_id} — mirrors `repos.rs::RepoUpdateResponse`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct RepoUpdateResponse {
    message: String,
    config: RepoConfig,
}

/// DELETE /codescan/repos/{repo_id} — mirrors `repos.rs::RepoDeleteResponse`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct RepoDeleteResponse {
    message: String,
    deleted: bool,
}

/// One `codescan_reviews` row — mirrors `reviews.rs::ReviewRow`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewRow {
    id: i64,
    external_id: Option<String>,
    tenant_id: uuid::Uuid,
    team_id: Option<i64>,
    triggered_by: Option<i64>,
    repo_config_id: i64,
    pr_number: Option<i32>,
    pr_title: Option<String>,
    pr_url: Option<String>,
    base_sha: Option<String>,
    head_sha: Option<String>,
    review_type: String,
    categories: Option<serde_json::Value>,
    ai_provider: Option<String>,
    ai_model: Option<String>,
    status: String,
    error_message: Option<String>,
    files_reviewed: i32,
    comments_count: i32,
    summary: Option<String>,
    started_at: Option<String>,
    completed_at: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// Shared pagination envelope — mirrors `reviews.rs::PaginationMeta`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct PaginationMeta {
    page: i64,
    per_page: i64,
    total: i64,
    pages: i64,
}

/// GET /codescan/reviews — mirrors `reviews.rs::ReviewListResponse`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewListResponse {
    data: Vec<ReviewRow>,
    pagination: PaginationMeta,
}

/// One `codescan_review_comments` row — mirrors `reviews.rs::ReviewComment`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewComment {
    id: i64,
    file_path: Option<String>,
    line_number: Option<i32>,
    comment: Option<String>,
    category: Option<String>,
    severity: Option<String>,
    created_at: Option<String>,
}

/// One `codescan_review_detections` row — mirrors
/// `reviews.rs::ReviewDetection`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewDetection {
    id: i64,
    detection_type: Option<String>,
    name: Option<String>,
    confidence: Option<f64>,
    file_count: Option<i32>,
    created_at: Option<String>,
}

/// One `codescan_license_violations` row — mirrors
/// `reviews.rs::ReviewLicenseViolation`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewLicenseViolation {
    id: i64,
    license_name: Option<String>,
    package_name: Option<String>,
    policy: Option<String>,
    severity: Option<String>,
    status: String,
    created_at: Option<String>,
}

/// GET /codescan/reviews/{review_id} — mirrors
/// `reviews.rs::ReviewDetailResponse` (the review row flattened, plus
/// `comments`/`detections`/`license_violations` arrays).
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewDetailResponse {
    #[serde(flatten)]
    review: ReviewRow,
    comments: Vec<ReviewComment>,
    detections: Vec<ReviewDetection>,
    license_violations: Vec<ReviewLicenseViolation>,
}

/// One `codescan_issue_plans` row — mirrors `plans.rs::PlanRow`. Deliberately
/// has no `tenant_id` field: upstream never exposes it in the plan response
/// (see `plans.rs`'s own `NOTE` on `PlanRow`), so it isn't part of this
/// allowlist either.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct PlanRow {
    id: i64,
    external_id: String,
    platform: String,
    repository: String,
    issue_number: i32,
    issue_url: Option<String>,
    issue_title: Option<String>,
    plan_content: Option<String>,
    plan_steps: Option<serde_json::Value>,
    ai_provider: Option<String>,
    ai_model: Option<String>,
    status: String,
    error_message: Option<String>,
    comment_posted: bool,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// GET /codescan/plans — mirrors `plans.rs::PlanListResponse`.
#[derive(Deserialize, Serialize, utoipa::ToSchema)]
pub(crate) struct PlanListResponse {
    plans: Vec<PlanRow>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// GET /darwin/status — CodeScan service status, proxied verbatim.
///
/// This whole router is a thin authenticated proxy to worker-codescan — only
/// the canonical `/codescan/*` paths are documented here (the deprecated
/// `/darwin/*` aliases mount the same handlers, see `legacy_router`). Every
/// successful response is re-serialized through an explicit DTO (see
/// [`allowlist`]) before it reaches the caller — defense-in-depth so a field
/// upstream never intended to expose is dropped rather than forwarded, even
/// though `codescan-backend` is audit-clean today.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/status",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Service status and review queue depth", body = StatusResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn codescan_status(
    State(state): State<AppState>,
    _user: CurrentUser,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let resp = proxy(&headers, reqwest::Method::GET, "/status", &[], None).await;
    Ok(allowlist::<StatusResponse>(resp).await)
}

/// GET /darwin/repos — list repository configurations; query params forward
/// upstream (first value per key, matching v1 `dict(request.args)`).
#[utoipa::path(
    get,
    path = "/api/v1/codescan/repos",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Repository configurations", body = RepoListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_repos(
    State(state): State<AppState>,
    _user: CurrentUser,
    headers: HeaderMap,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let params = dedupe_first(&params);
    let resp = proxy(&headers, reqwest::Method::GET, "/repos", &params, None).await;
    Ok(allowlist::<RepoListResponse>(resp).await)
}

/// POST /darwin/repos — add a repository configuration (admin only); the
/// JSON body forwards upstream.
#[utoipa::path(
    post,
    path = "/api/v1/codescan/repos",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    request_body = serde_json::Value,
    responses(
        (status = 201, description = "Repository configuration created", body = RepoCreateResponse),
        (status = 400, description = "Invalid JSON body", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_repo(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    user.require_role(&["admin"])?;
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let payload = parse_body(&body)?;
    let resp = proxy(
        &headers,
        reqwest::Method::POST,
        "/repos",
        &[],
        Some(&payload),
    )
    .await;
    Ok(allowlist::<RepoCreateResponse>(resp).await)
}

/// GET /darwin/repos/{repo_id} — fetch one repository configuration.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/repos/{repo_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("repo_id" = i32, Path, description = "worker-codescan repository configuration id")),
    responses(
        (status = 200, description = "Repository configuration", body = RepoConfig),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_repo(
    State(state): State<AppState>,
    _user: CurrentUser,
    headers: HeaderMap,
    Path(repo_id): Path<i32>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let resp = proxy(
        &headers,
        reqwest::Method::GET,
        &format!("/repos/{repo_id}"),
        &[],
        None,
    )
    .await;
    Ok(allowlist::<RepoConfig>(resp).await)
}

/// PUT /darwin/repos/{repo_id} — update a repository configuration (admin
/// only); the JSON body forwards upstream.
#[utoipa::path(
    put,
    path = "/api/v1/codescan/repos/{repo_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("repo_id" = i32, Path, description = "worker-codescan repository configuration id")),
    request_body = serde_json::Value,
    responses(
        (status = 200, description = "Repository configuration updated", body = RepoUpdateResponse),
        (status = 400, description = "Invalid JSON body", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_repo(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(repo_id): Path<i32>,
    body: Bytes,
) -> Result<Response, ApiError> {
    user.require_role(&["admin"])?;
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let payload = parse_body(&body)?;
    let resp = proxy(
        &headers,
        reqwest::Method::PUT,
        &format!("/repos/{repo_id}"),
        &[],
        Some(&payload),
    )
    .await;
    Ok(allowlist::<RepoUpdateResponse>(resp).await)
}

/// DELETE /darwin/repos/{repo_id} — delete a repository configuration
/// (admin only).
#[utoipa::path(
    delete,
    path = "/api/v1/codescan/repos/{repo_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("repo_id" = i32, Path, description = "worker-codescan repository configuration id")),
    responses(
        (status = 200, description = "Repository configuration deleted", body = RepoDeleteResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn delete_repo(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(repo_id): Path<i32>,
) -> Result<Response, ApiError> {
    user.require_role(&["admin"])?;
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let resp = proxy(
        &headers,
        reqwest::Method::DELETE,
        &format!("/repos/{repo_id}"),
        &[],
        None,
    )
    .await;
    Ok(allowlist::<RepoDeleteResponse>(resp).await)
}

/// GET /darwin/reviews — list code reviews; query params forward upstream.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/reviews",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Paginated review list", body = ReviewListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_reviews(
    State(state): State<AppState>,
    _user: CurrentUser,
    headers: HeaderMap,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let params = dedupe_first(&params);
    let resp = proxy(&headers, reqwest::Method::GET, "/reviews", &params, None).await;
    Ok(allowlist::<ReviewListResponse>(resp).await)
}

/// POST /darwin/reviews — queue a code review. v1 quirk replicated: the gate
/// is `role_required("maintainer")`, so ONLY the maintainer role passes —
/// admins get 403 (contract §codescan: "reviews (POST maintainer)").
#[utoipa::path(
    post,
    path = "/api/v1/codescan/reviews",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    request_body = serde_json::Value,
    responses(
        (status = 201, description = "Review created and enqueued", body = ReviewRow),
        (status = 400, description = "Invalid JSON body", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or caller is not the maintainer role", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_review(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    user.require_role(&["maintainer"])?;
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let payload = parse_body(&body)?;
    let resp = proxy(
        &headers,
        reqwest::Method::POST,
        "/reviews",
        &[],
        Some(&payload),
    )
    .await;
    Ok(allowlist::<ReviewRow>(resp).await)
}

/// GET /darwin/reviews/{review_id} — fetch a code review with comments.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/reviews/{review_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("review_id" = i32, Path, description = "worker-codescan review id")),
    responses(
        (status = 200, description = "Review detail with comments", body = ReviewDetailResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_review(
    State(state): State<AppState>,
    _user: CurrentUser,
    headers: HeaderMap,
    Path(review_id): Path<i32>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let resp = proxy(
        &headers,
        reqwest::Method::GET,
        &format!("/reviews/{review_id}"),
        &[],
        None,
    )
    .await;
    Ok(allowlist::<ReviewDetailResponse>(resp).await)
}

/// GET /darwin/plans — list issue plans; query params forward upstream.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/plans",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Paginated issue-plan list", body = PlanListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_plans(
    State(state): State<AppState>,
    _user: CurrentUser,
    headers: HeaderMap,
    Query(params): Query<Vec<(String, String)>>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let params = dedupe_first(&params);
    let resp = proxy(&headers, reqwest::Method::GET, "/plans", &params, None).await;
    Ok(allowlist::<PlanListResponse>(resp).await)
}

/// POST /darwin/plans — queue an issue-plan generation (any authenticated
/// role, matching v1's bare `@auth_required`).
#[utoipa::path(
    post,
    path = "/api/v1/codescan/plans",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    request_body = serde_json::Value,
    responses(
        (status = 201, description = "Issue plan created", body = PlanRow),
        (status = 400, description = "Invalid JSON body", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_plan(
    State(state): State<AppState>,
    _user: CurrentUser,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let payload = parse_body(&body)?;
    let resp = proxy(
        &headers,
        reqwest::Method::POST,
        "/plans",
        &[],
        Some(&payload),
    )
    .await;
    Ok(allowlist::<PlanRow>(resp).await)
}

/// GET /darwin/plans/{plan_id} — fetch one issue plan.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/plans/{plan_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("plan_id" = i32, Path, description = "worker-codescan issue plan id")),
    responses(
        (status = 200, description = "Issue plan detail", body = PlanRow),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 503, description = "Cannot connect to worker-codescan", body = ErrorResponse),
        (status = 504, description = "worker-codescan request timed out", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_plan(
    State(state): State<AppState>,
    _user: CurrentUser,
    headers: HeaderMap,
    Path(plan_id): Path<i32>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let resp = proxy(
        &headers,
        reqwest::Method::GET,
        &format!("/plans/{plan_id}"),
        &[],
        None,
    )
    .await;
    Ok(allowlist::<PlanRow>(resp).await)
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use std::sync::Arc;

    use penguin_licensing::{LicenseClient, LicenseConfig};
    use wiremock::matchers::{body_json, header, method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::state::AppStateInner;

    /// Dev-mode license client — bypass evaluates every flag enabled.
    fn dev_license() -> Arc<LicenseClient> {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    /// Release-mode client with no license/PostHog keys: refresh stays fully
    /// offline (community fallback + empty flag set), so `skauswatch.codescan`
    /// reads disabled — the gate's fail-safe default-OFF path.
    fn gated_license() -> Arc<LicenseClient> {
        let mut cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        cfg.release_mode = true;
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    /// Boots a TestServer with only the codescan router nested under /api/v1 —
    /// self-contained regardless of routes/mod.rs wiring.
    fn test_server() -> axum_test::TestServer {
        let state = AppStateInner::for_tests(dev_license());
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
            tenant_id: uuid::Uuid::nil(),
        }
    }

    async fn response_parts(resp: Response) -> (StatusCode, serde_json::Value) {
        let status = resp.status();
        let bytes = match axum::body::to_bytes(resp.into_body(), usize::MAX).await {
            Ok(b) => b,
            Err(e) => panic!("body: {e}"),
        };
        let value = match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(e) => panic!("non-JSON response body: {e}"),
        };
        (status, value)
    }

    #[tokio::test]
    async fn all_legacy_alias_routes_require_auth() {
        let server = test_server();
        let responses = [
            server.get("/api/v1/darwin/status").await,
            server.get("/api/v1/darwin/repos").await,
            server.post("/api/v1/darwin/repos").await,
            server.get("/api/v1/darwin/repos/1").await,
            server.put("/api/v1/darwin/repos/1").await,
            server.delete("/api/v1/darwin/repos/1").await,
            server.get("/api/v1/darwin/reviews").await,
            server.post("/api/v1/darwin/reviews").await,
            server.get("/api/v1/darwin/reviews/1").await,
            server.get("/api/v1/darwin/plans").await,
            server.post("/api/v1/darwin/plans").await,
            server.get("/api/v1/darwin/plans/1").await,
        ];
        for res in responses {
            res.assert_status(StatusCode::UNAUTHORIZED);
            let body: serde_json::Value = res.json();
            assert_eq!(body["error"], "Missing or invalid authorization header");
        }
    }

    #[tokio::test]
    async fn all_canonical_routes_require_auth() {
        let server = test_server();
        let responses = [
            server.get("/api/v1/codescan/status").await,
            server.get("/api/v1/codescan/repos").await,
            server.get("/api/v1/codescan/reviews").await,
            server.get("/api/v1/codescan/plans").await,
        ];
        for res in responses {
            res.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn legacy_alias_carries_deprecation_headers() {
        let server = test_server();
        let res = server.get("/api/v1/darwin/status").await;
        res.assert_header("deprecation", "true");
        res.assert_header("sunset", "Thu, 01 Jul 2027 00:00:00 GMT");
    }

    #[tokio::test]
    async fn canonical_route_has_no_deprecation_headers() {
        let server = test_server();
        let res = server.get("/api/v1/codescan/status").await;
        assert!(res.maybe_header("deprecation").is_none());
    }

    #[tokio::test]
    async fn garbage_bearer_token_is_rejected() {
        let server = test_server();
        let res = server
            .get("/api/v1/darwin/status")
            .authorization_bearer("not-a-jwt")
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Invalid token");
    }

    #[tokio::test]
    async fn license_gate_denies_with_v1_body_when_flag_off() {
        let state = AppStateInner::for_tests(gated_license());
        let denied = match license_denied(&state).await {
            Some(d) => d,
            None => panic!("expected the codescan gate to deny"),
        };
        let (status, body) = response_parts(denied).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            body,
            serde_json::json!({"error": "CodeScan AI review requires a CodeScan license."})
        );
    }

    #[tokio::test]
    async fn license_gate_allows_under_dev_bypass() {
        let state = AppStateInner::for_tests(dev_license());
        assert!(license_denied(&state).await.is_none());
    }

    #[tokio::test]
    async fn proxy_forwards_auth_header_and_passes_json_through() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/codescan/status"))
            .and(header("authorization", "Bearer tok-123"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status": "ok", "queue_depth": 2})),
            )
            .expect(1)
            .mount(&upstream)
            .await;

        let resp = forward(
            &format!("{}/api/v1/codescan", upstream.uri()),
            Duration::from_secs(5),
            reqwest::Method::GET,
            "/status",
            Some("Bearer tok-123".to_owned()),
            &[],
            None,
        )
        .await;
        let (status, body) = response_parts(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"status": "ok", "queue_depth": 2}));
    }

    #[tokio::test]
    async fn proxy_forwards_query_params_and_json_body() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/codescan/repos"))
            .and(query_param("page", "2"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"items": []})),
            )
            .expect(1)
            .mount(&upstream)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/codescan/repos"))
            .and(body_json(
                serde_json::json!({"url": "https://github.com/penguintechinc/skauswatch"}),
            ))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": 7})))
            .expect(1)
            .mount(&upstream)
            .await;

        let base = format!("{}/api/v1/codescan", upstream.uri());
        let listed = forward(
            &base,
            Duration::from_secs(5),
            reqwest::Method::GET,
            "/repos",
            None,
            &[("page".to_owned(), "2".to_owned())],
            None,
        )
        .await;
        let (status, body) = response_parts(listed).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"items": []}));

        let created = forward(
            &base,
            Duration::from_secs(5),
            reqwest::Method::POST,
            "/repos",
            None,
            &[],
            Some(&serde_json::json!({"url": "https://github.com/penguintechinc/skauswatch"})),
        )
        .await;
        let (status, body) = response_parts(created).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body, serde_json::json!({"id": 7}));
    }

    #[tokio::test]
    async fn proxy_passes_upstream_error_status_and_body_through() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/codescan/reviews"))
            .respond_with(
                ResponseTemplate::new(422)
                    .set_body_json(serde_json::json!({"error": "invalid repo_id"})),
            )
            .mount(&upstream)
            .await;

        let resp = forward(
            &format!("{}/api/v1/codescan", upstream.uri()),
            Duration::from_secs(5),
            reqwest::Method::POST,
            "/reviews",
            None,
            &[],
            Some(&serde_json::json!({})),
        )
        .await;
        let (status, body) = response_parts(resp).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body, serde_json::json!({"error": "invalid repo_id"}));
    }

    #[tokio::test]
    async fn proxy_wraps_non_json_upstream_as_raw() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/codescan/status"))
            .respond_with(ResponseTemplate::new(200).set_body_string("plain text"))
            .mount(&upstream)
            .await;

        let resp = forward(
            &format!("{}/api/v1/codescan", upstream.uri()),
            Duration::from_secs(5),
            reqwest::Method::GET,
            "/status",
            None,
            &[],
            None,
        )
        .await;
        let (status, body) = response_parts(resp).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"raw": "plain text"}));
    }

    /// Defense-in-depth regression: an unmodeled field ("internal_secret")
    /// that `codescan-backend` has no business exposing must never survive
    /// `allowlist` — only fields declared on the DTO reach the caller.
    #[tokio::test]
    async fn allowlist_strips_unknown_field_from_status_response() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/codescan/status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": "ok",
                "queue_depth": 4,
                "internal_secret": "leak-me-not",
            })))
            .mount(&upstream)
            .await;

        let resp = forward(
            &format!("{}/api/v1/codescan", upstream.uri()),
            Duration::from_secs(5),
            reqwest::Method::GET,
            "/status",
            None,
            &[],
            None,
        )
        .await;
        let stripped = allowlist::<StatusResponse>(resp).await;
        let (status, body) = response_parts(stripped).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({"status": "ok", "queue_depth": 4}));
        assert!(
            body.get("internal_secret").is_none(),
            "unmodeled upstream field must be stripped, got {body}"
        );
    }

    /// Non-2xx bodies are error/diagnostic shapes, not modeled response DTOs
    /// — `allowlist` must leave them completely untouched even though they
    /// wouldn't deserialize as the success-path DTO at all.
    #[tokio::test]
    async fn allowlist_passes_non_success_status_through_unchanged() {
        let upstream = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/codescan/reviews"))
            .respond_with(ResponseTemplate::new(422).set_body_json(serde_json::json!({
                "error": "invalid repo_id",
                "internal_debug": "should still pass through on errors",
            })))
            .mount(&upstream)
            .await;

        let resp = forward(
            &format!("{}/api/v1/codescan", upstream.uri()),
            Duration::from_secs(5),
            reqwest::Method::POST,
            "/reviews",
            None,
            &[],
            Some(&serde_json::json!({})),
        )
        .await;
        let passed = allowlist::<ReviewRow>(resp).await;
        let (status, body) = response_parts(passed).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body,
            serde_json::json!({
                "error": "invalid repo_id",
                "internal_debug": "should still pass through on errors",
            })
        );
    }

    /// A 2xx body that doesn't match the modeled DTO at all (an upstream
    /// contract break) fails closed as a 502 rather than forwarding a shape
    /// the caller was never promised.
    #[tokio::test]
    async fn allowlist_fails_closed_on_a_2xx_body_that_does_not_match_the_dto() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/codescan/status"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"unexpected": "shape"})),
            )
            .mount(&upstream)
            .await;

        let resp = forward(
            &format!("{}/api/v1/codescan", upstream.uri()),
            Duration::from_secs(5),
            reqwest::Method::GET,
            "/status",
            None,
            &[],
            None,
        )
        .await;
        let stripped = allowlist::<StatusResponse>(resp).await;
        let (status, body) = response_parts(stripped).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(
            body,
            serde_json::json!({"error": "Unexpected response shape from worker-codescan"})
        );
    }

    #[tokio::test]
    async fn proxy_timeout_maps_to_v1_504() {
        let upstream = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/codescan/status"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&upstream)
            .await;

        let resp = forward(
            &format!("{}/api/v1/codescan", upstream.uri()),
            Duration::from_millis(100),
            reqwest::Method::GET,
            "/status",
            None,
            &[],
            None,
        )
        .await;
        let (status, body) = response_parts(resp).await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(
            body,
            serde_json::json!({"error": "worker-codescan timeout"})
        );
    }

    #[tokio::test]
    async fn proxy_unreachable_upstream_maps_to_v1_503() {
        // Port 1 is never listening — immediate connection refusal.
        let resp = forward(
            "http://127.0.0.1:1/api/v1/codescan",
            Duration::from_secs(2),
            reqwest::Method::GET,
            "/status",
            None,
            &[],
            None,
        )
        .await;
        let (status, body) = response_parts(resp).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            body,
            serde_json::json!({"error": "Cannot connect to worker-codescan"})
        );
    }

    #[test]
    fn role_gates_match_v1() {
        // repos mutations: admin only.
        assert!(user_with_role("admin").require_role(&["admin"]).is_ok());
        for role in ["maintainer", "viewer"] {
            match user_with_role(role).require_role(&["admin"]) {
                Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Insufficient permissions"),
                other => panic!("expected 403 for {role}, got {other:?}"),
            }
        }
        // reviews POST: v1 `role_required("maintainer")` admits ONLY the
        // maintainer role — admins are rejected too (replicated quirk).
        assert!(
            user_with_role("maintainer")
                .require_role(&["maintainer"])
                .is_ok()
        );
        for role in ["admin", "viewer"] {
            match user_with_role(role).require_role(&["maintainer"]) {
                Err(ApiError::Forbidden(msg)) => assert_eq!(msg, "Insufficient permissions"),
                other => panic!("expected 403 for {role}, got {other:?}"),
            }
        }
    }

    #[test]
    fn body_parsing_matches_quart_get_json_or_empty() {
        let parse = |raw: &str| parse_body(&Bytes::copy_from_slice(raw.as_bytes()));
        // Empty body → {} (Quart get_json() → None → `or {}`).
        match parse("") {
            Ok(v) => assert_eq!(v, serde_json::json!({})),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
        // Python-falsy JSON values all collapse to {}.
        for falsy in ["null", "false", "0", "\"\"", "[]", "{}"] {
            match parse(falsy) {
                Ok(v) => assert_eq!(v, serde_json::json!({}), "for input {falsy}"),
                Err(e) => panic!("expected ok for {falsy}, got {e:?}"),
            }
        }
        // Truthy values pass through untouched.
        match parse(r#"{"url": "x"}"#) {
            Ok(v) => assert_eq!(v, serde_json::json!({"url": "x"})),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
        match parse("[1]") {
            Ok(v) => assert_eq!(v, serde_json::json!([1])),
            Err(e) => panic!("expected ok, got {e:?}"),
        }
        // Malformed JSON → envelope 400.
        assert!(matches!(parse("{not json"), Err(ApiError::BadRequest(_))));
    }

    #[test]
    fn query_params_first_value_wins() {
        let pairs = vec![
            ("page".to_owned(), "1".to_owned()),
            ("page".to_owned(), "9".to_owned()),
            ("status".to_owned(), "queued".to_owned()),
        ];
        assert_eq!(
            dedupe_first(&pairs),
            vec![
                ("page".to_owned(), "1".to_owned()),
                ("status".to_owned(), "queued".to_owned()),
            ]
        );
    }

    /// Exercises the thin per-route wrapper handlers (`codescan_status`,
    /// `list_repos`, `create_repo`, ...) directly — bypassing the HTTP router
    /// entirely, the same trick `routes/asm.rs` uses, since none of them
    /// extract anything beyond `State`/`CurrentUser`/headers/body. The
    /// workspace forbids `unsafe`, so these cannot mutate `WORKER_CODESCAN_URL`
    /// to point at a wiremock upstream (unlike the `forward()`-level tests
    /// above, which take the base URL as a plain argument); every call here
    /// resolves the real default `http://worker-codescan:5005`, which is
    /// unreachable in the test sandbox, so every non-forbidden/non-license-
    /// denied call still exercises the wrapper's full body (license gate +
    /// `proxy()` + response conversion) and lands on a transport-error
    /// response rather than a 2xx.
    #[tokio::test]
    async fn wrapper_handlers_reach_proxy_against_the_default_upstream() {
        let state = AppStateInner::for_tests(dev_license());
        let headers = HeaderMap::new();

        let status = codescan_status(
            State(state.clone()),
            user_with_role("viewer"),
            headers.clone(),
        )
        .await
        .unwrap_or_else(|e| panic!("status: {e:?}"));
        assert!(status.status().is_client_error() || status.status().is_server_error());

        let listed = list_repos(
            State(state.clone()),
            user_with_role("viewer"),
            headers.clone(),
            Query(vec![]),
        )
        .await
        .unwrap_or_else(|e| panic!("list_repos: {e:?}"));
        assert!(listed.status().is_server_error() || listed.status().is_client_error());

        let created = create_repo(
            State(state.clone()),
            user_with_role("admin"),
            headers.clone(),
            Bytes::from_static(br#"{"url":"https://example.com/r"}"#),
        )
        .await
        .unwrap_or_else(|e| panic!("create_repo: {e:?}"));
        assert!(created.status().is_server_error() || created.status().is_client_error());

        let forbidden = create_repo(
            State(state.clone()),
            user_with_role("viewer"),
            headers.clone(),
            Bytes::new(),
        )
        .await;
        assert!(matches!(forbidden, Err(ApiError::Forbidden(_))));

        let fetched = get_repo(
            State(state.clone()),
            user_with_role("viewer"),
            headers.clone(),
            Path(1),
        )
        .await
        .unwrap_or_else(|e| panic!("get_repo: {e:?}"));
        assert!(fetched.status().is_server_error() || fetched.status().is_client_error());

        let updated = update_repo(
            State(state.clone()),
            user_with_role("admin"),
            headers.clone(),
            Path(1),
            Bytes::from_static(b"{}"),
        )
        .await
        .unwrap_or_else(|e| panic!("update_repo: {e:?}"));
        assert!(updated.status().is_server_error() || updated.status().is_client_error());

        let deleted = delete_repo(
            State(state.clone()),
            user_with_role("admin"),
            headers.clone(),
            Path(1),
        )
        .await
        .unwrap_or_else(|e| panic!("delete_repo: {e:?}"));
        assert!(deleted.status().is_server_error() || deleted.status().is_client_error());

        let reviews = list_reviews(
            State(state.clone()),
            user_with_role("viewer"),
            headers.clone(),
            Query(vec![]),
        )
        .await
        .unwrap_or_else(|e| panic!("list_reviews: {e:?}"));
        assert!(reviews.status().is_server_error() || reviews.status().is_client_error());

        let review_created = create_review(
            State(state.clone()),
            user_with_role("maintainer"),
            headers.clone(),
            Bytes::from_static(b"{}"),
        )
        .await
        .unwrap_or_else(|e| panic!("create_review: {e:?}"));
        assert!(
            review_created.status().is_server_error() || review_created.status().is_client_error()
        );

        let review_forbidden = create_review(
            State(state.clone()),
            user_with_role("admin"),
            headers.clone(),
            Bytes::new(),
        )
        .await;
        assert!(matches!(review_forbidden, Err(ApiError::Forbidden(_))));

        let review = get_review(
            State(state.clone()),
            user_with_role("viewer"),
            headers.clone(),
            Path(1),
        )
        .await
        .unwrap_or_else(|e| panic!("get_review: {e:?}"));
        assert!(review.status().is_server_error() || review.status().is_client_error());

        let plans = list_plans(
            State(state.clone()),
            user_with_role("viewer"),
            headers.clone(),
            Query(vec![]),
        )
        .await
        .unwrap_or_else(|e| panic!("list_plans: {e:?}"));
        assert!(plans.status().is_server_error() || plans.status().is_client_error());

        let plan_created = create_plan(
            State(state.clone()),
            user_with_role("viewer"),
            headers.clone(),
            Bytes::from_static(b"{}"),
        )
        .await
        .unwrap_or_else(|e| panic!("create_plan: {e:?}"));
        assert!(plan_created.status().is_server_error() || plan_created.status().is_client_error());

        let plan = get_plan(
            State(state.clone()),
            user_with_role("viewer"),
            headers,
            Path(1),
        )
        .await
        .unwrap_or_else(|e| panic!("get_plan: {e:?}"));
        assert!(plan.status().is_server_error() || plan.status().is_client_error());

        // License-denied path through a wrapper handler.
        let gated_state = AppStateInner::for_tests(gated_license());
        let denied = codescan_status(
            State(gated_state),
            user_with_role("viewer"),
            HeaderMap::new(),
        )
        .await
        .unwrap_or_else(|e| panic!("status: {e:?}"));
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    }
}
