//! /api/v1/codescan/reviews — review CRUD + task enqueue. Port of
//! `darwin/services/flask-backend/app/api/v1/reviews.py`. Creating a review
//! enqueues a `CodeScanReviewTask` onto the `codescan:tasks` stream
//! (skauswatch_streams::STREAM_CODESCAN_TASKS) with the exact field names
//! `services/worker-codescan/src/message.rs` parses.
//!
//! POST is gated to the `maintainer` role only — a deliberate replication of
//! the manager's already-tested proxy gate
//! (`services/manager/src/routes/codescan.rs::create_review`), which admits
//! ONLY `maintainer` (admins get 403 at the proxy layer before reaching this
//! service). v1's own `role_required("admin", "maintainer")` was broader;
//! matching the manager's tested contract here keeps both layers consistent
//! rather than silently disagreeing.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use skauswatch_streams::STREAM_CODESCAN_TASKS;

use crate::auth::{CurrentUser, MaintainerOnly};
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::routes::license_denied;
use crate::state::AppState;

const VALID_REVIEW_TYPES: [&str; 2] = ["differential", "whole"];
const DEFAULT_PER_PAGE: i64 = 20;
const MAX_PER_PAGE: i64 = 100;

/// Router for /api/v1/codescan/reviews.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/codescan/reviews", get(list_reviews).post(create_review))
        .route("/codescan/reviews/{review_id}", get(get_review))
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

fn pagination(page: Option<i64>, per_page: Option<i64>) -> (i64, i64) {
    (
        page.unwrap_or(1).max(1),
        per_page.unwrap_or(DEFAULT_PER_PAGE).clamp(1, MAX_PER_PAGE),
    )
}

#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewRow {
    id: i64,
    external_id: Option<String>,
    tenant_id: Option<i64>,
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
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    started_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    completed_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

const REVIEW_COLUMNS: &str = "id, external_id, tenant_id, team_id, triggered_by, repo_config_id, \
     pr_number, pr_title, pr_url, base_sha, head_sha, review_type, categories, ai_provider, \
     ai_model, status, error_message, files_reviewed, comments_count, summary, started_at, \
     completed_at, created_at, updated_at";

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    repo_config_id: Option<i64>,
    status: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

/// Pagination metadata shared by the `reviews` and `plans` list responses.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PaginationMeta {
    page: i64,
    per_page: i64,
    total: i64,
    pages: i64,
}

/// Documentation-only mirror of `list_reviews`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewListResponse {
    data: Vec<ReviewRow>,
    pagination: PaginationMeta,
}

/// GET /codescan/reviews — paginated, optionally filtered by `repo_config_id`
/// and `status`.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/reviews",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Paginated review list", body = ReviewListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_reviews(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let (page, per_page) = pagination(q.page, q.per_page);
    let offset = (page - 1) * per_page;

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
        "SELECT {REVIEW_COLUMNS} FROM codescan_reviews WHERE 1=1"
    ));
    if let Some(repo_config_id) = q.repo_config_id {
        qb.push(" AND repo_config_id = ").push_bind(repo_config_id);
    }
    if let Some(status) = &q.status {
        qb.push(" AND status = ").push_bind(status.clone());
    }
    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);

    let items = qb
        .build_query_as::<ReviewRow>()
        .fetch_all(&state.db)
        .await?;

    let mut count_qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT count(*) FROM codescan_reviews WHERE 1=1",
    );
    if let Some(repo_config_id) = q.repo_config_id {
        count_qb
            .push(" AND repo_config_id = ")
            .push_bind(repo_config_id);
    }
    if let Some(status) = &q.status {
        count_qb.push(" AND status = ").push_bind(status.clone());
    }
    let total: i64 = count_qb.build_query_scalar().fetch_one(&state.db).await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "data": items,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total,
                "pages": (total + per_page - 1) / per_page,
            },
        })),
    )
        .into_response())
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateReviewRequest {
    repo_config_id: i64,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default = "default_review_type")]
    review_type: String,
    #[serde(default)]
    categories: Vec<String>,
    #[serde(default)]
    ai_provider: Option<String>,
    #[serde(default)]
    ai_model: Option<String>,
    #[serde(default)]
    pr_number: Option<i32>,
    #[serde(default)]
    pr_title: Option<String>,
    pr_url: String,
    #[serde(default)]
    base_sha: Option<String>,
    #[serde(default)]
    head_sha: Option<String>,
}

fn default_review_type() -> String {
    "differential".to_owned()
}

fn validate_create(body: &CreateReviewRequest) -> Result<(), ApiError> {
    if !VALID_REVIEW_TYPES.contains(&body.review_type.as_str()) {
        return Err(validation(
            "review_type",
            "Input should be 'differential' or 'whole'",
        ));
    }
    if body.pr_url.trim().is_empty() {
        return Err(validation("pr_url", "pr_url is required"));
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct RepoConfigRef {
    id: i64,
    tenant_id: Option<i64>,
    provider: String,
    repo_name: String,
    default_ai_provider: Option<String>,
}

/// Builds the ordered `codescan:tasks` field list — a pure function so the
/// wire contract with worker-codescan (services/worker-codescan/src/message.rs)
/// can be unit-tested without a live Redis/Postgres.
fn build_review_task_fields(
    review_id: i64,
    repo_config: &RepoConfigRef,
    pr_url: &str,
    ai_provider: Option<&str>,
    ai_model: Option<&str>,
) -> skauswatch_streams::EntryFields {
    let mut fields = vec![
        ("review_id".to_owned(), review_id.to_string()),
        ("repo_config_id".to_owned(), repo_config.id.to_string()),
        ("provider".to_owned(), repo_config.provider.clone()),
        ("repo_name".to_owned(), repo_config.repo_name.clone()),
        ("pr_url".to_owned(), pr_url.to_owned()),
        (
            "tenant_id".to_owned(),
            repo_config.tenant_id.unwrap_or(0).to_string(),
        ),
    ];
    if let Some(p) = ai_provider {
        fields.push(("ai_provider".to_owned(), p.to_owned()));
    }
    if let Some(m) = ai_model {
        fields.push(("ai_model".to_owned(), m.to_owned()));
    }
    fields
}

/// POST /codescan/reviews — maintainer only (see module docs); enqueues onto
/// `codescan:tasks` after the row is committed.
#[utoipa::path(
    post,
    path = "/api/v1/codescan/reviews",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    request_body = CreateReviewRequest,
    responses(
        (status = 201, description = "Review created and enqueued", body = ReviewRow),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Repository configuration not found", body = ErrorResponse),
        (status = 409, description = "Review with this external_id already exists", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_review(
    State(state): State<AppState>,
    MaintainerOnly(user): MaintainerOnly,
    ApiJson(body): ApiJson<CreateReviewRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    validate_create(&body)?;

    let repo_config = sqlx::query_as::<_, RepoConfigRef>(
        "SELECT id, tenant_id, provider, repo_name, default_ai_provider \
         FROM codescan_repo_configs WHERE id = $1",
    )
    .bind(body.repo_config_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Repository configuration not found".to_owned()))?;

    if let Some(external_id) = &body.external_id {
        let existing: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM codescan_reviews WHERE external_id = $1")
                .bind(external_id)
                .fetch_optional(&state.db)
                .await?;
        if existing.is_some() {
            return Err(ApiError::Conflict(serde_json::json!({
                "error": "Review with this external_id already exists"
            })));
        }
    }

    let external_id = body.external_id.clone().unwrap_or_else(|| {
        format!(
            "codescan-{}-{}",
            body.repo_config_id,
            chrono::Utc::now().timestamp_millis()
        )
    });
    let ai_provider = body
        .ai_provider
        .clone()
        .or_else(|| repo_config.default_ai_provider.clone());

    let query = format!(
        "INSERT INTO codescan_reviews \
         (external_id, tenant_id, triggered_by, repo_config_id, pr_number, pr_title, pr_url, \
          base_sha, head_sha, review_type, categories, ai_provider, ai_model, status, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'queued',now()) \
         RETURNING {REVIEW_COLUMNS}"
    );
    let created = sqlx::query_as::<_, ReviewRow>(sqlx::AssertSqlSafe(query))
        .bind(&external_id)
        .bind(repo_config.tenant_id)
        .bind(user.id)
        .bind(body.repo_config_id)
        .bind(body.pr_number)
        .bind(&body.pr_title)
        .bind(&body.pr_url)
        .bind(&body.base_sha)
        .bind(&body.head_sha)
        .bind(&body.review_type)
        .bind(serde_json::to_value(&body.categories).unwrap_or(serde_json::Value::Null))
        .bind(&ai_provider)
        .bind(&body.ai_model)
        .fetch_one(&state.db)
        .await?;

    let fields = build_review_task_fields(
        created.id,
        &repo_config,
        &body.pr_url,
        ai_provider.as_deref(),
        body.ai_model.as_deref(),
    );
    state.publish_stream(STREAM_CODESCAN_TASKS, fields).await;

    Ok((StatusCode::CREATED, Json(created)).into_response())
}

#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewComment {
    id: i64,
    file_path: Option<String>,
    line_number: Option<i32>,
    comment: Option<String>,
    category: Option<String>,
    severity: Option<String>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Documentation-only mirror of `get_review`'s merged JSON body — the
/// handler builds this shape by hand (`ReviewRow` fields flattened, plus a
/// `comments` array) via `serde_json::Value` manipulation rather than
/// deriving `Serialize` on a single struct, so this type exists solely to
/// describe the wire shape to `utoipa`.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct ReviewDetailResponse {
    #[serde(flatten)]
    review: ReviewRow,
    comments: Vec<ReviewComment>,
}

/// GET /codescan/reviews/{review_id} — review detail enriched with comments.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/reviews/{review_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("review_id" = i64, Path, description = "Review id")),
    responses(
        (status = 200, description = "Review detail with comments", body = ReviewDetailResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 404, description = "Review not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_review(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(review_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let query = format!("SELECT {REVIEW_COLUMNS} FROM codescan_reviews WHERE id = $1");
    let review = sqlx::query_as::<_, ReviewRow>(sqlx::AssertSqlSafe(query))
        .bind(review_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Review not found".to_owned()))?;

    let comments = sqlx::query_as::<_, ReviewComment>(
        "SELECT id, file_path, line_number, comment, category, severity, created_at \
         FROM codescan_review_comments WHERE review_id = $1 ORDER BY created_at",
    )
    .bind(review_id)
    .fetch_all(&state.db)
    .await?;

    let mut payload = match serde_json::to_value(&review) {
        Ok(v) => v,
        Err(e) => return Err(ApiError::internal("serialize review", e)),
    };
    if let serde_json::Value::Object(map) = &mut payload {
        map.insert(
            "comments".to_owned(),
            serde_json::to_value(&comments).unwrap_or(serde_json::Value::Array(vec![])),
        );
    }
    Ok((StatusCode::OK, Json(payload)).into_response())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::routes::test_support::sign_token;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use std::sync::Arc;

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

    fn test_server(state: crate::state::AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    #[test]
    fn pagination_defaults_and_clamps() {
        assert_eq!(pagination(None, None), (1, 20));
        assert_eq!(pagination(Some(0), Some(0)), (1, 1));
        assert_eq!(pagination(Some(2), Some(500)), (2, 100));
    }

    #[test]
    fn validate_create_rejects_bad_review_type() {
        let body = CreateReviewRequest {
            repo_config_id: 1,
            external_id: None,
            review_type: "bogus".to_owned(),
            categories: vec![],
            ai_provider: None,
            ai_model: None,
            pr_number: None,
            pr_title: None,
            pr_url: "https://github.com/a/b/pull/1".to_owned(),
            base_sha: None,
            head_sha: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[test]
    fn validate_create_rejects_missing_pr_url() {
        let body = CreateReviewRequest {
            repo_config_id: 1,
            external_id: None,
            review_type: default_review_type(),
            categories: vec![],
            ai_provider: None,
            ai_model: None,
            pr_number: None,
            pr_title: None,
            pr_url: String::new(),
            base_sha: None,
            head_sha: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[test]
    fn task_fields_match_worker_codescan_message_contract() {
        let repo_config = RepoConfigRef {
            id: 7,
            tenant_id: Some(3),
            provider: "github".to_owned(),
            repo_name: "penguintechinc/skauswatch".to_owned(),
            default_ai_provider: Some("claude".to_owned()),
        };
        let fields = build_review_task_fields(
            42,
            &repo_config,
            "https://github.com/penguintechinc/skauswatch/pull/9",
            Some("claude"),
            Some("claude-opus"),
        );
        let map: std::collections::HashMap<_, _> = fields.into_iter().collect();
        assert_eq!(map.get("review_id"), Some(&"42".to_owned()));
        assert_eq!(map.get("repo_config_id"), Some(&"7".to_owned()));
        assert_eq!(map.get("provider"), Some(&"github".to_owned()));
        assert_eq!(
            map.get("repo_name"),
            Some(&"penguintechinc/skauswatch".to_owned())
        );
        assert_eq!(
            map.get("pr_url"),
            Some(&"https://github.com/penguintechinc/skauswatch/pull/9".to_owned())
        );
        assert_eq!(map.get("tenant_id"), Some(&"3".to_owned()));
        assert_eq!(map.get("ai_provider"), Some(&"claude".to_owned()));
        assert_eq!(map.get("ai_model"), Some(&"claude-opus".to_owned()));
    }

    #[test]
    fn task_fields_omit_optional_ai_overrides_when_absent() {
        let repo_config = RepoConfigRef {
            id: 1,
            tenant_id: None,
            provider: "gitlab".to_owned(),
            repo_name: "group/proj".to_owned(),
            default_ai_provider: None,
        };
        let fields =
            build_review_task_fields(1, &repo_config, "https://gitlab.com/g/p/-/mr/1", None, None);
        let keys: Vec<&str> = fields.iter().map(|(k, _)| k.as_str()).collect();
        assert!(!keys.contains(&"ai_provider"));
        assert!(!keys.contains(&"ai_model"));
        let map: std::collections::HashMap<_, _> = fields.into_iter().collect();
        assert_eq!(map.get("tenant_id"), Some(&"0".to_owned()));
    }

    #[tokio::test]
    async fn list_get_and_create_require_auth() {
        let server = test_server(AppStateInner::for_tests(dev_license()));
        for resp in [
            server.get("/api/v1/codescan/reviews").await,
            server.post("/api/v1/codescan/reviews").await,
            server.get("/api/v1/codescan/reviews/1").await,
        ] {
            resp.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn create_review_rejects_non_maintainer_roles() {
        for role in ["admin", "viewer"] {
            let state = AppStateInner::for_tests(dev_license());
            let token = sign_token(&state, "1", role);
            let server = test_server(state);
            let resp = server
                .post("/api/v1/codescan/reviews")
                .authorization_bearer(&token)
                .json(&serde_json::json!({}))
                .await;
            resp.assert_status(StatusCode::FORBIDDEN);
        }
    }

    /// Inserts a `codescan_repo_configs` row directly (bypassing the REST
    /// surface) so review tests have a valid `repo_config_id` to reference —
    /// keeps each review test focused on the reviews table itself.
    async fn seed_repo_config(state: &crate::state::AppState, repo_name: &str) -> i64 {
        let row: (i64,) = match sqlx::query_as(
            "INSERT INTO codescan_repo_configs (provider, repo_url, repo_name) \
             VALUES ('github', $1, $2) RETURNING id",
        )
        .bind(format!("https://github.com/a/{repo_name}"))
        .bind(repo_name)
        .fetch_one(&state.db)
        .await
        {
            Ok(r) => r,
            Err(e) => panic!("seed repo config: {e}"),
        };
        row.0
    }

    #[tokio::test]
    async fn list_is_empty_against_a_fresh_db() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = sign_token(&state, "1", "viewer");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/reviews")
            .authorization_bearer(token)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["pagination"]["total"], 0);
        assert_eq!(body["data"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn create_rejects_unknown_repo_config() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = sign_token(&state, "1", "maintainer");
        let server = test_server(state);
        let resp = server
            .post("/api/v1/codescan/reviews")
            .authorization_bearer(token)
            .json(&serde_json::json!({
                "repo_config_id": 999999,
                "pr_url": "https://github.com/a/b/pull/1",
            }))
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
        let body: serde_json::Value = resp.json();
        assert_eq!(body["error"], "Repository configuration not found");
    }

    #[tokio::test]
    async fn create_list_and_get_round_trip_with_comments() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let repo_config_id = seed_repo_config(&state, "reviewed-repo").await;
        let maintainer = sign_token(&state, "1", "maintainer");
        let server = test_server(state.clone());

        let created = server
            .post("/api/v1/codescan/reviews")
            .authorization_bearer(&maintainer)
            .json(&serde_json::json!({
                "repo_config_id": repo_config_id,
                "pr_url": "https://github.com/a/reviewed-repo/pull/1",
                "external_id": "ext-1",
            }))
            .await;
        created.assert_status(StatusCode::CREATED);
        let created_body: serde_json::Value = created.json();
        let review_id = created_body["id"].as_i64().unwrap_or_default();
        assert!(review_id > 0);
        assert_eq!(created_body["status"], "queued");

        let dup = server
            .post("/api/v1/codescan/reviews")
            .authorization_bearer(&maintainer)
            .json(&serde_json::json!({
                "repo_config_id": repo_config_id,
                "pr_url": "https://github.com/a/reviewed-repo/pull/1",
                "external_id": "ext-1",
            }))
            .await;
        dup.assert_status(StatusCode::CONFLICT);

        if let Err(e) = sqlx::query(
            "INSERT INTO codescan_review_comments (review_id, file_path, comment) \
             VALUES ($1, 'src/lib.rs', 'looks good')",
        )
        .bind(review_id)
        .execute(&state.db)
        .await
        {
            panic!("seed comment: {e}");
        }

        let fetched = server
            .get(&format!("/api/v1/codescan/reviews/{review_id}"))
            .authorization_bearer(&maintainer)
            .await;
        fetched.assert_status_ok();
        let fetched_body: serde_json::Value = fetched.json();
        assert_eq!(fetched_body["comments"].as_array().map(Vec::len), Some(1));
        assert_eq!(fetched_body["comments"][0]["comment"], "looks good");

        let listed = server
            .get(&format!(
                "/api/v1/codescan/reviews?repo_config_id={repo_config_id}"
            ))
            .authorization_bearer(&maintainer)
            .await;
        listed.assert_status_ok();
        let listed_body: serde_json::Value = listed.json();
        assert_eq!(listed_body["pagination"]["total"], 1);
    }

    #[tokio::test]
    async fn get_review_404_on_unknown_id() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = sign_token(&state, "1", "viewer");
        let server = test_server(state);
        server
            .get("/api/v1/codescan/reviews/999999")
            .authorization_bearer(token)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }
}
