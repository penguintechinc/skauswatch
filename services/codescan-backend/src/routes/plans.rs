//! /api/v1/codescan/plans — issue-plan CRUD. Port of
//! `darwin/services/flask-backend/app/api/v1/issue_plans.py`. POST admits any
//! authenticated role, matching v1's bare `@auth_required` and the manager's
//! already-tested proxy gate (services/manager/src/routes/codescan.rs).
//!
//! Deferred: v1 processed plans via a Celery worker
//! (`app/tasks/plan_worker.py`); worker-codescan
//! (services/worker-codescan/src/message.rs) only consumes review tasks from
//! `codescan:tasks`, not issue-plan generation. Plans created here persist as
//! `status = "queued"` with no active consumer in v2 yet — a tracked parity
//! gap, not silently dropped functionality.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::routes::license_denied;
use crate::state::AppState;

const VALID_PLATFORMS: [&str; 2] = ["github", "gitlab"];
const DEFAULT_PER_PAGE: i64 = 20;
const MAX_PER_PAGE: i64 = 100;

/// Router for /api/v1/codescan/plans.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/codescan/plans", get(list_plans).post(create_plan))
        .route("/codescan/plans/{plan_id}", get(get_plan))
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
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

const PLAN_COLUMNS: &str = "id, external_id, platform, repository, issue_number, issue_url, \
     issue_title, plan_content, plan_steps, ai_provider, ai_model, status, error_message, \
     comment_posted, created_at, updated_at";

// NOTE: `tenant_id` deliberately isn't in `PLAN_COLUMNS`/`PlanRow` — this
// service never exposed it in the plan detail/list response, and this pass
// only closes the tenant-isolation gap (filter/stamp), not the response
// shape. Every query below still filters/stamps on it.

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    platform: Option<String>,
    repository: Option<String>,
    status: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

/// Documentation-only mirror of `list_plans`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PlanListResponse {
    plans: Vec<PlanRow>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// GET /codescan/plans — paginated, optionally filtered.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/plans",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Paginated issue-plan list", body = PlanListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_plans(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let (page, per_page) = pagination(q.page, q.per_page);
    let offset = (page - 1) * per_page;

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
        "SELECT {PLAN_COLUMNS} FROM codescan_issue_plans WHERE tenant_id = "
    ));
    qb.push_bind(user.tenant_id);
    if let Some(platform) = &q.platform {
        qb.push(" AND platform = ").push_bind(platform.clone());
    }
    if let Some(repository) = &q.repository {
        qb.push(" AND repository = ").push_bind(repository.clone());
    }
    if let Some(status) = &q.status {
        qb.push(" AND status = ").push_bind(status.clone());
    }
    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let items = qb.build_query_as::<PlanRow>().fetch_all(&state.db).await?;

    let mut count_qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT count(*) FROM codescan_issue_plans WHERE tenant_id = ",
    );
    count_qb.push_bind(user.tenant_id);
    if let Some(platform) = &q.platform {
        count_qb
            .push(" AND platform = ")
            .push_bind(platform.clone());
    }
    if let Some(repository) = &q.repository {
        count_qb
            .push(" AND repository = ")
            .push_bind(repository.clone());
    }
    if let Some(status) = &q.status {
        count_qb.push(" AND status = ").push_bind(status.clone());
    }
    let total: i64 = count_qb.build_query_scalar().fetch_one(&state.db).await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "plans": items,
            "total": total,
            "page": page,
            "per_page": per_page,
        })),
    )
        .into_response())
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreatePlanRequest {
    platform: String,
    repository: String,
    issue_number: i32,
    #[serde(default)]
    external_id: Option<String>,
    #[serde(default)]
    issue_url: Option<String>,
    #[serde(default)]
    issue_title: Option<String>,
    #[serde(default)]
    issue_body: Option<String>,
    #[serde(default)]
    ai_provider: Option<String>,
    #[serde(default)]
    ai_model: Option<String>,
}

fn validate_create(body: &CreatePlanRequest) -> Result<(), ApiError> {
    if !VALID_PLATFORMS.contains(&body.platform.as_str()) {
        return Err(validation(
            "platform",
            "Input should be 'github' or 'gitlab'",
        ));
    }
    if body.repository.trim().is_empty() {
        return Err(validation("repository", "repository is required"));
    }
    Ok(())
}

/// POST /codescan/plans — any authenticated role (see module docs).
#[utoipa::path(
    post,
    path = "/api/v1/codescan/plans",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    request_body = CreatePlanRequest,
    responses(
        (status = 201, description = "Issue plan created", body = PlanRow),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 409, description = "Issue plan with this external_id already exists", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_plan(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiJson(body): ApiJson<CreatePlanRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    validate_create(&body)?;

    let external_id = body.external_id.clone().unwrap_or_else(|| {
        format!(
            "{}-issue-{}-{}",
            body.platform,
            body.issue_number,
            chrono::Utc::now().timestamp_millis()
        )
    });

    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM codescan_issue_plans WHERE external_id = $1 AND tenant_id = $2",
    )
    .bind(&external_id)
    .bind(user.tenant_id)
    .fetch_optional(&state.db)
    .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict(serde_json::json!({
            "error": "Issue plan with this external_id already exists"
        })));
    }

    let query = format!(
        "INSERT INTO codescan_issue_plans \
         (external_id, tenant_id, platform, repository, issue_number, issue_url, issue_title, \
          issue_body, ai_provider, ai_model, status, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'queued',now()) \
         RETURNING {PLAN_COLUMNS}"
    );
    let created = sqlx::query_as::<_, PlanRow>(sqlx::AssertSqlSafe(query))
        .bind(&external_id)
        .bind(user.tenant_id)
        .bind(&body.platform)
        .bind(&body.repository)
        .bind(body.issue_number)
        .bind(&body.issue_url)
        .bind(&body.issue_title)
        .bind(&body.issue_body)
        .bind(&body.ai_provider)
        .bind(&body.ai_model)
        .fetch_one(&state.db)
        .await?;

    Ok((StatusCode::CREATED, Json(created)).into_response())
}

/// GET /codescan/plans/{plan_id}.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/plans/{plan_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("plan_id" = i64, Path, description = "Issue plan id")),
    responses(
        (status = 200, description = "Issue plan detail", body = PlanRow),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 404, description = "Issue plan not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_plan(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(plan_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let query =
        format!("SELECT {PLAN_COLUMNS} FROM codescan_issue_plans WHERE id = $1 AND tenant_id = $2");
    let row = sqlx::query_as::<_, PlanRow>(sqlx::AssertSqlSafe(query))
        .bind(plan_id)
        .bind(user.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Issue plan not found".to_owned()))?;
    Ok((StatusCode::OK, Json(row)).into_response())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
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
        assert_eq!(pagination(Some(2), Some(500)), (2, 100));
    }

    #[test]
    fn validate_create_rejects_bad_platform() {
        let body = CreatePlanRequest {
            platform: "bitbucket".to_owned(),
            repository: "a/b".to_owned(),
            issue_number: 1,
            external_id: None,
            issue_url: None,
            issue_title: None,
            issue_body: None,
            ai_provider: None,
            ai_model: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[test]
    fn validate_create_rejects_empty_repository() {
        let body = CreatePlanRequest {
            platform: "github".to_owned(),
            repository: String::new(),
            issue_number: 1,
            external_id: None,
            issue_url: None,
            issue_title: None,
            issue_body: None,
            ai_provider: None,
            ai_model: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[tokio::test]
    async fn list_get_and_create_require_auth() {
        let server = test_server(AppStateInner::for_tests(dev_license()));
        for resp in [
            server.get("/api/v1/codescan/plans").await,
            server.post("/api/v1/codescan/plans").await,
            server.get("/api/v1/codescan/plans/1").await,
        ] {
            resp.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    fn create_body(repository: &str, issue_number: i32) -> serde_json::Value {
        serde_json::json!({
            "platform": "github",
            "repository": repository,
            "issue_number": issue_number,
            "external_id": format!("gh-{repository}-{issue_number}"),
        })
    }

    #[tokio::test]
    async fn list_is_empty_against_a_fresh_db() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = crate::routes::test_support::sign_token(&state, "1", "viewer");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/plans")
            .authorization_bearer(token)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["total"], 0);
        assert_eq!(body["plans"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn create_get_and_conflict_round_trip() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = crate::routes::test_support::sign_token(&state, "1", "viewer");
        let server = test_server(state);

        let created = server
            .post("/api/v1/codescan/plans")
            .authorization_bearer(&token)
            .json(&create_body("org/repo", 42))
            .await;
        created.assert_status(StatusCode::CREATED);
        let created_body: serde_json::Value = created.json();
        let plan_id = created_body["id"].as_i64().unwrap_or_default();
        assert!(plan_id > 0);
        assert_eq!(created_body["status"], "queued");

        let fetched = server
            .get(&format!("/api/v1/codescan/plans/{plan_id}"))
            .authorization_bearer(&token)
            .await;
        fetched.assert_status_ok();
        let fetched_body: serde_json::Value = fetched.json();
        assert_eq!(fetched_body["repository"], "org/repo");

        let dup = server
            .post("/api/v1/codescan/plans")
            .authorization_bearer(&token)
            .json(&create_body("org/repo", 42))
            .await;
        dup.assert_status(StatusCode::CONFLICT);
        let dup_body: serde_json::Value = dup.json();
        assert_eq!(
            dup_body["error"],
            "Issue plan with this external_id already exists"
        );

        let listed = server
            .get("/api/v1/codescan/plans?repository=org/repo")
            .authorization_bearer(&token)
            .await;
        listed.assert_status_ok();
        let listed_body: serde_json::Value = listed.json();
        assert_eq!(listed_body["total"], 1);
    }

    #[tokio::test]
    async fn get_plan_404_on_unknown_id() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = crate::routes::test_support::sign_token(&state, "1", "viewer");
        let server = test_server(state);
        server
            .get("/api/v1/codescan/plans/999999")
            .authorization_bearer(token)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    /// Tenant A cannot list or read tenant B's issue plans.
    #[tokio::test]
    async fn tenant_a_cannot_access_tenant_b_plans() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token_a = crate::routes::test_support::sign_token(&state, "1", "viewer");
        let token_b = crate::routes::test_support::sign_token_for_tenant(
            &state,
            "2",
            "viewer",
            crate::routes::test_support::OTHER_TENANT_ID,
        );
        let server = test_server(state);

        let created = server
            .post("/api/v1/codescan/plans")
            .authorization_bearer(&token_b)
            .json(&create_body("tenant-b/repo", 1))
            .await;
        created.assert_status(StatusCode::CREATED);
        let plan_id = created.json::<serde_json::Value>()["id"]
            .as_i64()
            .unwrap_or_default();

        let listed = server
            .get("/api/v1/codescan/plans")
            .authorization_bearer(&token_a)
            .await;
        listed.assert_status_ok();
        assert_eq!(listed.json::<serde_json::Value>()["total"], 0);

        server
            .get(&format!("/api/v1/codescan/plans/{plan_id}"))
            .authorization_bearer(&token_a)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }
}
