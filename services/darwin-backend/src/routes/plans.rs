//! /api/v1/darwin/plans — issue-plan CRUD. Port of
//! `darwin/services/flask-backend/app/api/v1/issue_plans.py`. POST admits any
//! authenticated role, matching v1's bare `@auth_required` and the manager's
//! already-tested proxy gate (services/manager/src/routes/darwin.rs).
//!
//! Deferred: v1 processed plans via a Celery worker
//! (`app/tasks/plan_worker.py`); worker-darwin
//! (services/worker-darwin/src/message.rs) only consumes review tasks from
//! `darwin:tasks`, not issue-plan generation. Plans created here persist as
//! `status = "queued"` with no active consumer in v2 yet — a tracked parity
//! gap, not silently dropped functionality.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson};
use crate::routes::license_denied;
use crate::state::AppState;

const VALID_PLATFORMS: [&str; 2] = ["github", "gitlab"];
const DEFAULT_PER_PAGE: i64 = 20;
const MAX_PER_PAGE: i64 = 100;

/// Router for /api/v1/darwin/plans.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/darwin/plans", get(list_plans).post(create_plan))
        .route("/darwin/plans/{plan_id}", get(get_plan))
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

#[derive(sqlx::FromRow, Serialize)]
struct PlanRow {
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
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    created_at: Option<chrono::NaiveDateTime>,
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    updated_at: Option<chrono::NaiveDateTime>,
}

const PLAN_COLUMNS: &str = "id, external_id, platform, repository, issue_number, issue_url, \
     issue_title, plan_content, plan_steps, ai_provider, ai_model, status, error_message, \
     comment_posted, created_at, updated_at";

#[derive(Deserialize)]
struct ListQuery {
    platform: Option<String>,
    repository: Option<String>,
    status: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

/// GET /darwin/plans — paginated, optionally filtered.
async fn list_plans(
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
        "SELECT {PLAN_COLUMNS} FROM darwin_issue_plans WHERE 1=1"
    ));
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
        "SELECT count(*) FROM darwin_issue_plans WHERE 1=1",
    );
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

#[derive(Deserialize)]
struct CreatePlanRequest {
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

/// POST /darwin/plans — any authenticated role (see module docs).
async fn create_plan(
    State(state): State<AppState>,
    _user: CurrentUser,
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

    let existing: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM darwin_issue_plans WHERE external_id = $1")
            .bind(&external_id)
            .fetch_optional(&state.db)
            .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict(serde_json::json!({
            "error": "Issue plan with this external_id already exists"
        })));
    }

    let query = format!(
        "INSERT INTO darwin_issue_plans \
         (external_id, platform, repository, issue_number, issue_url, issue_title, issue_body, \
          ai_provider, ai_model, status, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'queued',now()) \
         RETURNING {PLAN_COLUMNS}"
    );
    let created = sqlx::query_as::<_, PlanRow>(sqlx::AssertSqlSafe(query))
        .bind(&external_id)
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

/// GET /darwin/plans/{plan_id}.
async fn get_plan(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(plan_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let query = format!("SELECT {PLAN_COLUMNS} FROM darwin_issue_plans WHERE id = $1");
    let row = sqlx::query_as::<_, PlanRow>(sqlx::AssertSqlSafe(query))
        .bind(plan_id)
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
            server.get("/api/v1/darwin/plans").await,
            server.post("/api/v1/darwin/plans").await,
            server.get("/api/v1/darwin/plans/1").await,
        ] {
            resp.assert_status(StatusCode::UNAUTHORIZED);
        }
    }
}
