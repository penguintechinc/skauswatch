//! /api/v1/codescan/repos — repository configuration CRUD. Port of
//! `darwin/services/flask-backend/app/api/v1/configs.py`, reshaped onto the
//! `codescan_repo_configs` columns worker-codescan already queries
//! (services/worker-codescan/src/db.rs) and the URL shape the manager proxy
//! already tests (services/manager/src/routes/codescan.rs): `GET/POST /repos`,
//! `GET/PUT/DELETE /repos/{id}`.
//!
//! Mutations are admin-only, matching the manager's already-tested gate
//! (`user.require_role(&["admin"])`) rather than v1's finer-grained
//! admin+maintainer split — kept consistent with the one contract callers
//! actually exercise today.

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{AdminOnly, CurrentUser};
use crate::error::{ApiError, ApiJson};
use crate::routes::license_denied;
use crate::state::AppState;

/// Router for /api/v1/codescan/repos.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/codescan/repos", get(list_repos).post(create_repo))
        .route(
            "/codescan/repos/{repo_id}",
            get(get_repo).put(update_repo).delete(delete_repo),
        )
}

const VALID_PROVIDERS: [&str; 2] = ["github", "gitlab"];

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// Repo-config row shape returned by list/get/create/update.
#[derive(sqlx::FromRow, Serialize)]
struct RepoConfig {
    id: i64,
    tenant_id: Option<i64>,
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
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    created_at: Option<chrono::NaiveDateTime>,
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    updated_at: Option<chrono::NaiveDateTime>,
}

const REPO_CONFIG_COLUMNS: &str = "id, tenant_id, team_id, owner_id, provider, repo_url, \
     repo_name, enabled, auto_review, review_on_open, review_on_sync, default_categories, \
     default_ai_provider, ignored_paths, custom_rules, display_name, description, is_active, \
     credential_id, created_at, updated_at";

/// GET /codescan/repos — list repository configurations.
async fn list_repos(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }

    let query =
        format!("SELECT {REPO_CONFIG_COLUMNS} FROM codescan_repo_configs ORDER BY repo_name");
    let items = sqlx::query_as::<_, RepoConfig>(sqlx::AssertSqlSafe(query))
        .fetch_all(&state.db)
        .await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "data": items, "total": items.len() })),
    )
        .into_response())
}

/// POST /codescan/repos body.
#[derive(Deserialize)]
struct CreateRepoRequest {
    provider: String,
    repo_url: String,
    repo_name: String,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    auto_review: Option<bool>,
    #[serde(default)]
    review_on_open: Option<bool>,
    #[serde(default)]
    review_on_sync: Option<bool>,
    #[serde(default)]
    default_categories: Option<serde_json::Value>,
    #[serde(default)]
    default_ai_provider: Option<String>,
    #[serde(default)]
    ignored_paths: Option<serde_json::Value>,
    #[serde(default)]
    custom_rules: Option<serde_json::Value>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    credential_id: Option<i64>,
    #[serde(default)]
    tenant_id: Option<i64>,
    #[serde(default)]
    team_id: Option<i64>,
}

fn validate_create(body: &CreateRepoRequest) -> Result<(), ApiError> {
    if !VALID_PROVIDERS.contains(&body.provider.as_str()) {
        return Err(validation(
            "provider",
            "Input should be 'github' or 'gitlab'",
        ));
    }
    if body.repo_url.trim().is_empty() {
        return Err(validation("repo_url", "repo_url is required"));
    }
    if body.repo_name.trim().is_empty() {
        return Err(validation("repo_name", "repo_name is required"));
    }
    Ok(())
}

/// POST /codescan/repos — admin only.
async fn create_repo(
    State(state): State<AppState>,
    AdminOnly(user): AdminOnly,
    ApiJson(body): ApiJson<CreateRepoRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    validate_create(&body)?;

    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM codescan_repo_configs WHERE provider = $1 AND repo_name = $2",
    )
    .bind(&body.provider)
    .bind(&body.repo_name)
    .fetch_optional(&state.db)
    .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict(serde_json::json!({
            "error": "Repository already configured"
        })));
    }

    let query = format!(
        "INSERT INTO codescan_repo_configs \
         (tenant_id, team_id, owner_id, provider, repo_url, repo_name, enabled, auto_review, \
          review_on_open, review_on_sync, default_categories, default_ai_provider, \
          ignored_paths, custom_rules, display_name, description, credential_id, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,now()) \
         RETURNING {REPO_CONFIG_COLUMNS}"
    );
    let created = sqlx::query_as::<_, RepoConfig>(sqlx::AssertSqlSafe(query))
        .bind(body.tenant_id)
        .bind(body.team_id)
        .bind(user.id)
        .bind(&body.provider)
        .bind(&body.repo_url)
        .bind(&body.repo_name)
        .bind(body.enabled.unwrap_or(true))
        .bind(body.auto_review.unwrap_or(true))
        .bind(body.review_on_open.unwrap_or(true))
        .bind(body.review_on_sync.unwrap_or(false))
        .bind(&body.default_categories)
        .bind(body.default_ai_provider.as_deref().unwrap_or("claude"))
        .bind(&body.ignored_paths)
        .bind(&body.custom_rules)
        .bind(&body.display_name)
        .bind(&body.description)
        .bind(body.credential_id)
        .fetch_one(&state.db)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Configuration created successfully",
            "config": created,
        })),
    )
        .into_response())
}

/// GET /codescan/repos/{repo_id}.
async fn get_repo(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(repo_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let query = format!("SELECT {REPO_CONFIG_COLUMNS} FROM codescan_repo_configs WHERE id = $1");
    let row = sqlx::query_as::<_, RepoConfig>(sqlx::AssertSqlSafe(query))
        .bind(repo_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Configuration not found".to_owned()))?;
    Ok((StatusCode::OK, Json(row)).into_response())
}

/// PUT /codescan/repos/{repo_id} body — all fields optional (partial update).
#[derive(Deserialize, Default)]
struct UpdateRepoRequest {
    enabled: Option<bool>,
    auto_review: Option<bool>,
    review_on_open: Option<bool>,
    review_on_sync: Option<bool>,
    default_categories: Option<serde_json::Value>,
    default_ai_provider: Option<String>,
    ignored_paths: Option<serde_json::Value>,
    custom_rules: Option<serde_json::Value>,
    display_name: Option<String>,
    description: Option<String>,
    credential_id: Option<i64>,
}

/// PUT /codescan/repos/{repo_id} — admin only.
async fn update_repo(
    State(state): State<AppState>,
    _admin: AdminOnly,
    Path(repo_id): Path<i64>,
    ApiJson(body): ApiJson<UpdateRepoRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }

    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM codescan_repo_configs WHERE id = $1")
            .bind(repo_id)
            .fetch_optional(&state.db)
            .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("Configuration not found".to_owned()));
    }

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE codescan_repo_configs SET ");
    {
        let mut set = qb.separated(", ");
        if let Some(v) = body.enabled {
            set.push("enabled = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.auto_review {
            set.push("auto_review = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.review_on_open {
            set.push("review_on_open = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.review_on_sync {
            set.push("review_on_sync = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.default_categories {
            set.push("default_categories = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.default_ai_provider {
            set.push("default_ai_provider = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.ignored_paths {
            set.push("ignored_paths = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.custom_rules {
            set.push("custom_rules = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.display_name {
            set.push("display_name = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.description {
            set.push("description = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.credential_id {
            set.push("credential_id = ");
            set.push_bind_unseparated(v);
        }
        set.push("updated_at = now()");
    }
    qb.push(" WHERE id = ");
    qb.push_bind(repo_id);
    qb.build().execute(&state.db).await?;

    let query = format!("SELECT {REPO_CONFIG_COLUMNS} FROM codescan_repo_configs WHERE id = $1");
    let updated = sqlx::query_as::<_, RepoConfig>(sqlx::AssertSqlSafe(query))
        .bind(repo_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Configuration not found".to_owned()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Configuration updated successfully",
            "config": updated,
        })),
    )
        .into_response())
}

/// DELETE /codescan/repos/{repo_id} — admin only.
async fn delete_repo(
    State(state): State<AppState>,
    _admin: AdminOnly,
    Path(repo_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }

    let result = sqlx::query("DELETE FROM codescan_repo_configs WHERE id = $1")
        .bind(repo_id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("Configuration not found".to_owned()));
    }

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Configuration deleted successfully",
            "deleted": true,
        })),
    )
        .into_response())
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
    fn validate_create_rejects_bad_provider() {
        let body = CreateRepoRequest {
            provider: "bitbucket".to_owned(),
            repo_url: "https://example.com/x".to_owned(),
            repo_name: "x".to_owned(),
            enabled: None,
            auto_review: None,
            review_on_open: None,
            review_on_sync: None,
            default_categories: None,
            default_ai_provider: None,
            ignored_paths: None,
            custom_rules: None,
            display_name: None,
            description: None,
            credential_id: None,
            tenant_id: None,
            team_id: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[test]
    fn validate_create_rejects_empty_repo_name() {
        let body = CreateRepoRequest {
            provider: "github".to_owned(),
            repo_url: "https://github.com/a/b".to_owned(),
            repo_name: "  ".to_owned(),
            enabled: None,
            auto_review: None,
            review_on_open: None,
            review_on_sync: None,
            default_categories: None,
            default_ai_provider: None,
            ignored_paths: None,
            custom_rules: None,
            display_name: None,
            description: None,
            credential_id: None,
            tenant_id: None,
            team_id: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[tokio::test]
    async fn list_and_mutations_require_auth() {
        let server = test_server(AppStateInner::for_tests(dev_license()));
        for resp in [
            server.get("/api/v1/codescan/repos").await,
            server.post("/api/v1/codescan/repos").await,
            server.get("/api/v1/codescan/repos/1").await,
            server.put("/api/v1/codescan/repos/1").await,
            server.delete("/api/v1/codescan/repos/1").await,
        ] {
            resp.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn mutations_require_admin_role() {
        let state = AppStateInner::for_tests(dev_license());
        let token = sign_token(&state, "1", "maintainer");
        let server = test_server(state);
        let resp = server
            .post("/api/v1/codescan/repos")
            .authorization_bearer(&token)
            .json(&serde_json::json!({}))
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = resp.json();
        assert_eq!(body["error"], "Insufficient permissions");
    }
}
