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

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{AdminOnly, CurrentUser};
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
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
const DEFAULT_PER_PAGE: i64 = 20;
const MAX_PER_PAGE: i64 = 100;

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

/// Repo-config row shape returned by list/get/create/update.
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
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
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

const REPO_CONFIG_COLUMNS: &str = "id, tenant_id, team_id, owner_id, provider, repo_url, \
     repo_name, enabled, auto_review, review_on_open, review_on_sync, default_categories, \
     default_ai_provider, ignored_paths, custom_rules, display_name, description, is_active, \
     credential_id, created_at, updated_at";

/// Documentation-only mirror of `list_repos`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RepoListResponse {
    data: Vec<RepoConfig>,
    total: i64,
    page: i64,
    per_page: i64,
}

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    page: Option<i64>,
    per_page: Option<i64>,
}

/// GET /codescan/repos — paginated list of repository configurations.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/repos",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Repository configurations", body = RepoListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_repos(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let (page, per_page) = pagination(q.page, q.per_page);
    let offset = (page - 1) * per_page;

    let query = format!(
        "SELECT {REPO_CONFIG_COLUMNS} FROM codescan_repo_configs \
         WHERE tenant_id = $1 ORDER BY repo_name LIMIT $2 OFFSET $3"
    );
    let items = sqlx::query_as::<_, RepoConfig>(sqlx::AssertSqlSafe(query))
        .bind(user.tenant_id)
        .bind(per_page)
        .bind(offset)
        .fetch_all(&state.db)
        .await?;

    let total: i64 =
        sqlx::query_scalar("SELECT count(*) FROM codescan_repo_configs WHERE tenant_id = $1")
            .bind(user.tenant_id)
            .fetch_one(&state.db)
            .await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "data": items,
            "total": total,
            "page": page,
            "per_page": per_page,
        })),
    )
        .into_response())
}

/// POST /codescan/repos body. Deliberately has NO `tenant_id` field — the
/// pre-tenancy-retrofit version of this struct accepted one directly from
/// the client and stamped it verbatim onto the created row (a live IDOR: any
/// caller could assign an arbitrary tenant to a repo config, or collide with
/// another tenant's data). `tenant_id` is now sourced exclusively from the
/// validated JWT (`CurrentUser::tenant_id`, see `create_repo`) — even if a
/// caller includes a `tenant_id` key in the request JSON, serde silently
/// ignores it (no field to deserialize into), which is exactly the intended
/// behavior per docs/v2-port/tenancy-model.md.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateRepoRequest {
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

/// Documentation-only mirror of `create_repo`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RepoCreateResponse {
    message: String,
    config: RepoConfig,
}

/// POST /codescan/repos — admin only.
#[utoipa::path(
    post,
    path = "/api/v1/codescan/repos",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    request_body = CreateRepoRequest,
    responses(
        (status = 201, description = "Repository configuration created", body = RepoCreateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 409, description = "Repository already configured", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_repo(
    State(state): State<AppState>,
    AdminOnly(user): AdminOnly,
    ApiJson(body): ApiJson<CreateRepoRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    validate_create(&body)?;

    // Scoped to the caller's own tenant: a same-named repo already
    // configured by a *different* tenant must not block this create (nor
    // leak that it exists) — see docs/v2-port/tenancy-model.md §4. The
    // table's `UNIQUE (provider, repo_name)` constraint is still global
    // (unchanged by this pass), so a genuine cross-tenant name collision
    // surfaces as a 500 from the INSERT below rather than this 409 — a
    // pre-existing schema property, not introduced by tenant scoping.
    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM codescan_repo_configs WHERE provider = $1 AND repo_name = $2 \
         AND tenant_id = $3",
    )
    .bind(&body.provider)
    .bind(&body.repo_name)
    .bind(user.tenant_id)
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
        .bind(user.tenant_id)
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
#[utoipa::path(
    get,
    path = "/api/v1/codescan/repos/{repo_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("repo_id" = i64, Path, description = "Repository configuration id")),
    responses(
        (status = 200, description = "Repository configuration", body = RepoConfig),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 404, description = "Configuration not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_repo(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(repo_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let query = format!(
        "SELECT {REPO_CONFIG_COLUMNS} FROM codescan_repo_configs WHERE id = $1 AND tenant_id = $2"
    );
    let row = sqlx::query_as::<_, RepoConfig>(sqlx::AssertSqlSafe(query))
        .bind(repo_id)
        .bind(user.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Configuration not found".to_owned()))?;
    Ok((StatusCode::OK, Json(row)).into_response())
}

/// PUT /codescan/repos/{repo_id} body — all fields optional (partial update).
#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct UpdateRepoRequest {
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

/// Documentation-only mirror of `update_repo`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RepoUpdateResponse {
    message: String,
    config: RepoConfig,
}

/// PUT /codescan/repos/{repo_id} — admin only.
#[utoipa::path(
    put,
    path = "/api/v1/codescan/repos/{repo_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("repo_id" = i64, Path, description = "Repository configuration id")),
    request_body = UpdateRepoRequest,
    responses(
        (status = 200, description = "Repository configuration updated", body = RepoUpdateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Configuration not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_repo(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Path(repo_id): Path<i64>,
    ApiJson(body): ApiJson<UpdateRepoRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }

    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM codescan_repo_configs WHERE id = $1 AND tenant_id = $2")
            .bind(repo_id)
            .bind(admin.tenant_id)
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
    qb.push(" AND tenant_id = ");
    qb.push_bind(admin.tenant_id);
    qb.build().execute(&state.db).await?;

    let query = format!(
        "SELECT {REPO_CONFIG_COLUMNS} FROM codescan_repo_configs WHERE id = $1 AND tenant_id = $2"
    );
    let updated = sqlx::query_as::<_, RepoConfig>(sqlx::AssertSqlSafe(query))
        .bind(repo_id)
        .bind(admin.tenant_id)
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

/// Documentation-only mirror of `delete_repo`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RepoDeleteResponse {
    message: String,
    deleted: bool,
}

/// DELETE /codescan/repos/{repo_id} — admin only.
#[utoipa::path(
    delete,
    path = "/api/v1/codescan/repos/{repo_id}",
    tag = "codescan",
    security(("bearer_jwt" = [])),
    params(("repo_id" = i64, Path, description = "Repository configuration id")),
    responses(
        (status = 200, description = "Repository configuration deleted", body = RepoDeleteResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Configuration not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn delete_repo(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Path(repo_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }

    let result = sqlx::query("DELETE FROM codescan_repo_configs WHERE id = $1 AND tenant_id = $2")
        .bind(repo_id)
        .bind(admin.tenant_id)
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

    #[test]
    fn pagination_defaults_and_clamps() {
        assert_eq!(pagination(None, None), (1, 20));
        assert_eq!(pagination(Some(2), Some(500)), (2, 100));
    }

    fn create_body(repo_name: &str) -> serde_json::Value {
        serde_json::json!({
            "provider": "github",
            "repo_url": format!("https://github.com/a/{repo_name}"),
            "repo_name": repo_name,
        })
    }

    #[tokio::test]
    async fn list_is_empty_against_a_fresh_db() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = sign_token(&state, "1", "viewer");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/repos")
            .authorization_bearer(token)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["total"], 0);
        assert_eq!(body["data"], serde_json::json!([]));
    }

    /// `per_page` is capped and `page` offsets correctly, and tenant
    /// isolation still holds while paginating.
    #[tokio::test]
    async fn list_respects_pagination_bounds() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let other_admin = crate::routes::test_support::sign_token_for_tenant(
            &state,
            "2",
            "admin",
            crate::routes::test_support::OTHER_TENANT_ID,
        );
        let server = test_server(state);

        for i in 0..3 {
            server
                .post("/api/v1/codescan/repos")
                .authorization_bearer(&admin)
                .json(&create_body(&format!("page-repo-{i}")))
                .await
                .assert_status(StatusCode::CREATED);
        }
        // A different tenant's rows must never count toward this tenant's
        // total/page results.
        server
            .post("/api/v1/codescan/repos")
            .authorization_bearer(&other_admin)
            .json(&create_body("other-tenant-repo"))
            .await
            .assert_status(StatusCode::CREATED);

        let default_page = server
            .get("/api/v1/codescan/repos")
            .authorization_bearer(&admin)
            .await;
        default_page.assert_status_ok();
        let default_body: serde_json::Value = default_page.json();
        assert_eq!(default_body["total"], 3);
        assert_eq!(default_body["page"], 1);
        assert_eq!(default_body["per_page"], 20);
        assert_eq!(default_body["data"].as_array().map(Vec::len), Some(3));

        let paged = server
            .get("/api/v1/codescan/repos?page=1&per_page=2")
            .authorization_bearer(&admin)
            .await;
        paged.assert_status_ok();
        let paged_body: serde_json::Value = paged.json();
        assert_eq!(paged_body["total"], 3);
        assert_eq!(paged_body["per_page"], 2);
        assert_eq!(paged_body["data"].as_array().map(Vec::len), Some(2));

        let second_page = server
            .get("/api/v1/codescan/repos?page=2&per_page=2")
            .authorization_bearer(&admin)
            .await;
        second_page.assert_status_ok();
        let second_body: serde_json::Value = second_page.json();
        assert_eq!(second_body["total"], 3);
        assert_eq!(second_body["data"].as_array().map(Vec::len), Some(1));

        // per_page above MAX_PER_PAGE is clamped, not honored verbatim.
        let over_cap = server
            .get("/api/v1/codescan/repos?per_page=500")
            .authorization_bearer(&admin)
            .await;
        over_cap.assert_status_ok();
        assert_eq!(over_cap.json::<serde_json::Value>()["per_page"], 100);
    }

    #[tokio::test]
    async fn create_get_update_delete_round_trip() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        let created = server
            .post("/api/v1/codescan/repos")
            .authorization_bearer(&admin)
            .json(&create_body("roundtrip-repo"))
            .await;
        created.assert_status(StatusCode::CREATED);
        let created_body: serde_json::Value = created.json();
        let repo_id = created_body["config"]["id"].as_i64().unwrap_or_default();
        assert!(repo_id > 0, "expected a positive assigned id");
        assert_eq!(created_body["config"]["repo_name"], "roundtrip-repo");
        assert_eq!(created_body["config"]["enabled"], true);

        let fetched = server
            .get(&format!("/api/v1/codescan/repos/{repo_id}"))
            .authorization_bearer(&admin)
            .await;
        fetched.assert_status_ok();
        let fetched_body: serde_json::Value = fetched.json();
        assert_eq!(fetched_body["repo_name"], "roundtrip-repo");

        let updated = server
            .put(&format!("/api/v1/codescan/repos/{repo_id}"))
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"enabled": false, "display_name": "Round Trip"}))
            .await;
        updated.assert_status_ok();
        let updated_body: serde_json::Value = updated.json();
        assert_eq!(updated_body["config"]["enabled"], false);
        assert_eq!(updated_body["config"]["display_name"], "Round Trip");

        let deleted = server
            .delete(&format!("/api/v1/codescan/repos/{repo_id}"))
            .authorization_bearer(&admin)
            .await;
        deleted.assert_status_ok();
        let deleted_body: serde_json::Value = deleted.json();
        assert_eq!(deleted_body["deleted"], true);

        let missing = server
            .get(&format!("/api/v1/codescan/repos/{repo_id}"))
            .authorization_bearer(&admin)
            .await;
        missing.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_rejects_duplicate_provider_and_repo_name() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        let first = server
            .post("/api/v1/codescan/repos")
            .authorization_bearer(&admin)
            .json(&create_body("dup-repo"))
            .await;
        first.assert_status(StatusCode::CREATED);

        let second = server
            .post("/api/v1/codescan/repos")
            .authorization_bearer(&admin)
            .json(&create_body("dup-repo"))
            .await;
        second.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = second.json();
        assert_eq!(body["error"], "Repository already configured");
    }

    #[tokio::test]
    async fn get_update_delete_404_on_unknown_id() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        server
            .get("/api/v1/codescan/repos/999999")
            .authorization_bearer(&admin)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .put("/api/v1/codescan/repos/999999")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"enabled": false}))
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .delete("/api/v1/codescan/repos/999999")
            .authorization_bearer(&admin)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    /// Regression for the tenancy IDOR this service used to have: a
    /// client-supplied `tenant_id` in the create body must never override
    /// the tenant derived from the caller's JWT. `CreateRepoRequest` no
    /// longer even has a `tenant_id` field, so an extra key in the JSON body
    /// is simply ignored by serde — the created row's tenant must always
    /// equal the token's tenant claim.
    #[tokio::test]
    async fn body_tenant_id_cannot_override_the_jwt_tenant() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        let mut body = create_body("idor-attempt-repo");
        body["tenant_id"] = serde_json::json!(crate::routes::test_support::OTHER_TENANT_ID);

        let created = server
            .post("/api/v1/codescan/repos")
            .authorization_bearer(&admin)
            .json(&body)
            .await;
        created.assert_status(StatusCode::CREATED);
        let created_body: serde_json::Value = created.json();
        assert_eq!(
            created_body["config"]["tenant_id"],
            crate::routes::test_support::TEST_TENANT_ID,
            "tenant_id must come from the JWT, never the request body"
        );
    }

    /// Tenant A cannot list, read, update, or delete tenant B's repo
    /// configs — the core cross-tenant-isolation invariant this retrofit
    /// exists to establish.
    #[tokio::test]
    async fn tenant_a_cannot_access_tenant_b_repo_configs() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin_a = sign_token(&state, "1", "admin");
        let admin_b = crate::routes::test_support::sign_token_for_tenant(
            &state,
            "2",
            "admin",
            crate::routes::test_support::OTHER_TENANT_ID,
        );
        let server = test_server(state);

        let created = server
            .post("/api/v1/codescan/repos")
            .authorization_bearer(&admin_b)
            .json(&create_body("tenant-b-repo"))
            .await;
        created.assert_status(StatusCode::CREATED);
        let repo_id = created.json::<serde_json::Value>()["config"]["id"]
            .as_i64()
            .unwrap_or_default();

        // Tenant A's list never sees tenant B's row.
        let listed = server
            .get("/api/v1/codescan/repos")
            .authorization_bearer(&admin_a)
            .await;
        listed.assert_status_ok();
        assert_eq!(listed.json::<serde_json::Value>()["total"], 0);

        // Tenant A's direct GET/PUT/DELETE by id all 404, not 200/403 — this
        // must not leak that the row exists under a different tenant.
        server
            .get(&format!("/api/v1/codescan/repos/{repo_id}"))
            .authorization_bearer(&admin_a)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .put(&format!("/api/v1/codescan/repos/{repo_id}"))
            .authorization_bearer(&admin_a)
            .json(&serde_json::json!({"enabled": false}))
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .delete(&format!("/api/v1/codescan/repos/{repo_id}"))
            .authorization_bearer(&admin_a)
            .await
            .assert_status(StatusCode::NOT_FOUND);

        // Tenant B can still see its own row, proving the 404s above are
        // tenant-scoped rejections, not a broken query.
        server
            .get(&format!("/api/v1/codescan/repos/{repo_id}"))
            .authorization_bearer(&admin_b)
            .await
            .assert_status_ok();
    }
}
