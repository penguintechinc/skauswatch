//! /api/v1/credentials — git credential CRUD. Port of
//! `darwin/services/flask-backend/app/api/v1/credentials.py`, reshaped onto
//! the *actual* `codescan_git_credentials` columns
//! (`darwin/services/flask-backend/app/db_schema.py`) rather than the v1
//! PyDAL model in `app/models.py::store_credential`, which had drifted from
//! that schema (different column names entirely — `name`/`git_url_pattern`/
//! `encrypted_credential` vs. the live `user_id`/`platform`/
//! `credential_type`/`encrypted_token`). Admin-only, matching v1.
//!
//! Tokens are encrypted at rest with AES-256-GCM
//! (`skauswatch_vault::CredentialCipher`) and are
//! NEVER returned in a response body or written to a log line — every
//! response shape below omits `encrypted_token` entirely.
//!
//! Not yet proxied by the manager (services/manager/src/routes/codescan.rs
//! only forwards `/codescan/{status,repos,reviews,plans}`); this surface is
//! reachable directly today and is a tracked follow-up for the manager
//! proxy contract.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::AdminOnly;
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

// NOTE: `codescan_git_credentials` is keyed by `user_id`, not directly by
// tenant (docs/v2-port/tenancy-model.md §5) — `tenant_id` is denormalized
// from the owning user for tenant-scoped listing/audit without a join on
// every query, and every query below filters on it, but the authoritative
// ownership boundary stays `user_id`.

const VALID_PLATFORMS: [&str; 2] = ["github", "gitlab"];
const VALID_CREDENTIAL_TYPES: [&str; 2] = ["token", "ssh_key"];
const DEFAULT_PER_PAGE: i64 = 20;
const MAX_PER_PAGE: i64 = 100;

/// Router for /api/v1/credentials.
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/credentials",
            get(list_credentials).post(create_credential),
        )
        .route("/credentials/test", post(test_credential))
        .route(
            "/credentials/{credential_id}",
            get(get_credential)
                .patch(update_credential)
                .delete(delete_credential),
        )
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

/// Response shape — deliberately excludes `encrypted_token`.
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct CredentialSummary {
    id: i64,
    user_id: i64,
    name: Option<String>,
    platform: String,
    credential_type: String,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    token_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    is_active: bool,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

const SUMMARY_COLUMNS: &str = "id, user_id, name, platform, credential_type, token_expires_at, \
     is_active, created_at, updated_at";

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    platform: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

/// Documentation-only mirror of `list_credentials`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CredentialListResponse {
    data: Vec<CredentialSummary>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// GET /credentials — admin only, paginated; never includes token material.
#[utoipa::path(
    get,
    path = "/api/v1/credentials",
    tag = "credentials",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Git credential summaries (no token material)", body = CredentialListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_credentials(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let (page, per_page) = pagination(q.page, q.per_page);
    let offset = (page - 1) * per_page;

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
        "SELECT {SUMMARY_COLUMNS} FROM codescan_git_credentials WHERE tenant_id = "
    ));
    qb.push_bind(admin.tenant_id);
    if let Some(platform) = &q.platform {
        qb.push(" AND platform = ").push_bind(platform.clone());
    }
    qb.push(" ORDER BY created_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let items = qb
        .build_query_as::<CredentialSummary>()
        .fetch_all(&state.db)
        .await?;

    let mut count_qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT count(*) FROM codescan_git_credentials WHERE tenant_id = ",
    );
    count_qb.push_bind(admin.tenant_id);
    if let Some(platform) = &q.platform {
        count_qb
            .push(" AND platform = ")
            .push_bind(platform.clone());
    }
    let total: i64 = count_qb.build_query_scalar().fetch_one(&state.db).await?;

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

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateCredentialRequest {
    platform: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default = "default_credential_type")]
    credential_type: String,
    token: String,
    #[serde(default)]
    token_expires_at: Option<chrono::NaiveDateTime>,
}

fn default_credential_type() -> String {
    "token".to_owned()
}

fn validate_create(body: &CreateCredentialRequest) -> Result<(), ApiError> {
    if !VALID_PLATFORMS.contains(&body.platform.as_str()) {
        return Err(validation(
            "platform",
            "Input should be 'github' or 'gitlab'",
        ));
    }
    if !VALID_CREDENTIAL_TYPES.contains(&body.credential_type.as_str()) {
        return Err(validation(
            "credential_type",
            "Input should be 'token' or 'ssh_key'",
        ));
    }
    if body.token.trim().is_empty() {
        return Err(validation("token", "token is required"));
    }
    Ok(())
}

/// Documentation-only mirror of `create_credential`'s `serde_json::json!`
/// body — never includes token material.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CredentialCreateResponse {
    message: String,
    credential: CredentialSummary,
}

/// POST /credentials — admin only. `token` is encrypted before storage and
/// never echoed back.
#[utoipa::path(
    post,
    path = "/api/v1/credentials",
    tag = "credentials",
    security(("bearer_jwt" = [])),
    request_body = CreateCredentialRequest,
    responses(
        (status = 201, description = "Credential created", body = CredentialCreateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_credential(
    State(state): State<AppState>,
    AdminOnly(user): AdminOnly,
    ApiJson(body): ApiJson<CreateCredentialRequest>,
) -> Result<Response, ApiError> {
    validate_create(&body)?;

    let encrypted = state
        .crypto
        .encrypt(&body.token)
        .map_err(|e| ApiError::internal("credential encrypt", e))?;

    let query = format!(
        "INSERT INTO codescan_git_credentials \
         (user_id, tenant_id, name, platform, credential_type, encrypted_token, token_expires_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,now()) RETURNING {SUMMARY_COLUMNS}"
    );
    let created = sqlx::query_as::<_, CredentialSummary>(sqlx::AssertSqlSafe(query))
        .bind(user.id)
        .bind(user.tenant_id)
        .bind(&body.name)
        .bind(&body.platform)
        .bind(&body.credential_type)
        .bind(&encrypted)
        .bind(body.token_expires_at)
        .fetch_one(&state.db)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Credential created successfully",
            "credential": created,
        })),
    )
        .into_response())
}

/// GET /credentials/{id} — admin only.
#[utoipa::path(
    get,
    path = "/api/v1/credentials/{credential_id}",
    tag = "credentials",
    security(("bearer_jwt" = [])),
    params(("credential_id" = i64, Path, description = "Credential id")),
    responses(
        (status = 200, description = "Credential summary (no token material)", body = CredentialSummary),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Credential not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_credential(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Path(credential_id): Path<i64>,
) -> Result<Response, ApiError> {
    let query = format!(
        "SELECT {SUMMARY_COLUMNS} FROM codescan_git_credentials WHERE id = $1 AND tenant_id = $2"
    );
    let row = sqlx::query_as::<_, CredentialSummary>(sqlx::AssertSqlSafe(query))
        .bind(credential_id)
        .bind(admin.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Credential not found".to_owned()))?;
    Ok((StatusCode::OK, Json(row)).into_response())
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct UpdateCredentialRequest {
    name: Option<String>,
    token: Option<String>,
    is_active: Option<bool>,
    token_expires_at: Option<chrono::NaiveDateTime>,
}

/// Documentation-only mirror of `update_credential`'s `serde_json::json!`
/// body — never includes token material.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CredentialUpdateResponse {
    message: String,
    credential: CredentialSummary,
}

/// PATCH /credentials/{id} — admin only. A `token` field re-encrypts and
/// replaces the stored value; the plaintext is never echoed back.
#[utoipa::path(
    patch,
    path = "/api/v1/credentials/{credential_id}",
    tag = "credentials",
    security(("bearer_jwt" = [])),
    params(("credential_id" = i64, Path, description = "Credential id")),
    request_body = UpdateCredentialRequest,
    responses(
        (status = 200, description = "Credential updated", body = CredentialUpdateResponse),
        (status = 400, description = "Validation error (e.g. blank token)", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Credential not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_credential(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Path(credential_id): Path<i64>,
    ApiJson(body): ApiJson<UpdateCredentialRequest>,
) -> Result<Response, ApiError> {
    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM codescan_git_credentials WHERE id = $1 AND tenant_id = $2")
            .bind(credential_id)
            .bind(admin.tenant_id)
            .fetch_optional(&state.db)
            .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("Credential not found".to_owned()));
    }

    let encrypted_token = match &body.token {
        Some(t) if !t.trim().is_empty() => Some(
            state
                .crypto
                .encrypt(t)
                .map_err(|e| ApiError::internal("credential encrypt", e))?,
        ),
        Some(_) => return Err(validation("token", "token must not be empty")),
        None => None,
    };

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE codescan_git_credentials SET ");
    {
        let mut set = qb.separated(", ");
        if let Some(v) = &body.name {
            set.push("name = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = encrypted_token {
            set.push("encrypted_token = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.is_active {
            set.push("is_active = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = body.token_expires_at {
            set.push("token_expires_at = ");
            set.push_bind_unseparated(v);
        }
        set.push("updated_at = now()");
    }
    qb.push(" WHERE id = ").push_bind(credential_id);
    qb.push(" AND tenant_id = ").push_bind(admin.tenant_id);
    qb.build().execute(&state.db).await?;

    let query = format!(
        "SELECT {SUMMARY_COLUMNS} FROM codescan_git_credentials WHERE id = $1 AND tenant_id = $2"
    );
    let updated = sqlx::query_as::<_, CredentialSummary>(sqlx::AssertSqlSafe(query))
        .bind(credential_id)
        .bind(admin.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Credential not found".to_owned()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Credential updated successfully",
            "credential": updated,
        })),
    )
        .into_response())
}

/// Documentation-only mirror of `delete_credential`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct CredentialDeleteResponse {
    message: String,
    deleted: bool,
}

/// DELETE /credentials/{id} — admin only.
#[utoipa::path(
    delete,
    path = "/api/v1/credentials/{credential_id}",
    tag = "credentials",
    security(("bearer_jwt" = [])),
    params(("credential_id" = i64, Path, description = "Credential id")),
    responses(
        (status = 200, description = "Credential deleted", body = CredentialDeleteResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Credential not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn delete_credential(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Path(credential_id): Path<i64>,
) -> Result<Response, ApiError> {
    let result =
        sqlx::query("DELETE FROM codescan_git_credentials WHERE id = $1 AND tenant_id = $2")
            .bind(credential_id)
            .bind(admin.tenant_id)
            .execute(&state.db)
            .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("Credential not found".to_owned()));
    }
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Credential deleted successfully",
            "deleted": true,
        })),
    )
        .into_response())
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct TestCredentialRequest {
    credential_type: String,
    credential: String,
}

/// Documentation-only mirror of `test_credential`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TestCredentialResponse {
    valid: bool,
    message: String,
    #[serde(rename = "type")]
    credential_type: String,
}

/// POST /credentials/test — admin only; validates *format* only (no
/// connectivity check, no persistence), matching v1.
#[utoipa::path(
    post,
    path = "/api/v1/credentials/test",
    tag = "credentials",
    security(("bearer_jwt" = [])),
    request_body = TestCredentialRequest,
    responses(
        (status = 200, description = "Credential format looks valid", body = TestCredentialResponse),
        (status = 400, description = "Credential format is invalid, or validation error", body = TestCredentialResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn test_credential(
    _admin: AdminOnly,
    ApiJson(body): ApiJson<TestCredentialRequest>,
) -> Result<Response, ApiError> {
    if !VALID_CREDENTIAL_TYPES.contains(&body.credential_type.as_str()) {
        return Err(validation(
            "credential_type",
            "Input should be 'token' or 'ssh_key'",
        ));
    }
    if body.credential.is_empty() {
        return Err(validation("credential", "credential is required"));
    }

    let (valid, message) = match body.credential_type.as_str() {
        "token" if body.credential.len() < 10 => {
            (false, "Token appears to be too short".to_owned())
        }
        "token" => (true, "Token format looks valid".to_owned()),
        _ if !body.credential.starts_with("-----BEGIN") => (
            false,
            "SSH key does not appear to be in PEM format".to_owned(),
        ),
        _ => (true, "SSH key format looks valid".to_owned()),
    };

    let status = if valid {
        StatusCode::OK
    } else {
        StatusCode::BAD_REQUEST
    };
    Ok((
        status,
        Json(serde_json::json!({
            "valid": valid,
            "message": message,
            "type": body.credential_type,
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
    fn validate_create_rejects_bad_platform() {
        let body = CreateCredentialRequest {
            platform: "bitbucket".to_owned(),
            name: None,
            credential_type: default_credential_type(),
            token: "sometoken123".to_owned(),
            token_expires_at: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[test]
    fn validate_create_rejects_empty_token() {
        let body = CreateCredentialRequest {
            platform: "github".to_owned(),
            name: None,
            credential_type: default_credential_type(),
            token: String::new(),
            token_expires_at: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[tokio::test]
    async fn all_credential_routes_require_auth() {
        let server = test_server(AppStateInner::for_tests(dev_license()));
        for resp in [
            server.get("/api/v1/credentials").await,
            server.post("/api/v1/credentials").await,
            server.get("/api/v1/credentials/1").await,
            server.patch("/api/v1/credentials/1").await,
            server.delete("/api/v1/credentials/1").await,
            server.post("/api/v1/credentials/test").await,
        ] {
            resp.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn non_admin_roles_are_forbidden() {
        for role in ["maintainer", "viewer"] {
            let state = AppStateInner::for_tests(dev_license());
            let token = sign_token(&state, "1", role);
            let server = test_server(state);
            let resp = server
                .get("/api/v1/credentials")
                .authorization_bearer(&token)
                .await;
            resp.assert_status(StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn test_credential_validates_token_format_without_db() {
        let state = AppStateInner::for_tests(dev_license());
        let token = sign_token(&state, "1", "admin");
        let server = test_server(state);

        let short = server
            .post("/api/v1/credentials/test")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"credential_type": "token", "credential": "short"}))
            .await;
        short.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = short.json();
        assert_eq!(body["valid"], false);

        let ok = server
            .post("/api/v1/credentials/test")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"credential_type": "token", "credential": "ghp_1234567890"}))
            .await;
        ok.assert_status_ok();
        let body: serde_json::Value = ok.json();
        assert_eq!(body["valid"], true);
    }

    #[tokio::test]
    async fn test_credential_rejects_bad_ssh_key_format() {
        let state = AppStateInner::for_tests(dev_license());
        let token = sign_token(&state, "1", "admin");
        let server = test_server(state);
        let resp = server
            .post("/api/v1/credentials/test")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"credential_type": "ssh_key", "credential": "not-a-key"}))
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = resp.json();
        assert_eq!(body["valid"], false);
    }

    #[test]
    fn pagination_defaults_and_clamps() {
        assert_eq!(pagination(None, None), (1, 20));
        assert_eq!(pagination(Some(2), Some(500)), (2, 100));
    }

    #[tokio::test]
    async fn list_is_empty_against_a_fresh_db() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let token = sign_token(&state, "1", "admin");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/credentials")
            .authorization_bearer(token)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["total"], 0);
    }

    #[tokio::test]
    async fn list_respects_pagination_bounds() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        for i in 0..3 {
            server
                .post("/api/v1/credentials")
                .authorization_bearer(&admin)
                .json(&serde_json::json!({
                    "platform": "github",
                    "token": format!("ghp_pagetoken{i}aaaaaaaa"),
                }))
                .await
                .assert_status(StatusCode::CREATED);
        }

        let paged = server
            .get("/api/v1/credentials?page=1&per_page=2")
            .authorization_bearer(&admin)
            .await;
        paged.assert_status_ok();
        let paged_body: serde_json::Value = paged.json();
        assert_eq!(paged_body["total"], 3);
        assert_eq!(paged_body["per_page"], 2);
        assert_eq!(paged_body["data"].as_array().map(Vec::len), Some(2));

        let second_page = server
            .get("/api/v1/credentials?page=2&per_page=2")
            .authorization_bearer(&admin)
            .await;
        second_page.assert_status_ok();
        assert_eq!(
            second_page.json::<serde_json::Value>()["data"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );

        let over_cap = server
            .get("/api/v1/credentials?per_page=500")
            .authorization_bearer(&admin)
            .await;
        over_cap.assert_status_ok();
        assert_eq!(over_cap.json::<serde_json::Value>()["per_page"], 100);
    }

    #[tokio::test]
    async fn create_get_update_delete_round_trip_never_echoes_the_token() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        let created = server
            .post("/api/v1/credentials")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({
                "platform": "github",
                "name": "ci-bot",
                "token": "ghp_supersecrettoken1234",
            }))
            .await;
        created.assert_status(StatusCode::CREATED);
        let created_body: serde_json::Value = created.json();
        assert!(created_body["credential"].get("encrypted_token").is_none());
        assert_eq!(created_body["credential"]["name"], "ci-bot");
        let credential_id = created_body["credential"]["id"]
            .as_i64()
            .unwrap_or_default();
        assert!(credential_id > 0);

        let fetched = server
            .get(&format!("/api/v1/credentials/{credential_id}"))
            .authorization_bearer(&admin)
            .await;
        fetched.assert_status_ok();
        let fetched_body: serde_json::Value = fetched.json();
        assert!(fetched_body.get("encrypted_token").is_none());

        let updated = server
            .patch(&format!("/api/v1/credentials/{credential_id}"))
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"name": "ci-bot-renamed", "token": "ghp_newtoken5678"}))
            .await;
        updated.assert_status_ok();
        let updated_body: serde_json::Value = updated.json();
        assert_eq!(updated_body["credential"]["name"], "ci-bot-renamed");
        assert!(updated_body["credential"].get("encrypted_token").is_none());

        let deleted = server
            .delete(&format!("/api/v1/credentials/{credential_id}"))
            .authorization_bearer(&admin)
            .await;
        deleted.assert_status_ok();

        server
            .get(&format!("/api/v1/credentials/{credential_id}"))
            .authorization_bearer(&admin)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_rejects_blank_token() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        let created = server
            .post("/api/v1/credentials")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"platform": "gitlab", "token": "glpat-abcdef1234"}))
            .await;
        created.assert_status(StatusCode::CREATED);
        let created_body: serde_json::Value = created.json();
        let credential_id = created_body["credential"]["id"]
            .as_i64()
            .unwrap_or_default();

        let resp = server
            .patch(&format!("/api/v1/credentials/{credential_id}"))
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"token": "   "}))
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn get_update_delete_404_on_unknown_id() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        server
            .get("/api/v1/credentials/999999")
            .authorization_bearer(&admin)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .patch("/api/v1/credentials/999999")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"name": "x"}))
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .delete("/api/v1/credentials/999999")
            .authorization_bearer(&admin)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_filters_by_platform() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        server
            .post("/api/v1/credentials")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"platform": "github", "token": "ghp_aaaaaaaaaa"}))
            .await
            .assert_status(StatusCode::CREATED);
        server
            .post("/api/v1/credentials")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"platform": "gitlab", "token": "glpat-bbbbbbbbbb"}))
            .await
            .assert_status(StatusCode::CREATED);

        let resp = server
            .get("/api/v1/credentials?platform=gitlab")
            .authorization_bearer(&admin)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["total"], 1);
        assert_eq!(body["data"][0]["platform"], "gitlab");
    }

    /// Tenant A's admin cannot list, read, update, or delete tenant B's git
    /// credentials — even though this table is keyed by `user_id`, tenant
    /// scoping is a separate, mandatory boundary on top of it (see the
    /// module-level NOTE at the top of this file).
    #[tokio::test]
    async fn tenant_a_cannot_access_tenant_b_credentials() {
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
            .post("/api/v1/credentials")
            .authorization_bearer(&admin_b)
            .json(&serde_json::json!({"platform": "github", "token": "ghp_tenantbtoken123"}))
            .await;
        created.assert_status(StatusCode::CREATED);
        let credential_id = created.json::<serde_json::Value>()["credential"]["id"]
            .as_i64()
            .unwrap_or_default();

        let listed = server
            .get("/api/v1/credentials")
            .authorization_bearer(&admin_a)
            .await;
        listed.assert_status_ok();
        assert_eq!(listed.json::<serde_json::Value>()["total"], 0);

        server
            .get(&format!("/api/v1/credentials/{credential_id}"))
            .authorization_bearer(&admin_a)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .patch(&format!("/api/v1/credentials/{credential_id}"))
            .authorization_bearer(&admin_a)
            .json(&serde_json::json!({"name": "hijacked"}))
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .delete(&format!("/api/v1/credentials/{credential_id}"))
            .authorization_bearer(&admin_a)
            .await
            .assert_status(StatusCode::NOT_FOUND);

        // Tenant B still has it — proves the 404s above are tenant-scoped
        // rejections, not accidental deletion/corruption.
        server
            .get(&format!("/api/v1/credentials/{credential_id}"))
            .authorization_bearer(&admin_b)
            .await
            .assert_status_ok();
    }
}
