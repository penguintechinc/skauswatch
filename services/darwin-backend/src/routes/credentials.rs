//! /api/v1/credentials — git credential CRUD. Port of
//! `darwin/services/flask-backend/app/api/v1/credentials.py`, reshaped onto
//! the *actual* `darwin_git_credentials` columns
//! (`darwin/services/flask-backend/app/db_schema.py`) rather than the v1
//! PyDAL model in `app/models.py::store_credential`, which had drifted from
//! that schema (different column names entirely — `name`/`git_url_pattern`/
//! `encrypted_credential` vs. the live `user_id`/`platform`/
//! `credential_type`/`encrypted_token`). Admin-only, matching v1.
//!
//! Tokens are encrypted at rest with AES-256-GCM (`crate::crypto`) and are
//! NEVER returned in a response body or written to a log line — every
//! response shape below omits `encrypted_token` entirely.
//!
//! Not yet proxied by the manager (services/manager/src/routes/darwin.rs
//! only forwards `/darwin/{status,repos,reviews,plans}`); this surface is
//! reachable directly today and is a tracked follow-up for the manager
//! proxy contract.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::AdminOnly;
use crate::error::{ApiError, ApiJson};
use crate::state::AppState;

const VALID_PLATFORMS: [&str; 2] = ["github", "gitlab"];
const VALID_CREDENTIAL_TYPES: [&str; 2] = ["token", "ssh_key"];

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

/// Response shape — deliberately excludes `encrypted_token`.
#[derive(sqlx::FromRow, Serialize)]
struct CredentialSummary {
    id: i64,
    user_id: i64,
    name: Option<String>,
    platform: String,
    credential_type: String,
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    token_expires_at: Option<chrono::NaiveDateTime>,
    is_active: bool,
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    created_at: Option<chrono::NaiveDateTime>,
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    updated_at: Option<chrono::NaiveDateTime>,
}

const SUMMARY_COLUMNS: &str = "id, user_id, name, platform, credential_type, token_expires_at, \
     is_active, created_at, updated_at";

#[derive(Deserialize)]
struct ListQuery {
    platform: Option<String>,
}

/// GET /credentials — admin only; never includes token material.
async fn list_credentials(
    State(state): State<AppState>,
    _admin: AdminOnly,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
        "SELECT {SUMMARY_COLUMNS} FROM darwin_git_credentials WHERE 1=1"
    ));
    if let Some(platform) = &q.platform {
        qb.push(" AND platform = ").push_bind(platform.clone());
    }
    qb.push(" ORDER BY created_at DESC");
    let items = qb
        .build_query_as::<CredentialSummary>()
        .fetch_all(&state.db)
        .await?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "data": items, "total": items.len() })),
    )
        .into_response())
}

#[derive(Deserialize)]
struct CreateCredentialRequest {
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

/// POST /credentials — admin only. `token` is encrypted before storage and
/// never echoed back.
async fn create_credential(
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
        "INSERT INTO darwin_git_credentials \
         (user_id, name, platform, credential_type, encrypted_token, token_expires_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,now()) RETURNING {SUMMARY_COLUMNS}"
    );
    let created = sqlx::query_as::<_, CredentialSummary>(sqlx::AssertSqlSafe(query))
        .bind(user.id)
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
async fn get_credential(
    State(state): State<AppState>,
    _admin: AdminOnly,
    Path(credential_id): Path<i64>,
) -> Result<Response, ApiError> {
    let query = format!("SELECT {SUMMARY_COLUMNS} FROM darwin_git_credentials WHERE id = $1");
    let row = sqlx::query_as::<_, CredentialSummary>(sqlx::AssertSqlSafe(query))
        .bind(credential_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Credential not found".to_owned()))?;
    Ok((StatusCode::OK, Json(row)).into_response())
}

#[derive(Deserialize, Default)]
struct UpdateCredentialRequest {
    name: Option<String>,
    token: Option<String>,
    is_active: Option<bool>,
    token_expires_at: Option<chrono::NaiveDateTime>,
}

/// PATCH /credentials/{id} — admin only. A `token` field re-encrypts and
/// replaces the stored value; the plaintext is never echoed back.
async fn update_credential(
    State(state): State<AppState>,
    _admin: AdminOnly,
    Path(credential_id): Path<i64>,
    ApiJson(body): ApiJson<UpdateCredentialRequest>,
) -> Result<Response, ApiError> {
    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM darwin_git_credentials WHERE id = $1")
            .bind(credential_id)
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

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE darwin_git_credentials SET ");
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
    qb.build().execute(&state.db).await?;

    let query = format!("SELECT {SUMMARY_COLUMNS} FROM darwin_git_credentials WHERE id = $1");
    let updated = sqlx::query_as::<_, CredentialSummary>(sqlx::AssertSqlSafe(query))
        .bind(credential_id)
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

/// DELETE /credentials/{id} — admin only.
async fn delete_credential(
    State(state): State<AppState>,
    _admin: AdminOnly,
    Path(credential_id): Path<i64>,
) -> Result<Response, ApiError> {
    let result = sqlx::query("DELETE FROM darwin_git_credentials WHERE id = $1")
        .bind(credential_id)
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

#[derive(Deserialize)]
struct TestCredentialRequest {
    credential_type: String,
    credential: String,
}

/// POST /credentials/test — admin only; validates *format* only (no
/// connectivity check, no persistence), matching v1.
async fn test_credential(
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
}
