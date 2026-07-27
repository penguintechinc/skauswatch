//! `/api/v1/secrets` — CRUD for envelope-encrypted secrets, versioning, and
//! plaintext retrieval. Rust port of
//! `icebox/services/flask-backend/api/v1/secrets.py`.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::types::Json as SqlxJson;
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::routes::audit::write_audit;
use crate::routes::jit::validate_jit_token;
use crate::state::AppState;

/// Secret types accepted by `POST /secrets` — matches v1 `valid_types`.
const VALID_SECRET_TYPES: &[&str] = &[
    "api_key",
    "db_password",
    "token",
    "cloud_credential",
    "service_account",
    "certificate",
    "ssh_key",
];

/// Router for `/api/v1/secrets`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/secrets", get(list_secrets).post(create_secret))
        .route(
            "/secrets/{id}",
            get(get_secret).put(update_secret).delete(delete_secret),
        )
        .route("/secrets/{id}/value", get(get_secret_value))
        .route("/secrets/{id}/versions", get(list_secret_versions))
        .route("/secrets/{id}/rotate", post(rotate_secret))
}

#[derive(sqlx::FromRow)]
struct SecretRow {
    id: String,
    name: String,
    description: Option<String>,
    secret_type: String,
    tags: Option<SqlxJson<Value>>,
    expires_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
    created_by: Option<String>,
}

impl SecretRow {
    /// v1 `_secret_to_dict` — never includes the encrypted fields.
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "secret_type": self.secret_type,
            "tags": self.tags.as_ref().map(|j| j.0.clone()),
            "expires_at": self.expires_at.map(skauswatch_streams::py_isoformat),
            "created_at": skauswatch_streams::py_isoformat(self.created_at),
            "updated_at": skauswatch_streams::py_isoformat(self.updated_at),
            "created_by": self.created_by,
        })
    }
}

#[derive(Deserialize)]
struct ListQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    #[serde(rename = "type")]
    secret_type: Option<String>,
}

async fn list_secrets(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:read")?;

    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let (rows, total) = match &q.secret_type {
        Some(t) => {
            let rows = sqlx::query_as::<_, SecretRow>(
                "SELECT id, name, description, secret_type, tags, expires_at, created_at, \
                 updated_at, created_by FROM icebox_secrets WHERE secret_type = $1 \
                 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(t)
            .bind(per_page)
            .bind(offset)
            .fetch_all(&state.db)
            .await?;
            let total: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM icebox_secrets WHERE secret_type = $1")
                    .bind(t)
                    .fetch_one(&state.db)
                    .await?;
            (rows, total)
        }
        None => {
            let rows = sqlx::query_as::<_, SecretRow>(
                "SELECT id, name, description, secret_type, tags, expires_at, created_at, \
                 updated_at, created_by FROM icebox_secrets \
                 ORDER BY created_at DESC LIMIT $1 OFFSET $2",
            )
            .bind(per_page)
            .bind(offset)
            .fetch_all(&state.db)
            .await?;
            let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM icebox_secrets")
                .fetch_one(&state.db)
                .await?;
            (rows, total)
        }
    };

    Ok(Json(json!({
        "secrets": rows.iter().map(SecretRow::to_json).collect::<Vec<_>>(),
        "total": total,
        "page": page,
        "per_page": per_page,
    })))
}

#[derive(Deserialize)]
struct CreateSecretBody {
    name: Option<String>,
    value: Option<String>,
    #[serde(rename = "type")]
    secret_type: Option<String>,
    description: Option<String>,
    tags: Option<Value>,
    metadata: Option<Value>,
    expires_at: Option<NaiveDateTime>,
}

async fn create_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Json(body): Json<CreateSecretBody>,
) -> Result<(axum::http::StatusCode, Json<Value>), ApiError> {
    user.require_scope("secrets:write")?;

    let name = body.name.unwrap_or_default().trim().to_owned();
    let value = body.value.unwrap_or_default().trim().to_owned();
    if name.is_empty() || value.is_empty() {
        return Err(ApiError::BadRequest(
            "name and value are required".to_owned(),
        ));
    }
    let secret_type = body.secret_type.unwrap_or_else(|| "api_key".to_owned());
    if !VALID_SECRET_TYPES.contains(&secret_type.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "Invalid type. Must be one of: {}",
            VALID_SECRET_TYPES.join(", ")
        )));
    }

    let (encrypted_value, encrypted_dek, dek_version) =
        state.envelope.read().await.encrypt(&value)?;
    let secret_id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();

    sqlx::query(
        "INSERT INTO icebox_secrets (id, name, description, secret_type, encrypted_value, \
         encrypted_dek, dek_version, tags, secret_metadata, expires_at, created_at, \
         updated_at, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(&secret_id)
    .bind(&name)
    .bind(body.description.unwrap_or_default())
    .bind(&secret_type)
    .bind(&encrypted_value)
    .bind(&encrypted_dek)
    .bind(dek_version as i32)
    .bind(body.tags.map(SqlxJson))
    .bind(body.metadata.map(SqlxJson))
    .bind(body.expires_at)
    .bind(now)
    .bind(now)
    .bind(&user.user_id)
    .execute(&state.db)
    .await?;

    sqlx::query(
        "INSERT INTO icebox_secret_versions (id, secret_id, version_number, encrypted_value, \
         encrypted_dek, dek_version, created_by, created_at) VALUES ($1,$2,1,$3,$4,$5,$6,$7)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&secret_id)
    .bind(&encrypted_value)
    .bind(&encrypted_dek)
    .bind(dek_version as i32)
    .bind(&user.user_id)
    .bind(now)
    .execute(&state.db)
    .await?;

    sqlx::query(
        "INSERT INTO icebox_secret_owners (secret_id, owner_type, owner_id) VALUES ($1,'user',$2)",
    )
    .bind(&secret_id)
    .bind(&user.user_id)
    .execute(&state.db)
    .await?;

    write_audit(&state, &user.user_id, "secret.create", &secret_id, &headers).await;

    let secret = fetch_secret(&state, &secret_id)
        .await?
        .ok_or_else(|| ApiError::internal("create_secret", "row vanished after insert"))?;
    Ok((axum::http::StatusCode::CREATED, Json(secret.to_json())))
}

async fn fetch_secret(state: &AppState, id: &str) -> Result<Option<SecretRow>, ApiError> {
    Ok(sqlx::query_as::<_, SecretRow>(
        "SELECT id, name, description, secret_type, tags, expires_at, created_at, updated_at, \
         created_by FROM icebox_secrets WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?)
}

async fn get_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:read")?;
    let secret = fetch_secret(&state, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Not found".to_owned()))?;
    Ok(Json(secret.to_json()))
}

#[derive(Deserialize, Default)]
struct UpdateSecretBody {
    name: Option<String>,
    description: Option<String>,
    tags: Option<Value>,
    expires_at: Option<NaiveDateTime>,
    metadata: Option<Value>,
}

async fn update_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<UpdateSecretBody>>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:write")?;
    if fetch_secret(&state, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let now = Utc::now().naive_utc();

    sqlx::query(
        "UPDATE icebox_secrets SET \
         name = COALESCE($1, name), \
         description = COALESCE($2, description), \
         tags = COALESCE($3, tags), \
         expires_at = COALESCE($4, expires_at), \
         secret_metadata = COALESCE($5, secret_metadata), \
         updated_at = $6 \
         WHERE id = $7",
    )
    .bind(body.name.as_deref().map(str::trim))
    .bind(body.description)
    .bind(body.tags.map(SqlxJson))
    .bind(body.expires_at)
    .bind(body.metadata.map(SqlxJson))
    .bind(now)
    .bind(&id)
    .execute(&state.db)
    .await?;

    write_audit(&state, &user.user_id, "secret.update", &id, &headers).await;

    let secret = fetch_secret(&state, &id)
        .await?
        .ok_or_else(|| ApiError::internal("update_secret", "row vanished after update"))?;
    Ok(Json(secret.to_json()))
}

async fn delete_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    user.require_scope("secrets:delete")?;
    if fetch_secret(&state, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    write_audit(&state, &user.user_id, "secret.delete", &id, &headers).await;
    sqlx::query("DELETE FROM icebox_secrets WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[derive(sqlx::FromRow)]
struct EncryptedValueRow {
    encrypted_value: String,
    encrypted_dek: String,
    dek_version: i32,
    name: String,
}

/// GET /secrets/{id}/value — accepts a JIT token OR a standard bearer JWT
/// with `secrets:read` (v1 does not use the `CurrentUser` extractor here
/// because it must try the JIT-token path first).
async fn get_secret_value(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("Authorization required".to_owned()))?
        .trim();

    let actor_id = match validate_jit_token(&state, token, &id).await {
        Some(grantee_id) => grantee_id,
        None => {
            let user = crate::auth::decode_bearer(token, &state.auth.jwt_secret)
                .map_err(|_| ApiError::Unauthorized("Invalid or expired token".to_owned()))?;
            user.require_scope("secrets:read")?;
            user.user_id
        }
    };

    let row = sqlx::query_as::<_, EncryptedValueRow>(
        "SELECT encrypted_value, encrypted_dek, dek_version, name FROM icebox_secrets WHERE id = $1",
    )
    .bind(&id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Not found".to_owned()))?;

    let plaintext = state
        .envelope
        .read()
        .await
        .decrypt(
            &row.encrypted_value,
            &row.encrypted_dek,
            row.dek_version as u32,
        )
        .map_err(|e| {
            tracing::error!(secret_id = %id, error = %e, "decryption failed");
            ApiError::Internal
        })?;

    write_audit(&state, &actor_id, "secret.value.read", &id, &headers).await;

    Ok(Json(json!({
        "id": id,
        "name": row.name,
        "value": plaintext,
        "retrieved_at": skauswatch_streams::py_now_isoformat(),
    })))
}

#[derive(sqlx::FromRow)]
struct VersionRow {
    id: String,
    version_number: i32,
    created_by: Option<String>,
    created_at: NaiveDateTime,
    deprecated_at: Option<NaiveDateTime>,
}

async fn list_secret_versions(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:read")?;
    if fetch_secret(&state, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    let versions = sqlx::query_as::<_, VersionRow>(
        "SELECT id, version_number, created_by, created_at, deprecated_at \
         FROM icebox_secret_versions WHERE secret_id = $1 ORDER BY version_number DESC",
    )
    .bind(&id)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(json!({
        "secret_id": id,
        "versions": versions.iter().map(|v| json!({
            "id": v.id,
            "version_number": v.version_number,
            "created_by": v.created_by,
            "created_at": skauswatch_streams::py_isoformat(v.created_at),
            "deprecated_at": v.deprecated_at.map(skauswatch_streams::py_isoformat),
        })).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct RotateBody {
    value: Option<String>,
}

async fn rotate_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<RotateBody>>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:write")?;
    if fetch_secret(&state, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    let new_value = body
        .and_then(|Json(b)| b.value)
        .unwrap_or_default()
        .trim()
        .to_owned();
    if new_value.is_empty() {
        return Err(ApiError::BadRequest(
            "value is required for rotation".to_owned(),
        ));
    }

    let now = Utc::now().naive_utc();
    sqlx::query(
        "UPDATE icebox_secret_versions SET deprecated_at = $1 \
         WHERE secret_id = $2 AND deprecated_at IS NULL",
    )
    .bind(now)
    .bind(&id)
    .execute(&state.db)
    .await?;

    let (encrypted_value, encrypted_dek, dek_version) =
        state.envelope.read().await.encrypt(&new_value)?;

    let max_version: Option<i32> = sqlx::query_scalar(
        "SELECT MAX(version_number) FROM icebox_secret_versions WHERE secret_id = $1",
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await?;
    let next_version = max_version.unwrap_or(0) + 1;

    sqlx::query(
        "INSERT INTO icebox_secret_versions (id, secret_id, version_number, encrypted_value, \
         encrypted_dek, dek_version, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&id)
    .bind(next_version)
    .bind(&encrypted_value)
    .bind(&encrypted_dek)
    .bind(dek_version as i32)
    .bind(&user.user_id)
    .bind(now)
    .execute(&state.db)
    .await?;

    sqlx::query(
        "UPDATE icebox_secrets SET encrypted_value = $1, encrypted_dek = $2, dek_version = $3, \
         updated_at = $4 WHERE id = $5",
    )
    .bind(&encrypted_value)
    .bind(&encrypted_dek)
    .bind(dek_version as i32)
    .bind(now)
    .bind(&id)
    .execute(&state.db)
    .await?;

    write_audit(&state, &user.user_id, "secret.rotate", &id, &headers).await;

    Ok(Json(json!({
        "id": id,
        "version": next_version,
        "rotated_at": skauswatch_streams::py_isoformat(now),
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashSet;

    use axum_test::TestServer;
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use skauswatch_icebox::EnvelopeEncryption;

    use super::*;
    use crate::state::AppStateInner;

    fn dev_license() -> std::sync::Arc<LicenseClient> {
        let cfg = LicenseConfig::new("skauswatch").expect("config");
        LicenseClient::new(cfg).expect("client")
    }

    fn test_server() -> TestServer {
        let state = AppStateInner::for_tests(dev_license(), EnvelopeEncryption::default());
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        TestServer::new(app)
    }

    fn token(scopes: &str) -> String {
        use chrono::Utc;
        use jsonwebtoken::{EncodingKey, Header};
        jsonwebtoken::encode(
            &Header::default(),
            &serde_json::json!({
                "sub": "user-1",
                "exp": Utc::now().timestamp() + 3600,
                "scope": scopes,
            }),
            &EncodingKey::from_secret(b"test-secret"),
        )
        .expect("encode")
    }

    #[tokio::test]
    async fn list_secrets_requires_auth() {
        let server = test_server();
        let resp = server.get("/api/v1/secrets").await;
        resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn create_secret_requires_write_scope() {
        let server = test_server();
        let resp = server
            .post("/api/v1/secrets")
            .authorization_bearer(token("secrets:read"))
            .json(&serde_json::json!({"name": "x", "value": "y"}))
            .await;
        resp.assert_status(axum::http::StatusCode::FORBIDDEN);
        let body: Value = resp.json();
        assert_eq!(body["error"], "Insufficient scope");
    }

    #[tokio::test]
    async fn create_secret_validates_body_before_touching_db() {
        let server = test_server();
        let resp = server
            .post("/api/v1/secrets")
            .authorization_bearer(token("secrets:write"))
            .json(&serde_json::json!({"name": "", "value": ""}))
            .await;
        resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_secret_rejects_invalid_type_before_touching_db() {
        let server = test_server();
        let resp = server
            .post("/api/v1/secrets")
            .authorization_bearer(token("secrets:write"))
            .json(&serde_json::json!({"name": "n", "value": "v", "type": "bogus"}))
            .await;
        resp.assert_status(axum::http::StatusCode::BAD_REQUEST);
        let body: Value = resp.json();
        assert!(
            body["error"]
                .as_str()
                .unwrap_or_default()
                .starts_with("Invalid type")
        );
    }

    #[tokio::test]
    async fn secret_value_endpoint_requires_authorization_header() {
        let server = test_server();
        let resp = server.get("/api/v1/secrets/does-not-matter/value").await;
        resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
        let body: Value = resp.json();
        assert_eq!(body["error"], "Authorization required");
    }

    #[test]
    fn secret_row_to_json_matches_v1_shape() {
        let row = SecretRow {
            id: "s-1".into(),
            name: "n".into(),
            description: Some("d".into()),
            secret_type: "api_key".into(),
            tags: Some(SqlxJson(json!(["a", "b"]))),
            expires_at: None,
            created_at: chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            updated_at: chrono::NaiveDate::from_ymd_opt(2026, 1, 1)
                .unwrap()
                .and_hms_opt(0, 0, 0)
                .unwrap(),
            created_by: Some("u".into()),
        };
        let v = row.to_json();
        assert_eq!(v["id"], "s-1");
        assert_eq!(v["tags"], json!(["a", "b"]));
        assert_eq!(v["expires_at"], Value::Null);
        assert_eq!(v["created_at"], "2026-01-01T00:00:00");
        // No encrypted fields ever leak into the dict.
        assert!(v.get("encrypted_value").is_none());
        assert!(v.get("encrypted_dek").is_none());
    }

    #[test]
    fn require_scope_error_shape() {
        let user = CurrentUser {
            user_id: "u".into(),
            tenant_id: "default".into(),
            scopes: HashSet::new(),
            raw_token: "t".into(),
        };
        match user.require_scope("secrets:read") {
            Err(ApiError::InsufficientScope { required, missing }) => {
                assert_eq!(required, vec!["secrets:read".to_owned()]);
                assert_eq!(missing, vec!["secrets:read".to_owned()]);
            }
            other => panic!("expected InsufficientScope, got {other:?}"),
        }
    }
}
