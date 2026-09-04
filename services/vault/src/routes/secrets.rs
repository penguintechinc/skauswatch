//! `/api/v1/secrets` — CRUD for envelope-encrypted secrets, versioning, and
//! plaintext retrieval. Rust port of
//! `icebox/services/flask-backend/api/v1/secrets.py`.

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::types::Json as SqlxJson;
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse, InsufficientScopeResponse};
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

/// Documentation-only mirror of `SecretRow::to_json`'s wire shape — never
/// includes the encrypted fields.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SecretResponse {
    id: String,
    name: String,
    description: Option<String>,
    secret_type: String,
    tags: Option<Value>,
    expires_at: Option<String>,
    created_at: String,
    updated_at: String,
    created_by: Option<String>,
}

/// Documentation-only mirror of `list_secrets`'s response envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SecretListResponse {
    secrets: Vec<SecretResponse>,
    total: i64,
    page: i64,
    per_page: i64,
}

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    #[serde(rename = "type")]
    secret_type: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/secrets",
    tag = "secrets",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Paginated list of secrets (metadata only, never encrypted fields)", body = SecretListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires secrets:read)", body = InsufficientScopeResponse),
    ),
)]
pub(crate) async fn list_secrets(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:read")?;
    let tenant_id = user.tenant_uuid()?;

    let page = q.page.unwrap_or(1).max(1);
    let per_page = q.per_page.unwrap_or(20).clamp(1, 100);
    let offset = (page - 1) * per_page;

    let (rows, total) = match &q.secret_type {
        Some(t) => {
            let rows = sqlx::query_as::<_, SecretRow>(
                "SELECT id, name, description, secret_type, tags, expires_at, created_at, \
                 updated_at, created_by FROM vault_secrets \
                 WHERE tenant_id = $1 AND secret_type = $2 \
                 ORDER BY created_at DESC LIMIT $3 OFFSET $4",
            )
            .bind(tenant_id)
            .bind(t)
            .bind(per_page)
            .bind(offset)
            .fetch_all(&state.db)
            .await?;
            let total: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM vault_secrets WHERE tenant_id = $1 AND secret_type = $2",
            )
            .bind(tenant_id)
            .bind(t)
            .fetch_one(&state.db)
            .await?;
            (rows, total)
        }
        None => {
            let rows = sqlx::query_as::<_, SecretRow>(
                "SELECT id, name, description, secret_type, tags, expires_at, created_at, \
                 updated_at, created_by FROM vault_secrets WHERE tenant_id = $1 \
                 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
            )
            .bind(tenant_id)
            .bind(per_page)
            .bind(offset)
            .fetch_all(&state.db)
            .await?;
            let total: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM vault_secrets WHERE tenant_id = $1")
                    .bind(tenant_id)
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

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateSecretBody {
    name: Option<String>,
    /// Plaintext secret value — encrypted at rest immediately, never
    /// persisted or logged unencrypted.
    value: Option<String>,
    #[serde(rename = "type")]
    secret_type: Option<String>,
    description: Option<String>,
    tags: Option<Value>,
    metadata: Option<Value>,
    expires_at: Option<NaiveDateTime>,
}

#[utoipa::path(
    post,
    path = "/api/v1/secrets",
    tag = "secrets",
    security(("bearer_jwt" = [])),
    request_body = CreateSecretBody,
    responses(
        (status = 201, description = "Secret created", body = SecretResponse),
        (status = 400, description = "Missing name/value or invalid secret type", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires secrets:write)", body = InsufficientScopeResponse),
    ),
)]
pub(crate) async fn create_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Json(body): Json<CreateSecretBody>,
) -> Result<(axum::http::StatusCode, Json<Value>), ApiError> {
    user.require_scope("secrets:write")?;
    let tenant_id = user.tenant_uuid()?;

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
        "INSERT INTO vault_secrets (id, tenant_id, name, description, secret_type, \
         encrypted_value, encrypted_dek, dek_version, tags, secret_metadata, expires_at, \
         created_at, updated_at, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(&secret_id)
    .bind(tenant_id)
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
        "INSERT INTO vault_secret_versions (id, tenant_id, secret_id, version_number, \
         encrypted_value, encrypted_dek, dek_version, created_by, created_at) \
         VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(tenant_id)
    .bind(&secret_id)
    .bind(&encrypted_value)
    .bind(&encrypted_dek)
    .bind(dek_version as i32)
    .bind(&user.user_id)
    .bind(now)
    .execute(&state.db)
    .await?;

    sqlx::query(
        "INSERT INTO vault_secret_owners (secret_id, tenant_id, owner_type, owner_id) \
         VALUES ($1,$2,'user',$3)",
    )
    .bind(&secret_id)
    .bind(tenant_id)
    .bind(&user.user_id)
    .execute(&state.db)
    .await?;

    write_audit(
        &state,
        tenant_id,
        &user.user_id,
        "secret.create",
        &secret_id,
        &headers,
    )
    .await;

    let secret = fetch_secret(&state, tenant_id, &secret_id)
        .await?
        .ok_or_else(|| ApiError::internal("create_secret", "row vanished after insert"))?;
    Ok((axum::http::StatusCode::CREATED, Json(secret.to_json())))
}

async fn fetch_secret(
    state: &AppState,
    tenant_id: Uuid,
    id: &str,
) -> Result<Option<SecretRow>, ApiError> {
    Ok(sqlx::query_as::<_, SecretRow>(
        "SELECT id, name, description, secret_type, tags, expires_at, created_at, updated_at, \
         created_by FROM vault_secrets WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?)
}

#[utoipa::path(
    get,
    path = "/api/v1/secrets/{id}",
    tag = "secrets",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Secret id")),
    responses(
        (status = 200, description = "Secret metadata", body = SecretResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires secrets:read)", body = InsufficientScopeResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:read")?;
    let secret = fetch_secret(&state, user.tenant_uuid()?, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Not found".to_owned()))?;
    Ok(Json(secret.to_json()))
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct UpdateSecretBody {
    name: Option<String>,
    description: Option<String>,
    tags: Option<Value>,
    expires_at: Option<NaiveDateTime>,
    metadata: Option<Value>,
}

#[utoipa::path(
    put,
    path = "/api/v1/secrets/{id}",
    tag = "secrets",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Secret id")),
    request_body = UpdateSecretBody,
    responses(
        (status = 200, description = "Updated secret metadata", body = SecretResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires secrets:write)", body = InsufficientScopeResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<UpdateSecretBody>>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:write")?;
    let tenant_id = user.tenant_uuid()?;
    if fetch_secret(&state, tenant_id, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let now = Utc::now().naive_utc();

    sqlx::query(
        "UPDATE vault_secrets SET \
         name = COALESCE($1, name), \
         description = COALESCE($2, description), \
         tags = COALESCE($3, tags), \
         expires_at = COALESCE($4, expires_at), \
         secret_metadata = COALESCE($5, secret_metadata), \
         updated_at = $6 \
         WHERE id = $7 AND tenant_id = $8",
    )
    .bind(body.name.as_deref().map(str::trim))
    .bind(body.description)
    .bind(body.tags.map(SqlxJson))
    .bind(body.expires_at)
    .bind(body.metadata.map(SqlxJson))
    .bind(now)
    .bind(&id)
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    write_audit(
        &state,
        tenant_id,
        &user.user_id,
        "secret.update",
        &id,
        &headers,
    )
    .await;

    let secret = fetch_secret(&state, tenant_id, &id)
        .await?
        .ok_or_else(|| ApiError::internal("update_secret", "row vanished after update"))?;
    Ok(Json(secret.to_json()))
}

#[utoipa::path(
    delete,
    path = "/api/v1/secrets/{id}",
    tag = "secrets",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Secret id")),
    responses(
        (status = 204, description = "Secret deleted"),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires secrets:delete)", body = InsufficientScopeResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn delete_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    user.require_scope("secrets:delete")?;
    let tenant_id = user.tenant_uuid()?;
    if fetch_secret(&state, tenant_id, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    write_audit(
        &state,
        tenant_id,
        &user.user_id,
        "secret.delete",
        &id,
        &headers,
    )
    .await;
    sqlx::query("DELETE FROM vault_secrets WHERE id = $1 AND tenant_id = $2")
        .bind(&id)
        .bind(tenant_id)
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

/// Documentation-only mirror of `get_secret_value`'s response envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SecretValueResponse {
    id: String,
    name: String,
    /// Decrypted secret value — never populated with example data in the
    /// generated schema.
    value: String,
    retrieved_at: String,
}

/// GET /secrets/{id}/value — accepts a JIT token OR a standard bearer JWT
/// with `secrets:read` (v1 does not use the `CurrentUser` extractor here
/// because it must try the JIT-token path first). Documented with the
/// standard `bearer_jwt` scheme even though a JIT token satisfies the same
/// `Authorization: Bearer` header shape.
#[utoipa::path(
    get,
    path = "/api/v1/secrets/{id}/value",
    tag = "secrets",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Secret id")),
    responses(
        (status = 200, description = "Decrypted secret value", body = SecretValueResponse),
        (status = 401, description = "Missing/invalid authorization header or token", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires secrets:read)", body = InsufficientScopeResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_secret_value(
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

    // Two credential shapes share this endpoint (v1 parity): a JIT grant
    // token (no independent tenant claim of its own — its tenant is
    // whatever `vault_jit_grants.tenant_id` was stamped with at approval
    // time, denormalized from the request/secret it was granted against),
    // or a standard bearer JWT (tenant from `CurrentUser::tenant_uuid`).
    // Either way, `tenant_id` below is never trusted from the request path
    // — it is always resolved from a validated credential.
    let (actor_id, tenant_id) = match validate_jit_token(&state, token, &id).await {
        Some((grantee_id, tenant_id)) => (grantee_id, tenant_id),
        None => {
            let user = crate::auth::decode_bearer(token, &state.auth.jwt_verify_key)?;
            user.require_scope("secrets:read")?;
            let tenant_id = user.tenant_uuid()?;
            (user.user_id, tenant_id)
        }
    };

    let row = sqlx::query_as::<_, EncryptedValueRow>(
        "SELECT encrypted_value, encrypted_dek, dek_version, name FROM vault_secrets \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(tenant_id)
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

    write_audit(
        &state,
        tenant_id,
        &actor_id,
        "secret.value.read",
        &id,
        &headers,
    )
    .await;

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

/// Documentation-only mirror of one entry in `list_secret_versions`'s
/// `versions` array.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SecretVersionEntry {
    id: String,
    version_number: i32,
    created_by: Option<String>,
    created_at: String,
    deprecated_at: Option<String>,
}

/// Documentation-only mirror of `list_secret_versions`'s response envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SecretVersionsResponse {
    secret_id: String,
    versions: Vec<SecretVersionEntry>,
}

#[utoipa::path(
    get,
    path = "/api/v1/secrets/{id}/versions",
    tag = "secrets",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Secret id")),
    responses(
        (status = 200, description = "Version history (newest first)", body = SecretVersionsResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires secrets:read)", body = InsufficientScopeResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_secret_versions(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:read")?;
    let tenant_id = user.tenant_uuid()?;
    if fetch_secret(&state, tenant_id, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    let versions = sqlx::query_as::<_, VersionRow>(
        "SELECT id, version_number, created_by, created_at, deprecated_at \
         FROM vault_secret_versions WHERE secret_id = $1 AND tenant_id = $2 \
         ORDER BY version_number DESC",
    )
    .bind(&id)
    .bind(tenant_id)
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

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RotateBody {
    /// New plaintext secret value — encrypted at rest immediately.
    value: Option<String>,
}

/// Documentation-only mirror of `rotate_secret`'s response envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct RotateSecretResponse {
    id: String,
    version: i32,
    rotated_at: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/secrets/{id}/rotate",
    tag = "secrets",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Secret id")),
    request_body = RotateBody,
    responses(
        (status = 200, description = "New version created and set as current", body = RotateSecretResponse),
        (status = 400, description = "Missing rotation value", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires secrets:write)", body = InsufficientScopeResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn rotate_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<RotateBody>>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("secrets:write")?;
    let tenant_id = user.tenant_uuid()?;
    if fetch_secret(&state, tenant_id, &id).await?.is_none() {
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
        "UPDATE vault_secret_versions SET deprecated_at = $1 \
         WHERE secret_id = $2 AND tenant_id = $3 AND deprecated_at IS NULL",
    )
    .bind(now)
    .bind(&id)
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    let (encrypted_value, encrypted_dek, dek_version) =
        state.envelope.read().await.encrypt(&new_value)?;

    let max_version: Option<i32> = sqlx::query_scalar(
        "SELECT MAX(version_number) FROM vault_secret_versions WHERE secret_id = $1 AND tenant_id = $2",
    )
    .bind(&id)
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await?;
    let next_version = max_version.unwrap_or(0) + 1;

    sqlx::query(
        "INSERT INTO vault_secret_versions (id, tenant_id, secret_id, version_number, \
         encrypted_value, encrypted_dek, dek_version, created_by, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(tenant_id)
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
        "UPDATE vault_secrets SET encrypted_value = $1, encrypted_dek = $2, dek_version = $3, \
         updated_at = $4 WHERE id = $5 AND tenant_id = $6",
    )
    .bind(&encrypted_value)
    .bind(&encrypted_dek)
    .bind(dek_version as i32)
    .bind(now)
    .bind(&id)
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    write_audit(
        &state,
        tenant_id,
        &user.user_id,
        "secret.rotate",
        &id,
        &headers,
    )
    .await;

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
    use skauswatch_vault::EnvelopeEncryption;

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

    fn test_server_with_state(state: crate::state::AppState) -> TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        TestServer::new(app)
    }

    fn token(scopes: &str) -> String {
        use chrono::Utc;
        use jsonwebtoken::{Algorithm, Header};
        jsonwebtoken::encode(
            &Header::new(Algorithm::ES256),
            &serde_json::json!({
                "sub": "user-1",
                "exp": Utc::now().timestamp() + 3600,
                "scope": scopes,
                "tenant": crate::routes::test_support::TEST_TENANT,
            }),
            skauswatch_testkit::jwt::signing_key(),
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

    // -- DB-backed handler tests (real Postgres via skauswatch-testkit) --

    use crate::routes::test_support::{db_state, sign_token};

    #[tokio::test]
    async fn create_secret_response_never_leaks_encrypted_fields() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "owner-1", "secrets:write");
        let server = test_server_with_state(state);

        let resp = server
            .post("/api/v1/secrets")
            .authorization_bearer(&token)
            .json(&json!({"name": "db-password", "value": "hunter2", "type": "db_password"}))
            .await;
        resp.assert_status(axum::http::StatusCode::CREATED);
        let body: Value = resp.json();
        assert_eq!(body["name"], "db-password");
        assert_eq!(body["secret_type"], "db_password");
        assert!(body.get("encrypted_value").is_none());
        assert!(body.get("encrypted_dek").is_none());
        assert!(body.get("value").is_none());
    }

    #[tokio::test]
    async fn create_secret_defaults_type_to_api_key() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "owner-1", "secrets:write");
        let server = test_server_with_state(state);
        let resp = server
            .post("/api/v1/secrets")
            .authorization_bearer(&token)
            .json(&json!({"name": "n", "value": "v"}))
            .await;
        resp.assert_status(axum::http::StatusCode::CREATED);
        let body: Value = resp.json();
        assert_eq!(body["secret_type"], "api_key");
    }

    #[tokio::test]
    async fn list_secrets_is_empty_against_a_fresh_db() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "u", "secrets:read");
        let server = test_server_with_state(state);
        let resp = server
            .get("/api/v1/secrets")
            .authorization_bearer(&token)
            .await;
        resp.assert_status_ok();
        let body: Value = resp.json();
        assert_eq!(body["total"], 0);
        assert_eq!(body["secrets"], json!([]));
    }

    #[tokio::test]
    async fn list_secrets_filters_by_type_and_paginates() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "owner-1", "secrets:write secrets:read");
        let server = test_server_with_state(state);

        for (name, kind) in [("a", "api_key"), ("b", "api_key"), ("c", "token")] {
            let resp = server
                .post("/api/v1/secrets")
                .authorization_bearer(&token)
                .json(&json!({"name": name, "value": "v", "type": kind}))
                .await;
            resp.assert_status(axum::http::StatusCode::CREATED);
        }

        let filtered = server
            .get("/api/v1/secrets?type=api_key")
            .authorization_bearer(&token)
            .await;
        filtered.assert_status_ok();
        let filtered_body: Value = filtered.json();
        assert_eq!(filtered_body["total"], 2);

        let paged = server
            .get("/api/v1/secrets?page=1&per_page=1")
            .authorization_bearer(&token)
            .await;
        paged.assert_status_ok();
        let paged_body: Value = paged.json();
        assert_eq!(paged_body["total"], 3);
        assert_eq!(paged_body["secrets"].as_array().map(Vec::len), Some(1));
        assert_eq!(paged_body["per_page"], 1);
    }

    #[tokio::test]
    async fn get_secret_404_on_unknown_id() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "u", "secrets:read");
        let server = test_server_with_state(state);
        let resp = server
            .get("/api/v1/secrets/does-not-exist")
            .authorization_bearer(&token)
            .await;
        resp.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_secret_round_trip_and_404() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "owner-1", "secrets:write secrets:read");
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/secrets")
            .authorization_bearer(&token)
            .json(&json!({"name": "orig", "value": "v"}))
            .await;
        let id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let updated = server
            .put(&format!("/api/v1/secrets/{id}"))
            .authorization_bearer(&token)
            .json(&json!({"name": "renamed", "tags": ["x"]}))
            .await;
        updated.assert_status_ok();
        let updated_body: Value = updated.json();
        assert_eq!(updated_body["name"], "renamed");
        assert_eq!(updated_body["tags"], json!(["x"]));

        let missing = server
            .put("/api/v1/secrets/does-not-exist")
            .authorization_bearer(&token)
            .json(&json!({"name": "x"}))
            .await;
        missing.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_secret_round_trip_and_404() {
        let state = db_state(dev_license()).await;
        let token = sign_token(
            &state,
            "owner-1",
            "secrets:write secrets:read secrets:delete",
        );
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/secrets")
            .authorization_bearer(&token)
            .json(&json!({"name": "gone-soon", "value": "v"}))
            .await;
        let id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let deleted = server
            .delete(&format!("/api/v1/secrets/{id}"))
            .authorization_bearer(&token)
            .await;
        deleted.assert_status(axum::http::StatusCode::NO_CONTENT);

        let refetch = server
            .get(&format!("/api/v1/secrets/{id}"))
            .authorization_bearer(&token)
            .await;
        refetch.assert_status(axum::http::StatusCode::NOT_FOUND);

        let missing = server
            .delete("/api/v1/secrets/does-not-exist")
            .authorization_bearer(&token)
            .await;
        missing.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_secret_value_round_trips_plaintext_via_bearer_token() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "owner-1", "secrets:write secrets:read");
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/secrets")
            .authorization_bearer(&token)
            .json(&json!({"name": "n", "value": "correct-horse-battery-staple"}))
            .await;
        let id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let value_resp = server
            .get(&format!("/api/v1/secrets/{id}/value"))
            .authorization_bearer(&token)
            .await;
        value_resp.assert_status_ok();
        let value_body: Value = value_resp.json();
        assert_eq!(value_body["value"], "correct-horse-battery-staple");
    }

    #[tokio::test]
    async fn get_secret_value_rejects_invalid_token() {
        let state = db_state(dev_license()).await;
        let server = test_server_with_state(state);
        let resp = server
            .get("/api/v1/secrets/does-not-matter/value")
            .authorization_bearer("garbage-not-a-jwt")
            .await;
        resp.assert_status(axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_secret_value_404_on_unknown_id() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "u", "secrets:read");
        let server = test_server_with_state(state);
        let resp = server
            .get("/api/v1/secrets/does-not-exist/value")
            .authorization_bearer(&token)
            .await;
        resp.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_secret_value_accepts_a_valid_jit_token() {
        use sha2::{Digest, Sha256};

        let state = db_state(dev_license()).await;
        let owner_token = sign_token(&state, "owner-1", "secrets:write");
        let server = test_server_with_state(state.clone());

        let created = server
            .post("/api/v1/secrets")
            .authorization_bearer(&owner_token)
            .json(&json!({"name": "jit-target", "value": "jit-plaintext"}))
            .await;
        let secret_id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let expires_epoch = chrono::Utc::now().timestamp() + 3600;
        let grant_id = "grant-1";
        let grantee_id = "grantee-1";
        let jit_token = format!("jit:{grant_id}:{grantee_id}:{expires_epoch}");
        let mut hasher = Sha256::new();
        hasher.update(jit_token.as_bytes());
        let hash = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();

        let tenant_id: Uuid = crate::routes::test_support::TEST_TENANT
            .parse()
            .unwrap_or_else(|e| panic!("test tenant uuid: {e}"));

        // Satisfies `vault_jit_grants_request_id_fkey` — a real grant only
        // ever exists once `approve_jit_request` has created its parent
        // `vault_jit_requests` row.
        sqlx::query(
            "INSERT INTO vault_jit_requests (id, tenant_id, secret_id, requestor_id, reason, \
             requested_duration_seconds, status, created_at) \
             VALUES ('request-1', $1, $2, $3, 'test', 3600, 'approved', $4)",
        )
        .bind(tenant_id)
        .bind(&secret_id)
        .bind(grantee_id)
        .bind(chrono::Utc::now().naive_utc())
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed jit request: {e}"));

        sqlx::query(
            "INSERT INTO vault_jit_grants (id, tenant_id, request_id, secret_id, grantee_id, \
             access_token_hash, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(grant_id)
        .bind(tenant_id)
        .bind("request-1")
        .bind(&secret_id)
        .bind(grantee_id)
        .bind(&hash)
        .bind(
            chrono::DateTime::from_timestamp(expires_epoch, 0)
                .unwrap_or_default()
                .naive_utc(),
        )
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed jit grant: {e}"));

        let resp = server
            .get(&format!("/api/v1/secrets/{secret_id}/value"))
            .authorization_bearer(&jit_token)
            .await;
        resp.assert_status_ok();
        let body: Value = resp.json();
        assert_eq!(body["value"], "jit-plaintext");
    }

    #[tokio::test]
    async fn list_secret_versions_round_trip_and_404() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "owner-1", "secrets:write secrets:read");
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/secrets")
            .authorization_bearer(&token)
            .json(&json!({"name": "n", "value": "v"}))
            .await;
        let id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let versions = server
            .get(&format!("/api/v1/secrets/{id}/versions"))
            .authorization_bearer(&token)
            .await;
        versions.assert_status_ok();
        let body: Value = versions.json();
        assert_eq!(body["versions"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["versions"][0]["version_number"], 1);

        let missing = server
            .get("/api/v1/secrets/does-not-exist/versions")
            .authorization_bearer(&token)
            .await;
        missing.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rotate_secret_creates_new_version_and_updates_value() {
        let state = db_state(dev_license()).await;
        let token = sign_token(&state, "owner-1", "secrets:write secrets:read");
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/secrets")
            .authorization_bearer(&token)
            .json(&json!({"name": "n", "value": "old-value"}))
            .await;
        let id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let rotated = server
            .post(&format!("/api/v1/secrets/{id}/rotate"))
            .authorization_bearer(&token)
            .json(&json!({"value": "new-value"}))
            .await;
        rotated.assert_status_ok();
        let rotated_body: Value = rotated.json();
        assert_eq!(rotated_body["version"], 2);

        let value_resp = server
            .get(&format!("/api/v1/secrets/{id}/value"))
            .authorization_bearer(&token)
            .await;
        let value_body: Value = value_resp.json();
        assert_eq!(value_body["value"], "new-value");

        let versions = server
            .get(&format!("/api/v1/secrets/{id}/versions"))
            .authorization_bearer(&token)
            .await;
        let versions_body: Value = versions.json();
        assert_eq!(versions_body["versions"].as_array().map(Vec::len), Some(2));

        let empty_value = server
            .post(&format!("/api/v1/secrets/{id}/rotate"))
            .authorization_bearer(&token)
            .json(&json!({"value": ""}))
            .await;
        empty_value.assert_status(axum::http::StatusCode::BAD_REQUEST);

        let missing = server
            .post("/api/v1/secrets/does-not-exist/rotate")
            .authorization_bearer(&token)
            .json(&json!({"value": "x"}))
            .await;
        missing.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn tenant_isolation_across_read_write_and_value_endpoints() {
        use crate::routes::test_support::sign_token_for_tenant;

        let state = db_state(dev_license()).await;
        let tenant_a = sign_token_for_tenant(
            &state,
            "owner-a",
            "secrets:write secrets:read secrets:delete",
            crate::routes::test_support::TEST_TENANT,
        );
        let tenant_b = sign_token_for_tenant(
            &state,
            "owner-b",
            "secrets:write secrets:read secrets:delete",
            crate::routes::test_support::OTHER_TENANT,
        );
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/secrets")
            .authorization_bearer(&tenant_a)
            .json(&json!({"name": "a-secret", "value": "a-plaintext"}))
            .await;
        created.assert_status(axum::http::StatusCode::CREATED);
        let id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        // Tenant B cannot list tenant A's secret.
        let listed = server
            .get("/api/v1/secrets")
            .authorization_bearer(&tenant_b)
            .await;
        assert_eq!(listed.json::<Value>()["total"], 0);

        // Tenant B cannot read tenant A's secret metadata, value, or
        // versions — all 404, never leaking existence via a different code.
        server
            .get(&format!("/api/v1/secrets/{id}"))
            .authorization_bearer(&tenant_b)
            .await
            .assert_status(axum::http::StatusCode::NOT_FOUND);
        server
            .get(&format!("/api/v1/secrets/{id}/value"))
            .authorization_bearer(&tenant_b)
            .await
            .assert_status(axum::http::StatusCode::NOT_FOUND);
        server
            .get(&format!("/api/v1/secrets/{id}/versions"))
            .authorization_bearer(&tenant_b)
            .await
            .assert_status(axum::http::StatusCode::NOT_FOUND);

        // Tenant B cannot update, rotate, or delete tenant A's secret.
        server
            .put(&format!("/api/v1/secrets/{id}"))
            .authorization_bearer(&tenant_b)
            .json(&json!({"name": "hijacked"}))
            .await
            .assert_status(axum::http::StatusCode::NOT_FOUND);
        server
            .post(&format!("/api/v1/secrets/{id}/rotate"))
            .authorization_bearer(&tenant_b)
            .json(&json!({"value": "hijacked"}))
            .await
            .assert_status(axum::http::StatusCode::NOT_FOUND);
        server
            .delete(&format!("/api/v1/secrets/{id}"))
            .authorization_bearer(&tenant_b)
            .await
            .assert_status(axum::http::StatusCode::NOT_FOUND);

        // Tenant A's own access is untouched by tenant B's attempts.
        let still_there = server
            .get(&format!("/api/v1/secrets/{id}"))
            .authorization_bearer(&tenant_a)
            .await;
        still_there.assert_status_ok();
        assert_eq!(still_there.json::<Value>()["name"], "a-secret");
    }
}
