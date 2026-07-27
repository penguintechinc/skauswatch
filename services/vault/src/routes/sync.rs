//! `/api/v1/sync` — cloud vault integration management. Rust port of
//! `icebox/services/flask-backend/api/v1/sync.py`. Publishes sync events to
//! Redis Streams for `worker-vault-sync` (see `sync_stream_name`).

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sqlx::types::Json as SqlxJson;
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::state::AppState;

const VALID_PROVIDERS: &[&str] = &["aws", "azure", "gcp", "oracle", "kubernetes"];
const VALID_DIRECTIONS: &[&str] = &["vault_to_cloud", "cloud_to_vault", "bidirectional"];

/// Router for `/api/v1/sync`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/sync/integrations",
            get(list_integrations).post(create_integration),
        )
        .route(
            "/sync/integrations/{id}",
            axum::routing::put(update_integration).delete(delete_integration),
        )
        .route("/sync/integrations/{id}/trigger", post(trigger_sync))
}

/// Unprefixed stream name consumed by `worker-vault-sync`; the
/// `StreamProducer` prepends the shared `REDIS_KEY_PREFIX` (default
/// `skauswatch`), yielding `skauswatch:vault:sync:{provider}`.
fn sync_stream_name(provider: &str) -> String {
    format!("vault:sync:{provider}")
}

async fn publish_sync_event(
    state: &AppState,
    integration_id: &str,
    provider: &str,
    event_type: &str,
) {
    let Some(streams) = &state.streams else {
        tracing::warn!("no stream producer configured — skipping sync event publish");
        return;
    };
    let fields: skauswatch_streams::EntryFields = vec![
        ("integration_id".to_owned(), integration_id.to_owned()),
        ("event_type".to_owned(), event_type.to_owned()),
        (
            "timestamp".to_owned(),
            skauswatch_streams::py_now_isoformat(),
        ),
    ];
    if let Err(e) = streams.publish(&sync_stream_name(provider), fields).await {
        tracing::error!(error = %e, provider, "failed to publish sync event");
    }
}

#[derive(sqlx::FromRow)]
struct IntegrationRow {
    id: String,
    provider: String,
    name: String,
    description: Option<String>,
    sync_direction: String,
    sync_scopes: Option<SqlxJson<Value>>,
    enabled: bool,
    config: Option<SqlxJson<Value>>,
    last_sync_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
}

impl IntegrationRow {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "provider": self.provider,
            "name": self.name,
            "description": self.description,
            "sync_direction": self.sync_direction,
            "sync_scopes": self.sync_scopes.as_ref().map(|j| j.0.clone()),
            "enabled": self.enabled,
            "config": self.config.as_ref().map(|j| j.0.clone()),
            "last_sync_at": self.last_sync_at.map(skauswatch_streams::py_isoformat),
            "created_at": skauswatch_streams::py_isoformat(self.created_at),
        })
    }
}

async fn list_integrations(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("sync:read")?;
    let rows = sqlx::query_as::<_, IntegrationRow>(
        "SELECT id, provider, name, description, sync_direction, sync_scopes, enabled, config, \
         last_sync_at, created_at FROM vault_cloud_integrations ORDER BY name",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "integrations": rows.iter().map(IntegrationRow::to_json).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct CreateIntegrationBody {
    provider: Option<String>,
    name: Option<String>,
    description: Option<String>,
    sync_direction: Option<String>,
    sync_scopes: Option<Value>,
    credentials: Option<Value>,
    enabled: Option<bool>,
    config: Option<Value>,
}

async fn create_integration(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(body): Json<CreateIntegrationBody>,
) -> Result<(axum::http::StatusCode, Json<Value>), ApiError> {
    user.require_scope("sync:admin")?;

    let provider = body
        .provider
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let name = body.name.unwrap_or_default().trim().to_owned();
    if !VALID_PROVIDERS.contains(&provider.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "provider must be one of: {}",
            VALID_PROVIDERS.join(", ")
        )));
    }
    if name.is_empty() {
        return Err(ApiError::BadRequest("name is required".to_owned()));
    }
    let sync_direction = body
        .sync_direction
        .unwrap_or_else(|| "vault_to_cloud".to_owned());
    if !VALID_DIRECTIONS.contains(&sync_direction.as_str()) {
        return Err(ApiError::BadRequest(format!(
            "sync_direction must be one of: {}",
            VALID_DIRECTIONS.join(", ")
        )));
    }

    let encrypted_credentials = match &body.credentials {
        Some(creds) if !creds.is_null() => {
            let creds_json = serde_json::to_string(creds)
                .map_err(|e| ApiError::internal("serialize credentials", e))?;
            let (ciphertext, encrypted_dek, dek_version) =
                state.envelope.read().await.encrypt(&creds_json)?;
            Some(
                json!({
                    "ciphertext": ciphertext,
                    "dek": encrypted_dek,
                    "version": dek_version,
                })
                .to_string(),
            )
        }
        _ => None,
    };

    let integration_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO vault_cloud_integrations (id, provider, name, description, sync_direction, \
         sync_scopes, encrypted_credentials, enabled, config, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
    )
    .bind(&integration_id)
    .bind(&provider)
    .bind(&name)
    .bind(body.description.unwrap_or_default())
    .bind(&sync_direction)
    .bind(body.sync_scopes.map(SqlxJson))
    .bind(encrypted_credentials)
    .bind(body.enabled.unwrap_or(true))
    .bind(body.config.map(SqlxJson))
    .bind(Utc::now().naive_utc())
    .execute(&state.db)
    .await?;

    let row = fetch_integration(&state, &integration_id)
        .await?
        .ok_or_else(|| ApiError::internal("create_integration", "row vanished after insert"))?;
    Ok((axum::http::StatusCode::CREATED, Json(row.to_json())))
}

async fn fetch_integration(state: &AppState, id: &str) -> Result<Option<IntegrationRow>, ApiError> {
    Ok(sqlx::query_as::<_, IntegrationRow>(
        "SELECT id, provider, name, description, sync_direction, sync_scopes, enabled, config, \
         last_sync_at, created_at FROM vault_cloud_integrations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?)
}

#[derive(Deserialize, Default)]
struct UpdateIntegrationBody {
    name: Option<String>,
    description: Option<String>,
    sync_direction: Option<String>,
    sync_scopes: Option<Value>,
    config: Option<Value>,
    enabled: Option<bool>,
}

async fn update_integration(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    body: Option<Json<UpdateIntegrationBody>>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("sync:admin")?;
    if fetch_integration(&state, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    let body = body.map(|Json(b)| b).unwrap_or_default();
    if let Some(dir) = &body.sync_direction
        && !VALID_DIRECTIONS.contains(&dir.as_str())
    {
        return Err(ApiError::BadRequest("Invalid sync_direction".to_owned()));
    }

    sqlx::query(
        "UPDATE vault_cloud_integrations SET \
         name = COALESCE($1, name), \
         description = COALESCE($2, description), \
         sync_direction = COALESCE($3, sync_direction), \
         sync_scopes = COALESCE($4, sync_scopes), \
         config = COALESCE($5, config), \
         enabled = COALESCE($6, enabled) \
         WHERE id = $7",
    )
    .bind(body.name)
    .bind(body.description)
    .bind(body.sync_direction)
    .bind(body.sync_scopes.map(SqlxJson))
    .bind(body.config.map(SqlxJson))
    .bind(body.enabled)
    .bind(&id)
    .execute(&state.db)
    .await?;

    let row = fetch_integration(&state, &id)
        .await?
        .ok_or_else(|| ApiError::internal("update_integration", "row vanished after update"))?;
    Ok(Json(row.to_json()))
}

async fn delete_integration(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    user.require_scope("sync:admin")?;
    if fetch_integration(&state, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    sqlx::query("DELETE FROM vault_cloud_integrations WHERE id = $1")
        .bind(&id)
        .execute(&state.db)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn trigger_sync(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("sync:admin")?;
    let row = fetch_integration(&state, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Not found".to_owned()))?;
    if !row.enabled {
        return Err(ApiError::Conflict("Integration is disabled".to_owned()));
    }

    publish_sync_event(&state, &id, &row.provider, "manual_trigger").await;

    Ok(Json(json!({
        "integration_id": id,
        "provider": row.provider,
        "status": "sync_queued",
        "queued_at": skauswatch_streams::py_now_isoformat(),
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sync_stream_name_matches_v1_key_shape() {
        assert_eq!(sync_stream_name("aws"), "vault:sync:aws");
    }
}
