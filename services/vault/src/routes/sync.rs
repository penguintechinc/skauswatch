//! `/api/v1/sync` — cloud vault integration management. Rust port of
//! `icebox/services/flask-backend/api/v1/sync.py`. Publishes sync events to
//! Redis Streams for `worker-vault-sync` (see `sync_stream_name`).

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::types::Json as SqlxJson;
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse, InsufficientScopeResponse};
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

/// Documentation-only mirror of `IntegrationRow::to_json`'s wire shape —
/// never includes `encrypted_credentials`.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SyncIntegrationResponse {
    id: String,
    provider: String,
    name: String,
    description: Option<String>,
    sync_direction: String,
    sync_scopes: Option<Value>,
    enabled: bool,
    config: Option<Value>,
    last_sync_at: Option<String>,
    created_at: String,
}

/// Documentation-only mirror of `list_integrations`'s response envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SyncIntegrationListResponse {
    integrations: Vec<SyncIntegrationResponse>,
}

#[utoipa::path(
    get,
    path = "/api/v1/sync/integrations",
    tag = "sync",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Configured cloud vault integrations (credentials never included)", body = SyncIntegrationListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires sync:read)", body = InsufficientScopeResponse),
    ),
)]
pub(crate) async fn list_integrations(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("sync:read")?;
    let rows = sqlx::query_as::<_, IntegrationRow>(
        "SELECT id, provider, name, description, sync_direction, sync_scopes, enabled, config, \
         last_sync_at, created_at FROM vault_cloud_integrations WHERE tenant_id = $1 \
         ORDER BY name",
    )
    .bind(user.tenant_uuid()?)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(json!({
        "integrations": rows.iter().map(IntegrationRow::to_json).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateIntegrationBody {
    provider: Option<String>,
    name: Option<String>,
    description: Option<String>,
    sync_direction: Option<String>,
    sync_scopes: Option<Value>,
    /// Provider credentials — encrypted at rest immediately, never
    /// returned by any response.
    credentials: Option<Value>,
    enabled: Option<bool>,
    config: Option<Value>,
}

#[utoipa::path(
    post,
    path = "/api/v1/sync/integrations",
    tag = "sync",
    security(("bearer_jwt" = [])),
    request_body = CreateIntegrationBody,
    responses(
        (status = 201, description = "Integration created", body = SyncIntegrationResponse),
        (status = 400, description = "Invalid provider, missing name, or invalid sync_direction", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires sync:admin)", body = InsufficientScopeResponse),
    ),
)]
pub(crate) async fn create_integration(
    State(state): State<AppState>,
    user: CurrentUser,
    Json(body): Json<CreateIntegrationBody>,
) -> Result<(axum::http::StatusCode, Json<Value>), ApiError> {
    user.require_scope("sync:admin")?;
    let tenant_id = user.tenant_uuid()?;

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
        "INSERT INTO vault_cloud_integrations (id, tenant_id, provider, name, description, \
         sync_direction, sync_scopes, encrypted_credentials, enabled, config, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    )
    .bind(&integration_id)
    .bind(tenant_id)
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

    let row = fetch_integration(&state, tenant_id, &integration_id)
        .await?
        .ok_or_else(|| ApiError::internal("create_integration", "row vanished after insert"))?;
    Ok((axum::http::StatusCode::CREATED, Json(row.to_json())))
}

async fn fetch_integration(
    state: &AppState,
    tenant_id: Uuid,
    id: &str,
) -> Result<Option<IntegrationRow>, ApiError> {
    Ok(sqlx::query_as::<_, IntegrationRow>(
        "SELECT id, provider, name, description, sync_direction, sync_scopes, enabled, config, \
         last_sync_at, created_at FROM vault_cloud_integrations WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await?)
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct UpdateIntegrationBody {
    name: Option<String>,
    description: Option<String>,
    sync_direction: Option<String>,
    sync_scopes: Option<Value>,
    config: Option<Value>,
    enabled: Option<bool>,
}

#[utoipa::path(
    put,
    path = "/api/v1/sync/integrations/{id}",
    tag = "sync",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Integration id")),
    request_body = UpdateIntegrationBody,
    responses(
        (status = 200, description = "Updated integration", body = SyncIntegrationResponse),
        (status = 400, description = "Invalid sync_direction", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires sync:admin)", body = InsufficientScopeResponse),
        (status = 404, description = "Integration not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_integration(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
    body: Option<Json<UpdateIntegrationBody>>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("sync:admin")?;
    let tenant_id = user.tenant_uuid()?;
    if fetch_integration(&state, tenant_id, &id).await?.is_none() {
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
         WHERE id = $7 AND tenant_id = $8",
    )
    .bind(body.name)
    .bind(body.description)
    .bind(body.sync_direction)
    .bind(body.sync_scopes.map(SqlxJson))
    .bind(body.config.map(SqlxJson))
    .bind(body.enabled)
    .bind(&id)
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    let row = fetch_integration(&state, tenant_id, &id)
        .await?
        .ok_or_else(|| ApiError::internal("update_integration", "row vanished after update"))?;
    Ok(Json(row.to_json()))
}

#[utoipa::path(
    delete,
    path = "/api/v1/sync/integrations/{id}",
    tag = "sync",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Integration id")),
    responses(
        (status = 204, description = "Integration deleted"),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires sync:admin)", body = InsufficientScopeResponse),
        (status = 404, description = "Integration not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn delete_integration(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> Result<axum::http::StatusCode, ApiError> {
    user.require_scope("sync:admin")?;
    let tenant_id = user.tenant_uuid()?;
    if fetch_integration(&state, tenant_id, &id).await?.is_none() {
        return Err(ApiError::NotFound("Not found".to_owned()));
    }
    sqlx::query("DELETE FROM vault_cloud_integrations WHERE id = $1 AND tenant_id = $2")
        .bind(&id)
        .bind(tenant_id)
        .execute(&state.db)
        .await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Documentation-only mirror of `trigger_sync`'s response envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct TriggerSyncResponse {
    integration_id: String,
    provider: String,
    /// Always `"sync_queued"`.
    status: String,
    queued_at: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/sync/integrations/{id}/trigger",
    tag = "sync",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Integration id")),
    responses(
        (status = 200, description = "Sync event published to worker-vault-sync", body = TriggerSyncResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires sync:admin)", body = InsufficientScopeResponse),
        (status = 404, description = "Integration not found", body = ErrorResponse),
        (status = 409, description = "Integration is disabled", body = ErrorResponse),
    ),
)]
pub(crate) async fn trigger_sync(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("sync:admin")?;
    let row = fetch_integration(&state, user.tenant_uuid()?, &id)
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
    use axum_test::TestServer;
    use skauswatch_testkit::license::dev_license;

    use super::*;
    use crate::routes::test_support::{db_state, sign_token};

    #[test]
    fn sync_stream_name_matches_v1_key_shape() {
        assert_eq!(sync_stream_name("aws"), "vault:sync:aws");
    }

    fn test_server_with_state(state: crate::state::AppState) -> TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        TestServer::new(app)
    }

    #[tokio::test]
    async fn list_requires_sync_read_scope() {
        let state = db_state(dev_license("skauswatch")).await;
        let token = sign_token(&state, "u", "secrets:read");
        let server = test_server_with_state(state);
        server
            .get("/api/v1/sync/integrations")
            .authorization_bearer(&token)
            .await
            .assert_status(axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_is_empty_against_a_fresh_db() {
        let state = db_state(dev_license("skauswatch")).await;
        let token = sign_token(&state, "u", "sync:read");
        let server = test_server_with_state(state);
        let resp = server
            .get("/api/v1/sync/integrations")
            .authorization_bearer(&token)
            .await;
        resp.assert_status_ok();
        assert_eq!(resp.json::<Value>()["integrations"], json!([]));
    }

    #[tokio::test]
    async fn create_validates_provider_name_and_direction() {
        let state = db_state(dev_license("skauswatch")).await;
        let token = sign_token(&state, "u", "sync:admin");
        let server = test_server_with_state(state);

        server
            .post("/api/v1/sync/integrations")
            .authorization_bearer(&token)
            .json(&json!({"provider": "bogus", "name": "n"}))
            .await
            .assert_status(axum::http::StatusCode::BAD_REQUEST);

        server
            .post("/api/v1/sync/integrations")
            .authorization_bearer(&token)
            .json(&json!({"provider": "aws", "name": ""}))
            .await
            .assert_status(axum::http::StatusCode::BAD_REQUEST);

        server
            .post("/api/v1/sync/integrations")
            .authorization_bearer(&token)
            .json(&json!({"provider": "aws", "name": "n", "sync_direction": "bogus"}))
            .await
            .assert_status(axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_list_update_and_delete_round_trip() {
        let state = db_state(dev_license("skauswatch")).await;
        let admin = sign_token(&state, "u", "sync:admin");
        let reader = sign_token(&state, "u", "sync:read");
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/sync/integrations")
            .authorization_bearer(&admin)
            .json(&json!({
                "provider": "AWS",
                "name": "prod-secrets-manager",
                "sync_direction": "bidirectional",
                "credentials": {"access_key": "AKIA...", "secret_key": "shh"},
                "config": {"region": "us-east-1"},
            }))
            .await;
        created.assert_status(axum::http::StatusCode::CREATED);
        let created_body: Value = created.json();
        assert_eq!(created_body["provider"], "aws");
        assert_eq!(created_body["enabled"], true);
        assert!(created_body.get("encrypted_credentials").is_none());
        let id = created_body["id"].as_str().unwrap_or_default().to_owned();

        let listed = server
            .get("/api/v1/sync/integrations")
            .authorization_bearer(&reader)
            .await;
        assert_eq!(
            listed.json::<Value>()["integrations"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );

        let updated = server
            .put(&format!("/api/v1/sync/integrations/{id}"))
            .authorization_bearer(&admin)
            .json(&json!({"name": "renamed", "enabled": false}))
            .await;
        updated.assert_status_ok();
        let updated_body: Value = updated.json();
        assert_eq!(updated_body["name"], "renamed");
        assert_eq!(updated_body["enabled"], false);

        let bad_direction = server
            .put(&format!("/api/v1/sync/integrations/{id}"))
            .authorization_bearer(&admin)
            .json(&json!({"sync_direction": "bogus"}))
            .await;
        bad_direction.assert_status(axum::http::StatusCode::BAD_REQUEST);

        let missing_update = server
            .put("/api/v1/sync/integrations/does-not-exist")
            .authorization_bearer(&admin)
            .json(&json!({}))
            .await;
        missing_update.assert_status(axum::http::StatusCode::NOT_FOUND);

        let deleted = server
            .delete(&format!("/api/v1/sync/integrations/{id}"))
            .authorization_bearer(&admin)
            .await;
        deleted.assert_status(axum::http::StatusCode::NO_CONTENT);

        let missing_delete = server
            .delete(&format!("/api/v1/sync/integrations/{id}"))
            .authorization_bearer(&admin)
            .await;
        missing_delete.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn trigger_sync_requires_enabled_integration() {
        let state = db_state(dev_license("skauswatch")).await;
        let admin = sign_token(&state, "u", "sync:admin");
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/sync/integrations")
            .authorization_bearer(&admin)
            .json(&json!({"provider": "gcp", "name": "n", "enabled": false}))
            .await;
        let id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let disabled = server
            .post(&format!("/api/v1/sync/integrations/{id}/trigger"))
            .authorization_bearer(&admin)
            .await;
        disabled.assert_status(axum::http::StatusCode::CONFLICT);

        let enabled = server
            .put(&format!("/api/v1/sync/integrations/{id}"))
            .authorization_bearer(&admin)
            .json(&json!({"enabled": true}))
            .await;
        enabled.assert_status_ok();

        let triggered = server
            .post(&format!("/api/v1/sync/integrations/{id}/trigger"))
            .authorization_bearer(&admin)
            .await;
        triggered.assert_status_ok();
        assert_eq!(triggered.json::<Value>()["status"], "sync_queued");

        let missing = server
            .post("/api/v1/sync/integrations/does-not-exist/trigger")
            .authorization_bearer(&admin)
            .await;
        missing.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn tenant_isolation_across_list_update_delete_and_trigger() {
        use crate::routes::test_support::{OTHER_TENANT, sign_token_for_tenant};

        let state = db_state(dev_license("skauswatch")).await;
        let tenant_a_admin = sign_token(&state, "u", "sync:admin sync:read");
        let tenant_b_admin =
            sign_token_for_tenant(&state, "u", "sync:admin sync:read", OTHER_TENANT);
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/sync/integrations")
            .authorization_bearer(&tenant_a_admin)
            .json(&json!({"provider": "aws", "name": "tenant-a-integration"}))
            .await;
        created.assert_status(axum::http::StatusCode::CREATED);
        let id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let listed = server
            .get("/api/v1/sync/integrations")
            .authorization_bearer(&tenant_b_admin)
            .await;
        assert_eq!(listed.json::<Value>()["integrations"], json!([]));

        server
            .put(&format!("/api/v1/sync/integrations/{id}"))
            .authorization_bearer(&tenant_b_admin)
            .json(&json!({"name": "hijacked"}))
            .await
            .assert_status(axum::http::StatusCode::NOT_FOUND);
        server
            .post(&format!("/api/v1/sync/integrations/{id}/trigger"))
            .authorization_bearer(&tenant_b_admin)
            .await
            .assert_status(axum::http::StatusCode::NOT_FOUND);
        server
            .delete(&format!("/api/v1/sync/integrations/{id}"))
            .authorization_bearer(&tenant_b_admin)
            .await
            .assert_status(axum::http::StatusCode::NOT_FOUND);

        // Untouched by tenant B's attempts.
        let still_there = server
            .get("/api/v1/sync/integrations")
            .authorization_bearer(&tenant_a_admin)
            .await;
        assert_eq!(
            still_there.json::<Value>()["integrations"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }
}
