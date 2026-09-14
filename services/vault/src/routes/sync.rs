//! `/api/v1/sync` — cloud vault integration management. Rust port of
//! `icebox/services/flask-backend/api/v1/sync.py`. Publishes sync events to
//! Redis Streams for `worker-vault-sync` (see `sync_stream_name`).
//!
//! **Fixes a pre-existing v1 defect** (see
//! `docs/v2-port/phase12-scope-infra.md` §1): v1's `trigger_sync` — and this
//! service's prior 1:1 port of it — published only
//! `{integration_id, event_type, timestamp}`, never the `secret_id`/
//! `secret_name`/`encrypted_value`/`encrypted_dek`/`dek_version` fields
//! `worker-vault-sync`'s `SyncHandler::do_push` requires. Every manual
//! trigger, for every provider including AWS, therefore always failed to
//! decrypt and silently skipped — "full sync parity" was never actually
//! reachable. `trigger_sync` now enumerates the triggering tenant's secrets
//! (see [`scoped_secret_ids`]) and publishes one real, ciphertext-carrying
//! push message per secret. Vault never decrypts here — `encrypted_value`/
//! `encrypted_dek`/`dek_version` are forwarded byte-for-byte from
//! `vault_secrets`, exactly as stored; only `worker-vault-sync` (holding the
//! same envelope MEK) ever decrypts them, preserving envelope encryption
//! end-to-end.

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

/// Publishes one already-built [`skauswatch_streams::EntryFields`] payload to
/// the given provider's sync stream. `None` streams (test states with no
/// Redis wired) log and no-op rather than failing the request — matches v1's
/// fire-and-forget `_publish_sync_event`/`publish` behavior (a manual
/// trigger reports `sync_queued` regardless of whether the publish actually
/// lands, same as before this fix).
async fn publish_fields(state: &AppState, provider: &str, fields: skauswatch_streams::EntryFields) {
    let Some(streams) = &state.streams else {
        tracing::warn!("no stream producer configured — skipping sync event publish");
        return;
    };
    if let Err(e) = streams.publish(&sync_stream_name(provider), fields).await {
        tracing::error!(error = %e, provider, "failed to publish sync event");
    }
}

/// A single secret's ciphertext, as read from `vault_secrets`, ready to be
/// forwarded (never decrypted here — see module doc comment) into a
/// sync-stream push message.
#[derive(sqlx::FromRow, Debug, Clone, PartialEq, Eq)]
struct SecretForSyncRow {
    id: String,
    name: String,
    encrypted_value: String,
    encrypted_dek: String,
    dek_version: i32,
}

/// Builds the `EntryFields` for one `action=push` sync-stream message —
/// matches exactly the field names `worker-vault-sync`'s
/// `SyncHandler::do_push` (`handler.rs`) reads via `msg.get(...)`:
/// `secret_id`, `secret_name`, `encrypted_value`, `encrypted_dek`,
/// `dek_version`, `integration_id`.
fn push_fields(integration_id: &str, secret: &SecretForSyncRow) -> skauswatch_streams::EntryFields {
    vec![
        ("action".to_owned(), "push".to_owned()),
        ("event_type".to_owned(), "manual_trigger".to_owned()),
        ("integration_id".to_owned(), integration_id.to_owned()),
        ("secret_id".to_owned(), secret.id.clone()),
        ("secret_name".to_owned(), secret.name.clone()),
        ("encrypted_value".to_owned(), secret.encrypted_value.clone()),
        ("encrypted_dek".to_owned(), secret.encrypted_dek.clone()),
        ("dek_version".to_owned(), secret.dek_version.to_string()),
        (
            "timestamp".to_owned(),
            skauswatch_streams::py_now_isoformat(),
        ),
    ]
}

/// Extracts an explicit secret-id allowlist from an integration's
/// `sync_scopes` column, if it's a non-empty JSON array of strings.
/// `sync_scopes` was round-tripped through create/update in both v1 and v2
/// but never actually interpreted anywhere — this is the first real
/// consumer. `None` (absent, non-array, or empty array) means "sync every
/// secret this tenant owns", matching the only behavior a bare manual
/// trigger could sensibly have had before any scoping existed.
fn scoped_secret_ids(sync_scopes: Option<&Value>) -> Option<Vec<String>> {
    let ids: Vec<String> = sync_scopes?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    (!ids.is_empty()).then_some(ids)
}

/// Loads the tenant-scoped secrets a manual trigger should push — every
/// tenant secret, or just `scope_ids` when [`scoped_secret_ids`] returned an
/// explicit allowlist. `tenant_id` is always the caller's already-authorized
/// tenant (never trusted from the integration row or request), so this can
/// never cross a tenant boundary.
async fn secrets_for_sync(
    state: &AppState,
    tenant_id: Uuid,
    scope_ids: Option<&[String]>,
) -> Result<Vec<SecretForSyncRow>, ApiError> {
    let rows =
        match scope_ids {
            Some(ids) if !ids.is_empty() => sqlx::query_as::<_, SecretForSyncRow>(
                "SELECT id, name, encrypted_value, encrypted_dek, dek_version FROM vault_secrets \
                 WHERE tenant_id = $1 AND id = ANY($2) ORDER BY id",
            )
            .bind(tenant_id)
            .bind(ids)
            .fetch_all(&state.db)
            .await?,
            _ => sqlx::query_as::<_, SecretForSyncRow>(
                "SELECT id, name, encrypted_value, encrypted_dek, dek_version FROM vault_secrets \
                 WHERE tenant_id = $1 ORDER BY id",
            )
            .bind(tenant_id)
            .fetch_all(&state.db)
            .await?,
        };
    Ok(rows)
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
    /// Number of `action=push` messages actually published — one per
    /// matched secret. `0` for a `cloud_to_vault`-only integration (no push
    /// leg exists) or when the tenant has no secrets in scope.
    secrets_queued: i64,
    queued_at: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/sync/integrations/{id}/trigger",
    tag = "sync",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Integration id")),
    responses(
        (status = 200, description = "Sync event(s) published to worker-vault-sync, one per in-scope secret", body = TriggerSyncResponse),
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
    let tenant_id = user.tenant_uuid()?;
    let row = fetch_integration(&state, tenant_id, &id)
        .await?
        .ok_or_else(|| ApiError::NotFound("Not found".to_owned()))?;
    if !row.enabled {
        return Err(ApiError::Conflict("Integration is disabled".to_owned()));
    }

    // `cloud_to_vault` is pull-only — there is no push leg to queue, and the
    // cloud→vault pull direction has never been wired to a poll loop in
    // either version (see `providers/mod.rs` doc comment). Publishing an
    // empty push for it would just reproduce the old no-payload bug under a
    // different name.
    let secrets_queued = if row.sync_direction == "cloud_to_vault" {
        tracing::debug!(
            integration_id = %id,
            "cloud_to_vault direction has no push leg — nothing to queue"
        );
        0i64
    } else {
        let scope_ids = scoped_secret_ids(row.sync_scopes.as_ref().map(|j| &j.0));
        let secrets = secrets_for_sync(&state, tenant_id, scope_ids.as_deref()).await?;
        for secret in &secrets {
            publish_fields(&state, &row.provider, push_fields(&id, secret)).await;
        }
        secrets.len() as i64
    };

    Ok(Json(json!({
        "integration_id": id,
        "provider": row.provider,
        "status": "sync_queued",
        "secrets_queued": secrets_queued,
        "queued_at": skauswatch_streams::py_now_isoformat(),
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::collections::HashMap;

    use axum_test::TestServer;
    use fred::interfaces::{ClientLike, StreamsInterface};
    use skauswatch_testkit::license::dev_license;
    use skauswatch_vault::EnvelopeEncryption;

    use super::*;
    use crate::routes::test_support::{
        TEST_TENANT, db_state, db_state_with_streams, sign_token, test_envelope,
    };

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

    // ── payload-plumbing fix (docs/v2-port/phase12-scope-infra.md §1) ──────

    fn sample_secret() -> SecretForSyncRow {
        SecretForSyncRow {
            id: "secret-1".to_owned(),
            name: "db-password".to_owned(),
            encrypted_value: "ciphertext-blob".to_owned(),
            encrypted_dek: "dek-blob".to_owned(),
            dek_version: 3,
        }
    }

    #[test]
    fn push_fields_carries_the_real_secret_payload_worker_do_push_expects() {
        // Before this fix, `trigger_sync` published only
        // `{integration_id, event_type, timestamp}` — `secret_id`,
        // `secret_name`, `encrypted_value`, `encrypted_dek`, and
        // `dek_version` were entirely absent, so `SyncHandler::do_push`
        // always failed to decrypt (see module doc comment). This proves
        // every field it reads via `msg.get(...)` is now present.
        let fields = push_fields("int-1", &sample_secret());
        let map: HashMap<&str, &str> = fields
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(map.get("action"), Some(&"push"));
        assert_eq!(map.get("integration_id"), Some(&"int-1"));
        assert_eq!(map.get("secret_id"), Some(&"secret-1"));
        assert_eq!(map.get("secret_name"), Some(&"db-password"));
        assert_eq!(map.get("encrypted_value"), Some(&"ciphertext-blob"));
        assert_eq!(map.get("encrypted_dek"), Some(&"dek-blob"));
        assert_eq!(map.get("dek_version"), Some(&"3"));
        assert!(map.contains_key("timestamp"));
    }

    #[test]
    fn scoped_secret_ids_extracts_a_non_empty_string_array() {
        let scopes = json!(["secret-a", "secret-b"]);
        assert_eq!(
            scoped_secret_ids(Some(&scopes)),
            Some(vec!["secret-a".to_owned(), "secret-b".to_owned()])
        );
    }

    #[test]
    fn scoped_secret_ids_ignores_non_string_array_entries() {
        let scopes = json!(["secret-a", 5, null]);
        assert_eq!(
            scoped_secret_ids(Some(&scopes)),
            Some(vec!["secret-a".to_owned()])
        );
    }

    #[test]
    fn scoped_secret_ids_returns_none_for_absent_empty_or_non_array_scopes() {
        assert_eq!(scoped_secret_ids(None), None);
        assert_eq!(scoped_secret_ids(Some(&json!([]))), None);
        assert_eq!(scoped_secret_ids(Some(&json!({"not": "an array"}))), None);
        assert_eq!(scoped_secret_ids(Some(&Value::Null)), None);
    }

    async fn seed_secret(
        pool: &sqlx::PgPool,
        id: &str,
        tenant_id: Uuid,
        name: &str,
        envelope: &EnvelopeEncryption,
        plaintext: &str,
    ) {
        let (encrypted_value, encrypted_dek, dek_version) =
            envelope.encrypt(plaintext).expect("encrypt secret value");
        sqlx::query(
            "INSERT INTO vault_secrets (id, tenant_id, name, description, secret_type, \
             encrypted_value, encrypted_dek, dek_version, created_at, updated_at) \
             VALUES ($1,$2,$3,'','api_key',$4,$5,$6,now(),now())",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(&encrypted_value)
        .bind(&encrypted_dek)
        .bind(dek_version as i32)
        .execute(pool)
        .await
        .expect("seed secret");
    }

    #[tokio::test]
    async fn secrets_for_sync_scopes_to_tenant_and_honors_explicit_allowlist() {
        let state = db_state(dev_license("skauswatch")).await;
        let envelope = test_envelope();
        let tenant_a: Uuid = TEST_TENANT.parse().expect("uuid");
        let tenant_b: Uuid = crate::routes::test_support::OTHER_TENANT
            .parse()
            .expect("uuid");
        seed_secret(&state.db, "s-a1", tenant_a, "a1", &envelope, "va1").await;
        seed_secret(&state.db, "s-a2", tenant_a, "a2", &envelope, "va2").await;
        seed_secret(&state.db, "s-b1", tenant_b, "b1", &envelope, "vb1").await;

        // No scope filter — every one of tenant A's secrets, never tenant B's.
        let all_a = secrets_for_sync(&state, tenant_a, None)
            .await
            .expect("query");
        assert_eq!(
            all_a.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
            vec!["s-a1".to_owned(), "s-a2".to_owned()]
        );

        // Explicit allowlist restricts to just the named secret, still
        // tenant-scoped — tenant A can never pull in tenant B's id even if
        // named explicitly.
        let scoped = secrets_for_sync(
            &state,
            tenant_a,
            Some(&["s-a1".to_owned(), "s-b1".to_owned()]),
        )
        .await
        .expect("query");
        assert_eq!(
            scoped.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
            vec!["s-a1".to_owned()]
        );
    }

    fn redis_url() -> String {
        std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379/0".to_owned())
    }

    fn unique_prefix() -> String {
        format!("vaulttest:{}", Uuid::new_v4().simple())
    }

    async fn raw_redis_client() -> fred::clients::Client {
        let config = fred::types::config::Config::from_url(&redis_url()).expect("valid redis url");
        let client = fred::types::Builder::from_config(config)
            .build()
            .expect("build client");
        client.init().await.expect("connect");
        client
    }

    async fn stream_entries(
        client: &fred::clients::Client,
        prefix: &str,
        stream: &str,
    ) -> Vec<(String, HashMap<String, String>)> {
        let key = skauswatch_streams::prefixed_key(prefix, stream);
        client
            .xrange_values(key, "-", "+", None)
            .await
            .expect("xrange")
    }

    /// The end-to-end regression test for the payload-plumbing bug: drives
    /// `trigger_sync` through the real HTTP router against a real Redis
    /// (`REDIS_URL`, always available alongside Postgres in this repo's
    /// test/verify environment — see `docs/v2-port/phase12-scope-infra.md`
    /// §1), then reads the raw stream entry back and decrypts it with the
    /// same envelope `worker-vault-sync` would use. Before this fix, no
    /// `secret_id`/`encrypted_value`/`encrypted_dek`/`dek_version` field
    /// existed on the published entry at all; this proves not just their
    /// presence but that they decrypt to the exact original plaintext, i.e.
    /// a real secret now actually reaches the point a cloud provider would
    /// receive it (`worker-vault-sync`'s own `handler.rs` tests separately
    /// prove that, given exactly this field shape, `SyncHandler::do_push`
    /// decrypts and successfully calls the provider).
    #[tokio::test]
    async fn trigger_sync_publishes_a_real_decryptable_secret_payload_to_the_stream() {
        let prefix = unique_prefix();
        let streams = skauswatch_streams::StreamProducer::connect(&redis_url(), None, &prefix)
            .await
            .expect("connect stream producer");
        let state = db_state_with_streams(dev_license("skauswatch"), streams).await;

        let envelope = test_envelope();
        let tenant_id: Uuid = TEST_TENANT.parse().expect("uuid");
        seed_secret(
            &state.db,
            "secret-real-1",
            tenant_id,
            "db-password",
            &envelope,
            "hunter2",
        )
        .await;

        let admin = sign_token(&state, "u", "sync:admin");
        let server = test_server_with_state(state.clone());

        let created = server
            .post("/api/v1/sync/integrations")
            .authorization_bearer(&admin)
            .json(&json!({"provider": "aws", "name": "real-payload-test"}))
            .await;
        created.assert_status(axum::http::StatusCode::CREATED);
        let integration_id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let triggered = server
            .post(&format!(
                "/api/v1/sync/integrations/{integration_id}/trigger"
            ))
            .authorization_bearer(&admin)
            .await;
        triggered.assert_status_ok();
        assert_eq!(triggered.json::<Value>()["secrets_queued"], 1);

        let client = raw_redis_client().await;
        let entries = stream_entries(&client, &prefix, "vault:sync:aws").await;
        assert_eq!(entries.len(), 1, "exactly one push message published");
        let (_id, fields) = &entries[0];

        assert_eq!(fields.get("action").map(String::as_str), Some("push"));
        assert_eq!(
            fields.get("integration_id").map(String::as_str),
            Some(integration_id.as_str())
        );
        assert_eq!(
            fields.get("secret_id").map(String::as_str),
            Some("secret-real-1")
        );
        assert_eq!(
            fields.get("secret_name").map(String::as_str),
            Some("db-password")
        );

        let encrypted_value = fields
            .get("encrypted_value")
            .expect("encrypted_value present");
        let encrypted_dek = fields.get("encrypted_dek").expect("encrypted_dek present");
        let dek_version: u32 = fields
            .get("dek_version")
            .expect("dek_version present")
            .parse()
            .expect("numeric dek_version");
        assert!(!encrypted_value.is_empty());
        assert!(!encrypted_dek.is_empty());

        let plaintext = envelope
            .decrypt(encrypted_value, encrypted_dek, dek_version)
            .expect("decrypt the forwarded ciphertext with the same envelope MEK");
        assert_eq!(plaintext, "hunter2");
    }

    #[tokio::test]
    async fn trigger_sync_queues_zero_for_cloud_to_vault_only_direction() {
        // No push leg exists for a pull-only integration — must not
        // reproduce the old bug's shape (an empty/placeholder push message)
        // under a new name.
        let prefix = unique_prefix();
        let streams = skauswatch_streams::StreamProducer::connect(&redis_url(), None, &prefix)
            .await
            .expect("connect stream producer");
        let state = db_state_with_streams(dev_license("skauswatch"), streams).await;
        let envelope = test_envelope();
        let tenant_id: Uuid = TEST_TENANT.parse().expect("uuid");
        seed_secret(&state.db, "s-pull", tenant_id, "n", &envelope, "v").await;

        let admin = sign_token(&state, "u", "sync:admin");
        let server = test_server_with_state(state.clone());

        let created = server
            .post("/api/v1/sync/integrations")
            .authorization_bearer(&admin)
            .json(&json!({
                "provider": "aws", "name": "pull-only", "sync_direction": "cloud_to_vault",
            }))
            .await;
        let integration_id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let triggered = server
            .post(&format!(
                "/api/v1/sync/integrations/{integration_id}/trigger"
            ))
            .authorization_bearer(&admin)
            .await;
        triggered.assert_status_ok();
        assert_eq!(triggered.json::<Value>()["secrets_queued"], 0);

        let client = raw_redis_client().await;
        let entries = stream_entries(&client, &prefix, "vault:sync:aws").await;
        assert!(
            entries.is_empty(),
            "no push message should be published for a pull-only integration"
        );
    }

    #[tokio::test]
    async fn trigger_sync_honors_sync_scopes_allowlist_end_to_end() {
        let prefix = unique_prefix();
        let streams = skauswatch_streams::StreamProducer::connect(&redis_url(), None, &prefix)
            .await
            .expect("connect stream producer");
        let state = db_state_with_streams(dev_license("skauswatch"), streams).await;
        let envelope = test_envelope();
        let tenant_id: Uuid = TEST_TENANT.parse().expect("uuid");
        seed_secret(&state.db, "s-in-scope", tenant_id, "in", &envelope, "v-in").await;
        seed_secret(
            &state.db,
            "s-out-of-scope",
            tenant_id,
            "out",
            &envelope,
            "v-out",
        )
        .await;

        let admin = sign_token(&state, "u", "sync:admin");
        let server = test_server_with_state(state.clone());

        let created = server
            .post("/api/v1/sync/integrations")
            .authorization_bearer(&admin)
            .json(&json!({
                "provider": "aws", "name": "scoped", "sync_scopes": ["s-in-scope"],
            }))
            .await;
        let integration_id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let triggered = server
            .post(&format!(
                "/api/v1/sync/integrations/{integration_id}/trigger"
            ))
            .authorization_bearer(&admin)
            .await;
        triggered.assert_status_ok();
        assert_eq!(triggered.json::<Value>()["secrets_queued"], 1);

        let client = raw_redis_client().await;
        let entries = stream_entries(&client, &prefix, "vault:sync:aws").await;
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].1.get("secret_id").map(String::as_str),
            Some("s-in-scope")
        );
    }
}
