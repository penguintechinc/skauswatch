//! `/api/v1/one-time-secrets` — self-destructing shared secrets. Rust port
//! of `icebox/services/flask-backend/api/v1/one_time.py`.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse, InsufficientScopeResponse};
use crate::state::AppState;

/// Router for `/api/v1/one-time-secrets`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/one-time-secrets", post(create_one_time_secret))
        .route("/one-time-secrets/{token}", get(retrieve_one_time_secret))
}

/// URL-safe base64 (no padding) token, matching Python's
/// `secrets.token_urlsafe(32)` (32 random bytes → ~43 url-safe chars).
fn generate_token() -> (String, String) {
    let raw = skauswatch_vault::random_32_bytes();
    let token = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, raw);
    let hash = {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher.finalize()
    };
    let hash_hex = hash.iter().map(|b| format!("{b:02x}")).collect::<String>();
    (token, hash_hex)
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateBody {
    /// Plaintext value to share — encrypted at rest immediately, never
    /// persisted or logged unencrypted.
    value: Option<String>,
    /// Time-to-live in seconds; must be between 60 and 604800 (7 days).
    /// Defaults to 86400 (24h).
    ttl_seconds: Option<i64>,
}

/// Documentation-only mirror of `create_one_time_secret`'s response
/// envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OneTimeCreateResponse {
    id: String,
    /// Path to retrieve the secret exactly once — the webui/ingress owns
    /// the scheme and host it's reachable at.
    view_url: String,
    expires_at: String,
    ttl_seconds: i64,
}

#[utoipa::path(
    post,
    path = "/api/v1/one-time-secrets",
    tag = "one-time-secrets",
    security(("bearer_jwt" = [])),
    request_body = CreateBody,
    responses(
        (status = 201, description = "One-time secret created", body = OneTimeCreateResponse),
        (status = 400, description = "Missing value or ttl_seconds out of the 60..=604800 range", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires secrets:write)", body = InsufficientScopeResponse),
    ),
)]
pub(crate) async fn create_one_time_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    body: Option<Json<CreateBody>>,
) -> Result<(axum::http::StatusCode, Json<Value>), ApiError> {
    user.require_scope("secrets:write")?;
    let tenant_id = user.tenant_uuid()?;

    let body = body.map(|Json(b)| b).unwrap_or(CreateBody {
        value: None,
        ttl_seconds: None,
    });
    let value = body.value.unwrap_or_default().trim().to_owned();
    if value.is_empty() {
        return Err(ApiError::BadRequest("value is required".to_owned()));
    }
    let ttl_seconds = body.ttl_seconds.unwrap_or(86_400);
    if !(60..=604_800).contains(&ttl_seconds) {
        return Err(ApiError::BadRequest(
            "ttl_seconds must be between 60 and 604800".to_owned(),
        ));
    }

    let (encrypted_value, encrypted_dek, dek_version) =
        state.envelope.read().await.encrypt(&value)?;
    let (token, token_hash) = generate_token();
    let secret_id = Uuid::new_v4().to_string();
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds);

    sqlx::query(
        "INSERT INTO vault_one_time_secrets (id, tenant_id, token_hash, encrypted_value, \
         encrypted_dek, dek_version, expires_at, created_by, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(&secret_id)
    .bind(tenant_id)
    .bind(&token_hash)
    .bind(&encrypted_value)
    .bind(&encrypted_dek)
    .bind(dek_version as i32)
    .bind(expires_at.naive_utc())
    .bind(&user.user_id)
    .bind(Utc::now().naive_utc())
    .execute(&state.db)
    .await?;

    // v1 builds the view URL from the inbound request host; the Rust port
    // publishes the token path only — the webui/ingress owns the scheme and
    // host it's actually reachable at, which the backend cannot know
    // reliably behind a Gateway/ingress tier.
    let view_path = format!("/api/v1/one-time-secrets/{token}");

    Ok((
        axum::http::StatusCode::CREATED,
        Json(json!({
            "id": secret_id,
            "view_url": view_path,
            "expires_at": skauswatch_streams::py_isoformat(expires_at.naive_utc()),
            "ttl_seconds": ttl_seconds,
        })),
    ))
}

#[derive(sqlx::FromRow)]
struct OneTimeRow {
    encrypted_value: String,
    encrypted_dek: String,
    dek_version: i32,
    expires_at: chrono::NaiveDateTime,
    viewed_at: Option<chrono::NaiveDateTime>,
}

/// Documentation-only mirror of `retrieve_one_time_secret`'s response
/// envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct OneTimeValueResponse {
    /// The decrypted one-time value — never populated with example data in
    /// the generated schema.
    value: String,
    retrieved_at: String,
}

/// Deliberately **no** `security(...)` clause — unlike every other route in
/// this service, this endpoint has no bearer-token auth at all by design:
/// the URL-embedded, single-use token *is* the credential (v1 parity). Not
/// an oversight; see `docs/v2-port/openapi-pattern.md` step 2.
#[utoipa::path(
    get,
    path = "/api/v1/one-time-secrets/{token}",
    tag = "one-time-secrets",
    params(("token" = String, Path, description = "URL-safe single-use retrieval token")),
    responses(
        (status = 200, description = "Decrypted value; the token is now consumed and cannot be reused", body = OneTimeValueResponse),
        (status = 404, description = "Unknown token", body = ErrorResponse),
        (status = 410, description = "Secret already viewed or expired", body = ErrorResponse),
    ),
)]
/// Deliberately **not** filtered by `tenant_id`: this route has no
/// `CurrentUser` (see the doc comment above) so there is no validated
/// tenant claim to filter on. This is a documented exception to "every
/// query filters on tenant_id, no exceptions" — the URL-embedded token
/// (32 cryptographically random bytes, SHA-256-hashed, globally unique by
/// construction) is already the *complete* credential; a tenant filter
/// would add no isolation value on top of it, since possessing the token
/// already proves authorization regardless of tenant. `tenant_id` is still
/// stamped on the row at creation (`create_one_time_secret`) for audit/
/// listing purposes, just never consulted on this read path.
pub(crate) async fn retrieve_one_time_secret(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let token_hash = {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };

    let row = sqlx::query_as::<_, OneTimeRow>(
        "SELECT encrypted_value, encrypted_dek, dek_version, expires_at, viewed_at \
         FROM vault_one_time_secrets WHERE token_hash = $1",
    )
    .bind(&token_hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Not found".to_owned()))?;

    if row.expires_at < Utc::now().naive_utc() {
        return Err(ApiError::Gone("This secret has expired".to_owned()));
    }
    if row.viewed_at.is_some() {
        return Err(ApiError::Gone(
            "This secret has already been viewed".to_owned(),
        ));
    }

    // Atomic claim: only the request that flips `viewed_at` from NULL may
    // proceed to decrypt/return the value (v1's race-safe UPDATE ... WHERE
    // viewed_at IS NULL, guarded by the DB rather than app-level locking).
    let claimed = sqlx::query(
        "UPDATE vault_one_time_secrets SET viewed_at = $1 \
         WHERE token_hash = $2 AND viewed_at IS NULL",
    )
    .bind(Utc::now().naive_utc())
    .bind(&token_hash)
    .execute(&state.db)
    .await?;

    if claimed.rows_affected() == 0 {
        return Err(ApiError::Gone(
            "This secret has already been viewed".to_owned(),
        ));
    }

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
            tracing::error!(error = %e, "decryption failed for one-time secret");
            ApiError::Internal
        })?;

    Ok(Json(json!({
        "value": plaintext,
        "retrieved_at": skauswatch_streams::py_now_isoformat(),
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
    fn generate_token_produces_distinct_url_safe_tokens_with_matching_hash() {
        let (t1, h1) = generate_token();
        let (t2, _h2) = generate_token();
        assert_ne!(t1, t2);
        assert!(!t1.contains('+') && !t1.contains('/') && !t1.contains('='));
        let mut hasher = Sha256::new();
        hasher.update(t1.as_bytes());
        let expect = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        assert_eq!(h1, expect);
    }

    fn test_server_with_state(state: crate::state::AppState) -> TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        TestServer::new(app)
    }

    #[tokio::test]
    async fn create_requires_write_scope() {
        let state = db_state(dev_license("skauswatch")).await;
        let token = sign_token(&state, "u", "secrets:read");
        let server = test_server_with_state(state);
        let resp = server
            .post("/api/v1/one-time-secrets")
            .authorization_bearer(&token)
            .json(&json!({"value": "v"}))
            .await;
        resp.assert_status(axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_validates_value_and_ttl() {
        let state = db_state(dev_license("skauswatch")).await;
        let token = sign_token(&state, "u", "secrets:write");
        let server = test_server_with_state(state);

        server
            .post("/api/v1/one-time-secrets")
            .authorization_bearer(&token)
            .json(&json!({"value": ""}))
            .await
            .assert_status(axum::http::StatusCode::BAD_REQUEST);

        server
            .post("/api/v1/one-time-secrets")
            .authorization_bearer(&token)
            .json(&json!({"value": "v", "ttl_seconds": 1}))
            .await
            .assert_status(axum::http::StatusCode::BAD_REQUEST);

        server
            .post("/api/v1/one-time-secrets")
            .authorization_bearer(&token)
            .json(&json!({"value": "v", "ttl_seconds": 999_999_999}))
            .await
            .assert_status(axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_and_retrieve_round_trip_then_single_use_enforced() {
        let state = db_state(dev_license("skauswatch")).await;
        let token = sign_token(&state, "u", "secrets:write");
        let server = test_server_with_state(state);

        let created = server
            .post("/api/v1/one-time-secrets")
            .authorization_bearer(&token)
            .json(&json!({"value": "share-me-once", "ttl_seconds": 300}))
            .await;
        created.assert_status(axum::http::StatusCode::CREATED);
        let created_body: Value = created.json();
        let view_path = created_body["view_url"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let one_time_token = view_path.rsplit('/').next().unwrap_or_default().to_owned();

        let first = server
            .get(&format!("/api/v1/one-time-secrets/{one_time_token}"))
            .await;
        first.assert_status_ok();
        assert_eq!(first.json::<Value>()["value"], "share-me-once");

        let second = server
            .get(&format!("/api/v1/one-time-secrets/{one_time_token}"))
            .await;
        second.assert_status(axum::http::StatusCode::GONE);
    }

    #[tokio::test]
    async fn retrieve_unknown_token_is_404() {
        let state = db_state(dev_license("skauswatch")).await;
        let server = test_server_with_state(state);
        let resp = server
            .get("/api/v1/one-time-secrets/not-a-real-token")
            .await;
        resp.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn retrieve_expired_secret_is_gone() {
        let state = db_state(dev_license("skauswatch")).await;
        let server = test_server_with_state(state.clone());

        let (token, token_hash) = generate_token();
        let (ciphertext, dek, dek_version) = crate::routes::test_support::test_envelope()
            .encrypt("stale")
            .unwrap_or_else(|e| panic!("encrypt: {e}"));
        let tenant_id: Uuid = crate::routes::test_support::TEST_TENANT
            .parse()
            .unwrap_or_else(|e| panic!("test tenant uuid: {e}"));
        sqlx::query(
            "INSERT INTO vault_one_time_secrets (id, tenant_id, token_hash, encrypted_value, \
             encrypted_dek, dek_version, expires_at, created_by, created_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,'u',$8)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(tenant_id)
        .bind(&token_hash)
        .bind(ciphertext)
        .bind(dek)
        .bind(dek_version as i32)
        .bind(Utc::now().naive_utc() - chrono::Duration::seconds(60))
        .bind(Utc::now().naive_utc())
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed expired one-time secret: {e}"));

        let resp = server
            .get(&format!("/api/v1/one-time-secrets/{token}"))
            .await;
        resp.assert_status(axum::http::StatusCode::GONE);
    }
}
