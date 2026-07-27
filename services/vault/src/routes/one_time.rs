//! `/api/v1/one-time-secrets` — self-destructing shared secrets. Rust port
//! of `icebox/services/flask-backend/api/v1/one_time.py`.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::ApiError;
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

#[derive(Deserialize)]
struct CreateBody {
    value: Option<String>,
    ttl_seconds: Option<i64>,
}

async fn create_one_time_secret(
    State(state): State<AppState>,
    user: CurrentUser,
    body: Option<Json<CreateBody>>,
) -> Result<(axum::http::StatusCode, Json<Value>), ApiError> {
    user.require_scope("secrets:write")?;

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
        "INSERT INTO vault_one_time_secrets (id, token_hash, encrypted_value, encrypted_dek, \
         dek_version, expires_at, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(&secret_id)
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

async fn retrieve_one_time_secret(
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
    use super::*;

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
}
