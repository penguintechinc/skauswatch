//! `/api/v1/jit` — Just-in-Time access requests and approvals. Rust port of
//! `icebox/services/flask-backend/api/v1/jit.py`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::routing::{get, patch};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::ApiError;
use crate::state::AppState;

/// Router for `/api/v1/jit`.
pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/jit/requests",
            get(list_jit_requests).post(create_jit_request),
        )
        .route("/jit/requests/{id}/approve", patch(approve_jit_request))
        .route("/jit/requests/{id}/reject", patch(reject_jit_request))
}

/// v1 JIT token format: `jit:{grant_id}:{grantee_id}:{expires_epoch}`.
fn generate_jit_token(grant_id: &str, grantee_id: &str, expires_epoch: i64) -> String {
    format!("jit:{grant_id}:{grantee_id}:{expires_epoch}")
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex_lower(&hasher.finalize())
}

/// Minimal lowercase-hex encoder (avoids an extra `hex` crate dependency
/// for a single call site).
fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Validates a JIT access token for `secret_id`. Returns the grantee id on
/// success. Rust port of v1 `_validate_jit_token`.
pub async fn validate_jit_token(state: &AppState, token: &str, secret_id: &str) -> Option<String> {
    let parts: Vec<&str> = token.split(':').collect();
    if parts.len() != 4 || parts[0] != "jit" {
        return None;
    }
    let grant_id = parts[1];
    let grantee_id = parts[2];
    let expires_epoch: i64 = parts[3].parse().ok()?;

    let now_epoch = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    if now_epoch > expires_epoch {
        return None;
    }

    #[derive(sqlx::FromRow)]
    struct GrantRow {
        access_token_hash: String,
        expires_at: NaiveDateTime,
    }

    let grant = sqlx::query_as::<_, GrantRow>(
        "SELECT access_token_hash, expires_at FROM vault_jit_grants \
         WHERE id = $1 AND secret_id = $2 AND grantee_id = $3 AND revoked_at IS NULL",
    )
    .bind(grant_id)
    .bind(secret_id)
    .bind(grantee_id)
    .fetch_optional(&state.db)
    .await
    .ok()??;

    if grant.expires_at < Utc::now().naive_utc() {
        return None;
    }
    if token_hash(token) != grant.access_token_hash {
        return None;
    }
    Some(grantee_id.to_owned())
}

#[derive(sqlx::FromRow)]
struct RequestRow {
    id: String,
    secret_id: String,
    requestor_id: String,
    reason: String,
    requested_duration_seconds: i32,
    approved_duration_seconds: Option<i32>,
    status: String,
    approved_by: Option<String>,
    approved_at: Option<NaiveDateTime>,
    access_expires_at: Option<NaiveDateTime>,
    created_at: NaiveDateTime,
}

impl RequestRow {
    fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "secret_id": self.secret_id,
            "requestor_id": self.requestor_id,
            "reason": self.reason,
            "requested_duration_seconds": self.requested_duration_seconds,
            "approved_duration_seconds": self.approved_duration_seconds,
            "status": self.status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at.map(skauswatch_streams::py_isoformat),
            "access_expires_at": self.access_expires_at.map(skauswatch_streams::py_isoformat),
            "created_at": skauswatch_streams::py_isoformat(self.created_at),
        })
    }
}

async fn is_secret_owner(
    state: &AppState,
    secret_id: &str,
    user_id: &str,
) -> Result<bool, ApiError> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM vault_secret_owners \
         WHERE secret_id = $1 AND owner_type = 'user' AND owner_id = $2",
    )
    .bind(secret_id)
    .bind(user_id)
    .fetch_one(&state.db)
    .await?;
    Ok(count > 0)
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    status: Vec<String>,
}

async fn list_jit_requests(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<Value>, ApiError> {
    user.require_any_scope(&["jit:request", "jit:approve"])?;
    let has_approve = user.scopes.contains("jit:approve");

    let rows = if has_approve {
        sqlx::query_as::<_, RequestRow>(
            "SELECT r.id, r.secret_id, r.requestor_id, r.reason, r.requested_duration_seconds, \
             r.approved_duration_seconds, r.status, r.approved_by, r.approved_at, \
             r.access_expires_at, r.created_at FROM vault_jit_requests r \
             WHERE r.requestor_id = $1 \
                OR r.secret_id IN (SELECT secret_id FROM vault_secret_owners \
                                   WHERE owner_type = 'user' AND owner_id = $1) \
             ORDER BY r.created_at DESC",
        )
        .bind(&user.user_id)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, RequestRow>(
            "SELECT id, secret_id, requestor_id, reason, requested_duration_seconds, \
             approved_duration_seconds, status, approved_by, approved_at, access_expires_at, \
             created_at FROM vault_jit_requests WHERE requestor_id = $1 ORDER BY created_at DESC",
        )
        .bind(&user.user_id)
        .fetch_all(&state.db)
        .await?
    };

    let filtered: Vec<&RequestRow> = if q.status.is_empty() {
        rows.iter().collect()
    } else {
        rows.iter()
            .filter(|r| q.status.contains(&r.status))
            .collect()
    };

    Ok(Json(json!({
        "requests": filtered.iter().map(|r| r.to_json()).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize)]
struct CreateJitRequestBody {
    secret_id: Option<String>,
    reason: Option<String>,
    requested_duration_seconds: Option<i32>,
}

async fn create_jit_request(
    State(state): State<AppState>,
    user: CurrentUser,
    body: Option<Json<CreateJitRequestBody>>,
) -> Result<(axum::http::StatusCode, Json<Value>), ApiError> {
    user.require_scope("jit:request")?;
    let body = body.map(|Json(b)| b).unwrap_or(CreateJitRequestBody {
        secret_id: None,
        reason: None,
        requested_duration_seconds: None,
    });
    let secret_id = body.secret_id.unwrap_or_default().trim().to_owned();
    let reason = body.reason.unwrap_or_default().trim().to_owned();
    let duration = body.requested_duration_seconds.unwrap_or(3600);

    if secret_id.is_empty() || reason.is_empty() {
        return Err(ApiError::BadRequest(
            "secret_id and reason are required".to_owned(),
        ));
    }

    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM vault_secrets WHERE id = $1")
        .bind(&secret_id)
        .fetch_one(&state.db)
        .await?;
    if exists == 0 {
        return Err(ApiError::NotFound("Secret not found".to_owned()));
    }

    // v1 default max: `JIT_TOKEN_MAX_DURATION_SECONDS` (default 3600s).
    let max_duration: i32 = std::env::var("JIT_TOKEN_MAX_DURATION_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);
    if duration > max_duration {
        return Err(ApiError::BadRequest(format!(
            "Requested duration exceeds maximum ({max_duration}s)"
        )));
    }

    let req_id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    sqlx::query(
        "INSERT INTO vault_jit_requests (id, secret_id, requestor_id, reason, \
         requested_duration_seconds, status, created_at) VALUES ($1,$2,$3,$4,$5,'pending',$6)",
    )
    .bind(&req_id)
    .bind(&secret_id)
    .bind(&user.user_id)
    .bind(&reason)
    .bind(duration)
    .bind(now)
    .execute(&state.db)
    .await?;

    let row = sqlx::query_as::<_, RequestRow>(
        "SELECT id, secret_id, requestor_id, reason, requested_duration_seconds, \
         approved_duration_seconds, status, approved_by, approved_at, access_expires_at, \
         created_at FROM vault_jit_requests WHERE id = $1",
    )
    .bind(&req_id)
    .fetch_one(&state.db)
    .await?;

    Ok((axum::http::StatusCode::CREATED, Json(row.to_json())))
}

#[derive(Deserialize, Default)]
struct ApproveBody {
    approved_duration_seconds: Option<i32>,
}

async fn approve_jit_request(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(request_id): Path<String>,
    body: Option<Json<ApproveBody>>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("jit:approve")?;

    let jit_req = sqlx::query_as::<_, RequestRow>(
        "SELECT id, secret_id, requestor_id, reason, requested_duration_seconds, \
         approved_duration_seconds, status, approved_by, approved_at, access_expires_at, \
         created_at FROM vault_jit_requests WHERE id = $1",
    )
    .bind(&request_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Request not found".to_owned()))?;

    if jit_req.status != "pending" {
        return Err(ApiError::Conflict(format!(
            "Request is already {}",
            jit_req.status
        )));
    }
    if !is_secret_owner(&state, &jit_req.secret_id, &user.user_id).await? {
        return Err(ApiError::Forbidden(
            "Not an owner of this secret".to_owned(),
        ));
    }

    let max_duration: i32 = std::env::var("JIT_TOKEN_MAX_DURATION_SECONDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600);
    let requested = body
        .and_then(|Json(b)| b.approved_duration_seconds)
        .unwrap_or(jit_req.requested_duration_seconds);
    let approved_duration = requested.min(max_duration);

    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(approved_duration as i64);
    let expires_epoch = expires_at.timestamp();
    let grant_id = Uuid::new_v4().to_string();
    let token = generate_jit_token(&grant_id, &jit_req.requestor_id, expires_epoch);
    let hash = token_hash(&token);

    sqlx::query(
        "INSERT INTO vault_jit_grants (id, request_id, secret_id, grantee_id, \
         access_token_hash, expires_at) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(&grant_id)
    .bind(&request_id)
    .bind(&jit_req.secret_id)
    .bind(&jit_req.requestor_id)
    .bind(&hash)
    .bind(expires_at.naive_utc())
    .execute(&state.db)
    .await?;

    sqlx::query(
        "UPDATE vault_jit_requests SET status = 'approved', approved_by = $1, approved_at = $2, \
         approved_duration_seconds = $3, access_expires_at = $4 WHERE id = $5",
    )
    .bind(&user.user_id)
    .bind(now.naive_utc())
    .bind(approved_duration)
    .bind(expires_at.naive_utc())
    .bind(&request_id)
    .execute(&state.db)
    .await?;

    Ok(Json(json!({
        "request_id": request_id,
        "grant_id": grant_id,
        "access_token": token,
        "expires_at": skauswatch_streams::py_isoformat(expires_at.naive_utc()),
        "secret_id": jit_req.secret_id,
    })))
}

async fn reject_jit_request(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(request_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    user.require_scope("jit:approve")?;

    let jit_req = sqlx::query_as::<_, RequestRow>(
        "SELECT id, secret_id, requestor_id, reason, requested_duration_seconds, \
         approved_duration_seconds, status, approved_by, approved_at, access_expires_at, \
         created_at FROM vault_jit_requests WHERE id = $1",
    )
    .bind(&request_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("Request not found".to_owned()))?;

    if jit_req.status != "pending" {
        return Err(ApiError::Conflict(format!(
            "Request is already {}",
            jit_req.status
        )));
    }
    if !is_secret_owner(&state, &jit_req.secret_id, &user.user_id).await? {
        return Err(ApiError::Forbidden(
            "Not an owner of this secret".to_owned(),
        ));
    }

    sqlx::query(
        "UPDATE vault_jit_requests SET status = 'rejected', approved_by = $1, approved_at = $2 \
         WHERE id = $3",
    )
    .bind(&user.user_id)
    .bind(Utc::now().naive_utc())
    .bind(&request_id)
    .execute(&state.db)
    .await?;

    Ok(Json(
        json!({"request_id": request_id, "status": "rejected"}),
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn jit_token_format_matches_v1() {
        let token = generate_jit_token("g-1", "user-1", 1234567890);
        assert_eq!(token, "jit:g-1:user-1:1234567890");
    }

    #[test]
    fn token_hash_is_64_char_lowercase_hex() {
        let h = token_hash("jit:g-1:user-1:1234567890");
        assert_eq!(h.len(), 64);
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn token_hash_is_sha256() {
        // Known SHA-256("abc") test vector.
        assert_eq!(
            token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn validate_jit_token_rejects_malformed_token() {
        let state = crate::state::AppStateInner::for_tests(
            {
                let cfg = penguin_licensing::LicenseConfig::new("skauswatch").expect("config");
                penguin_licensing::LicenseClient::new(cfg).expect("client")
            },
            skauswatch_vault::EnvelopeEncryption::default(),
        );
        assert!(
            validate_jit_token(&state, "not-a-jit-token", "secret-1")
                .await
                .is_none()
        );
        assert!(
            validate_jit_token(&state, "jit:only:two", "secret-1")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn validate_jit_token_rejects_expired_epoch_without_db_hit() {
        let state = crate::state::AppStateInner::for_tests(
            {
                let cfg = penguin_licensing::LicenseConfig::new("skauswatch").expect("config");
                penguin_licensing::LicenseClient::new(cfg).expect("client")
            },
            skauswatch_vault::EnvelopeEncryption::default(),
        );
        let expired = generate_jit_token("g", "u", 1);
        assert!(
            validate_jit_token(&state, &expired, "secret-1")
                .await
                .is_none()
        );
    }
}
