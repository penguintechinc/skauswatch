//! `/api/v1/jit` — Just-in-Time access requests and approvals. Rust port of
//! `icebox/services/flask-backend/api/v1/jit.py`.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Path, Query, State};
use axum::routing::{get, patch};
use axum::{Json, Router};
use chrono::{NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse, InsufficientScopeResponse};
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

/// Documentation-only mirror of `RequestRow::to_json`'s wire shape.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct JitRequestResponse {
    id: String,
    secret_id: String,
    requestor_id: String,
    reason: String,
    requested_duration_seconds: i32,
    approved_duration_seconds: Option<i32>,
    status: String,
    approved_by: Option<String>,
    approved_at: Option<String>,
    access_expires_at: Option<String>,
    created_at: String,
}

/// Documentation-only mirror of `list_jit_requests`'s response envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct JitRequestListResponse {
    requests: Vec<JitRequestResponse>,
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

#[utoipa::path(
    get,
    path = "/api/v1/jit/requests",
    tag = "jit",
    security(("bearer_jwt" = [])),
    params(
        ("status" = Option<Vec<String>>, Query, description = "Filter by request status; repeatable (?status=pending&status=approved). Manually declared (not an IntoParams struct) because the handler extracts raw query pairs — see the comment on the `raw_query` parameter below."),
    ),
    responses(
        (status = 200, description = "Requestor's own requests, plus (for jit:approve callers) requests against secrets they own", body = JitRequestListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Missing both jit:request and jit:approve scopes", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_jit_requests(
    State(state): State<AppState>,
    user: CurrentUser,
    // `status` is a repeated-key filter (`?status=a&status=b`), matching v1's
    // `request.args.getlist("status")`. `axum::extract::Query<T>` is backed
    // by `serde_urlencoded`, which cannot deserialize repeated keys into a
    // `Vec<String>` field (see its own `Query` doc comment, which points at
    // `axum_extra::extract::Query` for that — not a dependency this crate
    // carries). `Query<Vec<(String, String)>>` sidesteps that: serde_urlencoded
    // deserializes the whole query string as an ordered sequence of raw pairs
    // just fine, so every occurrence of `status` is preserved and filtered
    // out here instead of relying on struct-field deserialization.
    Query(raw_query): Query<Vec<(String, String)>>,
) -> Result<Json<Value>, ApiError> {
    user.require_any_scope(&["jit:request", "jit:approve"])?;
    let status_filter: Vec<String> = raw_query
        .iter()
        .filter(|(k, _)| k == "status")
        .map(|(_, v)| v.clone())
        .collect();
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

    let filtered: Vec<&RequestRow> = if status_filter.is_empty() {
        rows.iter().collect()
    } else {
        rows.iter()
            .filter(|r| status_filter.contains(&r.status))
            .collect()
    };

    Ok(Json(json!({
        "requests": filtered.iter().map(|r| r.to_json()).collect::<Vec<_>>(),
    })))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateJitRequestBody {
    secret_id: Option<String>,
    reason: Option<String>,
    requested_duration_seconds: Option<i32>,
}

#[utoipa::path(
    post,
    path = "/api/v1/jit/requests",
    tag = "jit",
    security(("bearer_jwt" = [])),
    request_body = CreateJitRequestBody,
    responses(
        (status = 201, description = "JIT request created (status: pending)", body = JitRequestResponse),
        (status = 400, description = "Missing secret_id/reason or duration exceeds the configured maximum", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires jit:request)", body = InsufficientScopeResponse),
        (status = 404, description = "Secret not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_jit_request(
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

#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct ApproveBody {
    approved_duration_seconds: Option<i32>,
}

/// Documentation-only mirror of `approve_jit_request`'s response envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct JitApproveResponse {
    request_id: String,
    grant_id: String,
    /// The bearer-style JIT access token (`jit:{grant_id}:{grantee_id}:
    /// {expires_epoch}`) granted to the requestor — sensitive, never
    /// populated with example data in the generated schema.
    access_token: String,
    expires_at: String,
    secret_id: String,
}

#[utoipa::path(
    patch,
    path = "/api/v1/jit/requests/{id}/approve",
    tag = "jit",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "JIT request id")),
    request_body = ApproveBody,
    responses(
        (status = 200, description = "Request approved; a JIT access token is minted", body = JitApproveResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires jit:approve, richer {required,missing} body) or not an owner of the target secret (bare body, shown here — simplified rather than modeled as oneOf)", body = ErrorResponse),
        (status = 404, description = "Request not found", body = ErrorResponse),
        (status = 409, description = "Request is no longer pending", body = ErrorResponse),
    ),
)]
pub(crate) async fn approve_jit_request(
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

/// Documentation-only mirror of `reject_jit_request`'s response envelope.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct JitRejectResponse {
    request_id: String,
    status: String,
}

#[utoipa::path(
    patch,
    path = "/api/v1/jit/requests/{id}/reject",
    tag = "jit",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "JIT request id")),
    responses(
        (status = 200, description = "Request rejected", body = JitRejectResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient scope (requires jit:approve) or not an owner of the target secret", body = ErrorResponse),
        (status = 404, description = "Request not found", body = ErrorResponse),
        (status = 409, description = "Request is no longer pending", body = ErrorResponse),
    ),
)]
pub(crate) async fn reject_jit_request(
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

    // -- DB-backed handler tests (real Postgres via skauswatch-testkit) --

    use axum_test::TestServer;
    use skauswatch_testkit::license::dev_license;

    use crate::routes::test_support::{db_state, sign_token};

    fn test_server_with_state(state: crate::state::AppState) -> TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        TestServer::new(app)
    }

    async fn seed_secret(state: &crate::state::AppState, owner_id: &str) -> String {
        let secret_id = Uuid::new_v4().to_string();
        let now = Utc::now().naive_utc();
        sqlx::query(
            "INSERT INTO vault_secrets (id, name, description, secret_type, encrypted_value, \
             encrypted_dek, dek_version, tags, secret_metadata, expires_at, created_at, \
             updated_at, created_by) VALUES ($1,'n',NULL,'api_key','ct','dek',1,NULL,NULL,NULL,$2,$2,$3)",
        )
        .bind(&secret_id)
        .bind(now)
        .bind(owner_id)
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed secret: {e}"));
        sqlx::query(
            "INSERT INTO vault_secret_owners (secret_id, owner_type, owner_id) \
             VALUES ($1, 'user', $2)",
        )
        .bind(&secret_id)
        .bind(owner_id)
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed owner: {e}"));
        secret_id
    }

    /// Seeds a `vault_jit_requests` row with a fixed `id` — satisfies the
    /// `vault_jit_grants_request_id_fkey` FK for tests that hand-craft a
    /// grant row directly (bypassing `approve_jit_request`).
    async fn seed_jit_request_row(state: &crate::state::AppState, id: &str, secret_id: &str) {
        sqlx::query(
            "INSERT INTO vault_jit_requests (id, secret_id, requestor_id, reason, \
             requested_duration_seconds, status, created_at) \
             VALUES ($1,$2,'requestor-1','test',3600,'approved',$3)",
        )
        .bind(id)
        .bind(secret_id)
        .bind(Utc::now().naive_utc())
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed jit request row: {e}"));
    }

    #[tokio::test]
    async fn create_jit_request_validates_body_and_secret_existence() {
        let state = db_state(dev_license("skauswatch")).await;
        let token = sign_token(&state, "requestor-1", "jit:request");
        let server = test_server_with_state(state.clone());

        let missing_fields = server
            .post("/api/v1/jit/requests")
            .authorization_bearer(&token)
            .json(&serde_json::json!({}))
            .await;
        missing_fields.assert_status(axum::http::StatusCode::BAD_REQUEST);

        let unknown_secret = server
            .post("/api/v1/jit/requests")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"secret_id": "does-not-exist", "reason": "need it"}))
            .await;
        unknown_secret.assert_status(axum::http::StatusCode::NOT_FOUND);

        let secret_id = seed_secret(&state, "owner-1").await;
        let too_long = server
            .post("/api/v1/jit/requests")
            .authorization_bearer(&token)
            .json(&serde_json::json!({
                "secret_id": secret_id,
                "reason": "need it",
                "requested_duration_seconds": 999_999,
            }))
            .await;
        too_long.assert_status(axum::http::StatusCode::BAD_REQUEST);

        let created = server
            .post("/api/v1/jit/requests")
            .authorization_bearer(&token)
            .json(&serde_json::json!({"secret_id": secret_id, "reason": "need it"}))
            .await;
        created.assert_status(axum::http::StatusCode::CREATED);
        let body: Value = created.json();
        assert_eq!(body["status"], "pending");
        assert_eq!(body["secret_id"], secret_id);
    }

    #[tokio::test]
    async fn list_jit_requests_scopes_by_requestor_without_approve_scope() {
        let state = db_state(dev_license("skauswatch")).await;
        let secret_id = seed_secret(&state, "owner-1").await;
        let requestor_token = sign_token(&state, "requestor-1", "jit:request");
        let other_token = sign_token(&state, "requestor-2", "jit:request");
        let server = test_server_with_state(state.clone());

        server
            .post("/api/v1/jit/requests")
            .authorization_bearer(&requestor_token)
            .json(&serde_json::json!({"secret_id": secret_id, "reason": "need it"}))
            .await
            .assert_status(axum::http::StatusCode::CREATED);

        let mine = server
            .get("/api/v1/jit/requests")
            .authorization_bearer(&requestor_token)
            .await;
        mine.assert_status_ok();
        assert_eq!(
            mine.json::<Value>()["requests"].as_array().map(Vec::len),
            Some(1)
        );

        let theirs = server
            .get("/api/v1/jit/requests")
            .authorization_bearer(&other_token)
            .await;
        theirs.assert_status_ok();
        assert_eq!(
            theirs.json::<Value>()["requests"].as_array().map(Vec::len),
            Some(0)
        );

        let no_scope = sign_token(&state, "nobody", "");
        server
            .get("/api/v1/jit/requests")
            .authorization_bearer(&no_scope)
            .await
            .assert_status(axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_jit_requests_with_approve_scope_sees_owned_secret_requests_and_status_filter() {
        let state = db_state(dev_license("skauswatch")).await;
        let secret_id = seed_secret(&state, "owner-1").await;
        let requestor_token = sign_token(&state, "requestor-1", "jit:request");
        let owner_token = sign_token(&state, "owner-1", "jit:approve");
        let server = test_server_with_state(state.clone());

        server
            .post("/api/v1/jit/requests")
            .authorization_bearer(&requestor_token)
            .json(&serde_json::json!({"secret_id": secret_id, "reason": "need it"}))
            .await
            .assert_status(axum::http::StatusCode::CREATED);

        let all = server
            .get("/api/v1/jit/requests")
            .authorization_bearer(&owner_token)
            .await;
        assert_eq!(
            all.json::<Value>()["requests"].as_array().map(Vec::len),
            Some(1)
        );

        // `status` is a `Vec<String>` query param — the extractor requires
        // repeated keys (`status=a&status=b`), not a single scalar value.
        let no_match = server
            .get("/api/v1/jit/requests?status=rejected&status=approved")
            .authorization_bearer(&owner_token)
            .await;
        assert_eq!(
            no_match.json::<Value>()["requests"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );

        let matching = server
            .get("/api/v1/jit/requests?status=pending&status=rejected")
            .authorization_bearer(&owner_token)
            .await;
        assert_eq!(
            matching.json::<Value>()["requests"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
    }

    #[tokio::test]
    async fn approve_jit_request_full_flow_and_conflict() {
        let state = db_state(dev_license("skauswatch")).await;
        let secret_id = seed_secret(&state, "owner-1").await;
        let requestor_token = sign_token(&state, "requestor-1", "jit:request");
        let owner_token = sign_token(&state, "owner-1", "jit:approve");
        let non_owner_token = sign_token(&state, "someone-else", "jit:approve");
        let server = test_server_with_state(state.clone());

        let created = server
            .post("/api/v1/jit/requests")
            .authorization_bearer(&requestor_token)
            .json(&serde_json::json!({"secret_id": secret_id, "reason": "need it"}))
            .await;
        let request_id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let forbidden = server
            .patch(&format!("/api/v1/jit/requests/{request_id}/approve"))
            .authorization_bearer(&non_owner_token)
            .json(&serde_json::json!({}))
            .await;
        forbidden.assert_status(axum::http::StatusCode::FORBIDDEN);

        let approved = server
            .patch(&format!("/api/v1/jit/requests/{request_id}/approve"))
            .authorization_bearer(&owner_token)
            .json(&serde_json::json!({"approved_duration_seconds": 120}))
            .await;
        approved.assert_status_ok();
        let approved_body: Value = approved.json();
        assert!(
            approved_body["access_token"]
                .as_str()
                .unwrap_or_default()
                .starts_with("jit:")
        );

        let already = server
            .patch(&format!("/api/v1/jit/requests/{request_id}/approve"))
            .authorization_bearer(&owner_token)
            .json(&serde_json::json!({}))
            .await;
        already.assert_status(axum::http::StatusCode::CONFLICT);

        let missing = server
            .patch("/api/v1/jit/requests/does-not-exist/approve")
            .authorization_bearer(&owner_token)
            .json(&serde_json::json!({}))
            .await;
        missing.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn reject_jit_request_full_flow_and_conflict() {
        let state = db_state(dev_license("skauswatch")).await;
        let secret_id = seed_secret(&state, "owner-1").await;
        let requestor_token = sign_token(&state, "requestor-1", "jit:request");
        let owner_token = sign_token(&state, "owner-1", "jit:approve");
        let non_owner_token = sign_token(&state, "someone-else", "jit:approve");
        let server = test_server_with_state(state.clone());

        let created = server
            .post("/api/v1/jit/requests")
            .authorization_bearer(&requestor_token)
            .json(&serde_json::json!({"secret_id": secret_id, "reason": "need it"}))
            .await;
        let request_id = created.json::<Value>()["id"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let forbidden = server
            .patch(&format!("/api/v1/jit/requests/{request_id}/reject"))
            .authorization_bearer(&non_owner_token)
            .await;
        forbidden.assert_status(axum::http::StatusCode::FORBIDDEN);

        let rejected = server
            .patch(&format!("/api/v1/jit/requests/{request_id}/reject"))
            .authorization_bearer(&owner_token)
            .await;
        rejected.assert_status_ok();
        assert_eq!(rejected.json::<Value>()["status"], "rejected");

        let already = server
            .patch(&format!("/api/v1/jit/requests/{request_id}/reject"))
            .authorization_bearer(&owner_token)
            .await;
        already.assert_status(axum::http::StatusCode::CONFLICT);

        let missing = server
            .patch("/api/v1/jit/requests/does-not-exist/reject")
            .authorization_bearer(&owner_token)
            .await;
        missing.assert_status(axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn validate_jit_token_full_success_and_db_backed_rejections() {
        let state = db_state(dev_license("skauswatch")).await;
        let secret_id = seed_secret(&state, "owner-1").await;

        let expires_epoch = Utc::now().timestamp() + 3600;
        let grant_id = "grant-1";
        let grantee_id = "grantee-1";
        let token = generate_jit_token(grant_id, grantee_id, expires_epoch);
        let hash = token_hash(&token);

        seed_jit_request_row(&state, "req-1", &secret_id).await;
        sqlx::query(
            "INSERT INTO vault_jit_grants (id, request_id, secret_id, grantee_id, \
             access_token_hash, expires_at) VALUES ($1,'req-1',$2,$3,$4,$5)",
        )
        .bind(grant_id)
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
        .unwrap_or_else(|e| panic!("seed grant: {e}"));

        assert_eq!(
            validate_jit_token(&state, &token, &secret_id).await,
            Some(grantee_id.to_owned())
        );

        // Wrong secret id: grant row exists but doesn't match.
        assert!(
            validate_jit_token(&state, &token, "some-other-secret")
                .await
                .is_none()
        );

        // Tampered token (hash mismatch).
        let tampered = generate_jit_token(grant_id, grantee_id, expires_epoch + 1);
        assert!(
            validate_jit_token(&state, &tampered, &secret_id)
                .await
                .is_none()
        );

        // Grant row that has already expired in the DB (independent of the
        // token's own embedded expiry epoch).
        let past_epoch = Utc::now().timestamp() + 10;
        let past_grant_id = "grant-2";
        let past_token = generate_jit_token(past_grant_id, grantee_id, past_epoch);
        let past_hash = token_hash(&past_token);
        seed_jit_request_row(&state, "req-2", &secret_id).await;
        sqlx::query(
            "INSERT INTO vault_jit_grants (id, request_id, secret_id, grantee_id, \
             access_token_hash, expires_at) VALUES ($1,'req-2',$2,$3,$4,$5)",
        )
        .bind(past_grant_id)
        .bind(&secret_id)
        .bind(grantee_id)
        .bind(&past_hash)
        .bind(Utc::now().naive_utc() - chrono::Duration::seconds(3600))
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed expired grant: {e}"));
        assert!(
            validate_jit_token(&state, &past_token, &secret_id)
                .await
                .is_none()
        );
    }
}
