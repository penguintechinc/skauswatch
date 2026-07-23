//! /api/v1/auth — login, refresh (with rotation), logout, me, register.
//! Contract: docs/v2-port/manager-contract.md §auth. Exact error detail
//! strings are provisional until the golden parity harness verifies them
//! against live v1 responses.

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::auth::{
    self, CurrentUser, create_access_token, create_refresh_token, decode_refresh, token_hash,
};
use crate::error::{ApiError, ApiJson};
use crate::state::AppState;

/// Router for /api/v1/auth.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/auth/register", post(register))
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

fn valid_email(email: &str) -> bool {
    email.parse::<email_address::EmailAddress>().is_ok()
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(sqlx::FromRow)]
struct LoginRow {
    id: i32,
    email: String,
    password_hash: String,
    /// v1 renders `user.full_name or ""` — SELECT COALESCEs to "".
    full_name: String,
    role: String,
    is_active: bool,
    failed_login_attempts: i32,
    locked: bool,
}

async fn login(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<LoginRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    if !valid_email(&body.email) {
        return Err(validation("email", "value is not a valid email address"));
    }
    if body.password.is_empty() {
        return Err(validation(
            "password",
            "String should have at least 1 character",
        ));
    }

    // v1 lowercases the login email before lookup.
    let row = sqlx::query_as::<_, LoginRow>(
        "SELECT id, email, password_hash, COALESCE(full_name, '') AS full_name, role, is_active, \
                failed_login_attempts, \
                (account_locked_until IS NOT NULL AND account_locked_until > now()) AS locked \
         FROM users WHERE email = $1",
    )
    .bind(body.email.to_lowercase())
    .fetch_optional(&state.db)
    .await?;

    let Some(user) = row else {
        return Err(ApiError::Unauthorized(
            "Invalid email or password".to_owned(),
        ));
    };
    if user.locked {
        return Err(ApiError::Unauthorized(
            "Account is locked. Please try again later.".to_owned(),
        ));
    }

    // v1 order: password check (and attempt bookkeeping) runs BEFORE the
    // is_active check — a deactivated user with a wrong password sees
    // "Invalid email or password", not the deactivation message.
    // pyDAL parity: every users UPDATE below also bumps updated_at
    // (Field(update=utcnow) fires on all v1 updates, including these).
    if !auth::verify_password(&body.password, &user.password_hash) {
        let attempts = user.failed_login_attempts + 1;
        if attempts >= state.auth.max_login_attempts {
            sqlx::query(
                "UPDATE users SET failed_login_attempts = $1, \
                 account_locked_until = now() + make_interval(mins => $2), \
                 updated_at = now() WHERE id = $3",
            )
            .bind(attempts)
            .bind(state.auth.lockout_minutes as i32)
            .bind(user.id)
            .execute(&state.db)
            .await?;
        } else {
            sqlx::query(
                "UPDATE users SET failed_login_attempts = $1, updated_at = now() WHERE id = $2",
            )
            .bind(attempts)
            .bind(user.id)
            .execute(&state.db)
            .await?;
        }
        return Err(ApiError::Unauthorized(
            "Invalid email or password".to_owned(),
        ));
    }

    if !user.is_active {
        return Err(ApiError::Unauthorized("Account is deactivated".to_owned()));
    }

    sqlx::query(
        "UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, \
         updated_at = now() WHERE id = $1",
    )
    .bind(user.id)
    .execute(&state.db)
    .await?;

    let (access, refresh_token) = issue_token_pair(&state, user.id, &user.role).await?;

    Ok(Json(serde_json::json!({
        "access_token": access,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": state.auth.access_expires_minutes * 60,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role,
        }
    })))
}

/// Issues an access+refresh pair and stores sha256(refresh) per v1.
async fn issue_token_pair(
    state: &AppState,
    user_id: i32,
    role: &str,
) -> Result<(String, String), ApiError> {
    let access = create_access_token(
        user_id,
        role,
        &state.auth.jwt_secret,
        state.auth.access_expires_minutes,
    )?;
    let refresh = create_refresh_token(
        user_id,
        &state.auth.jwt_secret,
        state.auth.refresh_expires_days,
    )?;
    let expires_at = (Utc::now() + Duration::days(state.auth.refresh_expires_days)).naive_utc();
    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked) \
         VALUES ($1, $2, $3, false)",
    )
    .bind(user_id)
    .bind(token_hash(&refresh))
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok((access, refresh))
}

#[derive(Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(sqlx::FromRow)]
struct RefreshRow {
    id: i32,
    user_id: i32,
}

async fn refresh(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<RefreshRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let claims = decode_refresh(&body.refresh_token, &state.auth.jwt_secret)?;
    let hash = token_hash(&body.refresh_token);

    let row = sqlx::query_as::<_, RefreshRow>(
        "SELECT id, user_id FROM refresh_tokens \
         WHERE token_hash = $1 AND revoked = false AND expires_at > now()",
    )
    .bind(&hash)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::Unauthorized("Refresh token has been revoked".to_owned()))?;

    let claimed_user: i32 = claims
        .sub
        .parse()
        .map_err(|_| ApiError::Unauthorized("Invalid refresh token".to_owned()))?;
    if claimed_user != row.user_id {
        return Err(ApiError::Unauthorized("Invalid refresh token".to_owned()));
    }

    #[derive(sqlx::FromRow)]
    struct RoleRow {
        role: String,
        is_active: bool,
    }
    let user = sqlx::query_as::<_, RoleRow>("SELECT role, is_active FROM users WHERE id = $1")
        .bind(row.user_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::Unauthorized("User not found or deactivated".to_owned()))?;
    if !user.is_active {
        return Err(ApiError::Unauthorized(
            "User not found or deactivated".to_owned(),
        ));
    }

    // Rotation: revoke the presented token before issuing a new pair.
    sqlx::query("UPDATE refresh_tokens SET revoked = true WHERE id = $1")
        .bind(row.id)
        .execute(&state.db)
        .await?;

    let (access, new_refresh) = issue_token_pair(&state, row.user_id, &user.role).await?;
    Ok(Json(serde_json::json!({
        "access_token": access,
        "refresh_token": new_refresh,
        "token_type": "Bearer",
        "expires_in": state.auth.access_expires_minutes * 60,
    })))
}

async fn logout(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Json<serde_json::Value>, ApiError> {
    // v1 counts the pyDAL update over ALL of the user's rows (already-
    // revoked ones included) — no `revoked = false` filter.
    let result = sqlx::query("UPDATE refresh_tokens SET revoked = true WHERE user_id = $1")
        .bind(user.id)
        .execute(&state.db)
        .await?;
    Ok(Json(serde_json::json!({
        "message": "Successfully logged out",
        "tokens_revoked": result.rows_affected(),
    })))
}

/// Re-renders `CurrentUser.created_at` (Postgres `timestamp::text`, loaded
/// by the auth extractor: `YYYY-MM-DD HH:MM:SS[.f…]`, trailing fraction zeros
/// trimmed) as Python `datetime.isoformat()` for v1 wire parity. The
/// Postgres text form is lossless, so parse-and-reformat is exact; an
/// unparseable value falls through unchanged rather than being dropped.
fn created_at_isoformat(raw: Option<&str>) -> Option<String> {
    let s = raw?;
    match chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f") {
        Ok(t) => Some(skauswatch_streams::py_isoformat(t)),
        Err(_) => Some(s.to_owned()),
    }
}

async fn me(user: CurrentUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
        "is_active": user.is_active,
        "mfa_enabled": user.mfa_enabled,
        "created_at": created_at_isoformat(user.created_at.as_deref()),
    }))
}

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    #[serde(default)]
    full_name: String,
}

async fn register(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<RegisterRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), ApiError> {
    if !valid_email(&body.email) {
        return Err(validation("email", "value is not a valid email address"));
    }
    if body.password.len() < 8 || body.password.len() > 128 {
        return Err(validation(
            "password",
            "String should have at least 8 characters",
        ));
    }
    if body.full_name.len() > 255 {
        return Err(validation(
            "full_name",
            "String should have at most 255 characters",
        ));
    }

    // v1 lowercases the email for both the existence check and the insert.
    let email = body.email.to_lowercase();
    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_some() {
        return Err(ApiError::Conflict(serde_json::json!({
            "error": "Email already registered"
        })));
    }

    let password_hash = auth::hash_password(&body.password)?;
    let (id,): (i32,) = sqlx::query_as(
        "INSERT INTO users (email, password_hash, full_name, role, is_active, updated_at) \
         VALUES ($1, $2, $3, 'viewer', true, now()) RETURNING id",
    )
    .bind(&email)
    .bind(&password_hash)
    .bind(&body.full_name)
    .fetch_one(&state.db)
    .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Registration successful",
            "user": {
                "id": id,
                "email": email,
                "full_name": body.full_name,
                "role": "viewer",
            }
        })),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn me_created_at_reformats_postgres_text_as_python_isoformat() {
        // Postgres trims trailing fraction zeros; Python pads to six digits.
        assert_eq!(
            created_at_isoformat(Some("2026-07-22 10:03:07.1")),
            Some("2026-07-22T10:03:07.100000".to_owned())
        );
        assert_eq!(
            created_at_isoformat(Some("2026-07-22 10:03:07.123456")),
            Some("2026-07-22T10:03:07.123456".to_owned())
        );
        // microsecond == 0 → Python omits the fraction entirely.
        assert_eq!(
            created_at_isoformat(Some("2026-07-22 10:03:07")),
            Some("2026-07-22T10:03:07".to_owned())
        );
        // NULL column → JSON null.
        assert_eq!(created_at_isoformat(None), None);
    }
}
