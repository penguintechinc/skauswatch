//! /api/v1/auth — login, refresh (with rotation), logout, me, register.
//! Contract: docs/v2-port/manager-contract.md §auth. Exact error detail
//! strings are provisional until the golden parity harness verifies them
//! against live v1 responses.

use std::sync::LazyLock;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::auth::cookies;
use crate::auth::{
    self, CurrentUser, create_access_token, create_refresh_token, decode_refresh, token_hash,
};
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

/// Bcrypt hash of an arbitrary fixed string — never a real credential, used
/// solely to burn the same bcrypt cost-factor CPU time that a real password
/// check would (finding #8). Computed once per process; falls back to a
/// well-formed public bcrypt test vector in the practically-unreachable case
/// `hash_password` itself fails, so the dummy verify never short-circuits.
static DUMMY_PASSWORD_HASH: LazyLock<String> = LazyLock::new(|| {
    auth::hash_password("skauswatch-login-timing-equalizer-not-a-real-credential").unwrap_or_else(
        |_| "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy".to_owned(),
    )
});

/// Router for /api/v1/auth — merges [`public_router`] and
/// [`protected_router`]. Used as-is by this module's own tests; the app-wide
/// assembly (`routes/mod.rs`) mounts the two halves separately so
/// `tenant_middleware` wraps only the protected half (see that module's
/// docs for why login/refresh/register must never sit behind it).
#[cfg_attr(not(test), allow(dead_code))]
pub fn router() -> Router<AppState> {
    public_router().merge(protected_router())
}

/// The unauthenticated auth endpoints: login (the credential exchange
/// itself), refresh (the refresh token in the body is its own credential —
/// no bearer header at all), and register (v1-parity open self-service
/// signup, see `register`'s docs). None of these carry a bearer token, so
/// none can carry a `tenant` claim — `tenant_middleware` must never wrap
/// this half of the router.
pub fn public_router() -> Router<AppState> {
    Router::new()
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/register", post(register))
}

/// The bearer-JWT-gated auth endpoints — wrapped in `tenant_middleware` like
/// every other authenticated route in `routes/mod.rs`'s app-wide assembly.
pub fn protected_router() -> Router<AppState> {
    Router::new()
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

fn valid_email(email: &str) -> bool {
    email.parse::<email_address::EmailAddress>().is_ok()
}

/// POST /auth/login body.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct LoginRequest {
    email: String,
    password: String,
}

/// User summary embedded in [`LoginResponse`].
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct LoginUser {
    id: i32,
    email: String,
    full_name: String,
    role: String,
}

/// Documentation-only mirror of `login`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct LoginResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    /// Access-token lifetime in seconds.
    expires_in: i64,
    user: LoginUser,
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
    /// Stamped into the minted access token's `tenant` claim and
    /// denormalized onto the issued `refresh_tokens` row — see
    /// `issue_token_pair` and docs/v2-port/tenancy-model.md §2.
    tenant_id: uuid::Uuid,
}

/// POST /auth/login — the sole unauthenticated endpoint in this service;
/// see `PublicApiDoc` in `routes/openapi.rs` for the standalone public spec
/// this path is exported into.
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Authenticated — access/refresh token pair", body = LoginResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Invalid credentials, deactivated, or locked account", body = ErrorResponse),
    ),
)]
pub(crate) async fn login(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<LoginRequest>,
) -> Result<(HeaderMap, Json<serde_json::Value>), ApiError> {
    if !valid_email(&body.email) {
        return Err(validation("email", "value is not a valid email address"));
    }
    if body.password.is_empty() {
        return Err(validation(
            "password",
            "String should have at least 1 character",
        ));
    }

    // v1 lowercases the login email before lookup. Not tenant-filtered —
    // login has no tenant to filter by yet; it's the query that *derives*
    // one (see docs/v2-port/tenancy-model.md §4's auth-inherently-needs
    // exception).
    let row = sqlx::query_as::<_, LoginRow>(
        "SELECT id, email, password_hash, COALESCE(full_name, '') AS full_name, role, is_active, \
                failed_login_attempts, \
                (account_locked_until IS NOT NULL AND account_locked_until > now()) AS locked, \
                tenant_id \
         FROM users WHERE email = $1",
    )
    .bind(body.email.to_lowercase())
    .fetch_optional(&state.db)
    .await?;

    let Some(user) = row else {
        // Finding #8: without this, an unknown email returns instantly while
        // a known email always pays the ~ms bcrypt cost below — a timing
        // oracle an attacker can use to enumerate valid accounts. Running a
        // dummy verify here equalizes the two paths' wall-clock cost.
        let _ = auth::verify_password(&body.password, &DUMMY_PASSWORD_HASH);
        return Err(ApiError::Unauthorized(
            "Invalid email or password".to_owned(),
        ));
    };
    if user.locked {
        // Equalize wall-clock cost with the verify paths (unknown-email dummy
        // + known-email real bcrypt) so response time cannot single out a
        // currently-locked account — otherwise the #8 fix merely shifts the
        // timing oracle onto lockout state.
        let _ = auth::verify_password(&body.password, &DUMMY_PASSWORD_HASH);
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

    let (access, refresh_token) =
        issue_token_pair(&state, user.id, &user.role, user.tenant_id).await?;

    // H2 audit fix: mint the HttpOnly cookie pair + `sw_csrf` alongside the
    // unchanged response-body token — Bearer clients (CLI/mobile/the golden
    // parity harness) keep reading the body and never see these cookies.
    let cookie_headers = cookies::auth_cookies(
        &access,
        &refresh_token,
        &cookies::generate_csrf_token(),
        state.auth.access_expires_minutes * 60,
        state.auth.refresh_expires_days * 86_400,
    )?;

    Ok((
        cookie_headers,
        Json(serde_json::json!({
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
        })),
    ))
}

/// Issues an access+refresh pair and stores sha256(refresh) per v1. `tenant`
/// is stamped into the access token's `tenant` claim AND denormalized onto
/// the `refresh_tokens` row (docs/v2-port/tenancy-model.md §2), so rotation
/// (`refresh`, below) never needs a second `users` join to re-derive it.
async fn issue_token_pair(
    state: &AppState,
    user_id: i32,
    role: &str,
    tenant: uuid::Uuid,
) -> Result<(String, String), ApiError> {
    let access = create_access_token(
        user_id,
        role,
        &tenant.to_string(),
        &state.auth.jwt_signing_key,
        state.auth.access_expires_minutes,
    )?;
    let refresh = create_refresh_token(
        user_id,
        &state.auth.jwt_signing_key,
        state.auth.refresh_expires_days,
    )?;
    let expires_at = (Utc::now() + Duration::days(state.auth.refresh_expires_days)).naive_utc();
    sqlx::query(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, tenant_id) \
         VALUES ($1, $2, $3, false, $4)",
    )
    .bind(user_id)
    .bind(token_hash(&refresh))
    .bind(expires_at)
    .bind(tenant)
    .execute(&state.db)
    .await?;
    Ok((access, refresh))
}

/// POST /auth/refresh body.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RefreshRequest {
    refresh_token: String,
}

/// Documentation-only mirror of `refresh`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    token_type: String,
    /// Access-token lifetime in seconds.
    expires_in: i64,
}

#[derive(sqlx::FromRow)]
struct RefreshRow {
    id: i32,
    user_id: i32,
    /// Read straight off this row (denormalized at issuance by
    /// `issue_token_pair`) rather than re-derived via a `users` join — see
    /// docs/v2-port/tenancy-model.md §2.
    tenant_id: uuid::Uuid,
}

/// POST /auth/refresh — unauthenticated (the refresh token in the body is
/// the credential; no bearer header is required or checked).
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    tag = "auth",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Rotated access/refresh token pair", body = RefreshResponse),
        (status = 401, description = "Invalid, revoked, or expired refresh token", body = ErrorResponse),
    ),
)]
pub(crate) async fn refresh(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<RefreshRequest>,
) -> Result<(HeaderMap, Json<serde_json::Value>), ApiError> {
    let claims = decode_refresh(&body.refresh_token, &state.auth.jwt_verify_key)?;
    let hash = token_hash(&body.refresh_token);

    let row = sqlx::query_as::<_, RefreshRow>(
        "SELECT id, user_id, tenant_id FROM refresh_tokens \
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

    let (access, new_refresh) =
        issue_token_pair(&state, row.user_id, &user.role, row.tenant_id).await?;

    // H2 audit fix: rotate all three cookies alongside the rotated
    // response-body token pair.
    let cookie_headers = cookies::auth_cookies(
        &access,
        &new_refresh,
        &cookies::generate_csrf_token(),
        state.auth.access_expires_minutes * 60,
        state.auth.refresh_expires_days * 86_400,
    )?;

    Ok((
        cookie_headers,
        Json(serde_json::json!({
            "access_token": access,
            "refresh_token": new_refresh,
            "token_type": "Bearer",
            "expires_in": state.auth.access_expires_minutes * 60,
        })),
    ))
}

/// Documentation-only mirror of `logout`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct LogoutResponse {
    message: String,
    tokens_revoked: u64,
}

/// POST /auth/logout — revokes every refresh token belonging to the caller.
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    tag = "auth",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "All refresh tokens revoked", body = LogoutResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn logout(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<(HeaderMap, Json<serde_json::Value>), ApiError> {
    // v1 counts the pyDAL update over ALL of the user's rows (already-
    // revoked ones included) — no `revoked = false` filter.
    let result = sqlx::query("UPDATE refresh_tokens SET revoked = true WHERE user_id = $1")
        .bind(user.id)
        .execute(&state.db)
        .await?;

    // H2 audit fix: expire all three cookies on logout, mirroring the
    // response-body-only contract v1 clients never saw.
    let cookie_headers = cookies::clear_auth_cookies()?;

    Ok((
        cookie_headers,
        Json(serde_json::json!({
            "message": "Successfully logged out",
            "tokens_revoked": result.rows_affected(),
        })),
    ))
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

/// Documentation-only mirror of `me`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct MeResponse {
    id: i32,
    email: String,
    full_name: Option<String>,
    role: String,
    is_active: bool,
    mfa_enabled: bool,
    created_at: Option<String>,
}

/// GET /auth/me — the caller's own profile (mirrors `g.current_user`).
#[utoipa::path(
    get,
    path = "/api/v1/auth/me",
    tag = "auth",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Current authenticated user", body = MeResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn me(user: CurrentUser) -> Json<serde_json::Value> {
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

/// POST /auth/register body.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct RegisterRequest {
    email: String,
    password: String,
    #[serde(default)]
    full_name: String,
}

/// User summary embedded in [`RegisterResponse`].
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct RegisterUser {
    id: i32,
    email: String,
    full_name: String,
    role: String,
}

/// Documentation-only mirror of `register`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct RegisterResponse {
    message: String,
    user: RegisterUser,
}

/// POST /auth/register — unauthenticated self-service signup; always
/// creates a `viewer`-role account (see `PublicApiDoc` note on `login`
/// above — `register` itself is NOT part of the public doc, only `login`
/// is, per `docs/v2-port/openapi-pattern.md` §6).
///
/// Tenancy (v2.0 decision, docs/v2-port/tenancy-model.md §8): admin-
/// provisioned tenants only — this endpoint never creates a tenant, it
/// attaches the new registrant to the seeded bootstrap tenant
/// ([`crate::auth::DEFAULT_TENANT_ID`]). There is no inviter/admin context
/// to derive a different tenant from at this unauthenticated call site;
/// self-serve *multi-tenant* signup is a v2.1 backlog item.
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    tag = "auth",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Account created", body = RegisterResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 409, description = "Email already registered", body = ErrorResponse),
    ),
)]
pub(crate) async fn register(
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
        "INSERT INTO users (email, password_hash, full_name, role, is_active, updated_at, \
         tenant_id) \
         VALUES ($1, $2, $3, 'viewer', true, now(), $4) RETURNING id",
    )
    .bind(&email)
    .bind(&password_hash)
    .bind(&body.full_name)
    .bind(auth::default_tenant_uuid())
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
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use cookie::Cookie as TestCookie;

    use crate::routes::test_support::{authed_user, db_state};

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    async fn test_server_with_state(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    /// Seeds a user row with a real bcrypt hash for `password`, bypassing
    /// the HTTP surface so login tests exercise a known-good credential.
    async fn seed_login_user(
        state: &AppState,
        email: &str,
        password: &str,
        role: &str,
        is_active: bool,
    ) -> i32 {
        let hash = auth::hash_password(password).unwrap_or_else(|e| panic!("hash: {e:?}"));
        let (id,): (i32,) = sqlx::query_as(
            "INSERT INTO users (email, password_hash, full_name, role, is_active, \
             failed_login_attempts, created_at, tenant_id) \
             VALUES ($1, $2, 'Test User', $3, $4, 0, now(), $5) RETURNING id",
        )
        .bind(email)
        .bind(&hash)
        .bind(role)
        .bind(is_active)
        .bind(auth::default_tenant_uuid())
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed_login_user: {e}"));
        id
    }

    #[tokio::test]
    async fn login_rejects_invalid_email_and_empty_password() {
        let state = db_state(dev_license()).await;
        let server = test_server_with_state(state).await;

        let res = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "not-an-email", "password": "x"}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["details"][0]["loc"], serde_json::json!(["email"]));

        let res = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "a@example.com", "password": ""}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["details"][0]["loc"], serde_json::json!(["password"]));
    }

    #[tokio::test]
    async fn login_rejects_unknown_email() {
        let state = db_state(dev_license()).await;
        let server = test_server_with_state(state).await;
        let res = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "ghost@example.com", "password": "whatever1"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Invalid email or password");
    }

    #[tokio::test]
    async fn login_rejects_wrong_password_and_locks_after_max_attempts() {
        let state = db_state(dev_license()).await;
        seed_login_user(
            &state,
            "lockout@example.com",
            "correct-horse",
            "viewer",
            true,
        )
        .await;
        let server = test_server_with_state(state).await;

        // max_login_attempts = 5 (test default) — 5 wrong attempts land the
        // account in the locked state; the 6th sees the lockout message.
        for _ in 0..5 {
            let res = server
                .post("/api/v1/auth/login")
                .json(&serde_json::json!({"email": "lockout@example.com", "password": "wrong"}))
                .await;
            res.assert_status(StatusCode::UNAUTHORIZED);
            let body: serde_json::Value = res.json();
            assert_eq!(body["error"], "Invalid email or password");
        }
        let res = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "lockout@example.com", "password": "wrong"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Account is locked. Please try again later.");

        // Even the correct password is rejected while locked.
        let res = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "lockout@example.com", "password": "correct-horse"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Account is locked. Please try again later.");
    }

    #[tokio::test]
    async fn login_rejects_deactivated_account_with_correct_password() {
        let state = db_state(dev_license()).await;
        seed_login_user(&state, "gone@example.com", "correct-horse", "viewer", false).await;
        let server = test_server_with_state(state).await;
        let res = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "gone@example.com", "password": "correct-horse"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Account is deactivated");
    }

    #[tokio::test]
    async fn login_succeeds_and_issues_token_pair() {
        let state = db_state(dev_license()).await;
        let id = seed_login_user(&state, "ok@example.com", "correct-horse", "admin", true).await;
        let server = test_server_with_state(state).await;
        let res = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "OK@Example.com", "password": "correct-horse"}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["token_type"], "Bearer");
        assert!(body["access_token"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(
            body["refresh_token"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );
        assert_eq!(body["user"]["id"], id);
        assert_eq!(body["user"]["email"], "ok@example.com");
        assert_eq!(body["user"]["role"], "admin");

        // Regression: the minted access token must carry the house Claims
        // shape with a real, non-empty tenant claim (docs/v2-port/
        // tenancy-model.md §2) — decode it the same way any consumer would.
        // `db_state`/`AppStateInner::for_tests_with_db` always fixes
        // `jwt_verify_key` to this fixture (src/state.rs — byte-identical
        // to `skauswatch_testkit::jwt::verify_key`).
        let access = body["access_token"].as_str().unwrap_or_default();
        let claims = match auth::decode_access(access, skauswatch_testkit::jwt::verify_key()) {
            Ok(c) => c,
            Err(e) => panic!("decode minted access token: {e:?}"),
        };
        assert_eq!(claims.sub, id.to_string());
        assert_eq!(claims.tenant, crate::auth::DEFAULT_TENANT_ID);
        assert!(claims.has_scope("users:admin"));
    }

    /// H2 audit fix: login must set the HttpOnly cookie pair + the
    /// JS-readable `sw_csrf` cookie, with the exact attributes the webui
    /// frontend agent's cookie contract requires, IN ADDITION TO the
    /// unchanged response-body token (Bearer clients keep working).
    #[tokio::test]
    async fn login_sets_httponly_secure_cookies_alongside_unchanged_body_token() {
        let state = db_state(dev_license()).await;
        seed_login_user(
            &state,
            "cookies@example.com",
            "correct-horse",
            "admin",
            true,
        )
        .await;
        let server = test_server_with_state(state).await;
        let res = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "cookies@example.com", "password": "correct-horse"}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        let body_access = body["access_token"].as_str().unwrap_or_default();
        assert!(!body_access.is_empty(), "body token must be unchanged");

        let access: TestCookie = res.cookie("sw_access");
        assert_eq!(access.value(), body_access);
        assert_eq!(access.http_only(), Some(true));
        assert_eq!(access.secure(), Some(true));
        assert_eq!(access.same_site(), Some(cookie::SameSite::Lax));
        assert_eq!(access.path(), Some("/"));

        let refresh: TestCookie = res.cookie("sw_refresh");
        assert_eq!(
            refresh.value(),
            body["refresh_token"].as_str().unwrap_or_default()
        );
        assert_eq!(refresh.http_only(), Some(true));
        assert_eq!(refresh.secure(), Some(true));
        assert_eq!(refresh.same_site(), Some(cookie::SameSite::Strict));
        assert_eq!(refresh.path(), Some("/api/v1/auth"));

        let csrf: TestCookie = res.cookie("sw_csrf");
        assert_ne!(
            csrf.http_only(),
            Some(true),
            "sw_csrf must be JS-readable, not HttpOnly"
        );
        assert_eq!(csrf.secure(), Some(true));
        assert_eq!(csrf.same_site(), Some(cookie::SameSite::Lax));
        assert!(!csrf.value().is_empty());
    }

    /// A request authenticated purely via the `sw_access` cookie (no
    /// `Authorization` header at all) must succeed exactly like Bearer.
    #[tokio::test]
    async fn cookie_authed_request_succeeds_same_as_bearer() {
        let state = db_state(dev_license()).await;
        let id = seed_login_user(
            &state,
            "cookie-only@example.com",
            "correct-horse",
            "admin",
            true,
        )
        .await;
        let server = test_server_with_state(state).await;
        let login = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "cookie-only@example.com", "password": "correct-horse"}))
            .await;
        login.assert_status_ok();
        let access: TestCookie = login.cookie("sw_access");

        let res = server
            .get("/api/v1/auth/me")
            .add_cookie(TestCookie::new("sw_access", access.value().to_owned()))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["id"], id);
    }

    /// A cookie-authed mutating request without a matching `X-CSRF-Token`
    /// must 403; the identical request WITH the header must succeed —
    /// double-submit CSRF, exercised end-to-end through `/auth/logout`.
    #[tokio::test]
    async fn cookie_authed_logout_requires_matching_csrf_token() {
        let state = db_state(dev_license()).await;
        seed_login_user(
            &state,
            "csrf-logout@example.com",
            "correct-horse",
            "viewer",
            true,
        )
        .await;
        let server = test_server_with_state(state).await;
        let login = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "csrf-logout@example.com", "password": "correct-horse"}))
            .await;
        login.assert_status_ok();
        let access: TestCookie = login.cookie("sw_access");
        let csrf: TestCookie = login.cookie("sw_csrf");

        // No X-CSRF-Token header at all → 403.
        let missing = server
            .post("/api/v1/auth/logout")
            .add_cookie(TestCookie::new("sw_access", access.value().to_owned()))
            .add_cookie(TestCookie::new("sw_csrf", csrf.value().to_owned()))
            .await;
        missing.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = missing.json();
        assert_eq!(body["error"], "CSRF token missing or invalid");

        // Matching X-CSRF-Token header → success, cookies cleared.
        let ok = server
            .post("/api/v1/auth/logout")
            .add_cookie(TestCookie::new("sw_access", access.value().to_owned()))
            .add_cookie(TestCookie::new("sw_csrf", csrf.value().to_owned()))
            .add_header("x-csrf-token", csrf.value())
            .await;
        ok.assert_status_ok();
        let body: serde_json::Value = ok.json();
        assert_eq!(body["message"], "Successfully logged out");
    }

    /// Critical regression: a Bearer-authed mutating request with NO
    /// `X-CSRF-Token` at all must still succeed — this is what protects the
    /// CLI/mobile/golden-parity-harness write paths.
    #[tokio::test]
    async fn bearer_authed_logout_succeeds_without_any_csrf_token() {
        let state = db_state(dev_license()).await;
        let (_, token) = authed_user(&state, "bearer-no-csrf@example.com", "viewer").await;
        let server = test_server_with_state(state).await;
        let res = server
            .post("/api/v1/auth/logout")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
    }

    /// Logout must expire all three cookies (`Max-Age=0`), regardless of
    /// which auth mechanism reached it.
    #[tokio::test]
    async fn logout_expires_all_three_cookies() {
        let state = db_state(dev_license()).await;
        let (_, token) = authed_user(&state, "logout-clears-cookies@example.com", "viewer").await;
        let server = test_server_with_state(state).await;
        let res = server
            .post("/api/v1/auth/logout")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();

        for name in ["sw_access", "sw_refresh", "sw_csrf"] {
            let cleared: TestCookie = res.cookie(name);
            let max_age = cleared
                .max_age()
                .unwrap_or_else(|| panic!("{name}: expected Max-Age on cleared cookie"));
            assert_eq!(
                max_age,
                cookie::time::Duration::seconds(0),
                "{name}: expected Max-Age=0"
            );
        }
    }

    #[tokio::test]
    async fn refresh_rejects_garbage_and_unknown_tokens() {
        let state = db_state(dev_license()).await;
        let server = test_server_with_state(state).await;
        let res = server
            .post("/api/v1/auth/refresh")
            .json(&serde_json::json!({"refresh_token": "not-a-jwt"}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);

        // Well-formed but never issued (never stored) → revoked message.
        let state2 = db_state(dev_license()).await;
        let fabricated = create_refresh_token(1, &state2.auth.jwt_signing_key, 7)
            .unwrap_or_else(|e| panic!("encode: {e:?}"));
        let server2 = test_server_with_state(state2).await;
        let res = server2
            .post("/api/v1/auth/refresh")
            .json(&serde_json::json!({"refresh_token": fabricated}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Refresh token has been revoked");
    }

    #[tokio::test]
    async fn refresh_rotates_token_and_revokes_the_old_one() {
        let state = db_state(dev_license()).await;
        seed_login_user(&state, "rot@example.com", "correct-horse", "viewer", true).await;
        let server = test_server_with_state(state).await;

        let login = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "rot@example.com", "password": "correct-horse"}))
            .await;
        login.assert_status_ok();
        let login_body: serde_json::Value = login.json();
        let refresh_token = login_body["refresh_token"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let first = server
            .post("/api/v1/auth/refresh")
            .json(&serde_json::json!({"refresh_token": refresh_token}))
            .await;
        first.assert_status_ok();
        let first_body: serde_json::Value = first.json();
        assert_eq!(first_body["token_type"], "Bearer");
        assert!(
            first_body["access_token"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        );

        // Regression: rotation must preserve the tenant claim (read off the
        // `refresh_tokens` row, not re-derived — docs/v2-port/
        // tenancy-model.md §2), not silently drop it on the re-minted token.
        let rotated_access = first_body["access_token"].as_str().unwrap_or_default();
        let claims =
            match auth::decode_access(rotated_access, skauswatch_testkit::jwt::verify_key()) {
                Ok(c) => c,
                Err(e) => panic!("decode rotated access token: {e:?}"),
            };
        assert_eq!(claims.tenant, crate::auth::DEFAULT_TENANT_ID);

        // The original refresh token was revoked by rotation — reusing it
        // must now fail.
        let reused = server
            .post("/api/v1/auth/refresh")
            .json(&serde_json::json!({"refresh_token": refresh_token}))
            .await;
        reused.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = reused.json();
        assert_eq!(body["error"], "Refresh token has been revoked");
    }

    /// H2 audit fix: rotation must also re-set the cookie trio, not just
    /// the response body.
    #[tokio::test]
    async fn refresh_sets_rotated_cookies() {
        let state = db_state(dev_license()).await;
        seed_login_user(
            &state,
            "refresh-cookies@example.com",
            "correct-horse",
            "viewer",
            true,
        )
        .await;
        let server = test_server_with_state(state).await;
        let login = server
            .post("/api/v1/auth/login")
            .json(&serde_json::json!({"email": "refresh-cookies@example.com", "password": "correct-horse"}))
            .await;
        login.assert_status_ok();
        let login_body: serde_json::Value = login.json();
        let refresh_token = login_body["refresh_token"]
            .as_str()
            .unwrap_or_default()
            .to_owned();

        let res = server
            .post("/api/v1/auth/refresh")
            .json(&serde_json::json!({"refresh_token": refresh_token}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();

        let access: TestCookie = res.cookie("sw_access");
        assert_eq!(
            access.value(),
            body["access_token"].as_str().unwrap_or_default()
        );
        assert_eq!(access.http_only(), Some(true));

        let refresh: TestCookie = res.cookie("sw_refresh");
        assert_eq!(
            refresh.value(),
            body["refresh_token"].as_str().unwrap_or_default()
        );
        assert_eq!(refresh.http_only(), Some(true));

        let csrf: TestCookie = res.cookie("sw_csrf");
        assert!(!csrf.value().is_empty());
    }

    #[tokio::test]
    async fn refresh_rejects_deactivated_user() {
        let state = db_state(dev_license()).await;
        let id =
            seed_login_user(&state, "deact@example.com", "correct-horse", "viewer", true).await;
        let refresh = create_refresh_token(id, &state.auth.jwt_signing_key, 7)
            .unwrap_or_else(|e| panic!("encode: {e:?}"));
        sqlx::query(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, tenant_id) \
             VALUES ($1, $2, now() + interval '7 days', false, $3)",
        )
        .bind(id)
        .bind(token_hash(&refresh))
        .bind(auth::default_tenant_uuid())
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed refresh: {e}"));
        sqlx::query("UPDATE users SET is_active = false WHERE id = $1")
            .bind(id)
            .execute(&state.db)
            .await
            .unwrap_or_else(|e| panic!("deactivate: {e}"));

        let server = test_server_with_state(state).await;
        let res = server
            .post("/api/v1/auth/refresh")
            .json(&serde_json::json!({"refresh_token": refresh}))
            .await;
        res.assert_status(StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "User not found or deactivated");
    }

    #[tokio::test]
    async fn logout_requires_auth_and_revokes_tokens() {
        let state = db_state(dev_license()).await;
        let (id, token) = authed_user(&state, "logout@example.com", "viewer").await;
        sqlx::query(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked, tenant_id) \
             VALUES ($1, 'h1', now() + interval '7 days', false, $2), \
                    ($1, 'h2', now() + interval '7 days', false, $2)",
        )
        .bind(id)
        .bind(auth::default_tenant_uuid())
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed refresh tokens: {e}"));
        let server = test_server_with_state(state).await;

        let unauth = server.post("/api/v1/auth/logout").await;
        unauth.assert_status(StatusCode::UNAUTHORIZED);

        let res = server
            .post("/api/v1/auth/logout")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["message"], "Successfully logged out");
        assert_eq!(body["tokens_revoked"], 2);
    }

    #[tokio::test]
    async fn me_requires_auth_and_returns_current_user_shape() {
        let state = db_state(dev_license()).await;
        let (id, token) = authed_user(&state, "me@example.com", "maintainer").await;
        let server = test_server_with_state(state).await;

        let unauth = server.get("/api/v1/auth/me").await;
        unauth.assert_status(StatusCode::UNAUTHORIZED);

        let res = server
            .get("/api/v1/auth/me")
            .authorization_bearer(&token)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["id"], id);
        assert_eq!(body["email"], "me@example.com");
        assert_eq!(body["role"], "maintainer");
        assert_eq!(body["is_active"], true);
        assert!(body["created_at"].is_string());
    }

    #[tokio::test]
    async fn register_validates_email_password_and_full_name() {
        let state = db_state(dev_license()).await;
        let server = test_server_with_state(state).await;

        let res = server
            .post("/api/v1/auth/register")
            .json(&serde_json::json!({"email": "bad", "password": "longenough1"}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);

        let res = server
            .post("/api/v1/auth/register")
            .json(&serde_json::json!({"email": "a@example.com", "password": "short"}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);

        let res = server
            .post("/api/v1/auth/register")
            .json(&serde_json::json!({
                "email": "a@example.com",
                "password": "x".repeat(129),
            }))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);

        let res = server
            .post("/api/v1/auth/register")
            .json(&serde_json::json!({
                "email": "a@example.com",
                "password": "longenough1",
                "full_name": "x".repeat(256),
            }))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_succeeds_then_rejects_duplicate_email() {
        let state = db_state(dev_license()).await;
        let server = test_server_with_state(state).await;

        let res = server
            .post("/api/v1/auth/register")
            .json(&serde_json::json!({
                "email": "New@Example.com",
                "password": "longenough1",
                "full_name": "New Person",
            }))
            .await;
        res.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["message"], "Registration successful");
        assert_eq!(body["user"]["email"], "new@example.com");
        assert_eq!(body["user"]["role"], "viewer");

        let dup = server
            .post("/api/v1/auth/register")
            .json(&serde_json::json!({
                "email": "new@example.com",
                "password": "anotherpass1",
            }))
            .await;
        dup.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = dup.json();
        assert_eq!(body["error"], "Email already registered");
    }

    /// "First-user bootstrap" (docs/v2-port/tenancy-model.md §8): the only
    /// unauthenticated user-creation path this service exposes always
    /// attaches the new account to the seeded default tenant — there is no
    /// admin/inviter context yet for whoever registers first (or ever, via
    /// this endpoint) to be placed anywhere else.
    #[tokio::test]
    async fn register_bootstraps_new_user_into_default_tenant() {
        let state = db_state(dev_license()).await;
        let server = test_server_with_state(state.clone()).await;

        let res = server
            .post("/api/v1/auth/register")
            .json(&serde_json::json!({
                "email": "bootstrap@example.com",
                "password": "longenough1",
            }))
            .await;
        res.assert_status(StatusCode::CREATED);

        let (tenant_id,): (uuid::Uuid,) =
            sqlx::query_as("SELECT tenant_id FROM users WHERE email = $1")
                .bind("bootstrap@example.com")
                .fetch_one(&state.db)
                .await
                .unwrap_or_else(|e| panic!("verify bootstrap tenant: {e}"));
        assert_eq!(tenant_id.to_string(), crate::auth::DEFAULT_TENANT_ID);
    }

    /// Regression for finding #8 (login timing oracle): the unknown-email
    /// dummy verify must actually pay bcrypt's real cost-factor work, not
    /// fail-fast, or it doesn't equalize anything. Compares against a
    /// deliberately malformed hash (which fails parsing near-instantly) with
    /// a generous 10x margin to avoid CI timing flakiness while still
    /// proving the dummy path isn't a cheap short-circuit.
    #[test]
    fn dummy_password_hash_costs_real_bcrypt_work_not_a_fast_fail() {
        assert!(DUMMY_PASSWORD_HASH.starts_with("$2"));
        assert!(!auth::verify_password(
            "definitely-not-it",
            &DUMMY_PASSWORD_HASH
        ));

        let malformed = "not-a-bcrypt-hash";
        let start = std::time::Instant::now();
        let _ = auth::verify_password("x", malformed);
        let malformed_elapsed = start.elapsed();

        let start = std::time::Instant::now();
        let _ = auth::verify_password("x", &DUMMY_PASSWORD_HASH);
        let dummy_elapsed = start.elapsed();

        assert!(
            dummy_elapsed > malformed_elapsed * 10,
            "dummy verify ({dummy_elapsed:?}) should cost real bcrypt work, \
             far more than a fail-fast malformed-hash parse ({malformed_elapsed:?})"
        );
    }

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
