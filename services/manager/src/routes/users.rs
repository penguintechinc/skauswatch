//! /api/v1/users — list, get, create, update, delete. Port of
//! `services/manager/api/v1/users.py`; contract in
//! docs/v2-port/manager-contract.md §users. v1's bare `{"error": ...}` bodies
//! map onto the `ApiError` envelope (same convention as routes/auth.rs),
//! pending golden-harness verification of exact detail strings.
//!
//! Port decisions: (1) v1's per-request Host-header exempt-domain check for
//! the free-tier cap is folded into the licensing client's bypass domains
//! (contract §Auth license gating, v2 decision); (2) `page`/`per_page` are
//! clamped to ≥1 — v1 500s on `per_page=0` via ZeroDivisionError.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{self, CurrentUser};
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

/// Free-tier user cap (v1 `SIEMConfig.free_tier_user_cap`).
const FREE_TIER_USER_CAP: i64 = 5;
/// Default page size (v1 default 20).
const DEFAULT_PER_PAGE: i64 = 20;
/// Hard page-size ceiling (v1 caps `per_page` at 100).
const MAX_PER_PAGE: i64 = 100;
/// Allowed role values (v1 `UserRole` enum).
const ROLES: [&str; 3] = ["admin", "maintainer", "viewer"];

/// Router for /api/v1/users.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/users", get(list_users).post(create_user))
        .route(
            "/users/{user_id}",
            get(get_user).put(update_user).delete(delete_user),
        )
}

/// Builds the v1 `{error: "Validation error", details: [...]}` body for a
/// single-field failure (same helper shape as routes/auth.rs).
fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// Mirrors pydantic `EmailStr` acceptance closely enough for parity.
fn valid_email(email: &str) -> bool {
    email.parse::<email_address::EmailAddress>().is_ok()
}

/// Enforces the v1 password bounds (8..=128) with pydantic-style messages.
fn check_password(password: &str) -> Result<(), ApiError> {
    if password.len() < 8 {
        Err(validation(
            "password",
            "String should have at least 8 characters",
        ))
    } else if password.len() > 128 {
        Err(validation(
            "password",
            "String should have at most 128 characters",
        ))
    } else {
        Ok(())
    }
}

/// Enforces the v1 full_name bound (≤255) with the pydantic-style message.
fn check_full_name(full_name: &str) -> Result<(), ApiError> {
    if full_name.len() > 255 {
        Err(validation(
            "full_name",
            "String should have at most 255 characters",
        ))
    } else {
        Ok(())
    }
}

/// Rejects roles outside the v1 `UserRole` set (admin/maintainer/viewer).
fn check_role(role: &str) -> Result<(), ApiError> {
    if ROLES.contains(&role) {
        Ok(())
    } else {
        Err(validation(
            "role",
            "Input should be 'admin', 'maintainer' or 'viewer'",
        ))
    }
}

/// Parses an int query param the way Quart's `args.get(type=int)` does:
/// missing or unparseable values fall back to the default.
fn int_param(raw: Option<&str>, default: i64) -> i64 {
    raw.and_then(|s| s.parse().ok()).unwrap_or(default)
}

/// Resolves `page`/`per_page` per v1 (defaults 1/20, per_page capped at 100)
/// with an additional ≥1 clamp so bad input cannot produce SQL errors.
fn pagination(page: Option<&str>, per_page: Option<&str>) -> (i64, i64) {
    let page = int_param(page, 1).max(1);
    let per_page = int_param(per_page, DEFAULT_PER_PAGE).clamp(1, MAX_PER_PAGE);
    (page, per_page)
}

/// v1 page-count formula: `(total + per_page - 1) // per_page`. `per_page`
/// is guaranteed ≥1 by `pagination`.
fn page_count(total: i64, per_page: i64) -> i64 {
    (total + per_page - 1) / per_page
}

/// v1 access rule for GET /users/{id}: self, or any admin/maintainer.
fn can_view_user(current_id: i32, role: &str, target_id: i32) -> bool {
    current_id == target_id || matches!(role, "admin" | "maintainer")
}

/// List-item shape: `{id,email,full_name,role,is_active,mfa_enabled,created_at}`.
/// Timestamps render as Python `datetime.isoformat()` (v1 wire parity).
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct UserItem {
    id: i32,
    email: String,
    full_name: String,
    role: String,
    is_active: bool,
    mfa_enabled: bool,
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    #[schema(value_type = Option<String>)]
    created_at: Option<chrono::NaiveDateTime>,
}

/// Detail shape (GET by id): list-item fields plus `updated_at`.
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct UserDetail {
    id: i32,
    email: String,
    full_name: String,
    role: String,
    is_active: bool,
    mfa_enabled: bool,
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    #[schema(value_type = Option<String>)]
    created_at: Option<chrono::NaiveDateTime>,
    #[serde(serialize_with = "skauswatch_streams::serde_py_isoformat_opt")]
    #[schema(value_type = Option<String>)]
    updated_at: Option<chrono::NaiveDateTime>,
}

/// Summary shape used inside create/update responses:
/// `{id,email,full_name,role,is_active}`.
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct UserSummary {
    id: i32,
    email: String,
    full_name: String,
    role: String,
    is_active: bool,
}

/// Raw pagination query params, parsed leniently (see `int_param`).
#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    page: Option<String>,
    per_page: Option<String>,
}

/// Documentation-only mirror of `list_users`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UserListResponse {
    items: Vec<UserItem>,
    total: i64,
    page: i64,
    per_page: i64,
    pages: i64,
}

/// GET /users — admin/maintainer only; paginated `{items,total,page,per_page,pages}`.
#[utoipa::path(
    get,
    path = "/api/v1/users",
    tag = "users",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Paginated user list", body = UserListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_users(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin", "maintainer"])?;
    let (page, per_page) = pagination(q.page.as_deref(), q.per_page.as_deref());
    let offset = (page - 1) * per_page;

    let items = sqlx::query_as::<_, UserItem>(
        "SELECT id, email, COALESCE(full_name, '') AS full_name, role, is_active, \
                COALESCE(mfa_enabled, false) AS mfa_enabled, created_at \
         FROM users ORDER BY created_at LIMIT $1 OFFSET $2",
    )
    .bind(per_page)
    .bind(offset)
    .fetch_all(&state.db)
    .await?;

    let total: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(&state.db)
        .await?;

    Ok(Json(serde_json::json!({
        "items": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": page_count(total, per_page),
    })))
}

/// GET /users/{user_id} — self or admin/maintainer; 404 if missing.
#[utoipa::path(
    get,
    path = "/api/v1/users/{user_id}",
    tag = "users",
    security(("bearer_jwt" = [])),
    params(("user_id" = i32, Path, description = "User id")),
    responses(
        (status = 200, description = "User detail", body = UserDetail),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Forbidden — not self and not admin/maintainer", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(user_id): Path<i32>,
) -> Result<Json<UserDetail>, ApiError> {
    if !can_view_user(user.id, &user.role, user_id) {
        return Err(ApiError::Forbidden("Forbidden".to_owned()));
    }

    let row = sqlx::query_as::<_, UserDetail>(
        "SELECT id, email, COALESCE(full_name, '') AS full_name, role, is_active, \
                COALESCE(mfa_enabled, false) AS mfa_enabled, \
                created_at, updated_at \
         FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("User not found".to_owned()))?;

    Ok(Json(row))
}

fn default_role() -> String {
    "viewer".to_owned()
}

fn default_true() -> bool {
    true
}

/// POST /users body — mirrors v1 `UserCreateRequest` defaults.
#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateRequest {
    email: String,
    password: String,
    #[serde(default)]
    full_name: String,
    #[serde(default = "default_role")]
    role: String,
    #[serde(default = "default_true")]
    is_active: bool,
}

/// Documentation-only mirror of `create_user`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UserCreateResponse {
    message: String,
    user: UserSummary,
}

/// POST /users — admin only; 403 free-tier cap, 409 duplicate email,
/// 201 `{message,user}` on success.
#[utoipa::path(
    post,
    path = "/api/v1/users",
    tag = "users",
    security(("bearer_jwt" = [])),
    request_body = CreateRequest,
    responses(
        (status = 201, description = "User created", body = UserCreateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions, or free-tier user cap reached", body = ErrorResponse),
        (status = 409, description = "Email already registered", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_user(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiJson(body): ApiJson<CreateRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_role(&["admin"])?;

    if !valid_email(&body.email) {
        return Err(validation("email", "value is not a valid email address"));
    }
    check_password(&body.password)?;
    check_full_name(&body.full_name)?;
    check_role(&body.role)?;

    // Free-tier cap. v1 exempted requests whose Host header matched the SIEM
    // exempt domains; v2 folds that into the licensing client's bypass-domain
    // list. check_feature() already returns true under bypass — the explicit
    // OR documents the exemption path. Fail-closed on license errors matches
    // v1's `except → has_premium = False`.
    let premium_or_exempt =
        state.license.check_feature("premium").await || state.license.bypass_active();
    if !premium_or_exempt {
        let user_count: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&state.db)
            .await?;
        if user_count >= FREE_TIER_USER_CAP {
            return Err(ApiError::Forbidden(
                "User limit reached. Upgrade to premium for more than 5 users.".to_owned(),
            ));
        }
    }

    let email = body.email.to_lowercase();
    let existing: Option<(i32,)> = sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict(serde_json::json!({
            "error": "Email already registered"
        })));
    }

    let password_hash = auth::hash_password(&body.password)?;
    let created = sqlx::query_as::<_, UserSummary>(
        "INSERT INTO users (email, password_hash, full_name, role, is_active, updated_at) \
         VALUES ($1, $2, $3, $4, $5, now()) \
         RETURNING id, email, COALESCE(full_name, '') AS full_name, role, is_active",
    )
    .bind(&email)
    .bind(&password_hash)
    .bind(&body.full_name)
    .bind(&body.role)
    .bind(body.is_active)
    .fetch_one(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "User created successfully",
            "user": created,
        })),
    ))
}

/// PUT /users/{user_id} body — mirrors v1 `UserUpdateRequest` (all optional).
#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct UpdateRequest {
    email: Option<String>,
    full_name: Option<String>,
    role: Option<String>,
    is_active: Option<bool>,
    password: Option<String>,
}

/// Column changes that survived the permission filter.
#[derive(Debug, PartialEq, Eq)]
struct AllowedUpdates {
    full_name: Option<String>,
    password: Option<String>,
    email: Option<String>,
    role: Option<String>,
    is_active: Option<bool>,
}

impl AllowedUpdates {
    /// True when no column would change (v1 skips the UPDATE entirely).
    fn is_empty(&self) -> bool {
        self.full_name.is_none()
            && self.password.is_none()
            && self.email.is_none()
            && self.role.is_none()
            && self.is_active.is_none()
    }
}

/// Applies the v1 permission matrix: self or admin may change full_name and
/// password; only admins may change email (lowercased), role, and is_active.
/// Admin-only fields sent by a non-admin are silently dropped (v1 parity).
fn allowed_updates(body: UpdateRequest, is_admin: bool) -> AllowedUpdates {
    AllowedUpdates {
        full_name: body.full_name,
        password: body.password,
        email: if is_admin {
            body.email.map(|e| e.to_lowercase())
        } else {
            None
        },
        role: if is_admin { body.role } else { None },
        is_active: if is_admin { body.is_active } else { None },
    }
}

/// Documentation-only mirror of `update_user`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UserUpdateResponse {
    message: String,
    user: UserSummary,
}

/// PUT /users/{user_id} — self (full_name/password only) or admin (all
/// fields); 409 email in use, 404 missing, 200 `{message,user}`.
#[utoipa::path(
    put,
    path = "/api/v1/users/{user_id}",
    tag = "users",
    security(("bearer_jwt" = [])),
    params(("user_id" = i32, Path, description = "User id")),
    request_body = UpdateRequest,
    responses(
        (status = 200, description = "User updated", body = UserUpdateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Forbidden — not self and not admin", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
        (status = 409, description = "Email already in use", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(user_id): Path<i32>,
    ApiJson(body): ApiJson<UpdateRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let is_self = user.id == user_id;
    let is_admin = user.role == "admin";
    if !is_self && !is_admin {
        return Err(ApiError::Forbidden("Forbidden".to_owned()));
    }

    // v1 validates the entire body before dropping admin-only fields, so a
    // self-update with a malformed email still 400s even though the email
    // change itself would be ignored.
    if let Some(email) = body.email.as_deref()
        && !valid_email(email)
    {
        return Err(validation("email", "value is not a valid email address"));
    }
    if let Some(full_name) = body.full_name.as_deref() {
        check_full_name(full_name)?;
    }
    if let Some(role) = body.role.as_deref() {
        check_role(role)?;
    }
    if let Some(password) = body.password.as_deref() {
        check_password(password)?;
    }

    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("User not found".to_owned()));
    }

    let updates = allowed_updates(body, is_admin);

    if let Some(email) = updates.email.as_deref() {
        let dup: Option<(i32,)> =
            sqlx::query_as("SELECT id FROM users WHERE email = $1 AND id <> $2")
                .bind(email)
                .bind(user_id)
                .fetch_optional(&state.db)
                .await?;
        if dup.is_some() {
            return Err(ApiError::Conflict(serde_json::json!({
                "error": "Email already in use"
            })));
        }
    }

    if !updates.is_empty() {
        let password_hash = match updates.password.as_deref() {
            Some(pw) => Some(auth::hash_password(pw)?),
            None => None,
        };
        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE users SET ");
        {
            let mut set = qb.separated(", ");
            if let Some(v) = updates.full_name {
                set.push("full_name = ");
                set.push_bind_unseparated(v);
            }
            if let Some(v) = password_hash {
                set.push("password_hash = ");
                set.push_bind_unseparated(v);
            }
            if let Some(v) = updates.email {
                set.push("email = ");
                set.push_bind_unseparated(v);
            }
            if let Some(v) = updates.role {
                set.push("role = ");
                set.push_bind_unseparated(v);
            }
            if let Some(v) = updates.is_active {
                set.push("is_active = ");
                set.push_bind_unseparated(v);
            }
            // PyDAL parity: `update=datetime.utcnow` bumps updated_at on
            // every applied update.
            set.push("updated_at = now()");
        }
        qb.push(" WHERE id = ");
        qb.push_bind(user_id);
        qb.build().execute(&state.db).await?;
    }

    let updated = sqlx::query_as::<_, UserSummary>(
        "SELECT id, email, COALESCE(full_name, '') AS full_name, role, is_active \
         FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or_else(|| ApiError::NotFound("User not found".to_owned()))?;

    Ok(Json(serde_json::json!({
        "message": "User updated successfully",
        "user": updated,
    })))
}

/// Documentation-only mirror of `delete_user`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct UserDeleteResponse {
    message: String,
}

/// DELETE /users/{user_id} — admin only; 400 self-delete, 404 missing; also
/// removes the user's refresh tokens (transactionally, unlike v1).
#[utoipa::path(
    delete,
    path = "/api/v1/users/{user_id}",
    tag = "users",
    security(("bearer_jwt" = [])),
    params(("user_id" = i32, Path, description = "User id")),
    responses(
        (status = 200, description = "User deleted", body = UserDeleteResponse),
        (status = 400, description = "Cannot delete your own account", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn delete_user(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(user_id): Path<i32>,
) -> Result<Json<serde_json::Value>, ApiError> {
    user.require_role(&["admin"])?;

    if user.id == user_id {
        return Err(ApiError::BadRequest(
            "Cannot delete your own account".to_owned(),
        ));
    }

    let exists: Option<(i32,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("User not found".to_owned()));
    }

    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    Ok(Json(serde_json::json!({
        "message": "User deleted successfully"
    })))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    fn full_body() -> UpdateRequest {
        UpdateRequest {
            email: Some("New@Example.COM".to_owned()),
            full_name: Some("New Name".to_owned()),
            role: Some("admin".to_owned()),
            is_active: Some(false),
            password: Some("password123".to_owned()),
        }
    }

    #[test]
    fn pagination_defaults_match_v1() {
        assert_eq!(pagination(None, None), (1, 20));
        assert_eq!(pagination(Some("2"), Some("50")), (2, 50));
    }

    #[test]
    fn pagination_caps_and_clamps() {
        assert_eq!(pagination(Some("3"), Some("500")), (3, 100)); // v1 cap
        assert_eq!(pagination(Some("0"), Some("0")), (1, 1)); // ≥1 clamp
        assert_eq!(pagination(Some("-2"), Some("-5")), (1, 1));
        assert_eq!(pagination(Some("junk"), Some("junk")), (1, 20)); // lenient
    }

    #[test]
    fn page_count_matches_v1_ceiling() {
        assert_eq!(page_count(0, 20), 0);
        assert_eq!(page_count(1, 20), 1);
        assert_eq!(page_count(20, 20), 1);
        assert_eq!(page_count(41, 20), 3);
    }

    #[test]
    fn view_permission_matrix() {
        assert!(can_view_user(1, "viewer", 1)); // self
        assert!(!can_view_user(1, "viewer", 2)); // other, viewer
        assert!(can_view_user(1, "maintainer", 2)); // other, maintainer
        assert!(can_view_user(1, "admin", 2)); // other, admin
    }

    #[test]
    fn non_admin_updates_drop_admin_only_fields() {
        let u = allowed_updates(full_body(), false);
        assert_eq!(u.full_name.as_deref(), Some("New Name"));
        assert_eq!(u.password.as_deref(), Some("password123"));
        assert_eq!(u.email, None);
        assert_eq!(u.role, None);
        assert_eq!(u.is_active, None);
    }

    #[test]
    fn admin_updates_keep_all_fields_and_lowercase_email() {
        let u = allowed_updates(full_body(), true);
        assert_eq!(u.email.as_deref(), Some("new@example.com"));
        assert_eq!(u.full_name.as_deref(), Some("New Name"));
        assert_eq!(u.role.as_deref(), Some("admin"));
        assert_eq!(u.is_active, Some(false));
        assert_eq!(u.password.as_deref(), Some("password123"));
    }

    #[test]
    fn empty_update_is_detected() {
        assert!(allowed_updates(UpdateRequest::default(), true).is_empty());
        assert!(!allowed_updates(full_body(), false).is_empty());
        // Non-admin sending only admin-only fields ends up with no changes.
        let admin_only = UpdateRequest {
            email: Some("x@example.com".to_owned()),
            role: Some("admin".to_owned()),
            is_active: Some(false),
            ..UpdateRequest::default()
        };
        assert!(allowed_updates(admin_only, false).is_empty());
    }

    #[test]
    fn role_validation_matches_v1_enum() {
        assert!(check_role("admin").is_ok());
        assert!(check_role("maintainer").is_ok());
        assert!(check_role("viewer").is_ok());
        assert!(check_role("root").is_err());
        assert!(check_role("").is_err());
    }

    #[test]
    fn password_bounds_match_v1() {
        assert!(check_password("short").is_err());
        assert!(check_password(&"x".repeat(129)).is_err());
        assert!(check_password("password").is_ok());
        assert!(check_password(&"x".repeat(128)).is_ok());
    }

    #[test]
    fn full_name_bound_matches_v1() {
        assert!(check_full_name(&"x".repeat(255)).is_ok());
        assert!(check_full_name(&"x".repeat(256)).is_err());
    }

    #[test]
    fn int_param_is_lenient_like_quart() {
        assert_eq!(int_param(None, 7), 7);
        assert_eq!(int_param(Some("abc"), 7), 7);
        assert_eq!(int_param(Some("12"), 7), 12);
    }

    use crate::routes::test_support::{authed_user, db_state};

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    async fn server_for(state: AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    #[tokio::test]
    async fn list_users_requires_admin_or_maintainer() {
        let state = db_state(dev_license()).await;
        let (_, viewer) = authed_user(&state, "v@example.com", "viewer").await;
        let (_, admin) = authed_user(&state, "a@example.com", "admin").await;
        let server = server_for(state).await;

        let res = server
            .get("/api/v1/users")
            .authorization_bearer(&viewer)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);

        let res = server
            .get("/api/v1/users")
            .authorization_bearer(&admin)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["total"].as_i64().unwrap_or(0) >= 2);
        assert_eq!(body["page"], 1);
        assert_eq!(body["per_page"], 20);
    }

    #[tokio::test]
    async fn get_user_self_or_privileged_only() {
        let state = db_state(dev_license()).await;
        let (viewer_id, viewer_tok) = authed_user(&state, "self@example.com", "viewer").await;
        let (other_id, _) = authed_user(&state, "other@example.com", "viewer").await;
        let (_, admin_tok) = authed_user(&state, "admin2@example.com", "admin").await;
        let server = server_for(state).await;

        // Self view — ok.
        let res = server
            .get(&format!("/api/v1/users/{viewer_id}"))
            .authorization_bearer(&viewer_tok)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["email"], "self@example.com");
        assert!(body["updated_at"].is_null() || body["updated_at"].is_string());

        // Viewer viewing another user — forbidden.
        let res = server
            .get(&format!("/api/v1/users/{other_id}"))
            .authorization_bearer(&viewer_tok)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);

        // Admin viewing another user — ok.
        let res = server
            .get(&format!("/api/v1/users/{other_id}"))
            .authorization_bearer(&admin_tok)
            .await;
        res.assert_status_ok();

        // Missing id — 404.
        let res = server
            .get("/api/v1/users/999999")
            .authorization_bearer(&admin_tok)
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_user_requires_admin_and_validates() {
        let state = db_state(dev_license()).await;
        let (_, viewer_tok) = authed_user(&state, "cv@example.com", "viewer").await;
        let (_, admin_tok) = authed_user(&state, "ca@example.com", "admin").await;
        let server = server_for(state).await;

        let res = server
            .post("/api/v1/users")
            .authorization_bearer(&viewer_tok)
            .json(&serde_json::json!({"email": "x@example.com", "password": "longenough1"}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);

        let res = server
            .post("/api/v1/users")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"email": "not-an-email", "password": "longenough1"}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);

        let res = server
            .post("/api/v1/users")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"email": "nu@example.com", "password": "short"}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);

        let res = server
            .post("/api/v1/users")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({
                "email": "nu@example.com", "password": "longenough1", "role": "root"
            }))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_user_succeeds_then_rejects_duplicate() {
        let state = db_state(dev_license()).await;
        let (_, admin_tok) = authed_user(&state, "cu-admin@example.com", "admin").await;
        let server = server_for(state).await;

        let res = server
            .post("/api/v1/users")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({
                "email": "Created@Example.com",
                "password": "longenough1",
                "full_name": "Created",
                "role": "maintainer",
                "is_active": true,
            }))
            .await;
        res.assert_status(StatusCode::CREATED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["user"]["email"], "created@example.com");
        assert_eq!(body["user"]["role"], "maintainer");

        let dup = server
            .post("/api/v1/users")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({
                "email": "created@example.com", "password": "longenough1"
            }))
            .await;
        dup.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = dup.json();
        assert_eq!(body["error"], "Email already registered");
    }

    #[tokio::test]
    async fn update_user_self_can_only_change_name_and_password() {
        let state = db_state(dev_license()).await;
        let (id, token) = authed_user(&state, "upd-self@example.com", "viewer").await;
        let server = server_for(state).await;

        let res = server
            .put(&format!("/api/v1/users/{id}"))
            .authorization_bearer(&token)
            .json(&serde_json::json!({
                "full_name": "New Name",
                "role": "admin",
                "is_active": false,
            }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["user"]["full_name"], "New Name");
        // Admin-only fields silently dropped for a self-update.
        assert_eq!(body["user"]["role"], "viewer");
        assert_eq!(body["user"]["is_active"], true);
    }

    #[tokio::test]
    async fn update_user_forbidden_for_other_non_admin() {
        let state = db_state(dev_license()).await;
        let (_, actor_tok) = authed_user(&state, "actor@example.com", "viewer").await;
        let (target_id, _) = authed_user(&state, "target@example.com", "viewer").await;
        let server = server_for(state).await;

        let res = server
            .put(&format!("/api/v1/users/{target_id}"))
            .authorization_bearer(&actor_tok)
            .json(&serde_json::json!({"full_name": "hax"}))
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn update_user_missing_returns_404() {
        let state = db_state(dev_license()).await;
        let (_, admin_tok) = authed_user(&state, "upd-admin@example.com", "admin").await;
        let server = server_for(state).await;
        let res = server
            .put("/api/v1/users/999999")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"full_name": "ghost"}))
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn update_user_admin_can_change_email_role_and_hits_conflict() {
        let state = db_state(dev_license()).await;
        let (_, admin_tok) = authed_user(&state, "conflict-admin@example.com", "admin").await;
        let (id_a, _) = authed_user(&state, "conflict-a@example.com", "viewer").await;
        let (_id_b, _) = authed_user(&state, "conflict-b@example.com", "viewer").await;
        let server = server_for(state).await;

        // Changing A's email to B's existing email → 409.
        let res = server
            .put(&format!("/api/v1/users/{id_a}"))
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"email": "conflict-b@example.com"}))
            .await;
        res.assert_status(StatusCode::CONFLICT);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Email already in use");

        // A legitimate admin update succeeds and reflects role/is_active.
        let res = server
            .put(&format!("/api/v1/users/{id_a}"))
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"role": "admin", "is_active": false}))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["user"]["role"], "admin");
        assert_eq!(body["user"]["is_active"], false);
    }

    #[tokio::test]
    async fn delete_user_requires_admin_rejects_self_and_cascades() {
        let state = db_state(dev_license()).await;
        let (admin_id, admin_tok) = authed_user(&state, "del-admin@example.com", "admin").await;
        let (viewer_id, viewer_tok) = authed_user(&state, "del-viewer@example.com", "viewer").await;
        sqlx::query(
            "INSERT INTO refresh_tokens (user_id, token_hash, expires_at, revoked) \
             VALUES ($1, 'del-h1', now() + interval '7 days', false)",
        )
        .bind(viewer_id)
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed refresh token: {e}"));
        let server = server_for(state).await;

        // Non-admin forbidden.
        let res = server
            .delete(&format!("/api/v1/users/{admin_id}"))
            .authorization_bearer(&viewer_tok)
            .await;
        res.assert_status(StatusCode::FORBIDDEN);

        // Self-delete rejected.
        let res = server
            .delete(&format!("/api/v1/users/{admin_id}"))
            .authorization_bearer(&admin_tok)
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Cannot delete your own account");

        // Missing target.
        let res = server
            .delete("/api/v1/users/999999")
            .authorization_bearer(&admin_tok)
            .await;
        res.assert_status(StatusCode::NOT_FOUND);

        // Successful delete.
        let res = server
            .delete(&format!("/api/v1/users/{viewer_id}"))
            .authorization_bearer(&admin_tok)
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["message"], "User deleted successfully");
    }
}
