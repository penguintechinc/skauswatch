//! /api/v1/license-policies — OSS license-compliance policy CRUD. Net-new
//! surface (Phase 12): v1's `app/api/v1/licenses.py` gave full CRUD but was
//! never wired to anything that populated `codescan_license_detections`
//! (see docs/v2-port/phase12-scope-codeai.md row 3), so there is no working
//! v1 behavior to port here — this is the admin-facing half of the license-
//! compliance feature; `services/worker-codescan/src/license_scan.rs`
//! resolves dependency licenses and evaluates them against the policies
//! this router manages.
//!
//! Read access (list/get) is open to any authenticated tenant member,
//! matching `repos.rs`'s convention; mutations (create/update/delete) are
//! admin-only, matching `credentials.rs`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{AdminOnly, CurrentUser};
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::routes::license_denied;
use crate::state::AppState;

const VALID_POLICIES: [&str; 3] = ["allowed", "review_required", "blocked"];

/// Router for /api/v1/license-policies.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/license-policies", get(list_policies).post(create_policy))
        .route(
            "/license-policies/{policy_id}",
            get(get_policy).patch(update_policy).delete(delete_policy),
        )
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// License-policy row shape returned by list/get/create/update.
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct LicensePolicy {
    id: i64,
    tenant_id: uuid::Uuid,
    license_name: String,
    policy: String,
    actions: Option<serde_json::Value>,
    description: Option<String>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

const POLICY_COLUMNS: &str =
    "id, tenant_id, license_name, policy, actions, description, created_at, updated_at";

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    policy: Option<String>,
}

/// Documentation-only mirror of `list_policies`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyListResponse {
    data: Vec<LicensePolicy>,
    total: usize,
}

/// GET /license-policies — list configured license policies, optionally
/// filtered by `policy` (allowed/review_required/blocked).
#[utoipa::path(
    get,
    path = "/api/v1/license-policies",
    tag = "license-policies",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "License policies", body = PolicyListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_policies(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
        "SELECT {POLICY_COLUMNS} FROM codescan_license_policies WHERE tenant_id = "
    ));
    qb.push_bind(user.tenant_id);
    if let Some(policy) = &q.policy {
        qb.push(" AND policy = ").push_bind(policy.clone());
    }
    qb.push(" ORDER BY license_name");
    let items = qb
        .build_query_as::<LicensePolicy>()
        .fetch_all(&state.db)
        .await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "data": items, "total": items.len() })),
    )
        .into_response())
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreatePolicyRequest {
    license_name: String,
    policy: String,
    #[serde(default)]
    actions: Option<serde_json::Value>,
    #[serde(default)]
    description: Option<String>,
}

fn validate_create(body: &CreatePolicyRequest) -> Result<(), ApiError> {
    if body.license_name.trim().is_empty() {
        return Err(validation("license_name", "license_name is required"));
    }
    if !VALID_POLICIES.contains(&body.policy.as_str()) {
        return Err(validation(
            "policy",
            "Input should be 'allowed', 'review_required', or 'blocked'",
        ));
    }
    Ok(())
}

/// Documentation-only mirror of `create_policy`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyCreateResponse {
    message: String,
    policy: LicensePolicy,
}

/// POST /license-policies — admin only.
#[utoipa::path(
    post,
    path = "/api/v1/license-policies",
    tag = "license-policies",
    security(("bearer_jwt" = [])),
    request_body = CreatePolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = PolicyCreateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 409, description = "A policy for this license_name already exists", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_policy(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    ApiJson(body): ApiJson<CreatePolicyRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    validate_create(&body)?;

    let existing: Option<(i64,)> = sqlx::query_as(
        "SELECT id FROM codescan_license_policies WHERE tenant_id = $1 AND license_name = $2",
    )
    .bind(admin.tenant_id)
    .bind(&body.license_name)
    .fetch_optional(&state.db)
    .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict(serde_json::json!({
            "error": "A policy for this license_name already exists"
        })));
    }

    let query = format!(
        "INSERT INTO codescan_license_policies \
         (tenant_id, license_name, policy, actions, description, updated_at) \
         VALUES ($1,$2,$3,$4,$5,now()) RETURNING {POLICY_COLUMNS}"
    );
    let created = sqlx::query_as::<_, LicensePolicy>(sqlx::AssertSqlSafe(query))
        .bind(admin.tenant_id)
        .bind(&body.license_name)
        .bind(&body.policy)
        .bind(&body.actions)
        .bind(&body.description)
        .fetch_one(&state.db)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "License policy created successfully",
            "policy": created,
        })),
    )
        .into_response())
}

/// GET /license-policies/{id}.
#[utoipa::path(
    get,
    path = "/api/v1/license-policies/{policy_id}",
    tag = "license-policies",
    security(("bearer_jwt" = [])),
    params(("policy_id" = i64, Path, description = "License policy id")),
    responses(
        (status = 200, description = "License policy", body = LicensePolicy),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed", body = ErrorResponse),
        (status = 404, description = "License policy not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_policy(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(policy_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let query = format!(
        "SELECT {POLICY_COLUMNS} FROM codescan_license_policies WHERE id = $1 AND tenant_id = $2"
    );
    let row = sqlx::query_as::<_, LicensePolicy>(sqlx::AssertSqlSafe(query))
        .bind(policy_id)
        .bind(user.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("License policy not found".to_owned()))?;
    Ok((StatusCode::OK, Json(row)).into_response())
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct UpdatePolicyRequest {
    policy: Option<String>,
    actions: Option<serde_json::Value>,
    description: Option<String>,
}

/// Documentation-only mirror of `update_policy`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyUpdateResponse {
    message: String,
    policy: LicensePolicy,
}

/// PATCH /license-policies/{id} — admin only.
#[utoipa::path(
    patch,
    path = "/api/v1/license-policies/{policy_id}",
    tag = "license-policies",
    security(("bearer_jwt" = [])),
    params(("policy_id" = i64, Path, description = "License policy id")),
    request_body = UpdatePolicyRequest,
    responses(
        (status = 200, description = "License policy updated", body = PolicyUpdateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 404, description = "License policy not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_policy(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Path(policy_id): Path<i64>,
    ApiJson(body): ApiJson<UpdatePolicyRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    if let Some(policy) = &body.policy
        && !VALID_POLICIES.contains(&policy.as_str())
    {
        return Err(validation(
            "policy",
            "Input should be 'allowed', 'review_required', or 'blocked'",
        ));
    }

    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM codescan_license_policies WHERE id = $1 AND tenant_id = $2")
            .bind(policy_id)
            .bind(admin.tenant_id)
            .fetch_optional(&state.db)
            .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("License policy not found".to_owned()));
    }

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE codescan_license_policies SET ");
    {
        let mut set = qb.separated(", ");
        if let Some(v) = &body.policy {
            set.push("policy = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.actions {
            set.push("actions = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.description {
            set.push("description = ");
            set.push_bind_unseparated(v.clone());
        }
        set.push("updated_at = now()");
    }
    qb.push(" WHERE id = ").push_bind(policy_id);
    qb.push(" AND tenant_id = ").push_bind(admin.tenant_id);
    qb.build().execute(&state.db).await?;

    let query = format!(
        "SELECT {POLICY_COLUMNS} FROM codescan_license_policies WHERE id = $1 AND tenant_id = $2"
    );
    let updated = sqlx::query_as::<_, LicensePolicy>(sqlx::AssertSqlSafe(query))
        .bind(policy_id)
        .bind(admin.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("License policy not found".to_owned()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "License policy updated successfully",
            "policy": updated,
        })),
    )
        .into_response())
}

/// Documentation-only mirror of `delete_policy`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyDeleteResponse {
    message: String,
    deleted: bool,
}

/// DELETE /license-policies/{id} — admin only.
#[utoipa::path(
    delete,
    path = "/api/v1/license-policies/{policy_id}",
    tag = "license-policies",
    security(("bearer_jwt" = [])),
    params(("policy_id" = i64, Path, description = "License policy id")),
    responses(
        (status = 200, description = "License policy deleted", body = PolicyDeleteResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan feature not licensed, or insufficient permissions", body = ErrorResponse),
        (status = 404, description = "License policy not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn delete_policy(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Path(policy_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = license_denied(&state).await {
        return Ok(denied);
    }
    let result =
        sqlx::query("DELETE FROM codescan_license_policies WHERE id = $1 AND tenant_id = $2")
            .bind(policy_id)
            .bind(admin.tenant_id)
            .execute(&state.db)
            .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("License policy not found".to_owned()));
    }
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "License policy deleted successfully",
            "deleted": true,
        })),
    )
        .into_response())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::routes::test_support::sign_token;
    use crate::state::AppStateInner;
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use std::sync::Arc;

    fn dev_license() -> Arc<LicenseClient> {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    fn test_server(state: crate::state::AppState) -> axum_test::TestServer {
        let app = axum::Router::new()
            .nest("/api/v1", router())
            .with_state(state);
        axum_test::TestServer::new(app)
    }

    #[test]
    fn validate_create_rejects_bad_policy_value() {
        let body = CreatePolicyRequest {
            license_name: "MIT".to_owned(),
            policy: "sometimes".to_owned(),
            actions: None,
            description: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[test]
    fn validate_create_rejects_empty_license_name() {
        let body = CreatePolicyRequest {
            license_name: String::new(),
            policy: "allowed".to_owned(),
            actions: None,
            description: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[tokio::test]
    async fn all_routes_require_auth() {
        let server = test_server(AppStateInner::for_tests(dev_license()));
        for resp in [
            server.get("/api/v1/license-policies").await,
            server.post("/api/v1/license-policies").await,
            server.get("/api/v1/license-policies/1").await,
            server.patch("/api/v1/license-policies/1").await,
            server.delete("/api/v1/license-policies/1").await,
        ] {
            resp.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn mutations_reject_non_admin_roles() {
        for role in ["maintainer", "viewer"] {
            let state = AppStateInner::for_tests(dev_license());
            let token = sign_token(&state, "1", role);
            let server = test_server(state);
            let resp = server
                .post("/api/v1/license-policies")
                .authorization_bearer(&token)
                .json(&serde_json::json!({"license_name": "MIT", "policy": "allowed"}))
                .await;
            resp.assert_status(StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn viewer_can_list_and_read_but_not_write() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let viewer = sign_token(&state, "2", "viewer");
        let server = test_server(state);

        server
            .post("/api/v1/license-policies")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"license_name": "GPL-3.0", "policy": "blocked"}))
            .await
            .assert_status(StatusCode::CREATED);

        let listed = server
            .get("/api/v1/license-policies")
            .authorization_bearer(&viewer)
            .await;
        listed.assert_status_ok();
        assert_eq!(listed.json::<serde_json::Value>()["total"], 1);
    }

    #[tokio::test]
    async fn create_get_update_delete_round_trip() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        let created = server
            .post("/api/v1/license-policies")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({
                "license_name": "AGPL-3.0-only",
                "policy": "review_required",
                "actions": ["notify_legal"],
            }))
            .await;
        created.assert_status(StatusCode::CREATED);
        let created_body: serde_json::Value = created.json();
        let policy_id = created_body["policy"]["id"].as_i64().unwrap_or_default();
        assert!(policy_id > 0);

        let fetched = server
            .get(&format!("/api/v1/license-policies/{policy_id}"))
            .authorization_bearer(&admin)
            .await;
        fetched.assert_status_ok();
        let fetched_body: serde_json::Value = fetched.json();
        assert_eq!(fetched_body["policy"], "review_required");

        let updated = server
            .patch(&format!("/api/v1/license-policies/{policy_id}"))
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"policy": "blocked"}))
            .await;
        updated.assert_status_ok();
        let updated_body: serde_json::Value = updated.json();
        assert_eq!(updated_body["policy"]["policy"], "blocked");

        let deleted = server
            .delete(&format!("/api/v1/license-policies/{policy_id}"))
            .authorization_bearer(&admin)
            .await;
        deleted.assert_status_ok();

        server
            .get(&format!("/api/v1/license-policies/{policy_id}"))
            .authorization_bearer(&admin)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_rejects_duplicate_license_name_for_the_same_tenant() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        server
            .post("/api/v1/license-policies")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"license_name": "MIT", "policy": "allowed"}))
            .await
            .assert_status(StatusCode::CREATED);

        let dup = server
            .post("/api/v1/license-policies")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"license_name": "MIT", "policy": "blocked"}))
            .await;
        dup.assert_status(StatusCode::CONFLICT);
    }

    /// Regression for the tenant-collision bug fixed in
    /// `migrations/0003_license_policy_tenant_unique.sql`: two tenants must
    /// each be able to configure their own policy for the same license name.
    #[tokio::test]
    async fn two_tenants_can_each_configure_a_policy_for_the_same_license_name() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin_a = sign_token(&state, "1", "admin");
        let admin_b = crate::routes::test_support::sign_token_for_tenant(
            &state,
            "2",
            "admin",
            crate::routes::test_support::OTHER_TENANT_ID,
        );
        let server = test_server(state);

        server
            .post("/api/v1/license-policies")
            .authorization_bearer(&admin_a)
            .json(&serde_json::json!({"license_name": "GPL-3.0", "policy": "blocked"}))
            .await
            .assert_status(StatusCode::CREATED);

        let tenant_b_created = server
            .post("/api/v1/license-policies")
            .authorization_bearer(&admin_b)
            .json(&serde_json::json!({"license_name": "GPL-3.0", "policy": "allowed"}))
            .await;
        tenant_b_created.assert_status(StatusCode::CREATED);
    }

    #[tokio::test]
    async fn tenant_a_cannot_access_tenant_bs_policies() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin_a = sign_token(&state, "1", "admin");
        let admin_b = crate::routes::test_support::sign_token_for_tenant(
            &state,
            "2",
            "admin",
            crate::routes::test_support::OTHER_TENANT_ID,
        );
        let server = test_server(state);

        let created = server
            .post("/api/v1/license-policies")
            .authorization_bearer(&admin_b)
            .json(&serde_json::json!({"license_name": "MIT", "policy": "allowed"}))
            .await;
        created.assert_status(StatusCode::CREATED);
        let policy_id = created.json::<serde_json::Value>()["policy"]["id"]
            .as_i64()
            .unwrap_or_default();

        let listed = server
            .get("/api/v1/license-policies")
            .authorization_bearer(&admin_a)
            .await;
        listed.assert_status_ok();
        assert_eq!(listed.json::<serde_json::Value>()["total"], 0);

        server
            .get(&format!("/api/v1/license-policies/{policy_id}"))
            .authorization_bearer(&admin_a)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .patch(&format!("/api/v1/license-policies/{policy_id}"))
            .authorization_bearer(&admin_a)
            .json(&serde_json::json!({"policy": "blocked"}))
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .delete(&format!("/api/v1/license-policies/{policy_id}"))
            .authorization_bearer(&admin_a)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_update_delete_404_on_unknown_id() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        server
            .get("/api/v1/license-policies/999999")
            .authorization_bearer(&admin)
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .patch("/api/v1/license-policies/999999")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"policy": "blocked"}))
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .delete("/api/v1/license-policies/999999")
            .authorization_bearer(&admin)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_filters_by_policy() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        server
            .post("/api/v1/license-policies")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"license_name": "MIT", "policy": "allowed"}))
            .await
            .assert_status(StatusCode::CREATED);
        server
            .post("/api/v1/license-policies")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"license_name": "GPL-3.0", "policy": "blocked"}))
            .await
            .assert_status(StatusCode::CREATED);

        let resp = server
            .get("/api/v1/license-policies?policy=blocked")
            .authorization_bearer(&admin)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["total"], 1);
        assert_eq!(body["data"][0]["license_name"], "GPL-3.0");
    }
}
