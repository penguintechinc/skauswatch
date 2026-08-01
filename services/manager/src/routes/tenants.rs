//! /api/v1/tenants — super-admin tenant provisioning. Contract:
//! docs/v2-port/tenancy-model.md §2/§8 (admin-provisioned tenants for
//! v2.0 — no open self-serve tenant creation; `/auth/register` attaches new
//! registrants to the seeded bootstrap tenant instead, see
//! `crate::auth::DEFAULT_TENANT_ID`).
//!
//! Gating note: `super_admin` is a manager-internal role value, deliberately
//! NOT part of `routes/users.rs::ROLES` (the set the public users API will
//! accept) — a tenant admin must never be able to grant themselves or
//! anyone else cross-tenant tenant-management capability through the normal
//! user create/update endpoints. Provisioning a `super_admin` user is an
//! out-of-band operational action (direct DB write) for v2.0; a proper
//! separately-issued, short-lived super-admin credential (per
//! `security.md`'s "Super-admin: separately issued, short-lived,
//! audit-logged") is a follow-up, tracked alongside the rest of the
//! `audit:cross_tenant` scope work the tenancy design doc already defers.

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

/// Router for /api/v1/tenants.
pub fn router() -> Router<AppState> {
    Router::new().route("/tenants", post(create_tenant))
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

/// URL/subdomain-safe slug: lowercase ascii alphanumeric + hyphens, 1..=63
/// chars (matches `tenants.slug VARCHAR(63)`), never starting/ending with a
/// hyphen.
fn valid_slug(slug: &str) -> bool {
    let len = slug.len();
    if len == 0 || len > 63 {
        return false;
    }
    if slug.starts_with('-') || slug.ends_with('-') {
        return false;
    }
    slug.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// POST /tenants body.
#[derive(serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateTenantRequest {
    slug: String,
    name: String,
}

/// Tenant summary embedded in [`TenantCreateResponse`].
#[derive(sqlx::FromRow, serde::Serialize, utoipa::ToSchema)]
pub(crate) struct TenantSummary {
    id: uuid::Uuid,
    slug: String,
    name: String,
    status: String,
}

/// Documentation-only mirror of `create_tenant`'s `serde_json::json!` body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct TenantCreateResponse {
    message: String,
    tenant: TenantSummary,
}

/// POST /tenants — super_admin only; the sole tenant-creation surface for
/// v2.0 (admin-provisioned, per the module docs). 409 on a duplicate slug,
/// 201 `{message,tenant}` on success. Every call is audit-logged against
/// the newly created tenant (the only tenant the action is meaningfully
/// "about" — see `security.md`'s "Super-admin ... audit-logged").
#[utoipa::path(
    post,
    path = "/api/v1/tenants",
    tag = "tenants",
    security(("bearer_jwt" = [])),
    request_body = CreateTenantRequest,
    responses(
        (status = 201, description = "Tenant created", body = TenantCreateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions — super_admin required", body = ErrorResponse),
        (status = 409, description = "Slug already in use", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_tenant(
    State(state): State<AppState>,
    user: CurrentUser,
    ApiJson(body): ApiJson<CreateTenantRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), ApiError> {
    user.require_role(&["super_admin"])?;

    if !valid_slug(&body.slug) {
        return Err(validation(
            "slug",
            "String should be 1-63 lowercase alphanumeric/hyphen characters, \
             not starting or ending with a hyphen",
        ));
    }
    if body.name.is_empty() || body.name.len() > 255 {
        return Err(validation("name", "String should have 1 to 255 characters"));
    }

    let existing: Option<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM tenants WHERE slug = $1")
        .bind(&body.slug)
        .fetch_optional(&state.db)
        .await?;
    if existing.is_some() {
        return Err(ApiError::Conflict(serde_json::json!({
            "error": "Slug already in use"
        })));
    }

    let created = sqlx::query_as::<_, TenantSummary>(
        "INSERT INTO tenants (slug, name, status) VALUES ($1, $2, 'active') \
         RETURNING id, slug, name, status",
    )
    .bind(&body.slug)
    .bind(&body.name)
    .fetch_one(&state.db)
    .await?;

    // Audit-logged against the newly created tenant itself — see module docs.
    sqlx::query(
        "INSERT INTO audit_logs (event_type, action, resource_type, resource_id, user_id, \
         success, details, tenant_id) \
         VALUES ('tenant', 'tenant.created', 'tenant', $1, $2, true, $3, $4)",
    )
    .bind(created.id.to_string())
    .bind(user.id)
    .bind(serde_json::json!({"slug": created.slug, "name": created.name}))
    .bind(created.id)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Tenant created successfully",
            "tenant": created,
        })),
    ))
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use axum::http::StatusCode as HttpStatusCode;

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

    #[test]
    fn slug_validation() {
        assert!(valid_slug("acme"));
        assert!(valid_slug("acme-corp-2"));
        assert!(!valid_slug(""));
        assert!(!valid_slug("-acme"));
        assert!(!valid_slug("acme-"));
        assert!(!valid_slug("Acme"));
        assert!(!valid_slug("acme_corp"));
        assert!(!valid_slug(&"a".repeat(64)));
    }

    #[tokio::test]
    async fn create_tenant_requires_super_admin() {
        let state = db_state(dev_license()).await;
        let (_, admin_tok) = authed_user(&state, "tenant-admin@example.com", "admin").await;
        let server = server_for(state).await;

        let res = server
            .post("/api/v1/tenants")
            .authorization_bearer(&admin_tok)
            .json(&serde_json::json!({"slug": "acme", "name": "Acme"}))
            .await;
        res.assert_status(HttpStatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_tenant_validates_slug_and_name() {
        let state = db_state(dev_license()).await;
        // super_admin is DB-only provisioned — never via the public users
        // API (see module docs); tests seed it directly.
        let (_, super_tok) =
            crate::routes::test_support::seed_super_admin(&state, "root@example.com").await;
        let server = server_for(state).await;

        let res = server
            .post("/api/v1/tenants")
            .authorization_bearer(&super_tok)
            .json(&serde_json::json!({"slug": "Not_Valid", "name": "X"}))
            .await;
        res.assert_status(HttpStatusCode::BAD_REQUEST);

        let res = server
            .post("/api/v1/tenants")
            .authorization_bearer(&super_tok)
            .json(&serde_json::json!({"slug": "valid-slug", "name": ""}))
            .await;
        res.assert_status(HttpStatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_tenant_succeeds_then_rejects_duplicate_slug() {
        let state = db_state(dev_license()).await;
        let (_, super_tok) =
            crate::routes::test_support::seed_super_admin(&state, "root2@example.com").await;
        let server = server_for(state).await;

        let res = server
            .post("/api/v1/tenants")
            .authorization_bearer(&super_tok)
            .json(&serde_json::json!({"slug": "acme-corp", "name": "Acme Corp"}))
            .await;
        res.assert_status(HttpStatusCode::CREATED);
        let body: serde_json::Value = res.json();
        assert_eq!(body["tenant"]["slug"], "acme-corp");
        assert_eq!(body["tenant"]["name"], "Acme Corp");
        assert_eq!(body["tenant"]["status"], "active");

        let dup = server
            .post("/api/v1/tenants")
            .authorization_bearer(&super_tok)
            .json(&serde_json::json!({"slug": "acme-corp", "name": "Different Name"}))
            .await;
        dup.assert_status(HttpStatusCode::CONFLICT);
    }
}
