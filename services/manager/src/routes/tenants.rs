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

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::state::AppState;

/// Router for /api/v1/tenants.
pub fn router() -> Router<AppState> {
    Router::new().route("/tenants", post(create_tenant)).route(
        "/tenants/{tenant_id}/enrollment-tokens",
        post(create_enrollment_token),
    )
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

/// Default enrollment token lifetime (24h) — long enough for a fleet
/// installer run, short enough that a leaked/unused token doesn't stay
/// exploitable indefinitely (`docs/v2-port/service-auth-model.md` §5).
const DEFAULT_ENROLLMENT_TOKEN_TTL_SECONDS: i64 = 86_400;
/// Hard ceiling on a requested token lifetime (30 days).
const MAX_ENROLLMENT_TOKEN_TTL_SECONDS: i64 = 30 * 86_400;
/// Default consumption cap — one agent per token, the common case; a fleet
/// rollout can request a higher value explicitly.
const DEFAULT_ENROLLMENT_TOKEN_MAX_USES: i64 = 1;
/// Hard ceiling on a requested consumption cap.
const MAX_ENROLLMENT_TOKEN_MAX_USES: i64 = 10_000;

/// POST /tenants/{tenant_id}/enrollment-tokens body — both fields optional,
/// falling back to the defaults above.
#[derive(Default, serde::Deserialize, utoipa::ToSchema)]
pub(crate) struct CreateEnrollmentTokenRequest {
    /// Token lifetime in seconds (default 86400).
    expires_in_seconds: Option<i64>,
    /// Number of `register_agent` calls the token may resolve before it's
    /// exhausted (default 1).
    max_uses: Option<i64>,
}

/// Documentation-only mirror of `create_enrollment_token`'s success body.
#[derive(serde::Serialize, utoipa::ToSchema)]
pub(crate) struct EnrollmentTokenResponse {
    /// The raw enrollment token — returned exactly once; only its SHA-256
    /// hash is ever persisted (same principle as `users.password_hash`), so
    /// it can never be retrieved again after this response.
    token: String,
    tenant_id: uuid::Uuid,
    /// RFC 3339 expiry timestamp.
    expires_at: String,
    max_uses: i64,
}

/// Generates a fresh, cryptographically random raw enrollment token: two
/// concatenated UUIDv4s (`uuid`'s `v4` feature is backed by `getrandom`'s
/// OS CSPRNG), giving 256 bits of entropy as a 64-character lowercase hex
/// string — no new dependency needed for a secure random token.
fn generate_enrollment_token() -> String {
    format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    )
}

/// POST /tenants/{tenant_id}/enrollment-tokens — super_admin only (matching
/// this module's existing tenant-provisioning posture — see the "Decision
/// needing user confirmation" note in `docs/v2-port/service-auth-model.md`
/// §5: a narrower delegated `tenant_admin` role is a v2.1-backlog
/// candidate, not required for v2.0). Mints a token scoped to `tenant_id`;
/// `routes::endpoint::register_agent` resolves a *new* agent's tenant from
/// it instead of the default bootstrap tenant (§5 Option A).
#[utoipa::path(
    post,
    path = "/api/v1/tenants/{tenant_id}/enrollment-tokens",
    tag = "tenants",
    security(("bearer_jwt" = [])),
    params(("tenant_id" = uuid::Uuid, Path, description = "Tenant the minted token enrolls new agents into")),
    request_body(content = CreateEnrollmentTokenRequest, description = "Optional — a missing/empty body accepts the defaults"),
    responses(
        (status = 201, description = "Enrollment token minted", body = EnrollmentTokenResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Insufficient permissions — super_admin required", body = ErrorResponse),
        (status = 404, description = "Tenant not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_enrollment_token(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(tenant_id): Path<uuid::Uuid>,
    body: Bytes,
) -> Result<(StatusCode, Json<EnrollmentTokenResponse>), ApiError> {
    user.require_role(&["super_admin"])?;

    let parsed: CreateEnrollmentTokenRequest = if body.is_empty() {
        CreateEnrollmentTokenRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|_| validation("body", "Invalid JSON body"))?
    };

    let exists: Option<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM tenants WHERE id = $1")
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("Tenant not found".to_owned()));
    }

    let ttl = parsed
        .expires_in_seconds
        .unwrap_or(DEFAULT_ENROLLMENT_TOKEN_TTL_SECONDS);
    if !(1..=MAX_ENROLLMENT_TOKEN_TTL_SECONDS).contains(&ttl) {
        return Err(validation(
            "expires_in_seconds",
            &format!("Must be between 1 and {MAX_ENROLLMENT_TOKEN_TTL_SECONDS} seconds"),
        ));
    }
    let max_uses = parsed.max_uses.unwrap_or(DEFAULT_ENROLLMENT_TOKEN_MAX_USES);
    if !(1..=MAX_ENROLLMENT_TOKEN_MAX_USES).contains(&max_uses) {
        return Err(validation(
            "max_uses",
            &format!("Must be between 1 and {MAX_ENROLLMENT_TOKEN_MAX_USES}"),
        ));
    }

    let raw_token = generate_enrollment_token();
    let token_hash = crate::auth::token_hash(&raw_token);

    let (expires_at,): (chrono::NaiveDateTime,) = sqlx::query_as(
        "INSERT INTO endpoint_enrollment_tokens \
         (tenant_id, token_hash, max_uses, expires_at, created_by) \
         VALUES ($1, $2, $3, now() + make_interval(secs => $4), $5) \
         RETURNING expires_at",
    )
    .bind(tenant_id)
    .bind(&token_hash)
    .bind(max_uses as i32)
    .bind(ttl as f64)
    .bind(user.id)
    .fetch_one(&state.db)
    .await?;

    // Audit-logged the same way tenant creation is (module docs above).
    sqlx::query(
        "INSERT INTO audit_logs (event_type, action, resource_type, resource_id, user_id, \
         success, details, tenant_id) \
         VALUES ('tenant', 'enrollment_token.created', 'tenant', $1, $2, true, $3, $4)",
    )
    .bind(tenant_id.to_string())
    .bind(user.id)
    .bind(serde_json::json!({"max_uses": max_uses, "expires_in_seconds": ttl}))
    .bind(tenant_id)
    .execute(&state.db)
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(EnrollmentTokenResponse {
            token: raw_token,
            tenant_id,
            expires_at: expires_at.and_utc().to_rfc3339(),
            max_uses,
        }),
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

    #[tokio::test]
    async fn create_enrollment_token_requires_super_admin() {
        let state = db_state(dev_license()).await;
        let tenant = crate::routes::test_support::seed_tenant(&state.db, "enroll-tok-a").await;
        let (_, admin_tok) = authed_user(&state, "enroll-admin@example.com", "admin").await;
        let server = server_for(state).await;

        let res = server
            .post(&format!("/api/v1/tenants/{tenant}/enrollment-tokens"))
            .authorization_bearer(&admin_tok)
            .await;
        res.assert_status(HttpStatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn create_enrollment_token_404s_unknown_tenant() {
        let state = db_state(dev_license()).await;
        let (_, super_tok) =
            crate::routes::test_support::seed_super_admin(&state, "enroll-root-404@example.com")
                .await;
        let server = server_for(state).await;

        let res = server
            .post(&format!(
                "/api/v1/tenants/{}/enrollment-tokens",
                uuid::Uuid::new_v4()
            ))
            .authorization_bearer(&super_tok)
            .await;
        res.assert_status(HttpStatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_enrollment_token_validates_bounds() {
        let state = db_state(dev_license()).await;
        let tenant = crate::routes::test_support::seed_tenant(&state.db, "enroll-tok-bounds").await;
        let (_, super_tok) =
            crate::routes::test_support::seed_super_admin(&state, "enroll-root-bounds@example.com")
                .await;
        let server = server_for(state).await;

        for body in [
            serde_json::json!({"expires_in_seconds": 0}),
            serde_json::json!({"expires_in_seconds": MAX_ENROLLMENT_TOKEN_TTL_SECONDS + 1}),
            serde_json::json!({"max_uses": 0}),
            serde_json::json!({"max_uses": MAX_ENROLLMENT_TOKEN_MAX_USES + 1}),
        ] {
            let res = server
                .post(&format!("/api/v1/tenants/{tenant}/enrollment-tokens"))
                .authorization_bearer(&super_tok)
                .json(&body)
                .await;
            res.assert_status(HttpStatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn create_enrollment_token_mints_a_usable_hashed_token() {
        let state = db_state(dev_license()).await;
        let tenant = crate::routes::test_support::seed_tenant(&state.db, "enroll-tok-mint").await;
        let (_, super_tok) =
            crate::routes::test_support::seed_super_admin(&state, "enroll-root-mint@example.com")
                .await;
        let server = server_for(state.clone()).await;

        // Empty body accepts the defaults (24h TTL, single use).
        let res = server
            .post(&format!("/api/v1/tenants/{tenant}/enrollment-tokens"))
            .authorization_bearer(&super_tok)
            .await;
        res.assert_status(HttpStatusCode::CREATED);
        let body: serde_json::Value = res.json();
        let raw_token = body["token"]
            .as_str()
            .unwrap_or_else(|| panic!("token missing from response: {body}"));
        assert_eq!(raw_token.len(), 64, "two concatenated UUIDv4 hex strings");
        assert_eq!(body["tenant_id"], tenant.to_string());
        assert_eq!(body["max_uses"], 1);
        assert!(body["expires_at"].as_str().is_some());

        // Only the hash is persisted — never the raw token.
        let stored: (String,) = sqlx::query_as(
            "SELECT token_hash FROM endpoint_enrollment_tokens WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|e| panic!("fetch stored token: {e}"));
        assert_eq!(stored.0, crate::auth::token_hash(raw_token));
        assert_ne!(stored.0, raw_token);
    }
}
