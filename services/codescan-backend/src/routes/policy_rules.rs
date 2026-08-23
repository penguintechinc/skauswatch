//! /api/v1/codescan/policy-rules — CodeScan Sentinel P3 policy engine rule
//! CRUD (docs/v2-port/v2.1-codescan-sentinel.md §6). Admin-defined,
//! priority-ordered rules that `worker-codescan::policy::evaluate` consumes
//! (via `worker-codescan::db::list_policy_rules`) to override the fixed
//! default action matrix. This service only manages the rule store; it
//! never evaluates a rule against a finding itself (that happens in the
//! worker, at scan time).
//!
//! Gated on both [`crate::routes::SENTINEL_FLAG`] (Sentinel itself must be
//! enabled) and Enterprise tier (spec §13: "AI-assisted capabilities ...
//! gate at Enterprise" — the policy engine is one of them, alongside AI
//! triage). Mutations are admin-only, matching `license_policies.rs`/
//! `credentials.rs`; reads are open to any authenticated tenant member.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::{AdminOnly, CurrentUser};
use crate::error::{ApiError, ApiJson, ErrorResponse, ValidationErrorResponse};
use crate::routes::{enterprise_denied, sentinel_denied};
use crate::state::AppState;

/// Matches `codescan_policy_rules.action`'s `CHECK` constraint and
/// `worker-codescan::policy::VALID_ACTIONS` exactly (spec §6).
const VALID_ACTIONS: [&str; 4] = ["ignore", "document", "alert", "fix"];
const VALID_SEVERITIES: [&str; 5] = ["critical", "high", "medium", "low", "unknown"];
const VALID_REACHABILITY: [&str; 3] = ["reachable", "unreachable", "unknown"];
const VALID_EXPOSURE: [&str; 3] = ["internal", "external", "none"];
const DEFAULT_PER_PAGE: i64 = 20;
const MAX_PER_PAGE: i64 = 100;

/// Router for /api/v1/codescan/policy-rules.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/codescan/policy-rules", get(list_rules).post(create_rule))
        .route(
            "/codescan/policy-rules/{rule_id}",
            get(get_rule).patch(update_rule).delete(delete_rule),
        )
}

fn validation(field: &str, msg: &str) -> ApiError {
    ApiError::Validation(vec![serde_json::json!({
        "loc": [field], "msg": msg, "type": "value_error"
    })])
}

fn pagination(page: Option<i64>, per_page: Option<i64>) -> (i64, i64) {
    (
        page.unwrap_or(1).max(1),
        per_page.unwrap_or(DEFAULT_PER_PAGE).clamp(1, MAX_PER_PAGE),
    )
}

/// Combined license gate: both [`crate::routes::sentinel_denied`] (Sentinel
/// enabled) and [`crate::routes::enterprise_denied`] (Enterprise tier) must
/// pass — the policy engine is meaningless without Sentinel, and gated
/// Enterprise on top of it (spec §13).
async fn policy_engine_denied(state: &AppState) -> Option<Response> {
    if let Some(denied) = sentinel_denied(state).await {
        return Some(denied);
    }
    enterprise_denied(state).await
}

/// One `codescan_policy_rules` row.
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyRule {
    id: i64,
    tenant_id: uuid::Uuid,
    priority: i32,
    repo: Option<String>,
    ecosystem: Option<String>,
    package: Option<String>,
    cve: Option<String>,
    severity: Option<String>,
    reachability: Option<String>,
    exposure: Option<String>,
    tool: Option<String>,
    kind: Option<String>,
    action: String,
    description: Option<String>,
    created_by: Option<String>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    updated_by: Option<String>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

const RULE_COLUMNS: &str = "id, tenant_id, priority, repo, ecosystem, package, cve, severity, \
     reachability, exposure, tool, kind, action, description, created_by, created_at, \
     updated_by, updated_at";

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    action: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

/// Documentation-only mirror of `list_rules`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyRuleListResponse {
    data: Vec<PolicyRule>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// GET /codescan/policy-rules — paginated list, optionally filtered by
/// `action`, ordered by priority ascending (evaluation order).
#[utoipa::path(
    get,
    path = "/api/v1/codescan/policy-rules",
    tag = "codescan-sentinel-policy",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Policy rules", body = PolicyRuleListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Sentinel not licensed, or below Enterprise tier", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_rules(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    if let Some(denied) = policy_engine_denied(&state).await {
        return Ok(denied);
    }
    let (page, per_page) = pagination(q.page, q.per_page);
    let offset = (page - 1) * per_page;

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
        "SELECT {RULE_COLUMNS} FROM codescan_policy_rules WHERE tenant_id = "
    ));
    qb.push_bind(user.tenant_id);
    if let Some(action) = &q.action {
        qb.push(" AND action = ").push_bind(action.clone());
    }
    qb.push(" ORDER BY priority ASC, id ASC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let items = qb
        .build_query_as::<PolicyRule>()
        .fetch_all(&state.db)
        .await?;

    let mut count_qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT count(*) FROM codescan_policy_rules WHERE tenant_id = ",
    );
    count_qb.push_bind(user.tenant_id);
    if let Some(action) = &q.action {
        count_qb.push(" AND action = ").push_bind(action.clone());
    }
    let total: i64 = count_qb.build_query_scalar().fetch_one(&state.db).await?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "data": items,
            "total": total,
            "page": page,
            "per_page": per_page,
        })),
    )
        .into_response())
}

#[derive(Deserialize, utoipa::ToSchema)]
pub(crate) struct CreatePolicyRuleRequest {
    #[serde(default)]
    priority: Option<i32>,
    #[serde(default)]
    repo: Option<String>,
    #[serde(default)]
    ecosystem: Option<String>,
    #[serde(default)]
    package: Option<String>,
    #[serde(default)]
    cve: Option<String>,
    #[serde(default)]
    severity: Option<String>,
    #[serde(default)]
    reachability: Option<String>,
    #[serde(default)]
    exposure: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    action: String,
    #[serde(default)]
    description: Option<String>,
}

fn validate_enum_field(
    field: &str,
    value: &Option<String>,
    allowed: &[&str],
) -> Result<(), ApiError> {
    match value {
        Some(v) if !allowed.contains(&v.as_str()) => Err(validation(
            field,
            &format!("must be one of: {}", allowed.join(", ")),
        )),
        _ => Ok(()),
    }
}

fn validate_create(body: &CreatePolicyRuleRequest) -> Result<(), ApiError> {
    if !VALID_ACTIONS.contains(&body.action.as_str()) {
        return Err(validation(
            "action",
            "Input should be 'ignore', 'document', 'alert', or 'fix'",
        ));
    }
    validate_enum_field("severity", &body.severity, &VALID_SEVERITIES)?;
    validate_enum_field("reachability", &body.reachability, &VALID_REACHABILITY)?;
    validate_enum_field("exposure", &body.exposure, &VALID_EXPOSURE)?;
    Ok(())
}

/// Documentation-only mirror of `create_rule`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyRuleCreateResponse {
    message: String,
    rule: PolicyRule,
}

/// POST /codescan/policy-rules — admin only. `created_by`/`updated_by`
/// are stamped from the caller's JWT `sub`, never client-supplied (spec
/// §6: "audit fields").
#[utoipa::path(
    post,
    path = "/api/v1/codescan/policy-rules",
    tag = "codescan-sentinel-policy",
    security(("bearer_jwt" = [])),
    request_body = CreatePolicyRuleRequest,
    responses(
        (status = 201, description = "Policy rule created", body = PolicyRuleCreateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Sentinel not licensed, below Enterprise tier, or insufficient permissions", body = ErrorResponse),
    ),
)]
pub(crate) async fn create_rule(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    ApiJson(body): ApiJson<CreatePolicyRuleRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = policy_engine_denied(&state).await {
        return Ok(denied);
    }
    validate_create(&body)?;

    let created_by = admin.id.to_string();
    let query = format!(
        "INSERT INTO codescan_policy_rules \
         (tenant_id, priority, repo, ecosystem, package, cve, severity, reachability, exposure, \
          tool, kind, action, description, created_by, updated_by, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14,now()) \
         RETURNING {RULE_COLUMNS}"
    );
    let created = sqlx::query_as::<_, PolicyRule>(sqlx::AssertSqlSafe(query))
        .bind(admin.tenant_id)
        .bind(body.priority.unwrap_or(100))
        .bind(&body.repo)
        .bind(&body.ecosystem)
        .bind(&body.package)
        .bind(&body.cve)
        .bind(&body.severity)
        .bind(&body.reachability)
        .bind(&body.exposure)
        .bind(&body.tool)
        .bind(&body.kind)
        .bind(&body.action)
        .bind(&body.description)
        .bind(&created_by)
        .fetch_one(&state.db)
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "message": "Policy rule created successfully",
            "rule": created,
        })),
    )
        .into_response())
}

/// GET /codescan/policy-rules/{id}.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/policy-rules/{rule_id}",
    tag = "codescan-sentinel-policy",
    security(("bearer_jwt" = [])),
    params(("rule_id" = i64, Path, description = "codescan_policy_rules.id")),
    responses(
        (status = 200, description = "Policy rule", body = PolicyRule),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Sentinel not licensed, or below Enterprise tier", body = ErrorResponse),
        (status = 404, description = "Policy rule not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_rule(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(rule_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = policy_engine_denied(&state).await {
        return Ok(denied);
    }
    let query = format!(
        "SELECT {RULE_COLUMNS} FROM codescan_policy_rules WHERE id = $1 AND tenant_id = $2"
    );
    let row = sqlx::query_as::<_, PolicyRule>(sqlx::AssertSqlSafe(query))
        .bind(rule_id)
        .bind(user.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Policy rule not found".to_owned()))?;
    Ok((StatusCode::OK, Json(row)).into_response())
}

#[derive(Deserialize, Default, utoipa::ToSchema)]
pub(crate) struct UpdatePolicyRuleRequest {
    priority: Option<i32>,
    repo: Option<String>,
    ecosystem: Option<String>,
    package: Option<String>,
    cve: Option<String>,
    severity: Option<String>,
    reachability: Option<String>,
    exposure: Option<String>,
    tool: Option<String>,
    kind: Option<String>,
    action: Option<String>,
    description: Option<String>,
}

/// Documentation-only mirror of `update_rule`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyRuleUpdateResponse {
    message: String,
    rule: PolicyRule,
}

/// PATCH /codescan/policy-rules/{id} — admin only.
#[utoipa::path(
    patch,
    path = "/api/v1/codescan/policy-rules/{rule_id}",
    tag = "codescan-sentinel-policy",
    security(("bearer_jwt" = [])),
    params(("rule_id" = i64, Path, description = "codescan_policy_rules.id")),
    request_body = UpdatePolicyRuleRequest,
    responses(
        (status = 200, description = "Policy rule updated", body = PolicyRuleUpdateResponse),
        (status = 400, description = "Validation error", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Sentinel not licensed, below Enterprise tier, or insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Policy rule not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn update_rule(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Path(rule_id): Path<i64>,
    ApiJson(body): ApiJson<UpdatePolicyRuleRequest>,
) -> Result<Response, ApiError> {
    if let Some(denied) = policy_engine_denied(&state).await {
        return Ok(denied);
    }
    if let Some(action) = &body.action
        && !VALID_ACTIONS.contains(&action.as_str())
    {
        return Err(validation(
            "action",
            "Input should be 'ignore', 'document', 'alert', or 'fix'",
        ));
    }
    validate_enum_field("severity", &body.severity, &VALID_SEVERITIES)?;
    validate_enum_field("reachability", &body.reachability, &VALID_REACHABILITY)?;
    validate_enum_field("exposure", &body.exposure, &VALID_EXPOSURE)?;

    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT id FROM codescan_policy_rules WHERE id = $1 AND tenant_id = $2")
            .bind(rule_id)
            .bind(admin.tenant_id)
            .fetch_optional(&state.db)
            .await?;
    if exists.is_none() {
        return Err(ApiError::NotFound("Policy rule not found".to_owned()));
    }

    let updated_by = admin.id.to_string();
    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE codescan_policy_rules SET ");
    {
        let mut set = qb.separated(", ");
        if let Some(v) = body.priority {
            set.push("priority = ");
            set.push_bind_unseparated(v);
        }
        if let Some(v) = &body.repo {
            set.push("repo = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.ecosystem {
            set.push("ecosystem = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.package {
            set.push("package = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.cve {
            set.push("cve = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.severity {
            set.push("severity = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.reachability {
            set.push("reachability = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.exposure {
            set.push("exposure = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.tool {
            set.push("tool = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.kind {
            set.push("kind = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.action {
            set.push("action = ");
            set.push_bind_unseparated(v.clone());
        }
        if let Some(v) = &body.description {
            set.push("description = ");
            set.push_bind_unseparated(v.clone());
        }
        set.push("updated_by = ");
        set.push_bind_unseparated(updated_by);
        set.push("updated_at = now()");
    }
    qb.push(" WHERE id = ").push_bind(rule_id);
    qb.push(" AND tenant_id = ").push_bind(admin.tenant_id);
    qb.build().execute(&state.db).await?;

    let query = format!(
        "SELECT {RULE_COLUMNS} FROM codescan_policy_rules WHERE id = $1 AND tenant_id = $2"
    );
    let updated = sqlx::query_as::<_, PolicyRule>(sqlx::AssertSqlSafe(query))
        .bind(rule_id)
        .bind(admin.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Policy rule not found".to_owned()))?;

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Policy rule updated successfully",
            "rule": updated,
        })),
    )
        .into_response())
}

/// Documentation-only mirror of `delete_rule`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct PolicyRuleDeleteResponse {
    message: String,
    deleted: bool,
}

/// DELETE /codescan/policy-rules/{id} — admin only.
#[utoipa::path(
    delete,
    path = "/api/v1/codescan/policy-rules/{rule_id}",
    tag = "codescan-sentinel-policy",
    security(("bearer_jwt" = [])),
    params(("rule_id" = i64, Path, description = "codescan_policy_rules.id")),
    responses(
        (status = 200, description = "Policy rule deleted", body = PolicyRuleDeleteResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Sentinel not licensed, below Enterprise tier, or insufficient permissions", body = ErrorResponse),
        (status = 404, description = "Policy rule not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn delete_rule(
    State(state): State<AppState>,
    AdminOnly(admin): AdminOnly,
    Path(rule_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = policy_engine_denied(&state).await {
        return Ok(denied);
    }
    let result = sqlx::query("DELETE FROM codescan_policy_rules WHERE id = $1 AND tenant_id = $2")
        .bind(rule_id)
        .bind(admin.tenant_id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::NotFound("Policy rule not found".to_owned()));
    }
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "message": "Policy rule deleted successfully",
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

    /// Dev-bypass license (Enterprise via `skauswatch.app` domain bypass) —
    /// see `penguintech.md` License Bypass Domains.
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

    /// Bypass disabled — resolves to `Tier::Free`, for proving the
    /// Enterprise gate actually gates.
    fn gated_license() -> Arc<LicenseClient> {
        let mut cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        cfg.release_mode = true;
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
    fn validate_create_rejects_an_invalid_action() {
        let body = CreatePolicyRuleRequest {
            priority: None,
            repo: None,
            ecosystem: None,
            package: None,
            cve: None,
            severity: None,
            reachability: None,
            exposure: None,
            tool: None,
            kind: None,
            action: "yolo".to_owned(),
            description: None,
        };
        assert!(validate_create(&body).is_err());
    }

    #[test]
    fn validate_create_rejects_an_invalid_severity() {
        let body = CreatePolicyRuleRequest {
            priority: None,
            repo: None,
            ecosystem: None,
            package: None,
            cve: None,
            severity: Some("apocalyptic".to_owned()),
            reachability: None,
            exposure: None,
            tool: None,
            kind: None,
            action: "ignore".to_owned(),
            description: None,
        };
        assert!(validate_create(&body).is_err());
    }

    /// Unit-level test of [`crate::routes::enterprise_denied`] in isolation
    /// (no DB, no HTTP route) — the full-route test below can only ever
    /// exercise the *combined* gate (`sentinel_denied` runs first in
    /// [`policy_engine_denied`]), since this codebase's `gated_license()`
    /// convention (no `license_key`/`posthog_key` configured) fails every
    /// gate at once, same as every other `gated_license()` test in this
    /// service (e.g. `routes::openapi::tests::openapi_404s_when_flag_disabled`).
    #[tokio::test]
    async fn enterprise_denied_rejects_below_enterprise_tier() {
        let state = AppStateInner::for_tests(gated_license());
        assert!(crate::routes::enterprise_denied(&state).await.is_some());
    }

    #[tokio::test]
    async fn enterprise_denied_allows_under_dev_bypass() {
        let state = AppStateInner::for_tests(dev_license());
        assert!(crate::routes::enterprise_denied(&state).await.is_none());
    }

    #[tokio::test]
    async fn routes_are_forbidden_below_enterprise_tier() {
        let state = crate::routes::test_support::db_state(gated_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        let resp = server
            .get("/api/v1/codescan/policy-rules")
            .authorization_bearer(&admin)
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn all_routes_require_auth() {
        let server = test_server(AppStateInner::for_tests(dev_license()));
        for resp in [
            server.get("/api/v1/codescan/policy-rules").await,
            server.post("/api/v1/codescan/policy-rules").await,
            server.get("/api/v1/codescan/policy-rules/1").await,
            server.patch("/api/v1/codescan/policy-rules/1").await,
            server.delete("/api/v1/codescan/policy-rules/1").await,
        ] {
            resp.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn mutations_reject_non_admin_roles() {
        for role in ["maintainer", "viewer"] {
            let state = crate::routes::test_support::db_state(dev_license()).await;
            let token = sign_token(&state, "1", role);
            let server = test_server(state);
            let resp = server
                .post("/api/v1/codescan/policy-rules")
                .authorization_bearer(&token)
                .json(&serde_json::json!({"action": "ignore"}))
                .await;
            resp.assert_status(StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn create_get_update_delete_round_trip() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        let created = server
            .post("/api/v1/codescan/policy-rules")
            .authorization_bearer(&admin)
            .json(&serde_json::json!({
                "priority": 5,
                "package": "left-pad",
                "action": "ignore",
                "description": "known false positive"
            }))
            .await;
        created.assert_status(StatusCode::CREATED);
        let created_body: serde_json::Value = created.json();
        assert_eq!(created_body["rule"]["priority"], 5);
        assert_eq!(created_body["rule"]["package"], "left-pad");
        assert_eq!(created_body["rule"]["created_by"], "1");
        let rule_id = created_body["rule"]["id"].as_i64().unwrap_or_default();
        assert!(rule_id > 0);

        let fetched = server
            .get(&format!("/api/v1/codescan/policy-rules/{rule_id}"))
            .authorization_bearer(&admin)
            .await;
        fetched.assert_status_ok();
        assert_eq!(fetched.json::<serde_json::Value>()["action"], "ignore");

        let updated = server
            .patch(&format!("/api/v1/codescan/policy-rules/{rule_id}"))
            .authorization_bearer(&admin)
            .json(&serde_json::json!({"action": "document"}))
            .await;
        updated.assert_status_ok();
        assert_eq!(
            updated.json::<serde_json::Value>()["rule"]["action"],
            "document"
        );

        let deleted = server
            .delete(&format!("/api/v1/codescan/policy-rules/{rule_id}"))
            .authorization_bearer(&admin)
            .await;
        deleted.assert_status_ok();

        server
            .get(&format!("/api/v1/codescan/policy-rules/{rule_id}"))
            .authorization_bearer(&admin)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_orders_by_priority_ascending() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);

        for (priority, action) in [(50, "fix"), (5, "ignore"), (100, "document")] {
            server
                .post("/api/v1/codescan/policy-rules")
                .authorization_bearer(&admin)
                .json(&serde_json::json!({"priority": priority, "action": action}))
                .await
                .assert_status(StatusCode::CREATED);
        }

        let listed = server
            .get("/api/v1/codescan/policy-rules")
            .authorization_bearer(&admin)
            .await;
        listed.assert_status_ok();
        let body: serde_json::Value = listed.json();
        let priorities: Vec<i64> = body["data"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|r| r["priority"].as_i64())
            .collect();
        assert_eq!(priorities, vec![5, 50, 100]);
    }

    #[tokio::test]
    async fn tenant_a_cannot_access_tenant_bs_rules() {
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
            .post("/api/v1/codescan/policy-rules")
            .authorization_bearer(&admin_b)
            .json(&serde_json::json!({"action": "ignore"}))
            .await;
        created.assert_status(StatusCode::CREATED);
        let rule_id = created.json::<serde_json::Value>()["rule"]["id"]
            .as_i64()
            .unwrap_or_default();

        let listed = server
            .get("/api/v1/codescan/policy-rules")
            .authorization_bearer(&admin_a)
            .await;
        listed.assert_status_ok();
        assert_eq!(listed.json::<serde_json::Value>()["total"], 0);

        server
            .get(&format!("/api/v1/codescan/policy-rules/{rule_id}"))
            .authorization_bearer(&admin_a)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }
}
