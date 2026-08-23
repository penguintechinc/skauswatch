//! /api/v1/codescan/fix-batches — CodeScan Sentinel P4 grouped auto-fix
//! read surface (docs/v2-port/v2.1-codescan-sentinel.md §7/§9). Read-only:
//! `worker-codescan::fix::run_fix_batch` is the sole writer of
//! `codescan_fix_batches`/`codescan_fix_batch_findings`, via the shared
//! Postgres database — this service never mutates either table, only
//! lists/summarizes them (same division of labor as `findings.rs`).
//!
//! Gated on both [`crate::routes::sentinel_denied`] and
//! [`crate::routes::enterprise_denied`], same pattern as `policy_rules.rs` —
//! grouped auto-fix only ever produces rows via the Enterprise-gated policy
//! engine's `fix` action (spec §13).

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse};
use crate::routes::{enterprise_denied, sentinel_denied};
use crate::state::AppState;

const DEFAULT_PER_PAGE: i64 = 20;
const MAX_PER_PAGE: i64 = 100;

fn pagination(page: Option<i64>, per_page: Option<i64>) -> (i64, i64) {
    (
        page.unwrap_or(1).max(1),
        per_page.unwrap_or(DEFAULT_PER_PAGE).clamp(1, MAX_PER_PAGE),
    )
}

/// Combined license gate — mirrors `policy_rules.rs::policy_engine_denied`:
/// Sentinel enabled, and Enterprise tier (spec §13, grouped auto-fix rides
/// the policy engine).
async fn fix_batches_denied(state: &AppState) -> Option<Response> {
    if let Some(denied) = sentinel_denied(state).await {
        return Some(denied);
    }
    enterprise_denied(state).await
}

/// Router for /api/v1/codescan/fix-batches.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/codescan/fix-batches", get(list_batches))
        .route("/codescan/fix-batches/{batch_id}", get(get_batch))
}

/// One `codescan_fix_batches` row.
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct FixBatch {
    id: i64,
    repo_config_id: i64,
    target_branch: String,
    branch_name: String,
    pr_number: Option<i64>,
    pr_url: Option<String>,
    status: String,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    updated_at: Option<chrono::DateTime<chrono::Utc>>,
}

const BATCH_COLUMNS: &str = "id, repo_config_id, target_branch, branch_name, pr_number, pr_url, \
     status, created_at, updated_at";

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    repo_config_id: Option<i64>,
    status: Option<String>,
    page: Option<i64>,
    per_page: Option<i64>,
}

/// Documentation-only mirror of `list_batches`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FixBatchListResponse {
    data: Vec<FixBatch>,
    total: i64,
    page: i64,
    per_page: i64,
}

/// GET /codescan/fix-batches — paginated, filterable list of grouped
/// auto-fix batches, most-recently-updated first.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/fix-batches",
    tag = "codescan-sentinel-policy",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Fix batches", body = FixBatchListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Sentinel not licensed, or below Enterprise tier", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_batches(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    if let Some(denied) = fix_batches_denied(&state).await {
        return Ok(denied);
    }
    let (page, per_page) = pagination(q.page, q.per_page);
    let offset = (page - 1) * per_page;

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
        "SELECT {BATCH_COLUMNS} FROM codescan_fix_batches WHERE tenant_id = "
    ));
    qb.push_bind(user.tenant_id);
    if let Some(v) = q.repo_config_id {
        qb.push(" AND repo_config_id = ").push_bind(v);
    }
    if let Some(v) = &q.status {
        qb.push(" AND status = ").push_bind(v.clone());
    }
    qb.push(" ORDER BY updated_at DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let items = qb.build_query_as::<FixBatch>().fetch_all(&state.db).await?;

    let mut count_qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT count(*) FROM codescan_fix_batches WHERE tenant_id = ",
    );
    count_qb.push_bind(user.tenant_id);
    if let Some(v) = q.repo_config_id {
        count_qb.push(" AND repo_config_id = ").push_bind(v);
    }
    if let Some(v) = &q.status {
        count_qb.push(" AND status = ").push_bind(v.clone());
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

/// One `codescan_fix_batch_findings` row — the itemized content of a
/// batch's PR/MR body (spec §7: "pkg old→new · CVE(s) fixed · severity ·
/// reachability verdict").
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct FixBatchFinding {
    finding_id: i64,
    package_name: String,
    ecosystem: String,
    old_version: String,
    new_version: String,
    advisory_id: String,
    severity: String,
    reachability_verdict: String,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Documentation-only mirror of `get_batch`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FixBatchDetailResponse {
    batch: FixBatch,
    findings: Vec<FixBatchFinding>,
}

/// GET /codescan/fix-batches/{batch_id} — one batch plus every finding it
/// itemizes.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/fix-batches/{batch_id}",
    tag = "codescan-sentinel-policy",
    security(("bearer_jwt" = [])),
    params(("batch_id" = i64, Path, description = "Fix batch id")),
    responses(
        (status = 200, description = "Fix batch detail", body = FixBatchDetailResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "Sentinel not licensed, or below Enterprise tier", body = ErrorResponse),
        (status = 404, description = "Fix batch not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_batch(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(batch_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = fix_batches_denied(&state).await {
        return Ok(denied);
    }
    let query = format!(
        "SELECT {BATCH_COLUMNS} FROM codescan_fix_batches WHERE id = $1 AND tenant_id = $2"
    );
    let batch = sqlx::query_as::<_, FixBatch>(sqlx::AssertSqlSafe(query))
        .bind(batch_id)
        .bind(user.tenant_id)
        .fetch_optional(&state.db)
        .await?
        .ok_or_else(|| ApiError::NotFound("Fix batch not found".to_owned()))?;

    let findings = sqlx::query_as::<_, FixBatchFinding>(sqlx::AssertSqlSafe(
        "SELECT finding_id, package_name, ecosystem, old_version, new_version, advisory_id, \
         severity, reachability_verdict, created_at \
         FROM codescan_fix_batch_findings WHERE batch_id = $1 AND tenant_id = $2 \
         ORDER BY created_at ASC"
            .to_owned(),
    ))
    .bind(batch_id)
    .bind(user.tenant_id)
    .fetch_all(&state.db)
    .await?;

    Ok((
        StatusCode::OK,
        Json(FixBatchDetailResponse { batch, findings }),
    )
        .into_response())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::routes::test_support;
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use sqlx::Row;
    use std::sync::Arc;

    fn dev_license() -> Arc<LicenseClient> {
        let cfg =
            LicenseConfig::new("skauswatch").unwrap_or_else(|e| panic!("license config: {e}"));
        LicenseClient::new(cfg).unwrap_or_else(|e| panic!("license client: {e}"))
    }

    fn tenant_uuid(s: &str) -> uuid::Uuid {
        s.parse().unwrap_or_else(|e| panic!("tenant uuid: {e}"))
    }

    /// `codescan_repo_configs` has a table-wide (not tenant-scoped) `UNIQUE
    /// (provider, repo_name)` constraint (migrations/0001) — `repo_name`
    /// must be distinct across every call in a test that seeds more than
    /// one repo, hence the caller-supplied suffix.
    async fn seed_repo_config(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        name_suffix: &str,
    ) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name) \
             VALUES ($1, 'github', $2, $3) RETURNING id",
        )
        .bind(tenant_id)
        .bind(format!("https://github.com/acme/widgets-{name_suffix}"))
        .bind(format!("acme/widgets-{name_suffix}"))
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo config: {e}"));
        row.get::<i64, _>(0)
    }

    async fn seed_batch(
        pool: &sqlx::PgPool,
        tenant_id: uuid::Uuid,
        repo_config_id: i64,
        status: &str,
    ) -> i64 {
        let row = sqlx::query(
            "INSERT INTO codescan_fix_batches \
             (tenant_id, repo_config_id, target_branch, branch_name, pr_number, pr_url, status) \
             VALUES ($1, $2, 'main', 'codescan/sentinel-fixes-main', 42, \
             'https://github.com/acme/widgets/pull/42', $3) RETURNING id",
        )
        .bind(tenant_id)
        .bind(repo_config_id)
        .bind(status)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed batch: {e}"));
        row.get::<i64, _>(0)
    }

    #[tokio::test]
    async fn list_batches_is_tenant_scoped() {
        let state = test_support::db_state(dev_license()).await;
        let tenant = tenant_uuid(test_support::TEST_TENANT_ID);
        let other = tenant_uuid(test_support::OTHER_TENANT_ID);
        let repo = seed_repo_config(&state.db, tenant, "a").await;
        seed_batch(&state.db, tenant, repo, "open").await;
        let other_repo = seed_repo_config(&state.db, other, "b").await;
        seed_batch(&state.db, other, other_repo, "open").await;

        let server = axum_test::TestServer::new(crate::routes::router(state.clone()));
        let token = test_support::sign_token(&state, "1", "viewer");
        let resp = server
            .get("/api/v1/codescan/fix-batches")
            .authorization_bearer(token)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        let data = body["data"]
            .as_array()
            .unwrap_or_else(|| panic!("data array"));
        assert_eq!(
            data.len(),
            1,
            "only the caller's own tenant's batch must be returned"
        );
    }

    #[tokio::test]
    async fn get_batch_returns_itemized_findings() {
        let state = test_support::db_state(dev_license()).await;
        let tenant = tenant_uuid(test_support::TEST_TENANT_ID);
        let repo = seed_repo_config(&state.db, tenant, "c").await;
        let batch_id = seed_batch(&state.db, tenant, repo, "open").await;

        let finding_row = sqlx::query(
            "INSERT INTO codescan_findings \
             (tenant_id, repo_config_id, branch, kind, ecosystem, package_name, current_version, \
              advisory_id, severity) \
             VALUES ($1, $2, 'main', 'cve', 'npm', 'left-pad', '1.0.0', 'GHSA-test', 'high') \
             RETURNING id",
        )
        .bind(tenant)
        .bind(repo)
        .fetch_one(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed finding: {e}"));
        let finding_id: i64 = finding_row.get(0);

        sqlx::query(
            "INSERT INTO codescan_fix_batch_findings \
             (tenant_id, batch_id, finding_id, package_name, ecosystem, old_version, new_version, \
              advisory_id, severity, reachability_verdict) \
             VALUES ($1, $2, $3, 'left-pad', 'npm', '1.0.0', '1.0.1', 'GHSA-test', 'high', \
             'reachable/external')",
        )
        .bind(tenant)
        .bind(batch_id)
        .bind(finding_id)
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("seed batch finding: {e}"));

        let server = axum_test::TestServer::new(crate::routes::router(state.clone()));
        let token = test_support::sign_token(&state, "1", "viewer");
        let resp = server
            .get(&format!("/api/v1/codescan/fix-batches/{batch_id}"))
            .authorization_bearer(token)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["batch"]["pr_number"], 42);
        assert_eq!(
            body["findings"]
                .as_array()
                .unwrap_or_else(|| panic!("findings array"))
                .len(),
            1
        );
        assert_eq!(body["findings"][0]["package_name"], "left-pad");
    }

    #[tokio::test]
    async fn get_batch_404s_for_unknown_id() {
        let state = test_support::db_state(dev_license()).await;
        let server = axum_test::TestServer::new(crate::routes::router(state.clone()));
        let token = test_support::sign_token(&state, "1", "viewer");
        let resp = server
            .get("/api/v1/codescan/fix-batches/999999")
            .authorization_bearer(token)
            .await;
        resp.assert_status_not_found();
    }
}
