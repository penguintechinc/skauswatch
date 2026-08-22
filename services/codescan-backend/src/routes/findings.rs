//! /api/v1/codescan/findings — CodeScan Sentinel report surface
//! (docs/v2-port/v2.1-codescan-sentinel.md §8/§9, P1: report-only, no AI).
//! Read-only: `worker-codescan`'s scheduler + scan handler
//! (`services/worker-codescan/src/scheduler.rs`, `src/handler.rs`) are the
//! only writers of `codescan_findings`, via the shared Postgres database —
//! this service never mutates the table, only lists/summarizes it.
//!
//! Gated on `SENTINEL_FLAG` (`skauswatch.codescan.sentinel`), independent of
//! `CODESCAN_FLAG` — see `routes::sentinel_denied`.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::auth::CurrentUser;
use crate::error::{ApiError, ErrorResponse};
use crate::routes::sentinel_denied;
use crate::state::AppState;

/// Router for /api/v1/codescan/findings.
pub fn router() -> Router<AppState> {
    Router::new()
        .route("/codescan/findings", get(list_findings))
        .route("/codescan/findings/summary", get(findings_summary))
}

const DEFAULT_PER_PAGE: i64 = 20;
const MAX_PER_PAGE: i64 = 100;

fn pagination(page: Option<i64>, per_page: Option<i64>) -> (i64, i64) {
    (
        page.unwrap_or(1).max(1),
        per_page.unwrap_or(DEFAULT_PER_PAGE).clamp(1, MAX_PER_PAGE),
    )
}

/// One `codescan_findings` row, as returned by `list_findings` — an
/// explicit DTO (not a raw table passthrough), matching every other
/// response shape in this service (`security.md` Output Validation).
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct Finding {
    id: i64,
    repo_config_id: i64,
    branch: String,
    kind: String,
    ecosystem: String,
    package_name: String,
    current_version: String,
    latest_version: Option<String>,
    fixed_version: Option<String>,
    advisory_id: String,
    severity: String,
    source: String,
    status: String,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    first_seen: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

const FINDING_COLUMNS: &str = "id, repo_config_id, branch, kind, ecosystem, package_name, \
     current_version, latest_version, fixed_version, advisory_id, severity, source, status, \
     first_seen, last_seen";

/// Documentation-only mirror of `list_findings`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FindingListResponse {
    data: Vec<Finding>,
    total: i64,
    page: i64,
    per_page: i64,
}

#[derive(Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    page: Option<i64>,
    per_page: Option<i64>,
    repo_config_id: Option<i64>,
    branch: Option<String>,
    kind: Option<String>,
    severity: Option<String>,
    status: Option<String>,
}

/// GET /codescan/findings — paginated, filterable list of SCA/CVE findings.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/findings",
    tag = "codescan-sentinel",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Findings", body = FindingListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan Sentinel not licensed", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_findings(
    State(state): State<AppState>,
    user: CurrentUser,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    if let Some(denied) = sentinel_denied(&state).await {
        return Ok(denied);
    }
    let (page, per_page) = pagination(q.page, q.per_page);
    let offset = (page - 1) * per_page;

    let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
        "SELECT {FINDING_COLUMNS} FROM codescan_findings WHERE tenant_id = "
    ));
    qb.push_bind(user.tenant_id);
    if let Some(v) = q.repo_config_id {
        qb.push(" AND repo_config_id = ").push_bind(v);
    }
    if let Some(v) = &q.branch {
        qb.push(" AND branch = ").push_bind(v.clone());
    }
    if let Some(v) = &q.kind {
        qb.push(" AND kind = ").push_bind(v.clone());
    }
    if let Some(v) = &q.severity {
        qb.push(" AND severity = ").push_bind(v.clone());
    }
    if let Some(v) = &q.status {
        qb.push(" AND status = ").push_bind(v.clone());
    }
    qb.push(" ORDER BY last_seen DESC LIMIT ")
        .push_bind(per_page)
        .push(" OFFSET ")
        .push_bind(offset);
    let items = qb.build_query_as::<Finding>().fetch_all(&state.db).await?;

    let mut count_qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
        "SELECT count(*) FROM codescan_findings WHERE tenant_id = ",
    );
    count_qb.push_bind(user.tenant_id);
    if let Some(v) = q.repo_config_id {
        count_qb.push(" AND repo_config_id = ").push_bind(v);
    }
    if let Some(v) = &q.branch {
        count_qb.push(" AND branch = ").push_bind(v.clone());
    }
    if let Some(v) = &q.kind {
        count_qb.push(" AND kind = ").push_bind(v.clone());
    }
    if let Some(v) = &q.severity {
        count_qb.push(" AND severity = ").push_bind(v.clone());
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

/// One `(severity, kind, ecosystem)` bucket count for the exec/summary view.
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct SeverityCount {
    severity: String,
    kind: String,
    ecosystem: String,
    count: i64,
}

/// Documentation-only mirror of `findings_summary`'s `serde_json::json!` body.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct FindingsSummaryResponse {
    total_open: i64,
    by_bucket: Vec<SeverityCount>,
}

/// GET /codescan/findings/summary — exec-view counts by severity/kind/
/// ecosystem, open findings only (spec §8).
#[utoipa::path(
    get,
    path = "/api/v1/codescan/findings/summary",
    tag = "codescan-sentinel",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Findings summary", body = FindingsSummaryResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan Sentinel not licensed", body = ErrorResponse),
    ),
)]
pub(crate) async fn findings_summary(
    State(state): State<AppState>,
    user: CurrentUser,
) -> Result<Response, ApiError> {
    if let Some(denied) = sentinel_denied(&state).await {
        return Ok(denied);
    }

    let by_bucket = sqlx::query_as::<_, SeverityCount>(
        "SELECT severity, kind, ecosystem, count(*) AS count FROM codescan_findings \
         WHERE tenant_id = $1 AND status = 'open' \
         GROUP BY severity, kind, ecosystem \
         ORDER BY severity, kind, ecosystem",
    )
    .bind(user.tenant_id)
    .fetch_all(&state.db)
    .await?;

    let total_open: i64 = by_bucket.iter().map(|b| b.count).sum();

    Ok((
        StatusCode::OK,
        Json(serde_json::json!({
            "total_open": total_open,
            "by_bucket": by_bucket,
        })),
    )
        .into_response())
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::routes::test_support::sign_token;
    use penguin_licensing::{LicenseClient, LicenseConfig};
    use std::sync::Arc;
    use uuid::Uuid;

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
    fn pagination_defaults_and_clamps() {
        assert_eq!(pagination(None, None), (1, 20));
        assert_eq!(pagination(Some(2), Some(500)), (2, 100));
    }

    #[tokio::test]
    async fn list_and_summary_require_auth() {
        let server = test_server(crate::state::AppStateInner::for_tests(dev_license()));
        server
            .get("/api/v1/codescan/findings")
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
        server
            .get("/api/v1/codescan/findings/summary")
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_is_forbidden_when_sentinel_flag_disabled() {
        let state = crate::state::AppStateInner::for_tests(gated_license());
        let token = sign_token(&state, "1", "viewer");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/findings")
            .authorization_bearer(token)
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
    }

    /// `codescan_repo_configs` has a *global* `UNIQUE (provider, repo_name)`
    /// constraint (unchanged by the tenancy retrofit — see `repos.rs`'s own
    /// doc comment), so every call needs a distinct repo name even across
    /// different tenants — a random suffix keeps every seed call
    /// collision-free without threading a name through every call site.
    async fn seed_repo(pool: &sqlx::PgPool, tenant: Uuid) -> i64 {
        let repo_name = format!("acme/widgets-{}", Uuid::new_v4());
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO codescan_repo_configs (tenant_id, provider, repo_url, repo_name) \
             VALUES ($1, 'github', 'https://github.com/acme/widgets', $2) \
             RETURNING id",
        )
        .bind(tenant)
        .bind(&repo_name)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed repo: {e}"));
        row.0
    }

    #[allow(clippy::too_many_arguments)]
    async fn seed_finding(
        pool: &sqlx::PgPool,
        tenant: Uuid,
        repo_config_id: i64,
        branch: &str,
        kind: &str,
        severity: &str,
        package_name: &str,
        advisory_id: &str,
        status: &str,
    ) {
        sqlx::query(
            "INSERT INTO codescan_findings \
             (tenant_id, repo_config_id, branch, kind, ecosystem, package_name, \
              current_version, latest_version, advisory_id, severity, status) \
             VALUES ($1,$2,$3,$4,'npm',$5,'1.0.0','2.0.0',$6,$7,$8)",
        )
        .bind(tenant)
        .bind(repo_config_id)
        .bind(branch)
        .bind(kind)
        .bind(package_name)
        .bind(advisory_id)
        .bind(severity)
        .bind(status)
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed finding: {e}"));
    }

    #[tokio::test]
    async fn list_findings_is_tenant_scoped_and_paginated() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let other_admin = crate::routes::test_support::sign_token_for_tenant(
            &state,
            "2",
            "admin",
            crate::routes::test_support::OTHER_TENANT_ID,
        );
        let tenant: Uuid = crate::routes::test_support::TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let other_tenant: Uuid = crate::routes::test_support::OTHER_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let repo = seed_repo(&state.db, tenant).await;
        let other_repo = seed_repo(&state.db, other_tenant).await;

        seed_finding(
            &state.db, tenant, repo, "main", "cve", "critical", "left-pad", "GHSA-a", "open",
        )
        .await;
        seed_finding(
            &state.db, tenant, repo, "main", "sca", "low", "axios", "", "open",
        )
        .await;
        seed_finding(
            &state.db,
            other_tenant,
            other_repo,
            "main",
            "cve",
            "critical",
            "left-pad",
            "GHSA-a",
            "open",
        )
        .await;

        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/findings")
            .authorization_bearer(&admin)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(
            body["total"], 2,
            "another tenant's findings must never be counted"
        );
        assert_eq!(body["data"].as_array().map(Vec::len), Some(2));

        // Filter by severity.
        let filtered = server
            .get("/api/v1/codescan/findings?severity=critical")
            .authorization_bearer(&admin)
            .await;
        filtered.assert_status_ok();
        let filtered_body: serde_json::Value = filtered.json();
        assert_eq!(filtered_body["total"], 1);
        assert_eq!(filtered_body["data"][0]["package_name"], "left-pad");

        // Tenant B only ever sees its own row.
        let other_resp = server
            .get("/api/v1/codescan/findings")
            .authorization_bearer(&other_admin)
            .await;
        other_resp.assert_status_ok();
        assert_eq!(other_resp.json::<serde_json::Value>()["total"], 1);
    }

    #[tokio::test]
    async fn list_findings_filters_by_repo_branch_kind_and_status() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let tenant: Uuid = crate::routes::test_support::TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let repo = seed_repo(&state.db, tenant).await;

        seed_finding(
            &state.db, tenant, repo, "main", "sca", "low", "pkg-open", "", "open",
        )
        .await;
        seed_finding(
            &state.db,
            tenant,
            repo,
            "main",
            "sca",
            "low",
            "pkg-resolved",
            "",
            "resolved",
        )
        .await;
        seed_finding(
            &state.db,
            tenant,
            repo,
            "release/v1.0.x",
            "sca",
            "low",
            "pkg-release-branch",
            "",
            "open",
        )
        .await;

        let server = test_server(state);
        let status_filtered = server
            .get("/api/v1/codescan/findings?status=resolved")
            .authorization_bearer(&admin)
            .await;
        status_filtered.assert_status_ok();
        assert_eq!(status_filtered.json::<serde_json::Value>()["total"], 1);

        let branch_filtered = server
            .get("/api/v1/codescan/findings?branch=release%2Fv1.0.x")
            .authorization_bearer(&admin)
            .await;
        branch_filtered.assert_status_ok();
        let branch_body: serde_json::Value = branch_filtered.json();
        assert_eq!(branch_body["total"], 1);
        assert_eq!(branch_body["data"][0]["package_name"], "pkg-release-branch");

        let no_match = server
            .get("/api/v1/codescan/findings?kind=cve")
            .authorization_bearer(&admin)
            .await;
        no_match.assert_status_ok();
        assert_eq!(no_match.json::<serde_json::Value>()["total"], 0);

        // Empty-result and invalid-filter-value cases both just yield zero
        // rows, never an error — matches every other filtered list endpoint.
        let invalid_severity = server
            .get("/api/v1/codescan/findings?severity=not-a-real-severity")
            .authorization_bearer(&admin)
            .await;
        invalid_severity.assert_status_ok();
        assert_eq!(invalid_severity.json::<serde_json::Value>()["total"], 0);
    }

    #[tokio::test]
    async fn findings_summary_counts_open_findings_by_bucket_and_excludes_resolved() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let tenant: Uuid = crate::routes::test_support::TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let repo = seed_repo(&state.db, tenant).await;

        seed_finding(
            &state.db, tenant, repo, "main", "cve", "critical", "pkg-a", "GHSA-a", "open",
        )
        .await;
        seed_finding(
            &state.db, tenant, repo, "main", "cve", "critical", "pkg-b", "GHSA-b", "open",
        )
        .await;
        seed_finding(
            &state.db, tenant, repo, "main", "sca", "low", "pkg-c", "", "open",
        )
        .await;
        seed_finding(
            &state.db, tenant, repo, "main", "cve", "high", "pkg-d", "GHSA-d", "resolved",
        )
        .await;

        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/findings/summary")
            .authorization_bearer(&admin)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(
            body["total_open"], 3,
            "resolved findings must not count toward the open total"
        );
        let buckets = body["by_bucket"].as_array().cloned().unwrap_or_default();
        assert!(
            buckets
                .iter()
                .any(|b| b["severity"] == "critical" && b["kind"] == "cve" && b["count"] == 2)
        );
        assert!(
            buckets
                .iter()
                .any(|b| b["severity"] == "low" && b["kind"] == "sca" && b["count"] == 1)
        );
        assert!(
            !buckets.iter().any(|b| b["severity"] == "high"),
            "the resolved high-severity finding must not appear in the summary"
        );
    }

    #[tokio::test]
    async fn list_findings_respects_pagination_bounds() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let tenant: Uuid = crate::routes::test_support::TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let repo = seed_repo(&state.db, tenant).await;
        for i in 0..3 {
            seed_finding(
                &state.db,
                tenant,
                repo,
                "main",
                "sca",
                "low",
                &format!("pkg-{i}"),
                "",
                "open",
            )
            .await;
        }

        let server = test_server(state);
        let paged = server
            .get("/api/v1/codescan/findings?page=1&per_page=2")
            .authorization_bearer(&admin)
            .await;
        paged.assert_status_ok();
        let paged_body: serde_json::Value = paged.json();
        assert_eq!(paged_body["total"], 3);
        assert_eq!(paged_body["per_page"], 2);
        assert_eq!(paged_body["data"].as_array().map(Vec::len), Some(2));

        let second_page = server
            .get("/api/v1/codescan/findings?page=2&per_page=2")
            .authorization_bearer(&admin)
            .await;
        second_page.assert_status_ok();
        assert_eq!(
            second_page.json::<serde_json::Value>()["data"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );

        // per_page above MAX_PER_PAGE is clamped, not honored verbatim.
        let over_cap = server
            .get("/api/v1/codescan/findings?per_page=500")
            .authorization_bearer(&admin)
            .await;
        over_cap.assert_status_ok();
        assert_eq!(over_cap.json::<serde_json::Value>()["per_page"], 100);
    }

    #[tokio::test]
    async fn findings_summary_is_empty_for_a_tenant_with_no_findings() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/findings/summary")
            .authorization_bearer(&admin)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["total_open"], 0);
        assert_eq!(body["by_bucket"], serde_json::json!([]));
    }
}
