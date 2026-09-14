//! /api/v1/codescan/findings — CodeScan Sentinel report surface
//! (docs/v2-port/v2.1-codescan-sentinel.md §8/§9, P1: SCA/CVE report-only;
//! P2: folds in the SAST/secret/IaC tool registry + SBOM artifacts, see
//! `worker-codescan::scanner_tool`). Read-only: `worker-codescan`'s
//! scheduler + scan handler (`services/worker-codescan/src/scheduler.rs`,
//! `src/handler.rs`) are the only writers of `codescan_findings`/
//! `codescan_sbom_artifacts`, via the shared Postgres database — this
//! service never mutates either table, only lists/summarizes/serves them.
//!
//! Gated on `SENTINEL_FLAG` (`skauswatch.codescan.sentinel`), independent of
//! `CODESCAN_FLAG` — see `routes::sentinel_denied`.

use axum::extract::{Path, Query, State};
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
        .route("/codescan/findings/sbom/{scan_run_id}", get(get_sbom))
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
///
/// `tool`/`rule_id`/`file_path`/`line`/`title` are P2 additions
/// (migrations/0005_codescan_sentinel_tool_findings.sql) — empty string /
/// `None` for every P1 sca/cve row, populated for sast/secret/iac rows from
/// the scanner-tool registry (`worker-codescan::scanner_tool::ToolFinding`).
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
    tool: String,
    rule_id: String,
    file_path: Option<String>,
    line: Option<i32>,
    title: String,
    // ── CodeScan Sentinel P3 additions (migrations/0006) — reachability
    // triage verdict + the policy engine's resolved action. `None`/`""`
    // for any finding never triaged (AI disabled, below Enterprise tier,
    // or the finding predates P3) — see `worker-codescan::triage`/`::policy`.
    used: Option<bool>,
    reachable: Option<bool>,
    exposure: Option<String>,
    ai_severity: Option<String>,
    ai_rationale: Option<String>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    triaged_at: Option<chrono::DateTime<chrono::Utc>>,
    triage_source: String,
    /// The policy engine's resolved action (`ignore`/`document`/`alert`/
    /// `fix`), `""` when never evaluated (spec §6). The alert bridge
    /// (`worker-codescan::handler`) only ever alerts on `"alert"`.
    action: String,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    first_seen: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(serialize_with = "crate::dt::serde_py_isoformat_opt")]
    last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

const FINDING_COLUMNS: &str = "id, repo_config_id, branch, kind, ecosystem, package_name, \
     current_version, latest_version, fixed_version, advisory_id, severity, source, status, \
     tool, rule_id, file_path, line, title, used, reachable, exposure, ai_severity, \
     ai_rationale, triaged_at, triage_source, action, first_seen, last_seen";

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
    /// Filters to one scanner tool (P2: `semgrep`/`gitleaks`/`trivy`/
    /// `syft`) — `""` for every P1 sca/cve row, so this only ever matches
    /// tool-registry findings.
    tool: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    /// Filters to the policy engine's resolved action (P3) —
    /// `ignore`/`document`/`alert`/`fix`.
    action: Option<String>,
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
    if let Some(v) = &q.tool {
        qb.push(" AND tool = ").push_bind(v.clone());
    }
    if let Some(v) = &q.severity {
        qb.push(" AND severity = ").push_bind(v.clone());
    }
    if let Some(v) = &q.status {
        qb.push(" AND status = ").push_bind(v.clone());
    }
    if let Some(v) = &q.action {
        qb.push(" AND action = ").push_bind(v.clone());
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
    if let Some(v) = &q.tool {
        count_qb.push(" AND tool = ").push_bind(v.clone());
    }
    if let Some(v) = &q.severity {
        count_qb.push(" AND severity = ").push_bind(v.clone());
    }
    if let Some(v) = &q.status {
        count_qb.push(" AND status = ").push_bind(v.clone());
    }
    if let Some(v) = &q.action {
        count_qb.push(" AND action = ").push_bind(v.clone());
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

/// One `(severity, kind, ecosystem, tool)` bucket count for the exec/summary
/// view. `tool` is `""` for every P1 sca/cve row (see `Finding`'s doc
/// comment) — the P2 addition lets a summary consumer break tool-registry
/// findings down by which tool produced them (spec §8/§11 P2: "the '3 OSS
/// SAST tools' reports").
#[derive(sqlx::FromRow, Serialize, utoipa::ToSchema)]
pub(crate) struct SeverityCount {
    severity: String,
    kind: String,
    ecosystem: String,
    tool: String,
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
        "SELECT severity, kind, ecosystem, tool, count(*) AS count FROM codescan_findings \
         WHERE tenant_id = $1 AND status = 'open' \
         GROUP BY severity, kind, ecosystem, tool \
         ORDER BY severity, kind, ecosystem, tool",
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

/// Raw row shape for `codescan_sbom_artifacts` — not itself an API DTO
/// ([`SbomResponse`] below is), since `doc_gzip` needs decompression before
/// it's presentable.
#[derive(sqlx::FromRow)]
struct SbomRow {
    repo_config_id: i64,
    branch: String,
    format: String,
    doc_gzip: Vec<u8>,
}

/// GET /codescan/findings/sbom/{scan_run_id} response — the decompressed
/// CycloneDX document as a raw JSON *string* (not re-parsed into nested
/// JSON): keeps this endpoint's schema simple and type-safe rather than
/// asking `utoipa` to describe an arbitrary/untyped document shape.
/// Consumers (compliance/exec reporting, spec §8) parse `content` as
/// CycloneDX JSON client-side.
#[derive(Serialize, utoipa::ToSchema)]
pub(crate) struct SbomResponse {
    scan_run_id: i64,
    repo_config_id: i64,
    branch: String,
    format: String,
    content: String,
}

/// GET /codescan/findings/sbom/{scan_run_id} — the CycloneDX SBOM document
/// produced by the P2 `syft` tool for that scan run (spec §3/§8: "SBOM
/// output included for compliance"). Tenant-scoped by `scan_run_id`; a
/// scan run belonging to another tenant (or with no SBOM recorded, e.g. it
/// predates P2 or syft was unavailable that run) answers 404, never a
/// cross-tenant existence signal.
#[utoipa::path(
    get,
    path = "/api/v1/codescan/findings/sbom/{scan_run_id}",
    tag = "codescan-sentinel",
    security(("bearer_jwt" = [])),
    params(("scan_run_id" = i64, Path, description = "codescan_scan_runs.id")),
    responses(
        (status = 200, description = "CycloneDX SBOM document", body = SbomResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 403, description = "CodeScan Sentinel not licensed", body = ErrorResponse),
        (status = 404, description = "No SBOM recorded for this scan run", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_sbom(
    State(state): State<AppState>,
    user: CurrentUser,
    Path(scan_run_id): Path<i64>,
) -> Result<Response, ApiError> {
    if let Some(denied) = sentinel_denied(&state).await {
        return Ok(denied);
    }

    let row = sqlx::query_as::<_, SbomRow>(
        "SELECT repo_config_id, branch, format, doc_gzip FROM codescan_sbom_artifacts \
         WHERE tenant_id = $1 AND scan_run_id = $2",
    )
    .bind(user.tenant_id)
    .bind(scan_run_id)
    .fetch_optional(&state.db)
    .await?;

    let Some(row) = row else {
        return Err(ApiError::NotFound("SBOM not found".to_owned()));
    };

    let content = decompress_gzip_to_string(&row.doc_gzip)
        .map_err(|e| ApiError::internal("sbom gzip decompress", e))?;

    Ok((
        StatusCode::OK,
        Json(SbomResponse {
            scan_run_id,
            repo_config_id: row.repo_config_id,
            branch: row.branch,
            format: row.format,
            content,
        }),
    )
        .into_response())
}

fn decompress_gzip_to_string(gzipped: &[u8]) -> std::io::Result<String> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(gzipped);
    let mut out = String::new();
    decoder.read_to_string(&mut out)?;
    Ok(out)
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

    /// Seeds a P2 tool-registry finding (sast/secret/iac) — mirrors what
    /// `worker-codescan::db::upsert_tool_finding` writes.
    #[allow(clippy::too_many_arguments)]
    async fn seed_tool_finding(
        pool: &sqlx::PgPool,
        tenant: Uuid,
        repo_config_id: i64,
        branch: &str,
        kind: &str,
        tool: &str,
        rule_id: &str,
        severity: &str,
        file_path: &str,
        line: i32,
    ) {
        sqlx::query(
            "INSERT INTO codescan_findings \
             (tenant_id, repo_config_id, branch, kind, ecosystem, package_name, \
              current_version, tool, rule_id, severity, file_path, line, title, \
              fingerprint, status) \
             VALUES ($1,$2,$3,$4,'','','',$5,$6,$7,$8,$9,'a title',$10,'open')",
        )
        .bind(tenant)
        .bind(repo_config_id)
        .bind(branch)
        .bind(kind)
        .bind(tool)
        .bind(rule_id)
        .bind(severity)
        .bind(file_path)
        .bind(line)
        .bind(format!("{tool}:{rule_id}:{file_path}:{line}"))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed tool finding: {e}"));
    }

    async fn seed_scan_run(pool: &sqlx::PgPool, tenant: Uuid, repo_config_id: i64) -> i64 {
        let row: (i64,) = sqlx::query_as(
            "INSERT INTO codescan_scan_runs (tenant_id, repo_config_id, branch, status) \
             VALUES ($1, $2, 'main', 'completed') RETURNING id",
        )
        .bind(tenant)
        .bind(repo_config_id)
        .fetch_one(pool)
        .await
        .unwrap_or_else(|e| panic!("seed scan run: {e}"));
        row.0
    }

    fn gzip(content: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder
            .write_all(content)
            .unwrap_or_else(|e| panic!("gzip write: {e}"));
        encoder
            .finish()
            .unwrap_or_else(|e| panic!("gzip finish: {e}"))
    }

    async fn seed_sbom(
        pool: &sqlx::PgPool,
        tenant: Uuid,
        repo_config_id: i64,
        scan_run_id: i64,
        content: &[u8],
    ) {
        sqlx::query(
            "INSERT INTO codescan_sbom_artifacts \
             (tenant_id, repo_config_id, branch, scan_run_id, format, doc_gzip) \
             VALUES ($1, $2, 'main', $3, 'cyclonedx-json', $4)",
        )
        .bind(tenant)
        .bind(repo_config_id)
        .bind(scan_run_id)
        .bind(gzip(content))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("seed sbom: {e}"));
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

    /// CodeScan Sentinel P3: the policy engine's resolved `action` column
    /// (migrations/0006) must be both readable and filterable, and every
    /// triage column must serialize even when never triaged (`None`/`""`
    /// defaults — a finding predating P3, or one below Enterprise tier).
    #[tokio::test]
    async fn list_findings_filters_by_action_and_exposes_p3_triage_fields() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let tenant: Uuid = crate::routes::test_support::TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let repo = seed_repo(&state.db, tenant).await;

        seed_finding(
            &state.db,
            tenant,
            repo,
            "main",
            "cve",
            "critical",
            "pkg-untriaged",
            "GHSA-a",
            "open",
        )
        .await;
        seed_finding(
            &state.db,
            tenant,
            repo,
            "main",
            "cve",
            "critical",
            "pkg-triaged",
            "GHSA-b",
            "open",
        )
        .await;
        sqlx::query(
            "UPDATE codescan_findings SET action = 'alert', used = true, reachable = true, \
             exposure = 'external', ai_severity = 'high', ai_rationale = 'reachable', \
             triage_source = 'waddleai', triaged_at = now() \
             WHERE tenant_id = $1 AND package_name = 'pkg-triaged'",
        )
        .bind(tenant)
        .execute(&state.db)
        .await
        .unwrap_or_else(|e| panic!("update finding: {e}"));

        let server = test_server(state);

        let untriaged = server
            .get("/api/v1/codescan/findings?action=")
            .authorization_bearer(&admin)
            .await;
        untriaged.assert_status_ok();
        let untriaged_body: serde_json::Value = untriaged.json();
        assert_eq!(untriaged_body["total"], 1);
        assert_eq!(untriaged_body["data"][0]["package_name"], "pkg-untriaged");
        assert_eq!(untriaged_body["data"][0]["used"], serde_json::Value::Null);
        assert_eq!(untriaged_body["data"][0]["triage_source"], "");

        let triaged = server
            .get("/api/v1/codescan/findings?action=alert")
            .authorization_bearer(&admin)
            .await;
        triaged.assert_status_ok();
        let triaged_body: serde_json::Value = triaged.json();
        assert_eq!(triaged_body["total"], 1);
        let row = &triaged_body["data"][0];
        assert_eq!(row["package_name"], "pkg-triaged");
        assert_eq!(row["used"], true);
        assert_eq!(row["reachable"], true);
        assert_eq!(row["exposure"], "external");
        assert_eq!(row["ai_severity"], "high");
        assert_eq!(row["triage_source"], "waddleai");
        assert_eq!(
            row["severity"], "critical",
            "the original scanner severity must never be overwritten by ai_severity"
        );
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

    // ── P2 tool registry: findings filters + summary breakdown ────────────

    #[tokio::test]
    async fn list_findings_filters_by_tool_and_exposes_tool_registry_fields() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let tenant: Uuid = crate::routes::test_support::TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let repo = seed_repo(&state.db, tenant).await;

        seed_finding(
            &state.db, tenant, repo, "main", "sca", "low", "left-pad", "", "open",
        )
        .await;
        seed_tool_finding(
            &state.db, tenant, repo, "main", "sast", "semgrep", "rule-a", "high", "app.py", 10,
        )
        .await;

        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/findings?tool=semgrep")
            .authorization_bearer(&admin)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["total"], 1);
        assert_eq!(body["data"][0]["tool"], "semgrep");
        assert_eq!(body["data"][0]["rule_id"], "rule-a");
        assert_eq!(body["data"][0]["file_path"], "app.py");
        assert_eq!(body["data"][0]["line"], 10);
        assert_eq!(body["data"][0]["title"], "a title");

        // A P1 sca/cve row carries the tool-registry columns as empty
        // string / null, never leaking a stray value across kinds.
        let sca_resp = server
            .get("/api/v1/codescan/findings?kind=sca")
            .authorization_bearer(&admin)
            .await;
        sca_resp.assert_status_ok();
        let sca_body: serde_json::Value = sca_resp.json();
        assert_eq!(sca_body["data"][0]["tool"], "");
        assert!(sca_body["data"][0]["file_path"].is_null());
    }

    #[tokio::test]
    async fn findings_summary_breaks_down_by_tool() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let tenant: Uuid = crate::routes::test_support::TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let repo = seed_repo(&state.db, tenant).await;

        seed_finding(
            &state.db, tenant, repo, "main", "sca", "low", "left-pad", "", "open",
        )
        .await;
        seed_tool_finding(
            &state.db, tenant, repo, "main", "sast", "semgrep", "rule-a", "high", "app.py", 10,
        )
        .await;
        seed_tool_finding(
            &state.db,
            tenant,
            repo,
            "main",
            "secret",
            "gitleaks",
            "aws-key",
            "critical",
            "deploy.sh",
            4,
        )
        .await;

        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/findings/summary")
            .authorization_bearer(&admin)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["total_open"], 3);
        let buckets = body["by_bucket"].as_array().cloned().unwrap_or_default();
        assert!(
            buckets
                .iter()
                .any(|b| b["tool"] == "semgrep" && b["kind"] == "sast" && b["count"] == 1)
        );
        assert!(
            buckets
                .iter()
                .any(|b| b["tool"] == "gitleaks" && b["kind"] == "secret" && b["count"] == 1)
        );
        assert!(
            buckets
                .iter()
                .any(|b| b["tool"] == "" && b["kind"] == "sca" && b["count"] == 1)
        );
    }

    // ── SBOM endpoint ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn get_sbom_requires_auth() {
        let server = test_server(crate::state::AppStateInner::for_tests(dev_license()));
        server
            .get("/api/v1/codescan/findings/sbom/1")
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn get_sbom_is_forbidden_when_sentinel_flag_disabled() {
        let state = crate::state::AppStateInner::for_tests(gated_license());
        let token = sign_token(&state, "1", "viewer");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/findings/sbom/1")
            .authorization_bearer(token)
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_sbom_returns_404_when_no_sbom_recorded() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let server = test_server(state);
        let resp = server
            .get("/api/v1/codescan/findings/sbom/999999")
            .authorization_bearer(&admin)
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_sbom_returns_the_decompressed_cyclonedx_document() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let admin = sign_token(&state, "1", "admin");
        let tenant: Uuid = crate::routes::test_support::TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let repo = seed_repo(&state.db, tenant).await;
        let run_id = seed_scan_run(&state.db, tenant, repo).await;
        let doc = br#"{"bomFormat":"CycloneDX","components":[]}"#;
        seed_sbom(&state.db, tenant, repo, run_id, doc).await;

        let server = test_server(state);
        let resp = server
            .get(&format!("/api/v1/codescan/findings/sbom/{run_id}"))
            .authorization_bearer(&admin)
            .await;
        resp.assert_status_ok();
        let body: serde_json::Value = resp.json();
        assert_eq!(body["scan_run_id"], run_id);
        assert_eq!(body["repo_config_id"], repo);
        assert_eq!(body["format"], "cyclonedx-json");
        let content: serde_json::Value = serde_json::from_str(
            body["content"]
                .as_str()
                .unwrap_or_else(|| panic!("content must be a string")),
        )
        .unwrap_or_else(|e| panic!("content must be valid json: {e}"));
        assert_eq!(content["bomFormat"], "CycloneDX");
    }

    #[tokio::test]
    async fn get_sbom_is_tenant_scoped() {
        let state = crate::routes::test_support::db_state(dev_license()).await;
        let other_admin = crate::routes::test_support::sign_token_for_tenant(
            &state,
            "2",
            "admin",
            crate::routes::test_support::OTHER_TENANT_ID,
        );
        let tenant: Uuid = crate::routes::test_support::TEST_TENANT_ID
            .parse()
            .unwrap_or_else(|e| panic!("uuid: {e}"));
        let repo = seed_repo(&state.db, tenant).await;
        let run_id = seed_scan_run(&state.db, tenant, repo).await;
        seed_sbom(&state.db, tenant, repo, run_id, b"{}").await;

        let server = test_server(state);
        let resp = server
            .get(&format!("/api/v1/codescan/findings/sbom/{run_id}"))
            .authorization_bearer(&other_admin)
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }
}
