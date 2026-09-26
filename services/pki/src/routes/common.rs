//! Common REST handlers (v1 `api/v1/common.py`): statistics, combined CA
//! info, audit log, expiring certificates, and expired-status cleanup.
//!
//! TENANT ISOLATION (`docs/v2-port/tenancy-model.md` §6): `statistics` and
//! `audit` are per-tenant operational views and are filtered on the
//! caller's `crate::tenant::TenantId` like every other endpoint. `expiring`
//! and `cleanup` are the one deliberate exception in this service — see
//! their doc comments below.
//!
//! `expiring`/`cleanup` are defined here (bodies unchanged) but are no
//! longer mounted on this crate's primary, ES256-bearer-gated router
//! (`crate::routes::router`) or documented in the public OpenAPI spec —
//! they're served exclusively from the dedicated mTLS-required maintenance
//! listener, `crate::maintenance`, which is also where their request/
//! response-level tests now live. See that module's docs and
//! `docs/v2-port/service-auth-model.md` §3.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use chrono::{Duration, Utc};
use serde_json::Value;
use skauswatch_streams::{py_isoformat, py_isoformat_opt};
use sqlx::{QueryBuilder, Row};
use uuid::Uuid;

use crate::error::{ApiError, ErrorResponse};
use crate::state::AppState;
use crate::tenant::TenantId;

/// GET /api/v1/statistics — combined X.509 + SSH counts.
#[utoipa::path(
    get,
    path = "/api/v1/statistics",
    tag = "common",
    operation_id = "common_statistics",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Combined X.509 + SSH counts", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
)]
pub async fn statistics(
    State(st): State<AppState>,
    TenantId(tenant): TenantId,
) -> Result<Json<Value>, ApiError> {
    Ok(Json(st.manager.statistics(tenant).await?))
}

/// GET /api/v1/ca/info — info for both certificate authorities.
#[utoipa::path(
    get,
    path = "/api/v1/ca/info",
    tag = "common",
    operation_id = "common_all_ca_info",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Combined X.509 + SSH CA info", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub async fn all_ca_info(State(st): State<AppState>) -> Json<Value> {
    let info = st.manager.x509.info();
    Json(serde_json::json!({
        "x509": {
            "subject": info.subject,
            "issuer": info.issuer,
            "not_before": py_isoformat(info.not_before),
            "not_after": py_isoformat(info.not_after),
            "fingerprint_sha256": info.fingerprint_sha256,
            "serial_counter": st.manager.x509.serial_counter(),
            "crl_number": st.manager.x509.crl_number(),
        },
        "ssh": {
            "ca_public_key": st.manager.ssh.ca_public_key(),
            "key_type": st.manager.ssh.ca_key_type(),
            "fingerprint": st.manager.ssh.ca_fingerprint(),
            "serial_counter": st.manager.ssh.serial_counter(),
            "krl_version": st.manager.ssh.krl_version(),
        },
    }))
}

/// GET /api/v1/audit — paginated PKI audit log with filters.
#[utoipa::path(
    get,
    path = "/api/v1/audit",
    tag = "common",
    operation_id = "common_audit",
    security(("bearer_jwt" = [])),
    params(
        ("page" = Option<i64>, Query, description = "Page number (default 1)"),
        ("page_size" = Option<i64>, Query, description = "Page size (default 50)"),
        ("event_type" = Option<String>, Query, description = "Filter by audit event_type"),
        ("certificate_type" = Option<String>, Query, description = "Filter by certificate_type (x509/ssh)"),
    ),
    responses(
        (status = 200, description = "Paginated audit log", body = serde_json::Value),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
)]
pub async fn audit(
    State(st): State<AppState>,
    TenantId(tenant): TenantId,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let page: i64 = q.get("page").and_then(|v| v.parse().ok()).unwrap_or(1);
    let page_size: i64 = q
        .get("page_size")
        .and_then(|v| v.parse().ok())
        .unwrap_or(50);
    let event_type = q.get("event_type").map(String::as_str);
    let cert_type = q.get("certificate_type").map(String::as_str);

    let mut count = QueryBuilder::new("SELECT COUNT(*) FROM pki_audit_log");
    push_audit_filters(&mut count, tenant, event_type, cert_type);
    let total: i64 = count.build().fetch_one(st.manager.db()).await?.try_get(0)?;

    let mut qb = QueryBuilder::new(
        "SELECT id, event_type, certificate_type, certificate_id, serial_number, subject, \
         actor_id, action, status, error_message, timestamp FROM pki_audit_log",
    );
    push_audit_filters(&mut qb, tenant, event_type, cert_type);
    qb.push(" ORDER BY timestamp DESC LIMIT ")
        .push_bind(page_size)
        .push(" OFFSET ")
        .push_bind((page - 1).max(0) * page_size);
    let rows = qb.build().fetch_all(st.manager.db()).await?;

    let audit_log: Vec<Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "id": r.try_get::<Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                "event_type": r.try_get::<String, _>("event_type").unwrap_or_default(),
                "certificate_type": r.try_get::<Option<String>, _>("certificate_type").unwrap_or(None),
                "certificate_id": r.try_get::<Option<Uuid>, _>("certificate_id").ok().flatten().map(|u| u.to_string()),
                "serial_number": r.try_get::<Option<String>, _>("serial_number").unwrap_or(None),
                "subject": r.try_get::<Option<String>, _>("subject").unwrap_or(None),
                "actor_id": r.try_get::<Option<Uuid>, _>("actor_id").ok().flatten().map(|u| u.to_string()),
                "action": r.try_get::<String, _>("action").unwrap_or_default(),
                "status": r.try_get::<String, _>("status").unwrap_or_default(),
                "error_message": r.try_get::<Option<String>, _>("error_message").unwrap_or(None),
                "timestamp": py_isoformat_opt(r.try_get("timestamp").ok().flatten()),
            })
        })
        .collect();
    let pages = if page_size > 0 {
        (total + page_size - 1) / page_size
    } else {
        0
    };
    Ok(Json(serde_json::json!({
        "audit_log": audit_log,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    })))
}

/// GET /api/v1/expiring (served only via `crate::maintenance`) —
/// certificates expiring within N days.
///
/// CROSS-TENANT BY DESIGN: unlike every other query in this service, this
/// scans `x509_certificates`/`ssh_certificates` across all tenants with no
/// `tenant_id` filter. This is a deliberate exception (not an oversight —
/// see `docs/v2-port/tenancy-model.md` §6), authorized by the dedicated
/// `spiffe://penguintech.io/<env>/endpoint-agent-maintenance` mTLS peer
/// identity `crate::maintenance` requires to complete a connection to this
/// handler at all (`docs/v2-port/service-auth-model.md` §3) — a
/// cryptographic check, not the network-topology-only enforcement this
/// service relied on previously. No local extractor/scope check is needed
/// here: by the time this handler runs, the caller has already proven that
/// identity at the TLS layer.
#[utoipa::path(
    get,
    path = "/api/v1/expiring",
    tag = "common",
    operation_id = "common_expiring",
    params(
        ("days" = Option<i64>, Query, description = "Expiry window in days (default 30)"),
        ("type" = Option<String>, Query, description = "x509 | ssh | all (default all)"),
    ),
    responses(
        (status = 200, description = "Certificates expiring within the window", body = serde_json::Value),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
)]
pub async fn expiring(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let days: i64 = q.get("days").and_then(|v| v.parse().ok()).unwrap_or(30);
    let cert_type = q.get("type").map(String::as_str).unwrap_or("all");
    let now = Utc::now().naive_utc();
    let before = now + Duration::days(days);

    let mut result = serde_json::json!({
        "expiring_within_days": days,
        "x509": [],
        "ssh": [],
    });

    if cert_type == "x509" || cert_type == "all" {
        let rows = sqlx::query(
            "SELECT id, serial_number, subject, not_after FROM x509_certificates \
             WHERE status='active' AND not_after < $1 AND not_after > $2 ORDER BY not_after",
        )
        .bind(before)
        .bind(now)
        .fetch_all(st.manager.db())
        .await?;
        result["x509"] = rows
            .iter()
            .map(|r| {
                let na: chrono::NaiveDateTime = r.try_get("not_after").unwrap_or(now);
                serde_json::json!({
                    "id": r.try_get::<Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                    "serial_number": r.try_get::<String, _>("serial_number").unwrap_or_default(),
                    "subject": r.try_get::<String, _>("subject").unwrap_or_default(),
                    "not_after": py_isoformat(na),
                    "days_until_expiry": (na - now).num_days(),
                })
            })
            .collect();
    }
    if cert_type == "ssh" || cert_type == "all" {
        let rows = sqlx::query(
            "SELECT id, serial_number, key_id, valid_before FROM ssh_certificates \
             WHERE status='active' AND valid_before < $1 AND valid_before > $2 ORDER BY valid_before",
        )
        .bind(before)
        .bind(now)
        .fetch_all(st.manager.db())
        .await?;
        result["ssh"] = rows
            .iter()
            .map(|r| {
                let vb: chrono::NaiveDateTime = r.try_get("valid_before").unwrap_or(now);
                serde_json::json!({
                    "id": r.try_get::<Uuid, _>("id").map(|u| u.to_string()).unwrap_or_default(),
                    "serial_number": r.try_get::<String, _>("serial_number").unwrap_or_default(),
                    "key_id": r.try_get::<String, _>("key_id").unwrap_or_default(),
                    "valid_before": py_isoformat(vb),
                    "days_until_expiry": (vb - now).num_days(),
                })
            })
            .collect();
    }
    Ok(Json(result))
}

/// POST /api/v1/cleanup (served only via `crate::maintenance`) — mark
/// expired certificates as `expired`.
///
/// CROSS-TENANT BY DESIGN — same disposition and rationale as `expiring`
/// above: a maintenance sweep across every tenant's expired rows,
/// cryptographically authorized by the `endpoint-agent-maintenance` mTLS
/// peer identity (see that handler's doc comment).
#[utoipa::path(
    post,
    path = "/api/v1/cleanup",
    tag = "common",
    operation_id = "common_cleanup",
    responses(
        (status = 200, description = "Cleanup result", body = serde_json::Value),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
)]
pub async fn cleanup(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = Utc::now().naive_utc();
    let x = sqlx::query(
        "UPDATE x509_certificates SET status='expired', updated_at=$1 \
         WHERE status='active' AND not_after < $1",
    )
    .bind(now)
    .execute(st.manager.db())
    .await?
    .rows_affected();
    let s = sqlx::query(
        "UPDATE ssh_certificates SET status='expired', updated_at=$1 \
         WHERE status='active' AND valid_before < $1",
    )
    .bind(now)
    .execute(st.manager.db())
    .await?
    .rows_affected();
    Ok(Json(serde_json::json!({
        "message": "Cleanup completed",
        "updated_count": x + s,
    })))
}

fn push_audit_filters(
    qb: &mut QueryBuilder<sqlx::Postgres>,
    tenant: Uuid,
    event_type: Option<&str>,
    cert_type: Option<&str>,
) {
    qb.push(" WHERE tenant_id = ").push_bind(tenant);
    if let Some(e) = event_type {
        qb.push(" AND event_type = ").push_bind(e.to_owned());
    }
    if let Some(c) = cert_type {
        qb.push(" AND certificate_type = ").push_bind(c.to_owned());
    }
}

/// Router-level + unit tests for the common handlers. Every REST handler
/// here queries Postgres directly with no DB-free branch (unlike x509/ssh's
/// `(None, None)`-identifier shortcuts) — see
/// `docs/v2-port/testing-pattern.md` on why pki, lacking a `migrations/`
/// directory, can only exercise these up through the point the unreachable
/// pool fails. `push_audit_filters` is still fully unit-testable in
/// isolation since `QueryBuilder::sql()` needs no live connection.
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use axum::http::StatusCode;
    use sqlx::QueryBuilder;
    use uuid::Uuid;

    use crate::state::AppStateInner;
    use crate::tenant::TENANT_HEADER;

    use super::push_audit_filters;

    fn test_server() -> axum_test::TestServer {
        axum_test::TestServer::new(crate::routes::router(AppStateInner::for_tests()))
    }

    fn bearer() -> String {
        match skauswatch_auth::issue_service_token(
            "tester",
            "admin",
            skauswatch_testkit::jwt::signing_key(),
            300,
        ) {
            Ok(t) => format!("Bearer {t}"),
            Err(e) => panic!("issue test token: {e}"),
        }
    }

    /// Fixed tenant used by tests that don't specifically exercise
    /// cross-tenant isolation.
    fn tenant() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn push_audit_filters_builds_expected_where_clauses() {
        let t = tenant();
        let mut qb = QueryBuilder::new("SELECT 1 FROM x");
        push_audit_filters(&mut qb, t, None, None);
        assert!(
            qb.sql()
                .as_str()
                .contains("SELECT 1 FROM x WHERE tenant_id = ")
        );

        let mut qb2 = QueryBuilder::new("SELECT 1 FROM x");
        push_audit_filters(&mut qb2, t, Some("certificate_issued"), Some("x509"));
        assert!(qb2.sql().as_str().contains(" WHERE tenant_id = "));
        assert!(qb2.sql().as_str().contains(" AND event_type = "));
        assert!(qb2.sql().as_str().contains(" AND certificate_type = "));
    }

    #[tokio::test]
    async fn statistics_touches_db_and_500s() {
        let server = test_server();
        let res = server
            .get("/api/v1/statistics")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_header(TENANT_HEADER, tenant().to_string())
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn statistics_without_tenant_header_is_403() {
        let server = test_server();
        let res = server
            .get("/api/v1/statistics")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn audit_without_tenant_header_is_403() {
        let server = test_server();
        let res = server
            .get("/api/v1/audit")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn all_ca_info_never_touches_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/ca/info")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(
            body["x509"]["subject"]
                .as_str()
                .unwrap()
                .contains("SkausWatch")
        );
        assert!(
            body["ssh"]["ca_public_key"]
                .as_str()
                .unwrap()
                .starts_with("ssh-")
        );
    }

    #[tokio::test]
    async fn audit_with_filters_touches_db_and_500s() {
        let server = test_server();
        let res = server
            .get("/api/v1/audit")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_header(TENANT_HEADER, tenant().to_string())
            .add_query_param("event_type", "certificate_issued")
            .add_query_param("certificate_type", "x509")
            .add_query_param("page", "2")
            .add_query_param("page_size", "10")
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // `expiring`/`cleanup` request-level tests (both the DB-error and
    // DB-backed-success shapes previously here) moved to
    // `crate::maintenance`'s test module — those handlers are no longer
    // reachable via this router at all (see `super::router`'s doc comment
    // and `expiring_and_cleanup_are_no_longer_served_on_the_primary_router`
    // in `routes::mod`'s tests).

    // ===================== DB-backed success paths =====================

    async fn db_server_and_state() -> (axum_test::TestServer, crate::state::AppState) {
        let state = crate::routes::test_support::db_state().await;
        (
            axum_test::TestServer::new(crate::routes::router(state.clone())),
            state,
        )
    }

    #[tokio::test]
    async fn statistics_reports_real_counts() {
        let (server, state) = db_server_and_state().await;
        let t = tenant();
        state
            .manager
            .issue_x509(
                crate::ca::x509::X509IssueParams {
                    subject: "CN=common-stats.example.com".into(),
                    key_algorithm: "RSA".into(),
                    key_size: 2048,
                    validity_days: 30,
                    san_dns: vec![],
                    san_ip: vec![],
                    san_email: vec![],
                    key_usage: vec![],
                    extended_key_usage: vec![],
                    is_ca: false,
                    path_length: None,
                    csr_pem: None,
                },
                None,
                t,
            )
            .await
            .unwrap();

        let res = server
            .get("/api/v1/statistics")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_header(TENANT_HEADER, t.to_string())
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["x509"]["total"].as_i64().unwrap() >= 1);
    }

    #[tokio::test]
    async fn statistics_does_not_count_another_tenants_certificates() {
        let (server, state) = db_server_and_state().await;
        state
            .manager
            .issue_x509(
                crate::ca::x509::X509IssueParams {
                    subject: "CN=common-stats-other-tenant.example.com".into(),
                    key_algorithm: "RSA".into(),
                    key_size: 2048,
                    validity_days: 30,
                    san_dns: vec![],
                    san_ip: vec![],
                    san_email: vec![],
                    key_usage: vec![],
                    extended_key_usage: vec![],
                    is_ca: false,
                    path_length: None,
                    csr_pem: None,
                },
                None,
                tenant(), // a different tenant than the caller below
            )
            .await
            .unwrap();

        let res = server
            .get("/api/v1/statistics")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_header(TENANT_HEADER, tenant().to_string())
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["x509"]["total"], 0);
    }

    #[tokio::test]
    async fn all_ca_info_pairs_with_the_real_statistics_endpoint() {
        // Already DB-free (tested above without a real pool); confirm it
        // still succeeds when the state also carries a real, connected pool.
        let (server, _state) = db_server_and_state().await;
        let res = server
            .get("/api/v1/ca/info")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status_ok();
    }

    #[tokio::test]
    async fn audit_lists_a_real_row_written_by_issuance() {
        let (server, state) = db_server_and_state().await;
        let t = tenant();
        state
            .manager
            .issue_x509(
                crate::ca::x509::X509IssueParams {
                    subject: "CN=common-audit.example.com".into(),
                    key_algorithm: "RSA".into(),
                    key_size: 2048,
                    validity_days: 30,
                    san_dns: vec![],
                    san_ip: vec![],
                    san_email: vec![],
                    key_usage: vec![],
                    extended_key_usage: vec![],
                    is_ca: false,
                    path_length: None,
                    csr_pem: None,
                },
                None,
                t,
            )
            .await
            .unwrap();

        let res = server
            .get("/api/v1/audit")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_header(TENANT_HEADER, t.to_string())
            .add_query_param("event_type", "certificate_issued")
            .add_query_param("certificate_type", "x509")
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["total"].as_i64().unwrap() >= 1);
        let entries = body["audit_log"].as_array().unwrap();
        assert!(
            entries
                .iter()
                .any(|e| e["event_type"] == "certificate_issued")
        );
    }

    // `expiring_lists_real_x509_and_ssh_rows` / `cleanup_marks_real_expired_rows`
    // (DB-backed success paths) also moved to `crate::maintenance`'s test
    // module alongside the DB-error-path tests above.
}
