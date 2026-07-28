//! Common REST handlers (v1 `api/v1/common.py`): statistics, combined CA
//! info, audit log, expiring certificates, and expired-status cleanup.

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Query, State};
use chrono::{Duration, Utc};
use serde_json::Value;
use skauswatch_streams::{py_isoformat, py_isoformat_opt};
use sqlx::{QueryBuilder, Row};
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

/// GET /api/v1/statistics — combined X.509 + SSH counts.
pub async fn statistics(State(st): State<AppState>) -> Result<Json<Value>, ApiError> {
    Ok(Json(st.manager.statistics().await?))
}

/// GET /api/v1/ca/info — info for both certificate authorities.
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
pub async fn audit(
    State(st): State<AppState>,
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
    push_audit_filters(&mut count, event_type, cert_type);
    let total: i64 = count.build().fetch_one(st.manager.db()).await?.try_get(0)?;

    let mut qb = QueryBuilder::new(
        "SELECT id, event_type, certificate_type, certificate_id, serial_number, subject, \
         actor_id, action, status, error_message, timestamp FROM pki_audit_log",
    );
    push_audit_filters(&mut qb, event_type, cert_type);
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

/// GET /api/v1/expiring — certificates expiring within N days.
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

/// POST /api/v1/cleanup — mark expired certificates as `expired`.
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
    event_type: Option<&str>,
    cert_type: Option<&str>,
) {
    let mut first = true;
    let mut sep = |qb: &mut QueryBuilder<sqlx::Postgres>| {
        qb.push(if first { " WHERE " } else { " AND " });
        first = false;
    };
    if let Some(e) = event_type {
        sep(qb);
        qb.push("event_type = ").push_bind(e.to_owned());
    }
    if let Some(c) = cert_type {
        sep(qb);
        qb.push("certificate_type = ").push_bind(c.to_owned());
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

    use crate::state::AppStateInner;

    use super::push_audit_filters;

    fn test_server() -> axum_test::TestServer {
        axum_test::TestServer::new(crate::routes::router(AppStateInner::for_tests()))
    }

    fn bearer() -> String {
        match skauswatch_auth::issue_service_token("tester", "admin", "test-secret", 300) {
            Ok(t) => format!("Bearer {t}"),
            Err(e) => panic!("issue test token: {e}"),
        }
    }

    #[test]
    fn push_audit_filters_builds_expected_where_clauses() {
        let mut qb = QueryBuilder::new("SELECT 1 FROM x");
        push_audit_filters(&mut qb, None, None);
        assert_eq!(qb.sql().as_str(), "SELECT 1 FROM x");

        let mut qb2 = QueryBuilder::new("SELECT 1 FROM x");
        push_audit_filters(&mut qb2, Some("certificate_issued"), Some("x509"));
        assert!(qb2.sql().as_str().contains(" WHERE event_type = "));
        assert!(qb2.sql().as_str().contains(" AND certificate_type = "));
    }

    #[tokio::test]
    async fn statistics_touches_db_and_500s() {
        let server = test_server();
        let res = server
            .get("/api/v1/statistics")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
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
            .add_query_param("event_type", "certificate_issued")
            .add_query_param("certificate_type", "x509")
            .add_query_param("page", "2")
            .add_query_param("page_size", "10")
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn expiring_touches_db_for_x509_ssh_and_all_types() {
        let server = test_server();
        for cert_type in ["x509", "ssh", "all", "unrecognized"] {
            let res = server
                .get("/api/v1/expiring")
                .add_header(axum::http::header::AUTHORIZATION, bearer())
                .add_query_param("days", "7")
                .add_query_param("type", cert_type)
                .await;
            if cert_type == "unrecognized" {
                // Neither x509 nor ssh branch runs a query -> no DB touch.
                res.assert_status_ok();
                let body: serde_json::Value = res.json();
                assert_eq!(body["expiring_within_days"], 7);
            } else {
                res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    #[tokio::test]
    async fn cleanup_touches_db_and_500s() {
        let server = test_server();
        let res = server
            .post("/api/v1/cleanup")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

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
            )
            .await
            .unwrap();

        let res = server
            .get("/api/v1/statistics")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["x509"]["total"].as_i64().unwrap() >= 1);
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
            )
            .await
            .unwrap();

        let res = server
            .get("/api/v1/audit")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
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

    #[tokio::test]
    async fn expiring_lists_real_x509_and_ssh_rows() {
        let (server, state) = db_server_and_state().await;
        state
            .manager
            .issue_x509(
                crate::ca::x509::X509IssueParams {
                    subject: "CN=common-expiring.example.com".into(),
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
            )
            .await
            .unwrap();

        let x509_res = server
            .get("/api/v1/expiring")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_query_param("days", "60")
            .add_query_param("type", "x509")
            .await;
        x509_res.assert_status_ok();
        let x509_body: serde_json::Value = x509_res.json();
        assert!(!x509_body["x509"].as_array().unwrap().is_empty());
        assert!(x509_body["ssh"].as_array().unwrap().is_empty());

        // ssh_config's default validity is 86400s (1 day) — a 2-day window
        // catches a freshly-issued cert without needing to seed a row.
        let pubkey_path = std::env::temp_dir().join(format!(
            "skauswatch-pki-expiring-subject-{}",
            uuid::Uuid::new_v4()
        ));
        assert!(
            std::process::Command::new("ssh-keygen")
                .arg("-t")
                .arg("ed25519")
                .arg("-f")
                .arg(&pubkey_path)
                .arg("-N")
                .arg("")
                .arg("-q")
                .status()
                .unwrap()
                .success()
        );
        let pubkey = std::fs::read_to_string(format!("{}.pub", pubkey_path.display())).unwrap();
        state
            .manager
            .issue_ssh(
                crate::ca::ssh::SshIssueParams {
                    public_key: pubkey,
                    certificate_type: "user".into(),
                    key_id: None,
                    principals: vec!["alice".into()],
                    validity_seconds: 86_400,
                    extensions: None,
                    critical_options: None,
                    source_addresses: vec![],
                    force_command: None,
                    hostname: None,
                },
                None,
            )
            .await
            .unwrap();

        let all_res = server
            .get("/api/v1/expiring")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_query_param("days", "2")
            .add_query_param("type", "all")
            .await;
        all_res.assert_status_ok();
        let all_body: serde_json::Value = all_res.json();
        assert!(!all_body["ssh"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cleanup_marks_real_expired_rows() {
        let (server, state) = db_server_and_state().await;
        // Seed one already-expired row per CA directly — `issue_*` can only
        // ever produce future dates, so a real "already past not_after /
        // valid_before" row requires inserting past the API, exactly the
        // FK-seed pattern docs/v2-port/testing-pattern.md recommends.
        sqlx::query(
            "INSERT INTO x509_certificates \
             (id, serial_number, subject, issuer, not_before, not_after, key_algorithm, \
              signature_algorithm, fingerprint_sha256, certificate_pem, san_dns, san_ip, \
              san_email, key_usage, extended_key_usage, is_ca, status, metadata, \
              created_at, updated_at) \
             VALUES ($1,'expired-1','CN=expired','CN=expired', now() - interval '400 days', \
              now() - interval '1 day', 'RSA','SHA256','deadbeef','PEM','{}','{}','{}','{}', \
              '{}',false,'active','{}'::jsonb,now(),now())",
        )
        .bind(uuid::Uuid::new_v4())
        .execute(state.manager.db())
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO ssh_certificates \
             (id, serial_number, key_id, certificate_type, principals, valid_after, \
              valid_before, key_type, public_key, certificate, status, metadata, \
              created_at, updated_at) \
             VALUES ($1,'expired-1','k','user','{alice}', now() - interval '2 days', \
              now() - interval '1 day', 'ed25519','ssh-ed25519 AAAA','cert-data','active', \
              '{}'::jsonb, now(), now())",
        )
        .bind(uuid::Uuid::new_v4())
        .execute(state.manager.db())
        .await
        .unwrap();

        let res = server
            .post("/api/v1/cleanup")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["updated_count"].as_i64().unwrap() >= 2);
    }
}
