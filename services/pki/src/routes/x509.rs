//! X.509 REST handlers (v1 `api/v1/x509.py`, blueprint prefix
//! `/api/v1/certificates`).

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::Value;

use crate::error::{ApiError, ApiJson};
use crate::models::{RevokeRequest, X509CertificateRequest};
use crate::state::AppState;

use super::{page_params, user_id};

fn paginated(items: Vec<Value>, total: i64, page: i64, page_size: i64) -> Json<Value> {
    let pages = if page_size > 0 {
        (total + page_size - 1) / page_size
    } else {
        0
    };
    Json(serde_json::json!({
        "certificates": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }))
}

/// POST /api/v1/certificates — issue an X.509 certificate.
pub async fn issue(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: ApiJson<X509CertificateRequest>,
) -> Result<Response, ApiError> {
    let req = body.0;
    req.validate().map_err(ApiError::Validation)?;
    let params = req.into_issue_params();
    let result = st
        .manager
        .issue_x509(params, user_id(&headers).as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(result)).into_response())
}

/// GET /api/v1/certificates/{cert_id}
pub async fn get_cert(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let include_pk = q
        .get("include_private_key")
        .map(|v| v == "true")
        .unwrap_or(false);
    let mut cert = st
        .manager
        .get_x509(Some(&cert_id), None, true)
        .await?
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    #[allow(clippy::collapsible_if)]
    if !include_pk {
        if let Some(o) = cert.as_object_mut() {
            o.remove("private_key_pem");
        }
    }
    Ok(Json(cert))
}

/// GET /api/v1/certificates/serial/{serial}
pub async fn get_by_serial(
    State(st): State<AppState>,
    Path(serial): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let mut cert = st
        .manager
        .get_x509(None, Some(&serial), true)
        .await?
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    if let Some(o) = cert.as_object_mut() {
        o.remove("private_key_pem");
    }
    Ok(Json(cert))
}

/// POST /api/v1/certificates/{cert_id}/revoke
pub async fn revoke_cert(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
    headers: HeaderMap,
    body: ApiJson<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    let ok = st
        .manager
        .revoke_x509(
            Some(&cert_id),
            None,
            &body.0.reason,
            user_id(&headers).as_deref(),
        )
        .await?;
    if !ok {
        return Err(ApiError::NotFound("Certificate not found".into()));
    }
    Ok(Json(serde_json::json!({
        "message": "Certificate revoked",
        "certificate_id": cert_id,
    })))
}

/// POST /api/v1/certificates/serial/{serial}/revoke
pub async fn revoke_by_serial(
    State(st): State<AppState>,
    Path(serial): Path<String>,
    headers: HeaderMap,
    body: ApiJson<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    let ok = st
        .manager
        .revoke_x509(
            None,
            Some(&serial),
            &body.0.reason,
            user_id(&headers).as_deref(),
        )
        .await?;
    if !ok {
        return Err(ApiError::NotFound("Certificate not found".into()));
    }
    Ok(Json(serde_json::json!({
        "message": "Certificate revoked",
        "serial_number": serial,
    })))
}

/// GET /api/v1/certificates — list with filters.
pub async fn list(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (page, page_size) = page_params(&q);
    let expires_before = q
        .get("expires_before")
        .and_then(|v| chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M:%S").ok());
    let (items, total) = st
        .manager
        .list_x509(
            q.get("status").map(String::as_str),
            q.get("subject").map(String::as_str),
            expires_before,
            page,
            page_size,
        )
        .await?;
    Ok(paginated(items, total, page, page_size))
}

/// Body for POST /api/v1/certificates/search (v1 `CertificateSearchRequest`).
#[derive(Deserialize, Default)]
pub struct SearchBody {
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    expires_before: Option<String>,
    #[serde(default = "one")]
    page: i64,
    #[serde(default = "fifty")]
    page_size: i64,
}
fn one() -> i64 {
    1
}
fn fifty() -> i64 {
    50
}

/// POST /api/v1/certificates/search
pub async fn search(
    State(st): State<AppState>,
    body: ApiJson<SearchBody>,
) -> Result<Json<Value>, ApiError> {
    let b = body.0;
    let expires_before = b
        .expires_before
        .as_deref()
        .and_then(|v| chrono::NaiveDateTime::parse_from_str(v, "%Y-%m-%dT%H:%M:%S").ok());
    let (items, total) = st
        .manager
        .list_x509(
            b.status.as_deref(),
            b.subject.as_deref(),
            expires_before,
            b.page,
            b.page_size,
        )
        .await?;
    Ok(paginated(items, total, b.page, b.page_size))
}

/// GET /api/v1/certificates/crl
pub async fn get_crl(State(st): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let crl = st.manager.generate_x509_crl().await?;
    if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) == Some("application/pkix-crl") {
        let pem = crl
            .get("crl_pem")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        return Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/pkix-crl"),
                (header::CONTENT_DISPOSITION, "attachment; filename=crl.pem"),
            ],
            pem,
        )
            .into_response());
    }
    Ok(Json(crl).into_response())
}

/// POST /api/v1/certificates/ocsp — JSON OCSP status (binary → 501, per v1).
pub async fn ocsp(
    State(st): State<AppState>,
    headers: HeaderMap,
    bytes: axum::body::Bytes,
) -> Result<Response, ApiError> {
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        == Some("application/ocsp-request")
    {
        return Err(ApiError::NotImplemented(
            "Binary OCSP not yet implemented".into(),
        ));
    }
    let data: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    let serial = data.get("serial_number").and_then(Value::as_str);
    let Some(serial) = serial else {
        return Err(ApiError::BadRequest("serial_number required".into()));
    };
    let now = skauswatch_streams::py_now_isoformat();
    let cert = st.manager.get_x509(None, Some(serial), false).await?;
    let Some(cert) = cert else {
        return Ok(Json(serde_json::json!({
            "serial_number": serial,
            "status": "unknown",
            "this_update": now,
            "next_update": now,
        }))
        .into_response());
    };
    let (status, rev_time, rev_reason) =
        if cert.get("status").and_then(Value::as_str) == Some("revoked") {
            (
                "revoked",
                cert.get("revoked_at").cloned().unwrap_or(Value::Null),
                cert.get("revocation_reason")
                    .cloned()
                    .unwrap_or(Value::Null),
            )
        } else {
            ("good", Value::Null, Value::Null)
        };
    Ok(Json(serde_json::json!({
        "serial_number": serial,
        "status": status,
        "this_update": now,
        "next_update": now,
        "revocation_time": rev_time,
        "revocation_reason": rev_reason,
    }))
    .into_response())
}

/// GET /api/v1/certificates/ca — CA info + PEM.
pub async fn ca_info(State(st): State<AppState>) -> Json<Value> {
    let info = st.manager.x509.info();
    Json(serde_json::json!({
        "subject": info.subject,
        "issuer": info.issuer,
        "not_before": skauswatch_streams::py_isoformat(info.not_before),
        "not_after": skauswatch_streams::py_isoformat(info.not_after),
        "fingerprint_sha256": info.fingerprint_sha256,
        "serial_counter": st.manager.x509.serial_counter(),
        "crl_number": st.manager.x509.crl_number(),
        "ca_certificate_pem": st.manager.x509.ca_certificate_pem(),
    }))
}

/// GET /api/v1/certificates/ca/certificate — download CA cert PEM.
pub async fn download_ca_cert(State(st): State<AppState>) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/x-pem-file"),
            (header::CONTENT_DISPOSITION, "attachment; filename=ca.crt"),
        ],
        st.manager.x509.ca_certificate_pem().to_owned(),
    )
        .into_response()
}

/// GET /api/v1/certificates/{cert_id}/status
pub async fn cert_status(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let cert = st
        .manager
        .get_x509(Some(&cert_id), None, false)
        .await?
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    let na = cert
        .get("not_after")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_expired = chrono::NaiveDateTime::parse_from_str(na, "%Y-%m-%dT%H:%M:%S%.f")
        .map(|d| d < chrono::Utc::now().naive_utc())
        .unwrap_or(false);
    Ok(Json(serde_json::json!({
        "certificate_id": cert_id,
        "serial_number": cert.get("serial_number"),
        "status": cert.get("status"),
        "is_expired": is_expired,
        "not_before": cert.get("not_before"),
        "not_after": cert.get("not_after"),
        "revoked_at": cert.get("revoked_at"),
        "revocation_reason": cert.get("revocation_reason"),
    })))
}

/// Router-level tests for the X.509 handlers, run against the full
/// production router (auth layer included) with `AppStateInner::for_tests()`
/// — a real (rcgen-backed) X.509 CA and an unreachable lazy DB pool. Per
/// `docs/v2-port/testing-pattern.md`, pki has no `migrations/` directory:
/// "found"/success DB branches (issuance persisted then re-fetched, listing
/// real rows, revoking a real row) cannot be exercised without one, so
/// these tests cover validation, the auth gate, the fully-DB-free
/// `(None, None)`-identifier 404 branches, and every DB-touching handler's
/// real-crypto-then-500 path.
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use axum::http::StatusCode;

    use crate::state::AppStateInner;

    use super::paginated;

    #[test]
    fn paginated_computes_page_count_and_zero_page_size_is_zero() {
        let items = vec![serde_json::json!({"serial_number": "1a"})];
        let body = paginated(items.clone(), 101, 2, 50).0;
        assert_eq!(body["total"], 101);
        assert_eq!(body["pages"], 3);
        assert_eq!(body["certificates"], serde_json::json!(items));

        let zero_size = paginated(vec![], 5, 1, 0).0;
        assert_eq!(zero_size["pages"], 0);
    }

    fn test_server() -> axum_test::TestServer {
        axum_test::TestServer::new(crate::routes::router(AppStateInner::for_tests()))
    }

    fn bearer() -> String {
        match skauswatch_auth::issue_service_token("tester", "admin", "test-secret", 300) {
            Ok(t) => format!("Bearer {t}"),
            Err(e) => panic!("issue test token: {e}"),
        }
    }

    #[tokio::test]
    async fn issue_rejects_invalid_body_with_validation_details() {
        let server = test_server();
        let res = server
            .post("/api/v1/certificates")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({ "subject": "", "key_algorithm": "DSA" }))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Validation error");
        assert!(body["details"].as_array().unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn issue_valid_body_runs_real_crypto_then_500s_on_unreachable_db() {
        let server = test_server();
        let res = server
            .post("/api/v1/certificates")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({
                "subject": "CN=route-test.example.com",
                "san_dns": ["route-test.example.com"],
            }))
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
        let body: serde_json::Value = res.json();
        assert_eq!(body["error"], "Internal Server Error");
    }

    #[tokio::test]
    async fn get_cert_with_unparseable_id_is_404_without_touching_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/certificates/not-a-uuid")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_cert_with_valid_uuid_hits_db_and_500s() {
        let server = test_server();
        let res = server
            .get(&format!("/api/v1/certificates/{}", uuid::Uuid::new_v4()))
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_query_param("include_private_key", "true")
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_by_serial_always_touches_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/certificates/serial/abc123")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn revoke_cert_with_unparseable_id_is_404_without_touching_db() {
        let server = test_server();
        let res = server
            .post("/api/v1/certificates/not-a-uuid/revoke")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn revoke_cert_with_valid_uuid_hits_db_and_500s() {
        let server = test_server();
        let res = server
            .post(&format!(
                "/api/v1/certificates/{}/revoke",
                uuid::Uuid::new_v4()
            ))
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({ "reason": "key_compromise" }))
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn revoke_by_serial_always_touches_db() {
        let server = test_server();
        let res = server
            .post("/api/v1/certificates/serial/abc123/revoke")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn list_with_filters_touches_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/certificates")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_query_param("status", "active")
            .add_query_param("subject", "example")
            .add_query_param("expires_before", "2030-01-01T00:00:00")
            .add_query_param("page", "2")
            .add_query_param("page_size", "5")
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn search_rejects_invalid_json_and_500s_on_valid_body() {
        let server = test_server();
        let bad = server
            .post("/api/v1/certificates/search")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .bytes(axum::body::Bytes::from_static(b"not json"))
            .await;
        bad.assert_status(StatusCode::BAD_REQUEST);

        let ok = server
            .post("/api/v1/certificates/search")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({ "subject": "example", "status": "active" }))
            .await;
        ok.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_crl_touches_db_and_500s() {
        let server = test_server();
        let res = server
            .get("/api/v1/certificates/crl")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_header(axum::http::header::ACCEPT, "application/pkix-crl")
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn ocsp_binary_content_type_is_not_implemented() {
        let server = test_server();
        let res = server
            .post("/api/v1/certificates/ocsp")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_header(axum::http::header::CONTENT_TYPE, "application/ocsp-request")
            .bytes(axum::body::Bytes::from_static(b"\x30\x03"))
            .await;
        res.assert_status(StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn ocsp_missing_serial_number_is_bad_request() {
        let server = test_server();
        let res = server
            .post("/api/v1/certificates/ocsp")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ocsp_with_serial_touches_db_and_500s() {
        let server = test_server();
        let res = server
            .post("/api/v1/certificates/ocsp")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({ "serial_number": "abc123" }))
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn ca_info_never_touches_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/certificates/ca")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["subject"].as_str().unwrap().contains("SkausWatch"));
        assert!(
            body["ca_certificate_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
    }

    #[tokio::test]
    async fn download_ca_cert_returns_pem_with_expected_headers() {
        let server = test_server();
        let res = server
            .get("/api/v1/certificates/ca/certificate")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status_ok();
        assert_eq!(
            res.header(axum::http::header::CONTENT_TYPE),
            "application/x-pem-file"
        );
        let text = res.text();
        assert!(text.contains("BEGIN CERTIFICATE"));
    }

    #[tokio::test]
    async fn cert_status_with_unparseable_id_is_404_without_touching_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/certificates/not-a-uuid/status")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cert_status_with_valid_uuid_hits_db_and_500s() {
        let server = test_server();
        let res = server
            .get(&format!(
                "/api/v1/certificates/{}/status",
                uuid::Uuid::new_v4()
            ))
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ===================== DB-backed success paths =====================

    async fn db_server() -> axum_test::TestServer {
        axum_test::TestServer::new(crate::routes::router(
            crate::routes::test_support::db_state().await,
        ))
    }

    async fn issue_one(server: &axum_test::TestServer, subject: &str) -> serde_json::Value {
        let res = server
            .post("/api/v1/certificates")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "subject": subject, "san_dns": ["www.example.com"] }))
            .await;
        res.assert_status(StatusCode::CREATED);
        res.json()
    }

    #[tokio::test]
    async fn issue_persists_and_get_by_id_and_serial_find_it() {
        let server = db_server().await;
        let issued = issue_one(&server, "CN=route-db-issue.example.com").await;
        assert_eq!(issued["san_dns"], serde_json::json!(["www.example.com"]));
        let id = issued["id"].as_str().unwrap();
        let serial = issued["serial_number"].as_str().unwrap();

        let by_id = server
            .get(&format!("/api/v1/certificates/{id}"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        by_id.assert_status_ok();
        let by_id_json: serde_json::Value = by_id.json();
        // include_private_key defaults false -> field stripped.
        assert!(by_id_json.get("private_key_pem").is_none());

        let with_pk = server
            .get(&format!("/api/v1/certificates/{id}"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .add_query_param("include_private_key", "true")
            .await;
        let with_pk_json: serde_json::Value = with_pk.json();
        assert!(
            with_pk_json["private_key_pem"]
                .as_str()
                .unwrap()
                .contains("PRIVATE KEY")
        );

        let by_serial = server
            .get(&format!("/api/v1/certificates/serial/{serial}"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        by_serial.assert_status_ok();
        // get_by_serial always strips the private key, per the handler.
        let by_serial_json: serde_json::Value = by_serial.json();
        assert!(by_serial_json.get("private_key_pem").is_none());
    }

    #[tokio::test]
    async fn revoke_by_id_and_by_serial_succeed_on_real_rows() {
        let server = db_server().await;
        let issued = issue_one(&server, "CN=route-db-revoke.example.com").await;
        let id = issued["id"].as_str().unwrap();

        let res = server
            .post(&format!("/api/v1/certificates/{id}/revoke"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "reason": "key_compromise" }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert_eq!(body["message"], "Certificate revoked");

        let status = server
            .get(&format!("/api/v1/certificates/{id}/status"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        status.assert_status_ok();
        let status_json: serde_json::Value = status.json();
        assert_eq!(status_json["status"], "revoked");

        let issued2 = issue_one(&server, "CN=route-db-revoke2.example.com").await;
        let serial2 = issued2["serial_number"].as_str().unwrap();
        let res2 = server
            .post(&format!("/api/v1/certificates/serial/{serial2}/revoke"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({}))
            .await;
        res2.assert_status_ok();
    }

    #[tokio::test]
    async fn list_and_search_return_real_rows() {
        let server = db_server().await;
        issue_one(&server, "CN=route-db-list-1.example.com").await;
        issue_one(&server, "CN=route-db-list-2.example.com").await;

        let list_res = server
            .get("/api/v1/certificates")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        list_res.assert_status_ok();
        let list_json: serde_json::Value = list_res.json();
        assert!(list_json["total"].as_i64().unwrap() >= 2);

        let search_res = server
            .post("/api/v1/certificates/search")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "subject": "route-db-list-1" }))
            .await;
        search_res.assert_status_ok();
        let search_json: serde_json::Value = search_res.json();
        assert_eq!(search_json["total"], 1);
    }

    #[tokio::test]
    async fn get_crl_returns_real_pem_in_json_and_pkix_variants() {
        let server = db_server().await;
        let issued = issue_one(&server, "CN=route-db-crl.example.com").await;
        let id = issued["id"].as_str().unwrap();
        server
            .post(&format!("/api/v1/certificates/{id}/revoke"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({}))
            .await
            .assert_status_ok();

        let json_res = server
            .get("/api/v1/certificates/crl")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        json_res.assert_status_ok();
        let json_body: serde_json::Value = json_res.json();
        assert!(
            json_body["crl_pem"]
                .as_str()
                .unwrap()
                .contains("BEGIN X509 CRL")
        );

        let pkix_res = server
            .get("/api/v1/certificates/crl")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .add_header(axum::http::header::ACCEPT, "application/pkix-crl")
            .await;
        pkix_res.assert_status_ok();
        assert_eq!(
            pkix_res.header(axum::http::header::CONTENT_TYPE),
            "application/pkix-crl"
        );
        assert!(pkix_res.text().contains("BEGIN X509 CRL"));
    }

    #[tokio::test]
    async fn ocsp_reports_good_unknown_and_revoked_for_real_rows() {
        let server = db_server().await;
        let issued = issue_one(&server, "CN=route-db-ocsp.example.com").await;
        let serial = issued["serial_number"].as_str().unwrap().to_owned();
        let id = issued["id"].as_str().unwrap();

        let good = server
            .post("/api/v1/certificates/ocsp")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "serial_number": serial }))
            .await;
        good.assert_status_ok();
        let good_json: serde_json::Value = good.json();
        assert_eq!(good_json["status"], "good");

        let unknown = server
            .post("/api/v1/certificates/ocsp")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "serial_number": "does-not-exist" }))
            .await;
        unknown.assert_status_ok();
        let unknown_json: serde_json::Value = unknown.json();
        assert_eq!(unknown_json["status"], "unknown");

        server
            .post(&format!("/api/v1/certificates/{id}/revoke"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "reason": "ca_compromise" }))
            .await
            .assert_status_ok();
        let revoked = server
            .post("/api/v1/certificates/ocsp")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "serial_number": serial }))
            .await;
        revoked.assert_status_ok();
        let revoked_json: serde_json::Value = revoked.json();
        assert_eq!(revoked_json["status"], "revoked");
        assert_eq!(revoked_json["revocation_reason"], "ca_compromise");
    }
}
