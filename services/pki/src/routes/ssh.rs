//! SSH REST handlers (v1 `api/v1/ssh.py`, blueprint prefix `/api/v1/ssh`).

use std::collections::HashMap;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use serde_json::Value;

use crate::ca::ssh::SshIssueParams;
use crate::error::{ApiError, ApiJson};
use crate::models::{
    AuthorizedKeysRequest, RevokeRequest, SshCertificateRequest, SshConfigRequest,
};
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

fn map_to_pairs(m: std::collections::BTreeMap<String, String>) -> Vec<(String, String)> {
    m.into_iter().collect()
}

/// POST /api/v1/ssh/certificates — issue an SSH certificate.
pub async fn issue(
    State(st): State<AppState>,
    headers: HeaderMap,
    body: ApiJson<SshCertificateRequest>,
) -> Result<Response, ApiError> {
    let req = body.0;
    req.validate().map_err(ApiError::Validation)?;
    let extensions = if req.certificate_type == "host" {
        None
    } else {
        req.extensions.map(map_to_pairs)
    };
    let critical_options = req.critical_options.map(map_to_pairs);
    let params = SshIssueParams {
        public_key: req.public_key,
        certificate_type: req.certificate_type,
        key_id: Some(req.key_id),
        principals: req.principals,
        validity_seconds: req.validity_seconds,
        extensions,
        critical_options,
        source_addresses: req.source_addresses,
        force_command: req.force_command,
        hostname: req.hostname,
    };
    let result = st
        .manager
        .issue_ssh(params, user_id(&headers).as_deref())
        .await?;
    Ok((StatusCode::CREATED, Json(result)).into_response())
}

/// GET /api/v1/ssh/certificates/{cert_id}
pub async fn get_cert(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    st.manager
        .get_ssh(Some(&cert_id), None, true)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))
}

/// GET /api/v1/ssh/certificates/serial/{serial}
pub async fn get_by_serial(
    State(st): State<AppState>,
    Path(serial): Path<String>,
) -> Result<Json<Value>, ApiError> {
    st.manager
        .get_ssh(None, Some(&serial), true)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))
}

/// POST /api/v1/ssh/certificates/{cert_id}/revoke
pub async fn revoke_cert(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
    headers: HeaderMap,
    body: ApiJson<RevokeRequest>,
) -> Result<Json<Value>, ApiError> {
    let ok = st
        .manager
        .revoke_ssh(
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

/// GET /api/v1/ssh/certificates — list with filters.
pub async fn list(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let (page, page_size) = page_params(&q);
    let (items, total) = st
        .manager
        .list_ssh(
            q.get("status").map(String::as_str),
            q.get("type").map(String::as_str),
            q.get("principal").map(String::as_str),
            page,
            page_size,
        )
        .await?;
    Ok(paginated(items, total, page, page_size))
}

/// GET /api/v1/ssh/krl
pub async fn get_krl(State(st): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let krl = st.manager.generate_ssh_krl().await?;
    if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) == Some("application/octet-stream")
    {
        let b64 = krl
            .get("krl_binary")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| ApiError::internal("krl decode", e))?;
        return Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (
                    header::CONTENT_DISPOSITION,
                    "attachment; filename=revoked_keys",
                ),
            ],
            bytes,
        )
            .into_response());
    }
    Ok(Json(krl).into_response())
}

/// GET /api/v1/ssh/ca — SSH CA info.
pub async fn ca_info(State(st): State<AppState>) -> Json<Value> {
    Json(serde_json::json!({
        "ca_public_key": st.manager.ssh.ca_public_key(),
        "key_type": st.manager.ssh.ca_key_type(),
        "fingerprint": st.manager.ssh.ca_fingerprint(),
        "serial_counter": st.manager.ssh.serial_counter(),
        "krl_version": st.manager.ssh.krl_version(),
    }))
}

/// GET /api/v1/ssh/ca/public-key
pub async fn ca_public_key(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let key = st.manager.ssh.ca_public_key().to_owned();
    if headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) == Some("text/plain") {
        return (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], key).into_response();
    }
    Json(serde_json::json!({ "ca_public_key": key })).into_response()
}

/// POST /api/v1/ssh/config/known-hosts
pub async fn known_hosts(
    State(st): State<AppState>,
    body: ApiJson<Value>,
) -> Result<Json<Value>, ApiError> {
    let hostnames: Vec<String> = body
        .0
        .get("hostnames")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    if hostnames.is_empty() {
        return Err(ApiError::BadRequest("hostnames required".into()));
    }
    Ok(Json(serde_json::json!({
        "known_hosts": st.manager.ssh.known_hosts_entry(&hostnames, true),
        "hostnames": hostnames,
    })))
}

/// POST /api/v1/ssh/config/authorized-keys
pub async fn authorized_keys(
    State(st): State<AppState>,
    body: ApiJson<AuthorizedKeysRequest>,
) -> Json<Value> {
    let req = body.0;
    let options = map_to_pairs(req.options);
    let entry = st
        .manager
        .ssh
        .authorized_keys_entry(&req.principals, &options);
    Json(serde_json::json!({
        "authorized_keys": entry,
        "trustedUserCAKeys": st.manager.ssh.ca_public_key(),
        "principals": req.principals,
    }))
}

/// POST /api/v1/ssh/config/ssh-config
pub async fn ssh_config(
    State(st): State<AppState>,
    body: ApiJson<SshConfigRequest>,
) -> Json<Value> {
    let req = body.0;
    let cfg = st.manager.ssh.ssh_config(
        &req.hostname,
        req.port,
        req.user.as_deref(),
        req.identity_file.as_deref(),
    );
    let kh = st
        .manager
        .ssh
        .known_hosts_entry(std::slice::from_ref(&req.hostname), true);
    Json(serde_json::json!({
        "ssh_config": cfg,
        "known_hosts_entry": kh,
        "ca_public_key": st.manager.ssh.ca_public_key(),
    }))
}

/// GET /api/v1/ssh/certificates/{cert_id}/status
pub async fn cert_status(
    State(st): State<AppState>,
    Path(cert_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let cert = st
        .manager
        .get_ssh(Some(&cert_id), None, false)
        .await?
        .ok_or_else(|| ApiError::NotFound("Certificate not found".into()))?;
    let vb = cert
        .get("valid_before")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let is_expired = chrono::NaiveDateTime::parse_from_str(vb, "%Y-%m-%dT%H:%M:%S%.f")
        .map(|d| d < chrono::Utc::now().naive_utc())
        .unwrap_or(false);
    Ok(Json(serde_json::json!({
        "certificate_id": cert_id,
        "serial_number": cert.get("serial_number"),
        "key_id": cert.get("key_id"),
        "status": cert.get("status"),
        "is_expired": is_expired,
        "valid_after": cert.get("valid_after"),
        "valid_before": cert.get("valid_before"),
        "revoked_at": cert.get("revoked_at"),
        "revocation_reason": cert.get("revocation_reason"),
    })))
}

/// POST /api/v1/ssh/verify — parse + verify an SSH certificate.
pub async fn verify(
    State(st): State<AppState>,
    body: ApiJson<Value>,
) -> Result<Response, ApiError> {
    let cert = body
        .0
        .get("certificate")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let Some(cert) = cert else {
        return Err(ApiError::BadRequest("certificate required".into()));
    };
    let ssh = st.manager.ssh.clone();
    let cert_for_task = cert.clone();
    let mut info = tokio::task::spawn_blocking(move || ssh.check_certificate(&cert_for_task))
        .await
        .map_err(|e| ApiError::internal("verify join", e))?
        .map_err(ApiError::from)?;

    // Overlay revocation status from the DB when the serial is known.
    #[allow(clippy::collapsible_if)]
    if let Some(serial) = info
        .get("serial")
        .and_then(Value::as_str)
        .map(str::to_owned)
    {
        if let Some(row) = st.manager.get_ssh(None, Some(&serial), false).await? {
            if row.get("status").and_then(Value::as_str) == Some("revoked") {
                info["status"] = Value::String("revoked".into());
            }
            info["revoked_at"] = row.get("revoked_at").cloned().unwrap_or(Value::Null);
        }
    }
    Ok(Json(info).into_response())
}

/// Router-level tests for the SSH handlers. Handlers that back a real
/// `ssh-keygen` subprocess (`issue`, `verify`) use
/// `AppStateInner::for_tests_with_real_ca()`; everything else uses the
/// cheaper canned `AppStateInner::for_tests()`. See the module doc on
/// `routes::x509::tests` and `docs/v2-port/testing-pattern.md` for why
/// DB-backed success branches (a real issued cert re-fetched, listing real
/// rows) are out of scope here — pki has no `migrations/` directory.
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use axum::http::StatusCode;

    use crate::state::AppStateInner;

    use super::paginated;

    #[test]
    fn paginated_computes_page_count_and_zero_page_size_is_zero() {
        let items = vec![serde_json::json!({"id": "1"})];
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

    fn real_ca_server() -> axum_test::TestServer {
        axum_test::TestServer::new(crate::routes::router(
            AppStateInner::for_tests_with_real_ca(),
        ))
    }

    fn bearer() -> String {
        match skauswatch_auth::issue_service_token("tester", "admin", "test-secret", 300) {
            Ok(t) => format!("Bearer {t}"),
            Err(e) => panic!("issue test token: {e}"),
        }
    }

    fn gen_subject_pubkey() -> String {
        let path = std::env::temp_dir().join(format!(
            "skauswatch-ssh-route-subject-{}",
            uuid::Uuid::new_v4()
        ));
        let status = std::process::Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-f")
            .arg(&path)
            .arg("-N")
            .arg("")
            .arg("-q")
            .status()
            .unwrap_or_else(|e| panic!("run ssh-keygen: {e}"));
        assert!(status.success());
        std::fs::read_to_string(format!("{}.pub", path.display()))
            .unwrap_or_else(|e| panic!("read generated pubkey: {e}"))
            .trim()
            .to_owned()
    }

    #[tokio::test]
    async fn issue_rejects_invalid_body() {
        let server = test_server();
        let res = server
            .post("/api/v1/ssh/certificates")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({ "public_key": "bad", "key_id": "k", "principals": [] }))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn issue_valid_body_signs_real_certificate_then_500s_on_unreachable_db() {
        let server = real_ca_server();
        let pubkey = gen_subject_pubkey();
        let res = server
            .post("/api/v1/ssh/certificates")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({
                "public_key": pubkey,
                "key_id": "route-test",
                "principals": ["alice"],
            }))
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_cert_with_unparseable_id_is_404_without_touching_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/ssh/certificates/not-a-uuid")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_cert_with_valid_uuid_hits_db_and_500s() {
        let server = test_server();
        let res = server
            .get(&format!(
                "/api/v1/ssh/certificates/{}",
                uuid::Uuid::new_v4()
            ))
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_by_serial_always_touches_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/ssh/certificates/serial/123")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn revoke_cert_with_unparseable_id_is_404_without_touching_db() {
        let server = test_server();
        let res = server
            .post("/api/v1/ssh/certificates/not-a-uuid/revoke")
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
                "/api/v1/ssh/certificates/{}/revoke",
                uuid::Uuid::new_v4()
            ))
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn list_touches_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/ssh/certificates")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_query_param("status", "active")
            .add_query_param("type", "user")
            .add_query_param("principal", "alice")
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn get_krl_touches_db_json_and_binary_accept_variants() {
        let server = test_server();
        let json_res = server
            .get("/api/v1/ssh/krl")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        json_res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);

        let bin_res = server
            .get("/api/v1/ssh/krl")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_header(axum::http::header::ACCEPT, "application/octet-stream")
            .await;
        bin_res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn ca_info_never_touches_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/ssh/ca")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["ca_public_key"].as_str().unwrap().starts_with("ssh-"));
    }

    #[tokio::test]
    async fn ca_public_key_supports_json_and_text_plain() {
        let server = test_server();
        let json_res = server
            .get("/api/v1/ssh/ca/public-key")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        json_res.assert_status_ok();
        let body: serde_json::Value = json_res.json();
        assert!(body["ca_public_key"].as_str().unwrap().starts_with("ssh-"));

        let text_res = server
            .get("/api/v1/ssh/ca/public-key")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .add_header(axum::http::header::ACCEPT, "text/plain")
            .await;
        text_res.assert_status_ok();
        assert!(text_res.text().starts_with("ssh-"));
    }

    #[tokio::test]
    async fn known_hosts_requires_hostnames_and_succeeds_when_present() {
        let server = test_server();
        let bad = server
            .post("/api/v1/ssh/config/known-hosts")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({}))
            .await;
        bad.assert_status(StatusCode::BAD_REQUEST);

        let ok = server
            .post("/api/v1/ssh/config/known-hosts")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({ "hostnames": ["a.example.com"] }))
            .await;
        ok.assert_status_ok();
        let body: serde_json::Value = ok.json();
        assert!(
            body["known_hosts"]
                .as_str()
                .unwrap()
                .starts_with("@cert-authority")
        );
    }

    #[tokio::test]
    async fn authorized_keys_never_touches_db() {
        let server = test_server();
        let res = server
            .post("/api/v1/ssh/config/authorized-keys")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({ "principals": ["alice"], "options": {} }))
            .await;
        res.assert_status_ok();
    }

    #[tokio::test]
    async fn ssh_config_never_touches_db() {
        let server = test_server();
        let res = server
            .post("/api/v1/ssh/config/ssh-config")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({ "hostname": "host.example.com" }))
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(
            body["ssh_config"]
                .as_str()
                .unwrap()
                .contains("Host host.example.com")
        );
    }

    #[tokio::test]
    async fn cert_status_with_unparseable_id_is_404_without_touching_db() {
        let server = test_server();
        let res = server
            .get("/api/v1/ssh/certificates/not-a-uuid/status")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cert_status_with_valid_uuid_hits_db_and_500s() {
        let server = test_server();
        let res = server
            .get(&format!(
                "/api/v1/ssh/certificates/{}/status",
                uuid::Uuid::new_v4()
            ))
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn verify_requires_certificate_field() {
        let server = test_server();
        let res = server
            .post("/api/v1/ssh/verify")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({}))
            .await;
        res.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_parses_a_real_certificate_then_500s_overlaying_revocation_from_db() {
        // Mint a real signed certificate directly against the manager
        // (bypassing HTTP, where issuance always 500s on the unreachable
        // DB insert before returning the cert) so /verify has genuine
        // cert-v01 bytes to feed `ssh-keygen -L` for real.
        let state = AppStateInner::for_tests_with_real_ca();
        let pubkey = gen_subject_pubkey();
        let issued = state
            .manager
            .issue_ssh(
                crate::ca::ssh::SshIssueParams {
                    public_key: pubkey,
                    certificate_type: "user".into(),
                    key_id: Some("verify-test".into()),
                    principals: vec!["alice".into()],
                    validity_seconds: 3600,
                    extensions: None,
                    critical_options: None,
                    source_addresses: vec![],
                    force_command: None,
                    hostname: None,
                },
                None,
            )
            .await;
        // The manager's INSERT still fails against the unreachable pool —
        // real signing already happened via spawn_blocking before that, so
        // pull the certificate PEM out of the CA engine directly instead.
        assert!(issued.is_err(), "manager insert should fail without a DB");

        let real_issued = state
            .manager
            .ssh
            .issue(&crate::ca::ssh::SshIssueParams {
                public_key: gen_subject_pubkey(),
                certificate_type: "user".into(),
                key_id: Some("verify-test-2".into()),
                principals: vec!["alice".into()],
                validity_seconds: 3600,
                extensions: None,
                critical_options: None,
                source_addresses: vec![],
                force_command: None,
                hostname: None,
            })
            .unwrap_or_else(|e| panic!("real ssh issue: {e}"));

        let server = axum_test::TestServer::new(crate::routes::router(state));
        let res = server
            .post("/api/v1/ssh/verify")
            .add_header(axum::http::header::AUTHORIZATION, bearer())
            .json(&serde_json::json!({ "certificate": real_issued.certificate }))
            .await;
        // check_certificate() ran for real (parsed type/serial/key_id); the
        // handler then tries to overlay revocation status from the DB and
        // fails there, so the *observable* outcome is still 500 — but the
        // real spawn_blocking + parse path executed, unlike the BadRequest
        // test above which never reaches it.
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ===================== DB-backed success paths =====================

    async fn db_server() -> axum_test::TestServer {
        axum_test::TestServer::new(crate::routes::router(
            crate::routes::test_support::db_state().await,
        ))
    }

    async fn issue_one(server: &axum_test::TestServer, key_id: &str) -> serde_json::Value {
        let res = server
            .post("/api/v1/ssh/certificates")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({
                "public_key": gen_subject_pubkey(),
                "key_id": key_id,
                "principals": ["alice"],
            }))
            .await;
        res.assert_status(StatusCode::CREATED);
        res.json()
    }

    #[tokio::test]
    async fn issue_persists_and_get_by_id_and_serial_find_it() {
        let server = db_server().await;
        let issued = issue_one(&server, "route-db-issue").await;
        assert_eq!(issued["key_id"], "route-db-issue");
        let id = issued["id"].as_str().unwrap();
        let serial = issued["serial_number"].as_str().unwrap();

        let by_id = server
            .get(&format!("/api/v1/ssh/certificates/{id}"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        by_id.assert_status_ok();
        let by_id_json: serde_json::Value = by_id.json();
        assert!(
            by_id_json["certificate"]
                .as_str()
                .unwrap()
                .contains("cert-v01@openssh.com")
        );

        let by_serial = server
            .get(&format!("/api/v1/ssh/certificates/serial/{serial}"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        by_serial.assert_status_ok();
    }

    #[tokio::test]
    async fn revoke_succeeds_on_a_real_row_and_reflects_in_status() {
        let server = db_server().await;
        let issued = issue_one(&server, "route-db-revoke").await;
        let id = issued["id"].as_str().unwrap();

        let res = server
            .post(&format!("/api/v1/ssh/certificates/{id}/revoke"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "reason": "key_compromise" }))
            .await;
        res.assert_status_ok();

        let status = server
            .get(&format!("/api/v1/ssh/certificates/{id}/status"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        status.assert_status_ok();
        let status_json: serde_json::Value = status.json();
        assert_eq!(status_json["status"], "revoked");
    }

    #[tokio::test]
    async fn list_returns_real_rows() {
        let server = db_server().await;
        issue_one(&server, "route-db-list-1").await;
        issue_one(&server, "route-db-list-2").await;

        let res = server
            .get("/api/v1/ssh/certificates")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["total"].as_i64().unwrap() >= 2);
    }

    #[tokio::test]
    async fn get_krl_returns_real_binary_in_json_and_octet_stream_variants() {
        let server = db_server().await;
        let issued = issue_one(&server, "route-db-krl").await;
        let id = issued["id"].as_str().unwrap();
        server
            .post(&format!("/api/v1/ssh/certificates/{id}/revoke"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({}))
            .await
            .assert_status_ok();

        let json_res = server
            .get("/api/v1/ssh/krl")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .await;
        json_res.assert_status_ok();
        let json_body: serde_json::Value = json_res.json();
        assert!(!json_body["krl_binary"].as_str().unwrap().is_empty());

        let bin_res = server
            .get("/api/v1/ssh/krl")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .add_header(axum::http::header::ACCEPT, "application/octet-stream")
            .await;
        bin_res.assert_status_ok();
        assert_eq!(
            bin_res.header(axum::http::header::CONTENT_TYPE),
            "application/octet-stream"
        );
        assert!(!bin_res.as_bytes().is_empty());
    }

    #[tokio::test]
    async fn verify_overlays_real_revocation_status_from_the_db() {
        let server = db_server().await;
        let issued = issue_one(&server, "route-db-verify").await;
        let cert = issued["certificate"].as_str().unwrap().to_owned();
        let id = issued["id"].as_str().unwrap();

        let before = server
            .post("/api/v1/ssh/verify")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "certificate": cert }))
            .await;
        before.assert_status_ok();
        let before_json: serde_json::Value = before.json();
        assert_ne!(before_json["status"], serde_json::json!("revoked"));

        server
            .post(&format!("/api/v1/ssh/certificates/{id}/revoke"))
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({}))
            .await
            .assert_status_ok();

        let after = server
            .post("/api/v1/ssh/verify")
            .add_header(
                axum::http::header::AUTHORIZATION,
                crate::routes::test_support::bearer(),
            )
            .json(&serde_json::json!({ "certificate": cert }))
            .await;
        after.assert_status_ok();
        let after_json: serde_json::Value = after.json();
        assert_eq!(after_json["status"], "revoked");
    }
}
