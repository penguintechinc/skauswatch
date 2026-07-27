//! REST surface for the SSH CA service, mounted under `/api/v1/ssh`.
//!
//! The v1 ssh-ca container ran a `skauswatch.services.ssh_ca.main:app` module
//! that was not preserved in the repo (only the `AsyncSSHProcessor` engine
//! remains), so the concrete paths here are reconstructed from the engine's
//! operations and the canonical SSH REST shape in the v1 pki-server
//! `api/v1/ssh.py`. The parity-critical piece — the certificate template — is
//! ported faithfully; see `ca.rs` and `docs/v2-port/ssh-ca-contract.md`.
//!
//! AUTH (hardened, finding #2): `docs/v2-port/ssh-ca-contract.md` originally
//! documented this as intentionally unauthenticated ("cluster-internal,
//! reached by the manager/pki plane"), but a security audit determined that
//! posture is unacceptable for a service holding an SSH CA signing key —
//! anyone who can reach the pod can mint host/user SSH certificates. Every
//! route now requires `Authorization: Bearer <jwt>` (HS256, shared
//! `JWT_SECRET_KEY`), enforced as a router-wide layer via
//! `skauswatch_auth::AuthenticatedCaller`. No in-repo caller exists today
//! (confirmed by repo-wide grep for `ssh-ca`/`SSH_CA_URL`) — gating
//! introduces no breakage; a future caller must present a machine JWT minted
//! with `skauswatch_auth::issue_service_token`.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;

use crate::ca::{SignError, SignParams, SshCa};
use crate::error::ApiError;
use crate::error::ApiJson;
use crate::model::{
    CertificateType, DEFAULT_VALIDITY_SECONDS, IssueCertificateRequest, IssueCertificateResponse,
    RevokeCertificateRequest,
};
use crate::store::{CertStore, StoredCert};

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// The CA signing identity.
    pub ca: Arc<SshCa>,
    /// The issued-certificate + revocation store.
    pub store: Arc<CertStore>,
    /// Shared HS256 signing secret (`JWT_SECRET_KEY`) — every route below
    /// requires a valid bearer token verified against this (finding #2).
    pub jwt_secret: Arc<str>,
}

impl skauswatch_auth::JwtSecretSource for AppState {
    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }
}

/// Builds the `/api/v1/ssh` router. Every route requires a valid bearer
/// token (finding #2) — enforced as a single router-wide layer so no
/// individual handler can accidentally be added without the gate.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/api/v1/ssh/certificates",
            post(issue_certificate).get(list_certificates),
        )
        .route("/api/v1/ssh/certificates/{id}", get(get_certificate))
        .route(
            "/api/v1/ssh/certificates/{id}/revoke",
            post(revoke_certificate),
        )
        .route("/api/v1/ssh/krl", get(get_krl))
        .route("/api/v1/ssh/ca/public-key", get(get_ca_public_key))
        .layer(axum::middleware::from_extractor_with_state::<
            skauswatch_auth::AuthenticatedCaller,
            AppState,
        >(state.clone()))
        .with_state(state)
}

/// The five OpenSSH-standard user-certificate permit extensions, applied by
/// default when a user-cert request omits `extensions`. v1's engine defaulted
/// to no extensions, which produced login-unusable certs (no pty); this is a
/// documented parity deviation.
const DEFAULT_USER_EXTENSIONS: [&str; 5] = [
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
];

fn to_naive(secs: i64) -> chrono::NaiveDateTime {
    chrono::DateTime::from_timestamp(secs, 0)
        .unwrap_or_default()
        .naive_utc()
}

/// `POST /api/v1/ssh/certificates` — issue and store a certificate.
async fn issue_certificate(
    State(state): State<AppState>,
    ApiJson(req): ApiJson<IssueCertificateRequest>,
) -> Result<Response, ApiError> {
    if req.public_key.trim().is_empty() {
        return Err(ApiError::BadRequest("public_key is required".to_owned()));
    }
    let validity = req.validity_duration.unwrap_or(DEFAULT_VALIDITY_SECONDS);
    if validity == 0 {
        return Err(ApiError::BadRequest(
            "validity_duration must be positive".to_owned(),
        ));
    }

    let request_id = req
        .request_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    // v1 key_id format: "{type}-{request_id}".
    let key_id = req
        .key_id
        .clone()
        .unwrap_or_else(|| format!("{}-{}", req.certificate_type.as_str(), request_id));

    // Extensions: caller's map verbatim if present, else the standard user set
    // (host certs default to none).
    let extensions: BTreeMap<String, String> = match req.extensions.clone() {
        Some(m) => m,
        None => match req.certificate_type {
            CertificateType::User => DEFAULT_USER_EXTENSIONS
                .iter()
                .map(|e| ((*e).to_owned(), String::new()))
                .collect(),
            CertificateType::Host => BTreeMap::new(),
        },
    };

    // Critical options: caller's map plus source-address/force-command
    // shorthands (v1 accepted these fields but dropped them).
    let mut critical_options = req.critical_options.clone().unwrap_or_default();
    if let Some(addr) = req.source_address.as_ref().filter(|s| !s.is_empty()) {
        critical_options.insert("source-address".to_owned(), addr.clone());
    }
    if let Some(cmd) = req.force_command.as_ref().filter(|s| !s.is_empty()) {
        critical_options.insert("force-command".to_owned(), cmd.clone());
    }

    let valid_after = Utc::now().timestamp();
    let valid_before = valid_after.saturating_add(validity as i64);
    let serial = state.store.next_serial();

    let signed = state
        .ca
        .sign(&SignParams {
            certificate_type: req.certificate_type,
            public_key_line: &req.public_key,
            principals: &req.principals,
            serial,
            key_id: &key_id,
            valid_after: valid_after as u64,
            valid_before: valid_before as u64,
            extensions: &extensions,
            critical_options: &critical_options,
        })
        .map_err(|e| match e {
            SignError::InvalidSubjectKey(m) => ApiError::BadRequest(m),
            SignError::Signing(m) => ApiError::internal("ssh certificate signing", m),
        })?;

    tracing::info!(
        serial, key_id = %key_id, cert_type = req.certificate_type.as_str(),
        requester = req.requester_id.as_deref().unwrap_or("-"),
        "SSH certificate issued"
    );

    let metadata = req.metadata.clone().unwrap_or(serde_json::Value::Null);
    let stored = StoredCert {
        certificate_id: request_id.clone(),
        certificate_type: req.certificate_type,
        serial_number: serial,
        key_id: key_id.clone(),
        principals: req.principals.clone(),
        status: "active".to_owned(),
        signed_certificate: signed.signed_certificate.clone(),
        public_key_fingerprint: signed.public_key_fingerprint.clone(),
        ca_fingerprint: state.ca.fingerprint().to_owned(),
        valid_after: to_naive(valid_after),
        valid_before: to_naive(valid_before),
        revoked_at: None,
        revocation_reason: None,
        metadata: metadata.clone(),
    };
    state.store.insert(stored);

    let resp = IssueCertificateResponse {
        certificate_id: request_id,
        certificate_type: req.certificate_type,
        signed_certificate: signed.signed_certificate,
        serial_number: serial,
        principals: req.principals,
        key_id,
        valid_after: skauswatch_streams::py_isoformat(to_naive(valid_after)),
        valid_before: skauswatch_streams::py_isoformat(to_naive(valid_before)),
        public_key_fingerprint: signed.public_key_fingerprint,
        ca_fingerprint: state.ca.fingerprint().to_owned(),
        metadata,
    };
    Ok((StatusCode::CREATED, Json(resp)).into_response())
}

fn stored_to_json(c: &StoredCert) -> serde_json::Value {
    serde_json::json!({
        "certificate_id": c.certificate_id,
        "certificate_type": c.certificate_type,
        "serial_number": c.serial_number,
        "key_id": c.key_id,
        "principals": c.principals,
        "status": c.status,
        "signed_certificate": c.signed_certificate,
        "public_key_fingerprint": c.public_key_fingerprint,
        "ca_fingerprint": c.ca_fingerprint,
        "valid_after": skauswatch_streams::py_isoformat(c.valid_after),
        "valid_before": skauswatch_streams::py_isoformat(c.valid_before),
        "revoked_at": skauswatch_streams::py_isoformat_opt(c.revoked_at),
        "revocation_reason": c.revocation_reason,
        "metadata": c.metadata,
    })
}

/// Query parameters for `GET /api/v1/ssh/certificates`.
#[derive(serde::Deserialize)]
struct ListQuery {
    #[serde(rename = "type")]
    certificate_type: Option<CertificateType>,
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// `GET /api/v1/ssh/certificates` — list certificates with filters.
async fn list_certificates(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let certs = state
        .store
        .list(q.certificate_type, q.status.as_deref(), limit);
    let items: Vec<serde_json::Value> = certs.iter().map(stored_to_json).collect();
    let total = items.len();
    Ok(Json(serde_json::json!({ "certificates": items, "total": total })).into_response())
}

/// `GET /api/v1/ssh/certificates/{id}` — fetch one certificate.
async fn get_certificate(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    match state.store.get(&id) {
        Some(c) => Ok(Json(stored_to_json(&c)).into_response()),
        None => Err(ApiError::NotFound("Certificate not found".to_owned())),
    }
}

/// `POST /api/v1/ssh/certificates/{id}/revoke` — revoke a certificate.
async fn revoke_certificate(
    State(state): State<AppState>,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<RevokeCertificateRequest>,
) -> Result<Response, ApiError> {
    let reason = req.reason.unwrap_or_else(|| "unspecified".to_owned());
    if state.store.revoke(&id, &reason, Utc::now().naive_utc()) {
        Ok(Json(serde_json::json!({
            "message": "Certificate revoked",
            "certificate_id": id,
        }))
        .into_response())
    } else {
        Err(ApiError::NotFound("Certificate not found".to_owned()))
    }
}

/// `GET /api/v1/ssh/krl` — current Key Revocation List (v1 `_generate_krl_sync`).
async fn get_krl(State(state): State<AppState>) -> Result<Response, ApiError> {
    let revoked: Vec<serde_json::Value> = state
        .store
        .krl_entries()
        .iter()
        .map(|e| {
            serde_json::json!({
                "serial_number": e.serial_number,
                "revocation_time": skauswatch_streams::py_isoformat(e.revocation_time),
                "reason": e.reason,
                "fingerprint": e.certificate_fingerprint,
            })
        })
        .collect();
    Ok(Json(serde_json::json!({
        "version": 1,
        "generated_at": skauswatch_streams::py_now_isoformat(),
        "ca_fingerprint": state.ca.fingerprint(),
        "revoked_certificates": revoked,
    }))
    .into_response())
}

/// `GET /api/v1/ssh/ca/public-key` — CA public key (JSON, or text/plain when
/// requested via `Accept`).
async fn get_ca_public_key(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let line = state.ca.public_key_openssh();
    let wants_text = headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/plain"))
        .unwrap_or(false);
    if wants_text {
        ([(header::CONTENT_TYPE, "text/plain")], line.to_owned()).into_response()
    } else {
        Json(serde_json::json!({
            "ca_public_key": line,
            "ca_fingerprint": state.ca.fingerprint(),
        }))
        .into_response()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::Path;

    const TEST_JWT_SECRET: &str = "test-secret";

    fn test_state() -> AppState {
        // Missing path → ephemeral CA key (fine for tests).
        let ca = SshCa::load_or_generate(Path::new("/nonexistent-skauswatch-ssh-ca-key"))
            .expect("ephemeral ca");
        AppState {
            ca: Arc::new(ca),
            store: Arc::new(CertStore::new()),
            jwt_secret: TEST_JWT_SECRET.into(),
        }
    }

    /// `Authorization` header value with a valid bearer token signed with
    /// `TEST_JWT_SECRET`, matching `test_state()`.
    fn auth_header() -> (&'static str, String) {
        let token = skauswatch_auth::issue_service_token("tester", "admin", TEST_JWT_SECRET, 300)
            .expect("issue test token");
        ("Authorization", format!("Bearer {token}"))
    }

    fn subject_pub_line() -> String {
        let key = ssh_key::PrivateKey::random(
            &mut ssh_key::rand_core::OsRng,
            ssh_key::Algorithm::Ed25519,
        )
        .expect("subject key");
        key.public_key().to_openssh().expect("subject pub")
    }

    #[tokio::test]
    async fn issue_get_list_revoke_flow() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let body = serde_json::json!({
            "certificate_type": "user",
            "public_key": subject_pub_line(),
            "principals": ["alice", "bob"],
            "validity_duration": 3600,
        });

        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val.clone())
            .json(&body)
            .await;
        resp.assert_status(StatusCode::CREATED);
        let issued: serde_json::Value = resp.json();
        let cert_id = issued["certificate_id"]
            .as_str()
            .expect("cert id")
            .to_owned();
        assert_eq!(issued["serial_number"].as_u64(), Some(1_000_001));
        assert_eq!(
            issued["key_id"].as_str(),
            Some(format!("user-{cert_id}").as_str())
        );
        let signed = issued["signed_certificate"].as_str().expect("signed");
        // The issued certificate parses as a real OpenSSH certificate.
        let cert = ssh_key::Certificate::from_openssh(signed).expect("parse cert");
        assert_eq!(cert.cert_type(), ssh_key::certificate::CertType::User);
        assert!(cert.extensions().0.contains_key("permit-pty"));

        // GET it back.
        let got = server
            .get(&format!("/api/v1/ssh/certificates/{cert_id}"))
            .add_header(hdr, val.clone())
            .await;
        got.assert_status_ok();
        assert_eq!(got.json::<serde_json::Value>()["status"], "active");

        // List with type filter.
        let list = server
            .get("/api/v1/ssh/certificates")
            .add_header(hdr, val.clone())
            .add_query_param("type", "user")
            .await;
        list.assert_status_ok();
        assert_eq!(list.json::<serde_json::Value>()["total"], 1);

        // Revoke.
        let rev = server
            .post(&format!("/api/v1/ssh/certificates/{cert_id}/revoke"))
            .add_header(hdr, val.clone())
            .json(&serde_json::json!({ "reason": "keyCompromise" }))
            .await;
        rev.assert_status_ok();

        // KRL reflects the revocation.
        let krl = server
            .get("/api/v1/ssh/krl")
            .add_header(hdr, val.clone())
            .await;
        krl.assert_status_ok();
        let krl_json: serde_json::Value = krl.json();
        assert_eq!(
            krl_json["revoked_certificates"].as_array().map(|a| a.len()),
            Some(1)
        );
    }

    #[tokio::test]
    async fn unknown_certificate_is_404() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let resp = server
            .get("/api/v1/ssh/certificates/nope")
            .add_header(hdr, val)
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_public_key_is_400() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .json(&serde_json::json!({ "certificate_type": "user", "public_key": "" }))
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ca_public_key_endpoint() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let resp = server
            .get("/api/v1/ssh/ca/public-key")
            .add_header(hdr, val)
            .await;
        resp.assert_status_ok();
        let json: serde_json::Value = resp.json();
        assert!(
            json["ca_fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("SHA256:")
        );
    }

    /// Regression for finding #2: this service holds an SSH CA signing
    /// key — every route must reject an unauthenticated caller with 401
    /// before touching the CA/store at all.
    #[tokio::test]
    async fn every_route_requires_jwt() {
        let server = axum_test::TestServer::new(router(test_state()));
        for (method, path) in [
            ("GET", "/api/v1/ssh/certificates"),
            ("POST", "/api/v1/ssh/certificates"),
            ("GET", "/api/v1/ssh/certificates/x"),
            ("POST", "/api/v1/ssh/certificates/x/revoke"),
            ("GET", "/api/v1/ssh/krl"),
            ("GET", "/api/v1/ssh/ca/public-key"),
        ] {
            let resp = match method {
                "GET" => server.get(path).await,
                _ => server.post(path).await,
            };
            resp.assert_status(StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn token_signed_with_wrong_secret_is_rejected() {
        let server = axum_test::TestServer::new(router(test_state()));
        let bad_token = skauswatch_auth::issue_service_token("x", "admin", "wrong-secret", 300)
            .expect("issue token");
        let resp = server
            .get("/api/v1/ssh/ca/public-key")
            .add_header("Authorization", format!("Bearer {bad_token}"))
            .await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }
}
