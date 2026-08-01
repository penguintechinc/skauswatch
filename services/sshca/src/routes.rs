//! REST surface for the SSH CA service, mounted under `/api/v1/ssh`.
//!
//! The v1 sshca container ran a `skauswatch.services.sshca.main:app` module
//! that was not preserved in the repo (only the `AsyncSSHProcessor` engine
//! remains), so the concrete paths here are reconstructed from the engine's
//! operations and the canonical SSH REST shape in the v1 pki
//! `api/v1/ssh.py`. The parity-critical piece — the certificate template — is
//! ported faithfully; see `ca.rs` and `docs/v2-port/sshca-contract.md`.
//!
//! AUTH (hardened, finding #2): `docs/v2-port/sshca-contract.md` originally
//! documented this as intentionally unauthenticated ("cluster-internal,
//! reached by the manager/pki plane"), but a security audit determined that
//! posture is unacceptable for a service holding an SSH CA signing key —
//! anyone who can reach the pod can mint host/user SSH certificates. Every
//! route now requires `Authorization: Bearer <jwt>` (HS256, shared
//! `JWT_SECRET_KEY`), enforced as a router-wide layer via
//! `skauswatch_auth::AuthenticatedCaller`. No in-repo caller exists today
//! (confirmed by repo-wide grep for `sshca`/`SSHCA_URL`) — gating
//! introduces no breakage; a future caller must present a machine JWT minted
//! with `skauswatch_auth::issue_service_token`.

pub(crate) mod openapi;

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use penguin_licensing::LicenseClient;

use crate::ca::{SignError, SignParams, SshCa};
use crate::error::ApiJson;
use crate::error::{ApiError, ErrorResponse, ValidationErrorResponse};
use crate::model::{
    CaPublicKeyResponse, CertificateListResponse, CertificateRecord, CertificateType,
    DEFAULT_VALIDITY_SECONDS, IssueCertificateRequest, IssueCertificateResponse, KrlResponse,
    RevokeCertificateRequest, RevokeCertificateResponse,
};
use crate::store::{CertStore, StoredCert};
use crate::tenant::TenantId;

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
    /// License entitlement + PostHog flag client (fail-safe) — gates the
    /// live `/api/v1/ssh/openapi.json` route (see `openapi::OPENAPI_FLAG`).
    /// Not otherwise consulted: certificate issuance itself is unlicensed.
    pub license: Arc<LicenseClient>,
}

impl skauswatch_auth::JwtSecretSource for AppState {
    fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }
}

/// PostHog flag gating certificate *issuance* — default OFF until
/// validated (see `general.md` Feature Toggling & License Enforcement).
/// Independent of `openapi::OPENAPI_FLAG`. Read/list/revoke routes on the
/// same `/api/v1/ssh/certificates` path are unaffected by this flag.
pub const ISSUANCE_FLAG: &str = "skauswatch.sshca";

/// Builds the `/api/v1/ssh` router. Every route requires a valid bearer
/// token (finding #2) — enforced as a single router-wide layer so no
/// individual handler can accidentally be added without the gate.
///
/// `POST /api/v1/ssh/certificates` (issuance) is split into its own
/// sub-router so `ISSUANCE_FLAG` can gate it without affecting
/// `GET /api/v1/ssh/certificates` (list) on the same path — `Router::merge`
/// combines method routers registered for the same path across two
/// routers. The flag layer is applied to `issuance` before it merges, so it
/// sits *innermost* relative to the outer `AuthenticatedCaller` layer:
/// auth runs first, then the flag check.
pub fn router(state: AppState) -> Router {
    let issuance = Router::new()
        .route("/api/v1/ssh/certificates", post(issue_certificate))
        .layer(axum::middleware::from_fn_with_state(
            penguin_licensing::axum::FlagGate::new(state.license.clone(), ISSUANCE_FLAG),
            penguin_licensing::axum::flag_gate,
        ));

    Router::new()
        .route("/api/v1/ssh/certificates", get(list_certificates))
        .route("/api/v1/ssh/certificates/{id}", get(get_certificate))
        .route(
            "/api/v1/ssh/certificates/{id}/revoke",
            post(revoke_certificate),
        )
        .route("/api/v1/ssh/krl", get(get_krl))
        .route("/api/v1/ssh/ca/public-key", get(get_ca_public_key))
        .merge(issuance)
        // Merged *before* the auth layer below so the router-wide
        // AuthenticatedCaller layer covers this route the same as every
        // other one (see openapi.rs module docs and
        // docs/v2-port/openapi-pattern.md's "router-wide auth" row).
        .merge(openapi::router())
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
#[utoipa::path(
    post,
    path = "/api/v1/ssh/certificates",
    tag = "sshca",
    security(("bearer_jwt" = [])),
    request_body = IssueCertificateRequest,
    responses(
        (status = 201, description = "Certificate issued", body = IssueCertificateResponse),
        (status = 400, description = "Empty public key, non-positive validity_duration, or an unparseable subject key", body = ErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn issue_certificate(
    State(state): State<AppState>,
    TenantId(tenant): TenantId,
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
        tenant_id: tenant,
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
#[derive(serde::Deserialize, utoipa::IntoParams)]
pub(crate) struct ListQuery {
    /// Filter by certificate type (`user`/`host`) — utoipa derives the
    /// `type` query param name from the `#[serde(rename)]` below.
    #[serde(rename = "type")]
    certificate_type: Option<CertificateType>,
    /// Filter by status (`active`/`revoked`/`expired`).
    status: Option<String>,
    /// Maximum results to return (clamped to 1..=1000, default 100).
    #[serde(default)]
    limit: Option<usize>,
}

/// `GET /api/v1/ssh/certificates` — list certificates with filters.
#[utoipa::path(
    get,
    path = "/api/v1/ssh/certificates",
    tag = "sshca",
    security(("bearer_jwt" = [])),
    params(ListQuery),
    responses(
        (status = 200, description = "Matching certificates", body = CertificateListResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn list_certificates(
    State(state): State<AppState>,
    TenantId(tenant): TenantId,
    Query(q): Query<ListQuery>,
) -> Result<Response, ApiError> {
    let limit = q.limit.unwrap_or(100).clamp(1, 1000);
    let certs = state
        .store
        .list(tenant, q.certificate_type, q.status.as_deref(), limit);
    let items: Vec<serde_json::Value> = certs.iter().map(stored_to_json).collect();
    let total = items.len();
    Ok(Json(serde_json::json!({ "certificates": items, "total": total })).into_response())
}

/// `GET /api/v1/ssh/certificates/{id}` — fetch one certificate.
#[utoipa::path(
    get,
    path = "/api/v1/ssh/certificates/{id}",
    tag = "sshca",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Certificate id")),
    responses(
        (status = 200, description = "Certificate record", body = CertificateRecord),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Certificate not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_certificate(
    State(state): State<AppState>,
    TenantId(tenant): TenantId,
    Path(id): Path<String>,
) -> Result<Response, ApiError> {
    match state.store.get(&id, tenant) {
        Some(c) => Ok(Json(stored_to_json(&c)).into_response()),
        None => Err(ApiError::NotFound("Certificate not found".to_owned())),
    }
}

/// `POST /api/v1/ssh/certificates/{id}/revoke` — revoke a certificate.
#[utoipa::path(
    post,
    path = "/api/v1/ssh/certificates/{id}/revoke",
    tag = "sshca",
    security(("bearer_jwt" = [])),
    params(("id" = String, Path, description = "Certificate id")),
    request_body = RevokeCertificateRequest,
    responses(
        (status = 200, description = "Certificate revoked", body = RevokeCertificateResponse),
        (status = 400, description = "Malformed request body", body = ValidationErrorResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
        (status = 404, description = "Certificate not found", body = ErrorResponse),
    ),
)]
pub(crate) async fn revoke_certificate(
    State(state): State<AppState>,
    TenantId(tenant): TenantId,
    Path(id): Path<String>,
    ApiJson(req): ApiJson<RevokeCertificateRequest>,
) -> Result<Response, ApiError> {
    let reason = req.reason.unwrap_or_else(|| "unspecified".to_owned());
    if state
        .store
        .revoke(&id, tenant, &reason, Utc::now().naive_utc())
    {
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
#[utoipa::path(
    get,
    path = "/api/v1/ssh/krl",
    tag = "sshca",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "Current Key Revocation List", body = KrlResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_krl(
    State(state): State<AppState>,
    TenantId(tenant): TenantId,
) -> Result<Response, ApiError> {
    let revoked: Vec<serde_json::Value> = state
        .store
        .krl_entries(tenant)
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
#[utoipa::path(
    get,
    path = "/api/v1/ssh/ca/public-key",
    tag = "sshca",
    security(("bearer_jwt" = [])),
    responses(
        (status = 200, description = "CA public key and fingerprint (JSON by default; plain OpenSSH key line when the caller sends `Accept: text/plain`)", body = CaPublicKeyResponse),
        (status = 401, description = "Missing or invalid authorization header", body = ErrorResponse),
    ),
)]
pub(crate) async fn get_ca_public_key(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
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

    /// Dev-mode license client (flags default enabled) — none of the
    /// business routes in this file consult it; only `openapi.rs`'s own
    /// tests exercise the flag-gated path (see that module's `dev_license`/
    /// `gated_license` helpers).
    fn dev_license() -> Arc<penguin_licensing::LicenseClient> {
        let cfg = match penguin_licensing::LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        match penguin_licensing::LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    fn test_state() -> AppState {
        // Missing path → ephemeral CA key (fine for tests).
        let ca = SshCa::load_or_generate(Path::new("/nonexistent-skauswatch-sshca-key"))
            .expect("ephemeral ca");
        AppState {
            ca: Arc::new(ca),
            store: Arc::new(CertStore::new()),
            jwt_secret: TEST_JWT_SECRET.into(),
            license: dev_license(),
        }
    }

    /// `Authorization` header value with a valid bearer token signed with
    /// `TEST_JWT_SECRET`, matching `test_state()`.
    fn auth_header() -> (&'static str, String) {
        let token = skauswatch_auth::issue_service_token("tester", "admin", TEST_JWT_SECRET, 300)
            .expect("issue test token");
        ("Authorization", format!("Bearer {token}"))
    }

    /// `X-Tenant-ID` header value with a fresh tenant — pair with
    /// [`auth_header`] for every request that touches a tenant-scoped
    /// handler (everything except `get_ca_public_key`).
    fn tenant_header() -> (&'static str, String) {
        (
            crate::tenant::TENANT_HEADER,
            uuid::Uuid::new_v4().to_string(),
        )
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
        let (thdr, tval) = tenant_header();
        let body = serde_json::json!({
            "certificate_type": "user",
            "public_key": subject_pub_line(),
            "principals": ["alice", "bob"],
            "validity_duration": 3600,
        });

        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val.clone())
            .add_header(thdr, tval.clone())
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
            .add_header(thdr, tval.clone())
            .await;
        got.assert_status_ok();
        assert_eq!(got.json::<serde_json::Value>()["status"], "active");

        // List with type filter.
        let list = server
            .get("/api/v1/ssh/certificates")
            .add_header(hdr, val.clone())
            .add_header(thdr, tval.clone())
            .add_query_param("type", "user")
            .await;
        list.assert_status_ok();
        assert_eq!(list.json::<serde_json::Value>()["total"], 1);

        // Revoke.
        let rev = server
            .post(&format!("/api/v1/ssh/certificates/{cert_id}/revoke"))
            .add_header(hdr, val.clone())
            .add_header(thdr, tval.clone())
            .json(&serde_json::json!({ "reason": "keyCompromise" }))
            .await;
        rev.assert_status_ok();

        // KRL reflects the revocation.
        let krl = server
            .get("/api/v1/ssh/krl")
            .add_header(hdr, val.clone())
            .add_header(thdr, tval.clone())
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
        let (thdr, tval) = tenant_header();
        let resp = server
            .get("/api/v1/ssh/certificates/nope")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn missing_public_key_is_400() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let (thdr, tval) = tenant_header();
        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .json(&serde_json::json!({ "certificate_type": "user", "public_key": "" }))
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn zero_validity_duration_is_400() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let (thdr, tval) = tenant_header();
        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .json(&serde_json::json!({
                "certificate_type": "user",
                "public_key": subject_pub_line(),
                "validity_duration": 0,
            }))
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
    }

    /// Regression: issuance without a tenant header must be rejected before
    /// touching the CA or store at all.
    #[tokio::test]
    async fn issue_without_tenant_header_is_403() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .json(&serde_json::json!({
                "certificate_type": "user",
                "public_key": subject_pub_line(),
            }))
            .await;
        resp.assert_status(StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn invalid_subject_key_is_400_via_http() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let (thdr, tval) = tenant_header();
        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .json(&serde_json::json!({
                "certificate_type": "user",
                "public_key": "not-a-real-openssh-key",
            }))
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
        let json: serde_json::Value = resp.json();
        assert!(json["error"].as_str().is_some());
    }

    /// Explicit `extensions` map is used verbatim (not the default
    /// user-cert permit set).
    #[tokio::test]
    async fn explicit_extensions_are_used_verbatim() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let (thdr, tval) = tenant_header();
        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .json(&serde_json::json!({
                "certificate_type": "user",
                "public_key": subject_pub_line(),
                "extensions": {"permit-pty": ""},
            }))
            .await;
        resp.assert_status(StatusCode::CREATED);
        let issued: serde_json::Value = resp.json();
        let signed = issued["signed_certificate"].as_str().expect("signed");
        let cert = ssh_key::Certificate::from_openssh(signed).expect("parse cert");
        assert_eq!(cert.extensions().0.len(), 1);
        assert!(cert.extensions().0.contains_key("permit-pty"));
    }

    /// Host certificates default to no extensions (only user certs get the
    /// default permit set).
    #[tokio::test]
    async fn host_certificate_defaults_to_no_extensions() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let (thdr, tval) = tenant_header();
        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .json(&serde_json::json!({
                "certificate_type": "host",
                "public_key": subject_pub_line(),
                "principals": ["host.example.com"],
            }))
            .await;
        resp.assert_status(StatusCode::CREATED);
        let issued: serde_json::Value = resp.json();
        let signed = issued["signed_certificate"].as_str().expect("signed");
        let cert = ssh_key::Certificate::from_openssh(signed).expect("parse cert");
        assert_eq!(cert.cert_type(), ssh_key::certificate::CertType::Host);
        assert!(cert.extensions().0.is_empty());
    }

    /// `source_address`/`force_command` shorthands map onto the
    /// corresponding OpenSSH critical options (v1 accepted, but dropped
    /// them).
    #[tokio::test]
    async fn source_address_and_force_command_become_critical_options() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let (thdr, tval) = tenant_header();
        let resp = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .json(&serde_json::json!({
                "certificate_type": "user",
                "public_key": subject_pub_line(),
                "source_address": "10.0.0.0/8",
                "force_command": "/usr/bin/true",
            }))
            .await;
        resp.assert_status(StatusCode::CREATED);
        let issued: serde_json::Value = resp.json();
        let signed = issued["signed_certificate"].as_str().expect("signed");
        let cert = ssh_key::Certificate::from_openssh(signed).expect("parse cert");
        assert!(cert.critical_options().0.contains_key("source-address"));
        assert!(cert.critical_options().0.contains_key("force-command"));
    }

    #[tokio::test]
    async fn revoking_unknown_certificate_is_404() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let (thdr, tval) = tenant_header();
        let resp = server
            .post("/api/v1/ssh/certificates/nope/revoke")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .json(&serde_json::json!({ "reason": "keyCompromise" }))
            .await;
        resp.assert_status(StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn ca_public_key_text_plain_via_accept_header() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let resp = server
            .get("/api/v1/ssh/ca/public-key")
            .add_header(hdr, val)
            .add_header("Accept", "text/plain")
            .await;
        resp.assert_status_ok();
        let text = resp.text();
        assert!(text.starts_with("ssh-ed25519") || text.starts_with("ssh-"));
    }

    #[tokio::test]
    async fn list_respects_limit_clamp() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let (thdr, tval) = tenant_header();
        for _ in 0..3 {
            let resp = server
                .post("/api/v1/ssh/certificates")
                .add_header(hdr, val.clone())
                .add_header(thdr, tval.clone())
                .json(&serde_json::json!({
                    "certificate_type": "user",
                    "public_key": subject_pub_line(),
                }))
                .await;
            resp.assert_status(StatusCode::CREATED);
        }
        let list = server
            .get("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .add_query_param("limit", 1)
            .await;
        list.assert_status_ok();
        let json: serde_json::Value = list.json();
        assert_eq!(json["total"], 1);
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

    /// Regression: tenant A's issued certificate must be invisible — not
    /// gettable, not listable, not revocable — to a caller presenting
    /// tenant B's `X-Tenant-ID` header, even with a fully valid bearer
    /// token. This service holds an SSH CA signing key; cross-tenant
    /// visibility here is a severe bug.
    #[tokio::test]
    async fn tenant_b_cannot_get_list_or_revoke_tenant_as_certificate() {
        let server = axum_test::TestServer::new(router(test_state()));
        let (hdr, val) = auth_header();
        let tenant_a = uuid::Uuid::new_v4().to_string();
        let tenant_b = uuid::Uuid::new_v4().to_string();

        let issued = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val.clone())
            .add_header(crate::tenant::TENANT_HEADER, tenant_a.clone())
            .json(&serde_json::json!({
                "certificate_type": "user",
                "public_key": subject_pub_line(),
                "principals": ["alice"],
            }))
            .await;
        issued.assert_status(StatusCode::CREATED);
        let issued: serde_json::Value = issued.json();
        let cert_id = issued["certificate_id"].as_str().expect("cert id");

        server
            .get(&format!("/api/v1/ssh/certificates/{cert_id}"))
            .add_header(hdr, val.clone())
            .add_header(crate::tenant::TENANT_HEADER, tenant_b.clone())
            .await
            .assert_status(StatusCode::NOT_FOUND);

        let list_res = server
            .get("/api/v1/ssh/certificates")
            .add_header(hdr, val.clone())
            .add_header(crate::tenant::TENANT_HEADER, tenant_b.clone())
            .await;
        list_res.assert_status_ok();
        let list_json: serde_json::Value = list_res.json();
        assert_eq!(list_json["total"], 0);

        server
            .post(&format!("/api/v1/ssh/certificates/{cert_id}/revoke"))
            .add_header(hdr, val.clone())
            .add_header(crate::tenant::TENANT_HEADER, tenant_b)
            .json(&serde_json::json!({}))
            .await
            .assert_status(StatusCode::NOT_FOUND);

        let status_res = server
            .get(&format!("/api/v1/ssh/certificates/{cert_id}"))
            .add_header(hdr, val)
            .add_header(crate::tenant::TENANT_HEADER, tenant_a)
            .await;
        status_res.assert_status_ok();
        assert_eq!(status_res.json::<serde_json::Value>()["status"], "active");
    }

    /// `release_mode = true` license client (flags default OFF).
    fn gated_license() -> Arc<penguin_licensing::LicenseClient> {
        let mut cfg = match penguin_licensing::LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        cfg.release_mode = true;
        match penguin_licensing::LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        }
    }

    /// Regression: issuance must be denied while `ISSUANCE_FLAG` evaluates
    /// disabled — read/list/revoke routes on the same path are unaffected.
    #[tokio::test]
    async fn issuance_is_denied_when_the_flag_is_disabled() {
        let ca = SshCa::load_or_generate(Path::new("/nonexistent-skauswatch-sshca-key-2"))
            .expect("ephemeral ca");
        let state = AppState {
            ca: Arc::new(ca),
            store: Arc::new(CertStore::new()),
            jwt_secret: TEST_JWT_SECRET.into(),
            license: gated_license(),
        };
        let server = axum_test::TestServer::new(router(state));
        let (hdr, val) = auth_header();
        let (thdr, tval) = tenant_header();

        let issue_res = server
            .post("/api/v1/ssh/certificates")
            .add_header(hdr, val.clone())
            .add_header(thdr, tval.clone())
            .json(&serde_json::json!({
                "certificate_type": "user",
                "public_key": subject_pub_line(),
            }))
            .await;
        issue_res.assert_status(StatusCode::FORBIDDEN);
        let body: serde_json::Value = issue_res.json();
        assert_eq!(body["error"], "feature_disabled");
        assert_eq!(body["flag"], super::ISSUANCE_FLAG);

        // Read route on the same path is unaffected by the flag.
        let list_res = server
            .get("/api/v1/ssh/certificates")
            .add_header(hdr, val)
            .add_header(thdr, tval)
            .await;
        list_res.assert_status_ok();
    }
}
