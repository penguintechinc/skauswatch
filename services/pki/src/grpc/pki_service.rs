//! gRPC `PKIService` implementation (v1 `grpc/server.py`), delegating to the
//! shared `CertManager`. Every request carries `api_version`; unknown values
//! return `UNIMPLEMENTED` per the backend API standard.

use async_trait::async_trait;
use skauswatch_proto::pki::pki_service_server::PkiService;
use skauswatch_proto::pki::{
    CertQuery, CrlResponse, Empty, HealthResponse, KrlResponse, ListCertRequest, RevokeRequest,
    RevokeResponse, RevokedCertEntry, SshCertInfo, SshCertListResponse, SshCertRequest,
    SshCertResponse, SshStatistics, SshcaInfoResponse, StatisticsResponse, StatusResponse,
    X509CertInfo, X509CertListResponse, X509CertRequest, X509CertResponse, X509Statistics,
    X509caInfoResponse, cert_query, revoke_request,
};
use tonic::{Request, Response, Status};

use crate::ca::ssh::SshIssueParams;
use crate::ca::x509::X509IssueParams;
use crate::manager::ManagerError;
use crate::state::AppState;

/// gRPC servicer holding shared app state.
pub struct PkiGrpc {
    state: AppState,
}

impl PkiGrpc {
    /// Builds the servicer over shared state.
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

fn require_v1(api_version: &str) -> Result<(), Status> {
    if skauswatch_proto::is_v1(api_version) {
        Ok(())
    } else {
        Err(Status::unimplemented(format!(
            "api_version {api_version} not supported"
        )))
    }
}

fn map_err(e: ManagerError) -> Status {
    match e {
        ManagerError::X509(crate::ca::x509::X509Error::BadRequest(m))
        | ManagerError::Ssh(crate::ca::ssh::SshError::BadRequest(m)) => Status::invalid_argument(m),
        // Log the real cause server-side; never return sqlx/CA internals
        // (constraint/column names, query context) to the caller.
        other => {
            tracing::error!(error = %other, "pki gRPC internal error");
            Status::internal("Internal Server Error")
        }
    }
}

fn js(v: &serde_json::Value, k: &str) -> String {
    v.get(k)
        .and_then(|x| x.as_str())
        .unwrap_or_default()
        .to_owned()
}
fn ji(v: &serde_json::Value, k: &str) -> i64 {
    v.get(k).and_then(serde_json::Value::as_i64).unwrap_or(0)
}
fn arr(v: &serde_json::Value, k: &str) -> Vec<String> {
    v.get(k)
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
fn opt_str(s: String) -> String {
    s // proto uses empty string for "absent"; nulls already map to "" via js()
}

fn status_to_proto(s: &str) -> i32 {
    match s {
        "active" => 1,
        "revoked" => 2,
        "expired" => 3,
        "pending" => 4,
        _ => 0,
    }
}
fn key_alg_from_proto(i: i32) -> &'static str {
    match i {
        2 => "ECDSA",
        3 => "ED25519",
        _ => "RSA",
    }
}
fn key_alg_to_proto(s: &str) -> i32 {
    match s.to_uppercase().as_str() {
        "RSA" => 1,
        "ECDSA" => 2,
        "ED25519" => 3,
        _ => 0,
    }
}
fn reason_from_proto(i: i32) -> &'static str {
    match i {
        1 => "key_compromise",
        2 => "ca_compromise",
        3 => "affiliation_changed",
        4 => "superseded",
        5 => "cessation_of_operation",
        6 => "certificate_hold",
        7 => "privilege_withdrawn",
        _ => "unspecified",
    }
}
fn key_usage_from_proto(i: i32) -> Option<&'static str> {
    Some(match i {
        1 => "digital_signature",
        2 => "key_encipherment",
        3 => "data_encipherment",
        4 => "key_agreement",
        5 => "key_cert_sign",
        6 => "crl_sign",
        _ => return None,
    })
}
fn eku_from_proto(i: i32) -> Option<&'static str> {
    Some(match i {
        1 => "server_auth",
        2 => "client_auth",
        3 => "code_signing",
        4 => "email_protection",
        5 => "time_stamping",
        6 => "ocsp_signing",
        _ => return None,
    })
}
fn ssh_type_from_proto(i: i32) -> &'static str {
    match i {
        2 => "host",
        _ => "user",
    }
}
fn ssh_type_to_proto(s: &str) -> i32 {
    match s {
        "host" => 2,
        _ => 1,
    }
}

fn query_ids(id: &Option<cert_query::Identifier>) -> (Option<String>, Option<String>) {
    match id {
        Some(cert_query::Identifier::Id(v)) => (Some(v.clone()), None),
        Some(cert_query::Identifier::SerialNumber(v)) => (None, Some(v.clone())),
        None => (None, None),
    }
}
fn revoke_ids(id: &Option<revoke_request::Identifier>) -> (Option<String>, Option<String>) {
    match id {
        Some(revoke_request::Identifier::Id(v)) => (Some(v.clone()), None),
        Some(revoke_request::Identifier::SerialNumber(v)) => (None, Some(v.clone())),
        None => (None, None),
    }
}

fn none_if_empty(s: &str) -> Option<&str> {
    if s.is_empty() { None } else { Some(s) }
}

fn x509_response(d: &serde_json::Value) -> X509CertResponse {
    X509CertResponse {
        id: js(d, "id"),
        serial_number: js(d, "serial_number"),
        subject: js(d, "subject"),
        issuer: js(d, "issuer"),
        not_before: js(d, "not_before"),
        not_after: js(d, "not_after"),
        key_algorithm: key_alg_to_proto(&js(d, "key_algorithm")),
        key_size: ji(d, "key_size") as i32,
        fingerprint_sha256: js(d, "fingerprint_sha256"),
        certificate_pem: js(d, "certificate_pem"),
        private_key_pem: js(d, "private_key_pem"),
        san_dns: arr(d, "san_dns"),
        san_ip: arr(d, "san_ip"),
        status: status_to_proto(&js(d, "status")),
        created_at: js(d, "created_at"),
        ..Default::default()
    }
}

fn ssh_response(d: &serde_json::Value) -> SshCertResponse {
    SshCertResponse {
        id: js(d, "id"),
        serial_number: js(d, "serial_number"),
        key_id: js(d, "key_id"),
        certificate_type: ssh_type_to_proto(&js(d, "certificate_type")),
        principals: arr(d, "principals"),
        valid_after: js(d, "valid_after"),
        valid_before: js(d, "valid_before"),
        key_type: js(d, "key_type"),
        certificate: js(d, "certificate"),
        ca_public_key: js(d, "ca_public_key"),
        extensions: json_str_map(d.get("extensions")),
        critical_options: json_str_map(d.get("critical_options")),
        status: status_to_proto(&js(d, "status")),
        created_at: js(d, "created_at"),
    }
}

fn json_str_map(v: Option<&serde_json::Value>) -> std::collections::HashMap<String, String> {
    v.and_then(|x| x.as_object())
        .map(|o| {
            o.iter()
                .map(|(k, val)| (k.clone(), val.as_str().unwrap_or_default().to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

#[async_trait]
impl PkiService for PkiGrpc {
    async fn issue_x509_certificate(
        &self,
        request: Request<X509CertRequest>,
    ) -> Result<Response<X509CertResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let key_usage: Vec<String> = r
            .key_usage
            .iter()
            .filter_map(|i| key_usage_from_proto(*i).map(str::to_owned))
            .collect();
        let eku: Vec<String> = r
            .extended_key_usage
            .iter()
            .filter_map(|i| eku_from_proto(*i).map(str::to_owned))
            .collect();
        let params = X509IssueParams {
            subject: r.subject,
            key_algorithm: key_alg_from_proto(r.key_algorithm).to_owned(),
            key_size: if r.key_size == 0 {
                4096
            } else {
                r.key_size as i64
            },
            validity_days: if r.validity_days == 0 {
                365
            } else {
                r.validity_days as i64
            },
            san_dns: r.san_dns,
            san_ip: r.san_ip,
            san_email: r.san_email,
            key_usage,
            extended_key_usage: eku,
            is_ca: r.is_ca,
            path_length: if r.is_ca {
                Some(r.path_length as i64)
            } else {
                None
            },
            csr_pem: none_if_empty(&r.csr_pem).map(str::to_owned),
        };
        let d = self
            .state
            .manager
            .issue_x509(params, none_if_empty(&r.requester_id))
            .await
            .map_err(map_err)?;
        Ok(Response::new(x509_response(&d)))
    }

    async fn get_x509_certificate(
        &self,
        request: Request<CertQuery>,
    ) -> Result<Response<X509CertResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let (id, serial) = query_ids(&r.identifier);
        let d = self
            .state
            .manager
            .get_x509(id.as_deref(), serial.as_deref(), true)
            .await
            .map_err(map_err)?
            .ok_or_else(|| Status::not_found("Certificate not found"))?;
        Ok(Response::new(x509_response(&d)))
    }

    async fn revoke_x509_certificate(
        &self,
        request: Request<RevokeRequest>,
    ) -> Result<Response<RevokeResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let (id, serial) = revoke_ids(&r.identifier);
        let ok = self
            .state
            .manager
            .revoke_x509(
                id.as_deref(),
                serial.as_deref(),
                reason_from_proto(r.reason),
                None,
            )
            .await
            .map_err(map_err)?;
        if !ok {
            return Err(Status::not_found("Certificate not found"));
        }
        Ok(Response::new(RevokeResponse {
            success: true,
            message: "Certificate revoked".into(),
            serial_number: opt_str(serial.unwrap_or_default()),
            revoked_at: skauswatch_streams::py_now_isoformat(),
        }))
    }

    async fn get_x509_status(
        &self,
        request: Request<CertQuery>,
    ) -> Result<Response<StatusResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let (id, serial) = query_ids(&r.identifier);
        let d = self
            .state
            .manager
            .get_x509(id.as_deref(), serial.as_deref(), false)
            .await
            .map_err(map_err)?
            .ok_or_else(|| Status::not_found("Certificate not found"))?;
        let na = js(&d, "not_after");
        let is_expired = chrono::NaiveDateTime::parse_from_str(&na, "%Y-%m-%dT%H:%M:%S%.f")
            .map(|t| t < chrono::Utc::now().naive_utc())
            .unwrap_or(false);
        Ok(Response::new(StatusResponse {
            id: js(&d, "id"),
            serial_number: js(&d, "serial_number"),
            status: status_to_proto(&js(&d, "status")),
            is_expired,
            not_before: js(&d, "not_before"),
            not_after: na,
            revoked_at: js(&d, "revoked_at"),
            revocation_reason: js(&d, "revocation_reason"),
        }))
    }

    async fn list_x509_certificates(
        &self,
        request: Request<ListCertRequest>,
    ) -> Result<Response<X509CertListResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let page = if r.page == 0 { 1 } else { r.page as i64 };
        let page_size = if r.page_size == 0 {
            50
        } else {
            r.page_size as i64
        };
        let status = proto_status_name(r.status);
        let (items, total) = self
            .state
            .manager
            .list_x509(status, none_if_empty(&r.subject), None, page, page_size)
            .await
            .map_err(map_err)?;
        let certificates = items
            .iter()
            .map(|d| X509CertInfo {
                id: js(d, "id"),
                serial_number: js(d, "serial_number"),
                subject: js(d, "subject"),
                issuer: js(d, "issuer"),
                not_before: js(d, "not_before"),
                not_after: js(d, "not_after"),
                fingerprint_sha256: js(d, "fingerprint_sha256"),
                status: status_to_proto(&js(d, "status")),
                revoked_at: js(d, "revoked_at"),
                created_at: js(d, "created_at"),
            })
            .collect();
        Ok(Response::new(X509CertListResponse {
            certificates,
            total: total as i32,
            page: page as i32,
            page_size: page_size as i32,
            pages: pages(total, page_size),
        }))
    }

    async fn issue_ssh_certificate(
        &self,
        request: Request<SshCertRequest>,
    ) -> Result<Response<SshCertResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let cert_type = ssh_type_from_proto(r.certificate_type).to_owned();
        let params = SshIssueParams {
            public_key: r.public_key,
            certificate_type: cert_type.clone(),
            key_id: none_if_empty(&r.key_id).map(str::to_owned),
            principals: r.principals,
            validity_seconds: if r.validity_seconds == 0 {
                86_400
            } else {
                r.validity_seconds as i64
            },
            extensions: if cert_type == "host" || r.extensions.is_empty() {
                None
            } else {
                Some(r.extensions.into_iter().collect())
            },
            critical_options: if r.critical_options.is_empty() {
                None
            } else {
                Some(r.critical_options.into_iter().collect())
            },
            source_addresses: r.source_addresses,
            force_command: none_if_empty(&r.force_command).map(str::to_owned),
            hostname: none_if_empty(&r.hostname).map(str::to_owned),
        };
        let d = self
            .state
            .manager
            .issue_ssh(params, none_if_empty(&r.requester_id))
            .await
            .map_err(map_err)?;
        Ok(Response::new(ssh_response(&d)))
    }

    async fn get_ssh_certificate(
        &self,
        request: Request<CertQuery>,
    ) -> Result<Response<SshCertResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let (id, serial) = query_ids(&r.identifier);
        let d = self
            .state
            .manager
            .get_ssh(id.as_deref(), serial.as_deref(), true)
            .await
            .map_err(map_err)?
            .ok_or_else(|| Status::not_found("Certificate not found"))?;
        let mut resp = ssh_response(&d);
        resp.ca_public_key = self.state.manager.ssh.ca_public_key().to_owned();
        Ok(Response::new(resp))
    }

    async fn revoke_ssh_certificate(
        &self,
        request: Request<RevokeRequest>,
    ) -> Result<Response<RevokeResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let (id, serial) = revoke_ids(&r.identifier);
        let ok = self
            .state
            .manager
            .revoke_ssh(
                id.as_deref(),
                serial.as_deref(),
                reason_from_proto(r.reason),
                None,
            )
            .await
            .map_err(map_err)?;
        if !ok {
            return Err(Status::not_found("Certificate not found"));
        }
        Ok(Response::new(RevokeResponse {
            success: true,
            message: "Certificate revoked".into(),
            serial_number: serial.unwrap_or_default(),
            revoked_at: skauswatch_streams::py_now_isoformat(),
        }))
    }

    async fn get_ssh_status(
        &self,
        request: Request<CertQuery>,
    ) -> Result<Response<StatusResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let (id, serial) = query_ids(&r.identifier);
        let d = self
            .state
            .manager
            .get_ssh(id.as_deref(), serial.as_deref(), false)
            .await
            .map_err(map_err)?
            .ok_or_else(|| Status::not_found("Certificate not found"))?;
        let vb = js(&d, "valid_before");
        let is_expired = chrono::NaiveDateTime::parse_from_str(&vb, "%Y-%m-%dT%H:%M:%S%.f")
            .map(|t| t < chrono::Utc::now().naive_utc())
            .unwrap_or(false);
        Ok(Response::new(StatusResponse {
            id: js(&d, "id"),
            serial_number: js(&d, "serial_number"),
            status: status_to_proto(&js(&d, "status")),
            is_expired,
            not_before: js(&d, "valid_after"),
            not_after: vb,
            revoked_at: js(&d, "revoked_at"),
            revocation_reason: js(&d, "revocation_reason"),
        }))
    }

    async fn list_ssh_certificates(
        &self,
        request: Request<ListCertRequest>,
    ) -> Result<Response<SshCertListResponse>, Status> {
        let r = request.into_inner();
        require_v1(&r.api_version)?;
        let page = if r.page == 0 { 1 } else { r.page as i64 };
        let page_size = if r.page_size == 0 {
            50
        } else {
            r.page_size as i64
        };
        let (items, total) = self
            .state
            .manager
            .list_ssh(
                proto_status_name(r.status),
                None,
                none_if_empty(&r.principal),
                page,
                page_size,
            )
            .await
            .map_err(map_err)?;
        let certificates = items
            .iter()
            .map(|d| SshCertInfo {
                id: js(d, "id"),
                serial_number: js(d, "serial_number"),
                key_id: js(d, "key_id"),
                certificate_type: ssh_type_to_proto(&js(d, "certificate_type")),
                principals: arr(d, "principals"),
                valid_after: js(d, "valid_after"),
                valid_before: js(d, "valid_before"),
                key_type: js(d, "key_type"),
                hostname: js(d, "hostname"),
                status: status_to_proto(&js(d, "status")),
                revoked_at: js(d, "revoked_at"),
                created_at: js(d, "created_at"),
            })
            .collect();
        Ok(Response::new(SshCertListResponse {
            certificates,
            total: total as i32,
            page: page as i32,
            page_size: page_size as i32,
            pages: pages(total, page_size),
        }))
    }

    async fn get_crl(&self, request: Request<Empty>) -> Result<Response<CrlResponse>, Status> {
        require_v1(&request.into_inner().api_version)?;
        let d = self
            .state
            .manager
            .generate_x509_crl()
            .await
            .map_err(map_err)?;
        let revoked = d
            .get("revoked_certificates")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .map(|e| RevokedCertEntry {
                        serial_number: js(e, "serial_number"),
                        revoked_at: js(e, "revoked_at"),
                        reason: js(e, "reason"),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Response::new(CrlResponse {
            crl_number: ji(&d, "crl_number") as i32,
            this_update: js(&d, "this_update"),
            next_update: js(&d, "next_update"),
            revoked_certificates: revoked,
            crl_pem: js(&d, "crl_pem"),
        }))
    }

    async fn get_krl(&self, request: Request<Empty>) -> Result<Response<KrlResponse>, Status> {
        use base64::Engine as _;
        require_v1(&request.into_inner().api_version)?;
        let d = self
            .state
            .manager
            .generate_ssh_krl()
            .await
            .map_err(map_err)?;
        let revoked = d
            .get("revoked_keys")
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .map(|e| RevokedCertEntry {
                        serial_number: js(e, "serial_number"),
                        ..Default::default()
                    })
                    .collect()
            })
            .unwrap_or_default();
        let krl_binary = base64::engine::general_purpose::STANDARD
            .decode(js(&d, "krl_binary"))
            .unwrap_or_default();
        Ok(Response::new(KrlResponse {
            version: ji(&d, "version") as i32,
            generated_at: js(&d, "generated_at"),
            revoked_keys: revoked,
            krl_binary,
        }))
    }

    async fn get_x509ca_info(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<X509caInfoResponse>, Status> {
        require_v1(&request.into_inner().api_version)?;
        let info = self.state.manager.x509.info();
        Ok(Response::new(X509caInfoResponse {
            subject: info.subject.clone(),
            issuer: info.issuer.clone(),
            not_before: skauswatch_streams::py_isoformat(info.not_before),
            not_after: skauswatch_streams::py_isoformat(info.not_after),
            fingerprint_sha256: info.fingerprint_sha256.clone(),
            serial_counter: self.state.manager.x509.serial_counter(),
            crl_number: self.state.manager.x509.crl_number() as i32,
            ca_certificate_pem: self.state.manager.x509.ca_certificate_pem().to_owned(),
            ocsp_responder_url: self
                .state
                .x509_config
                .ocsp_responder_url
                .clone()
                .unwrap_or_default(),
            crl_distribution_points: Vec::new(),
        }))
    }

    async fn get_sshca_info(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<SshcaInfoResponse>, Status> {
        require_v1(&request.into_inner().api_version)?;
        Ok(Response::new(SshcaInfoResponse {
            ca_public_key: self.state.manager.ssh.ca_public_key().to_owned(),
            key_type: self.state.manager.ssh.ca_key_type(),
            fingerprint: self.state.manager.ssh.ca_fingerprint().to_owned(),
            serial_counter: self.state.manager.ssh.serial_counter(),
            krl_version: self.state.manager.ssh.krl_version() as i32,
        }))
    }

    async fn health_check(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<HealthResponse>, Status> {
        let mut components = std::collections::HashMap::new();
        components.insert("x509_ca".to_owned(), true);
        components.insert("sshca".to_owned(), true);
        components.insert(
            "database".to_owned(),
            sqlx::query("SELECT 1")
                .execute(self.state.manager.db())
                .await
                .is_ok(),
        );
        Ok(Response::new(HealthResponse {
            healthy: true,
            version: env!("CARGO_PKG_VERSION").to_owned(),
            timestamp: skauswatch_streams::py_now_isoformat(),
            components,
        }))
    }

    async fn get_statistics(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<StatisticsResponse>, Status> {
        require_v1(&request.into_inner().api_version)?;
        let d = self.state.manager.statistics().await.map_err(map_err)?;
        let x = d.get("x509").cloned().unwrap_or_default();
        let s = d.get("ssh").cloned().unwrap_or_default();
        Ok(Response::new(StatisticsResponse {
            x509: Some(X509Statistics {
                total: ji(&x, "total") as i32,
                active: ji(&x, "active") as i32,
                revoked: ji(&x, "revoked") as i32,
                expired: ji(&x, "expired") as i32,
                expiring_soon: ji(&x, "expiring_soon") as i32,
            }),
            ssh: Some(SshStatistics {
                total: ji(&s, "total") as i32,
                active: ji(&s, "active") as i32,
                revoked: ji(&s, "revoked") as i32,
            }),
            timestamp: js(&d, "timestamp"),
        }))
    }
}

fn pages(total: i64, page_size: i64) -> i32 {
    if page_size > 0 {
        ((total + page_size - 1) / page_size) as i32
    } else {
        0
    }
}

/// Maps a proto `CertificateStatus` enum value to the DB status name, or
/// `None` for `STATUS_UNSPECIFIED` (no filter), matching v1.
fn proto_status_name(i: i32) -> Option<&'static str> {
    match i {
        1 => Some("active"),
        2 => Some("revoked"),
        3 => Some("expired"),
        4 => Some("pending"),
        _ => None,
    }
}

/// Tests for the gRPC servicer. Pure mapping helpers (enum <-> proto, JSON
/// dict accessors, response builders) are unit-tested directly — no gRPC
/// call needed. RPC-level tests cover: the `api_version` gate on every
/// method, the fully-DB-free `not_found`/`invalid_argument` branches (an
/// unusable identifier resolves to `Ok(None)`/`Ok(false)` in the manager
/// without a query, or the SSH CA engine itself rejects empty principals),
/// and the real-crypto-then-`internal`-on-unreachable-DB path. See
/// `docs/v2-port/testing-pattern.md` — pki has no `migrations/` directory,
/// so "found"/list/CRL/KRL/statistics success bodies are out of scope.
#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use skauswatch_proto::pki::{cert_query, revoke_request};
    use tonic::Code;

    use super::*;
    use crate::state::AppStateInner;

    fn grpc() -> PkiGrpc {
        PkiGrpc::new(AppStateInner::for_tests())
    }

    fn real_ca_grpc() -> PkiGrpc {
        PkiGrpc::new(AppStateInner::for_tests_with_real_ca())
    }

    fn assert_unimplemented(status: Status) {
        assert_eq!(status.code(), Code::Unimplemented);
        assert!(status.message().contains("not supported"));
    }

    // ---------- api_version gate: one test per RPC ----------

    #[tokio::test]
    async fn issue_x509_certificate_rejects_unknown_api_version() {
        let status = grpc()
            .issue_x509_certificate(Request::new(X509CertRequest {
                api_version: "v2".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn get_x509_certificate_rejects_unknown_api_version() {
        let status = grpc()
            .get_x509_certificate(Request::new(CertQuery {
                api_version: "v2".into(),
                identifier: None,
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn revoke_x509_certificate_rejects_unknown_api_version() {
        let status = grpc()
            .revoke_x509_certificate(Request::new(RevokeRequest {
                api_version: "v2".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn get_x509_status_rejects_unknown_api_version() {
        let status = grpc()
            .get_x509_status(Request::new(CertQuery {
                api_version: "v2".into(),
                identifier: None,
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn list_x509_certificates_rejects_unknown_api_version() {
        let status = grpc()
            .list_x509_certificates(Request::new(ListCertRequest {
                api_version: "v2".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn issue_ssh_certificate_rejects_unknown_api_version() {
        let status = grpc()
            .issue_ssh_certificate(Request::new(SshCertRequest {
                api_version: "v2".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn get_ssh_certificate_rejects_unknown_api_version() {
        let status = grpc()
            .get_ssh_certificate(Request::new(CertQuery {
                api_version: "v2".into(),
                identifier: None,
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn revoke_ssh_certificate_rejects_unknown_api_version() {
        let status = grpc()
            .revoke_ssh_certificate(Request::new(RevokeRequest {
                api_version: "v2".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn get_ssh_status_rejects_unknown_api_version() {
        let status = grpc()
            .get_ssh_status(Request::new(CertQuery {
                api_version: "v2".into(),
                identifier: None,
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn list_ssh_certificates_rejects_unknown_api_version() {
        let status = grpc()
            .list_ssh_certificates(Request::new(ListCertRequest {
                api_version: "v2".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn get_crl_rejects_unknown_api_version() {
        let status = grpc()
            .get_crl(Request::new(Empty {
                api_version: "v2".into(),
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn get_krl_rejects_unknown_api_version() {
        let status = grpc()
            .get_krl(Request::new(Empty {
                api_version: "v2".into(),
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn get_x509ca_info_rejects_unknown_api_version() {
        let status = grpc()
            .get_x509ca_info(Request::new(Empty {
                api_version: "v2".into(),
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn get_sshca_info_rejects_unknown_api_version() {
        let status = grpc()
            .get_sshca_info(Request::new(Empty {
                api_version: "v2".into(),
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    #[tokio::test]
    async fn get_statistics_rejects_unknown_api_version() {
        let status = grpc()
            .get_statistics(Request::new(Empty {
                api_version: "v2".into(),
            }))
            .await
            .unwrap_err();
        assert_unimplemented(status);
    }

    // ---------- fully DB-free success/error branches ----------

    #[tokio::test]
    async fn get_x509_certificate_not_found_without_db_for_bad_identifier() {
        let svc = grpc();
        for identifier in [None, Some(cert_query::Identifier::Id("not-a-uuid".into()))] {
            let status = svc
                .get_x509_certificate(Request::new(CertQuery {
                    api_version: String::new(),
                    identifier,
                }))
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::NotFound);
        }
    }

    #[tokio::test]
    async fn get_ssh_certificate_not_found_without_db_for_bad_identifier() {
        let status = grpc()
            .get_ssh_certificate(Request::new(CertQuery {
                api_version: "v1".into(),
                identifier: Some(cert_query::Identifier::Id("not-a-uuid".into())),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn get_x509_status_not_found_without_db_for_bad_identifier() {
        let status = grpc()
            .get_x509_status(Request::new(CertQuery {
                api_version: "v1".into(),
                identifier: None,
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn get_ssh_status_not_found_without_db_for_bad_identifier() {
        let status = grpc()
            .get_ssh_status(Request::new(CertQuery {
                api_version: "v1".into(),
                identifier: Some(cert_query::Identifier::Id("bad".into())),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn revoke_x509_certificate_not_found_without_db_for_bad_identifier() {
        let svc = grpc();
        for identifier in [
            None,
            Some(revoke_request::Identifier::Id("not-a-uuid".into())),
        ] {
            let status = svc
                .revoke_x509_certificate(Request::new(RevokeRequest {
                    api_version: "v1".into(),
                    identifier,
                    reason: 0,
                    invalidity_date: String::new(),
                }))
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::NotFound);
        }
    }

    #[tokio::test]
    async fn revoke_ssh_certificate_not_found_without_db_for_bad_identifier() {
        let status = grpc()
            .revoke_ssh_certificate(Request::new(RevokeRequest {
                api_version: "v1".into(),
                identifier: Some(revoke_request::Identifier::Id("bad".into())),
                reason: 0,
                invalidity_date: String::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::NotFound);
    }

    #[tokio::test]
    async fn issue_ssh_certificate_empty_principals_is_invalid_argument() {
        // The SSH CA engine itself rejects this before any DB call — proves
        // map_err's BadRequest -> invalid_argument branch.
        let status = grpc()
            .issue_ssh_certificate(Request::new(SshCertRequest {
                api_version: "v1".into(),
                public_key: "ssh-ed25519 AAAA".into(),
                certificate_type: 1,
                key_id: "k".into(),
                principals: vec![],
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    // ---------- DB-touching handlers: real work, then internal on unreachable DB ----------

    #[tokio::test]
    async fn issue_x509_certificate_runs_real_crypto_then_internal_on_db() {
        let status = grpc()
            .issue_x509_certificate(Request::new(X509CertRequest {
                api_version: "v1".into(),
                subject: "CN=grpc-test.example.com".into(),
                is_ca: false,
                // Non-empty so the key_usage/extended_key_usage
                // filter_map loops actually iterate (proto enum ints, not
                // KU_UNSPECIFIED/EKU_UNSPECIFIED).
                key_usage: vec![1, 2],
                extended_key_usage: vec![1],
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
        assert_eq!(status.message(), "Internal Server Error");
    }

    #[tokio::test]
    async fn issue_x509_certificate_invalid_csr_is_invalid_argument() {
        // Exercises map_err's X509(BadRequest) arm specifically (the SSH
        // arm is covered by issue_ssh_certificate_empty_principals_is_invalid_argument).
        let status = grpc()
            .issue_x509_certificate(Request::new(X509CertRequest {
                api_version: "v1".into(),
                subject: "CN=grpc-badcsr.example.com".into(),
                csr_pem: "not a real csr".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
    }

    #[tokio::test]
    async fn list_x509_certificates_defaults_page_then_internal_on_db() {
        let status = grpc()
            .list_x509_certificates(Request::new(ListCertRequest {
                api_version: "v1".into(),
                page: 0,
                page_size: 0,
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn list_ssh_certificates_internal_on_db() {
        let status = grpc()
            .list_ssh_certificates(Request::new(ListCertRequest {
                api_version: "v1".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn get_crl_internal_on_db() {
        let status = grpc()
            .get_crl(Request::new(Empty {
                api_version: "v1".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn get_krl_internal_on_db() {
        let status = grpc()
            .get_krl(Request::new(Empty {
                api_version: "v1".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    #[tokio::test]
    async fn get_statistics_internal_on_db() {
        let status = grpc()
            .get_statistics(Request::new(Empty {
                api_version: "v1".into(),
            }))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal);
    }

    // ---------- fully DB-free successful RPCs ----------

    #[tokio::test]
    async fn get_x509ca_info_succeeds_without_db() {
        let resp = grpc()
            .get_x509ca_info(Request::new(Empty {
                api_version: String::new(),
            }))
            .await
            .unwrap_or_else(|e| panic!("get_x509ca_info: {e}"))
            .into_inner();
        assert!(resp.subject.contains("SkausWatch"));
        assert!(resp.ca_certificate_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(resp.serial_counter, 1);
    }

    #[tokio::test]
    async fn get_sshca_info_succeeds_without_db() {
        let resp = grpc()
            .get_sshca_info(Request::new(Empty {
                api_version: "v1".into(),
            }))
            .await
            .unwrap_or_else(|e| panic!("get_sshca_info: {e}"))
            .into_inner();
        assert_eq!(resp.key_type, "ed25519");
        assert!(resp.ca_public_key.starts_with("ssh-"));
    }

    #[tokio::test]
    async fn health_check_reports_healthy_true_regardless_of_db_and_ignores_api_version() {
        let resp = grpc()
            .health_check(Request::new(Empty {
                api_version: "totally-unchecked".into(),
            }))
            .await
            .unwrap_or_else(|e| panic!("health_check: {e}"))
            .into_inner();
        assert!(resp.healthy);
        assert_eq!(resp.components.get("database"), Some(&false));
        assert_eq!(resp.components.get("x509_ca"), Some(&true));
    }

    #[tokio::test]
    async fn issue_ssh_certificate_real_ca_signs_then_internal_on_db() {
        // Real ssh-keygen-backed CA + a real subject key -> genuine signing
        // happens before the DB insert fails.
        let path = std::env::temp_dir().join(format!(
            "skauswatch-pki-grpc-subject-{}",
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
        let pubkey = std::fs::read_to_string(format!("{}.pub", path.display()))
            .unwrap_or_else(|e| panic!("read pubkey: {e}"));

        let grpc_status = real_ca_grpc()
            .issue_ssh_certificate(Request::new(SshCertRequest {
                api_version: "v1".into(),
                public_key: pubkey,
                certificate_type: 1,
                key_id: "grpc-test".into(),
                principals: vec!["alice".into()],
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(grpc_status.code(), Code::Internal);
    }

    // ---------- pure mapping / accessor helpers ----------

    #[test]
    fn key_alg_round_trips_and_defaults_to_rsa() {
        assert_eq!(key_alg_from_proto(1), "RSA");
        assert_eq!(key_alg_from_proto(2), "ECDSA");
        assert_eq!(key_alg_from_proto(3), "ED25519");
        assert_eq!(key_alg_from_proto(0), "RSA");
        assert_eq!(key_alg_to_proto("rsa"), 1);
        assert_eq!(key_alg_to_proto("ECDSA"), 2);
        assert_eq!(key_alg_to_proto("ed25519"), 3);
        assert_eq!(key_alg_to_proto("bogus"), 0);
    }

    #[test]
    fn reason_from_proto_covers_all_named_reasons_and_default() {
        assert_eq!(reason_from_proto(1), "key_compromise");
        assert_eq!(reason_from_proto(2), "ca_compromise");
        assert_eq!(reason_from_proto(3), "affiliation_changed");
        assert_eq!(reason_from_proto(4), "superseded");
        assert_eq!(reason_from_proto(5), "cessation_of_operation");
        assert_eq!(reason_from_proto(6), "certificate_hold");
        assert_eq!(reason_from_proto(7), "privilege_withdrawn");
        assert_eq!(reason_from_proto(0), "unspecified");
        assert_eq!(reason_from_proto(99), "unspecified");
    }

    #[test]
    fn key_usage_and_eku_from_proto_cover_all_variants_and_unknown() {
        for i in 1..=6 {
            assert!(key_usage_from_proto(i).is_some());
        }
        assert_eq!(key_usage_from_proto(0), None);
        assert_eq!(key_usage_from_proto(99), None);

        for i in 1..=6 {
            assert!(eku_from_proto(i).is_some());
        }
        assert_eq!(eku_from_proto(0), None);
    }

    #[test]
    fn ssh_type_round_trips() {
        assert_eq!(ssh_type_from_proto(1), "user");
        assert_eq!(ssh_type_from_proto(2), "host");
        assert_eq!(ssh_type_from_proto(0), "user");
        assert_eq!(ssh_type_to_proto("host"), 2);
        assert_eq!(ssh_type_to_proto("user"), 1);
        assert_eq!(ssh_type_to_proto("bogus"), 1);
    }

    #[test]
    fn status_to_proto_covers_all_named_statuses_and_default() {
        assert_eq!(status_to_proto("active"), 1);
        assert_eq!(status_to_proto("revoked"), 2);
        assert_eq!(status_to_proto("expired"), 3);
        assert_eq!(status_to_proto("pending"), 4);
        assert_eq!(status_to_proto("bogus"), 0);
    }

    #[test]
    fn query_ids_and_revoke_ids_map_each_oneof_variant() {
        assert_eq!(
            query_ids(&Some(cert_query::Identifier::Id("x".into()))),
            (Some("x".to_owned()), None)
        );
        assert_eq!(
            query_ids(&Some(cert_query::Identifier::SerialNumber("s".into()))),
            (None, Some("s".to_owned()))
        );
        assert_eq!(query_ids(&None), (None, None));

        assert_eq!(
            revoke_ids(&Some(revoke_request::Identifier::Id("x".into()))),
            (Some("x".to_owned()), None)
        );
        assert_eq!(
            revoke_ids(&Some(revoke_request::Identifier::SerialNumber("s".into()))),
            (None, Some("s".to_owned()))
        );
        assert_eq!(revoke_ids(&None), (None, None));
    }

    #[test]
    fn none_if_empty_and_opt_str_are_pass_through_helpers() {
        assert_eq!(none_if_empty(""), None);
        assert_eq!(none_if_empty("x"), Some("x"));
        assert_eq!(opt_str("y".into()), "y");
    }

    #[test]
    fn js_ji_arr_extract_from_json_with_missing_field_defaults() {
        let v = serde_json::json!({
            "s": "hello",
            "n": 42,
            "a": ["x", "y", 1],
        });
        assert_eq!(js(&v, "s"), "hello");
        assert_eq!(js(&v, "missing"), "");
        assert_eq!(ji(&v, "n"), 42);
        assert_eq!(ji(&v, "missing"), 0);
        assert_eq!(arr(&v, "a"), vec!["x".to_owned(), "y".to_owned()]);
        assert_eq!(arr(&v, "missing"), Vec::<String>::new());
    }

    #[test]
    fn json_str_map_converts_object_and_defaults_on_missing() {
        let v = serde_json::json!({ "k1": "v1", "k2": "v2" });
        let m = json_str_map(Some(&v));
        assert_eq!(m.get("k1"), Some(&"v1".to_owned()));
        assert_eq!(m.len(), 2);
        assert!(json_str_map(None).is_empty());
    }

    #[test]
    fn x509_response_and_ssh_response_map_dict_fields() {
        let d = serde_json::json!({
            "id": "id-1",
            "serial_number": "1a",
            "subject": "CN=x",
            "issuer": "CN=ca",
            "not_before": "2026-01-01T00:00:00",
            "not_after": "2027-01-01T00:00:00",
            "key_algorithm": "ECDSA",
            "key_size": 256,
            "fingerprint_sha256": "abc",
            "certificate_pem": "PEM",
            "private_key_pem": "KEY",
            "san_dns": ["a.example.com"],
            "san_ip": ["10.0.0.1"],
            "status": "revoked",
            "created_at": "2026-01-01T00:00:00",
        });
        let resp = x509_response(&d);
        assert_eq!(resp.key_algorithm, 2);
        assert_eq!(resp.status, 2);
        assert_eq!(resp.san_dns, vec!["a.example.com".to_owned()]);

        let ssh_d = serde_json::json!({
            "id": "id-2",
            "serial_number": "2",
            "key_id": "kid",
            "certificate_type": "host",
            "principals": ["h.example.com"],
            "valid_after": "2026-01-01T00:00:00",
            "valid_before": "2027-01-01T00:00:00",
            "key_type": "ed25519",
            "certificate": "CERT",
            "ca_public_key": "ssh-ed25519 AAAA",
            "extensions": { "e1": "v1" },
            "critical_options": { "c1": "v1" },
            "status": "active",
            "created_at": "2026-01-01T00:00:00",
        });
        let ssh_resp = ssh_response(&ssh_d);
        assert_eq!(ssh_resp.certificate_type, 2);
        assert_eq!(ssh_resp.status, 1);
        assert_eq!(ssh_resp.extensions.get("e1"), Some(&"v1".to_owned()));
    }

    #[test]
    fn pages_rounds_up_and_zero_page_size_is_zero() {
        assert_eq!(pages(0, 50), 0);
        assert_eq!(pages(1, 50), 1);
        assert_eq!(pages(50, 50), 1);
        assert_eq!(pages(51, 50), 2);
        assert_eq!(pages(10, 0), 0);
    }

    #[test]
    fn proto_status_name_covers_all_named_statuses_and_unspecified() {
        assert_eq!(proto_status_name(1), Some("active"));
        assert_eq!(proto_status_name(2), Some("revoked"));
        assert_eq!(proto_status_name(3), Some("expired"));
        assert_eq!(proto_status_name(4), Some("pending"));
        assert_eq!(proto_status_name(0), None);
    }
}
