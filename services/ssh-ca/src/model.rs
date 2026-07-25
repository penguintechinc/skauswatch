//! Request/response DTOs for the SSH CA REST surface.
//!
//! Field names track the v1 `SSHCertificateRequest` dataclass and the dict
//! returned by `_sign_certificate_sync` so existing callers keep working; the
//! parity-critical semantics (type→1/2, `key_id` format, validity duration)
//! are preserved. `source_address`/`force_command` are accepted and now
//! correctly mapped onto the OpenSSH `source-address`/`force-command` critical
//! options (v1 accepted but silently dropped them).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Default certificate validity window in seconds (v1 default `3600`).
pub const DEFAULT_VALIDITY_SECONDS: u64 = 3600;

/// SSH certificate type — user (login) or host certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateType {
    /// User certificate (`ssh-keygen` cert type 1).
    User,
    /// Host certificate (`ssh-keygen` cert type 2).
    Host,
}

impl CertificateType {
    /// Lowercase wire value (`"user"`/`"host"`), matching v1's enum `.value`.
    pub fn as_str(self) -> &'static str {
        match self {
            CertificateType::User => "user",
            CertificateType::Host => "host",
        }
    }
}

/// Body for `POST /api/v1/ssh/certificates`.
#[derive(Debug, Clone, Deserialize)]
pub struct IssueCertificateRequest {
    /// `user` or `host`.
    pub certificate_type: CertificateType,
    /// Subject public key as an OpenSSH line (`ssh-ed25519 AAAA... comment`).
    pub public_key: String,
    /// Certificate principals (usernames for user certs, hostnames for host).
    #[serde(default)]
    pub principals: Vec<String>,
    /// Validity window in seconds (v1 `validity_duration`; `validity_seconds`
    /// accepted as an alias for the pki-server request shape).
    #[serde(default, alias = "validity_seconds")]
    pub validity_duration: Option<u64>,
    /// Certificate extensions (flag values are empty strings, e.g. `permit-pty`).
    #[serde(default)]
    pub extensions: Option<BTreeMap<String, String>>,
    /// Critical options (e.g. `force-command`, `source-address`).
    #[serde(default)]
    pub critical_options: Option<BTreeMap<String, String>>,
    /// Optional `source-address` critical option shorthand.
    #[serde(default)]
    pub source_address: Option<String>,
    /// Optional `force-command` critical option shorthand.
    #[serde(default)]
    pub force_command: Option<String>,
    /// Optional explicit key id; defaults to `{type}-{request_id}` (v1 format).
    #[serde(default)]
    pub key_id: Option<String>,
    /// Optional caller-supplied request id; a UUID is generated when absent.
    #[serde(default)]
    pub request_id: Option<String>,
    /// Optional requester identity (audit only).
    #[serde(default)]
    pub requester_id: Option<String>,
    /// Opaque metadata echoed back on the response (v1 parity).
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Response for a successful certificate issuance (201).
#[derive(Debug, Clone, Serialize)]
pub struct IssueCertificateResponse {
    /// Certificate id (equals the request id).
    pub certificate_id: String,
    /// `user` or `host`.
    pub certificate_type: CertificateType,
    /// Signed OpenSSH certificate line (`ssh-…-cert-v01@openssh.com AAAA…`).
    pub signed_certificate: String,
    /// Certificate serial number.
    pub serial_number: u64,
    /// Effective principals.
    pub principals: Vec<String>,
    /// Certificate key id.
    pub key_id: String,
    /// Valid-after timestamp (Python-isoformat, second precision).
    pub valid_after: String,
    /// Valid-before timestamp (Python-isoformat, second precision).
    pub valid_before: String,
    /// Subject key OpenSSH SHA256 fingerprint (`SHA256:…`).
    pub public_key_fingerprint: String,
    /// CA key OpenSSH SHA256 fingerprint (`SHA256:…`).
    pub ca_fingerprint: String,
    /// Echoed request metadata.
    pub metadata: serde_json::Value,
}

/// Body for `POST /api/v1/ssh/certificates/{id}/revoke`.
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeCertificateRequest {
    /// Human-readable revocation reason (defaults to `unspecified`).
    #[serde(default)]
    pub reason: Option<String>,
}
