//! Request DTOs + validation mirroring the v1 pydantic models
//! (`validators/pydantic_models.py`). Responses are built as `serde_json`
//! values in the handlers to match v1's `jsonify(dict)` shapes exactly.
//!
//! Per the port contract, validation-error `details` are simplified
//! `{loc, msg, type}` entries (same 400 envelope; payload not byte-identical).

use serde::Deserialize;

use crate::ca::x509::X509IssueParams;

/// Builds one simplified validation detail entry.
fn detail(loc: &str, msg: &str) -> serde_json::Value {
    serde_json::json!({ "loc": [loc], "msg": msg, "type": "value_error" })
}

fn default_key_algorithm() -> String {
    "RSA".into()
}
fn default_key_size() -> i64 {
    4096
}
fn default_validity_days() -> i64 {
    365
}
fn default_true() -> bool {
    true
}
fn default_ssh_type() -> String {
    "user".into()
}
fn default_validity_seconds() -> i64 {
    86_400
}
fn default_port() -> i64 {
    22
}

/// X.509 certificate issuance request (v1 `X509CertificateRequest`).
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct X509CertificateRequest {
    /// Subject DN string.
    pub subject: String,
    /// Key algorithm (`RSA`/`ECDSA`/`ED25519`).
    #[serde(default = "default_key_algorithm")]
    pub key_algorithm: String,
    /// Key size in bits.
    #[serde(default = "default_key_size")]
    pub key_size: i64,
    /// Validity in days.
    #[serde(default = "default_validity_days")]
    pub validity_days: i64,
    /// SubjectAltName DNS entries.
    #[serde(default)]
    pub san_dns: Vec<String>,
    /// SubjectAltName IP entries.
    #[serde(default)]
    pub san_ip: Vec<String>,
    /// SubjectAltName email entries.
    #[serde(default)]
    pub san_email: Vec<String>,
    /// KeyUsage names (empty → CA engine default).
    #[serde(default)]
    pub key_usage: Vec<String>,
    /// ExtendedKeyUsage names (empty → CA engine default).
    #[serde(default)]
    pub extended_key_usage: Vec<String>,
    /// Issue as CA.
    #[serde(default)]
    pub is_ca: bool,
    /// pathLenConstraint for CA certs.
    #[serde(default)]
    pub path_length: Option<i64>,
    /// PEM CSR (public key taken from it; no private key generated).
    #[serde(default)]
    pub csr_pem: Option<String>,
    /// Present for wire compat; issuance path decided by `csr_pem`.
    #[serde(default = "default_true")]
    pub generate_key: bool,
}

impl X509CertificateRequest {
    /// Validates the request (v1 field constraints + model validators),
    /// returning simplified detail entries on failure.
    pub fn validate(&self) -> Result<(), Vec<serde_json::Value>> {
        let mut errs = Vec::new();
        if self.subject.is_empty() || self.subject.len() > 512 {
            errs.push(detail("subject", "length must be 1..512"));
        }
        let alg = self.key_algorithm.to_uppercase();
        if !matches!(alg.as_str(), "RSA" | "ECDSA" | "ED25519") {
            errs.push(detail("key_algorithm", "must be RSA, ECDSA or ED25519"));
        }
        if self.key_size < 2048 || self.key_size > 8192 {
            errs.push(detail("key_size", "must be 2048..8192"));
        }
        if self.validity_days < 1 || self.validity_days > 825 {
            errs.push(detail("validity_days", "must be 1..825"));
        }
        if self.san_dns.len() > 50 {
            errs.push(detail("san_dns", "at most 50 entries"));
        }
        if self.san_ip.len() > 20 {
            errs.push(detail("san_ip", "at most 20 entries"));
        }
        if self.san_email.len() > 10 {
            errs.push(detail("san_email", "at most 10 entries"));
        }
        if let Some(pl) = self.path_length {
            if !(0..=10).contains(&pl) {
                errs.push(detail("path_length", "must be 0..10"));
            }
            // v1 model_validator: path_length only valid for CA certificates.
            if !self.is_ca {
                errs.push(detail(
                    "path_length",
                    "path_length only valid for CA certificates",
                ));
            }
        }
        for d in &self.san_dns {
            if !valid_dns(d) {
                errs.push(detail("san_dns", &format!("Invalid DNS name: {d}")));
            }
        }
        for ip in &self.san_ip {
            if ip.parse::<std::net::IpAddr>().is_err() {
                errs.push(detail("san_ip", &format!("Invalid IP address: {ip}")));
            }
        }
        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }

    /// Converts to CA engine params, applying the v1 model validator that
    /// appends `key_cert_sign` to KeyUsage for CA certificates.
    pub fn into_issue_params(self) -> X509IssueParams {
        let mut key_usage = self.key_usage;
        if self.is_ca && !key_usage.iter().any(|k| k == "key_cert_sign") {
            key_usage.push("key_cert_sign".into());
        }
        X509IssueParams {
            subject: self.subject,
            key_algorithm: self.key_algorithm,
            key_size: self.key_size,
            validity_days: self.validity_days,
            san_dns: self.san_dns,
            san_ip: self.san_ip,
            san_email: self.san_email,
            key_usage,
            extended_key_usage: self.extended_key_usage,
            is_ca: self.is_ca,
            path_length: self.path_length,
            csr_pem: self.csr_pem,
        }
    }
}

fn valid_dns(d: &str) -> bool {
    // Mirrors v1's DNS SAN regex intent: optional wildcard, labels, TLD.
    if d.is_empty() || d.len() > 253 {
        return false;
    }
    let body = d.strip_prefix("*.").unwrap_or(d);
    if !body.contains('.') {
        return false;
    }
    body.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

/// SSH certificate issuance request (v1 `SSHCertificateRequest`).
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct SshCertificateRequest {
    /// Subject SSH public key line.
    pub public_key: String,
    /// `user` or `host`.
    #[serde(default = "default_ssh_type")]
    pub certificate_type: String,
    /// Key identifier.
    pub key_id: String,
    /// Certificate principals.
    pub principals: Vec<String>,
    /// Validity in seconds.
    #[serde(default = "default_validity_seconds")]
    pub validity_seconds: i64,
    /// Extensions (defaulted to the v1 permit-* set when omitted).
    #[serde(default)]
    pub extensions: Option<std::collections::BTreeMap<String, String>>,
    /// Critical options.
    #[serde(default)]
    pub critical_options: Option<std::collections::BTreeMap<String, String>>,
    /// Allowed source addresses.
    #[serde(default)]
    pub source_addresses: Vec<String>,
    /// Forced command.
    #[serde(default)]
    pub force_command: Option<String>,
    /// Hostname (required for host certs).
    #[serde(default)]
    pub hostname: Option<String>,
}

impl SshCertificateRequest {
    /// Validates the request (v1 field constraints + host-cert validator).
    pub fn validate(&self) -> Result<(), Vec<serde_json::Value>> {
        let mut errs = Vec::new();
        if self.public_key.len() < 50
            || !(self.public_key.starts_with("ssh-rsa")
                || self.public_key.starts_with("ssh-ed25519")
                || self.public_key.starts_with("ecdsa-sha2"))
        {
            errs.push(detail("public_key", "Invalid SSH public key format"));
        }
        if self.key_id.is_empty() || self.key_id.len() > 256 {
            errs.push(detail("key_id", "length must be 1..256"));
        }
        if self.principals.is_empty() || self.principals.len() > 50 {
            errs.push(detail("principals", "1..50 principals required"));
        }
        for p in &self.principals {
            if p.is_empty()
                || !p
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            {
                errs.push(detail("principals", &format!("Invalid principal: {p}")));
            }
        }
        if self.validity_seconds < 60 || self.validity_seconds > 604_800 {
            errs.push(detail("validity_seconds", "must be 60..604800"));
        }
        if !matches!(self.certificate_type.as_str(), "user" | "host") {
            errs.push(detail("certificate_type", "must be user or host"));
        }
        if self.certificate_type == "host" && self.hostname.as_deref().unwrap_or("").is_empty() {
            errs.push(detail(
                "hostname",
                "hostname required for host certificates",
            ));
        }
        if errs.is_empty() { Ok(()) } else { Err(errs) }
    }
}

/// Certificate revocation request (v1 `RevokeRequest`).
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct RevokeRequest {
    /// Revocation reason name (default `unspecified`).
    #[serde(default = "default_reason")]
    pub reason: String,
    /// Optional invalidity date.
    #[serde(default)]
    pub invalidity_date: Option<String>,
}

fn default_reason() -> String {
    "unspecified".into()
}

/// SSH client config generation request (v1 `SSHConfigRequest`).
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct SshConfigRequest {
    /// Target hostname.
    pub hostname: String,
    /// Target port (default 22).
    #[serde(default = "default_port")]
    pub port: i64,
    /// Optional login user.
    #[serde(default)]
    pub user: Option<String>,
    /// Optional identity file path.
    #[serde(default)]
    pub identity_file: Option<String>,
}

/// authorized_keys generation request (v1 `AuthorizedKeysRequest`).
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct AuthorizedKeysRequest {
    /// Principals to authorize.
    pub principals: Vec<String>,
    /// SSH options.
    #[serde(default)]
    pub options: std::collections::BTreeMap<String, String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn x509_rejects_bad_algorithm_and_range() {
        let req = X509CertificateRequest {
            subject: "CN=x".into(),
            key_algorithm: "DSA".into(),
            key_size: 1024,
            validity_days: 900,
            san_dns: vec![],
            san_ip: vec![],
            san_email: vec![],
            key_usage: vec![],
            extended_key_usage: vec![],
            is_ca: false,
            path_length: Some(1),
            csr_pem: None,
            generate_key: true,
        };
        let errors = req.validate();
        assert!(errors.is_err());
        if let Err(errs) = errors {
            // bad algorithm + key_size + validity_days + path_length-not-CA.
            assert!(errs.len() >= 4);
        }
    }

    #[test]
    fn x509_ca_appends_key_cert_sign() {
        let req = X509CertificateRequest {
            subject: "CN=ca".into(),
            key_algorithm: "RSA".into(),
            key_size: 4096,
            validity_days: 365,
            san_dns: vec![],
            san_ip: vec![],
            san_email: vec![],
            key_usage: vec!["crl_sign".into()],
            extended_key_usage: vec![],
            is_ca: true,
            path_length: Some(0),
            csr_pem: None,
            generate_key: true,
        };
        let params = req.into_issue_params();
        assert!(params.key_usage.contains(&"key_cert_sign".to_string()));
    }

    #[test]
    fn ssh_host_requires_hostname() {
        let req = SshCertificateRequest {
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij".into(),
            certificate_type: "host".into(),
            key_id: "h1".into(),
            principals: vec!["host.example.com".into()],
            validity_seconds: 3600,
            extensions: None,
            critical_options: None,
            source_addresses: vec![],
            force_command: None,
            hostname: None,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn valid_dns_accepts_wildcard_and_rejects_bare() {
        assert!(valid_dns("*.example.com"));
        assert!(valid_dns("www.example.com"));
        assert!(!valid_dns("localhost"));
        assert!(!valid_dns("-bad.example.com"));
    }

    #[test]
    fn valid_dns_rejects_empty_and_overlong_names() {
        assert!(!valid_dns(""));
        assert!(!valid_dns(&"a.".repeat(130))); // > 253 chars
    }

    fn base_x509_req() -> X509CertificateRequest {
        X509CertificateRequest {
            subject: "CN=x".into(),
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
            generate_key: true,
        }
    }

    #[test]
    fn x509_rejects_too_many_san_entries() {
        let mut req = base_x509_req();
        req.san_dns = (0..51).map(|i| format!("h{i}.example.com")).collect();
        req.san_ip = (0..21).map(|i| format!("10.0.0.{}", i % 255)).collect();
        req.san_email = (0..11).map(|i| format!("u{i}@example.com")).collect();
        let errs = req.validate().unwrap_err();
        let msgs: Vec<String> = errs
            .iter()
            .map(|e| e["msg"].as_str().unwrap().to_owned())
            .collect();
        assert!(msgs.iter().any(|m| m.contains("50 entries")));
        assert!(msgs.iter().any(|m| m.contains("20 entries")));
        assert!(msgs.iter().any(|m| m.contains("10 entries")));
    }

    #[test]
    fn x509_rejects_invalid_dns_san_entry() {
        let mut req = base_x509_req();
        req.san_dns = vec!["not a dns name".into()];
        let errs = req.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| { e["msg"].as_str().unwrap().contains("Invalid DNS name") })
        );
    }

    #[test]
    fn x509_rejects_path_length_out_of_range() {
        let mut req = base_x509_req();
        req.is_ca = true;
        req.path_length = Some(15);
        let errs = req.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e["msg"].as_str().unwrap().contains("0..10"))
        );
    }

    fn base_ssh_req() -> SshCertificateRequest {
        SshCertificateRequest {
            public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabcdefghij".into(),
            certificate_type: "user".into(),
            key_id: "k1".into(),
            principals: vec!["alice".into()],
            validity_seconds: 3600,
            extensions: None,
            critical_options: None,
            source_addresses: vec![],
            force_command: None,
            hostname: None,
        }
    }

    #[test]
    fn ssh_accepts_ecdsa_public_key_format() {
        let mut req = base_ssh_req();
        req.public_key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY".into();
        // Long enough (>=50 chars) and matches the ecdsa-sha2 prefix branch.
        assert!(req.public_key.len() >= 50);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn ssh_rejects_empty_key_id() {
        let mut req = base_ssh_req();
        req.key_id = String::new();
        let errs = req.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e["msg"].as_str().unwrap().contains("1..256"))
        );
    }

    #[test]
    fn ssh_rejects_invalid_principal_characters() {
        let mut req = base_ssh_req();
        req.principals = vec!["bad principal!".into()];
        let errs = req.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| { e["msg"].as_str().unwrap().contains("Invalid principal") })
        );
    }

    #[test]
    fn ssh_rejects_validity_seconds_out_of_range() {
        let mut req = base_ssh_req();
        req.validity_seconds = 30;
        let errs = req.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e["msg"].as_str().unwrap().contains("60..604800"))
        );
    }

    #[test]
    fn ssh_rejects_unknown_certificate_type() {
        let mut req = base_ssh_req();
        req.certificate_type = "bogus".into();
        let errs = req.validate().unwrap_err();
        assert!(
            errs.iter()
                .any(|e| { e["msg"].as_str().unwrap().contains("must be user or host") })
        );
    }
}
