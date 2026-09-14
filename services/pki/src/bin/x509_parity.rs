//! X.509 parity harness: issues one certificate with the v2 Rust engine from a
//! JSON spec so its `openssl x509 -text` output can be diffed field-by-field
//! against the v1 Python service. Dev/verification tool only.

use std::path::PathBuf;

use serde::Deserialize;
use skauswatch_pki::ca::x509::{X509Ca, X509IssueParams};
use skauswatch_pki::config::X509CaConfig;

#[derive(Deserialize)]
struct Spec {
    ca_key: PathBuf,
    ca_cert: PathBuf,
    out: PathBuf,
    subject: String,
    #[serde(default = "rsa")]
    key_algorithm: String,
    #[serde(default = "k4096")]
    key_size: i64,
    #[serde(default = "d365")]
    validity_days: i64,
    #[serde(default)]
    san_dns: Vec<String>,
    #[serde(default)]
    san_ip: Vec<String>,
    #[serde(default)]
    san_email: Vec<String>,
    #[serde(default)]
    key_usage: Vec<String>,
    #[serde(default)]
    extended_key_usage: Vec<String>,
    #[serde(default)]
    is_ca: bool,
    #[serde(default)]
    path_length: Option<i64>,
    #[serde(default)]
    csr_pem_path: Option<PathBuf>,
}

fn rsa() -> String {
    "RSA".into()
}
fn k4096() -> i64 {
    4096
}
fn d365() -> i64 {
    365
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let spec_path = std::env::args()
        .nth(1)
        .ok_or("usage: x509_parity <spec.json>")?;
    let spec: Spec = serde_json::from_str(&std::fs::read_to_string(&spec_path)?)?;

    let ca_key = std::fs::read_to_string(&spec.ca_key)?;
    let ca_cert = std::fs::read_to_string(&spec.ca_cert)?;
    let csr_pem = match &spec.csr_pem_path {
        Some(p) => Some(std::fs::read_to_string(p)?),
        None => None,
    };

    let ca = X509Ca::from_pem(X509CaConfig::from_env(), ca_key, ca_cert)
        .map_err(|e| format!("load CA: {e}"))?;

    let issued = ca
        .issue(&X509IssueParams {
            subject: spec.subject,
            key_algorithm: spec.key_algorithm,
            key_size: spec.key_size,
            validity_days: spec.validity_days,
            san_dns: spec.san_dns,
            san_ip: spec.san_ip,
            san_email: spec.san_email,
            key_usage: spec.key_usage,
            extended_key_usage: spec.extended_key_usage,
            is_ca: spec.is_ca,
            path_length: spec.path_length,
            csr_pem,
        })
        .map_err(|e| format!("issue: {e}"))?;

    std::fs::write(&spec.out, issued.certificate_pem)?;
    println!(
        "serial={} subject={} issuer={} not_before={} not_after={} fp={}",
        issued.serial_hex,
        issued.subject,
        issued.issuer,
        issued.not_before,
        issued.not_after,
        issued.fingerprint_sha256
    );
    Ok(())
}
