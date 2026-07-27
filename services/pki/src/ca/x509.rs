//! X.509 Certificate Authority — byte-parity port of v1's
//! `ca/x509_authority.py` (Python `cryptography`) onto `rcgen` + `x509-parser`.
//!
//! Parity is proven field-by-field against the v1 service (see
//! `docs/v2-port/pki-contract.md`). The certificate template reproduces v1's
//! subject/issuer DN, validity duration, KeyUsage, ExtendedKeyUsage,
//! BasicConstraints, SubjectAltName, SubjectKeyIdentifier (RFC 5280 method 1 —
//! SHA1 of the subjectPublicKey), AuthorityKeyIdentifier, and
//! sha256WithRSAEncryption signature. Serial numbers, exact notBefore/notAfter
//! instants, and signature bytes differ by design (counter/time/nonce).

use std::sync::atomic::{AtomicU64, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
    PublicKeyData, RsaKeySize, SanType, SerialNumber, SigningKey,
};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;
use time::OffsetDateTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer as _;

use crate::config::X509CaConfig;

/// Errors raised by the X.509 CA engine.
#[derive(Debug, thiserror::Error)]
pub enum X509Error {
    /// Caller-supplied input was invalid (bad CSR, DN, algorithm, IP, …).
    #[error("{0}")]
    BadRequest(String),
    /// CA key/cert could not be loaded or an internal crypto op failed.
    #[error("{0}")]
    Internal(String),
}

/// Parameters for issuing one leaf certificate (mirrors v1
/// `issue_certificate` keyword args).
#[derive(Debug, Clone)]
pub struct X509IssueParams {
    /// Subject DN string, e.g. `CN=example.com,O=Example,C=US`.
    pub subject: String,
    /// Key algorithm: `RSA` / `ECDSA` / `ED25519` (used only when no CSR).
    pub key_algorithm: String,
    /// Key size in bits (RSA/ECDSA; ignored for ED25519 and CSR path).
    pub key_size: i64,
    /// Requested validity in days (capped at `max_validity_days`).
    pub validity_days: i64,
    /// SubjectAltName DNS entries.
    pub san_dns: Vec<String>,
    /// SubjectAltName IP entries.
    pub san_ip: Vec<String>,
    /// SubjectAltName email (rfc822Name) entries.
    pub san_email: Vec<String>,
    /// KeyUsage names (v1 vocabulary).
    pub key_usage: Vec<String>,
    /// ExtendedKeyUsage names (v1 vocabulary).
    pub extended_key_usage: Vec<String>,
    /// Issue as a CA certificate (BasicConstraints cA=true).
    pub is_ca: bool,
    /// pathLenConstraint for CA certificates.
    pub path_length: Option<i64>,
    /// PEM CSR — when present the public key is taken from it and no private
    /// key is generated/returned.
    pub csr_pem: Option<String>,
}

/// Result of issuing a certificate — the wire/DB fields v1 returns.
#[derive(Debug, Clone)]
pub struct IssuedX509 {
    /// Issued certificate in PEM.
    pub certificate_pem: String,
    /// Generated private key in PKCS#8 PEM (None on the CSR path).
    pub private_key_pem: Option<String>,
    /// Serial number, lowercase hex (v1 `format(serial, "x")`).
    pub serial_hex: String,
    /// Subject DN, cryptography `rfc4514_string()` form.
    pub subject: String,
    /// Issuer DN, cryptography `rfc4514_string()` form.
    pub issuer: String,
    /// notBefore (naive UTC).
    pub not_before: chrono::NaiveDateTime,
    /// notAfter (naive UTC).
    pub not_after: chrono::NaiveDateTime,
    /// Lowercase hex SHA256 of the certificate DER.
    pub fingerprint_sha256: String,
    /// Echoed key algorithm.
    pub key_algorithm: String,
    /// Key size (None for ED25519, matching v1).
    pub key_size: Option<i64>,
}

/// Static CA metadata parsed once at load (for CA info / issuer DN).
#[derive(Debug, Clone)]
pub struct X509CaInfo {
    /// CA subject DN, rfc4514 form.
    pub subject: String,
    /// CA issuer DN, rfc4514 form (self-signed → equals subject).
    pub issuer: String,
    /// CA notBefore (naive UTC).
    pub not_before: chrono::NaiveDateTime,
    /// CA notAfter (naive UTC).
    pub not_after: chrono::NaiveDateTime,
    /// Lowercase hex SHA256 of the CA certificate DER.
    pub fingerprint_sha256: String,
}

/// X.509 Certificate Authority: holds the loaded CA key/cert and issues
/// leaf certificates + CRLs. Serial and CRL counters mirror v1's in-memory
/// counters (start at 1 / 0 respectively; reset on restart — see the port
/// decision in the contract).
pub struct X509Ca {
    config: X509CaConfig,
    ca_cert_pem: String,
    ca_key_pem: String,
    info: X509CaInfo,
    serial_counter: AtomicU64,
    crl_number: AtomicU64,
}

impl X509Ca {
    /// Loads the CA key + certificate from the configured paths, generating a
    /// fresh self-signed CA (v1 template) when either file is missing.
    pub fn load_or_generate(config: X509CaConfig) -> Result<Self, X509Error> {
        let key_path = std::path::Path::new(&config.ca_key_path);
        let cert_path = std::path::Path::new(&config.ca_cert_path);

        let (ca_key_pem, ca_cert_pem) = if key_path.exists() && cert_path.exists() {
            let key = std::fs::read_to_string(key_path)
                .map_err(|e| X509Error::Internal(format!("read CA key: {e}")))?;
            let cert = std::fs::read_to_string(cert_path)
                .map_err(|e| X509Error::Internal(format!("read CA cert: {e}")))?;
            (key, cert)
        } else {
            tracing::warn!("CA key/cert not found, generating new CA");
            let (key, cert) = generate_ca()?;
            save_ca(&config, &key, &cert)?;
            (key, cert)
        };

        let info = parse_ca_info(&ca_cert_pem)?;
        tracing::info!(subject = %info.subject, "X.509 CA initialized");

        Ok(Self {
            config,
            ca_cert_pem,
            ca_key_pem,
            info,
            serial_counter: AtomicU64::new(1),
            crl_number: AtomicU64::new(0),
        })
    }

    /// Constructs a CA directly from in-memory PEM material (test/parity use).
    pub fn from_pem(
        config: X509CaConfig,
        ca_key_pem: String,
        ca_cert_pem: String,
    ) -> Result<Self, X509Error> {
        let info = parse_ca_info(&ca_cert_pem)?;
        Ok(Self {
            config,
            ca_cert_pem,
            ca_key_pem,
            info,
            serial_counter: AtomicU64::new(1),
            crl_number: AtomicU64::new(0),
        })
    }

    /// CA certificate in PEM (v1 `get_ca_certificate_pem`).
    pub fn ca_certificate_pem(&self) -> &str {
        &self.ca_cert_pem
    }

    /// Static CA metadata.
    pub fn info(&self) -> &X509CaInfo {
        &self.info
    }

    /// Current serial counter value (v1 `get_ca_info` `serial_counter`).
    pub fn serial_counter(&self) -> i64 {
        self.serial_counter.load(Ordering::SeqCst) as i64
    }

    /// Current CRL number (v1 `get_ca_info` `crl_number`).
    pub fn crl_number(&self) -> i64 {
        self.crl_number.load(Ordering::SeqCst) as i64
    }

    /// Issues a leaf certificate reproducing v1's template exactly.
    pub fn issue(&self, params: &X509IssueParams) -> Result<IssuedX509, X509Error> {
        let validity_days = params.validity_days.min(self.config.max_validity_days);

        // Public key source: CSR (no private key returned) or freshly generated.
        let generated = if params.csr_pem.is_none() {
            Some(generate_key(&params.key_algorithm, params.key_size)?)
        } else {
            None
        };
        let csr = match &params.csr_pem {
            Some(pem) => Some(
                CertificateSigningRequestParams::from_pem(pem)
                    .map_err(|e| X509Error::BadRequest(format!("invalid CSR: {e}")))?,
            ),
            None => None,
        };
        let public_key: &dyn PublicKeyData = match (&generated, &csr) {
            (Some(kp), _) => kp,
            (None, Some(c)) => &c.public_key,
            (None, None) => return Err(X509Error::Internal("no public key source".into())),
        };

        // Subject DN + rfc4514 rendering.
        let (dn, subject_rfc4514) = build_subject(&params.subject);

        let mut cp = CertificateParams::default();
        cp.distinguished_name = dn;

        // Serial (v1 sequential counter, formatted lowercase hex).
        let serial = self.serial_counter.fetch_add(1, Ordering::SeqCst);
        cp.serial_number = Some(SerialNumber::from(serial));
        let serial_hex = format!("{serial:x}");

        // Validity — second precision (UTCTime), duration is what parity checks.
        let now = chrono::Utc::now();
        let nb_secs = now.timestamp();
        let na_secs = nb_secs + validity_days.max(0) * 86_400;
        cp.not_before = OffsetDateTime::from_unix_timestamp(nb_secs)
            .map_err(|e| X509Error::Internal(format!("notBefore: {e}")))?;
        cp.not_after = OffsetDateTime::from_unix_timestamp(na_secs)
            .map_err(|e| X509Error::Internal(format!("notAfter: {e}")))?;
        let not_before = chrono::DateTime::from_timestamp(nb_secs, 0)
            .ok_or_else(|| X509Error::Internal("notBefore chrono".into()))?
            .naive_utc();
        let not_after = chrono::DateTime::from_timestamp(na_secs, 0)
            .ok_or_else(|| X509Error::Internal("notAfter chrono".into()))?
            .naive_utc();

        // BasicConstraints (always present + critical, matching v1).
        cp.is_ca = if params.is_ca {
            match params.path_length {
                Some(pl) if pl >= 0 => IsCa::Ca(BasicConstraints::Constrained(pl as u8)),
                _ => IsCa::Ca(BasicConstraints::Unconstrained),
            }
        } else {
            IsCa::ExplicitNoCa
        };

        // KeyUsage (critical) / ExtendedKeyUsage (non-critical). v1 applies
        // `x or default` — an EMPTY list falls back to the defaults just like
        // an omitted one (`[]` is falsy in Python), so an intermediate CA with
        // no EKU still gets server_auth. Replicated for parity (see contract).
        let ku_names: Vec<String> = if params.key_usage.is_empty() {
            vec!["digital_signature".into(), "key_encipherment".into()]
        } else {
            params.key_usage.clone()
        };
        let eku_names: Vec<String> = if params.extended_key_usage.is_empty() {
            vec!["server_auth".into()]
        } else {
            params.extended_key_usage.clone()
        };
        cp.key_usages = map_key_usages(&ku_names);
        cp.extended_key_usages = map_extended_key_usages(&eku_names);

        // SubjectAltName.
        cp.subject_alt_names = build_sans(&params.san_dns, &params.san_ip, &params.san_email)?;

        // SubjectKeyIdentifier = RFC 5280 method 1 (SHA1 of subjectPublicKey).
        let ski = Sha1::digest(public_key.der_bytes()).to_vec();
        cp.key_identifier_method = KeyIdMethod::PreSpecified(ski);
        // AuthorityKeyIdentifier present (v1 always adds it); its keyid comes
        // from the issuer's own SKI (read from the CA cert below).
        cp.use_authority_key_identifier_extension = true;

        // Issuer from the CA cert (preserves CA subject DN string types and
        // its SKI → leaf AKI keyid) signed by the CA key.
        let ca_key = KeyPair::from_pem(&self.ca_key_pem)
            .map_err(|e| X509Error::Internal(format!("load CA key: {e}")))?;
        let issuer: Issuer<'_, KeyPair> = Issuer::from_ca_cert_pem(&self.ca_cert_pem, ca_key)
            .map_err(|e| X509Error::Internal(format!("build issuer: {e}")))?;

        // signed_by needs a concrete (Sized) public key; sign from whichever
        // source produced it.
        let cert = match (&generated, &csr) {
            (Some(kp), _) => cp.signed_by(kp, &issuer),
            (None, Some(c)) => cp.signed_by(&c.public_key, &issuer),
            (None, None) => return Err(X509Error::Internal("no public key source".into())),
        }
        .map_err(|e| X509Error::Internal(format!("sign certificate: {e}")))?;

        let cert_pem = cert.pem();
        let fingerprint_sha256 = hex_lower(&Sha256::digest(cert.der().as_ref()));
        let key_algorithm = params.key_algorithm.to_uppercase();
        let key_size = if key_algorithm == "ED25519" {
            None
        } else {
            Some(params.key_size)
        };
        let private_key_pem = generated.as_ref().map(|kp| kp.serialize_pem());

        Ok(IssuedX509 {
            certificate_pem: cert_pem,
            private_key_pem,
            serial_hex,
            subject: subject_rfc4514,
            issuer: self.info.subject.clone(),
            not_before,
            not_after,
            fingerprint_sha256,
            key_algorithm,
            key_size,
        })
    }

    /// Generates an X.509 CRL over the supplied revoked entries, returning the
    /// PEM and the (post-increment) CRL number — mirrors v1 `generate_crl`.
    pub fn generate_crl(&self, entries: &[CrlEntry]) -> Result<(String, i64), X509Error> {
        use rcgen::{
            CertificateRevocationListParams, CrlIssuingDistributionPoint, RevokedCertParams,
        };

        let crl_number = self.crl_number.fetch_add(1, Ordering::SeqCst) + 1;
        let now = chrono::Utc::now().timestamp();
        let next = now + self.config.crl_validity_days.max(0) * 86_400;

        let mut revoked = Vec::with_capacity(entries.len());
        for e in entries {
            let serial_bytes = hex_to_be_bytes(&e.serial_hex)
                .ok_or_else(|| X509Error::BadRequest(format!("bad serial: {}", e.serial_hex)))?;
            let rev_at = OffsetDateTime::from_unix_timestamp(e.revoked_at.and_utc().timestamp())
                .map_err(|err| X509Error::Internal(format!("revocation_date: {err}")))?;
            revoked.push(RevokedCertParams {
                serial_number: SerialNumber::from_slice(&serial_bytes),
                revocation_time: rev_at,
                reason_code: map_revocation_reason(e.reason.as_deref()),
                invalidity_date: None,
            });
        }

        let params = CertificateRevocationListParams {
            this_update: OffsetDateTime::from_unix_timestamp(now)
                .map_err(|e| X509Error::Internal(format!("this_update: {e}")))?,
            next_update: OffsetDateTime::from_unix_timestamp(next)
                .map_err(|e| X509Error::Internal(format!("next_update: {e}")))?,
            crl_number: SerialNumber::from(crl_number),
            issuing_distribution_point: None::<CrlIssuingDistributionPoint>,
            revoked_certs: revoked,
            key_identifier_method: KeyIdMethod::PreSpecified(Vec::new()),
        };

        let ca_key = KeyPair::from_pem(&self.ca_key_pem)
            .map_err(|e| X509Error::Internal(format!("load CA key: {e}")))?;
        let issuer: Issuer<'_, KeyPair> = Issuer::from_ca_cert_pem(&self.ca_cert_pem, ca_key)
            .map_err(|e| X509Error::Internal(format!("build issuer: {e}")))?;
        let crl = params
            .signed_by(&issuer)
            .map_err(|e| X509Error::Internal(format!("sign CRL: {e}")))?;
        let pem = crl
            .pem()
            .map_err(|e| X509Error::Internal(format!("crl pem: {e}")))?;
        Ok((pem, crl_number as i64))
    }

    /// Verifies a PEM certificate was issued by this CA (issuer DN match +
    /// signature check), mirroring v1 `verify_certificate`.
    pub fn verify(&self, cert_pem: &str) -> bool {
        verify_impl(&self.ca_cert_pem, cert_pem).unwrap_or(false)
    }
}

/// One revoked-certificate record for CRL generation.
#[derive(Debug, Clone)]
pub struct CrlEntry {
    /// Serial number in lowercase hex (as stored in the DB).
    pub serial_hex: String,
    /// Revocation timestamp.
    pub revoked_at: chrono::NaiveDateTime,
    /// Revocation reason name (v1 vocabulary), if any.
    pub reason: Option<String>,
}

fn verify_impl(ca_cert_pem: &str, cert_pem: &str) -> Option<bool> {
    let ca_der = pem_str_to_der(ca_cert_pem)?;
    let leaf_der = pem_str_to_der(cert_pem)?;
    let (_, ca) = X509Certificate::from_der(&ca_der).ok()?;
    let (_, leaf) = X509Certificate::from_der(&leaf_der).ok()?;
    if leaf.issuer() != ca.subject() {
        return Some(false);
    }
    Some(leaf.verify_signature(Some(ca.public_key())).is_ok())
}

/// Maps v1 KeyUsage names to rcgen purposes, preserving request order and
/// silently dropping unknown names (v1 `KEY_USAGE_MAP` behavior).
fn map_key_usages(names: &[String]) -> Vec<KeyUsagePurpose> {
    names
        .iter()
        .filter_map(|n| match n.as_str() {
            "digital_signature" => Some(KeyUsagePurpose::DigitalSignature),
            "key_encipherment" => Some(KeyUsagePurpose::KeyEncipherment),
            "data_encipherment" => Some(KeyUsagePurpose::DataEncipherment),
            "key_agreement" => Some(KeyUsagePurpose::KeyAgreement),
            "key_cert_sign" => Some(KeyUsagePurpose::KeyCertSign),
            "crl_sign" => Some(KeyUsagePurpose::CrlSign),
            "encipher_only" => Some(KeyUsagePurpose::EncipherOnly),
            "decipher_only" => Some(KeyUsagePurpose::DecipherOnly),
            _ => None,
        })
        .collect()
}

/// Maps v1 ExtendedKeyUsage names to rcgen purposes (unknown names dropped).
fn map_extended_key_usages(names: &[String]) -> Vec<ExtendedKeyUsagePurpose> {
    names
        .iter()
        .filter_map(|n| match n.as_str() {
            "server_auth" => Some(ExtendedKeyUsagePurpose::ServerAuth),
            "client_auth" => Some(ExtendedKeyUsagePurpose::ClientAuth),
            "code_signing" => Some(ExtendedKeyUsagePurpose::CodeSigning),
            "email_protection" => Some(ExtendedKeyUsagePurpose::EmailProtection),
            "time_stamping" => Some(ExtendedKeyUsagePurpose::TimeStamping),
            "ocsp_signing" => Some(ExtendedKeyUsagePurpose::OcspSigning),
            _ => None,
        })
        .collect()
}

fn map_revocation_reason(reason: Option<&str>) -> Option<rcgen::RevocationReason> {
    use rcgen::RevocationReason as R;
    Some(match reason {
        Some("key_compromise") => R::KeyCompromise,
        Some("ca_compromise") => R::CaCompromise,
        Some("affiliation_changed") => R::AffiliationChanged,
        Some("superseded") => R::Superseded,
        Some("cessation_of_operation") => R::CessationOfOperation,
        Some("certificate_hold") => R::CertificateHold,
        Some("privilege_withdrawn") => R::PrivilegeWithdrawn,
        Some("unspecified") | None => R::Unspecified,
        // v1 CRLReason has no entry for unknown reasons → omit the extension.
        Some(_) => return None,
    })
}

/// Builds SubjectAltName entries in v1 order (DNS, then IP, then email).
fn build_sans(dns: &[String], ip: &[String], email: &[String]) -> Result<Vec<SanType>, X509Error> {
    let mut out = Vec::with_capacity(dns.len() + ip.len() + email.len());
    for d in dns {
        let name = d
            .as_str()
            .try_into()
            .map_err(|_| X509Error::BadRequest(format!("invalid DNS SAN: {d}")))?;
        out.push(SanType::DnsName(name));
    }
    for addr in ip {
        let parsed: std::net::IpAddr = addr
            .parse()
            .map_err(|_| X509Error::BadRequest(format!("invalid IP SAN: {addr}")))?;
        out.push(SanType::IpAddress(parsed));
    }
    for e in email {
        let name = e
            .as_str()
            .try_into()
            .map_err(|_| X509Error::BadRequest(format!("invalid email SAN: {e}")))?;
        out.push(SanType::Rfc822Name(name));
    }
    Ok(out)
}

/// Parses a v1 DN string (`CN=x,O=y,C=US`) into an rcgen `DistinguishedName`
/// plus the cryptography `rfc4514_string()` rendering (reversed RDN order).
/// DN components are normalized to RFC 4514 order (most significant first: C, O, OU, ST, L, CN).
fn build_subject(subject: &str) -> (DistinguishedName, String) {
    let mut parsed: Vec<(&str, String, DnType)> = Vec::new();
    for part in subject.split(',') {
        let part = part.trim();
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        let key = k.trim().to_uppercase();
        let value = v.trim().to_owned();
        let (dn_type, short): (DnType, &str) = match key.as_str() {
            "CN" => (DnType::CommonName, "CN"),
            "O" => (DnType::OrganizationName, "O"),
            "OU" => (DnType::OrganizationalUnitName, "OU"),
            "C" => (DnType::CountryName, "C"),
            "ST" => (DnType::StateOrProvinceName, "ST"),
            "L" => (DnType::LocalityName, "L"),
            "E" => (
                DnType::CustomDnType(vec![1, 2, 840, 113549, 1, 9, 1]),
                "1.2.840.113549.1.9.1",
            ),
            _ => continue,
        };
        parsed.push((short, value, dn_type));
    }
    if parsed.is_empty() {
        // v1 fallback: whole string becomes the CN.
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, DnValue::Utf8String(subject.to_owned()));
        return (dn, format!("CN={}", escape_rfc4514(subject)));
    }

    // Normalize to RFC 4514 order (most significant first).
    let order = ["C", "ST", "L", "O", "OU", "E", "CN"];
    let mut sorted: Vec<(&str, String, DnType)> = Vec::new();
    for &key in &order {
        for (short, value, dn_type) in &parsed {
            if *short == key {
                sorted.push((*short, value.clone(), dn_type.clone()));
            }
        }
    }

    // Build both the DistinguishedName and the RFC4514 string.
    let mut dn = DistinguishedName::new();
    let mut pairs: Vec<(&str, String)> = Vec::new();
    for (short, value, dn_type) in sorted {
        push_dn_value(&mut dn, dn_type, short, &value);
        pairs.push((short, value));
    }
    (dn, rfc4514(&pairs))
}

/// Pushes a DN attribute choosing the ASN.1 string type cryptography uses:
/// PrintableString for country, IA5String for email, UTF8String otherwise.
fn push_dn_value(dn: &mut DistinguishedName, dn_type: DnType, short: &str, value: &str) {
    match short {
        "C" => match value.try_into() {
            Ok(ps) => dn.push(dn_type, DnValue::PrintableString(ps)),
            Err(_) => dn.push(dn_type, DnValue::Utf8String(value.to_owned())),
        },
        "1.2.840.113549.1.9.1" => match value.try_into() {
            Ok(ia5) => dn.push(dn_type, DnValue::Ia5String(ia5)),
            Err(_) => dn.push(dn_type, DnValue::Utf8String(value.to_owned())),
        },
        _ => dn.push(dn_type, DnValue::Utf8String(value.to_owned())),
    }
}

/// Renders attribute pairs as cryptography's `rfc4514_string()` — RFC 4514
/// order (most significant first: C, O, OU, ST, L, CN), minimal escaping.
/// Note: pairs are expected to be pre-sorted in RFC 4514 order.
fn rfc4514(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", escape_rfc4514(v)))
        .collect::<Vec<_>>()
        .join(",")
}

fn escape_rfc4514(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for (i, ch) in value.chars().enumerate() {
        let last = i + ch.len_utf8() == value.len();
        match ch {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' => {
                out.push('\\');
                out.push(ch);
            }
            '#' if i == 0 => {
                out.push('\\');
                out.push(ch);
            }
            ' ' if i == 0 || last => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

/// Generates a leaf key pair for the requested algorithm/size.
fn generate_key(algorithm: &str, key_size: i64) -> Result<KeyPair, X509Error> {
    match algorithm.to_uppercase().as_str() {
        "RSA" => {
            let size = if key_size <= 2048 {
                RsaKeySize::_2048
            } else if key_size <= 3072 {
                RsaKeySize::_3072
            } else {
                RsaKeySize::_4096
            };
            KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, size)
                .map_err(|e| X509Error::Internal(format!("generate RSA key: {e}")))
        }
        "ECDSA" => {
            let alg = if key_size <= 256 {
                &rcgen::PKCS_ECDSA_P256_SHA256
            } else if key_size <= 384 {
                &rcgen::PKCS_ECDSA_P384_SHA384
            } else {
                &rcgen::PKCS_ECDSA_P521_SHA512
            };
            KeyPair::generate_for(alg)
                .map_err(|e| X509Error::Internal(format!("generate EC key: {e}")))
        }
        "ED25519" => KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| X509Error::Internal(format!("generate ED25519 key: {e}"))),
        other => Err(X509Error::BadRequest(format!(
            "Unsupported algorithm: {other}"
        ))),
    }
}

/// Generates a fresh RSA-4096 self-signed CA reproducing v1 `_generate_ca`.
fn generate_ca() -> Result<(String, String), X509Error> {
    let key = KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, RsaKeySize::_4096)
        .map_err(|e| X509Error::Internal(format!("generate CA key: {e}")))?;

    let mut dn = DistinguishedName::new();
    match "US".try_into() {
        Ok(ps) => dn.push(DnType::CountryName, DnValue::PrintableString(ps)),
        Err(_) => dn.push(DnType::CountryName, DnValue::Utf8String("US".into())),
    }
    dn.push(
        DnType::OrganizationName,
        DnValue::Utf8String("SkausWatch".into()),
    );
    dn.push(
        DnType::CommonName,
        DnValue::Utf8String("SkausWatch Root CA".into()),
    );

    let now = chrono::Utc::now().timestamp();
    let mut cp = CertificateParams::default();
    cp.distinguished_name = dn;
    cp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cp.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    cp.not_before = OffsetDateTime::from_unix_timestamp(now)
        .map_err(|e| X509Error::Internal(format!("CA notBefore: {e}")))?;
    cp.not_after = OffsetDateTime::from_unix_timestamp(now + 3650 * 86_400)
        .map_err(|e| X509Error::Internal(format!("CA notAfter: {e}")))?;
    // v1 CA SKI = SHA1(subjectPublicKey); no AKI on the self-signed root.
    cp.key_identifier_method = KeyIdMethod::PreSpecified(Sha1::digest(key.der_bytes()).to_vec());
    cp.use_authority_key_identifier_extension = false;

    let cert = cp
        .self_signed(&key)
        .map_err(|e| X509Error::Internal(format!("self-sign CA: {e}")))?;
    Ok((key.serialize_pem(), cert.pem()))
}

/// Persists a freshly generated CA to disk with v1 permissions (0600/0644).
fn save_ca(config: &X509CaConfig, key_pem: &str, cert_pem: &str) -> Result<(), X509Error> {
    use std::os::unix::fs::PermissionsExt as _;
    let key_path = std::path::Path::new(&config.ca_key_path);
    if let Some(parent) = key_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| X509Error::Internal(format!("create CA dir: {e}")))?;
    }
    std::fs::write(&config.ca_key_path, key_pem)
        .map_err(|e| X509Error::Internal(format!("write CA key: {e}")))?;
    std::fs::write(&config.ca_cert_path, cert_pem)
        .map_err(|e| X509Error::Internal(format!("write CA cert: {e}")))?;
    std::fs::set_permissions(&config.ca_key_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| X509Error::Internal(format!("chmod CA key: {e}")))?;
    std::fs::set_permissions(&config.ca_cert_path, std::fs::Permissions::from_mode(0o644))
        .map_err(|e| X509Error::Internal(format!("chmod CA cert: {e}")))?;
    Ok(())
}

/// Parses static CA metadata (subject/issuer/validity/fingerprint) from the
/// CA certificate PEM.
fn parse_ca_info(ca_cert_pem: &str) -> Result<X509CaInfo, X509Error> {
    let der = pem_str_to_der(ca_cert_pem)
        .ok_or_else(|| X509Error::Internal("CA cert not valid PEM".into()))?;
    let (_, cert) = X509Certificate::from_der(&der)
        .map_err(|e| X509Error::Internal(format!("parse CA cert: {e}")))?;

    let subject = rfc4514_from_name(cert.subject());
    let issuer = rfc4514_from_name(cert.issuer());
    let nb = ts_to_naive(cert.validity().not_before.timestamp())?;
    let na = ts_to_naive(cert.validity().not_after.timestamp())?;
    let fingerprint_sha256 = hex_lower(&Sha256::digest(&der));
    Ok(X509CaInfo {
        subject,
        issuer,
        not_before: nb,
        not_after: na,
        fingerprint_sha256,
    })
}

/// Renders an x509-parser `X509Name` as cryptography's rfc4514 string
/// (reversed RDN order, short type names).
fn rfc4514_from_name(name: &x509_parser::x509::X509Name<'_>) -> String {
    let mut pairs: Vec<(String, String)> = Vec::new();
    for rdn in name.iter_rdn() {
        for attr in rdn.iter() {
            let short = oid_short_name(attr.attr_type());
            let value = attr.as_str().map(|s| s.to_owned()).unwrap_or_default();
            pairs.push((short, value));
        }
    }
    pairs
        .iter()
        .rev()
        .map(|(k, v)| format!("{k}={}", escape_rfc4514(v)))
        .collect::<Vec<_>>()
        .join(",")
}

fn oid_short_name(oid: &x509_parser::der_parser::Oid<'_>) -> String {
    let s = oid.to_id_string();
    match s.as_str() {
        "2.5.4.3" => "CN".into(),
        "2.5.4.10" => "O".into(),
        "2.5.4.11" => "OU".into(),
        "2.5.4.6" => "C".into(),
        "2.5.4.8" => "ST".into(),
        "2.5.4.7" => "L".into(),
        other => other.to_owned(),
    }
}

fn ts_to_naive(secs: i64) -> Result<chrono::NaiveDateTime, X509Error> {
    Ok(chrono::DateTime::from_timestamp(secs, 0)
        .ok_or_else(|| X509Error::Internal("timestamp out of range".into()))?
        .naive_utc())
}

fn pem_str_to_der(pem_str: &str) -> Option<Vec<u8>> {
    let (_remaining, pem) = x509_parser::pem::parse_x509_pem(pem_str.as_bytes()).ok()?;
    Some(pem.contents)
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_to_be_bytes(hex: &str) -> Option<Vec<u8>> {
    let hex = hex.trim();
    let padded = if hex.len() % 2 == 1 {
        format!("0{hex}")
    } else {
        hex.to_owned()
    };
    let mut out = Vec::with_capacity(padded.len() / 2);
    let bytes = padded.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

// SigningKey is implemented for KeyPair by rcgen; this bound keeps the
// generic issuer type explicit above.
const _: fn() = || {
    fn assert_signing<T: SigningKey>() {}
    assert_signing::<KeyPair>();
};

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rfc4514_sorts_to_most_significant_first() {
        let (_, s) = build_subject("CN=example.com,O=Example,C=US");
        assert_eq!(s, "C=US,O=Example,CN=example.com");
    }

    #[test]
    fn rfc4514_defaults_to_cn_when_unparseable() {
        let (_, s) = build_subject("just-a-name");
        assert_eq!(s, "CN=just-a-name");
    }

    #[test]
    fn key_usage_mapping_drops_unknown_and_keeps_order() {
        let ku = map_key_usages(&[
            "digital_signature".into(),
            "bogus".into(),
            "key_cert_sign".into(),
        ]);
        assert_eq!(
            ku,
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyCertSign
            ]
        );
    }

    #[test]
    fn hex_roundtrip_pads_odd_length() {
        assert_eq!(hex_to_be_bytes("1"), Some(vec![1]));
        assert_eq!(hex_to_be_bytes("ff01"), Some(vec![0xff, 0x01]));
        assert_eq!(hex_to_be_bytes("zz"), None);
    }
}
