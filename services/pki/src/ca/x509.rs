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

    // Normalize to RFC 4514 order (most significant first). The "E" (email)
    // slot must match the `short` value `push_dn_value`/the parse loop above
    // actually assigns email components — the OID string, not the letter
    // "E" — otherwise `E=` subject components silently never match here and
    // are dropped entirely from the issued certificate's subject (found via
    // testing: an `E=`-only subject produced a completely empty DN).
    let order = ["C", "ST", "L", "O", "OU", "1.2.840.113549.1.9.1", "CN"];
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

    /// `X509Ca` intentionally does not derive `Debug` (it holds the CA
    /// private key PEM — never risk it reaching a `{:?}` log line), so
    /// `Result<X509Ca, _>::unwrap_err()` isn't available. This extracts the
    /// error without requiring `Debug` on the `Ok` side.
    fn expect_err<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected Err, got Ok"),
            Err(e) => e,
        }
    }

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
        assert_eq!(hex_to_be_bytes(""), Some(vec![]));
    }

    fn tmp_config() -> X509CaConfig {
        let dir =
            std::env::temp_dir().join(format!("skauswatch-x509-test-{}", uuid::Uuid::new_v4()));
        X509CaConfig {
            ca_key_path: dir.join("ca.key").to_string_lossy().into_owned(),
            ca_cert_path: dir.join("ca.crt").to_string_lossy().into_owned(),
            ca_key_password: None,
            default_validity_days: 365,
            max_validity_days: 825,
            default_key_algorithm: "RSA".into(),
            default_key_size: 2048,
            crl_validity_days: 7,
            ocsp_responder_url: None,
        }
    }

    fn base_params(subject: &str) -> X509IssueParams {
        X509IssueParams {
            subject: subject.into(),
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
        }
    }

    #[test]
    fn load_or_generate_writes_then_reloads_from_disk() {
        let config = tmp_config();
        let ca1 = X509Ca::load_or_generate(config.clone()).unwrap();
        assert!(std::path::Path::new(&config.ca_key_path).exists());
        assert!(std::path::Path::new(&config.ca_cert_path).exists());
        assert_eq!(ca1.serial_counter(), 1);
        assert_eq!(ca1.crl_number(), 0);
        assert!(ca1.info().subject.contains("SkausWatch"));

        // Second call loads the just-persisted key/cert from disk instead of
        // generating a fresh CA.
        let ca2 = X509Ca::load_or_generate(config).unwrap();
        assert_eq!(ca1.ca_certificate_pem(), ca2.ca_certificate_pem());
    }

    #[test]
    fn load_or_generate_propagates_unreadable_key_error() {
        // Cert file present but key path points at a directory (unreadable
        // as a file) — exercises the "read CA key" Internal error branch.
        let dir =
            std::env::temp_dir().join(format!("skauswatch-x509-baddir-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let key_dir = dir.join("ca.key");
        std::fs::create_dir_all(&key_dir).unwrap();
        let cert_path = dir.join("ca.crt");
        std::fs::write(&cert_path, "not-a-real-cert").unwrap();
        let mut config = tmp_config();
        config.ca_key_path = key_dir.to_string_lossy().into_owned();
        config.ca_cert_path = cert_path.to_string_lossy().into_owned();
        let err = expect_err(X509Ca::load_or_generate(config));
        assert!(matches!(err, X509Error::Internal(_)));
    }

    #[test]
    fn from_pem_builds_ca_directly() {
        let config = tmp_config();
        let ca = X509Ca::load_or_generate(config.clone()).unwrap();
        let ca2 = X509Ca::from_pem(
            config,
            std::fs::read_to_string(std::path::Path::new(&ca.config.ca_key_path)).unwrap(),
            ca.ca_certificate_pem().to_owned(),
        )
        .unwrap();
        assert_eq!(ca2.info().subject, ca.info().subject);
    }

    #[test]
    fn from_pem_rejects_garbage_cert() {
        let err = expect_err(X509Ca::from_pem(
            tmp_config(),
            "not a key".into(),
            "not a cert".into(),
        ));
        assert!(matches!(err, X509Error::Internal(_)));
    }

    #[test]
    fn issue_rsa_leaf_certificate_has_expected_fields() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let issued = ca
            .issue(&base_params("CN=example.com,O=Example,C=US"))
            .unwrap();
        assert_eq!(issued.serial_hex, "1");
        assert_eq!(issued.subject, "C=US,O=Example,CN=example.com");
        assert_eq!(issued.issuer, ca.info().subject);
        assert_eq!(issued.key_algorithm, "RSA");
        assert_eq!(issued.key_size, Some(2048));
        assert!(issued.private_key_pem.is_some());
        assert!(issued.certificate_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(issued.fingerprint_sha256.len(), 64);
        assert!(issued.not_after > issued.not_before);

        // Serial counter increments across calls.
        let issued2 = ca.issue(&base_params("CN=second.example.com")).unwrap();
        assert_eq!(issued2.serial_hex, "2");
    }

    #[test]
    fn issue_ecdsa_and_ed25519_and_larger_rsa_sizes() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        for (alg, size) in [
            ("ECDSA", 256),
            ("ECDSA", 384),
            ("ECDSA", 521),
            ("ed25519", 0),
            ("rsa", 3072),
            ("rsa", 4096),
        ] {
            let mut p = base_params("CN=alg-test.example.com");
            p.key_algorithm = alg.into();
            p.key_size = size;
            let issued = ca.issue(&p).unwrap();
            assert_eq!(issued.key_algorithm, alg.to_uppercase());
            if alg.eq_ignore_ascii_case("ed25519") {
                assert_eq!(issued.key_size, None);
            } else {
                assert_eq!(issued.key_size, Some(size));
            }
        }
    }

    #[test]
    fn issue_rejects_unsupported_algorithm() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let mut p = base_params("CN=bad-alg.example.com");
        p.key_algorithm = "DSA".into();
        let err = ca.issue(&p).unwrap_err();
        assert!(matches!(err, X509Error::BadRequest(_)));
    }

    #[test]
    fn issue_validity_days_capped_at_max() {
        let mut config = tmp_config();
        config.max_validity_days = 10;
        let ca = X509Ca::load_or_generate(config).unwrap();
        let mut p = base_params("CN=cap.example.com");
        p.validity_days = 9999;
        let issued = ca.issue(&p).unwrap();
        let days = (issued.not_after - issued.not_before).num_days();
        assert!(days <= 10, "expected capped validity, got {days} days");
    }

    #[test]
    fn issue_with_san_dns_ip_email_and_explicit_key_usages() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let mut p = base_params("CN=san.example.com");
        p.san_dns = vec!["www.example.com".into(), "*.example.com".into()];
        p.san_ip = vec!["10.0.0.1".into(), "::1".into()];
        p.san_email = vec!["admin@example.com".into()];
        p.key_usage = vec!["digital_signature".into(), "key_agreement".into()];
        p.extended_key_usage = vec!["client_auth".into(), "code_signing".into()];
        let issued = ca.issue(&p).unwrap();
        assert!(issued.certificate_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn issue_invalid_san_ip_is_bad_request() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let mut p = base_params("CN=bad-ip.example.com");
        p.san_ip = vec!["not-an-ip".into()];
        let err = ca.issue(&p).unwrap_err();
        assert!(matches!(err, X509Error::BadRequest(_)));
    }

    #[test]
    fn issue_non_ascii_san_dns_is_bad_request() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let mut p = base_params("CN=nonascii.example.com");
        p.san_dns = vec!["exämple.com".into()];
        let err = ca.issue(&p).unwrap_err();
        assert!(matches!(err, X509Error::BadRequest(_)));
    }

    #[test]
    fn issue_non_ascii_san_email_is_bad_request() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let mut p = base_params("CN=nonascii2.example.com");
        p.san_email = vec!["usér@example.com".into()];
        let err = ca.issue(&p).unwrap_err();
        assert!(matches!(err, X509Error::BadRequest(_)));
    }

    #[test]
    fn issue_ca_certificate_unconstrained_and_constrained_path_length() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let mut p = base_params("CN=intermediate.example.com,O=Example");
        p.is_ca = true;
        p.path_length = Some(2);
        let issued = ca.issue(&p).unwrap();
        assert!(issued.certificate_pem.contains("BEGIN CERTIFICATE"));

        // Negative path_length falls back to unconstrained (`_ => Unconstrained`).
        let mut p2 = base_params("CN=root-like.example.com");
        p2.is_ca = true;
        p2.path_length = Some(-1);
        let issued2 = ca.issue(&p2).unwrap();
        assert!(issued2.certificate_pem.contains("BEGIN CERTIFICATE"));

        // is_ca with no path_length also unconstrained.
        let mut p3 = base_params("CN=root-like2.example.com");
        p3.is_ca = true;
        ca.issue(&p3).unwrap();
    }

    #[test]
    fn issue_from_csr_returns_no_private_key() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let subject_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let csr_params = CertificateParams::default();
        let csr = csr_params.serialize_request(&subject_key).unwrap();
        let csr_pem = csr.pem().unwrap();

        let mut p = base_params("CN=csr.example.com");
        p.csr_pem = Some(csr_pem);
        let issued = ca.issue(&p).unwrap();
        assert!(issued.private_key_pem.is_none());
        assert!(issued.certificate_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn issue_invalid_csr_pem_is_bad_request() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let mut p = base_params("CN=badcsr.example.com");
        p.csr_pem = Some("not a real csr".into());
        let err = ca.issue(&p).unwrap_err();
        assert!(matches!(err, X509Error::BadRequest(_)));
    }

    #[test]
    fn generate_crl_covers_all_named_reasons_and_unspecified() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let issued = ca.issue(&base_params("CN=revoke-me.example.com")).unwrap();
        let reasons = [
            "key_compromise",
            "ca_compromise",
            "affiliation_changed",
            "superseded",
            "cessation_of_operation",
            "certificate_hold",
            "privilege_withdrawn",
            "unspecified",
        ];
        let entries: Vec<CrlEntry> = reasons
            .iter()
            .map(|r| CrlEntry {
                serial_hex: issued.serial_hex.clone(),
                revoked_at: chrono::Utc::now().naive_utc(),
                reason: Some((*r).to_owned()),
            })
            .collect();
        let (pem, number) = ca.generate_crl(&entries).unwrap();
        assert!(pem.contains("BEGIN X509 CRL"));
        assert_eq!(number, 1);

        // None reason and an unrecognized reason name (omits the extension,
        // per v1 CRLReason parity) both succeed.
        let entries2 = vec![
            CrlEntry {
                serial_hex: issued.serial_hex.clone(),
                revoked_at: chrono::Utc::now().naive_utc(),
                reason: None,
            },
            CrlEntry {
                serial_hex: issued.serial_hex,
                revoked_at: chrono::Utc::now().naive_utc(),
                reason: Some("totally_unknown_reason".into()),
            },
        ];
        let (_, number2) = ca.generate_crl(&entries2).unwrap();
        assert_eq!(number2, 2);
    }

    #[test]
    fn generate_crl_empty_entries_succeeds() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let (pem, number) = ca.generate_crl(&[]).unwrap();
        assert!(pem.contains("BEGIN X509 CRL"));
        assert_eq!(number, 1);
    }

    #[test]
    fn generate_crl_rejects_bad_serial_hex() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let entries = vec![CrlEntry {
            serial_hex: "not-hex".into(),
            revoked_at: chrono::Utc::now().naive_utc(),
            reason: None,
        }];
        let err = ca.generate_crl(&entries).unwrap_err();
        assert!(matches!(err, X509Error::BadRequest(_)));
    }

    #[test]
    fn verify_accepts_own_leaf_and_rejects_foreign_or_garbage() {
        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let issued = ca.issue(&base_params("CN=verify-me.example.com")).unwrap();
        assert!(ca.verify(&issued.certificate_pem));

        // A cert issued by a *different* CA fails the issuer/signature check.
        let other_ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        let other_issued = other_ca
            .issue(&base_params("CN=other.example.com"))
            .unwrap();
        assert!(!ca.verify(&other_issued.certificate_pem));

        // Unparsable PEM never panics — verify_impl returns None -> false.
        assert!(!ca.verify("not a certificate"));
    }

    #[test]
    fn verify_rejects_a_leaf_whose_issuer_dn_does_not_match_at_all() {
        // `generate_ca()` always uses the same hardcoded DN, so two
        // freshly-generated CAs share a subject string and a leaf from one
        // fails `ca.verify()` on the *signature* check, not the issuer-DN
        // check. Build a CA with a genuinely different subject DN (via a
        // hand-signed root, `from_pem`) to exercise the issuer-mismatch
        // branch specifically.
        let alt_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut alt_dn = DistinguishedName::new();
        alt_dn.push(
            DnType::CommonName,
            DnValue::Utf8String("totally-different-issuer".into()),
        );
        let mut alt_cp = CertificateParams::default();
        alt_cp.distinguished_name = alt_dn;
        alt_cp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let alt_cert = alt_cp.self_signed(&alt_key).unwrap();
        let alt_ca =
            X509Ca::from_pem(tmp_config(), alt_key.serialize_pem(), alt_cert.pem()).unwrap();
        let alt_issued = alt_ca
            .issue(&base_params("CN=leaf-from-alt.example.com"))
            .unwrap();

        let ca = X509Ca::load_or_generate(tmp_config()).unwrap();
        assert!(!ca.verify(&alt_issued.certificate_pem));
    }

    #[test]
    fn build_subject_parses_all_recognized_components_and_skips_unknown() {
        let (_, s) = build_subject("CN=x,O=Org,OU=Unit,C=US,ST=CA,L=City,E=a@b.com,X=ignored");
        assert_eq!(
            s,
            "C=US,ST=CA,L=City,O=Org,OU=Unit,1.2.840.113549.1.9.1=a@b.com,CN=x"
        );
    }

    #[test]
    fn build_subject_skips_malformed_parts_without_equals() {
        let (_, s) = build_subject("CN=x,garbage,O=Org");
        assert_eq!(s, "O=Org,CN=x");
    }

    #[test]
    fn push_dn_value_falls_back_to_utf8_for_non_printable_country() {
        // '_' is outside PrintableString's allowed charset -> fallback branch.
        let (dn, s) = build_subject("C=U_S");
        assert_eq!(s, "C=U_S");
        assert_eq!(dn.iter().count(), 1);
    }

    #[test]
    fn push_dn_value_falls_back_to_utf8_for_non_ascii_email() {
        let (_, s) = build_subject("E=usér@example.com");
        assert_eq!(s, "1.2.840.113549.1.9.1=usér@example.com");
    }

    #[test]
    fn escape_rfc4514_escapes_specials_and_leading_hash_and_edge_spaces() {
        assert_eq!(escape_rfc4514("a,b"), "a\\,b");
        assert_eq!(escape_rfc4514("#leading"), "\\#leading");
        assert_eq!(escape_rfc4514(" leading"), "\\ leading");
        assert_eq!(escape_rfc4514("trailing "), "trailing\\ ");
        assert_eq!(
            escape_rfc4514("a+b\"c\\d<e>f;g"),
            "a\\+b\\\"c\\\\d\\<e\\>f\\;g"
        );
    }

    #[test]
    fn extended_key_usage_mapping_covers_all_names_and_drops_unknown() {
        let eku = map_extended_key_usages(&[
            "server_auth".into(),
            "client_auth".into(),
            "code_signing".into(),
            "email_protection".into(),
            "time_stamping".into(),
            "ocsp_signing".into(),
            "bogus".into(),
        ]);
        assert_eq!(eku.len(), 6);
    }

    #[test]
    fn revocation_reason_mapping_covers_all_names() {
        assert!(matches!(
            map_revocation_reason(Some("key_compromise")),
            Some(rcgen::RevocationReason::KeyCompromise)
        ));
        assert!(matches!(
            map_revocation_reason(None),
            Some(rcgen::RevocationReason::Unspecified)
        ));
        assert_eq!(map_revocation_reason(Some("nonsense")), None);
    }

    #[test]
    fn generate_key_covers_all_algorithm_and_size_branches() {
        for (alg, size) in [
            ("RSA", 1024),
            ("RSA", 3000),
            ("RSA", 8192),
            ("ECDSA", 200),
            ("ECDSA", 300),
            ("ECDSA", 999),
            ("ED25519", 0),
        ] {
            generate_key(alg, size).unwrap();
        }
        assert!(generate_key("DSA", 1024).is_err());
    }

    #[test]
    fn hex_lower_renders_two_digit_groups() {
        assert_eq!(hex_lower(&[0x00, 0xab, 0xff]), "00abff");
    }

    #[test]
    fn pem_str_to_der_rejects_garbage() {
        assert!(pem_str_to_der("not pem at all").is_none());
    }

    #[test]
    fn ts_to_naive_rejects_out_of_range_timestamp() {
        assert!(ts_to_naive(i64::MAX).is_err());
        assert!(ts_to_naive(0).is_ok());
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod oid_short_name_extra {
    use super::oid_short_name;
    use x509_parser::der_parser::Oid;

    #[test]
    fn maps_all_known_short_names_and_passes_through_unknown() {
        assert_eq!(oid_short_name(&Oid::from(&[2, 5, 4, 3]).unwrap()), "CN");
        assert_eq!(oid_short_name(&Oid::from(&[2, 5, 4, 10]).unwrap()), "O");
        assert_eq!(oid_short_name(&Oid::from(&[2, 5, 4, 11]).unwrap()), "OU");
        assert_eq!(oid_short_name(&Oid::from(&[2, 5, 4, 6]).unwrap()), "C");
        assert_eq!(oid_short_name(&Oid::from(&[2, 5, 4, 8]).unwrap()), "ST");
        assert_eq!(oid_short_name(&Oid::from(&[2, 5, 4, 7]).unwrap()), "L");
        assert_eq!(
            oid_short_name(&Oid::from(&[1, 2, 3, 4]).unwrap()),
            "1.2.3.4"
        );
    }
}
