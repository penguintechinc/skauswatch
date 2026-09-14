//! Test-only SPIFFE certificate fixtures built with `rcgen`.
//!
//! Used by this crate's own unit tests (always, via `#[cfg(test)]`) and,
//! when the `testutil` feature is enabled, by downstream crates that need
//! to build a fake SPIFFE identity for integration-testing real mTLS
//! accept/reject against [`crate::IdentityProvider::from_svid_for_test`]
//! without a live SPIRE agent — see the crate-level "Testing without a live
//! SPIRE agent" docs. Not reachable from a normal production build either
//! way, and has no coverage obligation of its own beyond "the certs it
//! builds are usable", which every test that calls it already proves.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rcgen::string::Ia5String;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
pub use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use spiffe::TrustDomain;
pub use spiffe::{X509Bundle, X509BundleSet, X509Svid};

/// A self-signed test CA: holds its own signing key and can issue any
/// number of SPIFFE-SAN leaf certificates against it.
pub struct TestCa {
    cert_der: Vec<u8>,
    key: KeyPair,
    params: CertificateParams,
}

impl TestCa {
    /// Generates a fresh, unique self-signed CA.
    pub fn generate() -> Self {
        let key = match KeyPair::generate() {
            Ok(k) => k,
            Err(e) => panic!("generate CA key: {e}"),
        };
        let mut params = match CertificateParams::new(Vec::<String>::new()) {
            Ok(p) => p,
            Err(e) => panic!("build CA params: {e}"),
        };
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = match params.self_signed(&key) {
            Ok(c) => c,
            Err(e) => panic!("self-sign CA: {e}"),
        };
        let cert_der = cert.der().as_ref().to_vec();
        Self {
            cert_der,
            key,
            params,
        }
    }

    /// Issues a leaf certificate carrying `spiffe_id` as its sole URI SAN,
    /// signed by this CA, and parses the result into an [`X509Svid`].
    pub fn issue_leaf(&self, spiffe_id: &str) -> X509Svid {
        let leaf_key = match KeyPair::generate() {
            Ok(k) => k,
            Err(e) => panic!("generate leaf key: {e}"),
        };
        let uri = match Ia5String::try_from(spiffe_id.to_string()) {
            Ok(u) => u,
            Err(e) => panic!("SPIFFE URI SAN {spiffe_id}: {e}"),
        };
        let mut params = match CertificateParams::new(Vec::<String>::new()) {
            Ok(p) => p,
            Err(e) => panic!("build leaf params: {e}"),
        };
        params.subject_alt_names = vec![SanType::URI(uri)];
        // `IsCa::NoCa` omits the BasicConstraints extension entirely, but
        // `X509Svid::parse_from_der` requires it present (RFC 5280 2.5.29.19)
        // to confirm `CA:FALSE` on the leaf — `ExplicitNoCa` emits it.
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = match params.signed_by(&leaf_key, &issuer) {
            Ok(c) => c,
            Err(e) => panic!("sign leaf for {spiffe_id}: {e}"),
        };
        let cert_der = cert.der().as_ref().to_vec();
        let key_der = leaf_key.serialize_der();
        match X509Svid::parse_from_der(&cert_der, &key_der) {
            Ok(svid) => svid,
            Err(e) => panic!("parse issued leaf {spiffe_id} as X509Svid: {e}"),
        }
    }

    /// Issues a leaf certificate with a plain DNS SAN — no SPIFFE URI SAN
    /// at all — signed by this CA. Used to exercise the "peer certificate
    /// chains fine but carries no SPIFFE ID" rejection path. Returned
    /// directly as rustls DER types rather than an [`X509Svid`], since
    /// `X509Svid::parse_from_der` would (correctly) refuse a leaf with no
    /// SPIFFE ID.
    pub fn issue_leaf_without_spiffe_id(
        &self,
        dns_name: &str,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        let leaf_key = match KeyPair::generate() {
            Ok(k) => k,
            Err(e) => panic!("generate leaf key: {e}"),
        };
        let mut params = match CertificateParams::new(vec![dns_name.to_string()]) {
            Ok(p) => p,
            Err(e) => panic!("build leaf params: {e}"),
        };
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = match params.signed_by(&leaf_key, &issuer) {
            Ok(c) => c,
            Err(e) => panic!("sign leaf for {dns_name}: {e}"),
        };
        let chain = vec![CertificateDer::from(cert.der().as_ref().to_vec())];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
        (chain, key)
    }

    /// Builds this CA's trust bundle for `trust_domain`.
    pub fn bundle(&self, trust_domain: &TrustDomain) -> X509Bundle {
        match X509Bundle::from_x509_authorities(trust_domain.clone(), &[&self.cert_der]) {
            Ok(b) => b,
            Err(e) => panic!("build bundle for {trust_domain}: {e}"),
        }
    }
}

/// Builds a bundle set spanning every `(trust_domain, ca)` pair — the
/// fixture shape used to exercise federated (multi-trust-domain) scenarios.
pub fn bundle_set(entries: &[(&TrustDomain, &TestCa)]) -> X509BundleSet {
    let mut set = X509BundleSet::new();
    for (trust_domain, ca) in entries {
        set.add_bundle(ca.bundle(trust_domain));
    }
    set
}

/// Shorthand for parsing a [`TrustDomain`] in test code.
pub fn trust_domain(name: &str) -> TrustDomain {
    match TrustDomain::new(name) {
        Ok(td) => td,
        Err(e) => panic!("trust domain {name}: {e}"),
    }
}
