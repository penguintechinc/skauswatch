//! Builds `rustls` mTLS configs from SPIFFE X.509-SVID material.
//!
//! Both directions perform full mutual TLS: each side presents its own
//! X.509-SVID as its certificate, and each side verifies the peer's
//! certificate two ways — its chain must validate against the held
//! [`X509BundleSet`] (which may span more than one trust domain, see
//! [`crate::matcher`]), and its SPIFFE ID (from the certificate's URI SAN)
//! must satisfy the caller-supplied [`SpiffeIdMatcher`]. Neither check
//! alone is sufficient: a valid chain from an unlisted workload, or a
//! matching SPIFFE ID on a cert from an untrusted issuer, are both
//! rejected.
//!
//! Hostname/`ServerName` verification is deliberately never performed —
//! SPIFFE leaf certificates identify workloads by SPIFFE ID (a URI SAN),
//! not by DNS name, so rustls's default name-matching verifiers
//! (`WebPkiServerVerifier`) don't apply on the client side. The server
//! side's client-certificate verification has no such concept to begin
//! with (`ClientCertVerifier::verify_client_cert` takes no name parameter),
//! so it delegates chain validation straight to `WebPkiClientVerifier`
//! and only adds the SPIFFE ID check on top.

use std::fmt;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ParsedCertificate, WebPkiClientVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use spiffe::{SpiffeId, X509BundleSet, X509Svid};

use crate::IdentityError;
use crate::matcher::SpiffeIdMatcher;

/// Builds a `RootCertStore` from every X.509 authority across every trust
/// domain in `bundles`. Deliberately not filtered to a single trust domain:
/// a bundle set legitimately holds federated authorities, and which of
/// those are actually *acceptable* for a given peer is the
/// [`SpiffeIdMatcher`]'s job, not this function's.
fn root_store_from_bundles(bundles: &X509BundleSet) -> Result<RootCertStore, IdentityError> {
    let mut roots = RootCertStore::empty();
    for (_trust_domain, bundle) in bundles.iter() {
        for authority in bundle.authorities() {
            let der = CertificateDer::from(authority.as_bytes().to_vec());
            roots.add(der).map_err(IdentityError::Tls)?;
        }
    }
    if roots.is_empty() {
        return Err(IdentityError::EmptyTrustBundle);
    }
    Ok(roots)
}

/// Converts our own X.509-SVID into the DER chain + PKCS#8 key rustls's
/// config builders expect.
fn svid_cert_and_key(svid: &X509Svid) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let chain = svid
        .cert_chain()
        .iter()
        .map(|cert| CertificateDer::from(cert.as_bytes().to_vec()))
        .collect();
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
        svid.private_key().as_bytes().to_vec(),
    ));
    (chain, key)
}

/// Extracts the peer's SPIFFE ID from its leaf certificate, mapped to the
/// `rustls::Error` a verifier trait method must return on rejection.
fn peer_spiffe_id(end_entity: &CertificateDer<'_>) -> Result<SpiffeId, rustls::Error> {
    spiffe::cert::spiffe_id_from_der(end_entity.as_ref()).map_err(|e| {
        rustls::Error::General(format!("peer certificate has no valid SPIFFE ID: {e}"))
    })
}

/// Rejects the handshake unless `id` satisfies `allowed`.
fn require_allowed(id: &SpiffeId, allowed: &SpiffeIdMatcher) -> Result<(), rustls::Error> {
    if allowed.matches(id) {
        Ok(())
    } else {
        Err(rustls::Error::General(format!(
            "peer SPIFFE ID {id} is not permitted by policy"
        )))
    }
}

/// Client-side verifier: validates a server's certificate chain against a
/// [`RootCertStore`] built from the held bundle set, then requires its
/// SPIFFE ID to satisfy `allowed`. Chain validation uses
/// [`rustls::client::verify_server_cert_signed_by_trust_anchor`] directly
/// rather than `WebPkiServerVerifier`, because that verifier also enforces
/// a DNS-name match against `ServerName` that SPIFFE leaf certs (URI SAN
/// only) cannot satisfy.
struct SpiffeServerCertVerifier {
    roots: RootCertStore,
    allowed: SpiffeIdMatcher,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl fmt::Debug for SpiffeServerCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpiffeServerCertVerifier")
            .field("trust_anchors", &self.roots.len())
            .field("allowed", &self.allowed)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for SpiffeServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = ParsedCertificate::try_from(end_entity)?;
        rustls::client::verify_server_cert_signed_by_trust_anchor(
            &parsed,
            &self.roots,
            intermediates,
            now,
            self.provider.signature_verification_algorithms.all,
        )?;
        let spiffe_id = peer_spiffe_id(end_entity)?;
        require_allowed(&spiffe_id, &self.allowed)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Server-side verifier: delegates full chain-of-trust validation of the
/// client's certificate to a [`WebPkiClientVerifier`] built from the held
/// bundle set, then additionally requires the client's SPIFFE ID to
/// satisfy `allowed`. Unlike the client-side verifier above, no DNS-name
/// concern arises here — `ClientCertVerifier::verify_client_cert` has no
/// name parameter at all — so wrapping the standard verifier is safe and
/// avoids re-implementing chain validation a second time.
struct SpiffeClientCertVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allowed: SpiffeIdMatcher,
}

impl fmt::Debug for SpiffeClientCertVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpiffeClientCertVerifier")
            .field("allowed", &self.allowed)
            .finish_non_exhaustive()
    }
}

impl ClientCertVerifier for SpiffeClientCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let spiffe_id = peer_spiffe_id(end_entity)?;
        require_allowed(&spiffe_id, &self.allowed)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Builds a mTLS `rustls::ServerConfig`: presents `svid`, and requires
/// every connecting peer to present a certificate that both chains to an
/// authority in `bundles` and carries a SPIFFE ID satisfying `allowed`.
///
/// The returned config is a point-in-time snapshot of `svid`/`bundles` —
/// rebuild it (via [`crate::IdentityProvider::refresh`] followed by another
/// call to [`crate::IdentityProvider::server_tls_config`]) before the SVID
/// expires.
pub(crate) fn server_tls_config(
    svid: &X509Svid,
    bundles: &X509BundleSet,
    allowed: &SpiffeIdMatcher,
) -> Result<rustls::ServerConfig, IdentityError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let roots = Arc::new(root_store_from_bundles(bundles)?);
    let inner = WebPkiClientVerifier::builder_with_provider(roots, Arc::clone(&provider))
        .build()
        .map_err(IdentityError::VerifierBuild)?;
    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(SpiffeClientCertVerifier {
        inner,
        allowed: allowed.clone(),
    });
    let (chain, key) = svid_cert_and_key(svid);
    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(IdentityError::Tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(IdentityError::Tls)
}

/// Builds a mTLS `rustls::ClientConfig`: presents `svid` as the client
/// certificate, and requires the connecting server's certificate to both
/// chain to an authority in `bundles` and carry a SPIFFE ID satisfying
/// `allowed`. See [`server_tls_config`] for the snapshot/refresh caveat.
pub(crate) fn client_tls_config(
    svid: &X509Svid,
    bundles: &X509BundleSet,
    allowed: &SpiffeIdMatcher,
) -> Result<rustls::ClientConfig, IdentityError> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let roots = root_store_from_bundles(bundles)?;
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(SpiffeServerCertVerifier {
        roots,
        allowed: allowed.clone(),
        provider: Arc::clone(&provider),
    });
    let (chain, key) = svid_cert_and_key(svid);
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(IdentityError::Tls)?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(chain, key)
        .map_err(IdentityError::Tls)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::net::SocketAddr;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use super::*;
    use crate::testutil::{TestCa, bundle_set, trust_domain};

    /// Runs one mTLS handshake attempt, followed by a `ping`/`pong`
    /// application-data exchange, returning both sides' results.
    ///
    /// The post-handshake exchange matters: TLS 1.3 client-certificate
    /// authentication is verified only by the server, and a client's
    /// `connect()` future can resolve `Ok` *before* it has any way to know
    /// whether the server went on to accept or reject that certificate
    /// (the rejection alert only arrives on a subsequent read). Asserting
    /// on the handshake future alone would make a rejected client look
    /// like it succeeded; requiring a real round-trip is what actually
    /// proves the server never serves a rejected peer.
    async fn attempt_handshake(
        server_cfg: rustls::ServerConfig,
        client_cfg: rustls::ClientConfig,
    ) -> (Result<(), String>, Result<(), String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("local_addr");

        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
            let mut tls = acceptor.accept(stream).await.map_err(|e| e.to_string())?;
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
            tls.write_all(b"pong").await.map_err(|e| e.to_string())?;
            Ok(())
        });

        let connector = TlsConnector::from(Arc::new(client_cfg));
        let client = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| e.to_string())?;
            // SPIFFE certs carry no DNS SAN; this name is never checked by
            // our verifiers (see module docs) — any well-formed value works.
            let name = ServerName::try_from("skauswatch.invalid").expect("server name");
            let mut tls = connector
                .connect(name, stream)
                .await
                .map_err(|e| e.to_string())?;
            tls.write_all(b"ping").await.map_err(|e| e.to_string())?;
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.map_err(|e| e.to_string())?;
            if &buf != b"pong" {
                return Err(format!("unexpected response: {buf:?}"));
            }
            Ok(())
        });

        let server_result = server.await.expect("server task join");
        let client_result = client.await.expect("client task join");
        (server_result, client_result)
    }

    #[tokio::test]
    async fn mtls_succeeds_across_federated_trust_domains() {
        let home_ca = TestCa::generate();
        let federated_ca = TestCa::generate();
        let home_td = trust_domain("penguintech.io");
        let federated_td = trust_domain("customer.example");

        let server_svid = home_ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let client_svid = federated_ca.issue_leaf("spiffe://customer.example/agent/x");

        let bundles = bundle_set(&[(&home_td, &home_ca), (&federated_td, &federated_ca)]);

        let server_allowed = SpiffeIdMatcher::new().allow_trust_domain(federated_td.clone());
        let client_allowed = SpiffeIdMatcher::new().allow_trust_domain(home_td.clone());

        let server_cfg = server_tls_config(&server_svid, &bundles, &server_allowed)
            .expect("build server config");
        let client_cfg = client_tls_config(&client_svid, &bundles, &client_allowed)
            .expect("build client config");

        let (server_result, client_result) = attempt_handshake(server_cfg, client_cfg).await;
        assert_eq!(server_result, Ok(()));
        assert_eq!(client_result, Ok(()));
    }

    #[tokio::test]
    async fn mtls_rejects_peer_outside_matcher_allowlist() {
        let ca = TestCa::generate();
        let td = trust_domain("penguintech.io");
        let server_svid = ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let client_svid = ca.issue_leaf("spiffe://penguintech.io/beta/worker-vault-sync");
        let bundles = bundle_set(&[(&td, &ca)]);

        // Server only allows the "manager" workload's exact ID, not the
        // worker presenting a certificate here — chain validates fine, but
        // the SPIFFE ID must still be rejected.
        let server_allowed = SpiffeIdMatcher::new()
            .allow_exact(SpiffeId::new("spiffe://penguintech.io/beta/manager").expect("spiffe id"));
        let client_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());

        let server_cfg =
            server_tls_config(&server_svid, &bundles, &server_allowed).expect("server config");
        let client_cfg =
            client_tls_config(&client_svid, &bundles, &client_allowed).expect("client config");

        let (server_result, client_result) = attempt_handshake(server_cfg, client_cfg).await;
        assert!(
            server_result.is_err(),
            "server must reject disallowed peer SPIFFE ID"
        );
        assert!(
            client_result.is_err(),
            "client side observes the aborted handshake"
        );
    }

    #[tokio::test]
    async fn mtls_rejects_peer_from_untrusted_ca() {
        let trusted_ca = TestCa::generate();
        let untrusted_ca = TestCa::generate();
        let td = trust_domain("penguintech.io");

        let server_svid = trusted_ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        // Client presents a cert for the SAME trust domain name, but signed
        // by a CA the server's bundle set never included.
        let client_svid = untrusted_ca.issue_leaf("spiffe://penguintech.io/beta/worker-vault-sync");
        let bundles = bundle_set(&[(&td, &trusted_ca)]);

        let server_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());
        let client_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());

        let server_cfg =
            server_tls_config(&server_svid, &bundles, &server_allowed).expect("server config");
        let client_cfg =
            client_tls_config(&client_svid, &bundles, &client_allowed).expect("client config");

        let (server_result, client_result) = attempt_handshake(server_cfg, client_cfg).await;
        assert!(
            server_result.is_err(),
            "server must reject a cert chaining to an untrusted CA"
        );
        assert!(client_result.is_err());
    }

    #[tokio::test]
    async fn client_rejects_server_peer_lacking_a_spiffe_id() {
        let ca = TestCa::generate();
        let td = trust_domain("penguintech.io");
        let bundles = bundle_set(&[(&td, &ca)]);

        // Misconfigured/malicious server: its leaf chains to a CA our
        // client trusts, but carries a plain DNS SAN instead of a SPIFFE
        // URI SAN. Built directly with rustls (not `server_tls_config`),
        // and with no client-cert requirement, so this test isolates the
        // one property under test: our client-side verifier must still
        // reject it.
        let (server_chain, server_key) = ca.issue_leaf_without_spiffe_id("example.invalid");
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let server_cfg = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(server_chain, server_key)
            .expect("server config");

        let client_svid = ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let client_allowed = SpiffeIdMatcher::new().allow_trust_domain(td);
        let client_cfg =
            client_tls_config(&client_svid, &bundles, &client_allowed).expect("client config");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr: SocketAddr = listener.local_addr().expect("local_addr");
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept");
            // The server may or may not observe an error itself, depending
            // on exactly when the client aborts — the property under test
            // is the client's rejection below, not this side.
            let _ = acceptor.accept(stream).await;
        });

        let connector = TlsConnector::from(Arc::new(client_cfg));
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("tcp connect");
        let name = ServerName::try_from("skauswatch.invalid").expect("server name");
        let result = connector.connect(name, stream).await;
        assert!(
            result.is_err(),
            "client must reject a peer certificate with no SPIFFE ID"
        );
        server.await.expect("server task join");
    }

    #[tokio::test]
    async fn mtls_succeeds_over_tls_1_2() {
        // `with_safe_default_protocol_versions()` (used by
        // `server_tls_config`/`client_tls_config`) enables both TLS 1.2
        // and 1.3, and a same-process handshake always negotiates the
        // higher version — so the TLS 1.2 signature-verification delegates
        // on both custom verifiers are otherwise never exercised. Forcing
        // TLS 1.2 here on configs built directly (bypassing the
        // `tls12`-agnostic public helpers) proves those delegates are
        // wired correctly too, not just the TLS 1.3 path every other test
        // in this module exercises.
        let ca = TestCa::generate();
        let td = trust_domain("penguintech.io");
        let bundles = bundle_set(&[(&td, &ca)]);
        let server_svid = ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let client_svid = ca.issue_leaf("spiffe://penguintech.io/beta/worker-vault-sync");
        let allowed = SpiffeIdMatcher::new().allow_trust_domain(td);

        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let roots = Arc::new(root_store_from_bundles(&bundles).expect("roots"));
        let client_verifier =
            WebPkiClientVerifier::builder_with_provider(roots, Arc::clone(&provider))
                .build()
                .expect("client verifier");
        let server_verifier: Arc<dyn ClientCertVerifier> = Arc::new(SpiffeClientCertVerifier {
            inner: client_verifier,
            allowed: allowed.clone(),
        });
        let (server_chain, server_key) = svid_cert_and_key(&server_svid);
        let server_cfg = rustls::ServerConfig::builder_with_provider(Arc::clone(&provider))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("tls 1.2 only")
            .with_client_cert_verifier(server_verifier)
            .with_single_cert(server_chain, server_key)
            .expect("server config");

        let server_cert_verifier: Arc<dyn ServerCertVerifier> =
            Arc::new(SpiffeServerCertVerifier {
                roots: root_store_from_bundles(&bundles).expect("roots"),
                allowed: allowed.clone(),
                provider: Arc::clone(&provider),
            });
        let (client_chain, client_key) = svid_cert_and_key(&client_svid);
        let client_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("tls 1.2 only")
            .dangerous()
            .with_custom_certificate_verifier(server_cert_verifier)
            .with_client_auth_cert(client_chain, client_key)
            .expect("client config");

        let (server_result, client_result) = attempt_handshake(server_cfg, client_cfg).await;
        assert_eq!(server_result, Ok(()));
        assert_eq!(client_result, Ok(()));
    }

    #[test]
    fn verifier_debug_impls_report_useful_state() {
        let ca = TestCa::generate();
        let td = trust_domain("penguintech.io");
        let bundles = bundle_set(&[(&td, &ca)]);
        let allowed = SpiffeIdMatcher::new().allow_trust_domain(td);
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

        let server_verifier = SpiffeServerCertVerifier {
            roots: root_store_from_bundles(&bundles).expect("roots"),
            allowed: allowed.clone(),
            provider: Arc::clone(&provider),
        };
        let debug = format!("{server_verifier:?}");
        assert!(debug.contains("SpiffeServerCertVerifier"));
        assert!(debug.contains("trust_anchors"));

        let roots = Arc::new(root_store_from_bundles(&bundles).expect("roots"));
        let inner = WebPkiClientVerifier::builder_with_provider(roots, provider)
            .build()
            .expect("inner verifier");
        let client_verifier = SpiffeClientCertVerifier { inner, allowed };
        let debug = format!("{client_verifier:?}");
        assert!(debug.contains("SpiffeClientCertVerifier"));
    }

    #[test]
    fn server_tls_config_rejects_empty_bundle_set() {
        let ca = TestCa::generate();
        let svid = ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let empty = X509BundleSet::new();
        let allowed = SpiffeIdMatcher::new().allow_trust_domain(trust_domain("penguintech.io"));

        let err = server_tls_config(&svid, &empty, &allowed).expect_err("empty bundle set");
        assert!(matches!(err, IdentityError::EmptyTrustBundle));
    }

    #[test]
    fn client_tls_config_rejects_empty_bundle_set() {
        let ca = TestCa::generate();
        let svid = ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let empty = X509BundleSet::new();
        let allowed = SpiffeIdMatcher::new().allow_trust_domain(trust_domain("penguintech.io"));

        let err = client_tls_config(&svid, &empty, &allowed).expect_err("empty bundle set");
        assert!(matches!(err, IdentityError::EmptyTrustBundle));
    }
}
