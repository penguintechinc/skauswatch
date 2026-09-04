//! mTLS client identity for a future manager→pki gRPC caller (R2c-3,
//! `docs/v2-port/service-auth-model.md` §2/§6): builds the
//! `rustls::ClientConfig` manager presents (its own SVID) plus the
//! [`SpiffeIdMatcher`] it requires pki's server certificate to satisfy —
//! `spiffe://penguintech.io/<env>/pki` and nothing else, mirroring pki's own
//! `manager_matcher` on the other side of this same relationship
//! (`services/pki/src/grpc/mod.rs`).
//!
//! No real gRPC channel is wired to this yet: pki's gRPC surface has zero
//! in-repo callers today (confirmed by the design doc's module-level
//! inspection) — this module is the reusable building block a future real
//! caller (issuance-on-behalf-of-users) constructs its
//! `tonic::transport::Channel` from, so that work doesn't also have to
//! reinvent the mTLS identity plumbing already proven working in
//! `crates/skauswatch-identity` and `services/pki`.

use skauswatch_identity::{
    IdentityError, IdentityProvider, SpiffeId, SpiffeIdError, SpiffeIdMatcher,
};

/// The one identity manager's pki client trusts: the `pki` workload in this
/// deployment's environment (`docs/v2-port/service-auth-model.md` §1).
pub(crate) fn pki_matcher() -> Result<SpiffeIdMatcher, SpiffeIdError> {
    let env = crate::state::spiffe_env();
    let id = SpiffeId::new(format!("spiffe://penguintech.io/{env}/pki"))?;
    Ok(SpiffeIdMatcher::new().allow_exact(id))
}

/// Builds the mTLS `rustls::ClientConfig` manager would use to dial pki's
/// gRPC listener: presents manager's own SVID, requires the server's
/// certificate to chain to an authority in the held bundle set and its
/// SPIFFE ID to be exactly pki's (see [`pki_matcher`]). Returns
/// [`IdentityError::Degraded`] if `identity` holds no attested SVID.
#[allow(dead_code)] // no real caller yet — see module docs
pub(crate) fn pki_client_tls_config(
    identity: &IdentityProvider,
) -> Result<rustls::ClientConfig, anyhow::Error> {
    let matcher = pki_matcher().map_err(|e| anyhow::anyhow!("pki SPIFFE ID for gRPC mTLS: {e}"))?;
    identity
        .client_tls_config(&matcher)
        .map_err(|e: IdentityError| anyhow::anyhow!("pki gRPC mTLS client config: {e}"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // tests fail loudly by design
mod tests {
    use std::sync::Arc;

    use rustls::pki_types::ServerName;
    use skauswatch_identity::IdentityProvider;
    use skauswatch_identity::testutil::{TestCa, bundle_set, trust_domain};
    use tokio::io::AsyncReadExt as _;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[test]
    fn pki_matcher_accepts_only_pki_workload_in_this_env() {
        assert!(
            std::env::var("SPIFFE_ENV").is_err(),
            "test assumes the default SPIFFE_ENV (\"beta\")"
        );
        let matcher = pki_matcher().unwrap_or_else(|e| panic!("build matcher: {e}"));
        let id = |s: &str| SpiffeId::new(s).unwrap_or_else(|e| panic!("spiffe id {s}: {e}"));

        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/pki")));
        // Different workload, same trust domain/env.
        assert!(!matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        // Same workload name, different (federated) trust domain.
        assert!(!matcher.matches(&id("spiffe://customer.example/beta/pki")));
        // Same trust domain/workload, different env segment.
        assert!(!matcher.matches(&id("spiffe://penguintech.io/gamma/pki")));
    }

    /// Real mTLS handshake proving the client config built here actually
    /// works: a manager identity dials a bare rustls TLS listener presenting
    /// pki's SVID and completes the handshake, while an impostor server
    /// presenting a *different* workload's SVID (from the same trusted CA)
    /// is rejected by the matcher before any RPC could ever be sent.
    #[tokio::test]
    async fn manager_client_completes_handshake_with_pki_and_rejects_a_non_pki_server() {
        let ca = TestCa::generate();
        let td = trust_domain("penguintech.io");
        let bundles = bundle_set(&[(&td, &ca)]);

        let manager_svid = ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let manager_identity = IdentityProvider::from_svid_for_test(manager_svid, bundles.clone());
        let client_cfg =
            pki_client_tls_config(&manager_identity).unwrap_or_else(|e| panic!("client cfg: {e}"));

        // Any server identity may accept the connection (the server side's
        // own matcher choice is irrelevant here) — this test proves the
        // *client's* matcher only trusts pki's claimed identity.
        let open = SpiffeIdMatcher::new().allow_trust_domain(td.clone());

        let pki_svid = ca.issue_leaf("spiffe://penguintech.io/beta/pki");
        let pki_identity = IdentityProvider::from_svid_for_test(pki_svid, bundles.clone());
        let pki_server_cfg = pki_identity
            .server_tls_config(&open)
            .unwrap_or_else(|e| panic!("pki server cfg: {e}"));
        let addr = spawn_tls_echo_server(pki_server_cfg).await;
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect: {e}"));
        let name =
            ServerName::try_from("pki.invalid").unwrap_or_else(|e| panic!("server name: {e}"));
        let result = tokio_rustls::TlsConnector::from(Arc::new(client_cfg.clone()))
            .connect(name, stream)
            .await;
        assert!(
            result.is_ok(),
            "manager must complete the mTLS handshake with pki's SVID: {result:?}"
        );

        let impostor_svid = ca.issue_leaf("spiffe://penguintech.io/beta/worker-vault-sync");
        let impostor_identity = IdentityProvider::from_svid_for_test(impostor_svid, bundles);
        let impostor_server_cfg = impostor_identity
            .server_tls_config(&open)
            .unwrap_or_else(|e| panic!("impostor server cfg: {e}"));
        let addr = spawn_tls_echo_server(impostor_server_cfg).await;
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect: {e}"));
        let name =
            ServerName::try_from("pki.invalid").unwrap_or_else(|e| panic!("server name: {e}"));
        match tokio_rustls::TlsConnector::from(Arc::new(client_cfg))
            .connect(name, stream)
            .await
        {
            Err(_) => {}
            Ok(mut tls) => {
                // TLS 1.3: a client's connect() can resolve `Ok` before it
                // learns the server rejected its certificate — a
                // post-handshake read surfaces the rejection deterministically
                // either way (see skauswatch_identity's tls.rs test docs).
                let mut buf = [0u8; 1];
                assert!(
                    tls.read(&mut buf).await.is_err(),
                    "non-pki server identity must not survive past the handshake"
                );
            }
        }
    }

    /// Binds an ephemeral loopback TLS listener that accepts exactly one
    /// connection using `server_cfg`, then drops it — enough for the
    /// handshake-only assertions above.
    async fn spawn_tls_echo_server(server_cfg: rustls::ServerConfig) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap_or_else(|e| panic!("bind: {e}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|e| panic!("local_addr: {e}"));
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = acceptor.accept(stream).await;
            }
        });
        addr
    }
}
