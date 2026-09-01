//! gRPC control plane (tonic). Serves `skauswatch.pki` `PKIService` on
//! `GRPC_PORT` (default 50052, `GRPC_ENABLED` default true) — the same 16
//! RPCs the v1 servicer implemented (`grpc/server.py`).
//!
//! AUTH (hardened, finding #1; ES256 per audit finding H1b): every RPC —
//! including `HealthCheck` — now requires `authorization: Bearer <jwt>`
//! metadata, verified against the shared `JWT_VERIFY_KEY`
//! (`skauswatch_auth::verify_grpc_bearer`). Before
//! this pass the port was completely open: anyone on the network could mint
//! CA certificates and download private keys via gRPC with zero auth. A
//! future caller must present a machine JWT minted with
//! `skauswatch_auth::issue_service_token`. Every request carries
//! `api_version`; unknown values return UNIMPLEMENTED per the backend API
//! standard.
//!
//! TRANSPORT AUTH (R2c-1, `docs/v2-port/service-auth-model.md` §2): when
//! `AppState::identity` holds an attested SPIFFE X.509-SVID, this listener
//! additionally requires full mutual TLS — pki presents its own SVID over
//! the wire and accepts only a peer presenting
//! `spiffe://penguintech.io/<env>/manager` (see [`manager_matcher`]). This
//! is *additive* to, not a replacement for, [`auth_interceptor`]: for one
//! release cycle both a valid client certificate *and* a valid ES256
//! bearer token are required (dual-accept — see the doc's §2 "Transition
//! plan"; §3 there deletes the bearer-token layer entirely once mTLS is
//! confirmed healthy in beta). When no identity is held — `AppState::identity` is
//! `None`, or the SPIFFE Workload API attested but degraded (dev/test, no
//! SPIRE agent socket present) — the listener falls back to plaintext with
//! `auth_interceptor` as the sole gate, exactly as before this change.
//! Production hard-fails inside `AppStateInner::from_env` instead of ever
//! reaching this fallback (see `skauswatch_identity`'s fail-safe policy).

mod pki_service;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::TcpListenerStream;

use skauswatch_identity::{IdentityError, SpiffeId, SpiffeIdError, SpiffeIdMatcher};

use crate::state::AppState;

/// Default gRPC port — parity with v1 (`GRPC_PORT`, default 50052).
const DEFAULT_GRPC_PORT: u16 = 50_052;

/// Whether the gRPC server should run — enabled unless `GRPC_ENABLED`
/// (lowercased) is anything other than "true".
pub fn enabled() -> bool {
    std::env::var("GRPC_ENABLED")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true)
}

/// Resolves the gRPC listen port from `GRPC_PORT` (default 50052).
pub fn port() -> u16 {
    std::env::var("GRPC_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_GRPC_PORT)
}

/// Tonic interceptor requiring `authorization: Bearer <jwt>` on every RPC of
/// the service it's attached to (finding #1 — see module docs).
fn auth_interceptor(
    verify_key: jsonwebtoken::DecodingKey,
) -> impl FnMut(tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> + Clone {
    move |req: tonic::Request<()>| {
        skauswatch_auth::verify_grpc_bearer(req.metadata(), &verify_key)?;
        Ok(req)
    }
}

/// The one caller pki's gRPC surface trusts over mTLS: the `manager`
/// workload in this deployment's environment
/// (`docs/v2-port/service-auth-model.md` §1's who-calls-whom allowlist —
/// manager is pki's sole in-repo caller-to-be).
fn manager_matcher() -> Result<SpiffeIdMatcher, SpiffeIdError> {
    let env = crate::config::spiffe_env();
    let id = SpiffeId::new(format!("spiffe://penguintech.io/{env}/manager"))?;
    Ok(SpiffeIdMatcher::new().allow_exact(id))
}

/// Wraps `listener` in a mTLS-terminating stream for
/// `tonic::transport::Server::serve_with_incoming_shutdown`: each accepted
/// TCP connection is handshaked against `tls_config` — which presents pki's
/// own SVID and requires the peer's to satisfy whatever
/// [`skauswatch_identity::SpiffeIdMatcher`] it was built with — before being
/// handed to tonic. A failed handshake (bad/absent peer cert) is logged and
/// the accept loop continues rather than tearing down the whole listener,
/// mirroring `tonic`'s own `TcpIncoming`/`axum::serve::Listener`
/// accept-error retry behavior.
fn mtls_incoming(
    listener: TcpListener,
    tls_config: rustls::ServerConfig,
) -> impl tokio_stream::Stream<Item = std::io::Result<TlsStream<TcpStream>>> {
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));
    TcpListenerStream::new(listener).then(move |stream| {
        let acceptor = acceptor.clone();
        async move { acceptor.accept(stream?).await }
    })
}

/// Runs the tonic `PKIService` server on `addr` until `shutdown` resolves —
/// wired into the same signal as the REST server. `addr` is caller-supplied
/// (rather than resolved from `port()` internally) so tests can bind an
/// OS-assigned ephemeral port instead of racing each other for the real
/// `GRPC_PORT`/50052 default. Every RPC is gated by `auth_interceptor`
/// (finding #1) regardless of transport; see the module docs for the
/// additive mTLS layering (R2c-1) on top of it.
pub async fn serve(
    state: AppState,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    serve_with_ready(state, addr, shutdown, None).await
}

/// Same as [`serve`], but if `ready` is supplied, sends the actual bound
/// address through it once the listener is up — the real (`GRPC_PORT`, not
/// `port()`-resolved-internally) address `addr` resolves to, which matters
/// when `addr`'s port is `0` (OS-assigned). `serve` is the sole production
/// entry point (always passes `None`); this split exists purely so the
/// tests below can drive a real mTLS handshake against a known address
/// through the *actual* production code path, not a reimplementation of it.
async fn serve_with_ready(
    state: AppState,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send,
    ready: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> anyhow::Result<()> {
    use skauswatch_proto::pki::pki_service_server::PkiServiceServer;

    let interceptor = auth_interceptor(state.jwt_verify_key.clone());
    let identity = state.identity.clone();
    let router = tonic::transport::Server::builder().add_service(
        PkiServiceServer::with_interceptor(pki_service::PkiGrpc::new(state), interceptor),
    );

    let tls_config = match &identity {
        Some(provider) => {
            let matcher = manager_matcher()
                .map_err(|e| anyhow::anyhow!("manager SPIFFE ID for gRPC mTLS: {e}"))?;
            match provider.server_tls_config(&matcher) {
                Ok(cfg) => Some(cfg),
                Err(IdentityError::Degraded) => None,
                Err(e) => return Err(anyhow::anyhow!("pki gRPC mTLS config: {e}")),
            }
        }
        None => None,
    };

    match tls_config {
        Some(cfg) => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let bound = listener.local_addr()?;
            tracing::info!(addr = %bound, "pki gRPC listening (mTLS, manager-only + ES256 bearer)");
            if let Some(tx) = ready {
                let _ = tx.send(bound);
            }
            router
                .serve_with_incoming_shutdown(mtls_incoming(listener, cfg), shutdown)
                .await?;
        }
        None => {
            tracing::warn!(
                %addr,
                "no SPIFFE workload identity held — pki gRPC serving plaintext \
                 (dev/test only; ES256 bearer auth is still required on every RPC; \
                 production hard-fails at startup instead of reaching this fallback)"
            );
            if let Some(tx) = ready {
                let _ = tx.send(addr);
            }
            router.serve_with_shutdown(addr, shutdown).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use std::time::Duration;

    use rustls::pki_types::ServerName;
    use skauswatch_identity::IdentityProvider;
    use skauswatch_identity::testutil::{TestCa, bundle_set, trust_domain};
    use tokio::io::AsyncReadExt as _;

    use super::*;

    /// An OS-assigned ephemeral loopback port — every `serve()` test binds
    /// its own so parallel test threads never race for the same address
    /// (unlike the real `GRPC_PORT`/50052 default `main.rs` uses).
    fn ephemeral_addr() -> SocketAddr {
        ([127, 0, 0, 1], 0).into()
    }

    /// A shutdown future that has already resolved — `serve()` binds,
    /// starts serving, and returns almost immediately without needing a
    /// real client.
    fn already_shutdown() -> impl std::future::Future<Output = ()> + Send {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let _ = tx.send(());
        async move {
            let _ = rx.await;
        }
    }

    #[tokio::test]
    async fn serve_binds_and_shuts_down_cleanly_on_signal() {
        // identity: None (AppStateInner::for_tests()'s default) — serve()
        // must take the plaintext fallback without even attempting
        // manager_matcher()/server_tls_config.
        let state = crate::state::AppStateInner::for_tests();
        assert!(state.identity.is_none());
        let result = serve(state, ephemeral_addr(), already_shutdown()).await;
        assert!(
            result.is_ok(),
            "serve() should shut down cleanly: {result:?}"
        );
    }

    #[tokio::test]
    async fn serve_falls_back_to_plaintext_when_identity_is_held_but_degraded() {
        // identity: Some(provider), but the provider itself degraded (no
        // live SPIRE Workload API socket) — a distinct code path from the
        // `None` case above: this one calls
        // manager_matcher()/server_tls_config() and must map
        // IdentityError::Degraded to the same plaintext fallback rather
        // than propagating it as a hard error.
        let identity = crate::routes::test_support::degraded_identity();
        let state = crate::state::AppStateInner::for_tests_with_identity(identity);
        let result = serve(state, ephemeral_addr(), already_shutdown()).await;
        assert!(
            result.is_ok(),
            "serve() should degrade to plaintext cleanly: {result:?}"
        );
    }

    /// End-to-end mTLS handshake test against the *real* `serve()` code
    /// path (via `serve_with_ready`, not a reimplementation): a manager
    /// SVID completes the handshake, a non-manager SVID from the same
    /// trusted CA is rejected by [`manager_matcher`], and an SVID claiming
    /// the manager identity but signed by a CA outside the held bundle set
    /// is rejected by chain validation. Exercises `mtls_incoming` and the
    /// `Some(cfg)` branch of `serve`/`serve_with_ready` for real, which the
    /// existing `serve_*` tests above (identity `None`/degraded) never
    /// reach — see FIX 2/FIX 3 of the identity prod-hard-fail hardening
    /// pass.
    #[tokio::test]
    async fn grpc_mtls_accepts_manager_and_rejects_non_manager_and_untrusted_ca() {
        let trusted_ca = TestCa::generate();
        let untrusted_ca = TestCa::generate();
        let td = trust_domain("penguintech.io");

        let server_svid = trusted_ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let manager_client_svid = trusted_ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let worker_client_svid =
            trusted_ca.issue_leaf("spiffe://penguintech.io/beta/worker-vault-sync");
        // Same claimed SPIFFE ID as the legitimate manager, but signed by a
        // CA the server's bundle set never included — chain validation
        // must reject this before the matcher is even consulted.
        let impostor_client_svid = untrusted_ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let bundles = bundle_set(&[(&td, &trusted_ca)]);

        let server_identity = IdentityProvider::from_svid_for_test(server_svid, bundles.clone());
        let state = crate::state::AppStateInner::for_tests_with_identity(Arc::new(server_identity));

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown = async move {
            let _ = shutdown_rx.await;
        };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let serve_task = tokio::spawn(serve_with_ready(
            state,
            ephemeral_addr(),
            shutdown,
            Some(ready_tx),
        ));
        let addr = ready_rx
            .await
            .unwrap_or_else(|e| panic!("serve() never reported its bound address: {e}"));

        // Manager peer: trusted CA, allowed by the matcher — handshake
        // must complete.
        let manager_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());
        let manager_provider =
            IdentityProvider::from_svid_for_test(manager_client_svid, bundles.clone());
        let manager_result = connect_client(addr, &manager_provider, &manager_allowed).await;
        assert!(
            manager_result.is_ok(),
            "manager SVID must complete the mTLS handshake: {manager_result:?}"
        );
        drop(manager_result);

        // Non-manager peer: same trusted CA, disallowed path — the matcher
        // must reject it even though the chain validates fine.
        let worker_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());
        let worker_provider =
            IdentityProvider::from_svid_for_test(worker_client_svid, bundles.clone());
        assert_handshake_rejected(
            connect_client(addr, &worker_provider, &worker_allowed).await,
            "non-manager SVID",
        )
        .await;

        // Impostor peer: correct claimed SPIFFE ID, untrusted issuer — chain
        // validation must reject it.
        let impostor_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());
        let impostor_provider =
            IdentityProvider::from_svid_for_test(impostor_client_svid, bundles.clone());
        assert_handshake_rejected(
            connect_client(addr, &impostor_provider, &impostor_allowed).await,
            "untrusted-CA impostor SVID",
        )
        .await;

        let _ = shutdown_tx.send(());
        tokio::time::timeout(Duration::from_secs(5), serve_task)
            .await
            .unwrap_or_else(|e| panic!("serve() did not shut down in time: {e}"))
            .unwrap_or_else(|e| panic!("serve task join: {e}"))
            .unwrap_or_else(|e| panic!("serve() returned an error: {e}"));
    }

    type ClientTlsStream = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;

    /// Connects to `addr` presenting `provider`'s held identity as the
    /// client certificate, allowing the server's SPIFFE ID per `allowed`.
    async fn connect_client(
        addr: SocketAddr,
        provider: &IdentityProvider,
        allowed: &SpiffeIdMatcher,
    ) -> std::io::Result<ClientTlsStream> {
        let client_cfg = provider
            .client_tls_config(allowed)
            .unwrap_or_else(|e| panic!("client tls config: {e}"));
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect: {e}"));
        // SPIFFE certs carry no DNS SAN; this name is never checked by our
        // client verifier (see skauswatch_identity::tls module docs) — any
        // well-formed value works.
        let name =
            ServerName::try_from("pki.invalid").unwrap_or_else(|e| panic!("server name: {e}"));
        tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_cfg))
            .connect(name, stream)
            .await
    }

    /// Asserts that a `connect_client` outcome represents a rejected peer.
    /// TLS 1.3: a client's `connect()` can resolve `Ok` before it has any
    /// way to know the server went on to reject its certificate (the
    /// rejection alert only arrives on a subsequent read) — see
    /// `skauswatch_identity`'s `tls.rs` test docs for the same caveat. A
    /// post-handshake read surfaces the rejection deterministically either
    /// way.
    async fn assert_handshake_rejected(result: std::io::Result<ClientTlsStream>, label: &str) {
        match result {
            Err(_) => {}
            Ok(mut tls) => {
                let mut buf = [0u8; 1];
                assert!(
                    tls.read(&mut buf).await.is_err(),
                    "{label}'s connection must not survive past the handshake"
                );
            }
        }
    }

    #[test]
    fn manager_matcher_accepts_only_the_manager_workload_in_this_env() {
        assert!(
            std::env::var("SPIFFE_ENV").is_err(),
            "test assumes the default SPIFFE_ENV (\"beta\")"
        );
        let matcher = manager_matcher().unwrap_or_else(|e| panic!("build matcher: {e}"));
        let id = |s: &str| SpiffeId::new(s).unwrap_or_else(|e| panic!("spiffe id {s}: {e}"));

        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        // Different workload, same trust domain/env.
        assert!(!matcher.matches(&id("spiffe://penguintech.io/beta/worker-vault-sync")));
        // Same workload name, different (federated) trust domain.
        assert!(!matcher.matches(&id("spiffe://customer.example/beta/manager")));
        // Same trust domain/workload, different env segment.
        assert!(!matcher.matches(&id("spiffe://penguintech.io/gamma/manager")));
    }

    #[test]
    fn grpc_port_defaults_to_v1_50052() {
        assert_eq!(DEFAULT_GRPC_PORT, 50_052);
    }

    #[test]
    fn enabled_and_port_default_when_env_unset() {
        // Neither GRPC_ENABLED nor GRPC_PORT is set in this test process ->
        // both fall back to their documented defaults.
        assert!(std::env::var("GRPC_ENABLED").is_err());
        assert!(enabled());
        assert!(std::env::var("GRPC_PORT").is_err());
        assert_eq!(port(), DEFAULT_GRPC_PORT);
    }

    #[test]
    fn auth_interceptor_rejects_missing_and_wrong_secret() {
        let mut auth = auth_interceptor(skauswatch_testkit::jwt::verify_key().clone());
        assert!(auth(tonic::Request::new(())).is_err());

        let token = match skauswatch_auth::issue_service_token(
            "x",
            "admin",
            skauswatch_testkit::jwt::other_signing_key(),
            300,
        ) {
            Ok(t) => t,
            Err(e) => panic!("issue token: {e}"),
        };
        let mut req = tonic::Request::new(());
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        req.metadata_mut().insert("authorization", value);
        assert!(auth(req).is_err());
    }

    #[test]
    fn auth_interceptor_accepts_valid_token() {
        let mut auth = auth_interceptor(skauswatch_testkit::jwt::verify_key().clone());
        let token = match skauswatch_auth::issue_service_token(
            "x",
            "admin",
            skauswatch_testkit::jwt::signing_key(),
            300,
        ) {
            Ok(t) => t,
            Err(e) => panic!("issue token: {e}"),
        };
        let mut req = tonic::Request::new(());
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        req.metadata_mut().insert("authorization", value);
        assert!(auth(req).is_ok());
    }
}
