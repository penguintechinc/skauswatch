//! Dedicated mTLS-required listener for pki's two cross-tenant maintenance
//! operations, `GET /api/v1/expiring` and `POST /api/v1/cleanup`
//! (`crate::routes::common`).
//!
//! CLOSING THE MAINTENANCE GAP (R3-1, `docs/v2-port/service-auth-model.md`
//! §3): those two handlers are deliberately cross-tenant
//! (`docs/v2-port/tenancy-model.md` §6) and, before this module, were
//! enforced only by network topology — "which services can reach pki's
//! REST port" — not a cryptographic check (`ServiceClaims` carries no scope
//! claim to gate on). This module replaces that with a dedicated SPIFFE
//! identity, `spiffe://penguintech.io/<env>/endpoint-agent-maintenance`
//! (see [`maintenance_matcher`]): a caller must complete a full mTLS
//! handshake presenting exactly that SVID before the connection is even
//! accepted — the handshake itself *is* the authorization check, so no
//! separate bearer-token or extractor-level gate is layered on top (unlike
//! `grpc::serve`'s one-release-cycle dual-accept — see that module's docs
//! for why the two pieces made different calls here).
//!
//! These two routes are served **only** here, not on the primary REST
//! listener (`crate::routes::router`) — see that module and
//! `crate::routes::openapi` for the corresponding removals. Leaving them
//! dually reachable via the old bearer-token-only path would make this listener's
//! cryptographic enforcement pointless.
//!
//! FAIL-SAFE: when `AppState::identity` is `None`, or the held
//! [`skauswatch_identity::IdentityProvider`] is degraded (dev/test, no
//! SPIRE agent socket present), this listener does not bind at all —
//! `/api/v1/expiring`/`/api/v1/cleanup` become unreachable until a SPIRE
//! agent is attested, rather than falling back to an unauthenticated
//! plaintext listener the way `grpc::serve` falls back to plaintext-plus-
//! ES256. There is no bearer-token layer to fall back to here, so "serve it
//! anyway" would mean "serve it with no auth at all" — refusing to bind is
//! the safe degrade. Production hard-fails inside `AppStateInner::from_env`
//! instead of ever reaching this fallback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::{get, post};
use axum::serve::Listener;
use skauswatch_identity::{IdentityError, SpiffeId, SpiffeIdError, SpiffeIdMatcher};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::routes::common;
use crate::state::AppState;

/// Default maintenance listener port (`MAINTENANCE_PORT`) — distinct from
/// both the REST (`API_PORT`, 8001) and gRPC (`GRPC_PORT`, 50052) listeners.
const DEFAULT_MAINTENANCE_PORT: u16 = 8011;

/// Resolves the maintenance listen port from `MAINTENANCE_PORT` (default
/// 8011).
pub fn port() -> u16 {
    std::env::var("MAINTENANCE_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_MAINTENANCE_PORT)
}

/// The one caller this listener trusts: the dedicated maintenance/super-
/// admin identity for this deployment's environment
/// (`docs/v2-port/service-auth-model.md` §1's `endpoint-agent-maintenance`
/// row — an operator/CLI identity, not a long-running service; deliberately
/// distinct from `manager`'s SVID, which is not authorized here).
fn maintenance_matcher() -> Result<SpiffeIdMatcher, SpiffeIdError> {
    let env = crate::config::spiffe_env();
    let id = SpiffeId::new(format!(
        "spiffe://penguintech.io/{env}/endpoint-agent-maintenance"
    ))?;
    Ok(SpiffeIdMatcher::new().allow_exact(id))
}

/// The maintenance-only router: exactly the two cross-tenant handlers, no
/// tenant/bearer-token middleware layer — the mTLS peer check performed
/// before a connection is ever accepted (see module docs) is the entire
/// authorization gate for this listener.
fn maintenance_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/expiring", get(common::expiring))
        .route("/api/v1/cleanup", post(common::cleanup))
        .with_state(state)
}

/// [`axum::serve::Listener`] that terminates mTLS on every accepted TCP
/// connection before handing it to axum. A failed handshake (bad/absent/
/// disallowed peer cert) is logged and the accept loop continues rather
/// than tearing down the whole listener — mirroring `axum::serve`'s own
/// `TcpListener` impl, which retries on accept errors instead of
/// propagating them.
struct MtlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl Listener for MtlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.tcp.accept().await {
                Ok((stream, addr)) => match self.acceptor.accept(stream).await {
                    Ok(tls) => return (tls, addr),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            %addr,
                            "pki maintenance mTLS handshake failed"
                        );
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, "pki maintenance accept error");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// Runs the maintenance listener on `addr` until `shutdown` resolves —
/// wired into the same signal as the REST/gRPC servers. See module docs for
/// the fail-safe behavior when no SPIFFE identity is held.
pub async fn serve(
    state: AppState,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    serve_with_ready(state, addr, shutdown, None).await
}

/// Same as [`serve`], but if `ready` is supplied, sends the actual bound
/// address (or, in the "disabled" fallbacks, `addr` itself) through it once
/// known. `serve` is the sole production entry point (always passes
/// `None`); this split exists purely so the tests below can drive a real
/// mTLS handshake against a known address through the *actual* production
/// code path (including [`MtlsListener::accept`]), not a reimplementation
/// of it.
async fn serve_with_ready(
    state: AppState,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ready: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> anyhow::Result<()> {
    let Some(provider) = state.identity.clone() else {
        tracing::warn!(
            %addr,
            "no SPIFFE workload identity held — pki maintenance listener disabled \
             (dev/test only; production hard-fails at startup instead of reaching \
             this fallback). /api/v1/expiring and /api/v1/cleanup are unreachable \
             until a SPIRE agent is attested."
        );
        if let Some(tx) = ready {
            let _ = tx.send(addr);
        }
        shutdown.await;
        return Ok(());
    };

    let matcher = maintenance_matcher()
        .map_err(|e| anyhow::anyhow!("endpoint-agent-maintenance SPIFFE ID: {e}"))?;
    let tls_config = match provider.server_tls_config(&matcher) {
        Ok(cfg) => cfg,
        Err(IdentityError::Degraded) => {
            tracing::warn!(
                %addr,
                "SPIFFE identity degraded — pki maintenance listener disabled (dev/test)"
            );
            if let Some(tx) = ready {
                let _ = tx.send(addr);
            }
            shutdown.await;
            return Ok(());
        }
        Err(e) => return Err(anyhow::anyhow!("pki maintenance mTLS config: {e}")),
    };

    let tcp = TcpListener::bind(addr).await?;
    let bound = tcp.local_addr()?;
    let listener = MtlsListener {
        tcp,
        acceptor: TlsAcceptor::from(Arc::new(tls_config)),
    };
    tracing::info!(
        addr = %bound,
        "pki maintenance listening (mTLS, endpoint-agent-maintenance only)"
    );
    if let Some(tx) = ready {
        let _ = tx.send(bound);
    }
    axum::serve(listener, maintenance_router(state))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)] // tests fail loudly by design
mod tests {
    use axum::http::StatusCode;
    use rustls::pki_types::ServerName;
    use skauswatch_identity::IdentityProvider;
    use skauswatch_identity::testutil::{TestCa, bundle_set, trust_domain};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;
    use crate::state::AppStateInner;

    fn ephemeral_addr() -> SocketAddr {
        ([127, 0, 0, 1], 0).into()
    }

    fn already_shutdown() -> impl std::future::Future<Output = ()> + Send {
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let _ = tx.send(());
        async move {
            let _ = rx.await;
        }
    }

    #[test]
    fn port_defaults_to_8011_when_env_unset() {
        assert!(std::env::var("MAINTENANCE_PORT").is_err());
        assert_eq!(port(), DEFAULT_MAINTENANCE_PORT);
        assert_eq!(DEFAULT_MAINTENANCE_PORT, 8011);
    }

    #[test]
    fn maintenance_matcher_accepts_only_the_maintenance_identity() {
        assert!(
            std::env::var("SPIFFE_ENV").is_err(),
            "test assumes the default SPIFFE_ENV (\"beta\")"
        );
        let matcher = maintenance_matcher().unwrap_or_else(|e| panic!("build matcher: {e}"));
        let id = |s: &str| SpiffeId::new(s).unwrap_or_else(|e| panic!("spiffe id {s}: {e}"));

        assert!(matcher.matches(&id(
            "spiffe://penguintech.io/beta/endpoint-agent-maintenance"
        )));
        // manager is authorized on the gRPC listener, but not here.
        assert!(!matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        // Same workload name, different (federated) trust domain.
        assert!(!matcher.matches(&id(
            "spiffe://customer.example/beta/endpoint-agent-maintenance"
        )));
        // Same trust domain/workload, different env segment.
        assert!(!matcher.matches(&id(
            "spiffe://penguintech.io/gamma/endpoint-agent-maintenance"
        )));
    }

    #[tokio::test]
    async fn serve_disables_the_listener_when_identity_is_none() {
        let state = AppStateInner::for_tests();
        assert!(state.identity.is_none());
        let result = serve(state, ephemeral_addr(), already_shutdown()).await;
        assert!(
            result.is_ok(),
            "serve() should degrade to \"disabled\" cleanly: {result:?}"
        );
    }

    #[tokio::test]
    async fn serve_disables_the_listener_when_identity_is_held_but_degraded() {
        let identity = crate::routes::test_support::degraded_identity();
        let state = AppStateInner::for_tests_with_identity(identity);
        let result = serve(state, ephemeral_addr(), already_shutdown()).await;
        assert!(
            result.is_ok(),
            "serve() should degrade to \"disabled\" cleanly: {result:?}"
        );
    }

    /// End-to-end mTLS handshake test against the *real* `serve()` code
    /// path (via `serve_with_ready`, not a reimplementation): the
    /// `endpoint-agent-maintenance` SVID completes the handshake and its
    /// request reaches the real axum router, while a `manager` SVID from
    /// the same trusted CA never gets past the handshake. Exercises
    /// [`MtlsListener::accept`]'s retry-past-a-rejected-handshake loop for
    /// real — a previously-uncovered path, since the `serve_disables_*`
    /// tests above only reach the identity `None`/degraded fallbacks and
    /// never bind a live listener at all.
    #[tokio::test]
    async fn maintenance_mtls_accepts_maintenance_identity_and_rejects_manager() {
        let ca = TestCa::generate();
        let td = trust_domain("penguintech.io");
        let server_svid = ca.issue_leaf("spiffe://penguintech.io/beta/endpoint-agent-maintenance");
        let allowed_client_svid =
            ca.issue_leaf("spiffe://penguintech.io/beta/endpoint-agent-maintenance");
        let disallowed_client_svid = ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let bundles = bundle_set(&[(&td, &ca)]);

        let server_identity = IdentityProvider::from_svid_for_test(server_svid, bundles.clone());
        let state = AppStateInner::for_tests_with_identity(Arc::new(server_identity));

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

        // Disallowed peer: right CA, wrong SPIFFE ID (manager, not the
        // maintenance identity) — must not be surfaced as an accepted
        // connection by `MtlsListener::accept`; its retry loop must keep
        // running instead of tearing the listener down.
        let disallowed_provider =
            IdentityProvider::from_svid_for_test(disallowed_client_svid, bundles.clone());
        let disallowed_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());
        let disallowed_cfg = disallowed_provider
            .client_tls_config(&disallowed_allowed)
            .unwrap_or_else(|e| panic!("client tls config: {e}"));
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect: {e}"));
        let name =
            ServerName::try_from("pki.invalid").unwrap_or_else(|e| panic!("server name: {e}"));
        match tokio_rustls::TlsConnector::from(Arc::new(disallowed_cfg))
            .connect(name, stream)
            .await
        {
            Err(_) => {}
            Ok(mut tls) => {
                // TLS 1.3: a client's connect() can resolve `Ok` before it
                // learns the server rejected its certificate — a
                // post-handshake read surfaces the rejection (see
                // skauswatch_identity's tls.rs test docs for the same
                // caveat).
                let mut buf = [0u8; 1];
                assert!(
                    tls.read(&mut buf).await.is_err(),
                    "manager SVID's connection must not survive past the handshake"
                );
            }
        }

        // Allowed peer: the maintenance identity — the handshake must
        // complete and the request must reach the real axum router.
        let allowed_provider =
            IdentityProvider::from_svid_for_test(allowed_client_svid, bundles.clone());
        let allowed_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());
        let allowed_cfg = allowed_provider
            .client_tls_config(&allowed_allowed)
            .unwrap_or_else(|e| panic!("client tls config: {e}"));
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect: {e}"));
        let name =
            ServerName::try_from("pki.invalid").unwrap_or_else(|e| panic!("server name: {e}"));
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(allowed_cfg))
            .connect(name, stream)
            .await
            .unwrap_or_else(|e| {
                panic!("endpoint-agent-maintenance SVID must complete the mTLS handshake: {e}")
            });

        // `type=unrecognized` short-circuits before touching the DB (see
        // `expiring_touches_db_for_x509_ssh_and_all_types` above), so this
        // proves the HTTP layer was reached without depending on a real
        // database connection.
        tls.write_all(b"GET /api/v1/expiring?days=7&type=unrecognized HTTP/1.1\r\nHost: pki.invalid\r\nConnection: close\r\n\r\n")
            .await
            .unwrap_or_else(|e| panic!("write request: {e}"));
        let mut response = Vec::new();
        tls.read_to_end(&mut response)
            .await
            .unwrap_or_else(|e| panic!("read response: {e}"));
        let response = String::from_utf8_lossy(&response);
        assert!(
            response.starts_with("HTTP/1.1 200"),
            "expected a 200 response over the accepted mTLS connection, got: {response}"
        );

        let _ = shutdown_tx.send(());
        tokio::time::timeout(std::time::Duration::from_secs(5), serve_task)
            .await
            .unwrap_or_else(|e| panic!("serve() did not shut down in time: {e}"))
            .unwrap_or_else(|e| panic!("serve task join: {e}"))
            .unwrap_or_else(|e| panic!("serve() returned an error: {e}"));
    }

    // ===================== router-level handler tests =====================
    //
    // No Authorization header on any request below — this router has no
    // bearer-token layer at all (see module docs); `axum_test::TestServer`
    // exercises the router in-process, so these need no real TLS handshake.

    fn test_server() -> axum_test::TestServer {
        axum_test::TestServer::new(maintenance_router(AppStateInner::for_tests()))
    }

    #[tokio::test]
    async fn expiring_touches_db_for_x509_ssh_and_all_types() {
        let server = test_server();
        for cert_type in ["x509", "ssh", "all", "unrecognized"] {
            let res = server
                .get("/api/v1/expiring")
                .add_query_param("days", "7")
                .add_query_param("type", cert_type)
                .await;
            if cert_type == "unrecognized" {
                res.assert_status_ok();
                let body: serde_json::Value = res.json();
                assert_eq!(body["expiring_within_days"], 7);
            } else {
                res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    }

    #[tokio::test]
    async fn cleanup_touches_db_and_500s() {
        let server = test_server();
        let res = server.post("/api/v1/cleanup").await;
        res.assert_status(StatusCode::INTERNAL_SERVER_ERROR);
    }

    async fn db_server_and_state() -> (axum_test::TestServer, AppState) {
        let state = crate::routes::test_support::db_state().await;
        (
            axum_test::TestServer::new(maintenance_router(state.clone())),
            state,
        )
    }

    #[tokio::test]
    async fn expiring_lists_real_x509_and_ssh_rows() {
        let (server, state) = db_server_and_state().await;
        state
            .manager
            .issue_x509(
                crate::ca::x509::X509IssueParams {
                    subject: "CN=maintenance-expiring.example.com".into(),
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
                },
                None,
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();

        let x509_res = server
            .get("/api/v1/expiring")
            .add_query_param("days", "60")
            .add_query_param("type", "x509")
            .await;
        x509_res.assert_status_ok();
        let x509_body: serde_json::Value = x509_res.json();
        assert!(!x509_body["x509"].as_array().unwrap().is_empty());
        assert!(x509_body["ssh"].as_array().unwrap().is_empty());

        // ssh_config's default validity is 86400s (1 day) — a 2-day window
        // catches a freshly-issued cert without needing to seed a row.
        let pubkey_path = std::env::temp_dir().join(format!(
            "skauswatch-pki-maintenance-expiring-subject-{}",
            uuid::Uuid::new_v4()
        ));
        assert!(
            std::process::Command::new("ssh-keygen")
                .arg("-t")
                .arg("ed25519")
                .arg("-f")
                .arg(&pubkey_path)
                .arg("-N")
                .arg("")
                .arg("-q")
                .status()
                .unwrap()
                .success()
        );
        let pubkey = std::fs::read_to_string(format!("{}.pub", pubkey_path.display())).unwrap();
        state
            .manager
            .issue_ssh(
                crate::ca::ssh::SshIssueParams {
                    public_key: pubkey,
                    certificate_type: "user".into(),
                    key_id: None,
                    principals: vec!["alice".into()],
                    validity_seconds: 86_400,
                    extensions: None,
                    critical_options: None,
                    source_addresses: vec![],
                    force_command: None,
                    hostname: None,
                },
                None,
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();

        let all_res = server
            .get("/api/v1/expiring")
            .add_query_param("days", "2")
            .add_query_param("type", "all")
            .await;
        all_res.assert_status_ok();
        let all_body: serde_json::Value = all_res.json();
        assert!(!all_body["ssh"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn cleanup_marks_real_expired_rows() {
        let (server, state) = db_server_and_state().await;
        sqlx::query(
            "INSERT INTO x509_certificates \
             (id, tenant_id, serial_number, subject, issuer, not_before, not_after, \
              key_algorithm, signature_algorithm, fingerprint_sha256, certificate_pem, san_dns, \
              san_ip, san_email, key_usage, extended_key_usage, is_ca, status, metadata, \
              created_at, updated_at) \
             VALUES ($1,$2,'expired-maint-1','CN=expired','CN=expired', \
              now() - interval '400 days', now() - interval '1 day', 'RSA','SHA256', \
              'deadbeef','PEM','{}','{}','{}','{}','{}',false,'active','{}'::jsonb,now(),now())",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(uuid::Uuid::new_v4())
        .execute(state.manager.db())
        .await
        .unwrap();

        let res = server.post("/api/v1/cleanup").await;
        res.assert_status_ok();
        let body: serde_json::Value = res.json();
        assert!(body["updated_count"].as_i64().unwrap() >= 1);
    }
}
