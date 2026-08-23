//! Mesh-only mTLS admin listener — depgate's SPIFFE-readiness surface for
//! the admin/report API (`security.md`/`backend.md`: every service is
//! SPIFFE-ready, accepting an mTLS/X.509-SVID identity as a first-class
//! auth mechanism even where SPIRE isn't deployed yet). This listener is
//! **additive**, not a replacement: the existing JWT/tenant-scoped admin
//! routes (`crate::routes::admin`, `/api/v1/depgate/*` on the primary
//! `API_PORT` listener) are untouched. A trusted mesh peer now has a second,
//! cryptographic way to reach depgate's reporting surface — an SVID
//! identity accepted *alongside* the existing bearer-JWT path, not instead
//! of it — mirroring `services/pki/src/maintenance.rs`'s dedicated
//! mTLS-listener pattern.
//!
//! WHY A SEPARATE PORT, NOT A DUAL-ACCEPT ON THE EXISTING LISTENER: mTLS is
//! negotiated at the TCP/TLS layer, before any HTTP routing decision is
//! possible, so "require mTLS for `/api/v1/depgate/*` but not `/v2/*`" can't
//! be expressed on one shared listener/port. Terminating mTLS on the whole
//! `API_PORT` listener (the way `services/manager/src/grpc/mod.rs::serve`
//! does for its all-internal gRPC surface) would also gate the `/v2/*` OCI
//! proxy — wrong here, since its callers are `docker`/`npm` clients, not
//! mesh peers, and cannot present a workload SVID. `/v2/*` is therefore
//! deliberately **not** reachable on this listener at all and keeps its
//! existing JWT/tenant-scoped auth unchanged (`crate::routes` module docs).
//!
//! WHY CROSS-TENANT: the JWT-gated admin handlers
//! (`crate::routes::admin::{list_artifacts,list_quarantine,stats}`) scope
//! every query to the caller's own `tenant` JWT claim — there is no such
//! claim to read from an SVID-authenticated service caller, only a
//! workload identity. Rather than inventing a way to trust an unauthenticated
//! tenant parameter from a service caller (`security.md`: never trust a
//! tenant id from a request body/param), this listener exposes a distinct,
//! deliberately fleet-wide summary (`GET /api/v1/depgate/mesh/stats`) for a
//! trusted mesh peer doing cross-tenant aggregation/reporting — the same
//! "deliberately cross-tenant" posture `services/pki/src/maintenance.rs`
//! documents for its `expiring`/`cleanup` ops.
//!
//! MATCHER: `spiffe://penguintech.io/<env>/depgate` is this workload's own
//! reserved SPIFFE ID (`docs/v2-port/service-auth-model.md` §1); the peer
//! matcher below allows any workload in this deployment's own trust
//! domain/environment. There is no real caller of this surface yet
//! (confirmed by repo-wide grep, same as `services/manager`'s gRPC RPCs), so
//! a broad same-trust-domain allow avoids over-fitting a matcher to a caller
//! that doesn't exist yet — narrow to a specific identity once a real caller
//! is implemented, mirroring `services/manager/src/grpc/mod.rs::same_env_matcher`'s
//! documented rationale.
//!
//! FAIL-SAFE: when `AppState::identity` is `None`, or the held
//! [`skauswatch_identity::IdentityProvider`] is degraded (dev/test, no SPIRE
//! agent socket present), this listener does not bind at all — the mesh
//! summary becomes unreachable until a SPIRE agent is attested, rather than
//! falling back to an unauthenticated plaintext listener. There is no
//! bearer-token layer to fall back to here (this endpoint has no tenant
//! scope to gate on), so "serve it anyway" would mean "serve fleet-wide data
//! with no auth at all" — refusing to bind is the safe degrade. Production
//! hard-fails inside `AppStateInner::from_env` instead of ever reaching this
//! fallback.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::routing::get;
use axum::serve::Listener;
use serde::Serialize;
use skauswatch_identity::{IdentityError, SpiffeIdError, SpiffeIdMatcher, TrustDomain};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

use crate::error::ApiError;
use crate::state::AppState;

/// Default mesh admin listen port — distinct from both `API_PORT` (5050,
/// OCI proxy + JWT-gated admin API) and `metricsPort` (9090).
const DEFAULT_MESH_ADMIN_PORT: u16 = 5051;

/// Resolves the mesh admin listen port from `MESH_ADMIN_PORT` (default
/// 5051).
pub fn port() -> u16 {
    std::env::var("MESH_ADMIN_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_MESH_ADMIN_PORT)
}

/// Any workload in this deployment's own trust domain/environment — see
/// module docs for why this starts broad rather than narrowed to a specific
/// caller.
fn mesh_matcher() -> Result<SpiffeIdMatcher, SpiffeIdError> {
    let env = crate::config::spiffe_env();
    let td = TrustDomain::new("penguintech.io")?;
    Ok(SpiffeIdMatcher::new().allow_path_prefix(td, format!("/{env}")))
}

/// Fleet-wide (cross-tenant) verdict counts and quarantine total — see
/// module docs for why this is a distinct, deliberately unscoped summary
/// rather than the tenant-scoped `crate::routes::admin::stats` handler.
#[derive(Serialize)]
struct MeshStatsResponse {
    by_verdict: HashMap<String, i64>,
    quarantine_count: i64,
}

async fn mesh_stats(
    State(state): State<AppState>,
) -> Result<axum::Json<MeshStatsResponse>, ApiError> {
    let by_verdict = crate::db::verdict_counts_all_tenants(&state.db)
        .await?
        .into_iter()
        .collect();
    let quarantine_count = crate::db::quarantine_count_all_tenants(&state.db).await?;
    Ok(axum::Json(MeshStatsResponse {
        by_verdict,
        quarantine_count,
    }))
}

/// The mesh-only router: exactly the one cross-tenant summary handler, no
/// tenant/bearer-token middleware layer at all — the mTLS peer check
/// performed before a connection is ever accepted (see module docs) is the
/// entire authorization gate for this listener.
fn mesh_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/depgate/mesh/stats", get(mesh_stats))
        .with_state(state)
}

/// [`axum::serve::Listener`] that terminates mTLS on every accepted TCP
/// connection before handing it to axum. A failed handshake (bad/absent/
/// disallowed peer cert) is logged and the accept loop continues rather than
/// tearing down the whole listener — mirrors
/// `services/pki/src/maintenance.rs`'s identical helper.
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
                            "depgate mesh admin mTLS handshake failed"
                        );
                    }
                },
                Err(e) => {
                    tracing::error!(error = %e, "depgate mesh admin accept error");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// Runs the mesh admin listener on `addr` until `shutdown` resolves — wired
/// into the same signal as the main REST server. See module docs for the
/// fail-safe behavior when no SPIFFE identity is held.
pub async fn serve(
    state: AppState,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    serve_with_ready(state, addr, shutdown, None).await
}

/// Same as [`serve`], but if `ready` is supplied, sends the actual bound
/// address (or, in the "disabled" fallbacks, `addr` itself) through it once
/// known. `serve` is the sole production entry point (always passes `None`);
/// this split exists purely so the tests below can drive a real mTLS
/// handshake against a known address through the *actual* production code
/// path, mirroring `services/pki/src/maintenance.rs`'s identical seam.
async fn serve_with_ready(
    state: AppState,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
    ready: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> anyhow::Result<()> {
    let Some(provider) = state.identity.clone() else {
        tracing::warn!(
            %addr,
            "no SPIFFE workload identity held — depgate mesh admin listener disabled \
             (dev/test only; production hard-fails at startup instead of reaching this \
             fallback). GET /api/v1/depgate/mesh/stats is unreachable until a SPIRE agent \
             is attested."
        );
        if let Some(tx) = ready {
            let _ = tx.send(addr);
        }
        shutdown.await;
        return Ok(());
    };

    let matcher =
        mesh_matcher().map_err(|e| anyhow::anyhow!("depgate mesh admin SPIFFE matcher: {e}"))?;
    let tls_config = match provider.server_tls_config(&matcher) {
        Ok(cfg) => cfg,
        Err(IdentityError::Degraded) => {
            tracing::warn!(
                %addr,
                "SPIFFE identity degraded — depgate mesh admin listener disabled (dev/test)"
            );
            if let Some(tx) = ready {
                let _ = tx.send(addr);
            }
            shutdown.await;
            return Ok(());
        }
        Err(e) => return Err(anyhow::anyhow!("depgate mesh admin mTLS config: {e}")),
    };

    let tcp = TcpListener::bind(addr).await?;
    let bound = tcp.local_addr()?;
    let listener = MtlsListener {
        tcp,
        acceptor: TlsAcceptor::from(Arc::new(tls_config)),
    };
    tracing::info!(addr = %bound, "depgate mesh admin listening (mTLS, same-trust-domain)");
    if let Some(tx) = ready {
        let _ = tx.send(bound);
    }
    axum::serve(listener, mesh_router(state))
        .with_graceful_shutdown(shutdown)
        .await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)] // tests fail loudly by design
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

    async fn test_pool() -> sqlx::PgPool {
        skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")).await
    }

    fn dev_license() -> std::sync::Arc<penguin_licensing::LicenseClient> {
        skauswatch_testkit::license::dev_license("skauswatch")
    }

    #[test]
    fn port_defaults_to_5051_when_env_unset() {
        assert!(std::env::var("MESH_ADMIN_PORT").is_err());
        assert_eq!(port(), DEFAULT_MESH_ADMIN_PORT);
        assert_eq!(DEFAULT_MESH_ADMIN_PORT, 5051);
    }

    #[test]
    fn mesh_matcher_accepts_same_env_and_rejects_other_env_or_trust_domain() {
        assert!(
            std::env::var("SPIFFE_ENV").is_err(),
            "test assumes the default SPIFFE_ENV (\"beta\")"
        );
        let matcher = mesh_matcher().unwrap_or_else(|e| panic!("build matcher: {e}"));
        let id = |s: &str| {
            skauswatch_identity::SpiffeId::new(s).unwrap_or_else(|e| panic!("spiffe id {s}: {e}"))
        };

        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/depgate")));
        // Different (federated) trust domain.
        assert!(!matcher.matches(&id("spiffe://customer.example/beta/manager")));
        // Same trust domain, different env segment.
        assert!(!matcher.matches(&id("spiffe://penguintech.io/gamma/manager")));
    }

    #[tokio::test]
    async fn serve_disables_the_listener_when_identity_is_none() {
        let pool = test_pool().await;
        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        assert!(state.identity.is_none());
        let result = serve(state, ephemeral_addr(), already_shutdown()).await;
        assert!(
            result.is_ok(),
            "serve() should degrade to \"disabled\" cleanly: {result:?}"
        );
    }

    #[tokio::test]
    async fn serve_disables_the_listener_when_identity_is_held_but_degraded() {
        let pool = test_pool().await;
        let identity = std::sync::Arc::new(IdentityProvider::degraded_for_test());
        let state = AppStateInner::for_tests_with_identity(pool, dev_license(), identity);
        let result = serve(state, ephemeral_addr(), already_shutdown()).await;
        assert!(
            result.is_ok(),
            "serve() should degrade to \"disabled\" cleanly: {result:?}"
        );
    }

    /// End-to-end mTLS handshake test against the *real* `serve()` code path
    /// (via `serve_with_ready`, not a reimplementation): a same-trust-domain
    /// SVID completes the handshake and its request reaches the real axum
    /// router with real cross-tenant data, while a federated (different
    /// trust domain) SVID from a different CA never gets past the
    /// handshake. Exercises [`MtlsListener::accept`]'s retry-past-a-
    /// rejected-handshake loop for real.
    #[tokio::test]
    async fn mesh_admin_mtls_accepts_same_domain_and_rejects_federated_peer() {
        let pool = test_pool().await;
        let tenant_a = uuid::Uuid::new_v4();
        let tenant_b = uuid::Uuid::new_v4();
        crate::db::upsert_artifact(
            &pool,
            &crate::db::UpsertArtifact {
                ecosystem: "oci",
                name: "library/nginx",
                reference: "latest",
                sha256: "deadbeefcafebabe",
                upstream: "https://registry-1.docker.io",
                content_type: Some("application/vnd.oci.image.manifest.v1+json"),
                size_bytes: 42,
                verdict: "clean",
                scanner_version: "test",
                pinned: false,
                tenant_id: tenant_a,
            },
        )
        .await
        .expect("seed artifact tenant a");
        crate::db::upsert_artifact(
            &pool,
            &crate::db::UpsertArtifact {
                ecosystem: "oci",
                name: "library/redis",
                reference: "latest",
                sha256: "0ther5ha256",
                upstream: "https://registry-1.docker.io",
                content_type: Some("application/vnd.oci.image.manifest.v1+json"),
                size_bytes: 42,
                verdict: "clean",
                scanner_version: "test",
                pinned: false,
                tenant_id: tenant_b,
            },
        )
        .await
        .expect("seed artifact tenant b");

        let ca = TestCa::generate();
        let td = trust_domain("penguintech.io");
        let server_svid = ca.issue_leaf("spiffe://penguintech.io/beta/depgate");
        let allowed_client_svid = ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let bundles = bundle_set(&[(&td, &ca)]);

        let server_identity = IdentityProvider::from_svid_for_test(server_svid, bundles.clone());
        let state =
            AppStateInner::for_tests_with_identity(pool, dev_license(), Arc::new(server_identity));

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

        // Disallowed peer: a different CA entirely (federated trust domain)
        // — must not be surfaced as an accepted connection by
        // `MtlsListener::accept`; its retry loop must keep running instead
        // of tearing the listener down.
        let other_ca = TestCa::generate();
        let other_td = trust_domain("customer.example");
        let disallowed_client_svid = other_ca.issue_leaf("spiffe://customer.example/beta/manager");
        let disallowed_provider =
            IdentityProvider::from_svid_for_test(disallowed_client_svid, bundles.clone());
        let disallowed_allowed = SpiffeIdMatcher::new().allow_trust_domain(other_td);
        let disallowed_cfg = disallowed_provider
            .client_tls_config(&disallowed_allowed)
            .unwrap_or_else(|e| panic!("client tls config: {e}"));
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .unwrap_or_else(|e| panic!("tcp connect: {e}"));
        let name =
            ServerName::try_from("depgate.invalid").unwrap_or_else(|e| panic!("server name: {e}"));
        match tokio_rustls::TlsConnector::from(Arc::new(disallowed_cfg))
            .connect(name, stream)
            .await
        {
            Err(_) => {}
            Ok(mut tls) => {
                // TLS 1.3: a client's connect() can resolve `Ok` before it
                // learns the server rejected its certificate — a
                // post-handshake read surfaces the rejection.
                let mut buf = [0u8; 1];
                assert!(
                    tls.read(&mut buf).await.is_err(),
                    "federated SVID's connection must not survive past the handshake"
                );
            }
        }

        // Allowed peer: same trust domain — the handshake must complete and
        // the request must reach the real axum router with real cross-tenant
        // aggregated data.
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
            ServerName::try_from("depgate.invalid").unwrap_or_else(|e| panic!("server name: {e}"));
        let mut tls = tokio_rustls::TlsConnector::from(Arc::new(allowed_cfg))
            .connect(name, stream)
            .await
            .unwrap_or_else(|e| panic!("manager SVID must complete the mTLS handshake: {e}"));

        tls.write_all(
            b"GET /api/v1/depgate/mesh/stats HTTP/1.1\r\nHost: depgate.invalid\r\nConnection: close\r\n\r\n",
        )
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
        // Cross-tenant: both tenant_a's and tenant_b's artifacts show up in
        // one fleet-wide count, proving this handler is not tenant-scoped.
        assert!(
            response.contains("\"clean\":2"),
            "expected the fleet-wide count to include both tenants' artifacts, got: {response}"
        );

        let _ = shutdown_tx.send(());
        tokio::time::timeout(std::time::Duration::from_secs(5), serve_task)
            .await
            .unwrap_or_else(|e| panic!("serve() did not shut down in time: {e}"))
            .unwrap_or_else(|e| panic!("serve task join: {e}"))
            .unwrap_or_else(|e| panic!("serve() returned an error: {e}"));
    }

    // ===================== router-level handler test =====================
    //
    // No mTLS handshake needed here — `axum_test::TestServer` exercises the
    // router in-process; this only proves the handler itself aggregates
    // across tenants correctly, independent of the transport-level mTLS
    // gate exercised above.

    #[tokio::test]
    async fn mesh_stats_aggregates_across_tenants() {
        let pool = test_pool().await;
        let tenant_a = uuid::Uuid::new_v4();
        let tenant_b = uuid::Uuid::new_v4();
        crate::db::upsert_artifact(
            &pool,
            &crate::db::UpsertArtifact {
                ecosystem: "oci",
                name: "library/nginx",
                reference: "latest",
                sha256: "deadbeefcafebabe",
                upstream: "https://registry-1.docker.io",
                content_type: Some("application/vnd.oci.image.manifest.v1+json"),
                size_bytes: 42,
                verdict: "infected",
                scanner_version: "test",
                pinned: false,
                tenant_id: tenant_a,
            },
        )
        .await
        .expect("seed artifact tenant a");
        crate::db::insert_quarantine(
            &pool,
            &crate::db::QuarantineInsert {
                sha256: "badbad",
                ecosystem: "oci",
                name: "library/malicious",
                reference: "latest",
                reason: "infected",
                threat: "infected",
                policy_rule_id: None,
                tenant_id: tenant_b,
            },
        )
        .await
        .expect("seed quarantine tenant b");

        let state = AppStateInner::for_tests_with_db(pool, dev_license());
        let server = axum_test::TestServer::new(mesh_router(state));
        let res = server.get("/api/v1/depgate/mesh/stats").await;
        res.assert_status(StatusCode::OK);
        let body: serde_json::Value = res.json();
        assert_eq!(body["by_verdict"]["infected"], 1);
        assert_eq!(body["quarantine_count"], 1);
    }
}
