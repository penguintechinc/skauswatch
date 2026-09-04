//! v1-parity gRPC control plane (tonic). Serves `skauswatch.manager`
//! (7 live RPCs + UNIMPLEMENTED stubs) and `skauswatch.s3scan` on
//! `GRPC_PORT` (default 50051, `GRPC_ENABLED` default true). Contract:
//! docs/v2-port/manager-contract.md §gRPC; Python source of truth:
//! services/manager/grpc/{server,s3_scan_server}.py.
//!
//! AUTH (hardened, finding #3; ES256 per audit finding H1b): every
//! implemented business RPC now requires `authorization: Bearer <jwt>`
//! metadata — an ES256 access token verifiable with the shared
//! `JWT_VERIFY_KEY` (`skauswatch_auth::verify_grpc_bearer`).
//! `HealthCheck` stays open (liveness/readiness probes, no sensitive data,
//! not in the audit's gated-method list). Dead/UNIMPLEMENTED stub RPCs are
//! unauthenticated too — they do no work regardless of the caller. No
//! in-repo caller exists for either service today (confirmed by repo-wide
//! grep: ENDPOINT agents authenticate via the REST HMAC gate only, and workers
//! consume `s3scan:tasks`/publish results over Redis Streams, never gRPC) —
//! gating introduces no breakage; any future caller must present a machine
//! JWT minted with `skauswatch_auth::issue_service_token`.
//!
//! TRANSPORT AUTH (R2c-2, `docs/v2-port/service-auth-model.md` §2): when
//! `AppState::identity` holds an attested SPIFFE X.509-SVID, this listener
//! additionally requires full mutual TLS — manager presents its own SVID
//! over the wire and accepts only a peer within this deployment's own
//! trust domain/environment (see [`same_env_matcher`]; the design doc's §1
//! deliberately keeps this broad rather than narrowed to specific callers,
//! since every RPC here has zero real callers today). This is *additive*
//! to, not a replacement for, the per-RPC `require_jwt` gate above: for one
//! release cycle both a valid client certificate *and* a valid ES256
//! bearer token are required (dual-accept — see
//! `docs/v2-port/service-auth-model.md`'s §2 "Transition plan"; a later
//! pass deletes the bearer-token layer entirely once mTLS is confirmed healthy in
//! beta). When no identity is held — `AppState::identity` is `None`, or the
//! SPIFFE Workload API attested but degraded (dev/test, no SPIRE agent
//! socket present) — the listener falls back to plaintext with
//! `require_jwt` as the sole gate, exactly as before this change.
//! Production hard-fails inside `AppStateInner::from_env` instead of ever
//! reaching this fallback (see `skauswatch_identity`'s fail-safe policy).
//!
//! API VERSIONING: every request message (except HealthCheck's
//! `google.protobuf.Empty`) carries `api_version`. Fielded v1 Go agents
//! predate the field and send nothing — proto3 decodes that as `""` —
//! so `skauswatch_proto::is_v1` accepts both `""` and `"v1"`; anything
//! else gets UNIMPLEMENTED `api_version {v} not supported`.

mod manager_service;
mod pki_client;
mod s3_scan_service;
pub(crate) mod spire_entry;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::Status;

use skauswatch_identity::{IdentityError, SpiffeIdError, SpiffeIdMatcher, TrustDomain};

use crate::state::AppState;

/// Default gRPC port — parity with v1 (`GRPC_PORT`, default 50051).
const DEFAULT_GRPC_PORT: u16 = 50051;

/// Whether the gRPC server should run — v1 `GRPC_ENABLED` semantics:
/// enabled unless the env var (lowercased) is anything other than "true".
pub fn enabled() -> bool {
    enabled_from(std::env::var("GRPC_ENABLED").ok().as_deref())
}

/// Pure form of [`enabled`] for tests.
fn enabled_from(raw: Option<&str>) -> bool {
    raw.map(|v| v.to_lowercase() == "true").unwrap_or(true)
}

/// Resolves the gRPC listen port from `GRPC_PORT` (default 50051).
pub fn port() -> u16 {
    port_from(std::env::var("GRPC_PORT").ok().as_deref())
}

/// Pure form of [`port`] for tests.
fn port_from(raw: Option<&str>) -> u16 {
    raw.and_then(|p| p.parse().ok())
        .unwrap_or(DEFAULT_GRPC_PORT)
}

/// Any workload in this deployment's own trust domain/environment
/// (`docs/v2-port/service-auth-model.md` §1's who-calls-whom allowlist for
/// `ManagerService`/`S3ScanService`): these RPCs have zero real callers
/// today (confirmed by repo-wide grep), so a broad same-trust-domain allow
/// avoids over-fitting a matcher to callers that don't exist yet — narrow
/// to specific identities once a real caller is implemented (tracked as an
/// R3 follow-up, not blocking).
fn same_env_matcher() -> Result<SpiffeIdMatcher, SpiffeIdError> {
    let env = crate::state::spiffe_env();
    let td = TrustDomain::new("penguintech.io")?;
    Ok(SpiffeIdMatcher::new().allow_path_prefix(td, format!("/{env}")))
}

/// Wraps `listener` in a mTLS-terminating stream for
/// `tonic::transport::Server::serve_with_incoming_shutdown`: each accepted
/// TCP connection is handshaked against `tls_config` before being handed to
/// tonic. A failed handshake (bad/absent/disallowed peer cert) is logged and
/// the accept loop continues rather than tearing down the whole listener —
/// mirrors `services/pki/src/grpc/mod.rs`'s identical helper.
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

/// Runs the tonic server (ManagerService + S3ScanService) on 0.0.0.0:{port}
/// until `shutdown` resolves — wired into the same signal as the REST server.
pub async fn serve(
    state: AppState,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> anyhow::Result<()> {
    let addr: SocketAddr = ([0, 0, 0, 0], port()).into();
    serve_with_ready(state, addr, shutdown, None).await
}

/// Same as [`serve`], but if `ready` is supplied, sends the actual bound
/// address through it once the listener is up — lets tests drive a real
/// mTLS handshake against a known (OS-assigned) address through the *actual*
/// production code path, mirroring `services/pki/src/grpc/mod.rs`'s
/// identical test seam. `serve` is the sole production entry point (always
/// passes `None`).
async fn serve_with_ready(
    state: AppState,
    addr: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send,
    ready: Option<tokio::sync::oneshot::Sender<SocketAddr>>,
) -> anyhow::Result<()> {
    use skauswatch_proto::manager::manager_service_server::ManagerServiceServer;
    use skauswatch_proto::s3scan::s3_scan_service_server::S3ScanServiceServer;

    let identity = state.identity.clone();
    let router = tonic::transport::Server::builder()
        .add_service(ManagerServiceServer::new(
            manager_service::ManagerGrpc::new(state.clone()),
        ))
        .add_service(S3ScanServiceServer::new(s3_scan_service::S3ScanGrpc::new(
            state,
        )));

    let tls_config = match &identity {
        Some(provider) => {
            let matcher = same_env_matcher()
                .map_err(|e| anyhow::anyhow!("manager gRPC mTLS matcher: {e}"))?;
            match provider.server_tls_config(&matcher) {
                Ok(cfg) => Some(cfg),
                Err(IdentityError::Degraded) => None,
                Err(e) => return Err(anyhow::anyhow!("manager gRPC mTLS config: {e}")),
            }
        }
        None => None,
    };

    match tls_config {
        Some(cfg) => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            let bound = listener.local_addr()?;
            tracing::info!(
                addr = %bound,
                "manager gRPC listening (mTLS, same-trust-domain + ES256 bearer)"
            );
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
                "no SPIFFE workload identity held — manager gRPC serving plaintext \
                 (dev/test only; per-RPC ES256 bearer auth is still required; \
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

/// Requires a valid `authorization: Bearer <jwt>` gRPC metadata entry,
/// signed with the shared `JWT_SECRET_KEY` (finding #3). Maps verification
/// failure onto `UNAUTHENTICATED` via `skauswatch_auth::ServiceTokenError`'s
/// `From<_> for tonic::Status` impl.
fn require_jwt(
    metadata: &tonic::metadata::MetadataMap,
    verify_key: &jsonwebtoken::DecodingKey,
) -> Result<(), Status> {
    skauswatch_auth::verify_grpc_bearer(metadata, verify_key)?;
    Ok(())
}

/// Routes a request-carried `api_version` per the backend API standard:
/// `""`/`"v1"` → v1 handler; anything else → UNIMPLEMENTED with message
/// exactly `api_version {v} not supported`.
fn check_api_version(v: &str) -> Result<(), Status> {
    if skauswatch_proto::is_v1(v) {
        Ok(())
    } else {
        Err(Status::unimplemented(format!(
            "api_version {v} not supported"
        )))
    }
}

/// Extracts and validates the `x-tenant-id` gRPC metadata entry per
/// docs/v2-port/tenancy-model.md §3 (mirrors the pki/sshca `x-tenant-id`/
/// `X-Tenant-ID` contract): stamped by the calling *service*, never an end
/// client, and required on every task-dispatching RPC this surface exposes.
/// `UNAUTHENTICATED` if absent, empty, or not a valid UUID — this crate's
/// gRPC surface has zero in-repo callers today (see module docs above), so
/// this only takes effect once a future caller adopts the contract, but the
/// surface must never silently accept an untenanted task in the meantime.
pub(crate) fn require_tenant_metadata(
    metadata: &tonic::metadata::MetadataMap,
) -> Result<uuid::Uuid, Status> {
    let raw = metadata
        .get("x-tenant-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Status::unauthenticated("missing x-tenant-id metadata"))?;
    raw.parse()
        .map_err(|_| Status::unauthenticated("invalid x-tenant-id metadata"))
}

/// Dead-RPC response — v1's grpcio servicer base class answered every
/// unimplemented method with UNIMPLEMENTED "Method not implemented!"
/// before parsing the request, so no api_version routing applies here.
fn method_not_implemented() -> Status {
    Status::unimplemented("Method not implemented!")
}

/// Converts a Postgres naive-UTC timestamp into the protobuf Timestamp the
/// v1 servicer produced via `Timestamp.FromDatetime` (naive treated as UTC).
fn ts_from_naive(t: chrono::NaiveDateTime) -> prost_types::Timestamp {
    let utc = t.and_utc();
    prost_types::Timestamp {
        seconds: utc.timestamp(),
        nanos: utc.timestamp_subsec_nanos() as i32,
    }
}

/// Protobuf Timestamp for "now" (v1 `FromDatetime(datetime.utcnow())`).
fn now_ts() -> prost_types::Timestamp {
    ts_from_naive(chrono::Utc::now().naive_utc())
}

/// Maps a DB failure onto INTERNAL. v1's grpc.aio surfaced unhandled DB
/// exceptions as non-OK statuses too; the exact code was never contractual.
/// The real cause is logged server-side; the caller gets a generic message
/// so sqlx internals (constraint/column names, query context) never leak.
fn db_err(e: sqlx::Error) -> Status {
    tracing::error!(error = %e, "manager gRPC database error");
    Status::internal("Internal Server Error")
}

#[cfg(test)]
#[allow(clippy::panic)] // test helpers fail loudly by design
pub(crate) mod test_util {
    use std::path::Path;
    use std::sync::Arc;

    use penguin_licensing::{LicenseClient, LicenseConfig};

    use crate::state::{AppState, AppStateInner};

    /// Test AppState: unreachable lazy DB pool, no stream producer —
    /// exercises validation/routing/status layers without infrastructure.
    pub(crate) fn test_state() -> AppState {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        AppStateInner::for_tests(client)
    }

    /// Test AppState backed by a real, migrated Postgres pool holding this
    /// service's own tables — for RPC success paths that issue real queries
    /// (`ManagerService`: alerts/threat_indicators/audit_logs).
    pub(crate) async fn db_state() -> AppState {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client: Arc<LicenseClient> = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        let pool =
            skauswatch_testkit::db::test_pool(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations"))
                .await;
        AppStateInner::for_tests_with_db(client, pool)
    }

    /// Like [`db_state`] but also layers in `services/s3scan`'s migrations —
    /// `S3ScanService` RPCs query `s3_scan_jobs`/`s3_scan_results`/
    /// `adhoc_scan_results`, tables owned by the s3scan worker.
    pub(crate) async fn db_state_with_s3scan() -> AppState {
        let cfg = match LicenseConfig::new("skauswatch") {
            Ok(c) => c,
            Err(e) => panic!("license config: {e}"),
        };
        let client: Arc<LicenseClient> = match LicenseClient::new(cfg) {
            Ok(c) => c,
            Err(e) => panic!("license client: {e}"),
        };
        let pool = skauswatch_testkit::db::test_pool_multi(&[
            Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/migrations")),
            Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../s3scan/migrations")),
        ])
        .await;
        AppStateInner::for_tests_with_db(client, pool)
    }
}

#[cfg(test)]
#[allow(clippy::panic)] // tests fail loudly by design
mod tests {
    use super::*;

    #[test]
    fn api_version_gate_accepts_v1_and_empty() {
        assert!(check_api_version("").is_ok());
        assert!(check_api_version("v1").is_ok());
    }

    #[test]
    fn api_version_gate_rejects_unknown_with_exact_message() {
        let err = match check_api_version("v9") {
            Err(e) => e,
            Ok(()) => panic!("v9 must be rejected"),
        };
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert_eq!(err.message(), "api_version v9 not supported");
    }

    #[test]
    fn tenant_metadata_requires_present_nonempty_valid_uuid() {
        let empty = tonic::metadata::MetadataMap::new();
        match require_tenant_metadata(&empty) {
            Err(e) => assert_eq!(e.code(), tonic::Code::Unauthenticated),
            Ok(_) => panic!("missing x-tenant-id must be rejected"),
        }

        let mut blank = tonic::metadata::MetadataMap::new();
        blank.insert("x-tenant-id", "".parse().unwrap_or_else(|e| panic!("{e}")));
        assert!(require_tenant_metadata(&blank).is_err());

        let mut garbage = tonic::metadata::MetadataMap::new();
        garbage.insert(
            "x-tenant-id",
            "not-a-uuid".parse().unwrap_or_else(|e| panic!("{e}")),
        );
        match require_tenant_metadata(&garbage) {
            Err(e) => assert_eq!(e.code(), tonic::Code::Unauthenticated),
            Ok(_) => panic!("non-UUID x-tenant-id must be rejected"),
        }

        let tenant = uuid::Uuid::new_v4();
        let mut valid = tonic::metadata::MetadataMap::new();
        valid.insert(
            "x-tenant-id",
            tenant.to_string().parse().unwrap_or_else(|e| panic!("{e}")),
        );
        assert_eq!(
            require_tenant_metadata(&valid).unwrap_or_else(|e| panic!("{e}")),
            tenant
        );
    }

    #[test]
    fn ts_from_naive_converts_utc_epoch_fields() {
        let dt = chrono::NaiveDate::from_ymd_opt(2026, 7, 22)
            .and_then(|d| d.and_hms_micro_opt(10, 3, 7, 123456));
        let dt = match dt {
            Some(v) => v,
            None => panic!("valid test datetime"),
        };
        let ts = ts_from_naive(dt);
        assert_eq!(ts.seconds, dt.and_utc().timestamp());
        assert_eq!(ts.nanos, 123_456_000);
    }

    #[test]
    fn grpc_port_defaults_to_v1_50051() {
        // Env-free default; deployments override via GRPC_PORT.
        assert_eq!(DEFAULT_GRPC_PORT, 50051);
    }

    #[test]
    fn enabled_from_matches_v1_semantics() {
        assert!(enabled_from(None)); // default true
        assert!(enabled_from(Some("true")));
        assert!(enabled_from(Some("TRUE")));
        assert!(!enabled_from(Some("false")));
        assert!(!enabled_from(Some("nope")));
    }

    #[test]
    fn port_from_parses_or_falls_back() {
        assert_eq!(port_from(None), DEFAULT_GRPC_PORT);
        assert_eq!(port_from(Some("9000")), 9000);
        assert_eq!(port_from(Some("not-a-port")), DEFAULT_GRPC_PORT);
    }

    #[test]
    fn require_jwt_accepts_valid_and_rejects_missing() {
        let empty = tonic::metadata::MetadataMap::new();
        assert!(require_jwt(&empty, skauswatch_testkit::jwt::verify_key()).is_err());

        let token = match skauswatch_auth::issue_service_token(
            "1",
            "admin",
            skauswatch_testkit::jwt::signing_key(),
            300,
        ) {
            Ok(t) => t,
            Err(e) => panic!("issue token: {e}"),
        };
        let mut md = tonic::metadata::MetadataMap::new();
        let value = match format!("Bearer {token}").parse() {
            Ok(v) => v,
            Err(e) => panic!("metadata value: {e}"),
        };
        md.insert("authorization", value);
        assert!(require_jwt(&md, skauswatch_testkit::jwt::verify_key()).is_ok());
    }

    #[test]
    fn method_not_implemented_matches_v1_grpcio_message() {
        let s = method_not_implemented();
        assert_eq!(s.code(), tonic::Code::Unimplemented);
        assert_eq!(s.message(), "Method not implemented!");
    }

    #[test]
    fn db_err_maps_to_internal_without_leaking_detail() {
        let e = sqlx::Error::RowNotFound;
        let s = db_err(e);
        assert_eq!(s.code(), tonic::Code::Internal);
        assert_eq!(s.message(), "Internal Server Error");
    }

    /// An OS-assigned ephemeral loopback port — every `serve_with_ready`
    /// test binds its own so parallel test threads never race for the same
    /// address (unlike the real `GRPC_PORT`/50051 default `main.rs` uses).
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
    async fn serve_binds_and_shuts_down_cleanly() {
        // identity: None (AppStateInner::for_tests()'s default) — serve()
        // must take the plaintext fallback without even attempting
        // same_env_matcher()/server_tls_config.
        let state = test_util::test_state();
        assert!(state.identity.is_none());
        let result = serve_with_ready(state, ephemeral_addr(), already_shutdown(), None).await;
        assert!(
            result.is_ok(),
            "serve() should shut down cleanly: {result:?}"
        );
    }

    #[tokio::test]
    async fn serve_falls_back_to_plaintext_when_identity_is_held_but_degraded() {
        let identity = Arc::new(skauswatch_identity::IdentityProvider::degraded_for_test());
        let state = crate::state::AppStateInner::for_tests_with_identity(
            skauswatch_testkit::license::dev_license("skauswatch"),
            identity,
        );
        let result = serve_with_ready(state, ephemeral_addr(), already_shutdown(), None).await;
        assert!(
            result.is_ok(),
            "serve() should degrade to plaintext cleanly: {result:?}"
        );
    }

    #[test]
    fn same_env_matcher_accepts_any_workload_in_this_env_only() {
        assert!(
            std::env::var("SPIFFE_ENV").is_err(),
            "test assumes the default SPIFFE_ENV (\"beta\")"
        );
        let matcher = same_env_matcher().unwrap_or_else(|e| panic!("build matcher: {e}"));
        let id = |s: &str| {
            skauswatch_identity::SpiffeId::new(s).unwrap_or_else(|e| panic!("spiffe id {s}: {e}"))
        };

        // Any workload in this env's trust domain is allowed — the design
        // doc's §1 deliberately broad allow (no real caller yet).
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/manager")));
        assert!(matcher.matches(&id("spiffe://penguintech.io/beta/worker-vault-sync")));
        // Federated trust domain — never allowed regardless of path.
        assert!(!matcher.matches(&id("spiffe://customer.example/beta/manager")));
        // Same trust domain/workload, different env segment.
        assert!(!matcher.matches(&id("spiffe://penguintech.io/gamma/manager")));
    }

    /// End-to-end mTLS handshake test against the *real* `serve()` code path
    /// (via `serve_with_ready`, not a reimplementation): any peer in this
    /// env's trust domain completes the handshake (broad same-env allow —
    /// see [`same_env_matcher`]), a peer in a different env segment is
    /// rejected, and an SVID claiming an allowed identity but signed by a CA
    /// outside the held bundle set is rejected by chain validation. Mirrors
    /// `services/pki/src/grpc/mod.rs`'s identical test.
    #[tokio::test]
    async fn grpc_mtls_accepts_any_same_env_peer_and_rejects_other_env_and_untrusted_ca() {
        use rustls::pki_types::ServerName;
        use skauswatch_identity::IdentityProvider;
        use skauswatch_identity::testutil::{TestCa, bundle_set, trust_domain};
        use tokio::io::AsyncReadExt as _;

        let trusted_ca = TestCa::generate();
        let untrusted_ca = TestCa::generate();
        let td = trust_domain("penguintech.io");

        let server_svid = trusted_ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let same_env_peer_svid =
            trusted_ca.issue_leaf("spiffe://penguintech.io/beta/worker-vault-sync");
        let other_env_peer_svid =
            trusted_ca.issue_leaf("spiffe://penguintech.io/gamma/worker-vault-sync");
        let impostor_svid = untrusted_ca.issue_leaf("spiffe://penguintech.io/beta/manager");
        let bundles = bundle_set(&[(&td, &trusted_ca)]);

        let server_identity = IdentityProvider::from_svid_for_test(server_svid, bundles.clone());
        let state = crate::state::AppStateInner::for_tests_with_identity(
            skauswatch_testkit::license::dev_license("skauswatch"),
            Arc::new(server_identity),
        );

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

        async fn connect(
            addr: SocketAddr,
            provider: &skauswatch_identity::IdentityProvider,
            allowed: &SpiffeIdMatcher,
        ) -> std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
            let client_cfg = provider
                .client_tls_config(allowed)
                .unwrap_or_else(|e| panic!("client tls config: {e}"));
            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .unwrap_or_else(|e| panic!("tcp connect: {e}"));
            let name = ServerName::try_from("manager.invalid")
                .unwrap_or_else(|e| panic!("server name: {e}"));
            tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_cfg))
                .connect(name, stream)
                .await
        }

        async fn assert_rejected(
            result: std::io::Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>,
            label: &str,
        ) {
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

        // Same-env peer: trusted CA, /beta path — allowed by the broad
        // same-env matcher — handshake must complete.
        let same_env_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());
        let same_env_provider =
            IdentityProvider::from_svid_for_test(same_env_peer_svid, bundles.clone());
        let same_env_result = connect(addr, &same_env_provider, &same_env_allowed).await;
        assert!(
            same_env_result.is_ok(),
            "same-env SVID must complete the mTLS handshake: {same_env_result:?}"
        );
        drop(same_env_result);

        // Different-env peer: same trusted CA, disallowed path segment.
        let other_env_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());
        let other_env_provider =
            IdentityProvider::from_svid_for_test(other_env_peer_svid, bundles.clone());
        assert_rejected(
            connect(addr, &other_env_provider, &other_env_allowed).await,
            "other-env SVID",
        )
        .await;

        // Impostor peer: correct claimed SPIFFE ID, untrusted issuer.
        let impostor_allowed = SpiffeIdMatcher::new().allow_trust_domain(td.clone());
        let impostor_provider = IdentityProvider::from_svid_for_test(impostor_svid, bundles);
        assert_rejected(
            connect(addr, &impostor_provider, &impostor_allowed).await,
            "untrusted-CA impostor SVID",
        )
        .await;

        let _ = shutdown_tx.send(());
        tokio::time::timeout(std::time::Duration::from_secs(5), serve_task)
            .await
            .unwrap_or_else(|e| panic!("serve() did not shut down in time: {e}"))
            .unwrap_or_else(|e| panic!("serve task join: {e}"))
            .unwrap_or_else(|e| panic!("serve() returned an error: {e}"));
    }
}
